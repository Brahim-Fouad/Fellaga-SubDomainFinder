use crate::model::{
    DnsBenchmarkResult, DnsRecord, ResolvedHost, ResolverMetric, ResolverTestResult,
};
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream};
use hickory_client::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_client::proto::rr::Name;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::xfer::Protocol;
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{OnceCell, oneshot};

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);
const UDP_SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;

fn bind_buffered_udp(address: SocketAddr) -> Result<UdpSocket> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    socket.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    socket.bind(&address.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

#[derive(Debug)]
pub struct DnsQueryResult {
    pub owner: String,
    pub query_type: RecordType,
    pub records: Vec<DnsRecord>,
}

#[derive(Clone)]
pub struct DnsEngine {
    resolvers: Arc<Vec<ResolverNode>>,
    fast_resolvers: Arc<Vec<FastResolver>>,
    concurrency: usize,
    timeout: Duration,
    rate_limit: u64,
    next_query_at: Arc<tokio::sync::Mutex<Instant>>,
    selection_counter: Arc<AtomicU64>,
}

struct FastResolver {
    address: SocketAddr,
    transport: OnceCell<Arc<FastUdpTransport>>,
}

struct FastUdpTransport {
    socket: Arc<UdpSocket>,
    pending: Arc<tokio::sync::Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>,
    next_id: AtomicU16,
}

impl FastUdpTransport {
    async fn connect(address: SocketAddr) -> Result<Arc<Self>> {
        let bind_address = if address.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        let socket = Arc::new(bind_buffered_udp(bind_address)?);
        socket.connect(address).await?;
        let pending = Arc::new(tokio::sync::Mutex::new(HashMap::<
            u16,
            oneshot::Sender<Vec<u8>>,
        >::new()));
        let receiver_socket = socket.clone();
        let receiver_pending = pending.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            while let Ok(length) = receiver_socket.recv(&mut buffer).await {
                if length < 2 {
                    continue;
                }
                let id = u16::from_be_bytes([buffer[0], buffer[1]]);
                if let Some(sender) = receiver_pending.lock().await.remove(&id) {
                    let _ = sender.send(buffer[..length].to_vec());
                }
            }
        });
        Ok(Arc::new(Self {
            socket,
            pending,
            next_id: AtomicU16::new(1),
        }))
    }

    async fn query(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout_duration: Duration,
    ) -> Result<Message> {
        let id = loop {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed);
            if !self.pending.lock().await.contains_key(&candidate) {
                break candidate;
            }
        };
        let name = Name::from_str(&format!("{}.", fqdn.trim_end_matches('.')))?;
        let mut message = Message::new();
        let mut edns = Edns::new();
        edns.set_max_payload(1_232)
            .set_version(0)
            .set_dnssec_ok(true);
        message
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(recursion_desired)
            .add_query(Query::query(name, record_type))
            .set_edns(edns);
        let payload = message.to_vec()?;
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(id, sender);
        if let Err(error) = self.socket.send(&payload).await {
            self.pending.lock().await.remove(&id);
            return Err(error.into());
        }
        let response = match tokio::time::timeout(timeout_duration, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => {
                self.pending.lock().await.remove(&id);
                return Err(error.into());
            }
        };
        let response = Message::from_vec(&response)?;
        if response.id() != id || response.message_type() != MessageType::Response {
            bail!("réponse DNS UDP non corrélée");
        }
        Ok(response)
    }
}

impl FastResolver {
    async fn query(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout: Duration,
    ) -> Result<Message> {
        let transport = self
            .transport
            .get_or_try_init(|| FastUdpTransport::connect(self.address))
            .await?;
        transport
            .query(fqdn, record_type, recursion_desired, timeout)
            .await
    }
}

fn system_nameserver() -> Option<IpAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()?
        .lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("nameserver")
                .map(str::trim)
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
}

struct ResolverNode {
    label: String,
    resolver: Arc<TokioResolver>,
    state: Mutex<ResolverState>,
    inflight: AtomicUsize,
}

#[derive(Debug, Default)]
struct ResolverState {
    requests: u64,
    successes: u64,
    failures: u64,
    total_ms: u64,
    consecutive_failures: u64,
    reported_requests: u64,
    reported_successes: u64,
    reported_failures: u64,
    reported_total_ms: u64,
}

impl DnsEngine {
    pub async fn benchmark_loopback(
        queries: usize,
        concurrency: usize,
        timeout: Duration,
    ) -> Result<DnsBenchmarkResult> {
        if queries == 0 {
            bail!("le benchmark exige au moins une requête");
        }
        if !(1..=60_000).contains(&concurrency) {
            bail!("la concurrence du benchmark doit être comprise entre 1 et 60000");
        }
        let server = Arc::new(bind_buffered_udp("127.0.0.1:0".parse()?)?);
        let address = server.local_addr()?;
        let mut server_tasks = Vec::new();
        for _ in 0..4 {
            let server = server.clone();
            server_tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4_096];
                loop {
                    let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                        break;
                    };
                    if length < 12 {
                        continue;
                    }
                    buffer[2] |= 0x80;
                    buffer[3] = (buffer[3] & 0xF0) | 0x03;
                    let _ = server.send_to(&buffer[..length], peer).await;
                }
            }));
        }
        let transport = FastUdpTransport::connect(address).await?;
        let started = Instant::now();
        let (completed, failures) = stream::iter(0..queries)
            .map(|index| {
                let transport = transport.clone();
                async move {
                    transport
                        .query(
                            &format!("bench-{index}.example.invalid"),
                            RecordType::A,
                            true,
                            timeout,
                        )
                        .await
                        .is_ok()
                }
            })
            .buffer_unordered(concurrency)
            .fold(
                (0_usize, 0_usize),
                |(completed, failures), success| async move {
                    if success {
                        (completed + 1, failures)
                    } else {
                        (completed, failures + 1)
                    }
                },
            )
            .await;
        for task in server_tasks {
            task.abort();
        }
        let elapsed = started.elapsed();
        let duration_ms = elapsed.as_millis();
        Ok(DnsBenchmarkResult {
            queries,
            completed,
            failures,
            concurrency,
            duration_ms,
            queries_per_second: completed as f64 / elapsed.as_secs_f64().max(0.000_001),
            loss_rate: failures as f64 / queries as f64,
        })
    }

    pub fn new(concurrency: usize, timeout: Duration, nameservers: &[IpAddr]) -> Result<Self> {
        Self::new_with_rate(concurrency, timeout, nameservers, 0)
    }

    pub fn new_with_rate(
        concurrency: usize,
        timeout: Duration,
        nameservers: &[IpAddr],
        rate_limit: u64,
    ) -> Result<Self> {
        let mut resolvers = Vec::new();
        let mut fast_resolvers = Vec::new();
        if nameservers.is_empty() {
            let mut builder =
                TokioResolver::builder_tokio().context("lecture de /etc/resolv.conf")?;
            builder.options_mut().timeout = timeout;
            builder.options_mut().attempts = 1;
            builder.options_mut().cache_size = 0;
            resolvers.push(ResolverNode {
                label: "system".to_owned(),
                resolver: Arc::new(builder.build()),
                state: Mutex::new(ResolverState::default()),
                inflight: AtomicUsize::new(0),
            });
            if let Some(address) = system_nameserver() {
                fast_resolvers.push(FastResolver {
                    address: SocketAddr::new(address, 53),
                    transport: OnceCell::new(),
                });
            }
        } else {
            for address in nameservers {
                let mut config = ResolverConfig::new();
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(*address, 53),
                    Protocol::Udp,
                ));
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(*address, 53),
                    Protocol::Tcp,
                ));
                let mut resolver_builder =
                    TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
                resolver_builder.options_mut().timeout = timeout;
                resolver_builder.options_mut().attempts = 1;
                resolver_builder.options_mut().cache_size = 0;
                resolvers.push(ResolverNode {
                    label: address.to_string(),
                    resolver: Arc::new(resolver_builder.build()),
                    state: Mutex::new(ResolverState::default()),
                    inflight: AtomicUsize::new(0),
                });
                fast_resolvers.push(FastResolver {
                    address: SocketAddr::new(*address, 53),
                    transport: OnceCell::new(),
                });
            }
        }
        let effective_concurrency = concurrency.max(1);
        Ok(Self {
            resolvers: Arc::new(resolvers),
            fast_resolvers: Arc::new(fast_resolvers),
            concurrency: effective_concurrency,
            timeout,
            rate_limit,
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            selection_counter: Arc::new(AtomicU64::new(0)),
        })
    }

    async fn wait_for_rate_slot(&self) {
        if self.rate_limit == 0 {
            return;
        }
        let spacing = Duration::from_secs_f64(1.0 / self.rate_limit as f64);
        let mut next = self.next_query_at.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep(*next - now).await;
        }
        *next = Instant::now() + spacing;
    }

    pub fn seed_metrics(&self, history: &HashMap<String, ResolverMetric>) {
        for node in self.resolvers.iter() {
            let Some(metric) = history.get(&node.label) else {
                continue;
            };
            if let Ok(mut state) = node.state.lock() {
                state.requests = metric.requests;
                state.successes = metric.successes;
                state.failures = metric.failures;
                state.total_ms = metric.average_ms.saturating_mul(metric.requests);
                state.consecutive_failures = metric.consecutive_failures;
                state.reported_requests = state.requests;
                state.reported_successes = state.successes;
                state.reported_failures = state.failures;
                state.reported_total_ms = state.total_ms;
            }
        }
    }

    pub async fn test_resolvers(
        addresses: &[IpAddr],
        timeout: Duration,
    ) -> Vec<ResolverTestResult> {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut tests = stream::iter(addresses.iter().copied().collect::<BTreeSet<_>>())
            .map(|address| async move {
                let resolver = FastResolver {
                    address: SocketAddr::new(address, 53),
                    transport: OnceCell::new(),
                };
                let started = Instant::now();
                let nxdomain_name = format!("fellaga-{seed:x}.invalid");
                let nxdomain = resolver
                    .query(&nxdomain_name, RecordType::A, true, timeout)
                    .await;
                let dnssec = resolver
                    .query("cloudflare.com", RecordType::DNSKEY, true, timeout)
                    .await;
                let mut signatures = BTreeSet::new();
                let mut query_error = None;
                for _ in 0..3 {
                    match resolver
                        .query("example.com", RecordType::A, true, timeout)
                        .await
                    {
                        Ok(response) => {
                            signatures.insert(
                                response
                                    .answers()
                                    .iter()
                                    .filter(|record| record.record_type() == RecordType::A)
                                    .map(|record| record.data().to_string())
                                    .collect::<BTreeSet<_>>(),
                            );
                        }
                        Err(error) => query_error = Some(format!("{error:#}")),
                    }
                }
                let hijacks_nxdomain = nxdomain.as_ref().is_ok_and(|response| {
                    response.response_code() == ResponseCode::NoError
                        && !response.answers().is_empty()
                });
                let dnssec_records = dnssec.as_ref().is_ok_and(|response| {
                    response.response_code() == ResponseCode::NoError
                        && response
                            .answers()
                            .iter()
                            .any(|record| record.record_type() == RecordType::DNSKEY)
                });
                let validates_dnssec = dnssec
                    .as_ref()
                    .is_ok_and(|response| response.authentic_data());
                let consistent = signatures.len() == 1
                    && signatures
                        .iter()
                        .next()
                        .is_some_and(|values| !values.is_empty())
                    && query_error.is_none();
                let error = nxdomain
                    .err()
                    .map(|error| format!("NXDOMAIN: {error:#}"))
                    .or_else(|| dnssec.err().map(|error| format!("DNSSEC: {error:#}")))
                    .or(query_error);
                let usable = !hijacks_nxdomain
                    && dnssec_records
                    && validates_dnssec
                    && consistent
                    && error.is_none();
                ResolverTestResult {
                    resolver: address.to_string(),
                    usable,
                    hijacks_nxdomain,
                    dnssec_records,
                    validates_dnssec,
                    consistent,
                    average_ms: (started.elapsed().as_millis() / 5).min(u64::MAX as u128) as u64,
                    error,
                }
            })
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await;
        tests.sort_by(|left, right| left.resolver.cmp(&right.resolver));
        tests
    }

    pub async fn resolve_host_consensus(&self, fqdn: &str) -> Option<ResolvedHost> {
        let required = if self.fast_resolvers.len() >= 2 { 2 } else { 1 };
        let mut results = stream::iter(self.fast_resolvers.iter())
            .map(|resolver| async move {
                let (a, aaaa) = tokio::join!(
                    resolver.query(fqdn, RecordType::A, true, self.timeout),
                    resolver.query(fqdn, RecordType::AAAA, true, self.timeout),
                );
                [a.ok(), aaaa.ok()]
                    .into_iter()
                    .flatten()
                    .filter(|response| {
                        !response.truncated() && response.response_code() == ResponseCode::NoError
                    })
                    .flat_map(|response| {
                        response
                            .answers()
                            .iter()
                            .filter(|record| {
                                matches!(
                                    record.record_type(),
                                    RecordType::A | RecordType::AAAA | RecordType::CNAME
                                )
                            })
                            .map(|record| DnsRecord {
                                record_type: record.record_type().to_string(),
                                value: record.data().to_string().trim_end_matches('.').to_owned(),
                                ttl: record.ttl(),
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .buffer_unordered(self.fast_resolvers.len().max(1))
            .collect::<Vec<_>>()
            .await;
        results.retain(|records| !records.is_empty());
        if results.len() < required {
            return None;
        }
        let resolver_count = results.len().min(u16::MAX as usize) as u16;
        let mut records = results.into_iter().flatten().collect::<Vec<_>>();
        records.sort_by(|left, right| {
            (&left.record_type, &left.value).cmp(&(&right.record_type, &right.value))
        });
        records.dedup_by(|left, right| {
            left.record_type == right.record_type && left.value == right.value
        });
        Some(ResolvedHost {
            fqdn: fqdn.to_owned(),
            records,
            from_cache: false,
            last_verified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64),
            authoritative_validation: false,
            resolver_count,
        })
    }

    pub async fn authoritative_confirms(&self, fqdn: &str) -> bool {
        let Some(root_domain) = crate::util::registrable_domain(fqdn) else {
            return false;
        };
        let Ok(servers) = self.authoritative_servers(&root_domain).await else {
            return false;
        };
        let addresses = servers
            .into_iter()
            .flat_map(|(_, addresses)| addresses)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(4)
            .collect::<Vec<_>>();
        let mut results = stream::iter(addresses)
            .map(|address| async move {
                let resolver = FastResolver {
                    address: SocketAddr::new(address, 53),
                    transport: OnceCell::new(),
                };
                let (a, aaaa) = tokio::join!(
                    resolver.query(fqdn, RecordType::A, false, self.timeout),
                    resolver.query(fqdn, RecordType::AAAA, false, self.timeout),
                );
                [a.ok(), aaaa.ok()].into_iter().flatten().any(|response| {
                    response.authoritative()
                        && response.response_code() == ResponseCode::NoError
                        && response.answers().iter().any(|record| {
                            matches!(
                                record.record_type(),
                                RecordType::A | RecordType::AAAA | RecordType::CNAME
                            )
                        })
                })
            })
            .buffer_unordered(4);
        while let Some(confirmed) = results.next().await {
            if confirmed {
                return true;
            }
        }
        false
    }

    fn resolver_order(&self) -> Vec<usize> {
        let tick = self.selection_counter.fetch_add(1, Ordering::Relaxed);
        let mut scored = self
            .resolvers
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let state = node.state.lock().ok();
                let requests = state
                    .as_ref()
                    .map(|value| value.requests)
                    .unwrap_or_default();
                let failures = state
                    .as_ref()
                    .map(|value| value.failures)
                    .unwrap_or_default();
                let average = state
                    .as_ref()
                    .filter(|value| value.requests > 0)
                    .map(|value| value.total_ms / value.requests)
                    .unwrap_or(50);
                let consecutive = state
                    .as_ref()
                    .map(|value| value.consecutive_failures)
                    .unwrap_or_default();
                let failure_penalty = failures.saturating_mul(500) / requests.max(1);
                let score = average
                    .saturating_add(failure_penalty)
                    .saturating_add(consecutive.saturating_mul(1_000))
                    .saturating_add(node.inflight.load(Ordering::Relaxed) as u64 * 10);
                (index, score)
            })
            .collect::<Vec<_>>();
        scored.sort_by_key(|(index, score)| (*score, *index));
        if self.resolvers.len() > 1 && tick % 8 == 0 {
            let explore = (tick as usize / 8) % self.resolvers.len();
            if let Some(position) = scored.iter().position(|(index, _)| *index == explore) {
                let item = scored.remove(position);
                scored.insert(0, item);
            }
        }
        scored.into_iter().map(|(index, _)| index).collect()
    }

    pub fn take_metrics(&self) -> Vec<ResolverMetric> {
        self.resolvers
            .iter()
            .filter_map(|node| {
                let mut state = node.state.lock().ok()?;
                let requests = state.requests.saturating_sub(state.reported_requests);
                let successes = state.successes.saturating_sub(state.reported_successes);
                let failures = state.failures.saturating_sub(state.reported_failures);
                let elapsed = state.total_ms.saturating_sub(state.reported_total_ms);
                state.reported_requests = state.requests;
                state.reported_successes = state.successes;
                state.reported_failures = state.failures;
                state.reported_total_ms = state.total_ms;
                Some(ResolverMetric {
                    resolver: node.label.clone(),
                    requests,
                    successes,
                    failures,
                    average_ms: elapsed / requests.max(1),
                    consecutive_failures: state.consecutive_failures,
                })
            })
            .filter(|metric| metric.requests > 0)
            .collect()
    }

    pub async fn lookup_records(&self, fqdn: &str, record_type: RecordType) -> Vec<DnsRecord> {
        for index in self.resolver_order().into_iter().take(2) {
            self.wait_for_rate_slot().await;
            let node = &self.resolvers[index];
            node.inflight.fetch_add(1, Ordering::Relaxed);
            let started = Instant::now();
            let fast_response = if matches!(record_type, RecordType::A | RecordType::AAAA) {
                if let Some(resolver) = self.fast_resolvers.get(index) {
                    resolver
                        .query(fqdn, record_type, true, self.timeout)
                        .await
                        .ok()
                } else {
                    None
                }
            } else {
                None
            };
            let fast_result = fast_response.as_ref().and_then(|response| {
                if response.truncated() {
                    return None;
                }
                match response.response_code() {
                    ResponseCode::NoError => Some(
                        response
                            .answers()
                            .iter()
                            .filter(|record| {
                                record.record_type() == record_type
                                    || record.record_type() == RecordType::CNAME
                            })
                            .map(|record| DnsRecord {
                                record_type: record.record_type().to_string(),
                                value: record.data().to_string().trim_end_matches('.').to_owned(),
                                ttl: record.ttl(),
                            })
                            .collect::<Vec<_>>(),
                    ),
                    ResponseCode::NXDomain => Some(Vec::new()),
                    _ => None,
                }
            });
            let result = if fast_result.is_none() {
                Some(node.resolver.lookup(fqdn, record_type).await)
            } else {
                None
            };
            node.inflight.fetch_sub(1, Ordering::Relaxed);
            let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let no_records = result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .is_some_and(|error| error.is_no_records_found() || error.is_nx_domain());
            if let Ok(mut state) = node.state.lock() {
                state.requests += 1;
                state.total_ms = state.total_ms.saturating_add(duration_ms);
                if fast_result.is_some()
                    || result.as_ref().is_some_and(|result| result.is_ok())
                    || no_records
                {
                    state.successes += 1;
                    state.consecutive_failures = 0;
                } else {
                    state.failures += 1;
                    state.consecutive_failures += 1;
                }
            }
            if let Some(records) = fast_result {
                return records;
            }
            match result.expect("le résultat hickory existe sans résultat UDP") {
                Ok(lookup) => {
                    return lookup
                        .record_iter()
                        .filter_map(|record| {
                            let data = record.data();
                            (record.record_type() == record_type
                                || record.record_type() == RecordType::CNAME)
                                .then(|| DnsRecord {
                                    record_type: record.record_type().to_string(),
                                    value: data.to_string().trim_end_matches('.').to_owned(),
                                    ttl: record.ttl(),
                                })
                        })
                        .collect();
                }
                Err(_) if no_records => return Vec::new(),
                Err(_) => continue,
            }
        }
        Vec::new()
    }

    pub async fn soa_serial(&self, zone: &str) -> Option<u64> {
        self.lookup_records(zone, RecordType::SOA)
            .await
            .into_iter()
            .find_map(|record| {
                record
                    .value
                    .split_whitespace()
                    .nth(2)
                    .and_then(|value| value.parse().ok())
            })
    }

    pub async fn query_many(&self, queries: Vec<(String, RecordType)>) -> Vec<DnsQueryResult> {
        let engine = self.clone();
        let mut pending = stream::iter(queries)
            .map(move |(owner, query_type)| {
                let engine = engine.clone();
                async move {
                    let records = engine.lookup_records(&owner, query_type).await;
                    DnsQueryResult {
                        owner,
                        query_type,
                        records,
                    }
                }
            })
            .buffer_unordered(self.concurrency);
        let mut results = Vec::new();
        while let Some(result) = pending.next().await {
            results.push(result);
        }
        results.sort_by(|left, right| {
            (&left.owner, left.query_type.to_string())
                .cmp(&(&right.owner, right.query_type.to_string()))
        });
        results
    }

    pub async fn reverse_names(
        &self,
        addresses: Vec<IpAddr>,
    ) -> BTreeMap<IpAddr, BTreeSet<String>> {
        let resolver = self.resolvers[self.resolver_order()[0]].resolver.clone();
        stream::iter(addresses.into_iter().collect::<BTreeSet<_>>())
            .map(move |address| {
                let resolver = resolver.clone();
                async move {
                    let names = resolver
                        .reverse_lookup(address)
                        .await
                        .map(|lookup| {
                            lookup
                                .iter()
                                .map(|name| {
                                    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (address, names)
                }
            })
            .buffer_unordered(self.concurrency)
            .collect()
            .await
    }

    pub async fn resolve_host(&self, fqdn: &str) -> Option<ResolvedHost> {
        let (a, aaaa) = tokio::join!(
            self.lookup_records(fqdn, RecordType::A),
            self.lookup_records(fqdn, RecordType::AAAA),
        );
        let mut records = a;
        records.extend(aaaa);
        records.sort_by(|left, right| {
            (&left.record_type, &left.value).cmp(&(&right.record_type, &right.value))
        });
        records.dedup_by(|left, right| {
            left.record_type == right.record_type && left.value == right.value
        });
        (!records.is_empty()).then(|| ResolvedHost {
            fqdn: fqdn.to_owned(),
            records,
            from_cache: false,
            last_verified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64),
            authoritative_validation: false,
            resolver_count: 1,
        })
    }

    pub async fn resolve_many(&self, hosts: Vec<String>) -> Vec<ResolvedHost> {
        self.resolve_many_with_progress(hosts, |_, _| {}).await
    }

    pub async fn resolve_many_with_progress<F>(
        &self,
        hosts: Vec<String>,
        mut on_completed: F,
    ) -> Vec<ResolvedHost>
    where
        F: FnMut(&str, Option<&ResolvedHost>),
    {
        let engine = self.clone();
        let mut pending = stream::iter(hosts)
            .map(move |host| {
                let engine = engine.clone();
                async move {
                    let answer = engine.resolve_host(&host).await;
                    (host, answer)
                }
            })
            .buffer_unordered(self.concurrency);
        let mut answers = Vec::new();
        while let Some((host, answer)) = pending.next().await {
            on_completed(&host, answer.as_ref());
            if let Some(answer) = answer {
                answers.push(answer);
            }
        }
        answers.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        answers
    }

    pub async fn wildcard_signature(&self, domain: &str) -> BTreeSet<String> {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut non_empty = Vec::new();
        for _ in 0..5 {
            let counter = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let host = format!("fellaga-{seed:x}-{counter:x}.{domain}");
            if let Some(answer) = self.resolve_host(&host).await {
                non_empty.push(answer.signature());
            }
        }
        if non_empty.len() < 3 {
            return BTreeSet::new();
        }
        let sample_count = non_empty.len();
        let mut signature = BTreeSet::new();
        let mut type_samples = HashMap::<String, usize>::new();
        for sample in non_empty {
            let mut seen_types = BTreeSet::new();
            for record in sample {
                if let Some((record_type, _)) = record.split_once(':') {
                    seen_types.insert(record_type.to_owned());
                }
                signature.insert(record);
            }
            for record_type in seen_types {
                *type_samples.entry(record_type).or_default() += 1;
            }
        }
        for (record_type, count) in type_samples {
            if count.saturating_mul(2) >= sample_count.saturating_add(1) {
                signature.insert(format!("{record_type}:*"));
            }
        }
        signature
    }

    pub fn matches_wildcard(answer: &ResolvedHost, signature: &BTreeSet<String>) -> bool {
        !signature.is_empty()
            && !answer.records.is_empty()
            && answer.records.iter().all(|record| {
                signature.contains(&format!("{}:{}", record.record_type, record.value))
                    || signature.contains(&format!("{}:*", record.record_type))
            })
    }

    pub async fn authoritative_servers(&self, domain: &str) -> Result<Vec<(String, Vec<IpAddr>)>> {
        let resolver = self.resolvers[self.resolver_order()[0]].resolver.clone();
        let lookup = resolver
            .lookup(domain, RecordType::NS)
            .await
            .with_context(|| format!("résolution NS de {domain}"))?;
        let names: BTreeSet<String> = lookup
            .record_iter()
            .filter(|record| record.record_type() == RecordType::NS)
            .map(|record| record.data().to_string().trim_end_matches('.').to_owned())
            .collect();
        let mut result = Vec::new();
        for name in names {
            let addresses = resolver
                .lookup_ip(name.as_str())
                .await
                .map(|lookup| lookup.iter().collect())
                .unwrap_or_default();
            result.push((name, addresses));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_transport_correlates_out_of_order_responses_and_sends_edns0() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..2 {
                let mut buffer = [0_u8; 2_048];
                let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
                let message = Message::from_vec(&buffer[..length]).unwrap();
                assert!(message.extensions().is_some());
                assert!(message.recursion_desired());
                received.push((message, peer));
            }
            for (mut message, peer) in received.into_iter().rev() {
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let transport = FastUdpTransport::connect(address).await.unwrap();
        let (alpha, beta) = tokio::join!(
            transport.query(
                "alpha.example.com",
                RecordType::A,
                true,
                Duration::from_secs(1)
            ),
            transport.query(
                "beta.example.com",
                RecordType::AAAA,
                true,
                Duration::from_secs(1)
            )
        );
        server_task.await.unwrap();
        assert_eq!(
            alpha.unwrap().queries()[0].name().to_utf8(),
            "alpha.example.com."
        );
        assert_eq!(
            beta.unwrap().queries()[0].name().to_utf8(),
            "beta.example.com."
        );
    }

    #[tokio::test]
    async fn loopback_benchmark_reports_completed_queries_and_loss() {
        let result = DnsEngine::benchmark_loopback(1_000, 128, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(result.queries, 1_000);
        assert_eq!(result.completed, 1_000);
        assert_eq!(result.failures, 0);
        assert_eq!(result.loss_rate, 0.0);
        assert!(result.queries_per_second > 0.0);
    }

    #[test]
    fn wildcard_profiles_accept_rotating_values_by_record_type() {
        let answer = ResolvedHost {
            fqdn: "random.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.99".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: None,
            authoritative_validation: false,
            resolver_count: 1,
        };
        assert!(DnsEngine::matches_wildcard(
            &answer,
            &BTreeSet::from(["A:*".to_owned()])
        ));
        assert!(!DnsEngine::matches_wildcard(
            &answer,
            &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
        ));
    }

    #[test]
    fn resolver_pool_prefers_the_healthier_profile_but_keeps_exploration() {
        let engine = DnsEngine::new(
            10,
            Duration::from_secs(1),
            &["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
        )
        .unwrap();
        engine.seed_metrics(&HashMap::from([
            (
                "1.1.1.1".to_owned(),
                ResolverMetric {
                    resolver: "1.1.1.1".to_owned(),
                    requests: 100,
                    successes: 50,
                    failures: 50,
                    average_ms: 500,
                    consecutive_failures: 3,
                },
            ),
            (
                "8.8.8.8".to_owned(),
                ResolverMetric {
                    resolver: "8.8.8.8".to_owned(),
                    requests: 100,
                    successes: 100,
                    failures: 0,
                    average_ms: 20,
                    consecutive_failures: 0,
                },
            ),
        ]));
        let exploratory = engine.resolver_order();
        let adaptive = engine.resolver_order();
        assert_eq!(exploratory[0], 0);
        assert_eq!(adaptive[0], 1);
    }
}
