use super::policy::*;
use super::transport::*;
use super::wire::*;
use super::*;

#[derive(Clone)]
pub struct DnsEngine {
    pub(super) resolvers: Arc<Vec<ResolverNode>>,
    pub(super) fast_resolvers: Arc<Vec<FastResolver>>,
    pub(super) concurrency: usize,
    pub(super) timeout: Duration,
    pub(super) rate_limit: u64,
    pub(super) governor: Arc<NetworkGovernor>,
    pub(super) next_query_at: Arc<tokio::sync::Mutex<Instant>>,
    pub(super) cadence_reservations: Arc<tokio::sync::Semaphore>,
    pub(super) selection_counter: Arc<AtomicU64>,
    pub(super) authoritative_resolvers: Arc<Mutex<HashMap<SocketAddr, Arc<FastResolver>>>>,
    pub(super) authoritative_server_cache:
        Arc<tokio::sync::Mutex<HashMap<String, AuthoritativeServerCell>>>,
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
        Self::new_with_rate_and_control(
            concurrency,
            timeout,
            nameservers,
            rate_limit,
            NetworkControl::Fixed,
        )
    }

    pub fn new_with_rate_and_control(
        concurrency: usize,
        timeout: Duration,
        nameservers: &[IpAddr],
        rate_limit: u64,
        network_control: NetworkControl,
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
                resolver: Arc::new(
                    builder
                        .build()
                        .context("initialisation du résolveur système")?,
                ),
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
            for address in nameservers.iter().copied().collect::<BTreeSet<_>>() {
                let config = ResolverConfig::from_parts(
                    None,
                    Vec::new(),
                    vec![NameServerConfig::new(
                        address,
                        true,
                        vec![ConnectionConfig::udp(), ConnectionConfig::tcp()],
                    )],
                );
                let mut resolver_builder =
                    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
                resolver_builder.options_mut().timeout = timeout;
                resolver_builder.options_mut().attempts = 1;
                resolver_builder.options_mut().cache_size = 0;
                resolvers.push(ResolverNode {
                    label: address.to_string(),
                    resolver: Arc::new(
                        resolver_builder
                            .build()
                            .with_context(|| format!("initialisation du résolveur {address}"))?,
                    ),
                    state: Mutex::new(ResolverState::default()),
                    inflight: AtomicUsize::new(0),
                });
                fast_resolvers.push(FastResolver {
                    address: SocketAddr::new(address, 53),
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
            governor: Arc::new(NetworkGovernor::new(
                network_control,
                rate_limit,
                effective_concurrency,
            )),
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            cadence_reservations: Arc::new(tokio::sync::Semaphore::new(MAX_CADENCE_RESERVATIONS)),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Build a resolver from explicit socket addresses. This remains crate
    /// internal so production CLI resolver configuration stays IP-only, while
    /// controlled laboratories and benchmarks can use an unprivileged
    /// loopback port without sending any packet to an external resolver.
    pub(crate) fn new_with_socket_addresses(
        concurrency: usize,
        timeout: Duration,
        nameservers: &[SocketAddr],
        rate_limit: u64,
    ) -> Result<Self> {
        if nameservers.is_empty() {
            bail!("at least one DNS endpoint is required");
        }
        let mut resolvers = Vec::new();
        let mut fast_resolvers = Vec::new();
        for address in nameservers.iter().copied().collect::<BTreeSet<_>>() {
            let mut udp = ConnectionConfig::udp();
            udp.port = address.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = address.port();
            let config = ResolverConfig::from_parts(
                None,
                Vec::new(),
                vec![NameServerConfig::new(address.ip(), true, vec![udp, tcp])],
            );
            let mut resolver_builder =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
            resolver_builder.options_mut().timeout = timeout;
            resolver_builder.options_mut().attempts = 1;
            resolver_builder.options_mut().cache_size = 0;
            resolvers.push(ResolverNode {
                label: address.to_string(),
                resolver: Arc::new(
                    resolver_builder
                        .build()
                        .with_context(|| format!("initializing resolver {address}"))?,
                ),
                state: Mutex::new(ResolverState::default()),
                inflight: AtomicUsize::new(0),
            });
            fast_resolvers.push(FastResolver {
                address,
                transport: OnceCell::new(),
            });
        }
        Ok(Self {
            resolvers: Arc::new(resolvers),
            fast_resolvers: Arc::new(fast_resolvers),
            concurrency: concurrency.max(1),
            timeout,
            rate_limit,
            governor: Arc::new(NetworkGovernor::new(
                NetworkControl::Fixed,
                rate_limit,
                concurrency.max(1),
            )),
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            cadence_reservations: Arc::new(tokio::sync::Semaphore::new(MAX_CADENCE_RESERVATIONS)),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Partage le même cadenceur avec un second moteur (par exemple le
    /// consensus trusted) afin que la limite CLI soit réellement commune.
    pub fn share_rate_limit_with(mut self, other: &Self) -> Self {
        self.rate_limit = other.rate_limit;
        self.governor = other.governor.clone();
        self.next_query_at = other.next_query_at.clone();
        self.cadence_reservations = other.cadence_reservations.clone();
        self
    }

    pub fn concurrency(&self) -> usize {
        self.governor
            .current_concurrency()
            .min(self.concurrency)
            .max(1)
    }

    pub fn network_governor_snapshot(&self) -> NetworkGovernorSnapshot {
        self.governor.snapshot()
    }

    pub(super) fn observe_network_outcome(&self, operational: bool, duration_ms: u64) {
        self.governor
            .observe_delta(1, u64::from(!operational), duration_ms);
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn observed_fast_query_until(
        &self,
        resolver: &FastResolver,
        metric_node: Option<&ResolverNode>,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        deadline: Option<tokio::time::Instant>,
        host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Result<Message> {
        let rate_slot_acquired = match deadline {
            Some(deadline) => self.wait_for_rate_slot_before(deadline).await,
            None => {
                self.wait_for_rate_slot().await;
                true
            }
        };
        if !rate_slot_acquired {
            bail!("budget DNS atteint avant l'acquisition du limiteur de débit");
        }
        let request_timeout = deadline
            .map(|deadline| {
                deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .min(self.timeout)
            })
            .unwrap_or(self.timeout);
        if request_timeout.is_zero() {
            bail!("budget DNS atteint avant l'envoi");
        }
        let _inflight = metric_node.map(|node| ResolverInflightGuard::new(&node.inflight));
        let signal = DnsSendSignal::new(host_attempted);
        let mut accounting = ResolverAttemptGuard::new(
            metric_node.map(|node| &node.state),
            self.governor.as_ref(),
            signal.clone(),
        );
        let response = resolver
            .query_with_signal(
                fqdn,
                record_type,
                recursion_desired,
                request_timeout,
                Some(&signal),
            )
            .await;
        let operational = response.as_ref().is_ok_and(|response| {
            !response.truncated()
                && matches!(
                    response.response_code(),
                    ResponseCode::NoError | ResponseCode::NXDomain
                )
        });
        accounting.finish(operational);
        response
    }

    pub(super) async fn wait_for_rate_slot(&self) {
        if self.governor.current_rate() == 0 {
            return;
        }
        let Ok(permit) = self.cadence_reservations.clone().acquire_owned().await else {
            return;
        };
        // Adaptive control may have changed while this task waited for a
        // reservation permit, so calculate spacing only at admission time.
        let current_rate = self.governor.current_rate();
        if current_rate == 0 {
            return;
        }
        let spacing = Duration::from_secs_f64(1.0 / current_rate as f64);
        let slot = {
            let mut next = self.next_query_at.lock().await;
            let slot = (*next).max(Instant::now());
            *next = slot + spacing;
            slot
        };
        let slot = tokio::time::Instant::from_std(slot);
        let _reservation = CadenceReservation::new(permit, slot);
        tokio::time::sleep_until(slot).await;
    }

    /// Acquire the shared global DNS cadence slot without waiting beyond a
    /// caller-owned phase deadline. Direct DNS transports such as the NSEC TCP
    /// walker use this hook because they do not pass through the resolver
    /// lookup helpers that normally acquire the same limiter.
    pub(crate) async fn wait_for_rate_slot_before(&self, deadline: tokio::time::Instant) -> bool {
        if deadline <= tokio::time::Instant::now() {
            return false;
        }
        if self.governor.current_rate() == 0 {
            return true;
        }
        let Ok(Ok(permit)) =
            tokio::time::timeout_at(deadline, self.cadence_reservations.clone().acquire_owned())
                .await
        else {
            return false;
        };
        if deadline <= tokio::time::Instant::now() {
            return false;
        }
        // Re-read the adaptive rate after admission rather than reserving
        // several slots ahead using a stale value.
        let current_rate = self.governor.current_rate();
        if current_rate == 0 {
            return true;
        }
        let spacing = Duration::from_secs_f64(1.0 / current_rate as f64);
        let Ok(mut next) = tokio::time::timeout_at(deadline, self.next_query_at.lock()).await
        else {
            return false;
        };
        let slot = (*next).max(Instant::now());
        let slot = tokio::time::Instant::from_std(slot);
        if slot >= deadline {
            return false;
        }
        *next = slot.into_std() + spacing;
        drop(next);
        let _reservation = CadenceReservation::new(permit, slot);
        tokio::time::timeout_at(deadline, tokio::time::sleep_until(slot))
            .await
            .is_ok()
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
                    !response.answers().is_empty()
                        && matches!(
                            response.response_code(),
                            ResponseCode::NoError | ResponseCode::NXDomain
                        )
                });
                let nxdomain_ok = nxdomain.as_ref().is_ok_and(is_definitive_nxdomain);
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
                let nxdomain_error = match &nxdomain {
                    Err(error) => Some(format!("NXDOMAIN: {error:#}")),
                    Ok(response) if !nxdomain_ok => Some(format!(
                        "NXDOMAIN: réponse non définitive ({:?}, TC={})",
                        response.response_code(),
                        response.truncated()
                    )),
                    Ok(_) => None,
                };
                let dnssec_error = dnssec
                    .as_ref()
                    .err()
                    .map(|error| format!("DNSSEC: {error:#}"));
                let error = nxdomain_error.or(dnssec_error).or(query_error);
                let usable = nxdomain_ok
                    && !hijacks_nxdomain
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

    pub async fn resolve_host_consensus_classified(&self, fqdn: &str) -> DnsResolutionOutcome {
        self.resolve_host_consensus_classified_with_signal(fqdn, None)
            .await
    }

    pub(crate) async fn resolve_host_consensus_classified_with_network_signal(
        &self,
        fqdn: &str,
        host_attempted: Arc<std::sync::atomic::AtomicBool>,
    ) -> DnsResolutionOutcome {
        self.resolve_host_consensus_classified_with_signal(fqdn, Some(host_attempted))
            .await
    }

    pub(super) async fn resolve_host_consensus_classified_with_signal(
        &self,
        fqdn: &str,
        host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> DnsResolutionOutcome {
        let required = positive_quorum(self.fast_resolvers.len());
        let results = stream::iter(self.fast_resolvers.iter().enumerate())
            .map(|(index, resolver)| {
                let host_attempted = host_attempted.clone();
                async move {
                    let metric_node = self.resolvers.get(index);
                    let query_a = async {
                        classify_address_response(
                            self.observed_fast_query_until(
                                resolver,
                                metric_node,
                                fqdn,
                                RecordType::A,
                                true,
                                None,
                                host_attempted.clone(),
                            )
                            .await,
                            RecordType::A,
                        )
                    };
                    let query_aaaa = async {
                        classify_address_response(
                            self.observed_fast_query_until(
                                resolver,
                                metric_node,
                                fqdn,
                                RecordType::AAAA,
                                true,
                                None,
                                host_attempted.clone(),
                            )
                            .await,
                            RecordType::AAAA,
                        )
                    };
                    first_positive_or_both(query_a, query_aaaa).await
                }
            })
            .buffer_unordered(self.fast_resolvers.len().max(1));
        // Each UDP/TCP/Hickory operation has its own network timeout. Do not
        // wrap the whole host in another wall-clock timeout: time spent waiting
        // for the deliberate global rate limit is not a network stall and must
        // not turn an otherwise valid answer into an indeterminate result.
        collect_consensus_results(fqdn, required, results).await
    }

    pub async fn resolve_host_consensus(&self, fqdn: &str) -> Option<ResolvedHost> {
        match self.resolve_host_consensus_classified(fqdn).await {
            DnsResolutionOutcome::Positive(answer) => Some(answer),
            DnsResolutionOutcome::Negative { .. } | DnsResolutionOutcome::Indeterminate { .. } => {
                None
            }
        }
    }

    pub async fn authoritative_confirms(&self, fqdn: &str) -> bool {
        self.authoritative_confirms_until(fqdn, None).await
    }

    pub(crate) async fn authoritative_confirms_until(
        &self,
        fqdn: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> bool {
        let Some(root_domain) = crate::util::registrable_domain(fqdn) else {
            return false;
        };
        let mut servers = None;
        for zone in authoritative_zone_candidates(fqdn, &root_domain) {
            if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
                return false;
            }
            if let Ok(candidate) = self.authoritative_servers_until(&zone, deadline).await
                && !candidate.is_empty()
            {
                servers = Some(candidate);
                break;
            }
        }
        let Some(servers) = servers else {
            return false;
        };
        let resolvers = servers
            .into_iter()
            .flat_map(|(_, addresses)| addresses)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(4)
            .filter_map(|address| {
                self.authoritative_resolver(SocketAddr::new(address, 53))
                    .ok()
            })
            .collect::<Vec<_>>();
        let mut results = stream::iter(resolvers)
            .map(|resolver| async move {
                let a = async {
                    authoritative_response_confirms(
                        self.observed_fast_query_until(
                            &resolver,
                            None,
                            fqdn,
                            RecordType::A,
                            false,
                            deadline,
                            None,
                        )
                        .await,
                        RecordType::A,
                    )
                };
                let aaaa = async {
                    authoritative_response_confirms(
                        self.observed_fast_query_until(
                            &resolver,
                            None,
                            fqdn,
                            RecordType::AAAA,
                            false,
                            deadline,
                            None,
                        )
                        .await,
                        RecordType::AAAA,
                    )
                };
                first_true_or_both(a, aaaa).await
            })
            .buffer_unordered(4);
        while let Some(confirmed) = results.next().await {
            if confirmed {
                return true;
            }
        }
        false
    }

    pub(super) fn authoritative_resolver(&self, address: SocketAddr) -> Result<Arc<FastResolver>> {
        let mut resolvers = self
            .authoritative_resolvers
            .lock()
            .map_err(|_| anyhow::anyhow!("cache des résolveurs autoritaires empoisonné"))?;
        if !resolvers.contains_key(&address) && resolvers.len() >= MAX_AUTHORITATIVE_TRANSPORTS {
            // Cached transports own a UDP receiver task and large socket
            // buffers. Bound the optimization so scanning many providers does
            // not retain one socket/task for every authoritative IP forever.
            if let Some(evicted) = resolvers.keys().next().copied() {
                resolvers.remove(&evicted);
            }
        }
        Ok(resolvers
            .entry(address)
            .or_insert_with(|| {
                Arc::new(FastResolver {
                    address,
                    transport: OnceCell::new(),
                })
            })
            .clone())
    }

    pub(super) fn resolver_order(&self) -> Vec<usize> {
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
        if self.resolvers.len() > 1 && tick.is_multiple_of(8) {
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

    pub(super) async fn discovery_a_quorum_outcome(
        &self,
        fqdn: &str,
        host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> RecordLookupOutcome {
        let order = self
            .resolver_order()
            .into_iter()
            .filter(|index| *index < self.fast_resolvers.len())
            .take(2)
            .collect::<Vec<_>>();
        let [first, second] = order.as_slice() else {
            return RecordLookupOutcome::Indeterminate;
        };
        let query = |index: usize, signal: Option<Arc<std::sync::atomic::AtomicBool>>| async move {
            let (Some(resolver), Some(node)) =
                (self.fast_resolvers.get(index), self.resolvers.get(index))
            else {
                return RecordLookupOutcome::Indeterminate;
            };
            classify_address_response(
                self.observed_fast_query_until(
                    resolver,
                    Some(node),
                    fqdn,
                    RecordType::A,
                    true,
                    None,
                    signal,
                )
                .await,
                RecordType::A,
            )
        };
        let (first_outcome, second_outcome) = tokio::join!(
            query(*first, host_attempted.clone()),
            query(*second, host_attempted),
        );
        merge_record_lookup_outcomes(first_outcome, second_outcome)
    }

    pub(super) async fn lookup_records_classified(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> RecordLookupOutcome {
        let order = self
            .resolver_order()
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        self.lookup_records_classified_in_order(fqdn, record_type, &order, None)
            .await
    }

    pub(super) async fn lookup_records_classified_in_order(
        &self,
        fqdn: &str,
        record_type: RecordType,
        order: &[usize],
        host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> RecordLookupOutcome {
        let required_negatives = order.len().clamp(1, 2);
        let mut definitive_negatives = 0_usize;
        for index in order.iter().copied() {
            let node = &self.resolvers[index];
            let fast_response = if matches!(record_type, RecordType::A | RecordType::AAAA) {
                if let Some(resolver) = self.fast_resolvers.get(index) {
                    Some(
                        self.observed_fast_query_until(
                            resolver,
                            Some(node),
                            fqdn,
                            record_type,
                            true,
                            None,
                            host_attempted.clone(),
                        )
                        .await,
                    )
                } else {
                    None
                }
            } else {
                None
            };
            let fast_result = fast_response.as_ref().and_then(|response| {
                let Ok(response) = response else {
                    return None;
                };
                if response.truncated() {
                    return None;
                }
                let records = response_records(response, record_type);
                if !records.is_empty() {
                    Some(RecordLookupOutcome::Positive(records))
                } else if is_definitive_nxdomain(response) {
                    Some(RecordLookupOutcome::Negative)
                } else {
                    // NODATA proves only that this RR type is absent, not that
                    // the owner is absent. SERVFAIL/REFUSED/lame responses are
                    // likewise indeterminate. Retrying the same endpoint via
                    // Hickory would only duplicate traffic and latency.
                    Some(RecordLookupOutcome::Indeterminate)
                }
            });
            let fast_timed_out = matches!(
                &fast_response,
                Some(Err(error)) if error.is::<tokio::time::error::Elapsed>()
            );
            let fallback_started = Instant::now();
            let result = if fast_result.is_none() && !fast_timed_out {
                // The fast path failed without exhausting its network
                // timeout, or this resolver has no raw transport. Hickory
                // remains a compatibility fallback, but it is accounted only
                // after a terminal uncached result.
                self.wait_for_rate_slot().await;
                Some(node.resolver.lookup(fqdn, record_type).await)
            } else {
                None
            };
            if result.is_some()
                && let Some(host_attempted) = &host_attempted
            {
                // Hickory exposes no post-send hook. Its cache is disabled for
                // Fellaga resolvers, so a terminal lookup result proves that a
                // network attempt occurred without marking one before polling.
                host_attempted.store(true, Ordering::Release);
            }
            let fallback_duration_ms =
                fallback_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let fallback_operational = result.as_ref().is_some_and(|result| match result {
                Ok(_) => true,
                Err(error) => error.is_nx_domain() || error.is_no_records_found(),
            });
            let had_fallback = result.is_some();
            let classified = if let Some(result) = fast_result {
                result
            } else if fast_timed_out {
                // Retrying the same unresponsive endpoint through Hickory
                // would spend a second timeout window before the next resolver
                // gets a chance. Keep the timeout indeterminate and move on.
                RecordLookupOutcome::Indeterminate
            } else {
                match result.expect("le résultat hickory existe sans résultat UDP") {
                    Ok(lookup) => {
                        let records = Name::from_str(&format!("{}.", fqdn.trim_end_matches('.')))
                            .ok()
                            .map(|query_name| {
                                records_for_query(lookup.answers(), &query_name, record_type)
                            })
                            .unwrap_or_default();
                        if records.is_empty() {
                            // An empty successful Hickory lookup is NODATA. It
                            // must never demote a retained owner as NXDOMAIN.
                            RecordLookupOutcome::Indeterminate
                        } else {
                            RecordLookupOutcome::Positive(records)
                        }
                    }
                    Err(error) if error.is_nx_domain() => RecordLookupOutcome::Negative,
                    Err(error) if error.is_no_records_found() => RecordLookupOutcome::Indeterminate,
                    Err(_) => RecordLookupOutcome::Indeterminate,
                }
            };
            if had_fallback {
                if let Ok(mut state) = node.state.lock() {
                    record_resolver_state(&mut state, fallback_operational, fallback_duration_ms);
                }
                self.observe_network_outcome(fallback_operational, fallback_duration_ms);
            }
            match classified {
                RecordLookupOutcome::Positive(records) => {
                    return RecordLookupOutcome::Positive(records);
                }
                RecordLookupOutcome::Negative => definitive_negatives += 1,
                RecordLookupOutcome::Indeterminate => {}
            }
        }
        if definitive_negatives >= required_negatives {
            RecordLookupOutcome::Negative
        } else {
            RecordLookupOutcome::Indeterminate
        }
    }

    pub async fn lookup_records(&self, fqdn: &str, record_type: RecordType) -> Vec<DnsRecord> {
        match self.lookup_records_classified(fqdn, record_type).await {
            RecordLookupOutcome::Positive(records) => records,
            RecordLookupOutcome::Negative | RecordLookupOutcome::Indeterminate => Vec::new(),
        }
    }

    /// Performs a locally validated DNSSEC denial lookup.  This path uses
    /// Hickory's root trust anchor and consumes only records whose per-record
    /// proof is `Secure`; an upstream AD bit is never accepted on its own.
    /// It is intended for a small suspicious/wildcard subset, not every brute
    /// force candidate, and has one absolute wall deadline.
    pub async fn dnssec_denial_assessment(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> DnssecProofAssessment {
        let Some(address) = self
            .fast_resolvers
            .get(self.resolver_order().first().copied().unwrap_or_default())
            .map(|resolver| resolver.address)
        else {
            return DnssecProofAssessment::default();
        };
        let mut udp = ConnectionConfig::udp();
        udp.port = address.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(address.ip(), true, vec![udp, tcp])],
        );
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().timeout = self.timeout.min(Duration::from_secs(3));
        builder.options_mut().attempts = 1;
        builder.options_mut().cache_size = 32;
        builder.options_mut().num_concurrent_reqs = 1;
        builder.options_mut().max_active_requests = 8;
        builder.options_mut().validate = true;
        let Ok(resolver) = builder.build() else {
            return DnssecProofAssessment::default();
        };
        self.wait_for_rate_slot().await;
        let deadline = self
            .timeout
            .saturating_mul(3)
            .clamp(Duration::from_secs(1), Duration::from_secs(8));
        let Ok(result) = tokio::time::timeout(deadline, resolver.lookup(fqdn, record_type)).await
        else {
            return DnssecProofAssessment::default();
        };
        let authorities = match result {
            Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => no_records
                .authorities
                .map(|records| records.to_vec())
                .unwrap_or_default(),
            Err(NetError::Dns(DnsError::Nsec {
                response, proof, ..
            })) if proof.is_secure() => response.authorities.clone(),
            // Positive responses are deliberately inconclusive here. A secure
            // RRset can still be synthesized from a wildcard unless its denial
            // proof establishes the exact owner separately.
            Ok(_) | Err(_) => Vec::new(),
        };
        classify_dnssec_proof(&dnssec_input_from_authorities(
            fqdn,
            record_type,
            &authorities,
        ))
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
            .buffer_unordered(self.concurrency());
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
        self.reverse_names_until(addresses, None).await.0
    }

    /// Resolves PTR records while retaining every address completed before a
    /// shared phase deadline. Dropping the remaining stream cancels queued
    /// rate reservations and in-flight resolver futures.
    pub async fn reverse_names_until(
        &self,
        addresses: Vec<IpAddr>,
        deadline: Option<tokio::time::Instant>,
    ) -> (BTreeMap<IpAddr, BTreeSet<String>>, bool) {
        let resolver = self.resolvers[self.resolver_order()[0]].resolver.clone();
        let engine = self.clone();
        let mut pending = stream::iter(addresses.into_iter().collect::<BTreeSet<_>>())
            .map(move |address| {
                let resolver = resolver.clone();
                let engine = engine.clone();
                async move {
                    engine.wait_for_rate_slot().await;
                    let names = resolver
                        .reverse_lookup(address)
                        .await
                        .map(|lookup| {
                            lookup
                                .answers()
                                .iter()
                                .filter_map(|record| match &record.data {
                                    RData::PTR(name) => Some(
                                        name.to_utf8().trim_end_matches('.').to_ascii_lowercase(),
                                    ),
                                    _ => None,
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    (address, names)
                }
            })
            .buffer_unordered(self.concurrency());
        let deadline_sleep = async move {
            if let Some(deadline) = deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(deadline_sleep);
        let mut results = BTreeMap::new();
        loop {
            let next = tokio::select! {
                biased;
                _ = &mut deadline_sleep => return (results, true),
                next = pending.next() => next,
            };
            let Some((address, names)) = next else {
                return (results, false);
            };
            results.insert(address, names);
        }
    }

    pub(super) async fn resolve_host_classified_with_policy(
        &self,
        fqdn: &str,
        allow_discovery_fast_negative: bool,
        host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> DnsResolutionOutcome {
        // Fresh discovery candidates start with one parallel A query to two
        // independent resolvers. A positive A/CNAME answer establishes a live
        // owner immediately, while two strict NXDOMAIN replies establish a
        // discovery-only negative. Only disagreement, NODATA, timeout, or a
        // malformed response pays for the conservative A+AAAA fallback.
        if allow_discovery_fast_negative {
            match self
                .discovery_a_quorum_outcome(fqdn, host_attempted.clone())
                .await
            {
                outcome @ (RecordLookupOutcome::Positive(_) | RecordLookupOutcome::Negative) => {
                    return classify_host_lookup(fqdn, outcome);
                }
                RecordLookupOutcome::Indeterminate => {}
            }
        }
        // The individual resolver operations are bounded by `self.timeout`.
        // The queue imposed by `--dns-rate-limit` is intentionally excluded:
        // callers retain cancellation through their phase/global deadline.
        // Freeze one resolver order for both address families so the
        // conservative fallback evaluates one stable resolver quorum.
        let order = self
            .resolver_order()
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        let outcome = first_positive_or_both(
            self.lookup_records_classified_in_order(
                fqdn,
                RecordType::A,
                &order,
                host_attempted.clone(),
            ),
            self.lookup_records_classified_in_order(fqdn, RecordType::AAAA, &order, host_attempted),
        )
        .await;
        classify_host_lookup(fqdn, outcome)
    }

    /// Conservative host resolution for retained state, wildcard probes,
    /// enrichment, refresh, and final validation. A negative requires the full
    /// configured discovery quorum; this method never uses the fast-negative
    /// shortcut.
    pub async fn resolve_host_classified(&self, fqdn: &str) -> DnsResolutionOutcome {
        self.resolve_host_classified_with_policy(fqdn, false, None)
            .await
    }

    pub(crate) async fn resolve_host_classified_with_network_signal(
        &self,
        fqdn: &str,
        host_attempted: Arc<std::sync::atomic::AtomicBool>,
    ) -> DnsResolutionOutcome {
        self.resolve_host_classified_with_policy(fqdn, false, Some(host_attempted))
            .await
    }

    /// Fast classification for fresh enumeration candidates only. Callers must
    /// not use its negative outcome to demote or purge a retained/live name.
    /// Positive and indeterminate outcomes preserve the standard validation
    /// pipeline; only a qualified, discovery-only negative may short-circuit.
    #[cfg(test)]
    pub(crate) async fn resolve_host_discovery_classified(
        &self,
        fqdn: &str,
    ) -> DnsResolutionOutcome {
        self.resolve_host_classified_with_policy(fqdn, true, None)
            .await
    }

    pub(crate) async fn resolve_host_discovery_classified_with_network_signal(
        &self,
        fqdn: &str,
        host_attempted: Arc<std::sync::atomic::AtomicBool>,
    ) -> DnsResolutionOutcome {
        self.resolve_host_classified_with_policy(fqdn, true, Some(host_attempted))
            .await
    }

    pub async fn resolve_host(&self, fqdn: &str) -> Option<ResolvedHost> {
        match self.resolve_host_classified(fqdn).await {
            DnsResolutionOutcome::Positive(answer) => Some(answer),
            DnsResolutionOutcome::Negative { .. } | DnsResolutionOutcome::Indeterminate { .. } => {
                None
            }
        }
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
        self.resolve_many_classified_with_progress(hosts, |outcome| {
            on_completed(outcome.fqdn(), outcome.answer());
        })
        .await
        .into_iter()
        .filter_map(|outcome| match outcome {
            DnsResolutionOutcome::Positive(answer) => Some(answer),
            DnsResolutionOutcome::Negative { .. } | DnsResolutionOutcome::Indeterminate { .. } => {
                None
            }
        })
        .collect()
    }

    pub async fn resolve_many_classified_with_progress<F>(
        &self,
        hosts: Vec<String>,
        on_completed: F,
    ) -> Vec<DnsResolutionOutcome>
    where
        F: FnMut(&DnsResolutionOutcome),
    {
        self.resolve_many_classified_with_progress_policy(hosts, on_completed, false)
            .await
    }

    pub(super) async fn resolve_many_classified_with_progress_policy<F>(
        &self,
        hosts: Vec<String>,
        mut on_completed: F,
        discovery_fast_negative: bool,
    ) -> Vec<DnsResolutionOutcome>
    where
        F: FnMut(&DnsResolutionOutcome),
    {
        let engine = self.clone();
        let mut pending = stream::iter(hosts)
            .map(move |host| {
                let engine = engine.clone();
                async move {
                    engine
                        .resolve_host_classified_with_policy(&host, discovery_fast_negative, None)
                        .await
                }
            })
            .buffer_unordered(self.concurrency());
        let mut outcomes = Vec::new();
        while let Some(outcome) = pending.next().await {
            on_completed(&outcome);
            outcomes.push(outcome);
        }
        outcomes.sort_by(|left, right| left.fqdn().cmp(right.fqdn()));
        outcomes
    }

    pub(super) async fn wildcard_probe_with_policy(
        &self,
        domain: &str,
        require_positive_consensus: bool,
    ) -> WildcardProbeOutcome {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut non_empty = Vec::new();
        let mut negatives = 0_usize;

        for probe_count in [3_usize, 2] {
            let mut probes = stream::iter(0..probe_count)
                .map(|_| async move {
                    let counter = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
                    let host = format!("fellaga-{seed:x}-{counter:x}.{domain}");
                    if require_positive_consensus {
                        self.resolve_host_consensus_classified(&host).await
                    } else {
                        self.resolve_host_classified(&host).await
                    }
                })
                .buffer_unordered(probe_count);
            while let Some(outcome) = probes.next().await {
                match outcome {
                    DnsResolutionOutcome::Positive(answer) => non_empty.push(answer.signature()),
                    DnsResolutionOutcome::Negative { .. } => negatives += 1,
                    DnsResolutionOutcome::Indeterminate { .. } => {}
                }
            }

            if probe_count == 3
                && let Some(outcome) = conclusive_wildcard_outcome(&non_empty, negatives)
            {
                return outcome;
            }
        }

        classify_wildcard_samples(non_empty, negatives, 5)
    }

    pub async fn wildcard_probe(&self, domain: &str) -> WildcardProbeOutcome {
        self.wildcard_probe_with_policy(domain, false).await
    }

    pub async fn wildcard_probe_consensus(&self, domain: &str) -> WildcardProbeOutcome {
        self.wildcard_probe_with_policy(domain, true).await
    }

    pub async fn wildcard_signature(&self, domain: &str) -> BTreeSet<String> {
        match self.wildcard_probe(domain).await {
            WildcardProbeOutcome::Wildcard(signature) => signature,
            WildcardProbeOutcome::Normal | WildcardProbeOutcome::Indeterminate => BTreeSet::new(),
        }
    }

    pub fn matches_wildcard(answer: &ResolvedHost, signature: &BTreeSet<String>) -> bool {
        if signature.is_empty() || answer.records.is_empty() {
            return false;
        }
        let answer_signature = answer.signature();
        signature.is_subset(&answer_signature)
    }

    /// Exact matches may be quarantined after current trusted consensus.
    /// Superset answers remain ambiguous in output but can contain legitimate
    /// records in addition to the stable wildcard signature, so they are never
    /// cleanup candidates.
    pub fn exactly_matches_wildcard(answer: &ResolvedHost, signature: &BTreeSet<String>) -> bool {
        !signature.is_empty() && !answer.records.is_empty() && answer.signature() == *signature
    }

    pub(super) async fn load_authoritative_servers(
        &self,
        domain: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<AuthoritativeServers> {
        let index = self
            .resolver_order()
            .into_iter()
            .find(|index| {
                self.resolvers.get(*index).is_some() && self.fast_resolvers.get(*index).is_some()
            })
            .context("aucun résolveur récursif UDP instrumenté disponible")?;
        let node = &self.resolvers[index];
        let resolver = &self.fast_resolvers[index];
        let ns_response = self
            .observed_fast_query_until(
                resolver,
                Some(node),
                domain,
                RecordType::NS,
                true,
                deadline,
                None,
            )
            .await
            .with_context(|| format!("résolution NS de {domain}"))?;
        if is_definitive_nxdomain(&ns_response) {
            return Ok(Vec::new());
        }
        if ns_response.response_code() != ResponseCode::NoError {
            bail!(
                "résolution NS de {domain}: réponse {:?}",
                ns_response.response_code()
            );
        }
        let names = response_records(&ns_response, RecordType::NS)
            .into_iter()
            .map(|record| record.value.trim_end_matches('.').to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .take(MAX_NAMESERVERS_PER_ZONE)
            .collect::<BTreeSet<_>>();
        let mut result = Vec::new();
        for name in names {
            if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
                bail!("budget DNS autoritaire atteint pendant la résolution des adresses NS");
            }
            let mut addresses = BTreeSet::new();
            for record_type in [RecordType::A, RecordType::AAAA] {
                match self
                    .observed_fast_query_until(
                        resolver,
                        Some(node),
                        &name,
                        record_type,
                        true,
                        deadline,
                        None,
                    )
                    .await
                {
                    Ok(response) => {
                        addresses.extend(
                            response_records(&response, record_type)
                                .into_iter()
                                .filter_map(|record| record.value.parse::<IpAddr>().ok()),
                        );
                    }
                    Err(error)
                        if deadline
                            .is_some_and(|deadline| deadline <= tokio::time::Instant::now()) =>
                    {
                        return Err(error).context("budget DNS autoritaire atteint");
                    }
                    Err(_) => {}
                }
            }
            result.push((
                name,
                addresses
                    .into_iter()
                    .take(MAX_ADDRESSES_PER_NAMESERVER)
                    .collect(),
            ));
        }
        Ok(result)
    }

    pub async fn authoritative_servers(&self, domain: &str) -> Result<AuthoritativeServers> {
        self.authoritative_servers_until(domain, None).await
    }

    pub(crate) async fn authoritative_servers_until(
        &self,
        domain: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<AuthoritativeServers> {
        authoritative_servers_cached(&self.authoritative_server_cache, domain, |key| async move {
            self.load_authoritative_servers(&key, deadline).await
        })
        .await
    }
}
