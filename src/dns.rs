use crate::model::{
    DnsBenchmarkResult, DnsRecord, ResolvedHost, ResolverMetric, ResolverTestResult,
};
use anyhow::{Context, Result, bail};
use futures_util::{Stream, StreamExt, stream};
use hickory_net::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RData, Record};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::proto::rr::RecordType;
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OnceCell, oneshot};

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);
const UDP_SOCKET_BUFFER_BYTES: usize = 16 * 1024 * 1024;
type AuthoritativeServers = Vec<(String, Vec<IpAddr>)>;
type AuthoritativeServerCell = Arc<OnceCell<AuthoritativeServers>>;

/// Compatibilité locale avec les anciens accesseurs Hickory. La version 0.26
/// expose ces valeurs directement; les centraliser ici garde le moteur DNS
/// lisible et rend la migration vérifiable.
trait MessageCompat {
    fn id(&self) -> u16;
    fn set_id(&mut self, id: u16) -> &mut Self;
    fn message_type(&self) -> MessageType;
    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self;
    fn op_code(&self) -> OpCode;
    fn set_op_code(&mut self, op_code: OpCode) -> &mut Self;
    fn queries(&self) -> &[Query];
    fn answers(&self) -> &[Record];
    fn truncated(&self) -> bool;
    #[cfg(test)]
    fn set_truncated(&mut self, truncated: bool) -> &mut Self;
    #[cfg(test)]
    fn recursion_desired(&self) -> bool;
    fn set_recursion_desired(&mut self, desired: bool) -> &mut Self;
    fn authoritative(&self) -> bool;
    fn authentic_data(&self) -> bool;
    fn response_code(&self) -> ResponseCode;
    #[cfg(test)]
    fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self;
    #[cfg(test)]
    fn extensions(&self) -> Option<&Edns>;
}

impl MessageCompat for Message {
    fn id(&self) -> u16 {
        self.metadata.id
    }

    fn set_id(&mut self, id: u16) -> &mut Self {
        self.metadata.id = id;
        self
    }

    fn message_type(&self) -> MessageType {
        self.metadata.message_type
    }

    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.metadata.message_type = message_type;
        self
    }

    fn op_code(&self) -> OpCode {
        self.metadata.op_code
    }

    fn set_op_code(&mut self, op_code: OpCode) -> &mut Self {
        self.metadata.op_code = op_code;
        self
    }

    fn queries(&self) -> &[Query] {
        &self.queries
    }

    fn answers(&self) -> &[Record] {
        &self.answers
    }

    fn truncated(&self) -> bool {
        self.metadata.truncation
    }

    #[cfg(test)]
    fn set_truncated(&mut self, truncated: bool) -> &mut Self {
        self.metadata.truncation = truncated;
        self
    }

    #[cfg(test)]
    fn recursion_desired(&self) -> bool {
        self.metadata.recursion_desired
    }

    fn set_recursion_desired(&mut self, desired: bool) -> &mut Self {
        self.metadata.recursion_desired = desired;
        self
    }

    fn authoritative(&self) -> bool {
        self.metadata.authoritative
    }

    fn authentic_data(&self) -> bool {
        self.metadata.authentic_data
    }

    fn response_code(&self) -> ResponseCode {
        self.metadata.response_code
    }

    #[cfg(test)]
    fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self {
        self.metadata.response_code = response_code;
        self
    }

    #[cfg(test)]
    fn extensions(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }
}

trait RecordCompat {
    fn name(&self) -> &Name;
    fn data(&self) -> &RData;
    fn ttl(&self) -> u32;
}

impl RecordCompat for Record {
    fn name(&self) -> &Name {
        &self.name
    }

    fn data(&self) -> &RData {
        &self.data
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }
}

pub(crate) fn bind_buffered_udp(address: SocketAddr) -> Result<UdpSocket> {
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

#[derive(Debug, Clone)]
pub enum DnsResolutionOutcome {
    Positive(ResolvedHost),
    Negative { fqdn: String },
    Indeterminate { fqdn: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WildcardProbeOutcome {
    Wildcard(BTreeSet<String>),
    Normal,
    Indeterminate,
}

impl DnsResolutionOutcome {
    pub fn fqdn(&self) -> &str {
        match self {
            Self::Positive(answer) => &answer.fqdn,
            Self::Negative { fqdn } | Self::Indeterminate { fqdn } => fqdn,
        }
    }

    pub const fn answer(&self) -> Option<&ResolvedHost> {
        match self {
            Self::Positive(answer) => Some(answer),
            Self::Negative { .. } | Self::Indeterminate { .. } => None,
        }
    }
}

#[derive(Debug)]
enum RecordLookupOutcome {
    Positive(Vec<DnsRecord>),
    Negative,
    Indeterminate,
}

fn merge_record_lookup_outcomes(
    first: RecordLookupOutcome,
    second: RecordLookupOutcome,
) -> RecordLookupOutcome {
    match (first, second) {
        (RecordLookupOutcome::Positive(mut records), RecordLookupOutcome::Positive(more)) => {
            records.extend(more);
            records.sort_by(|left, right| {
                (&left.record_type, &left.value).cmp(&(&right.record_type, &right.value))
            });
            records.dedup_by(|left, right| {
                left.record_type == right.record_type && left.value == right.value
            });
            RecordLookupOutcome::Positive(records)
        }
        (RecordLookupOutcome::Positive(records), _)
        | (_, RecordLookupOutcome::Positive(records)) => RecordLookupOutcome::Positive(records),
        (RecordLookupOutcome::Negative, RecordLookupOutcome::Negative) => {
            RecordLookupOutcome::Negative
        }
        _ => RecordLookupOutcome::Indeterminate,
    }
}

/// Poll both address families together. A validated positive establishes that
/// the owner is live, so the other family can be cancelled immediately. A
/// negative remains deliberately strict and is returned only after both
/// families independently report NXDOMAIN.
async fn first_positive_or_both<A, Aaaa>(a: A, aaaa: Aaaa) -> RecordLookupOutcome
where
    A: std::future::Future<Output = RecordLookupOutcome>,
    Aaaa: std::future::Future<Output = RecordLookupOutcome>,
{
    tokio::pin!(a);
    tokio::pin!(aaaa);
    tokio::select! {
        a = &mut a => {
            if matches!(&a, RecordLookupOutcome::Positive(_)) {
                a
            } else {
                merge_record_lookup_outcomes(a, aaaa.await)
            }
        }
        aaaa = &mut aaaa => {
            if matches!(&aaaa, RecordLookupOutcome::Positive(_)) {
                aaaa
            } else {
                merge_record_lookup_outcomes(a.await, aaaa)
            }
        }
    }
}

async fn first_true_or_both<A, B>(first: A, second: B) -> bool
where
    A: std::future::Future<Output = bool>,
    B: std::future::Future<Output = bool>,
{
    tokio::pin!(first);
    tokio::pin!(second);
    tokio::select! {
        confirmed = &mut first => {
            if confirmed {
                true
            } else {
                second.await
            }
        }
        confirmed = &mut second => {
            if confirmed {
                true
            } else {
                first.await
            }
        }
    }
}

fn positive_consensus(fqdn: &str, positives: Vec<Vec<DnsRecord>>) -> DnsResolutionOutcome {
    let resolver_count = positives.len().min(u16::MAX as usize) as u16;
    let mut records = positives.into_iter().flatten().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        (&left.record_type, &left.value).cmp(&(&right.record_type, &right.value))
    });
    records
        .dedup_by(|left, right| left.record_type == right.record_type && left.value == right.value);
    DnsResolutionOutcome::Positive(ResolvedHost {
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

fn positive_quorum(resolver_count: usize) -> usize {
    match resolver_count {
        0 | 1 => 1,
        2 | 3 => 2,
        count => count / 2 + 1,
    }
}

async fn collect_consensus_results<S>(
    fqdn: &str,
    required: usize,
    results: S,
) -> DnsResolutionOutcome
where
    S: Stream<Item = RecordLookupOutcome>,
{
    tokio::pin!(results);
    let mut positives = Vec::new();
    let mut negatives = 0_usize;
    let mut indeterminate = 0_usize;
    while let Some(result) = results.next().await {
        match result {
            RecordLookupOutcome::Positive(records) => {
                positives.push(records);
                if positives.len() >= required {
                    // Dropping the stream cancels slower resolver queries once a
                    // positive quorum has already established a live answer.
                    return positive_consensus(fqdn, positives);
                }
            }
            RecordLookupOutcome::Negative => negatives += 1,
            RecordLookupOutcome::Indeterminate => indeterminate += 1,
        }
    }
    if positives.is_empty() && negatives >= required && indeterminate == 0 {
        DnsResolutionOutcome::Negative {
            fqdn: fqdn.to_owned(),
        }
    } else {
        DnsResolutionOutcome::Indeterminate {
            fqdn: fqdn.to_owned(),
        }
    }
}

fn classify_host_lookup(fqdn: &str, outcome: RecordLookupOutcome) -> DnsResolutionOutcome {
    match outcome {
        RecordLookupOutcome::Positive(records) => positive_consensus(fqdn, vec![records]),
        RecordLookupOutcome::Negative => DnsResolutionOutcome::Negative {
            fqdn: fqdn.to_owned(),
        },
        RecordLookupOutcome::Indeterminate => DnsResolutionOutcome::Indeterminate {
            fqdn: fqdn.to_owned(),
        },
    }
}

async fn authoritative_servers_cached<F, Fut>(
    cache: &tokio::sync::Mutex<HashMap<String, AuthoritativeServerCell>>,
    domain: &str,
    loader: F,
) -> Result<AuthoritativeServers>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<AuthoritativeServers>>,
{
    let key = domain.trim_end_matches('.').to_ascii_lowercase();
    let cell = {
        let mut cache = cache.lock().await;
        cache
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone()
    };
    cell.get_or_try_init(|| loader(key)).await.cloned()
}

fn classify_wildcard_samples(
    non_empty: Vec<BTreeSet<String>>,
    negatives: usize,
    total_samples: usize,
) -> WildcardProbeOutcome {
    if !non_empty.is_empty() && negatives > 0 {
        return WildcardProbeOutcome::Indeterminate;
    }
    if non_empty.len() >= 3 {
        let mut samples = non_empty.into_iter();
        let mut signature = samples.next().unwrap_or_default();
        for sample in samples {
            signature.retain(|record| sample.contains(record));
        }
        if signature.is_empty() {
            WildcardProbeOutcome::Indeterminate
        } else {
            WildcardProbeOutcome::Wildcard(signature)
        }
    } else if non_empty.is_empty() && negatives >= 3 && negatives == total_samples {
        WildcardProbeOutcome::Normal
    } else {
        WildcardProbeOutcome::Indeterminate
    }
}

/// Return a result only when the samples already satisfy the strict wildcard
/// classifier. An indeterminate first stage must collect more evidence: it can
/// represent timeouts, a rotating wildcard, or a mix of positive and negative
/// answers, and must never be shortened into a normal zone.
fn conclusive_wildcard_outcome(
    non_empty: &[BTreeSet<String>],
    negatives: usize,
) -> Option<WildcardProbeOutcome> {
    match classify_wildcard_samples(non_empty.to_vec(), negatives, 3) {
        outcome @ (WildcardProbeOutcome::Wildcard(_) | WildcardProbeOutcome::Normal) => {
            Some(outcome)
        }
        WildcardProbeOutcome::Indeterminate => None,
    }
}

fn normalized_dns_name(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

/// Keep only records reachable from the original question owner. DNS answer
/// sections may contain a CNAME chain, but unrelated records must never turn a
/// candidate into a positive result. The reachability pass is independent from
/// answer ordering and also handles multi-hop and cyclic CNAME responses.
fn records_for_query(
    answers: &[Record],
    query_name: &Name,
    record_type: RecordType,
) -> Vec<DnsRecord> {
    let mut reachable = BTreeSet::from([normalized_dns_name(&query_name.to_utf8())]);
    loop {
        let mut changed = false;
        for record in answers {
            if record.record_type() != RecordType::CNAME
                || !reachable.contains(&normalized_dns_name(&record.name().to_utf8()))
            {
                continue;
            }
            changed |= reachable.insert(normalized_dns_name(&record.data().to_string()));
        }
        if !changed {
            break;
        }
    }

    answers
        .iter()
        .filter(|record| {
            reachable.contains(&normalized_dns_name(&record.name().to_utf8()))
                && (record.record_type() == record_type
                    || record.record_type() == RecordType::CNAME)
        })
        .map(|record| DnsRecord {
            record_type: record.record_type().to_string(),
            value: record.data().to_string().trim_end_matches('.').to_owned(),
            ttl: record.ttl(),
        })
        .collect()
}

fn response_records(response: &Message, record_type: RecordType) -> Vec<DnsRecord> {
    response
        .queries()
        .first()
        .map(|query| records_for_query(response.answers(), query.name(), record_type))
        .unwrap_or_default()
}

fn is_definitive_nxdomain(response: &Message) -> bool {
    !response.truncated()
        && response.response_code() == ResponseCode::NXDomain
        && response.answers().is_empty()
}

fn classify_address_response(
    response: Result<Message>,
    record_type: RecordType,
) -> RecordLookupOutcome {
    let Ok(response) = response else {
        return RecordLookupOutcome::Indeterminate;
    };
    if response.truncated() {
        return RecordLookupOutcome::Indeterminate;
    }
    let records = response_records(&response, record_type);
    if !records.is_empty() {
        RecordLookupOutcome::Positive(records)
    } else if is_definitive_nxdomain(&response) {
        RecordLookupOutcome::Negative
    } else {
        RecordLookupOutcome::Indeterminate
    }
}

fn authoritative_response_confirms(response: Result<Message>, record_type: RecordType) -> bool {
    response.is_ok_and(|response| {
        response.authoritative()
            && !response.truncated()
            && !response_records(&response, record_type).is_empty()
    })
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
    authoritative_resolvers: Arc<Mutex<HashMap<SocketAddr, Arc<FastResolver>>>>,
    authoritative_server_cache: Arc<tokio::sync::Mutex<HashMap<String, AuthoritativeServerCell>>>,
}

struct FastResolver {
    address: SocketAddr,
    transport: OnceCell<Arc<FastUdpTransport>>,
}

struct FastUdpTransport {
    socket: Arc<UdpSocket>,
    pending: Arc<tokio::sync::Mutex<HashMap<u16, PendingDnsQuery>>>,
    slots: Arc<tokio::sync::Semaphore>,
    next_id: AtomicU16,
    receiver: tokio::task::AbortHandle,
}

struct PendingDnsQuery {
    name: Name,
    record_type: RecordType,
    dns_class: DNSClass,
    sender: oneshot::Sender<Vec<u8>>,
}

struct PendingQueryGuard {
    id: u16,
    pending: Arc<tokio::sync::Mutex<HashMap<u16, PendingDnsQuery>>>,
}

impl Drop for PendingQueryGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.try_lock() {
            pending.remove(&self.id);
            return;
        }
        let id = self.id;
        let pending = self.pending.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                pending.lock().await.remove(&id);
            });
        }
    }
}

fn dns_tcp_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(16)))
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
        let pending = Arc::new(tokio::sync::Mutex::new(
            HashMap::<u16, PendingDnsQuery>::new(),
        ));
        let receiver_socket = socket.clone();
        let receiver_pending = pending.clone();
        let receiver = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            loop {
                let length = match receiver_socket.recv(&mut buffer).await {
                    Ok(length) => length,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let Ok(response) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                if response.message_type() != MessageType::Response
                    || response.op_code() != OpCode::Query
                    || response.queries().len() != 1
                {
                    continue;
                }
                let id = response.id();
                let question = &response.queries()[0];
                let mut pending = receiver_pending.lock().await;
                let correlated = pending.get(&id).is_some_and(|request| {
                    question.name() == &request.name
                        && question.query_type() == request.record_type
                        && question.query_class() == request.dns_class
                });
                if correlated {
                    let request = pending.remove(&id).expect("requête DNS présente");
                    drop(pending);
                    let _ = request.sender.send(buffer[..length].to_vec());
                }
            }
        });
        Ok(Arc::new(Self {
            socket,
            pending,
            slots: Arc::new(tokio::sync::Semaphore::new(4_096)),
            next_id: AtomicU16::new(1),
            receiver: receiver.abort_handle(),
        }))
    }

    async fn query(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout_duration: Duration,
    ) -> Result<Message> {
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .context("transport DNS UDP fermé")?;
        let id = loop {
            let candidate = self.next_id.fetch_add(1, Ordering::Relaxed);
            if !self.pending.lock().await.contains_key(&candidate) {
                break candidate;
            }
        };
        let name = Name::from_str(&format!("{}.", fqdn.trim_end_matches('.')))?;
        let query = Query::query(name.clone(), record_type);
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        let mut edns = Edns::new();
        edns.set_max_payload(1_232)
            .set_version(0)
            .set_dnssec_ok(true);
        message
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(recursion_desired)
            .add_query(query.clone())
            .set_edns(edns);
        let payload = message.to_vec()?;
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(
            id,
            PendingDnsQuery {
                name: name.clone(),
                record_type,
                dns_class: query.query_class(),
                sender,
            },
        );
        // Cette garde retire l'identifiant même si Ctrl+C ou la deadline
        // globale annule le future pendant l'attente de la réponse.
        let _pending_guard = PendingQueryGuard {
            id,
            pending: self.pending.clone(),
        };
        if let Err(error) = self.socket.send(&payload).await {
            return Err(error.into());
        }
        let response = match tokio::time::timeout(timeout_duration, receiver).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => return Err(error.into()),
        };
        let response = Message::from_vec(&response)?;
        if response.id() != id
            || response.message_type() != MessageType::Response
            || response.op_code() != OpCode::Query
            || response.queries().len() != 1
            || response.queries()[0].name() != &name
            || response.queries()[0].query_type() != record_type
            || response.queries()[0].query_class() != query.query_class()
        {
            bail!("réponse DNS UDP non corrélée");
        }
        Ok(response)
    }
}

impl Drop for FastUdpTransport {
    fn drop(&mut self) {
        self.receiver.abort();
    }
}

async fn query_tcp(
    address: SocketAddr,
    fqdn: &str,
    record_type: RecordType,
    recursion_desired: bool,
    timeout_duration: Duration,
) -> Result<Message> {
    let _tcp_slot = dns_tcp_slots()
        .clone()
        .acquire_owned()
        .await
        .context("transport DNS TCP fermé")?;
    let id = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed) as u16;
    let name = Name::from_str(&format!("{}.", fqdn.trim_end_matches('.')))?;
    let query = Query::query(name.clone(), record_type);
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    let mut edns = Edns::new();
    edns.set_max_payload(1_232)
        .set_version(0)
        .set_dnssec_ok(true);
    message
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(recursion_desired)
        .add_query(query.clone())
        .set_edns(edns);
    let payload = message.to_vec()?;
    let response = tokio::time::timeout(timeout_duration, async move {
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await?;
        stream.write_all(&payload).await?;
        let length = stream.read_u16().await? as usize;
        if length < 12 {
            bail!("réponse DNS TCP trop courte");
        }
        let mut response = vec![0_u8; length];
        stream.read_exact(&mut response).await?;
        Ok::<_, anyhow::Error>(response)
    })
    .await
    .context("délai DNS TCP dépassé")??;
    let response = Message::from_vec(&response)?;
    if response.id() != id
        || response.message_type() != MessageType::Response
        || response.op_code() != OpCode::Query
        || response.queries().len() != 1
        || response.queries()[0].name() != &name
        || response.queries()[0].query_type() != record_type
        || response.queries()[0].query_class() != query.query_class()
    {
        bail!("réponse DNS TCP non corrélée");
    }
    Ok(response)
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
        let response = transport
            .query(fqdn, record_type, recursion_desired, timeout)
            .await?;
        if response.truncated() {
            query_tcp(self.address, fqdn, record_type, recursion_desired, timeout).await
        } else {
            Ok(response)
        }
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

/// Keeps resolver load accounting correct when a query future is cancelled by
/// a scan deadline. Without a drop guard, cancellation between `fetch_add` and
/// the matching `fetch_sub` would permanently inflate the resolver score.
struct ResolverInflightGuard<'a> {
    inflight: &'a AtomicUsize,
}

impl<'a> ResolverInflightGuard<'a> {
    fn new(inflight: &'a AtomicUsize) -> Self {
        inflight.fetch_add(1, Ordering::Relaxed);
        Self { inflight }
    }
}

impl Drop for ResolverInflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
    }
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
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
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
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Partage le même cadenceur avec un second moteur (par exemple le
    /// consensus trusted) afin que la limite CLI soit réellement commune.
    pub fn share_rate_limit_with(mut self, other: &Self) -> Self {
        self.rate_limit = other.rate_limit;
        self.next_query_at = other.next_query_at.clone();
        self
    }

    pub const fn concurrency(&self) -> usize {
        self.concurrency
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

    /// Acquire the shared global DNS cadence slot without waiting beyond a
    /// caller-owned phase deadline. Direct DNS transports such as the NSEC TCP
    /// walker use this hook because they do not pass through the resolver
    /// lookup helpers that normally acquire the same limiter.
    pub(crate) async fn wait_for_rate_slot_before(&self, deadline: tokio::time::Instant) -> bool {
        if deadline <= tokio::time::Instant::now() {
            return false;
        }
        if self.rate_limit == 0 {
            return true;
        }
        let spacing = Duration::from_secs_f64(1.0 / self.rate_limit as f64);
        let Ok(mut next) = tokio::time::timeout_at(deadline, self.next_query_at.lock()).await
        else {
            return false;
        };
        let now = Instant::now();
        if *next > now
            && tokio::time::timeout_at(deadline, tokio::time::sleep(*next - now))
                .await
                .is_err()
        {
            return false;
        }
        *next = Instant::now() + spacing;
        true
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
        let required = positive_quorum(self.fast_resolvers.len());
        let results = stream::iter(self.fast_resolvers.iter())
            .map(|resolver| async move {
                let query_a = async {
                    self.wait_for_rate_slot().await;
                    classify_address_response(
                        resolver
                            .query(fqdn, RecordType::A, true, self.timeout)
                            .await,
                        RecordType::A,
                    )
                };
                let query_aaaa = async {
                    self.wait_for_rate_slot().await;
                    classify_address_response(
                        resolver
                            .query(fqdn, RecordType::AAAA, true, self.timeout)
                            .await,
                        RecordType::AAAA,
                    )
                };
                first_positive_or_both(query_a, query_aaaa).await
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
        let Some(root_domain) = crate::util::registrable_domain(fqdn) else {
            return false;
        };
        let mut servers = None;
        let labels = fqdn.trim_end_matches('.').split('.').collect::<Vec<_>>();
        let root_labels = root_domain.split('.').count();
        let first_parent = usize::from(labels.len() > root_labels);
        for start in first_parent..=labels.len().saturating_sub(root_labels) {
            let zone = labels[start..].join(".");
            if let Ok(candidate) = self.authoritative_servers(&zone).await
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
                    self.wait_for_rate_slot().await;
                    authoritative_response_confirms(
                        resolver
                            .query(fqdn, RecordType::A, false, self.timeout)
                            .await,
                        RecordType::A,
                    )
                };
                let aaaa = async {
                    self.wait_for_rate_slot().await;
                    authoritative_response_confirms(
                        resolver
                            .query(fqdn, RecordType::AAAA, false, self.timeout)
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

    fn authoritative_resolver(&self, address: SocketAddr) -> Result<Arc<FastResolver>> {
        let mut resolvers = self
            .authoritative_resolvers
            .lock()
            .map_err(|_| anyhow::anyhow!("cache des résolveurs autoritaires empoisonné"))?;
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

    async fn resolver_reports_strict_nxdomain(&self, index: usize, fqdn: &str) -> bool {
        let (Some(resolver), Some(node)) =
            (self.fast_resolvers.get(index), self.resolvers.get(index))
        else {
            return false;
        };
        self.wait_for_rate_slot().await;
        let _inflight = ResolverInflightGuard::new(&node.inflight);
        let started = Instant::now();
        let response = resolver
            .query(fqdn, RecordType::A, true, self.timeout)
            .await;
        let strict = response.as_ref().is_ok_and(is_definitive_nxdomain);
        let operational = response.as_ref().is_ok_and(|response| {
            !response.truncated()
                && matches!(
                    response.response_code(),
                    ResponseCode::NoError | ResponseCode::NXDomain
                )
        });
        if let Ok(mut state) = node.state.lock() {
            state.requests += 1;
            state.total_ms = state
                .total_ms
                .saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
            if operational {
                state.successes += 1;
                state.consecutive_failures = 0;
            } else {
                state.failures += 1;
                state.consecutive_failures += 1;
            }
        }
        strict
    }

    async fn discovery_nxdomain_quorum(&self, fqdn: &str) -> bool {
        let order = self
            .resolver_order()
            .into_iter()
            .filter(|index| *index < self.fast_resolvers.len())
            .take(2)
            .collect::<Vec<_>>();
        let [first, second] = order.as_slice() else {
            return false;
        };
        let (first_negative, second_negative) = tokio::join!(
            self.resolver_reports_strict_nxdomain(*first, fqdn),
            self.resolver_reports_strict_nxdomain(*second, fqdn),
        );
        first_negative && second_negative
    }

    async fn lookup_records_classified(
        &self,
        fqdn: &str,
        record_type: RecordType,
    ) -> RecordLookupOutcome {
        let order = self
            .resolver_order()
            .into_iter()
            .take(2)
            .collect::<Vec<_>>();
        self.lookup_records_classified_in_order(fqdn, record_type, &order)
            .await
    }

    async fn lookup_records_classified_in_order(
        &self,
        fqdn: &str,
        record_type: RecordType,
        order: &[usize],
    ) -> RecordLookupOutcome {
        let required_negatives = order.len().clamp(1, 2);
        let mut definitive_negatives = 0_usize;
        for index in order.iter().copied() {
            self.wait_for_rate_slot().await;
            let node = &self.resolvers[index];
            let _inflight = ResolverInflightGuard::new(&node.inflight);
            let started = Instant::now();
            let fast_response = if matches!(record_type, RecordType::A | RecordType::AAAA) {
                if let Some(resolver) = self.fast_resolvers.get(index) {
                    Some(resolver.query(fqdn, record_type, true, self.timeout).await)
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
            let result = if fast_result.is_none() && !fast_timed_out {
                if fast_response.is_some() {
                    // Le repli Hickory produit une seconde sortie réseau.
                    self.wait_for_rate_slot().await;
                }
                Some(node.resolver.lookup(fqdn, record_type).await)
            } else {
                None
            };
            let duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
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
            if let Ok(mut state) = node.state.lock() {
                state.requests += 1;
                state.total_ms = state.total_ms.saturating_add(duration_ms);
                if matches!(
                    classified,
                    RecordLookupOutcome::Positive(_) | RecordLookupOutcome::Negative
                ) {
                    state.successes += 1;
                    state.consecutive_failures = 0;
                } else {
                    state.failures += 1;
                    state.consecutive_failures += 1;
                }
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
        let engine = self.clone();
        stream::iter(addresses.into_iter().collect::<BTreeSet<_>>())
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
            .buffer_unordered(self.concurrency)
            .collect()
            .await
    }

    async fn resolve_host_classified_with_policy(
        &self,
        fqdn: &str,
        allow_discovery_fast_negative: bool,
    ) -> DnsResolutionOutcome {
        // A strict NXDOMAIN from two independent resolvers proves that the
        // owner does not exist and lets the discovery path skip AAAA. Any
        // disagreement, NODATA, CNAME, timeout, or malformed response falls
        // back to the full conservative A+AAAA path.
        if allow_discovery_fast_negative && self.discovery_nxdomain_quorum(fqdn).await {
            return DnsResolutionOutcome::Negative {
                fqdn: fqdn.to_owned(),
            };
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
            self.lookup_records_classified_in_order(fqdn, RecordType::A, &order),
            self.lookup_records_classified_in_order(fqdn, RecordType::AAAA, &order),
        )
        .await;
        classify_host_lookup(fqdn, outcome)
    }

    /// Conservative host resolution for retained state, wildcard probes,
    /// enrichment, refresh, and final validation. A negative requires the full
    /// configured discovery quorum; this method never uses the fast-negative
    /// shortcut.
    pub async fn resolve_host_classified(&self, fqdn: &str) -> DnsResolutionOutcome {
        self.resolve_host_classified_with_policy(fqdn, false).await
    }

    /// Fast classification for fresh enumeration candidates only. Callers must
    /// not use its negative outcome to demote or purge a retained/live name.
    /// Positive and indeterminate outcomes preserve the standard validation
    /// pipeline; only a qualified, discovery-only negative may short-circuit.
    pub(crate) async fn resolve_host_discovery_classified(
        &self,
        fqdn: &str,
    ) -> DnsResolutionOutcome {
        self.resolve_host_classified_with_policy(fqdn, true).await
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

    async fn resolve_many_classified_with_progress_policy<F>(
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
                        .resolve_host_classified_with_policy(&host, discovery_fast_negative)
                        .await
                }
            })
            .buffer_unordered(self.concurrency);
        let mut outcomes = Vec::new();
        while let Some(outcome) = pending.next().await {
            on_completed(&outcome);
            outcomes.push(outcome);
        }
        outcomes.sort_by(|left, right| left.fqdn().cmp(right.fqdn()));
        outcomes
    }

    async fn wildcard_probe_with_policy(
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

    async fn load_authoritative_servers(&self, domain: &str) -> Result<AuthoritativeServers> {
        if self.resolvers.is_empty() {
            bail!("aucun résolveur récursif disponible");
        }
        let resolver = self.resolvers[self.resolver_order()[0]].resolver.clone();
        self.wait_for_rate_slot().await;
        let lookup = match resolver.lookup(domain, RecordType::NS).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() || error.is_nx_domain() => {
                return Ok(Vec::new());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("résolution NS de {domain}"));
            }
        };
        let names: BTreeSet<String> = lookup
            .answers()
            .iter()
            .filter(|record| record.record_type() == RecordType::NS)
            .map(|record| record.data().to_string().trim_end_matches('.').to_owned())
            .collect();
        let mut result = Vec::new();
        for name in names {
            self.wait_for_rate_slot().await;
            let addresses = resolver
                .lookup_ip(name.as_str())
                .await
                .map(|lookup| lookup.iter().collect())
                .unwrap_or_default();
            result.push((name, addresses));
        }
        Ok(result)
    }

    pub async fn authoritative_servers(&self, domain: &str) -> Result<AuthoritativeServers> {
        authoritative_servers_cached(&self.authoritative_server_cache, domain, |key| async move {
            self.load_authoritative_servers(&key).await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::rr::rdata::{A, CNAME};

    #[test]
    fn resolver_inflight_guard_releases_load_when_a_future_is_cancelled() {
        let inflight = AtomicUsize::new(0);
        {
            let _guard = ResolverInflightGuard::new(&inflight);
            assert_eq!(inflight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(inflight.load(Ordering::Relaxed), 0);
    }

    fn positive_records(value: &str) -> Vec<DnsRecord> {
        vec![DnsRecord {
            record_type: "A".to_owned(),
            value: value.to_owned(),
            ttl: 60,
        }]
    }

    #[test]
    fn response_records_follow_only_the_question_cname_chain() {
        let query_name = Name::from_str("api.example.test.").unwrap();
        let alias_name = Name::from_str("edge.example.test.").unwrap();
        let final_name = Name::from_str("origin.example.test.").unwrap();
        let unrelated_name = Name::from_str("poison.example.test.").unwrap();
        let mut response = Message::new(7, MessageType::Response, OpCode::Query);
        response
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(query_name.clone(), RecordType::A))
            // Put the terminal address before the CNAME records to verify that
            // chain validation does not depend on answer ordering.
            .add_answer(Record::from_rdata(
                final_name.clone(),
                60,
                RData::A(A("192.0.2.20".parse().unwrap())),
            ))
            .add_answer(Record::from_rdata(
                unrelated_name.clone(),
                60,
                RData::A(A("192.0.2.250".parse().unwrap())),
            ))
            .add_answer(Record::from_rdata(
                alias_name.clone(),
                60,
                RData::CNAME(CNAME(final_name)),
            ))
            .add_answer(Record::from_rdata(
                query_name,
                60,
                RData::CNAME(CNAME(alias_name)),
            ))
            .add_answer(Record::from_rdata(
                unrelated_name,
                60,
                RData::CNAME(CNAME(Name::from_str("elsewhere.example.test.").unwrap())),
            ));

        let records = response_records(&response, RecordType::A);
        let signatures = records
            .iter()
            .map(|record| format!("{}:{}", record.record_type, record.value))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            signatures,
            BTreeSet::from([
                "A:192.0.2.20".to_owned(),
                "CNAME:edge.example.test".to_owned(),
                "CNAME:origin.example.test".to_owned(),
            ])
        );
        assert!(!records.iter().any(|record| {
            record.value == "192.0.2.250" || record.value == "elsewhere.example.test"
        }));
    }

    #[tokio::test]
    async fn positive_consensus_uses_a_majority_above_three_resolvers() {
        assert_eq!(positive_quorum(0), 1);
        assert_eq!(positive_quorum(1), 1);
        assert_eq!(positive_quorum(2), 2);
        assert_eq!(positive_quorum(3), 2);
        assert_eq!(positive_quorum(4), 3);
        assert_eq!(positive_quorum(5), 3);
        assert_eq!(positive_quorum(6), 4);

        let minority = collect_consensus_results(
            "minority.example.test",
            positive_quorum(4),
            stream::iter([
                RecordLookupOutcome::Positive(positive_records("192.0.2.10")),
                RecordLookupOutcome::Positive(positive_records("192.0.2.10")),
                RecordLookupOutcome::Negative,
                RecordLookupOutcome::Negative,
            ]),
        )
        .await;
        assert!(matches!(
            minority,
            DnsResolutionOutcome::Indeterminate { .. }
        ));

        let majority = collect_consensus_results(
            "majority.example.test",
            positive_quorum(5),
            stream::iter([
                RecordLookupOutcome::Positive(positive_records("192.0.2.10")),
                RecordLookupOutcome::Positive(positive_records("192.0.2.11")),
                RecordLookupOutcome::Positive(positive_records("192.0.2.12")),
                RecordLookupOutcome::Negative,
                RecordLookupOutcome::Negative,
            ]),
        )
        .await;
        let DnsResolutionOutcome::Positive(answer) = majority else {
            panic!("a strict majority of positive resolvers was not accepted");
        };
        assert_eq!(answer.resolver_count, 3);
    }

    #[tokio::test]
    async fn authoritative_family_confirmation_cancels_a_silent_sibling() {
        let confirmed = tokio::time::timeout(
            Duration::from_millis(100),
            first_true_or_both(async { true }, async {
                std::future::pending::<bool>().await
            }),
        )
        .await
        .expect("authoritative confirmation waited for an irrelevant silent family");
        assert!(confirmed);
    }

    #[tokio::test]
    async fn one_family_nxdomain_never_shortcuts_a_silent_sibling() {
        let outcome = tokio::time::timeout(
            Duration::from_millis(50),
            first_positive_or_both(async { RecordLookupOutcome::Negative }, async {
                std::future::pending::<RecordLookupOutcome>().await
            }),
        )
        .await;
        assert!(outcome.is_err());
    }

    async fn nxdomain_resolver() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut buffer = [0_u8; 2_048];
                let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, task)
    }

    fn consensus_test_engine(addresses: Vec<SocketAddr>) -> DnsEngine {
        DnsEngine {
            resolvers: Arc::new(Vec::new()),
            fast_resolvers: Arc::new(
                addresses
                    .into_iter()
                    .map(|address| FastResolver {
                        address,
                        transport: OnceCell::new(),
                    })
                    .collect(),
            ),
            concurrency: 8,
            timeout: Duration::from_millis(100),
            rate_limit: 0,
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    fn resolver_node_at(address: SocketAddr, timeout: Duration) -> ResolverNode {
        let mut connection = ConnectionConfig::udp();
        connection.port = address.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(address.ip(), true, vec![connection])],
        );
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().timeout = timeout;
        builder.options_mut().attempts = 1;
        builder.options_mut().cache_size = 0;
        ResolverNode {
            label: address.to_string(),
            resolver: Arc::new(builder.build().unwrap()),
            state: Mutex::new(ResolverState::default()),
            inflight: AtomicUsize::new(0),
        }
    }

    fn discovery_test_engine(addresses: &[SocketAddr], timeout: Duration) -> DnsEngine {
        DnsEngine {
            resolvers: Arc::new(
                addresses
                    .iter()
                    .copied()
                    .map(|address| resolver_node_at(address, timeout))
                    .collect(),
            ),
            fast_resolvers: Arc::new(
                addresses
                    .iter()
                    .copied()
                    .map(|address| FastResolver {
                        address,
                        transport: OnceCell::new(),
                    })
                    .collect(),
            ),
            concurrency: 8,
            timeout,
            rate_limit: 0,
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    fn hickory_only_test_engine(address: SocketAddr, timeout: Duration) -> DnsEngine {
        DnsEngine {
            resolvers: Arc::new(vec![resolver_node_at(address, timeout)]),
            fast_resolvers: Arc::new(Vec::new()),
            concurrency: 8,
            timeout,
            rate_limit: 0,
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    async fn counting_nxdomain_resolver()
    -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, requests, task)
    }

    async fn target_positive_a_resolver(
        target: &str,
        value: &str,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let target = format!("{}.", target.trim_end_matches('.'));
        let value = value.parse().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                let question = &message.queries()[0];
                let positive = question.name().to_utf8().eq_ignore_ascii_case(&target)
                    && question.query_type() == RecordType::A;
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(if positive {
                        ResponseCode::NoError
                    } else {
                        ResponseCode::NXDomain
                    });
                if positive {
                    message.add_answer(Record::from_rdata(
                        message.queries()[0].name().clone(),
                        60,
                        RData::A(A(value)),
                    ));
                }
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, requests, task)
    }

    async fn target_positive_a_silent_aaaa_resolver(
        target: &str,
        value: &str,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let target = format!("{}.", target.trim_end_matches('.'));
        let value = value.parse().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                let question = &message.queries()[0];
                let target_query = question.name().to_utf8().eq_ignore_ascii_case(&target);
                if target_query && question.query_type() == RecordType::AAAA {
                    continue;
                }
                let positive = target_query && question.query_type() == RecordType::A;
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(if positive {
                        ResponseCode::NoError
                    } else {
                        ResponseCode::NXDomain
                    });
                if positive {
                    message.add_answer(Record::from_rdata(
                        message.queries()[0].name().clone(),
                        60,
                        RData::A(A(value)),
                    ));
                }
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, requests, task)
    }

    async fn target_nodata_resolver(
        target: &str,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let target = format!("{}.", target.trim_end_matches('.'));
        let task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                let target_query = message.queries()[0]
                    .name()
                    .to_utf8()
                    .eq_ignore_ascii_case(&target);
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(if target_query {
                        ResponseCode::NoError
                    } else {
                        ResponseCode::NXDomain
                    });
                message.metadata.recursion_available = true;
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, requests, task)
    }

    async fn cname_nxdomain_resolver(
        target: &str,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();
        let target = format!("{}.", target.trim_end_matches('.'));
        let cname = Name::from_str("missing-target.example.test.").unwrap();
        let task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                let target_query = message.queries()[0]
                    .name()
                    .to_utf8()
                    .eq_ignore_ascii_case(&target);
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                if target_query {
                    message.add_answer(Record::from_rdata(
                        message.queries()[0].name().clone(),
                        60,
                        RData::CNAME(CNAME(cname.clone())),
                    ));
                }
                server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, requests, task)
    }

    #[tokio::test]
    async fn consensus_returns_as_soon_as_a_positive_quorum_is_ready() {
        let results = stream::iter(vec![
            Box::pin(async { RecordLookupOutcome::Positive(positive_records("192.0.2.10")) })
                as futures_util::future::BoxFuture<'static, RecordLookupOutcome>,
            Box::pin(async { RecordLookupOutcome::Positive(positive_records("192.0.2.10")) }),
            Box::pin(async { std::future::pending::<RecordLookupOutcome>().await }),
        ])
        .buffer_unordered(3);
        let outcome = tokio::time::timeout(
            Duration::from_millis(250),
            collect_consensus_results("api.example.test", 2, results),
        )
        .await
        .expect("a ready positive quorum must cancel the slow tail");
        let DnsResolutionOutcome::Positive(answer) = outcome else {
            panic!("positive quorum was not accepted");
        };
        assert_eq!(answer.resolver_count, 2);
        assert_eq!(answer.records, positive_records("192.0.2.10"));
    }

    #[tokio::test]
    async fn consensus_keeps_negative_and_partial_results_conservative() {
        let negative = collect_consensus_results(
            "missing.example.test",
            2,
            stream::iter([RecordLookupOutcome::Negative, RecordLookupOutcome::Negative]),
        )
        .await;
        assert!(matches!(negative, DnsResolutionOutcome::Negative { .. }));

        let unavailable = collect_consensus_results(
            "unknown.example.test",
            2,
            stream::iter([
                RecordLookupOutcome::Negative,
                RecordLookupOutcome::Negative,
                RecordLookupOutcome::Indeterminate,
            ]),
        )
        .await;
        assert!(matches!(
            unavailable,
            DnsResolutionOutcome::Indeterminate { .. }
        ));

        let split_vote = collect_consensus_results(
            "split.example.test",
            2,
            stream::iter([
                RecordLookupOutcome::Positive(positive_records("192.0.2.20")),
                RecordLookupOutcome::Negative,
                RecordLookupOutcome::Negative,
            ]),
        )
        .await;
        assert!(matches!(
            split_vote,
            DnsResolutionOutcome::Indeterminate { .. }
        ));
    }

    #[tokio::test]
    async fn intentional_rate_queue_does_not_consume_the_network_timeout() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut buffer = [0_u8; 2_048];
                let Ok(Ok((length, peer))) =
                    tokio::time::timeout(Duration::from_millis(500), server.recv_from(&mut buffer))
                        .await
                else {
                    break;
                };
                let mut response = Message::from_vec(&buffer[..length]).unwrap();
                response
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NoError);
                if response.queries()[0].query_type() == RecordType::A {
                    response.add_answer(Record::from_rdata(
                        response.queries()[0].name().clone(),
                        60,
                        RData::A(A("192.0.2.30".parse().unwrap())),
                    ));
                }
                server
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        // Pre-consume one 200 ms rate slot so host resolution must wait in the
        // intentional queue. Its network timeout is much shorter and must not
        // begin until a packet is actually sent.
        let engine =
            DnsEngine::new_with_socket_addresses(8, Duration::from_millis(20), &[address], 5)
                .unwrap();
        engine.wait_for_rate_slot().await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            engine.resolve_host_classified("rate-limited.example.test"),
        )
        .await
        .expect("the caller's global cancellation bound remains effective");
        server_task.await.unwrap();
        let DnsResolutionOutcome::Positive(answer) = outcome else {
            panic!("the intentional rate-limit queue incorrectly consumed the network timeout");
        };
        assert_eq!(answer.records, positive_records("192.0.2.30"));
    }

    #[tokio::test]
    async fn dead_primary_does_not_hide_a_live_secondary_before_the_host_deadline() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_address = silent.local_addr().unwrap();
        let live_address = live.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut buffer = [0_u8; 2_048];
                let (length, peer) = live.recv_from(&mut buffer).await.unwrap();
                let mut response = Message::from_vec(&buffer[..length]).unwrap();
                response
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NoError);
                if response.queries()[0].query_type() == RecordType::A {
                    response.add_answer(Record::from_rdata(
                        response.queries()[0].name().clone(),
                        60,
                        RData::A(A("192.0.2.31".parse().unwrap())),
                    ));
                }
                live.send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let timeout = Duration::from_millis(50);
        let engine = DnsEngine {
            resolvers: Arc::new(vec![
                resolver_node_at(silent_address, timeout),
                resolver_node_at(live_address, timeout),
            ]),
            fast_resolvers: Arc::new(vec![
                FastResolver {
                    address: silent_address,
                    transport: OnceCell::new(),
                },
                FastResolver {
                    address: live_address,
                    transport: OnceCell::new(),
                },
            ]),
            concurrency: 8,
            timeout,
            rate_limit: 0,
            next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            selection_counter: Arc::new(AtomicU64::new(0)),
            authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
            authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(1),
            engine.resolve_host_classified("secondary.example.test"),
        )
        .await
        .expect("bounded resolver operations did not terminate");
        // The positive A answer can complete the host before the concurrently
        // issued AAAA branch reaches the mock server. Do not make teardown
        // depend on a packet that cancellation is explicitly allowed to skip.
        server.abort();
        let _ = server.await;
        let DnsResolutionOutcome::Positive(answer) = outcome else {
            panic!("the healthy secondary resolver was not reached");
        };
        assert!(
            answer
                .records
                .iter()
                .any(|record| record.value == "192.0.2.31")
        );
        drop(silent);
    }

    #[tokio::test]
    async fn authoritative_cache_is_single_flight_and_normalizes_keys() {
        let cache = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = calls.clone();
        let second_calls = calls.clone();
        let first_cache = cache.clone();
        let second_cache = cache.clone();
        let first =
            authoritative_servers_cached(&first_cache, "Example.TEST.", move |_| async move {
                first_calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(vec![(
                    "ns1.example.test".to_owned(),
                    vec!["192.0.2.53".parse().unwrap()],
                )])
            });
        let second =
            authoritative_servers_cached(&second_cache, "example.test", move |_| async move {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![(
                    "should-not-run.example.test".to_owned(),
                    vec!["192.0.2.54".parse().unwrap()],
                )])
            });
        let (first, second) = tokio::join!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(first.unwrap(), second.unwrap());
    }

    #[tokio::test]
    async fn authoritative_cache_keeps_empty_successes_but_retries_errors() {
        let empty_cache = tokio::sync::Mutex::new(HashMap::new());
        let empty_calls = Arc::new(AtomicUsize::new(0));
        let calls = empty_calls.clone();
        let first = authoritative_servers_cached(&empty_cache, "empty.test", move |_| async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        })
        .await
        .unwrap();
        let calls = empty_calls.clone();
        let second =
            authoritative_servers_cached(&empty_cache, "empty.test.", move |_| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![("unexpected.empty.test".to_owned(), Vec::new())])
            })
            .await
            .unwrap();
        assert!(first.is_empty());
        assert!(second.is_empty());
        assert_eq!(empty_calls.load(Ordering::SeqCst), 1);

        let retry_cache = tokio::sync::Mutex::new(HashMap::new());
        let retry_calls = Arc::new(AtomicUsize::new(0));
        let calls = retry_calls.clone();
        let first = authoritative_servers_cached(&retry_cache, "retry.test", move |_| async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("temporary failure"))
        })
        .await;
        assert!(first.is_err());
        let calls = retry_calls.clone();
        let second =
            authoritative_servers_cached(&retry_cache, "retry.test", move |_| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(vec![("ns.retry.test".to_owned(), Vec::new())])
            })
            .await
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(retry_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn consensus_distinguishes_nxdomain_from_an_unavailable_quorum() {
        let (first, first_task) = nxdomain_resolver().await;
        let (second, second_task) = nxdomain_resolver().await;
        let negative = consensus_test_engine(vec![first, second])
            .resolve_host_consensus_classified("missing.example.test")
            .await;
        first_task.await.unwrap();
        second_task.await.unwrap();
        assert!(matches!(negative, DnsResolutionOutcome::Negative { .. }));

        let (available, available_task) = nxdomain_resolver().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let indeterminate = consensus_test_engine(vec![available, silent.local_addr().unwrap()])
            .resolve_host_consensus_classified("unknown.example.test")
            .await;
        available_task.await.unwrap();
        assert!(matches!(
            indeterminate,
            DnsResolutionOutcome::Indeterminate { .. }
        ));
    }

    #[tokio::test]
    async fn consensus_sends_a_and_aaaa_without_waiting_for_each_other() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let mut buffer = [0_u8; 2_048];
                let received =
                    tokio::time::timeout(Duration::from_millis(500), server.recv_from(&mut buffer))
                        .await
                        .expect("A and AAAA must both be in flight")
                        .unwrap();
                let (length, peer) = received;
                requests.push((Message::from_vec(&buffer[..length]).unwrap(), peer));
            }
            let record_types = requests
                .iter()
                .map(|(message, _)| message.queries()[0].query_type())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                record_types,
                BTreeSet::from([RecordType::A, RecordType::AAAA])
            );
            for (mut response, peer) in requests {
                response
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                server
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });

        let mut engine = consensus_test_engine(vec![address]);
        engine.timeout = Duration::from_secs(2);
        let started = Instant::now();
        let outcome = engine
            .resolve_host_consensus_classified("parallel.example.test")
            .await;
        server_task.await.unwrap();
        assert!(matches!(outcome, DnsResolutionOutcome::Negative { .. }));
        assert!(started.elapsed() < Duration::from_millis(800));
    }

    #[tokio::test]
    async fn positive_a_cancels_a_silent_aaaa_before_the_network_timeout() {
        let target = "ipv4-only.example.test";
        let (address, _, server_task) =
            target_positive_a_silent_aaaa_resolver(target, "192.0.2.70").await;
        let network_timeout = Duration::from_secs(3);
        let completion_limit = Duration::from_millis(750);

        let mut consensus = consensus_test_engine(vec![address]);
        consensus.timeout = network_timeout;
        let started = Instant::now();
        let consensus_outcome = tokio::time::timeout(
            completion_limit,
            consensus.resolve_host_consensus_classified(target),
        )
        .await
        .expect("a validated A answer waited for the silent AAAA timeout");
        let DnsResolutionOutcome::Positive(answer) = consensus_outcome else {
            panic!("the consensus path discarded a validated A answer");
        };
        assert_eq!(answer.records, positive_records("192.0.2.70"));
        assert!(started.elapsed() < completion_limit);

        let conservative = discovery_test_engine(&[address], network_timeout);
        let started = Instant::now();
        let conservative_outcome = tokio::time::timeout(
            completion_limit,
            conservative.resolve_host_classified(target),
        )
        .await
        .expect("the conservative path waited for the silent AAAA timeout");
        let DnsResolutionOutcome::Positive(answer) = conservative_outcome else {
            panic!("the conservative path discarded a validated A answer");
        };
        assert_eq!(answer.records, positive_records("192.0.2.70"));
        assert!(started.elapsed() < completion_limit);

        server_task.abort();
    }

    #[tokio::test]
    async fn discovery_negative_requires_two_independent_nxdomain_resolvers() {
        let (primary, primary_requests, primary_task) = counting_nxdomain_resolver().await;
        let (secondary, secondary_requests, secondary_task) = counting_nxdomain_resolver().await;
        let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

        let first = engine
            .resolve_host_discovery_classified("first-missing.example.test")
            .await;
        assert!(matches!(first, DnsResolutionOutcome::Negative { .. }));
        assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
        assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

        let second = engine
            .resolve_host_discovery_classified("second-missing.example.test")
            .await;
        assert!(matches!(second, DnsResolutionOutcome::Negative { .. }));
        // Two A packets prove NXDOMAIN without an unnecessary AAAA query.
        assert_eq!(primary_requests.load(Ordering::SeqCst), 2);
        assert_eq!(secondary_requests.load(Ordering::SeqCst), 2);

        primary_task.abort();
        secondary_task.abort();
    }

    #[tokio::test]
    async fn qualified_fast_path_requires_explicit_nxdomain_not_nodata() {
        let target = "nodata-on-primary.example.test";
        let (primary, primary_requests, primary_task) = target_nodata_resolver(target).await;
        let (secondary, secondary_requests, secondary_task) =
            target_positive_a_resolver(target, "192.0.2.45").await;
        let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

        let outcome = engine.resolve_host_discovery_classified(target).await;
        let DnsResolutionOutcome::Positive(answer) = outcome else {
            panic!("an empty NOERROR response incorrectly stopped resolver consensus");
        };
        assert_eq!(answer.records, positive_records("192.0.2.45"));
        assert!(primary_requests.load(Ordering::SeqCst) >= 2);
        assert!(secondary_requests.load(Ordering::SeqCst) >= 2);

        primary_task.abort();
        secondary_task.abort();
    }

    #[tokio::test]
    async fn nodata_is_indeterminate_on_discovery_conservative_and_consensus_paths() {
        let target = "addressless.example.test";
        let (first, _, first_task) = target_nodata_resolver(target).await;
        let (second, _, second_task) = target_nodata_resolver(target).await;
        let engine = discovery_test_engine(&[first, second], Duration::from_millis(100));

        for outcome in [
            engine.resolve_host_discovery_classified(target).await,
            engine.resolve_host_classified(target).await,
            consensus_test_engine(vec![first, second])
                .resolve_host_consensus_classified(target)
                .await,
        ] {
            assert!(matches!(
                outcome,
                DnsResolutionOutcome::Indeterminate { .. }
            ));
        }

        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn hickory_fallback_distinguishes_nxdomain_from_nodata() {
        let target = "hickory-addressless.example.test";
        let (nodata, _, nodata_task) = target_nodata_resolver(target).await;
        let nodata_outcome = hickory_only_test_engine(nodata, Duration::from_millis(150))
            .resolve_host_classified(target)
            .await;
        assert!(matches!(
            nodata_outcome,
            DnsResolutionOutcome::Indeterminate { .. }
        ));
        nodata_task.abort();

        let (nxdomain, nxdomain_task) = nxdomain_resolver().await;
        let nxdomain_outcome = hickory_only_test_engine(nxdomain, Duration::from_millis(150))
            .resolve_host_classified("hickory-missing.example.test")
            .await;
        nxdomain_task.abort();
        assert!(matches!(
            nxdomain_outcome,
            DnsResolutionOutcome::Negative { .. }
        ));
    }

    #[tokio::test]
    async fn nxdomain_with_owner_cname_is_positive_on_every_resolution_path() {
        let target = "dangling.example.test";
        let (first, _, first_task) = cname_nxdomain_resolver(target).await;
        let (second, _, second_task) = cname_nxdomain_resolver(target).await;
        let engine = discovery_test_engine(&[first, second], Duration::from_millis(100));

        for outcome in [
            engine.resolve_host_discovery_classified(target).await,
            engine.resolve_host_classified(target).await,
            consensus_test_engine(vec![first, second])
                .resolve_host_consensus_classified(target)
                .await,
        ] {
            let DnsResolutionOutcome::Positive(answer) = outcome else {
                panic!("a dangling CNAME was classified as a missing owner");
            };
            assert!(answer.records.iter().any(|record| {
                record.record_type == "CNAME" && record.value == "missing-target.example.test"
            }));
        }

        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn discovery_disagreement_never_hides_a_live_secondary_answer() {
        let target = "live-on-secondary.example.test";
        let (primary, _, primary_task) = counting_nxdomain_resolver().await;
        let (secondary, _, secondary_task) = target_positive_a_resolver(target, "192.0.2.44").await;
        let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

        let DnsResolutionOutcome::Positive(answer) =
            engine.resolve_host_discovery_classified(target).await
        else {
            panic!("a primary NXDOMAIN hid the live secondary answer");
        };
        assert_eq!(answer.records, positive_records("192.0.2.44"));

        primary_task.abort();
        secondary_task.abort();
    }

    #[tokio::test]
    async fn conservative_and_trusted_paths_find_positive_after_primary_nxdomain() {
        let target = "live-on-secondary.example.test";
        let (primary, primary_requests, primary_task) = counting_nxdomain_resolver().await;
        let (secondary, secondary_requests, secondary_task) =
            target_positive_a_resolver(target, "192.0.2.44").await;
        let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

        let outcome = engine.resolve_host_classified(target).await;
        let DnsResolutionOutcome::Positive(answer) = outcome else {
            panic!("the conservative path stopped at the primary NXDOMAIN");
        };
        assert_eq!(answer.records, positive_records("192.0.2.44"));
        assert_eq!(primary_requests.load(Ordering::SeqCst), 2);
        assert_eq!(secondary_requests.load(Ordering::SeqCst), 2);

        // Final trusted consensus remains independent from the discovery
        // shortcut and still requires two positive resolvers.
        let (tertiary, _, tertiary_task) = target_positive_a_resolver(target, "192.0.2.44").await;
        let trusted = consensus_test_engine(vec![primary, secondary, tertiary])
            .resolve_host_consensus_classified(target)
            .await;
        let DnsResolutionOutcome::Positive(answer) = trusted else {
            panic!("trusted consensus did not retain the positive quorum");
        };
        assert_eq!(answer.resolver_count, 2);
        assert_eq!(answer.records, positive_records("192.0.2.44"));

        primary_task.abort();
        secondary_task.abort();
        tertiary_task.abort();
    }

    #[tokio::test]
    async fn strict_two_resolver_nxdomain_needs_no_cached_health_probe() {
        let primary_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary = primary_server.local_addr().unwrap();
        let primary_requests = Arc::new(AtomicUsize::new(0));
        let request_count = primary_requests.clone();
        let primary_task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = primary_server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                let question = &message.queries()[0];
                let health_aaaa = question
                    .name()
                    .to_utf8()
                    .starts_with("fellaga-negative-health-")
                    && question.query_type() == RecordType::AAAA;
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(if health_aaaa {
                        // An empty NOERROR is not a strict NXDOMAIN and must
                        // reject the one-resolver shortcut.
                        ResponseCode::NoError
                    } else {
                        ResponseCode::NXDomain
                    });
                primary_server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let (secondary, secondary_requests, secondary_task) = counting_nxdomain_resolver().await;
        let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

        let first = engine
            .resolve_host_discovery_classified("missing-after-bad-probe.example.test")
            .await;
        assert!(matches!(first, DnsResolutionOutcome::Negative { .. }));
        assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
        assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

        primary_task.abort();
        secondary_task.abort();
    }

    #[tokio::test]
    async fn discovery_quorum_timeout_falls_back_without_becoming_negative() {
        let primary_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary = primary_server.local_addr().unwrap();
        let primary_requests = Arc::new(AtomicUsize::new(0));
        let request_count = primary_requests.clone();
        let primary_task = tokio::spawn(async move {
            loop {
                let mut buffer = [0_u8; 2_048];
                let Ok((length, peer)) = primary_server.recv_from(&mut buffer).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut message = Message::from_vec(&buffer[..length]).unwrap();
                let question = &message.queries()[0];
                let drop_response = question
                    .name()
                    .to_utf8()
                    .eq_ignore_ascii_case("timeout.example.test.")
                    && question.query_type() == RecordType::A;
                if drop_response {
                    continue;
                }
                message
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                primary_server
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let (secondary, secondary_requests, secondary_task) = counting_nxdomain_resolver().await;
        let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(40));

        let warmup = engine
            .resolve_host_discovery_classified("warmup-missing.example.test")
            .await;
        assert!(matches!(warmup, DnsResolutionOutcome::Negative { .. }));
        assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
        assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

        let timed_out = engine
            .resolve_host_discovery_classified("timeout.example.test")
            .await;
        assert!(matches!(
            timed_out,
            DnsResolutionOutcome::Indeterminate { .. }
        ));
        assert!(primary_requests.load(Ordering::SeqCst) >= 3);
        assert!(secondary_requests.load(Ordering::SeqCst) >= 3);

        primary_task.abort();
        secondary_task.abort();
    }

    #[test]
    fn resolver_health_requires_a_strict_untruncated_nxdomain() {
        let mut response = Message::new(0, MessageType::Response, OpCode::Query);
        response
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NXDomain);
        assert!(is_definitive_nxdomain(&response));
        response.add_answer(Record::from_rdata(
            Name::from_str("probe.invalid.").unwrap(),
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        assert!(!is_definitive_nxdomain(&response));
        response.answers.clear();
        response.set_truncated(true);
        assert!(!is_definitive_nxdomain(&response));
        response
            .set_truncated(false)
            .set_response_code(ResponseCode::NoError);
        assert!(!is_definitive_nxdomain(&response));
        response.set_response_code(ResponseCode::ServFail);
        assert!(!is_definitive_nxdomain(&response));
    }

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
    async fn udp_transport_rejects_a_reused_id_with_the_wrong_question() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2_048];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let mut request = Message::from_vec(&buffer[..length]).unwrap();
            let mut wrong = Message::new(0, MessageType::Response, OpCode::Query);
            wrong
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_op_code(OpCode::Query)
                .set_response_code(ResponseCode::NoError)
                .add_query(Query::query(
                    Name::from_str("wrong.example.com.").unwrap(),
                    RecordType::A,
                ));
            server
                .send_to(&wrong.to_vec().unwrap(), peer)
                .await
                .unwrap();
            request
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            server
                .send_to(&request.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let transport = FastUdpTransport::connect(address).await.unwrap();
        let response = transport
            .query(
                "expected.example.com",
                RecordType::A,
                true,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        server_task.await.unwrap();
        assert_eq!(
            response.queries()[0].name().to_utf8(),
            "expected.example.com."
        );
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn truncated_udp_queries_fall_back_to_a_correlated_tcp_response() {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 2_048];
            let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer[..length]).unwrap();
            response
                .set_message_type(MessageType::Response)
                .set_truncated(true)
                .set_response_code(ResponseCode::NoError);
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap() as usize;
            let mut payload = vec![0_u8; length];
            stream.read_exact(&mut payload).await.unwrap();
            let mut response = Message::from_vec(&payload).unwrap();
            response
                .set_message_type(MessageType::Response)
                .set_truncated(false)
                .set_response_code(ResponseCode::NXDomain);
            let payload = response.to_vec().unwrap();
            stream.write_u16(payload.len() as u16).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let resolver = FastResolver {
            address,
            transport: OnceCell::new(),
        };
        let response = resolver
            .query(
                "missing.example.test",
                RecordType::A,
                true,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(!response.truncated());
    }

    #[tokio::test]
    async fn dropping_a_udp_transport_stops_its_receiver_task() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = FastUdpTransport::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        let receiver = transport.receiver.clone();
        assert!(!receiver.is_finished());
        drop(transport);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !receiver.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_udp_query_releases_its_pending_id() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = FastUdpTransport::connect(silent.local_addr().unwrap())
            .await
            .unwrap();
        let query_transport = transport.clone();
        let query = tokio::spawn(async move {
            query_transport
                .query(
                    "cancelled.example",
                    RecordType::A,
                    true,
                    Duration::from_secs(30),
                )
                .await
        });
        for _ in 0..100 {
            if !transport.pending.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(transport.pending.lock().await.len(), 1);
        query.abort();
        let _ = query.await;
        for _ in 0..100 {
            if transport.pending.lock().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(transport.pending.lock().await.is_empty());
    }

    #[test]
    fn trusted_engines_can_share_one_rate_limiter() {
        let primary = DnsEngine::new_with_rate(
            8,
            Duration::from_secs(1),
            &["1.1.1.1".parse().unwrap()],
            100,
        )
        .unwrap();
        let trusted = DnsEngine::new_with_rate(
            4,
            Duration::from_secs(1),
            &["8.8.8.8".parse().unwrap()],
            500,
        )
        .unwrap()
        .share_rate_limit_with(&primary);
        assert_eq!(trusted.rate_limit, 100);
        assert!(Arc::ptr_eq(&primary.next_query_at, &trusted.next_query_at));
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
    fn wildcard_profiles_require_an_observed_value_not_only_a_record_type() {
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
        assert!(!DnsEngine::matches_wildcard(
            &answer,
            &BTreeSet::from(["A:*".to_owned()])
        ));
        assert!(DnsEngine::matches_wildcard(
            &answer,
            &BTreeSet::from(["A:192.0.2.99".to_owned()])
        ));
        assert!(DnsEngine::exactly_matches_wildcard(
            &answer,
            &BTreeSet::from(["A:192.0.2.99".to_owned()])
        ));
        assert!(!DnsEngine::matches_wildcard(
            &answer,
            &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
        ));
        let aliased = ResolvedHost {
            fqdn: "random.example.com".to_owned(),
            records: vec![
                DnsRecord {
                    record_type: "CNAME".to_owned(),
                    value: "wild.example.com".to_owned(),
                    ttl: 60,
                },
                DnsRecord {
                    record_type: "A".to_owned(),
                    value: "192.0.2.123".to_owned(),
                    ttl: 60,
                },
            ],
            from_cache: false,
            last_verified_at: None,
            authoritative_validation: false,
            resolver_count: 2,
        };
        assert!(DnsEngine::matches_wildcard(
            &aliased,
            &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
        ));
        assert!(!DnsEngine::exactly_matches_wildcard(
            &aliased,
            &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
        ));
    }

    #[test]
    fn wildcard_probe_never_treats_timeouts_or_conflicts_as_a_normal_zone() {
        assert_eq!(
            classify_wildcard_samples(Vec::new(), 2, 3),
            WildcardProbeOutcome::Indeterminate
        );
        assert_eq!(
            classify_wildcard_samples(vec![BTreeSet::from(["A:192.0.2.10".to_owned()])], 4, 5,),
            WildcardProbeOutcome::Indeterminate
        );
        assert_eq!(
            classify_wildcard_samples(Vec::new(), 3, 3),
            WildcardProbeOutcome::Normal
        );
        assert_eq!(
            classify_wildcard_samples(Vec::new(), 3, 5),
            WildcardProbeOutcome::Indeterminate,
            "three NXDOMAIN answers plus two timeouts are incomplete evidence"
        );
        assert_eq!(
            classify_wildcard_samples(
                vec![
                    BTreeSet::from([
                        "A:192.0.2.10".to_owned(),
                        "CNAME:wild.example.com".to_owned(),
                    ]),
                    BTreeSet::from([
                        "A:192.0.2.11".to_owned(),
                        "CNAME:wild.example.com".to_owned(),
                    ]),
                    BTreeSet::from([
                        "A:192.0.2.12".to_owned(),
                        "CNAME:wild.example.com".to_owned(),
                    ]),
                ],
                0,
                3,
            ),
            WildcardProbeOutcome::Wildcard(BTreeSet::from(["CNAME:wild.example.com".to_owned()]))
        );
        assert_eq!(
            classify_wildcard_samples(
                vec![
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                    BTreeSet::from(["A:192.0.2.11".to_owned()]),
                    BTreeSet::from(["A:192.0.2.12".to_owned()]),
                ],
                0,
                3,
            ),
            WildcardProbeOutcome::Indeterminate
        );
    }

    #[test]
    fn wildcard_probe_first_stage_finishes_only_for_conclusive_samples() {
        assert_eq!(
            conclusive_wildcard_outcome(&[], 3),
            Some(WildcardProbeOutcome::Normal)
        );

        let stable_alias = vec![
            BTreeSet::from([
                "A:192.0.2.10".to_owned(),
                "CNAME:wild.example.com".to_owned(),
            ]),
            BTreeSet::from([
                "A:192.0.2.11".to_owned(),
                "CNAME:wild.example.com".to_owned(),
            ]),
            BTreeSet::from([
                "A:192.0.2.12".to_owned(),
                "CNAME:wild.example.com".to_owned(),
            ]),
        ];
        assert_eq!(
            conclusive_wildcard_outcome(&stable_alias, 0),
            Some(WildcardProbeOutcome::Wildcard(BTreeSet::from([
                "CNAME:wild.example.com".to_owned()
            ])))
        );

        let rotating_addresses = vec![
            BTreeSet::from(["A:192.0.2.10".to_owned()]),
            BTreeSet::from(["A:192.0.2.11".to_owned()]),
            BTreeSet::from(["A:192.0.2.12".to_owned()]),
        ];
        assert_eq!(
            conclusive_wildcard_outcome(&rotating_addresses, 0),
            None,
            "a rotating wildcard must receive the second probe stage"
        );
        assert_eq!(
            conclusive_wildcard_outcome(&[BTreeSet::from(["A:192.0.2.10".to_owned()])], 1,),
            None,
            "mixed or incomplete evidence must never become normal"
        );
    }

    #[test]
    fn wildcard_probe_second_stage_keeps_rotating_and_mixed_answers_indeterminate() {
        assert_eq!(
            classify_wildcard_samples(
                vec![
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                    BTreeSet::from(["A:192.0.2.11".to_owned()]),
                    BTreeSet::from(["A:192.0.2.12".to_owned()]),
                    BTreeSet::from(["A:192.0.2.13".to_owned()]),
                    BTreeSet::from(["A:192.0.2.14".to_owned()]),
                ],
                0,
                5,
            ),
            WildcardProbeOutcome::Indeterminate
        );
        assert_eq!(
            classify_wildcard_samples(
                vec![
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                ],
                3,
                5,
            ),
            WildcardProbeOutcome::Indeterminate,
            "mixed positive and negative samples must not become a normal zone"
        );
        assert_eq!(
            classify_wildcard_samples(
                vec![
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                    BTreeSet::from(["A:192.0.2.10".to_owned()]),
                ],
                2,
                5,
            ),
            WildcardProbeOutcome::Indeterminate,
            "mixed evidence must never authorize wildcard quarantine"
        );
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

    #[test]
    fn duplicate_resolver_addresses_cannot_fake_an_independent_quorum() {
        let address = "1.1.1.1".parse().unwrap();
        let engine = DnsEngine::new(10, Duration::from_secs(1), &[address, address]).unwrap();
        assert_eq!(engine.resolvers.len(), 1);
        assert_eq!(engine.fast_resolvers.len(), 1);
    }

    #[test]
    fn authoritative_transports_are_reused_per_address() {
        let engine =
            DnsEngine::new(10, Duration::from_secs(1), &["1.1.1.1".parse().unwrap()]).unwrap();
        let address = "192.0.2.53:53".parse().unwrap();
        let first = engine.authoritative_resolver(address).unwrap();
        let second = engine.authoritative_resolver(address).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }
}
