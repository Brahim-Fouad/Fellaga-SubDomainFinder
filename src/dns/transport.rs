use super::wire::*;
use super::*;

/// Keeps a cadence permit alive until its reserved instant even if the caller
/// is cancelled while sleeping. Without this handoff, repeated cancellations
/// could release permits early while leaving `next_query_at` advanced, letting
/// queued tasks build an unbounded chain of abandoned future slots.
pub(super) struct CadenceReservation {
    pub(super) permit: Option<tokio::sync::OwnedSemaphorePermit>,
    pub(super) slot: tokio::time::Instant,
}

impl CadenceReservation {
    pub(super) fn new(
        permit: tokio::sync::OwnedSemaphorePermit,
        slot: tokio::time::Instant,
    ) -> Self {
        Self {
            permit: Some(permit),
            slot,
        }
    }
}

impl Drop for CadenceReservation {
    fn drop(&mut self) {
        if self.slot <= tokio::time::Instant::now() {
            return;
        }
        let Some(permit) = self.permit.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let slot = self.slot;
        // Dropping a JoinHandle detaches the task. The task itself owns the
        // permit and releases it at the original reservation instant.
        drop(runtime.spawn(async move {
            tokio::time::sleep_until(slot).await;
            drop(permit);
        }));
    }
}

pub(super) struct FastResolver {
    pub(super) address: SocketAddr,
    pub(super) transport: OnceCell<Arc<FastUdpTransport>>,
}

pub(super) struct FastUdpTransport {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) pending: Arc<tokio::sync::Mutex<HashMap<u16, PendingDnsQuery>>>,
    pub(super) slots: Arc<tokio::sync::Semaphore>,
    pub(super) next_id: AtomicU16,
    pub(super) receiver: tokio::task::AbortHandle,
}

pub(super) struct PendingDnsQuery {
    pub(super) name: Name,
    pub(super) record_type: RecordType,
    pub(super) dns_class: DNSClass,
    pub(super) sender: oneshot::Sender<Vec<u8>>,
}

pub(super) struct PendingQueryGuard {
    pub(super) id: u16,
    pub(super) pending: Arc<tokio::sync::Mutex<HashMap<u16, PendingDnsQuery>>>,
    pub(super) armed: bool,
}

impl Drop for PendingQueryGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
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

pub(super) fn dns_tcp_slots() -> &'static Arc<tokio::sync::Semaphore> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(16)))
}

impl FastUdpTransport {
    pub(super) async fn connect(address: SocketAddr) -> Result<Arc<Self>> {
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
                if correlated && let Some(request) = pending.remove(&id) {
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

    pub(super) async fn query(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout_duration: Duration,
    ) -> Result<Message> {
        self.query_with_signal(fqdn, record_type, recursion_desired, timeout_duration, None)
            .await
    }

    pub(super) async fn query_with_signal(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout_duration: Duration,
        send_signal: Option<&DnsSendSignal>,
    ) -> Result<Message> {
        let started = Instant::now();
        let _slot = tokio::time::timeout(timeout_duration, self.slots.clone().acquire_owned())
            .await
            .context("délai de file DNS UDP dépassé")?
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
        let mut pending_guard = PendingQueryGuard {
            id,
            pending: self.pending.clone(),
            armed: true,
        };
        let remaining = timeout_duration.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("délai DNS UDP dépassé avant l'envoi");
        }
        let response = tokio::time::timeout(remaining, async {
            let sent = self.socket.send(&payload).await?;
            if sent != payload.len() {
                bail!("envoi DNS UDP partiel");
            }
            if let Some(send_signal) = send_signal {
                send_signal.mark_sent();
            }
            Ok::<_, anyhow::Error>(receiver.await?)
        })
        .await
        .context("délai DNS UDP dépassé")??;
        // The receiver removes a correlated entry before completing the
        // channel. Avoid taking the pending-map mutex a second time on every
        // successful response; cancellation and errors keep the guard armed.
        pending_guard.armed = false;
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

pub(super) async fn query_tcp(
    address: SocketAddr,
    fqdn: &str,
    record_type: RecordType,
    recursion_desired: bool,
    timeout_duration: Duration,
) -> Result<Message> {
    query_tcp_with_slots(
        dns_tcp_slots().clone(),
        address,
        fqdn,
        record_type,
        recursion_desired,
        timeout_duration,
    )
    .await
}

pub(super) async fn query_tcp_with_slots(
    slots: Arc<tokio::sync::Semaphore>,
    address: SocketAddr,
    fqdn: &str,
    record_type: RecordType,
    recursion_desired: bool,
    timeout_duration: Duration,
) -> Result<Message> {
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
    // The queue behind the global TCP cap is part of this request's deadline.
    // Previously thousands of truncated UDP answers could wait in batches of
    // sixteen and each batch received a fresh timeout after acquiring a slot.
    let response = tokio::time::timeout(timeout_duration, async move {
        let _tcp_slot = slots
            .acquire_owned()
            .await
            .context("transport DNS TCP fermé")?;
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
    pub(super) async fn query(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout: Duration,
    ) -> Result<Message> {
        self.query_with_signal(fqdn, record_type, recursion_desired, timeout, None)
            .await
    }

    pub(super) async fn query_with_signal(
        &self,
        fqdn: &str,
        record_type: RecordType,
        recursion_desired: bool,
        timeout: Duration,
        send_signal: Option<&DnsSendSignal>,
    ) -> Result<Message> {
        let started = Instant::now();
        let transport = tokio::time::timeout(
            timeout,
            self.transport
                .get_or_try_init(|| FastUdpTransport::connect(self.address)),
        )
        .await
        .context("délai d'initialisation DNS UDP dépassé")??;
        let udp_budget = timeout.saturating_sub(started.elapsed());
        if udp_budget.is_zero() {
            bail!("délai DNS épuisé avant la requête UDP");
        }
        let response = transport
            .query_with_signal(
                fqdn,
                record_type,
                recursion_desired,
                udp_budget,
                send_signal,
            )
            .await?;
        if response.truncated() {
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                bail!("délai DNS épuisé avant le repli TCP");
            }
            query_tcp(
                self.address,
                fqdn,
                record_type,
                recursion_desired,
                remaining,
            )
            .await
        } else {
            Ok(response)
        }
    }
}

pub(super) fn system_nameserver() -> Option<IpAddr> {
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

pub(super) struct ResolverNode {
    pub(super) label: String,
    pub(super) resolver: Arc<TokioResolver>,
    pub(super) state: Mutex<ResolverState>,
    pub(super) inflight: AtomicUsize,
}

/// Keeps resolver load accounting correct when a query future is cancelled by
/// a scan deadline. Without a drop guard, cancellation between `fetch_add` and
/// the matching `fetch_sub` would permanently inflate the resolver score.
pub(super) struct ResolverInflightGuard<'a> {
    pub(super) inflight: &'a AtomicUsize,
}

impl<'a> ResolverInflightGuard<'a> {
    pub(super) fn new(inflight: &'a AtomicUsize) -> Self {
        inflight.fetch_add(1, Ordering::Relaxed);
        Self { inflight }
    }
}

impl Drop for ResolverInflightGuard<'_> {
    fn drop(&mut self) {
        self.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Shared edge-triggered signal set only after the kernel accepted a DNS
/// datagram.  A caller-owned signal lets the durable scheduler distinguish a
/// future merely admitted to the async window from one that actually consumed
/// a network attempt.
#[derive(Clone, Default)]
pub(super) struct DnsSendSignal {
    pub(super) sent_at: Arc<Mutex<Option<Instant>>>,
    pub(super) host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl DnsSendSignal {
    pub(super) fn new(host_attempted: Option<Arc<std::sync::atomic::AtomicBool>>) -> Self {
        Self {
            sent_at: Arc::new(Mutex::new(None)),
            host_attempted,
        }
    }

    pub(super) fn mark_sent(&self) {
        let Ok(mut sent_at) = self.sent_at.lock() else {
            return;
        };
        if sent_at.is_some() {
            return;
        }
        *sent_at = Some(Instant::now());
        if let Some(host_attempted) = &self.host_attempted {
            host_attempted.store(true, Ordering::Release);
        }
    }

    pub(super) fn elapsed_ms(&self) -> Option<u64> {
        self.sent_at
            .lock()
            .ok()
            .and_then(|sent_at| *sent_at)
            .map(|sent_at| sent_at.elapsed().as_millis().min(u64::MAX as u128) as u64)
    }
}

/// Finalizes resolver accounting even when an outer phase deadline drops the
/// query future after its packet was sent. Pre-send cancellation leaves the
/// signal unset; post-send cancellation records traffic but remains neutral
/// to resolver health and to the adaptive governor.
pub(super) struct ResolverAttemptGuard<'a> {
    pub(super) state: Option<&'a Mutex<ResolverState>>,
    pub(super) governor: &'a NetworkGovernor,
    pub(super) signal: DnsSendSignal,
    pub(super) finalized: bool,
}

impl<'a> ResolverAttemptGuard<'a> {
    pub(super) fn new(
        state: Option<&'a Mutex<ResolverState>>,
        governor: &'a NetworkGovernor,
        signal: DnsSendSignal,
    ) -> Self {
        Self {
            state,
            governor,
            signal,
            finalized: false,
        }
    }

    pub(super) fn finish(&mut self, operational: bool) {
        if self.finalized {
            return;
        }
        self.finalized = true;
        let Some(duration_ms) = self.signal.elapsed_ms() else {
            return;
        };
        if let Some(state) = self.state
            && let Ok(mut state) = state.lock()
        {
            record_resolver_state(&mut state, operational, duration_ms);
        }
        self.governor
            .observe_delta(1, u64::from(!operational), duration_ms);
    }

    pub(super) fn finish_cancelled(&mut self) {
        if self.finalized {
            return;
        }
        self.finalized = true;
        let Some(duration_ms) = self.signal.elapsed_ms() else {
            return;
        };
        if let Some(state) = self.state
            && let Ok(mut state) = state.lock()
        {
            // The packet was accepted by the kernel, so retain request and
            // timing accounting. An outer phase cancellation is not evidence
            // that the resolver failed and must not trigger network backoff.
            state.requests = state.requests.saturating_add(1);
            state.total_ms = state.total_ms.saturating_add(duration_ms);
        }
    }
}

impl Drop for ResolverAttemptGuard<'_> {
    fn drop(&mut self) {
        self.finish_cancelled();
    }
}

#[derive(Debug, Default)]
pub(super) struct ResolverState {
    pub(super) requests: u64,
    pub(super) successes: u64,
    pub(super) failures: u64,
    pub(super) total_ms: u64,
    pub(super) consecutive_failures: u64,
    pub(super) reported_requests: u64,
    pub(super) reported_successes: u64,
    pub(super) reported_failures: u64,
    pub(super) reported_total_ms: u64,
}

pub(super) fn record_resolver_state(
    state: &mut ResolverState,
    operational: bool,
    duration_ms: u64,
) {
    state.requests = state.requests.saturating_add(1);
    state.total_ms = state.total_ms.saturating_add(duration_ms);
    if operational {
        state.successes = state.successes.saturating_add(1);
        state.consecutive_failures = 0;
    } else {
        state.failures = state.failures.saturating_add(1);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    }
}
