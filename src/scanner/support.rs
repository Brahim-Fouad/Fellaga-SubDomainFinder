use super::*;

pub(super) fn prioritized_answer_addresses<'a>(
    answers: impl IntoIterator<Item = &'a ResolvedHost>,
    public_only: bool,
    limit: usize,
) -> Vec<IpAddr> {
    let mut usage = BTreeMap::<IpAddr, usize>::new();
    for answer in answers {
        let addresses = answer
            .records
            .iter()
            .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
            .filter_map(|record| record.value.parse::<IpAddr>().ok())
            .filter(|address| !public_only || crate::passive::is_public_internet_address(*address))
            .collect::<BTreeSet<_>>();
        for address in addresses {
            *usage.entry(address).or_default() += 1;
        }
    }
    let mut prioritized = usage.into_iter().collect::<Vec<_>>();
    prioritized.sort_by_key(|(address, count)| (address.is_ipv6(), *count, *address));
    prioritized
        .into_iter()
        .take(limit)
        .map(|(address, _)| address)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum InternetDbCacheDecision {
    Use {
        hostnames: BTreeSet<String>,
        qualifier: &'static str,
    },
    Refresh,
}

pub(super) fn internetdb_cache_decision(
    cached: Option<&IpHostnameCacheEntry>,
    now: i64,
    refresh_seconds: i64,
    retry_seconds: i64,
    refresh_requested: bool,
) -> InternetDbCacheDecision {
    if refresh_requested {
        return InternetDbCacheDecision::Refresh;
    }
    let Some(cache) = cached else {
        return InternetDbCacheDecision::Refresh;
    };
    if cache.status == "error" && now.saturating_sub(cache.last_attempt_at) <= retry_seconds {
        return InternetDbCacheDecision::Use {
            hostnames: cache.hostnames.clone(),
            qualifier: ":stale",
        };
    }
    if cache.last_success_at <= 0 || now.saturating_sub(cache.last_success_at) > refresh_seconds {
        return InternetDbCacheDecision::Refresh;
    }
    if cache.status == "empty" {
        return InternetDbCacheDecision::Use {
            hostnames: BTreeSet::new(),
            qualifier: ":cache",
        };
    }
    InternetDbCacheDecision::Use {
        hostnames: cache.hostnames.clone(),
        qualifier: if cache.status == "error" {
            ":stale"
        } else {
            ":cache"
        },
    }
}

const PASSIVE_REFRESH_RELEASE_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
];
const PASSIVE_REFRESH_RELEASE_WORKERS: usize = 4;

struct PassiveLeaseReleaseJob {
    database: Database,
    root_domain: String,
    source: String,
    owner: String,
    #[cfg(test)]
    completion: Option<std::sync::mpsc::Sender<PassiveLeaseReleaseOutcome>>,
}

impl PassiveLeaseReleaseJob {
    fn run(self) {
        #[cfg(test)]
        let mut attempts = 0_usize;
        #[cfg(test)]
        let mut released = false;
        for delay in PASSIVE_REFRESH_RELEASE_RETRY_DELAYS {
            std::thread::sleep(delay);
            #[cfg(test)]
            {
                attempts = attempts.saturating_add(1);
            }
            if self
                .database
                .release_passive_refresh_lease_until(
                    &self.root_domain,
                    &self.source,
                    &self.owner,
                    Instant::now() + PASSIVE_REFRESH_RELEASE_RETRY_BUDGET,
                )
                .is_ok()
            {
                #[cfg(test)]
                {
                    released = true;
                }
                break;
            }
        }
        #[cfg(test)]
        if let Some(completion) = self.completion {
            let _ = completion.send(PassiveLeaseReleaseOutcome { attempts, released });
        }
    }

    #[cfg(test)]
    fn with_completion(
        mut self,
        completion: std::sync::mpsc::Sender<PassiveLeaseReleaseOutcome>,
    ) -> Self {
        self.completion = Some(completion);
        self
    }

    #[cfg(test)]
    fn notify_unscheduled(mut self) {
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(PassiveLeaseReleaseOutcome {
                attempts: 0,
                released: false,
            });
        }
    }
}

struct PassiveLeaseReleaseWorker {
    sender: std::sync::mpsc::Sender<PassiveLeaseReleaseJob>,
    // Retaining the handles makes the process-wide workers owned rather than
    // fire-and-forget Tokio tasks. They intentionally live for the process.
    _threads: Vec<std::thread::JoinHandle<()>>,
}

impl PassiveLeaseReleaseWorker {
    fn start() -> std::io::Result<Self> {
        let (sender, receiver) = std::sync::mpsc::channel::<PassiveLeaseReleaseJob>();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut threads = Vec::with_capacity(PASSIVE_REFRESH_RELEASE_WORKERS);
        for worker_index in 0..PASSIVE_REFRESH_RELEASE_WORKERS {
            let receiver = Arc::clone(&receiver);
            let thread = std::thread::Builder::new()
                .name(format!("fellaga-passive-lease-cleanup-{worker_index}"))
                .spawn(move || {
                    loop {
                        let job = receiver
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .recv();
                        let Ok(job) = job else {
                            break;
                        };
                        job.run();
                    }
                });
            match thread {
                Ok(thread) => threads.push(thread),
                Err(error) if threads.is_empty() => return Err(error),
                Err(_) => break,
            }
        }
        Ok(Self {
            sender,
            _threads: threads,
        })
    }
}

fn schedule_passive_lease_release(job: PassiveLeaseReleaseJob) -> bool {
    static WORKER: std::sync::OnceLock<Option<PassiveLeaseReleaseWorker>> =
        std::sync::OnceLock::new();
    let Some(worker) = WORKER
        .get_or_init(|| PassiveLeaseReleaseWorker::start().ok())
        .as_ref()
    else {
        #[cfg(test)]
        job.notify_unscheduled();
        #[cfg(not(test))]
        drop(job);
        return false;
    };
    match worker.sender.send(job) {
        Ok(()) => true,
        Err(error) => {
            #[cfg(test)]
            error.0.notify_unscheduled();
            #[cfg(not(test))]
            drop(error);
            false
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(super) struct PassiveLeaseReleaseOutcome {
    pub(super) attempts: usize,
    pub(super) released: bool,
}

pub(super) struct PassiveRefreshLeaseGuard {
    database: Database,
    root_domain: String,
    source: String,
    owner: String,
    ttl: Duration,
    deadline: Instant,
    released: AtomicBool,
}

impl PassiveRefreshLeaseGuard {
    pub(super) fn try_acquire(
        database: Database,
        root_domain: &str,
        source: &str,
        ttl: Duration,
        deadline: Instant,
    ) -> Result<Option<Self>> {
        let sequence = PASSIVE_REFRESH_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let owner = domain_hash(&format!(
            "passive-refresh-lease-v1:{}:{}:{sequence}:{root_domain}:{source}",
            std::process::id(),
            now_epoch()
        ));
        if !database.try_acquire_passive_refresh_lease_until(
            root_domain,
            source,
            &owner,
            ttl,
            deadline,
        )? {
            return Ok(None);
        }
        Ok(Some(Self {
            database,
            root_domain: root_domain.to_owned(),
            source: source.to_owned(),
            owner,
            ttl,
            deadline,
            released: AtomicBool::new(false),
        }))
    }

    pub(super) fn ensure_owned(&self) -> Result<()> {
        if self.released.load(Ordering::Acquire) {
            bail!("lease de rafraîchissement passif déjà libéré");
        }
        let renewal_ttl = passive_lease_renewal_ttl(
            self.deadline.saturating_duration_since(Instant::now()),
            self.ttl,
        );
        if !self.database.renew_passive_refresh_lease_until(
            &self.root_domain,
            &self.source,
            &self.owner,
            renewal_ttl,
            self.deadline,
        )? {
            bail!("lease de rafraîchissement passif perdu");
        }
        Ok(())
    }

    pub(super) fn release_bounded(&self) -> Result<()> {
        self.release_with_budget(PASSIVE_REFRESH_RELEASE_BUDGET)
    }

    fn release_with_budget(&self, budget: Duration) -> Result<()> {
        if self.released.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let release_deadline = Instant::now() + budget;
        match self.database.release_passive_refresh_lease_until(
            &self.root_domain,
            &self.source,
            &self.owner,
            release_deadline,
        ) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.released.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    fn deferred_release_job(&self) -> PassiveLeaseReleaseJob {
        PassiveLeaseReleaseJob {
            database: self.database.clone(),
            root_domain: self.root_domain.clone(),
            source: self.source.clone(),
            owner: self.owner.clone(),
            #[cfg(test)]
            completion: None,
        }
    }

    pub(super) fn release_or_schedule(&self) {
        if self.release_bounded().is_ok() {
            return;
        }
        if schedule_passive_lease_release(self.deferred_release_job()) {
            self.released.store(true, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub(super) fn release_or_schedule_tracked(
        &self,
    ) -> std::sync::mpsc::Receiver<PassiveLeaseReleaseOutcome> {
        let (completion, receiver) = std::sync::mpsc::channel();
        if self.release_bounded().is_ok() {
            let _ = completion.send(PassiveLeaseReleaseOutcome {
                attempts: 0,
                released: true,
            });
            return receiver;
        }
        let job = self.deferred_release_job().with_completion(completion);
        if schedule_passive_lease_release(job) {
            self.released.store(true, Ordering::Release);
        }
        receiver
    }
}

impl Drop for PassiveRefreshLeaseGuard {
    fn drop(&mut self) {
        // Normal task exits release explicitly. Drop is the cancellation and
        // panic fallback. One millisecond per guard prevents a global timeout
        // from accumulating 32 independent 250 ms waits.
        let _ = self.release_with_budget(PASSIVE_REFRESH_DROP_RELEASE_BUDGET);
    }
}

pub(super) fn passive_lease_renewal_ttl(remaining: Duration, acquired_ttl: Duration) -> Duration {
    remaining
        .saturating_add(PASSIVE_REFRESH_RENEWAL_GRACE)
        .min(acquired_ttl)
}

pub(super) fn metadata_phase_budget(web_budget_remaining: Option<Duration>) -> Option<Duration> {
    web_budget_remaining.map(|remaining| remaining.min(METADATA_PHASE_BUDGET_CAP))
}

pub(super) fn passive_connector_timing(
    phase_deadline: Option<tokio::time::Instant>,
    request_timeout: Duration,
    policy_total_timeout: Duration,
) -> (Duration, Duration) {
    let connector_budget = phase_deadline
        .as_ref()
        .map(|deadline| {
            deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .saturating_sub(Duration::from_millis(250))
                .min(policy_total_timeout)
        })
        // An unlimited passive phase removes only the shared phase deadline.
        // Each provider must still respect its own wall-clock policy so one
        // degraded paginated endpoint cannot hold the entire scan forever.
        .unwrap_or(policy_total_timeout);
    let lease_window = if phase_deadline.is_some() {
        connector_budget
    } else {
        policy_total_timeout.max(request_timeout)
    };
    let lease_ttl = lease_window.saturating_add(PASSIVE_REFRESH_LEASE_GRACE);
    (connector_budget, lease_ttl)
}

pub(super) fn merge_resolver_metrics(
    primary: Vec<ResolverMetric>,
    trusted: Vec<ResolverMetric>,
) -> Vec<ResolverMetric> {
    let mut merged = BTreeMap::<String, (u64, u64, u64, u128, u64)>::new();
    for metric in primary.into_iter().chain(trusted) {
        let entry = merged.entry(metric.resolver).or_default();
        entry.0 = entry.0.saturating_add(metric.requests);
        entry.1 = entry.1.saturating_add(metric.successes);
        entry.2 = entry.2.saturating_add(metric.failures);
        entry.3 = entry.3.saturating_add(
            u128::from(metric.average_ms).saturating_mul(u128::from(metric.requests)),
        );
        entry.4 = entry.4.max(metric.consecutive_failures);
    }
    merged
        .into_iter()
        .map(
            |(resolver, (requests, successes, failures, total_ms, consecutive_failures))| {
                ResolverMetric {
                    resolver,
                    requests,
                    successes,
                    failures,
                    average_ms: if requests == 0 {
                        0
                    } else {
                        (total_ms / u128::from(requests)).min(u128::from(u64::MAX)) as u64
                    },
                    consecutive_failures,
                }
            },
        )
        .collect()
}
