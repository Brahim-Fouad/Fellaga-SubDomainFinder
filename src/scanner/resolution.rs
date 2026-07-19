use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BatchDnsMode {
    Conservative,
    /// Only fresh generated candidates may use this mode. Its negatives are
    /// terminal for the current candidate row but journal-only globally.
    GeneratedDiscovery,
}

impl BatchDnsMode {
    pub(super) async fn resolve_host(
        self,
        dns: &DnsEngine,
        fqdn: &str,
        network_attempted: Arc<AtomicBool>,
    ) -> DnsResolutionOutcome {
        match self {
            Self::Conservative => {
                dns.resolve_host_classified_with_network_signal(fqdn, network_attempted)
                    .await
            }
            Self::GeneratedDiscovery => {
                dns.resolve_host_discovery_classified_with_network_signal(fqdn, network_attempted)
                    .await
            }
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct RoutedDnsOutcomes {
    pub(super) positives: Vec<ResolvedHost>,
    pub(super) cacheable_negatives: Vec<String>,
    pub(super) discovery_negatives: Vec<String>,
    pub(super) indeterminate: Vec<String>,
}

pub(super) fn route_dns_outcomes(
    mode: BatchDnsMode,
    completed: impl IntoIterator<Item = DnsResolutionOutcome>,
    unfinished: impl IntoIterator<Item = String>,
) -> RoutedDnsOutcomes {
    let mut routed = RoutedDnsOutcomes {
        indeterminate: unfinished.into_iter().collect(),
        ..RoutedDnsOutcomes::default()
    };
    for outcome in completed {
        match outcome {
            DnsResolutionOutcome::Positive(answer) => routed.positives.push(answer),
            DnsResolutionOutcome::Negative { fqdn } => match mode {
                BatchDnsMode::Conservative => routed.cacheable_negatives.push(fqdn),
                BatchDnsMode::GeneratedDiscovery => routed.discovery_negatives.push(fqdn),
            },
            DnsResolutionOutcome::Indeterminate { fqdn } => routed.indeterminate.push(fqdn),
        }
    }
    routed
}

pub(super) fn persist_routed_dns_outcomes(
    database: &Database,
    scan_id: i64,
    resolved: &[ResolvedHost],
    cacheable_negatives: &[String],
    discovery_negatives: &[String],
    indeterminate: &[String],
    negative_ttl: u32,
) -> Result<()> {
    database.update_cache_outcomes(
        Some(scan_id),
        resolved,
        cacheable_negatives,
        indeterminate,
        negative_ttl,
    )?;
    database.record_discovery_negatives(scan_id, discovery_negatives)
}

#[derive(Debug)]
pub(super) struct DeadlineDnsOutcomes {
    pub(super) completed: Vec<DnsResolutionOutcome>,
    /// Hosts for which at least one DNS packet was accepted by the transport.
    /// This is the only set allowed to consume a durable retry.
    pub(super) attempted: Vec<String>,
    /// Resolver futures that were launched but did not finish before the
    /// caller-owned deadline.
    pub(super) cancelled: Vec<String>,
    /// Hosts that never left the scheduler queue. They must not consume a DNS
    /// retry or create a verification journal entry.
    pub(super) not_started: Vec<String>,
    pub(super) deadline_exhausted: bool,
}

/// Drain every outcome that is already ready before observing the deadline,
/// then cancel only the still-pending resolver futures. Keeping the ready branch
/// biased makes the persistence boundary deterministic at the deadline.
pub(super) async fn collect_dns_outcomes_until<I, Resolve, ResolveFuture, F>(
    expected_hosts: I,
    concurrency: usize,
    deadline: Option<tokio::time::Instant>,
    mut resolve: Resolve,
    mut on_completed: F,
) -> DeadlineDnsOutcomes
where
    I: IntoIterator<Item = String>,
    Resolve: FnMut(String, Arc<AtomicBool>) -> ResolveFuture,
    ResolveFuture: Future<Output = DnsResolutionOutcome>,
    F: FnMut(&DnsResolutionOutcome),
{
    let mut queued = expected_hosts.into_iter().collect::<VecDeque<_>>();
    let mut unfinished = queued.iter().cloned().collect::<BTreeSet<_>>();
    let mut network_signals = BTreeMap::<String, Arc<AtomicBool>>::new();
    let mut completed = Vec::new();
    let mut pending = FuturesUnordered::new();
    let mut deadline_sleep = deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline)));

    let record_completed = |outcome: DnsResolutionOutcome,
                            unfinished: &mut BTreeSet<String>,
                            completed: &mut Vec<DnsResolutionOutcome>,
                            on_completed: &mut F| {
        unfinished.remove(outcome.fqdn());
        on_completed(&outcome);
        completed.push(outcome);
    };

    'resolve: loop {
        // FuturesUnordered only contains the currently in-flight window. Never
        // refill it once the deadline is reached: a biased ready branch cannot
        // starve the deadline by pulling and starting the entire host stream.
        while pending.len() < concurrency.max(1)
            && deadline.is_none_or(|deadline| tokio::time::Instant::now() < deadline)
        {
            let Some(host) = queued.pop_front() else {
                break;
            };
            let network_attempted = Arc::new(AtomicBool::new(false));
            network_signals.insert(host.clone(), network_attempted.clone());
            pending.push(resolve(host, network_attempted));
        }

        if pending.is_empty() {
            break;
        }

        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            // Preserve only futures that are already ready. Polling stops at
            // the first pending result and no replacement work is scheduled.
            while let Some(Some(outcome)) = pending.next().now_or_never() {
                record_completed(outcome, &mut unfinished, &mut completed, &mut on_completed);
            }
            break;
        }

        if let Some(sleep) = deadline_sleep.as_mut() {
            tokio::select! {
                biased;
                next = pending.next() => {
                    let Some(outcome) = next else {
                        break 'resolve;
                    };
                    record_completed(outcome, &mut unfinished, &mut completed, &mut on_completed);
                }
                _ = sleep.as_mut() => {
                    while let Some(Some(outcome)) = pending.next().now_or_never() {
                        record_completed(
                            outcome,
                            &mut unfinished,
                            &mut completed,
                            &mut on_completed,
                        );
                    }
                    break 'resolve;
                }
            }
        } else if let Some(outcome) = pending.next().await {
            record_completed(outcome, &mut unfinished, &mut completed, &mut on_completed);
        } else {
            break;
        }
    }
    // Dropping the in-flight futures runs their accounting guards before the
    // transport signals are classified below.
    drop(pending);
    completed.sort_by(|left, right| left.fqdn().cmp(right.fqdn()));
    let deadline_exhausted = deadline.is_some() && !unfinished.is_empty();
    let attempted = network_signals
        .iter()
        .filter(|(_, attempted)| attempted.load(Ordering::Acquire))
        .map(|(host, _)| host.clone())
        .collect::<BTreeSet<_>>();
    let cancelled = unfinished
        .intersection(&attempted)
        .cloned()
        .collect::<Vec<_>>();
    let not_started = unfinished
        .difference(&attempted)
        .cloned()
        .collect::<Vec<_>>();
    DeadlineDnsOutcomes {
        completed,
        attempted: attempted.into_iter().collect(),
        cancelled,
        not_started,
        deadline_exhausted,
    }
}

pub(super) async fn collect_refresh_dns_outcomes(
    dns: &DnsEngine,
    trusted_dns: Option<&DnsEngine>,
    hosts: Vec<String>,
    deadline: Option<tokio::time::Instant>,
) -> DeadlineDnsOutcomes {
    if let Some(trusted_dns) = trusted_dns {
        collect_dns_outcomes_until(
            hosts,
            trusted_dns.concurrency().clamp(1, 32),
            deadline,
            |fqdn, network_attempted| async move {
                trusted_dns
                    .resolve_host_consensus_classified_with_network_signal(&fqdn, network_attempted)
                    .await
            },
            |_| {},
        )
        .await
    } else {
        collect_dns_outcomes_until(
            hosts,
            dns.concurrency().clamp(1, 32),
            deadline,
            |fqdn, network_attempted| async move {
                dns.resolve_host_classified_with_network_signal(&fqdn, network_attempted)
                    .await
            },
            |_| {},
        )
        .await
    }
}

pub(super) fn dnssec_assessment_proves_nonexistence(assessment: &DnssecProofAssessment) -> bool {
    // A conventional NSEC3 interval is useful for resolver-side negative
    // caching, but it is not destructive wildcard-cleanup evidence here. Only
    // an explicit authenticated NXNAME bit can make NSEC3 authoritative enough
    // to quarantine a retained hostname.
    assessment.state == DnssecOwnerState::DoesNotExist
        && assessment.proofs.iter().any(|proof| {
            matches!(
                proof,
                DnssecProofKind::NxnameNsec
                    | DnssecProofKind::NxnameNsec3
                    | DnssecProofKind::NsecRangeDenial
            )
        })
}

/// Assess a deliberately tiny set, optionally under a caller-owned deadline.
///
/// The supplied assessment must already come from local DNSSEC validation.
/// This function intentionally has no AD-bit input and additionally requires a
/// concrete denial proof kind before it can return a hostname for quarantine.
pub(super) async fn assess_dnssec_suspects_bounded<F, Fut>(
    domain: &str,
    suspects: impl IntoIterator<Item = String>,
    deadline: Option<tokio::time::Instant>,
    assess: F,
) -> BTreeSet<String>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = DnssecProofAssessment>,
{
    if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
        return BTreeSet::new();
    }
    let suspects = suspects
        .into_iter()
        .filter_map(|fqdn| normalize_observed_name(&fqdn, domain))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(DNSSEC_WILDCARD_SUSPECT_CAP)
        .collect::<Vec<_>>();
    let mut pending = stream::iter(suspects)
        .map(|fqdn| {
            let assessment = assess(fqdn.clone());
            async move { (fqdn, assessment.await) }
        })
        .buffer_unordered(DNSSEC_WILDCARD_SUSPECT_CAP);
    let mut nonexistent = BTreeSet::new();
    loop {
        let next = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, pending.next())
                .await
                .ok()
                .flatten(),
            None => pending.next().await,
        };
        match next {
            Some((fqdn, assessment)) => {
                if dnssec_assessment_proves_nonexistence(&assessment) {
                    nonexistent.insert(fqdn);
                }
            }
            None => break,
        }
    }
    // Dropping the buffered stream cancels all unfinished resolver futures;
    // they never receive a fresh per-name wall-clock budget.
    drop(pending);
    nonexistent
}

#[derive(Debug, Default)]
pub(super) struct BatchResolution {
    pub(super) answers: Vec<ResolvedHost>,
    pub(super) cache_hits: usize,
    pub(super) resolved_from_network: usize,
    pub(super) deadline_exhausted: bool,
    pub(super) indeterminate_hosts: Vec<String>,
    pub(super) not_started_hosts: Vec<String>,
    pub(super) attempted_hosts: Vec<String>,
}

impl BatchResolution {
    pub(super) fn merge(&mut self, mut other: Self) {
        self.answers.append(&mut other.answers);
        self.cache_hits = self.cache_hits.saturating_add(other.cache_hits);
        self.resolved_from_network = self
            .resolved_from_network
            .saturating_add(other.resolved_from_network);
        self.deadline_exhausted |= other.deadline_exhausted;
        self.indeterminate_hosts
            .append(&mut other.indeterminate_hosts);
        self.not_started_hosts.append(&mut other.not_started_hosts);
        self.attempted_hosts.append(&mut other.attempted_hosts);
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct LateCtValidationDrain {
    pub(super) cache_hits: usize,
    pub(super) resolved_from_network: usize,
    pub(super) pending: usize,
    pub(super) deadline_exhausted: bool,
}
