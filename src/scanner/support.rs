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

pub(super) struct PassiveRefreshLeaseGuard {
    database: Database,
    root_domain: String,
    source: String,
    owner: String,
    ttl: Duration,
}

impl PassiveRefreshLeaseGuard {
    pub(super) fn try_acquire(
        database: Database,
        root_domain: &str,
        source: &str,
        ttl: Duration,
    ) -> Result<Option<Self>> {
        let sequence = PASSIVE_REFRESH_LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let owner = domain_hash(&format!(
            "passive-refresh-lease-v1:{}:{}:{sequence}:{root_domain}:{source}",
            std::process::id(),
            now_epoch()
        ));
        if !database.try_acquire_passive_refresh_lease(root_domain, source, &owner, ttl)? {
            return Ok(None);
        }
        Ok(Some(Self {
            database,
            root_domain: root_domain.to_owned(),
            source: source.to_owned(),
            owner,
            ttl,
        }))
    }

    pub(super) fn ensure_owned(&self) -> Result<()> {
        if !self.database.renew_passive_refresh_lease(
            &self.root_domain,
            &self.source,
            &self.owner,
            self.ttl,
        )? {
            bail!("lease de rafraîchissement passif perdu");
        }
        Ok(())
    }
}

impl Drop for PassiveRefreshLeaseGuard {
    fn drop(&mut self) {
        let _ = self.database.release_passive_refresh_lease(
            &self.root_domain,
            &self.source,
            &self.owner,
        );
    }
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
        // Passive connectors use zero as the explicit "no cumulative
        // deadline" sentinel; per-request timeouts and pagination caps remain.
        .unwrap_or(Duration::ZERO);
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
