use crate::db::{Database, DnssecCacheEntry};
use crate::dns::DnsEngine;
use crate::model::DnssecWalkResult;
use crate::util::{normalize_observed_name, now_epoch};
use futures_util::{StreamExt, stream};
use hickory_net::client::Client;
use hickory_net::proto::dnssec::rdata::DNSSECRData;
use hickory_net::proto::op::{DnsRequestOptions, Query};
use hickory_net::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::DnsHandle;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Instant, timeout};

const NSEC_QUERIES_PER_SECOND: u64 = 20;
const NSEC_ZONE_MAX_RUNTIME: Duration = Duration::from_secs(120);

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Default)]
struct NsecRateLimiter {
    next: tokio::sync::Mutex<Option<Instant>>,
}

impl NsecRateLimiter {
    async fn wait_before(&self, deadline: Instant) -> bool {
        if deadline <= Instant::now() {
            return false;
        }
        let spacing = Duration::from_secs_f64(1.0 / NSEC_QUERIES_PER_SECOND as f64);
        let Ok(mut next) = tokio::time::timeout_at(deadline, self.next.lock()).await else {
            return false;
        };
        let now = Instant::now();
        if let Some(scheduled) = *next
            && scheduled > now
            && tokio::time::timeout_at(deadline, tokio::time::sleep_until(scheduled))
                .await
                .is_err()
        {
            return false;
        }
        *next = Some(Instant::now() + spacing);
        true
    }
}

async fn wait_for_nsec_query_slot(
    dns: &DnsEngine,
    limiter: &NsecRateLimiter,
    deadline: Instant,
) -> bool {
    limiter.wait_before(deadline).await && dns.wait_for_rate_slot_before(deadline).await
}

fn earliest_deadline(zone_deadline: Instant, phase_deadline: Option<Instant>) -> Instant {
    phase_deadline
        .map(|deadline| deadline.min(zone_deadline))
        .unwrap_or(zone_deadline)
}

fn operation_budget(deadline: Instant, operation_timeout: Duration) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    (!remaining.is_zero()).then(|| remaining.min(operation_timeout))
}

fn mark_deadline(result: &mut DnssecWalkResult) {
    if !result.names.is_empty() {
        result.status = "partial".to_owned();
    }
    result.error = Some("budget de temps NSEC atteint".to_owned());
}

fn reusable_walk_status(status: &str) -> bool {
    matches!(
        status,
        "walked" | "nsec3-protected" | "nsec-minimal-protected"
    )
}

fn reusable_fresh_cache(cache: &DnssecCacheEntry, now: i64, freshness: i64) -> bool {
    reusable_walk_status(&cache.status) && now.saturating_sub(cache.updated_at) < freshness
}

fn reached_walk_limit(result: &DnssecWalkResult, max_names: usize) -> bool {
    result.status == "partial"
        && result.error.is_none()
        && (result.names.len() >= max_names || result.queries >= max_names.saturating_add(2))
}

fn stops_nameserver_fallback(result: &DnssecWalkResult, max_names: usize) -> bool {
    reusable_walk_status(&result.status) || reached_walk_limit(result, max_names)
}

fn result_priority(result: &DnssecWalkResult, max_names: usize) -> u8 {
    if reusable_walk_status(&result.status) {
        3
    } else if reached_walk_limit(result, max_names) {
        2
    } else if !result.names.is_empty() {
        1
    } else {
        0
    }
}

fn cached_result(zone: String, cache: DnssecCacheEntry) -> DnssecWalkResult {
    DnssecWalkResult {
        zone,
        nameserver: cache.nameserver,
        status: cache.status,
        queries: 0,
        names: cache.names.into_iter().collect(),
        from_cache: true,
        error: None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn walk_one(
    dns: &DnsEngine,
    root_domain: &str,
    zone: &str,
    nameserver: &str,
    address: IpAddr,
    operation_timeout: Duration,
    max_names: usize,
    limiter: &NsecRateLimiter,
    deadline: Instant,
) -> DnssecWalkResult {
    let mut result = DnssecWalkResult {
        zone: zone.to_owned(),
        nameserver: nameserver.to_owned(),
        status: "unsupported".to_owned(),
        queries: 0,
        names: BTreeSet::new(),
        from_cache: false,
        error: None,
    };
    let zone_name = match Name::from_str(&format!("{zone}.")) {
        Ok(name) => name,
        Err(error) => {
            result.error = Some(error.to_string());
            return result;
        }
    };
    let Some(connect_timeout) = operation_budget(deadline, operation_timeout) else {
        mark_deadline(&mut result);
        return result;
    };
    let socket = SocketAddr::new(address, 53);
    let (stream, sender) = TcpClientStream::new(socket, None, None, TokioRuntimeProvider::new());
    let connected_stream = match timeout(connect_timeout, stream).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => {
            result.error = Some(error.to_string());
            return result;
        }
        Err(_) => {
            if Instant::now() >= deadline {
                mark_deadline(&mut result);
            } else {
                result.error = Some("timeout de connexion DNSSEC".to_owned());
            }
            return result;
        }
    };
    let (client, background) = Client::<TokioRuntimeProvider>::new(connected_stream, sender);
    // Hickory's background driver owns the TCP transport. Keep its abort
    // handle tied to this walk so a phase deadline, Ctrl+C, or an early return
    // closes the task and socket instead of detaching them from the scan.
    let _background = AbortOnDrop(tokio::spawn(background));

    let probe_name = match Name::from_str(&format!("fellaga-nsec-probe-7f4b9d.{zone}.")) {
        Ok(name) => name,
        Err(error) => {
            result.error = Some(error.to_string());
            return result;
        }
    };
    if !wait_for_nsec_query_slot(dns, limiter, deadline).await {
        mark_deadline(&mut result);
        return result;
    }
    result.queries += 1;
    let mut probe_query = Query::query(probe_name, RecordType::A);
    probe_query.set_query_class(DNSClass::IN);
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    options.edns_set_dnssec_ok = true;
    options.recursion_desired = false;
    let mut probe_responses = client.lookup(probe_query, options);
    let Some(probe_timeout) = operation_budget(deadline, operation_timeout) else {
        mark_deadline(&mut result);
        return result;
    };
    let probe = match timeout(probe_timeout, probe_responses.next()).await {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(error))) => {
            result.error = Some(error.to_string());
            return result;
        }
        Ok(None) => {
            result.error = Some("réponse DNSSEC vide".to_owned());
            return result;
        }
        Err(_) => {
            if Instant::now() >= deadline {
                mark_deadline(&mut result);
            } else {
                result.error = Some("timeout de détection NSEC".to_owned());
            }
            return result;
        }
    };
    let mut current = None;
    let mut nsec3 = false;
    for record in probe.answers.iter().chain(&probe.authorities) {
        let RData::DNSSEC(data) = &record.data else {
            continue;
        };
        if matches!(data, DNSSECRData::NSEC3(_)) {
            nsec3 = true;
        }
        let DNSSECRData::NSEC(nsec) = data else {
            continue;
        };
        let owner = record
            .name
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let next_name = nsec
            .next_domain_name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if next_name.starts_with("\\000.") {
            result.status = "nsec-minimal-protected".to_owned();
            return result;
        }
        if let Some(owner) = normalize_observed_name(&owner, root_domain) {
            result.names.insert(owner);
        }
        if let Some(name) = normalize_observed_name(&next_name, root_domain) {
            result.names.insert(name);
        }
        current = Some(nsec.next_domain_name().clone());
        break;
    }
    let Some(mut current) = current else {
        if nsec3 {
            result.status = "nsec3-protected".to_owned();
        }
        return result;
    };
    if current == zone_name {
        result.status = "walked".to_owned();
        return result;
    }
    let mut seen = BTreeSet::new();
    loop {
        if result.names.len() >= max_names || result.queries >= max_names.saturating_add(2) {
            result.status = "partial".to_owned();
            break;
        }
        let current_text = current.to_utf8().to_ascii_lowercase();
        if !seen.insert(current_text) {
            result.status = "walked".to_owned();
            break;
        }
        if !wait_for_nsec_query_slot(dns, limiter, deadline).await {
            mark_deadline(&mut result);
            break;
        }
        result.queries += 1;
        let mut nsec_query = Query::query(current.clone(), RecordType::NSEC);
        nsec_query.set_query_class(DNSClass::IN);
        let mut nsec_responses = client.lookup(nsec_query, options);
        let Some(query_timeout) = operation_budget(deadline, operation_timeout) else {
            mark_deadline(&mut result);
            break;
        };
        let response = match timeout(query_timeout, nsec_responses.next()).await {
            Ok(Some(Ok(response))) => response,
            Ok(Some(Err(error))) => {
                result.error = Some(error.to_string());
                break;
            }
            Ok(None) => {
                result.error = Some("réponse NSEC vide".to_owned());
                break;
            }
            Err(_) => {
                if Instant::now() >= deadline {
                    mark_deadline(&mut result);
                } else {
                    result.error = Some("timeout pendant NSEC walking".to_owned());
                }
                break;
            }
        };
        let mut next = None;
        let mut nsec3 = false;
        for record in response.answers.iter().chain(&response.authorities) {
            let RData::DNSSEC(data) = &record.data else {
                continue;
            };
            if matches!(data, DNSSECRData::NSEC3(_)) {
                nsec3 = true;
            }
            let DNSSECRData::NSEC(nsec) = data else {
                continue;
            };
            let owner = record
                .name
                .to_utf8()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let next_name = nsec
                .next_domain_name()
                .to_utf8()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if let Some(owner) = normalize_observed_name(&owner, root_domain) {
                result.names.insert(owner);
            }
            if let Some(name) = normalize_observed_name(&next_name, root_domain) {
                result.names.insert(name);
            }
            next = Some(nsec.next_domain_name().clone());
            break;
        }
        if nsec3 && next.is_none() {
            result.status = "nsec3-protected".to_owned();
            break;
        }
        let Some(next_name) = next else {
            break;
        };
        if next_name == zone_name {
            result.status = "walked".to_owned();
            break;
        }
        current = next_name;
    }
    if result.status == "unsupported" && !result.names.is_empty() {
        result.status = "partial".to_owned();
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_nsec(
    database: &Database,
    dns: &DnsEngine,
    root_domain: &str,
    zones: BTreeSet<String>,
    operation_timeout: Duration,
    refresh: Duration,
    max_names: usize,
) -> Vec<DnssecWalkResult> {
    discover_nsec_until(
        database,
        dns,
        root_domain,
        zones,
        operation_timeout,
        refresh,
        max_names,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_nsec_bounded(
    database: &Database,
    dns: &DnsEngine,
    root_domain: &str,
    zones: BTreeSet<String>,
    operation_timeout: Duration,
    refresh: Duration,
    max_names: usize,
    phase_deadline: Option<Instant>,
) -> Vec<DnssecWalkResult> {
    discover_nsec_until(
        database,
        dns,
        root_domain,
        zones,
        operation_timeout,
        refresh,
        max_names,
        phase_deadline,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn discover_nsec_until(
    database: &Database,
    dns: &DnsEngine,
    root_domain: &str,
    zones: BTreeSet<String>,
    operation_timeout: Duration,
    refresh: Duration,
    max_names: usize,
    phase_deadline: Option<Instant>,
) -> Vec<DnssecWalkResult> {
    let now = now_epoch();
    let freshness = refresh.as_secs().min(i64::MAX as u64) as i64;
    let database = database.clone();
    let dns = dns.clone();
    let root = root_domain.to_owned();
    let limiter = Arc::new(NsecRateLimiter::default());
    let mut pending = stream::iter(zones)
        .map(move |zone| {
            let database = database.clone();
            let dns = dns.clone();
            let root = root.clone();
            let limiter = limiter.clone();
            async move {
                // Older releases persisted `partial` walks as if they were a
                // complete reusable snapshot. Ignore those legacy rows: a
                // deadline or transient nameserver failure must not suppress a
                // later attempt for the whole refresh window.
                let cached = database
                    .dnssec_cache(&root, &zone)
                    .ok()
                    .flatten()
                    .filter(|cache| reusable_walk_status(&cache.status));
                if let Some(cache) = &cached
                    && reusable_fresh_cache(cache, now, freshness)
                {
                    return cached_result(zone, cache.clone());
                }
                let mut best = DnssecWalkResult {
                    zone: zone.clone(),
                    nameserver: String::new(),
                    status: "unsupported".to_owned(),
                    queries: 0,
                    names: BTreeSet::new(),
                    from_cache: false,
                    error: Some("aucun serveur DNS autoritaire joignable".to_owned()),
                };
                let zone_deadline = Instant::now() + NSEC_ZONE_MAX_RUNTIME;
                let deadline = earliest_deadline(zone_deadline, phase_deadline);
                let mut observed_names = BTreeSet::new();
                let mut total_queries = 0_usize;
                if deadline <= Instant::now() {
                    mark_deadline(&mut best);
                } else {
                    match tokio::time::timeout_at(deadline, dns.authoritative_servers(&zone)).await
                    {
                        Ok(Ok(servers)) => {
                            'servers: for (nameserver, addresses) in servers {
                                for address in addresses {
                                    if deadline <= Instant::now() {
                                        mark_deadline(&mut best);
                                        break 'servers;
                                    }
                                    let attempt = walk_one(
                                        &dns,
                                        &root,
                                        &zone,
                                        &nameserver,
                                        address,
                                        operation_timeout,
                                        max_names,
                                        &limiter,
                                        deadline,
                                    )
                                    .await;
                                    let terminal = stops_nameserver_fallback(&attempt, max_names);
                                    total_queries = total_queries.saturating_add(attempt.queries);
                                    observed_names.extend(attempt.names.iter().cloned());
                                    if result_priority(&attempt, max_names)
                                        > result_priority(&best, max_names)
                                        || (result_priority(&attempt, max_names)
                                            == result_priority(&best, max_names)
                                            && attempt.names.len() > best.names.len())
                                    {
                                        best = attempt;
                                    }
                                    if terminal {
                                        break 'servers;
                                    }
                                }
                            }
                        }
                        Ok(Err(error)) => best.error = Some(error.to_string()),
                        Err(_) => mark_deadline(&mut best),
                    }
                }
                best.queries = total_queries;
                best.names.extend(observed_names);
                if best.names.is_empty()
                    && best.status == "unsupported"
                    && let Some(cache) = cached
                {
                    return cached_result(zone, cache);
                }
                if reusable_walk_status(&best.status)
                    && let Ok(cache) = database.store_dnssec_cache(
                        &root,
                        &zone,
                        &best.nameserver,
                        &best.status,
                        &best.names,
                    )
                {
                    best.names = cache.names.into_iter().collect();
                }
                best
            }
        })
        .buffer_unordered(2);
    let mut results = Vec::new();
    while let Some(result) = pending.next().await {
        results.push(result);
    }
    results.sort_by(|left, right| left.zone.cmp(&right.zone));
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropProbe(std::sync::Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn walk_result(
        status: &str,
        names: impl IntoIterator<Item = &'static str>,
        queries: usize,
        error: Option<&str>,
    ) -> DnssecWalkResult {
        DnssecWalkResult {
            zone: "example.test".to_owned(),
            nameserver: "ns1.example.test".to_owned(),
            status: status.to_owned(),
            queries,
            names: names.into_iter().map(str::to_owned).collect(),
            from_cache: false,
            error: error.map(str::to_owned),
        }
    }

    #[test]
    fn cumulative_deadline_always_caps_the_per_zone_deadline() {
        let now = Instant::now();
        let zone = now + Duration::from_secs(120);
        let phase = now + Duration::from_secs(3);
        assert_eq!(earliest_deadline(zone, Some(phase)), phase);
        assert_eq!(earliest_deadline(zone, None), zone);
    }

    #[test]
    fn expired_deadline_has_no_operation_budget() {
        let expired = Instant::now() - Duration::from_millis(1);
        assert_eq!(operation_budget(expired, Duration::from_secs(3)), None);
    }

    #[tokio::test]
    async fn nsec_background_is_aborted_when_walk_is_cancelled() {
        let dropped = std::sync::Arc::new(AtomicBool::new(false));
        let task_dropped = std::sync::Arc::clone(&dropped);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _probe = DropProbe(task_dropped);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        drop(AbortOnDrop(task));

        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("la tâche NSEC annulée doit libérer immédiatement ses ressources");
    }

    #[tokio::test]
    async fn rate_limiter_never_waits_past_an_expired_deadline() {
        let limiter = NsecRateLimiter::default();
        let expired = Instant::now() - Duration::from_millis(1);
        assert!(!limiter.wait_before(expired).await);
    }

    #[tokio::test]
    async fn nsec_queries_obey_the_shared_dns_engine_rate() {
        let primary = DnsEngine::new_with_rate(
            2,
            Duration::from_secs(1),
            &["192.0.2.1".parse().unwrap()],
            2,
        )
        .unwrap();
        let trusted = DnsEngine::new_with_rate(
            2,
            Duration::from_secs(1),
            &["192.0.2.2".parse().unwrap()],
            100,
        )
        .unwrap()
        .share_rate_limit_with(&primary);
        let deadline = Instant::now() + Duration::from_secs(2);
        assert!(trusted.wait_for_rate_slot_before(deadline).await);

        let limiter = NsecRateLimiter::default();
        let started = Instant::now();
        assert!(wait_for_nsec_query_slot(&primary, &limiter, deadline).await);
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "NSEC bypassed the shared two-queries-per-second cadence"
        );
    }

    #[tokio::test]
    async fn shared_dns_rate_wait_stops_at_the_nsec_deadline() {
        let dns = DnsEngine::new_with_rate(
            1,
            Duration::from_secs(1),
            &["192.0.2.1".parse().unwrap()],
            1,
        )
        .unwrap();
        let initial_deadline = Instant::now() + Duration::from_secs(1);
        assert!(dns.wait_for_rate_slot_before(initial_deadline).await);

        let limiter = NsecRateLimiter::default();
        let short_deadline = Instant::now() + Duration::from_millis(75);
        assert!(!wait_for_nsec_query_slot(&dns, &limiter, short_deadline).await);
    }

    #[test]
    fn only_complete_or_protected_walks_are_reused_from_cache() {
        let cache = |status: &str| DnssecCacheEntry {
            nameserver: "ns1.example.test".to_owned(),
            status: status.to_owned(),
            names: vec!["api.example.test".to_owned()],
            updated_at: 99,
        };
        for status in ["walked", "nsec3-protected", "nsec-minimal-protected"] {
            assert!(reusable_fresh_cache(&cache(status), 100, 3_600));
        }
        assert!(!reusable_fresh_cache(&cache("partial"), 100, 3_600));
        assert!(!reusable_fresh_cache(&cache("unsupported"), 100, 3_600));
        assert!(!reusable_fresh_cache(&cache("walked"), 3_700, 3_600));
    }

    #[test]
    fn transient_and_deadline_partials_try_another_nameserver() {
        let transient = walk_result(
            "partial",
            ["api.example.test"],
            3,
            Some("timeout pendant NSEC walking"),
        );
        let deadline = walk_result(
            "partial",
            ["api.example.test"],
            3,
            Some("budget de temps NSEC atteint"),
        );
        assert!(!stops_nameserver_fallback(&transient, 10));
        assert!(!stops_nameserver_fallback(&deadline, 10));

        let max_names = walk_result(
            "partial",
            ["api.example.test", "mail.example.test"],
            2,
            None,
        );
        assert!(stops_nameserver_fallback(&max_names, 2));
        assert!(!reusable_walk_status(&max_names.status));

        let complete = walk_result("walked", ["api.example.test"], 3, None);
        assert!(stops_nameserver_fallback(&complete, 10));
        assert!(reusable_walk_status(&complete.status));
    }
}
