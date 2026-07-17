use crate::axfr::attempt_axfr;
use crate::candidate::{CandidateProposal, MutationRule, generate_contextual_with_rules};
use crate::confidence::{assess_with_context as assess_confidence, evidence_families};
use crate::ct_monitor::{
    CtProgressCallback, CtProgressEvent, monitor_ct_logs_bounded_with_progress_and_limit,
};
use crate::db::{CachedAnswer, Database};
use crate::discovery::discover_dns_graph;
use crate::dns::{DnsEngine, DnsResolutionOutcome, WildcardProbeOutcome};
use crate::dnssec::discover_nsec_bounded;
use crate::dnssec_proof::{DnssecOwnerState, DnssecProofAssessment, DnssecProofKind};
use crate::intelligence::{IntelligenceConfig, NameObservation, learn_and_generate};
use crate::metadata_discovery::{MetadataDiscoveryConfig, discover_metadata};
use crate::model::{
    CtMonitorResult, DiscoveryEdge, DnssecWalkResult, Finding, OwnerProof, PhaseTiming,
    PipelineMetrics, ResolvedHost, ResolverMetric, ScanResult, SchedulerMetrics, ServiceEndpoint,
    StopReason, WebObservation, WildcardVerdict,
};
use crate::passive::{
    ApiKeyStore, PassivePageSink, current_commoncrawl_endpoint,
    fetch_detailed_bounded_with_sink as fetch_passive_bounded, sanitize_external_error,
    seed_commoncrawl_endpoint, source_metadata, source_policy,
};
use crate::pipeline::DiscoveryPipeline;
use crate::tls::discover as discover_tls_certificates;
use crate::util::{
    domain_hash, labels_from_name, learnable_label, learnable_relative_name, normalize_domain,
    normalize_observed_name, now_epoch,
};
use crate::web_discovery::discover_web_bounded;
use anyhow::{Result, bail};
use futures_util::{FutureExt, StreamExt, stream, stream::FuturesUnordered};
use hickory_net::proto::rr::RecordType;
use serde_json::json;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

const DNSSEC_WILDCARD_SUSPECT_CAP: usize = 4;
const DNSSEC_WILDCARD_SUSPECT_BUDGET: Duration = Duration::from_secs(8);
const METADATA_PHASE_BUDGET_CAP: Duration = Duration::from_secs(30);
const METADATA_DNS_CONCURRENCY: usize = 4;

fn metadata_phase_budget(web_budget_remaining: Option<Duration>) -> Duration {
    web_budget_remaining
        .map(|remaining| remaining.min(METADATA_PHASE_BUDGET_CAP))
        .unwrap_or(METADATA_PHASE_BUDGET_CAP)
}

fn merge_resolver_metrics(
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

#[derive(Debug, Clone)]
pub enum ProgressEvent {
    Started {
        scan_id: i64,
        domain: String,
    },
    Phase {
        name: String,
        detail: String,
    },
    PassiveSource {
        source: String,
        status: String,
        names: usize,
    },
    AxfrAttempt(crate::model::AxfrAttempt),
    TlsCertificates {
        endpoints: usize,
        network: usize,
        successes: usize,
        failures: usize,
        cache_hits: usize,
        names: usize,
        duration_ms: u128,
    },
    DnsGraph {
        queries: usize,
        edges: usize,
        names: usize,
        child_zones: usize,
        services: usize,
        duration_ms: u128,
    },
    WebDiscovery {
        hosts: usize,
        requests: usize,
        cache_hits: usize,
        failures: usize,
        names: usize,
        duration_ms: u128,
    },
    Dnssec {
        zones: usize,
        walked: usize,
        protected: usize,
        queries: usize,
        names: usize,
    },
    CtMonitor {
        logs: usize,
        entries: usize,
        failures: usize,
        names: usize,
        duration_ms: u128,
    },
    DnsProgress {
        phase: String,
        processed: usize,
        total: usize,
        found: usize,
        cache_hits: usize,
        rate: f64,
        elapsed_ms: u128,
    },
    Finding(Finding),
    Warning(String),
    Complete,
}

pub type ProgressCallback = Arc<dyn Fn(ProgressEvent) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub wordlist: Option<PathBuf>,
    pub mutation_rules: Vec<MutationRule>,
    pub max_words: usize,
    pub active_phase_timeout: Duration,
    pub passive: bool,
    pub passive_sources: Vec<String>,
    pub api_keys: ApiKeyStore,
    pub automatic_source_selection: bool,
    pub passive_refresh: Duration,
    pub passive_phase_timeout: Duration,
    pub passive_zone_concurrency: usize,
    pub passive_concurrency: usize,
    pub max_passive: usize,
    pub passive_only: bool,
    pub axfr: bool,
    pub axfr_timeout: Duration,
    pub refresh_cache: bool,
    pub verification_max_age: Duration,
    pub only_live: bool,
    pub profile: String,
    pub checkpoint_every: Duration,
    pub resume: Option<String>,
    pub ttl_cap: u32,
    pub negative_ttl: u32,
    pub include_wildcard: bool,
    pub wildcard_refresh: Duration,
    pub recursive_depth: usize,
    pub recursive_words: usize,
    pub recursive_hosts: usize,
    pub adaptive: bool,
    pub pipeline: bool,
    pub pipeline_rounds: usize,
    pub pipeline_budget: usize,
    pub tls_certificates: bool,
    pub tls_port: u16,
    pub tls_timeout: Duration,
    pub tls_refresh: Duration,
    pub tls_max_hosts: usize,
    pub tls_concurrency: usize,
    pub dns_graph: bool,
    pub graph_max_hosts: usize,
    pub service_discovery: bool,
    pub ptr_pivot: bool,
    pub ptr_max_ips: usize,
    pub dnssec_nsec: bool,
    pub nsec_timeout: Duration,
    pub nsec_refresh: Duration,
    pub nsec_max_names: usize,
    pub nsec_phase_timeout: Duration,
    pub ct_monitor: bool,
    pub ct_timeout: Duration,
    pub ct_phase_timeout: Duration,
    pub ct_max_logs: usize,
    pub ct_entries_per_log: usize,
    pub ct_initial_backfill: usize,
    pub metadata_discovery: bool,
    pub metadata_all_hosts: bool,
    pub metadata_max_requests: usize,
    pub web_discovery: bool,
    pub web_max_hosts: usize,
    pub web_timeout: Duration,
    pub web_phase_timeout: Duration,
    pub web_refresh: Duration,
    pub web_concurrency: usize,
    pub web_max_bytes: usize,
    pub web_assets_per_host: usize,
}

#[derive(Clone)]
pub struct Scanner {
    database: Database,
    dns: DnsEngine,
    trusted_dns: Option<DnsEngine>,
    options: ScanOptions,
    progress: Option<ProgressCallback>,
    passive_request_slots: Arc<tokio::sync::Semaphore>,
}

/// Persists an interrupted state if the scan future is cancelled by a timeout,
/// Ctrl+C, or by a caller dropping it before `scan_inner` returns.  The
/// checkpoint intentionally remains incomplete so `--resume` can reuse it.
struct ScanRunGuard {
    database: Database,
    scan_id: i64,
    started: Instant,
    armed: bool,
}

struct CheckpointHeartbeat {
    stop: Option<tokio::sync::watch::Sender<bool>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl CheckpointHeartbeat {
    fn start(
        database: Database,
        scan_id: i64,
        domain: String,
        options_hash: String,
        every: Duration,
    ) -> Self {
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        // A checkpoint period comes from public library configuration as well
        // as the CLI. Clamp pathological values so interval construction can
        // never overflow Tokio's monotonic clock.
        let every = every.clamp(Duration::from_secs(1), Duration::from_secs(86_400));
        let task = tokio::spawn(async move {
            let now = tokio::time::Instant::now();
            let first_tick = now.checked_add(every).unwrap_or(now);
            let mut interval = tokio::time::interval_at(first_tick, every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = database.upsert_checkpoint(
                            scan_id,
                            &domain,
                            "running",
                            &options_hash,
                        );
                    }
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for CheckpointHeartbeat {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl ScanRunGuard {
    fn new(database: Database, scan_id: i64, started: Instant) -> Self {
        Self {
            database,
            scan_id,
            started,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ScanRunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.database.finish_scan(
            self.scan_id,
            "interrupted",
            0,
            0,
            0,
            self.started.elapsed().as_millis(),
            &["scan annulé; checkpoint conservé pour --resume".to_owned()],
        );
    }
}

#[derive(Debug, Clone)]
struct WildcardProfileObservation {
    signature: Option<BTreeSet<String>>,
    current_probe_reliable: bool,
}

fn wildcard_profile_after_probe(
    cached_signature: Option<BTreeSet<String>>,
    probe: WildcardProbeOutcome,
) -> WildcardProfileObservation {
    match probe {
        WildcardProbeOutcome::Wildcard(signature) => WildcardProfileObservation {
            signature: Some(signature),
            current_probe_reliable: true,
        },
        WildcardProbeOutcome::Normal => WildcardProfileObservation {
            signature: Some(BTreeSet::new()),
            current_probe_reliable: true,
        },
        // A previously confirmed wildcard remains useful as a conservative
        // classification guard, but it is not fresh proof and can never
        // authorize destructive refresh cleanup.
        WildcardProbeOutcome::Indeterminate => WildcardProfileObservation {
            signature: cached_signature.filter(wildcard_signature_is_confirmed),
            current_probe_reliable: false,
        },
    }
}

async fn wildcard_profile_observed(
    database: &Database,
    dns: &DnsEngine,
    zone: &str,
    freshness: Duration,
    force_probe: bool,
    require_positive_consensus: bool,
) -> WildcardProfileObservation {
    // Versions 4/5 invalidate signatures produced before the stricter mixed
    // and incomplete-sample classifier. Consensus remains one level stronger
    // so a trusted cache can still satisfy the non-consensus path.
    let algorithm_version = if require_positive_consensus { 5 } else { 4 };
    let cached = database
        .wildcard_cache(zone)
        .ok()
        .flatten()
        .filter(|cache| {
            wildcard_cache_algorithm_is_current(cache.algorithm_version, algorithm_version)
        });
    if !force_probe
        && let Some(cache) = &cached
        && cache.expires_at > now_epoch()
    {
        return WildcardProfileObservation {
            signature: Some(cache.signature.clone()),
            current_probe_reliable: false,
        };
    }
    let serial = dns.soa_serial(zone).await;
    let probe = if require_positive_consensus {
        dns.wildcard_probe_consensus(zone).await
    } else {
        dns.wildcard_probe(zone).await
    };
    match &probe {
        WildcardProbeOutcome::Wildcard(signature) => {
            let _ = database.store_wildcard_cache_with_algorithm(
                zone,
                signature,
                serial,
                freshness,
                true,
                algorithm_version,
            );
        }
        WildcardProbeOutcome::Normal => {
            let signature = BTreeSet::new();
            let _ = database.store_wildcard_cache_with_algorithm(
                zone,
                &signature,
                serial,
                freshness,
                true,
                algorithm_version,
            );
        }
        WildcardProbeOutcome::Indeterminate => {}
    }
    wildcard_profile_after_probe(cached.map(|cache| cache.signature), probe)
}

fn wildcard_cache_algorithm_is_current(cached_version: i64, required_version: i64) -> bool {
    cached_version >= required_version
}

fn unprofiled_deepest_parents(
    parent_by_host: &HashMap<String, String>,
    wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    selected: &BTreeSet<String>,
) -> BTreeSet<String> {
    parent_by_host
        .values()
        .filter(|parent| !wildcard_by_parent.contains_key(*parent) && !selected.contains(*parent))
        .cloned()
        .collect()
}

const WILDCARD_INDETERMINATE: &str = "FELLAGA:WILDCARD_INDETERMINATE";

fn indeterminate_wildcard_signature() -> BTreeSet<String> {
    BTreeSet::from([WILDCARD_INDETERMINATE.to_owned()])
}

fn wildcard_signature_is_indeterminate(signature: &BTreeSet<String>) -> bool {
    signature.contains(WILDCARD_INDETERMINATE)
}

fn wildcard_signature_is_confirmed(signature: &BTreeSet<String>) -> bool {
    !signature.is_empty() && !wildcard_signature_is_indeterminate(signature)
}

fn wilson_upper_bound(successes: usize, trials: usize) -> f64 {
    if trials == 0 {
        return 1.0;
    }
    // One-sided 95% Wilson score bound.
    let z = 1.644_853_626_951_472_2_f64;
    let n = trials as f64;
    let p = successes.min(trials) as f64 / n;
    let z2 = z * z;
    let center = p + z2 / (2.0 * n);
    let margin = z * ((p * (1.0 - p) / n) + z2 / (4.0 * n * n)).sqrt();
    ((center + margin) / (1.0 + z2 / n)).clamp(0.0, 1.0)
}

fn should_expand_adaptive_wave(
    wildcard_classification_is_reliable: bool,
    previous_positive: usize,
    previous_attempted: usize,
    wave_number: usize,
    passive_positive: usize,
) -> bool {
    if !wildcard_classification_is_reliable {
        return false;
    }
    if wave_number == 2 && passive_positive >= 5 {
        return true;
    }
    previous_attempted < 512
        || wilson_upper_bound(previous_positive, previous_attempted) * 1_000.0 >= 1.0
}

fn source_requires_api_key(source: &str) -> bool {
    source_metadata(source).authentication == "required"
}

fn is_missing_api_key_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains(" absent pour la source ")
        || error.contains("missing api key for source")
        || error.contains("api key missing for source")
        || error.contains("clé api absente pour la source")
}

fn is_preflight_auth_error(error: &str) -> bool {
    if is_missing_api_key_error(error) {
        return true;
    }
    let error = error.to_ascii_lowercase();
    error.contains("doit être au format")
        && (error.contains("_api_key")
            || error.contains("_credentials")
            || error.contains("clé")
            || error.contains("credential"))
}

fn should_retry_source_after_key_added(
    source: &str,
    key_configured: bool,
    last_error: Option<&str>,
) -> bool {
    key_configured
        && last_error.is_some_and(|error| {
            is_missing_api_key_error(error)
                || (source == "otx"
                    && error.contains("429")
                    && error.contains("accès anonyme")
                    && !error.contains("clé fournie"))
        })
}

fn cache_requires_revalidation(
    answer: &ResolvedHost,
    verification_max_age: Duration,
    now: i64,
    require_trusted_consensus: bool,
) -> bool {
    if require_trusted_consensus && answer.resolver_count < 2 && !answer.authoritative_validation {
        return true;
    }
    if verification_max_age.is_zero() {
        return true;
    }
    answer
        .last_verified_at
        .is_none_or(|verified_at| verified_at < verification_cutoff(now, verification_max_age))
}

fn verification_cutoff(now: i64, verification_max_age: Duration) -> i64 {
    i64::try_from(verification_max_age.as_secs())
        .map_or(i64::MIN, |max_age| now.saturating_sub(max_age))
}

fn was_recently_verified(
    last_verified_at: Option<i64>,
    verification_max_age: Duration,
    now: i64,
) -> bool {
    if verification_max_age.is_zero() {
        return false;
    }
    let cutoff = verification_cutoff(now, verification_max_age);
    last_verified_at.is_some_and(|verified_at| verified_at >= cutoff)
}

async fn enrich_authoritative_answers(
    dns: &DnsEngine,
    answers: &mut [ResolvedHost],
    deadline: Option<tokio::time::Instant>,
) {
    if answers.is_empty() {
        return;
    }
    let hosts = answers
        .iter()
        .map(|answer| answer.fqdn.clone())
        .collect::<Vec<_>>();
    let mut pending = stream::iter(hosts)
        .map(|fqdn| async move {
            let confirmed = dns.authoritative_confirms_until(&fqdn, deadline).await;
            (fqdn, confirmed)
        })
        .buffer_unordered(dns.concurrency().clamp(1, 16));
    let mut confirmed = BTreeSet::new();
    loop {
        let next = match deadline {
            Some(deadline) if deadline <= tokio::time::Instant::now() => break,
            Some(deadline) => match tokio::time::timeout_at(deadline, pending.next()).await {
                Ok(next) => next,
                Err(_) => break,
            },
            None => pending.next().await,
        };
        let Some((fqdn, is_confirmed)) = next else {
            break;
        };
        if is_confirmed {
            confirmed.insert(fqdn);
        }
    }
    for answer in answers.iter_mut() {
        answer.authoritative_validation |= confirmed.contains(&answer.fqdn);
    }
}

fn external_retry_after_seconds(error: &str) -> Option<u64> {
    let (_, suffix) = error.split_once("Retry-After=")?;
    let digits = suffix
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

fn external_deferral_seconds(error: &str) -> Option<u64> {
    external_retry_after_seconds(error).or_else(|| {
        let error = error.to_ascii_lowercase();
        (error.contains("http 429")
            || error.contains("quota")
            || error.contains("rate limit")
            || error.contains("rate-limit")
            || error.contains("too many requests"))
        .then_some(15 * 60)
    })
}

fn source_error_is_deferred(error: &str) -> bool {
    external_deferral_seconds(error).is_some() || is_preflight_auth_error(error)
}

fn external_pause_status(retry_in_seconds: i64) -> String {
    let minutes = retry_in_seconds.max(1).saturating_add(59) / 60;
    format!("source externe différée, reprise dans {minutes} min, mémoire permanente")
}

fn record_candidate_wave_results(
    candidates: &[CandidateProposal],
    domain: &str,
    answers: &BTreeMap<String, ResolvedHost>,
    successes: &mut HashMap<String, usize>,
) {
    for candidate in candidates {
        let fqdn = format!("{}.{domain}", candidate.relative_name);
        if answers.contains_key(&fqdn) {
            let count = successes.entry(candidate.generator.clone()).or_default();
            *count = count.saturating_add(1);
        }
    }
}

fn discard_failed_candidate_origins(
    candidates: &[CandidateProposal],
    domain: &str,
    answers: &BTreeMap<String, ResolvedHost>,
    sources: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for candidate in candidates {
        let fqdn = format!("{}.{domain}", candidate.relative_name);
        if answers.contains_key(&fqdn) {
            continue;
        }
        let remove_entry = if let Some(origins) = sources.get_mut(&fqdn) {
            origins.retain(|origin| {
                origin != "dns"
                    && !origin.starts_with("dns-wave-")
                    && !origin.starts_with("candidate:")
            });
            origins.is_empty()
        } else {
            false
        };
        if remove_entry {
            sources.remove(&fqdn);
        }
    }
}

fn candidate_refill_capacity(
    queued: usize,
    total: usize,
    target_queued: usize,
    max_words: usize,
) -> usize {
    target_queued
        .saturating_sub(queued)
        .min(max_words.saturating_sub(total))
}

fn high_value_window_needs_materialization(capacity: usize, exhausted: bool) -> bool {
    capacity > 0 && !exhausted
}

fn high_value_window_persist_limit(
    total: usize,
    inserted: usize,
    max_words: usize,
    payload_len: usize,
) -> usize {
    max_words
        .saturating_sub(total.saturating_add(inserted))
        .min(payload_len)
}

// Mutation induction must never turn a large historical inventory into an
// equally large in-memory working set. Inspect a deterministic prefix, retain
// a smaller mix of the strongest observations and distinct parent/label
// shapes, and only then allocate owned hostname strings.
const MUTATION_OBSERVATION_SCAN_CAP: usize = 20_000;
const MUTATION_OBSERVATION_KEEP_CAP: usize = 5_000;

#[derive(Clone, Copy)]
struct MutationObservationRef<'a> {
    fqdn: &'a str,
    parent_relative: &'a str,
    shape: u8,
    evidence_score: i64,
}

fn mutation_observation_shape(relative: &str) -> u8 {
    let label = relative.split('.').next().unwrap_or_default();
    match (
        label.bytes().any(|byte| byte.is_ascii_digit()),
        label.contains('-'),
    ) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    }
}

fn select_bounded_mutation_observations<'a>(
    domain: &str,
    observed_names: impl IntoIterator<Item = (&'a str, i64)>,
    scan_cap: usize,
    keep_cap: usize,
) -> Vec<String> {
    let scan_cap = scan_cap.min(MUTATION_OBSERVATION_SCAN_CAP);
    let keep_cap = keep_cap.min(MUTATION_OBSERVATION_KEEP_CAP);
    if scan_cap == 0 || keep_cap == 0 {
        return Vec::new();
    }

    // `take` deliberately precedes filtering, sorting, maps and hostname
    // cloning: even a hostile or million-row iterator is polled at most
    // `scan_cap` times.
    let bounded = observed_names
        .into_iter()
        .take(scan_cap)
        .filter_map(|(fqdn, evidence_score)| {
            let prefix = fqdn.strip_suffix(domain)?;
            let relative = prefix.strip_suffix('.')?;
            if relative.is_empty() {
                return None;
            }
            let parent_relative = relative
                .split_once('.')
                .map(|(_, parent)| parent)
                .unwrap_or_default();
            Some(MutationObservationRef {
                fqdn,
                parent_relative,
                shape: mutation_observation_shape(relative),
                evidence_score,
            })
        })
        .collect::<Vec<_>>();

    let mut ranked = bounded.iter().collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .evidence_score
            .cmp(&left.evidence_score)
            .then_with(|| left.fqdn.cmp(right.fqdn))
    });

    let target = keep_cap.min(ranked.len());
    let strongest_quota = target.saturating_add(1) / 2;
    let mut selected = Vec::<&MutationObservationRef<'_>>::with_capacity(target);
    let mut selected_names = BTreeSet::<&str>::new();
    for observation in &ranked {
        if selected_names.insert(observation.fqdn) {
            selected.push(*observation);
        }
        if selected.len() == strongest_quota {
            break;
        }
    }

    // The second half is round-robin across parent zones and label shapes.
    // Each bucket is already evidence-ranked because `ranked` is.
    let mut buckets = BTreeMap::<(&str, u8), Vec<&MutationObservationRef<'_>>>::new();
    for observation in &ranked {
        if !selected_names.contains(observation.fqdn) {
            buckets
                .entry((observation.parent_relative, observation.shape))
                .or_default()
                .push(*observation);
        }
    }
    let mut buckets = buckets.into_iter().collect::<Vec<_>>();
    buckets.sort_by(|(left_key, left), (right_key, right)| {
        let left_score = left
            .first()
            .map(|observation| observation.evidence_score)
            .unwrap_or(i64::MIN);
        let right_score = right
            .first()
            .map(|observation| observation.evidence_score)
            .unwrap_or(i64::MIN);
        right_score
            .cmp(&left_score)
            .then_with(|| left_key.cmp(right_key))
    });
    let mut buckets = buckets
        .into_iter()
        .map(|(_, observations)| observations)
        .collect::<Vec<_>>();
    let mut offsets = vec![0_usize; buckets.len()];
    while selected.len() < target {
        let mut progressed = false;
        for (bucket, offset) in buckets.iter_mut().zip(&mut offsets) {
            while let Some(observation) = bucket.get(*offset).copied() {
                *offset = offset.saturating_add(1);
                if selected_names.insert(observation.fqdn) {
                    selected.push(observation);
                    progressed = true;
                    break;
                }
            }
            if selected.len() == target {
                break;
            }
        }
        if !progressed {
            break;
        }
    }

    // Duplicate-heavy iterators can leave the diversity pass short. Fill from
    // the same deterministic ranking without ever inspecting more input.
    if selected.len() < target {
        for observation in ranked {
            if selected_names.insert(observation.fqdn) {
                selected.push(observation);
            }
            if selected.len() == target {
                break;
            }
        }
    }

    selected
        .into_iter()
        .map(|observation| observation.fqdn.to_owned())
        .collect()
}

fn seed_candidate_priority(sources: &BTreeSet<String>) -> i64 {
    let families = evidence_families(sources);
    let authoritative = families.contains(&crate::model::EvidenceFamily::Authoritative);
    let fresh = sources
        .iter()
        .any(|source| !source.contains(":stale") && !source.contains(":cache"));
    1_000_000_i64
        .saturating_add(if authoritative { 500_000 } else { 0 })
        .saturating_add(if fresh { 100_000 } else { 0 })
        .saturating_add((families.len() as i64).saturating_mul(10_000))
        .saturating_add((sources.len() as i64).saturating_mul(1_000))
}

#[cfg(test)]
fn merge_ct_fallback_names(domain: &str, indexed: Vec<String>, cached: Vec<String>) -> Vec<String> {
    indexed
        .into_iter()
        .chain(cached)
        .filter_map(|name| normalize_observed_name(&name, domain))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
fn materialize_ct_fallback_bounded(
    database: &Database,
    domain: &str,
    limit: usize,
) -> Result<BTreeSet<String>> {
    Ok(merge_ct_fallback_names(
        domain,
        database.ct_passive_names_bounded(domain, limit)?,
        Vec::new(),
    )
    .into_iter()
    .collect())
}

fn source_bootstrap_score(source: &str) -> i64 {
    let metadata = source_metadata(source);
    let family = match metadata.evidence_family {
        crate::model::EvidenceFamily::PassiveDns => 650,
        crate::model::EvidenceFamily::CertificateTransparency => 600,
        crate::model::EvidenceFamily::WebCrawl => 500,
        crate::model::EvidenceFamily::Aggregator => 450,
        crate::model::EvidenceFamily::WebArchive => 350,
        crate::model::EvidenceFamily::CodeSearch => 300,
        crate::model::EvidenceFamily::Authoritative | crate::model::EvidenceFamily::LiveDns => 550,
    };
    let cost = match metadata.cost {
        "low" => 200,
        "medium" => 100,
        _ => -100,
    };
    family + cost + if metadata.experimental { -150 } else { 50 }
}

const PASSIVE_REQUEST_CONCURRENCY: usize = 8;

fn passive_connector_working_set_limit(max_passive: usize) -> usize {
    max_passive
        .saturating_add(PASSIVE_REQUEST_CONCURRENCY - 1)
        .saturating_div(PASSIVE_REQUEST_CONCURRENCY)
}

#[cfg(test)]
fn merge_passive_names_bounded(
    sources: &mut BTreeMap<String, BTreeSet<String>>,
    names: impl IntoIterator<Item = String>,
    origin: String,
    limit: usize,
) -> usize {
    let mut omitted = 0_usize;
    for name in names {
        if let Some(origins) = sources.get_mut(&name) {
            origins.insert(origin.clone());
        } else if sources.len() < limit {
            sources.entry(name).or_default().insert(origin.clone());
        } else {
            omitted = omitted.saturating_add(1);
        }
    }
    omitted
}

fn passive_origin_matches_source(origin: &str, source: &str) -> bool {
    origin
        .strip_prefix("passive:")
        .and_then(|origin| origin.split(':').next())
        == Some(source)
}

fn merge_passive_source_names_bounded(
    sources: &mut BTreeMap<String, BTreeSet<String>>,
    names: impl IntoIterator<Item = String>,
    source: &str,
    qualifier: Option<&str>,
    limit: usize,
) -> usize {
    let origin = qualifier.map_or_else(
        || format!("passive:{source}"),
        |qualifier| format!("passive:{source}:{qualifier}"),
    );
    let mut omitted = 0_usize;
    for name in names {
        if let Some(origins) = sources.get_mut(&name) {
            if !origins
                .iter()
                .any(|existing| passive_origin_matches_source(existing, source))
            {
                origins.insert(origin.clone());
            }
        } else if sources.len() < limit {
            sources.entry(name).or_default().insert(origin.clone());
        } else {
            omitted = omitted.saturating_add(1);
        }
    }
    omitted
}

fn refill_passive_union_from_cache(
    database: &Database,
    domain: &str,
    ordered_sources: &[String],
    sources: &mut BTreeMap<String, BTreeSet<String>>,
    limit: usize,
) -> Result<usize> {
    let before = sources.len();
    for source in ordered_sources {
        if sources.len() >= limit {
            break;
        }
        let Some(entry) = database.passive_cache_bounded(domain, source, limit)? else {
            continue;
        };
        merge_passive_source_names_bounded(sources, entry.names, source, Some("cache"), limit);
    }
    Ok(sources.len().saturating_sub(before))
}

fn passive_name_fingerprints(names: &[String]) -> Vec<u64> {
    let mut fingerprints = names
        .iter()
        .map(|name| {
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            hasher.finish()
        })
        .collect::<Vec<_>>();
    fingerprints.sort_unstable();
    fingerprints.dedup();
    fingerprints
}

fn passive_name_was_known(fingerprints: &[u64], name: &str) -> bool {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    fingerprints.binary_search(&hasher.finish()).is_ok()
}

fn automatic_bulk_source_limit(max_passive: usize) -> usize {
    max_passive
        .saturating_div(10)
        .clamp(500, 10_000)
        .min(max_passive)
}

fn cap_exclusive_bulk_source_names(
    domain: &str,
    sources: &mut BTreeMap<String, BTreeSet<String>>,
    source_prefix: &str,
    limit: usize,
) -> (usize, usize) {
    let mut exclusive = sources
        .iter()
        .filter(|(_, origins)| {
            !origins.is_empty()
                && origins
                    .iter()
                    .all(|origin| origin.starts_with(source_prefix))
        })
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let before = exclusive.len();
    if before <= limit {
        return (before, before);
    }
    exclusive.sort_by_key(|name| {
        let relative = name
            .strip_suffix(&format!(".{domain}"))
            .unwrap_or(name.as_str());
        (
            !learnable_relative_name(relative),
            relative.split('.').count(),
            relative.len(),
            name.clone(),
        )
    });
    let keep = exclusive.into_iter().take(limit).collect::<BTreeSet<_>>();
    sources.retain(|name, origins| {
        !origins
            .iter()
            .all(|origin| origin.starts_with(source_prefix))
            || keep.contains(name)
    });
    (before, keep.len())
}

fn seed_share(batch_limit: usize, active_candidates_enabled: bool) -> usize {
    if !active_candidates_enabled {
        return batch_limit;
    }
    batch_limit.saturating_mul(3).saturating_div(4).max(1)
}

fn late_ct_seed_reserve(max_passive: usize, ct_task_pending: bool) -> usize {
    if !ct_task_pending || max_passive <= 1 {
        return 0;
    }
    max_passive.saturating_div(5).clamp(1, 2_000)
}

type CtTaskJoinResult =
    std::result::Result<Result<(CtMonitorResult, Vec<String>)>, tokio::task::JoinError>;

async fn finish_pending_ct_task_after_grace_with_hook<F>(
    tasks: &mut tokio::task::JoinSet<Result<(CtMonitorResult, Vec<String>)>>,
    grace: Duration,
    before_abort: F,
) -> (Option<CtTaskJoinResult>, bool)
where
    F: Future<Output = ()>,
{
    if let Some(joined) = tasks.try_join_next() {
        return (Some(joined), false);
    }
    if !grace.is_zero()
        && let Ok(Some(joined)) = tokio::time::timeout(grace, tasks.join_next()).await
    {
        return (Some(joined), false);
    }
    if let Some(joined) = tasks.try_join_next() {
        return (Some(joined), false);
    }

    // The test hook also makes the narrow completion-vs-abort race explicit.
    // Production passes a ready future and pays no scheduling delay here.
    before_abort.await;
    tasks.abort_all();
    let mut completed = None;
    let mut terminal_error = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            joined @ Ok(_) if completed.is_none() => completed = Some(joined),
            Err(error) if !error.is_cancelled() && terminal_error.is_none() => {
                terminal_error = Some(Err(error));
            }
            _ => {}
        }
    }
    let joined = completed.or(terminal_error);
    let aborted_without_result = joined.is_none();
    (joined, aborted_without_result)
}

async fn finish_pending_ct_task_after_grace(
    tasks: &mut tokio::task::JoinSet<Result<(CtMonitorResult, Vec<String>)>>,
    grace: Duration,
) -> (Option<CtTaskJoinResult>, bool) {
    finish_pending_ct_task_after_grace_with_hook(tasks, grace, std::future::ready(())).await
}

fn phase_deadline(remaining: Option<Duration>) -> Option<tokio::time::Instant> {
    remaining.map(|remaining| {
        let now = tokio::time::Instant::now();
        // Fail closed for invalid library-provided durations instead of
        // panicking or silently turning a bounded phase into an unbounded one.
        now.checked_add(remaining).unwrap_or(now)
    })
}

fn consume_phase_budget(remaining: &mut Option<Duration>, elapsed: Duration) {
    if let Some(budget) = remaining {
        *budget = budget.saturating_sub(elapsed);
    }
}

fn active_candidate_budget_exhausted(remaining: Option<Duration>) -> bool {
    remaining.is_some_and(|remaining| remaining.is_zero())
}

fn active_candidate_work_allowed(remaining: Option<Duration>) -> bool {
    !active_candidate_budget_exhausted(remaining)
}

fn active_resume_required(
    remaining: Option<Duration>,
    pending_seed_candidates: usize,
    pending_candidates: usize,
    candidate_feed_remaining: bool,
    recursive_work_remaining: bool,
) -> bool {
    pending_seed_candidates > 0
        || recursive_work_remaining
        || (active_candidate_budget_exhausted(remaining)
            && (pending_candidates > 0 || candidate_feed_remaining))
}

fn candidate_uses_active_budget(_candidate: &CandidateProposal) -> bool {
    true
}

fn candidate_uses_discovery_fast_path(
    candidate: &CandidateProposal,
    generated_candidates_enabled: bool,
    resume_queue_draining: bool,
    is_retry: bool,
    is_known: bool,
) -> bool {
    generated_candidates_enabled
        && candidate_uses_active_budget(candidate)
        && candidate.generator != "wordlist"
        && !resume_queue_draining
        && !is_retry
        && !is_known
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchDnsMode {
    Conservative,
    /// Only fresh generated candidates may use this mode. Its negatives are
    /// terminal for the current candidate row but journal-only globally.
    GeneratedDiscovery,
}

impl BatchDnsMode {
    async fn resolve_host(
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
struct RoutedDnsOutcomes {
    positives: Vec<ResolvedHost>,
    cacheable_negatives: Vec<String>,
    discovery_negatives: Vec<String>,
    indeterminate: Vec<String>,
}

fn route_dns_outcomes(
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

fn persist_routed_dns_outcomes(
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
struct DeadlineDnsOutcomes {
    completed: Vec<DnsResolutionOutcome>,
    /// Hosts for which at least one DNS packet was accepted by the transport.
    /// This is the only set allowed to consume a durable retry.
    attempted: Vec<String>,
    /// Resolver futures that were launched but did not finish before the
    /// caller-owned deadline.
    cancelled: Vec<String>,
    /// Hosts that never left the scheduler queue. They must not consume a DNS
    /// retry or create a verification journal entry.
    not_started: Vec<String>,
    deadline_exhausted: bool,
}

/// Drain every outcome that is already ready before observing the deadline,
/// then cancel only the still-pending resolver futures. Keeping the ready branch
/// biased makes the persistence boundary deterministic at the deadline.
async fn collect_dns_outcomes_until<I, Resolve, ResolveFuture, F>(
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

async fn collect_refresh_dns_outcomes(
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

fn dnssec_assessment_proves_nonexistence(assessment: &DnssecProofAssessment) -> bool {
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

/// Assess a deliberately tiny set under one absolute deadline.
///
/// The supplied assessment must already come from local DNSSEC validation.
/// This function intentionally has no AD-bit input and additionally requires a
/// concrete denial proof kind before it can return a hostname for quarantine.
async fn assess_dnssec_suspects_bounded<F, Fut>(
    domain: &str,
    suspects: impl IntoIterator<Item = String>,
    deadline: tokio::time::Instant,
    assess: F,
) -> BTreeSet<String>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = DnssecProofAssessment>,
{
    if deadline <= tokio::time::Instant::now() {
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
        match tokio::time::timeout_at(deadline, pending.next()).await {
            Ok(Some((fqdn, assessment))) => {
                if dnssec_assessment_proves_nonexistence(&assessment) {
                    nonexistent.insert(fqdn);
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    // Dropping the buffered stream cancels all unfinished resolver futures;
    // they never receive a fresh per-name wall-clock budget.
    drop(pending);
    nonexistent
}

#[derive(Debug, Default)]
struct BatchResolution {
    answers: Vec<ResolvedHost>,
    cache_hits: usize,
    resolved_from_network: usize,
    deadline_exhausted: bool,
    indeterminate_hosts: Vec<String>,
    not_started_hosts: Vec<String>,
    attempted_hosts: Vec<String>,
}

impl BatchResolution {
    fn merge(&mut self, mut other: Self) {
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

impl Scanner {
    pub fn new(database: Database, dns: DnsEngine, options: ScanOptions) -> Self {
        let passive_concurrency = options.passive_concurrency.clamp(1, 32);
        Self {
            database,
            dns,
            trusted_dns: None,
            options,
            progress: None,
            passive_request_slots: Arc::new(tokio::sync::Semaphore::new(passive_concurrency)),
        }
    }

    pub fn with_progress(mut self, progress: ProgressCallback) -> Self {
        self.progress = Some(progress);
        self
    }

    pub fn with_trusted_dns(mut self, trusted_dns: DnsEngine) -> Self {
        self.trusted_dns = Some(trusted_dns);
        self
    }

    fn emit(&self, event: ProgressEvent) {
        if let Some(progress) = &self.progress {
            progress(event);
        }
    }

    async fn await_with_phase_heartbeat<F, T>(
        &self,
        name: impl Into<String>,
        detail: impl Into<String>,
        future: F,
    ) -> T
    where
        F: std::future::Future<Output = T>,
    {
        const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);

        let name = name.into();
        let detail = detail.into();
        let started = Instant::now();
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                output = &mut future => return output,
                _ = tokio::time::sleep(HEARTBEAT_EVERY) => {
                    self.emit(ProgressEvent::Phase {
                        name: name.clone(),
                        detail: format!(
                            "{detail}; en cours depuis {:.0}s",
                            started.elapsed().as_secs_f64()
                        ),
                    });
                }
            }
        }
    }

    fn parent_zone(host: &str, domain: &str) -> Option<String> {
        let relative = host.strip_suffix(&format!(".{domain}"))?;
        let (_, parent) = relative.split_once('.')?;
        Some(format!("{parent}.{domain}"))
    }

    fn ancestor_zones(host: &str, domain: &str) -> Vec<String> {
        let mut zones = Vec::new();
        let mut current = host;
        while let Some((_, parent)) = current.split_once('.') {
            if parent == domain {
                break;
            }
            if !parent.ends_with(&format!(".{domain}")) {
                break;
            }
            zones.push(parent.to_owned());
            current = parent;
        }
        zones
    }

    fn applicable_wildcard_signature<'a>(
        host: &str,
        root_wildcard: &'a BTreeSet<String>,
        wildcard_by_parent: &'a BTreeMap<String, BTreeSet<String>>,
    ) -> &'a BTreeSet<String> {
        let mut current = host;
        while let Some((_, parent)) = current.split_once('.') {
            if let Some(signature) = wildcard_by_parent.get(parent) {
                return signature;
            }
            current = parent;
        }
        root_wildcard
    }

    fn is_strict_enrichment_seed(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        !wildcard_signature_is_indeterminate(signature)
            && (!wildcard_signature_is_confirmed(signature)
                || !DnsEngine::matches_wildcard(answer, signature))
    }

    fn answer_is_wildcard_ambiguous(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        wildcard_signature_is_indeterminate(signature)
            || (wildcard_signature_is_confirmed(signature)
                && DnsEngine::matches_wildcard(answer, signature))
    }

    fn answer_matches_confirmed_wildcard_signature(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        wildcard_signature_is_confirmed(signature) && DnsEngine::matches_wildcard(answer, signature)
    }

    fn answer_matches_confirmed_wildcard(
        answer: &ResolvedHost,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        let signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        wildcard_signature_is_confirmed(signature)
            && DnsEngine::exactly_matches_wildcard(answer, signature)
    }

    fn dnssec_wildcard_suspects(
        answers: &[ResolvedHost],
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Vec<String> {
        let mut ranked = answers
            .iter()
            .filter(|answer| {
                Self::answer_is_wildcard_ambiguous(answer, root_wildcard, wildcard_by_parent)
            })
            .map(|answer| {
                (
                    u8::from(!Self::answer_matches_confirmed_wildcard(
                        answer,
                        root_wildcard,
                        wildcard_by_parent,
                    )),
                    answer.fqdn.clone(),
                )
            })
            .collect::<Vec<_>>();
        ranked.sort();
        ranked.dedup_by(|left, right| left.1 == right.1);
        ranked
            .into_iter()
            .map(|(_, fqdn)| fqdn)
            .take(DNSSEC_WILDCARD_SUSPECT_CAP)
            .collect()
    }

    async fn quarantine_dnssec_wildcard_suspects(
        &self,
        scan_id: i64,
        domain: &str,
        suspects: Vec<String>,
        phase_deadline: Option<tokio::time::Instant>,
    ) -> Result<BTreeSet<String>> {
        if suspects.is_empty() {
            return Ok(BTreeSet::new());
        }
        let local_deadline = tokio::time::Instant::now() + DNSSEC_WILDCARD_SUSPECT_BUDGET;
        let deadline = phase_deadline
            .map(|deadline| deadline.min(local_deadline))
            .unwrap_or(local_deadline);
        let dns = self.trusted_dns.as_ref().unwrap_or(&self.dns);
        let nonexistent =
            assess_dnssec_suspects_bounded(domain, suspects, deadline, |fqdn| async move {
                // TXT is intentionally orthogonal to the A/AAAA response that
                // triggered wildcard suspicion. A real owner yields secure
                // exact-owner NODATA, while a synthesized owner can expose the
                // validated denial needed to prove that QNAME nonexistent.
                dns.dnssec_denial_assessment(&fqdn, RecordType::TXT).await
            })
            .await;
        if nonexistent.is_empty() {
            return Ok(nonexistent);
        }
        let hosts = nonexistent.iter().cloned().collect::<Vec<_>>();
        self.database
            .quarantine_dnssec_nonexistent(scan_id, domain, &hosts)?;
        self.emit(ProgressEvent::Phase {
            name: "DNSSEC wildcard".to_owned(),
            detail: format!(
                "{} faux positif(s) prouvé(s) inexistant(s), cache actif purgé avec audit",
                nonexistent.len()
            ),
        });
        Ok(nonexistent)
    }

    async fn wildcard_signature_cached(&self, zone: &str) -> Option<BTreeSet<String>> {
        let (dns, require_positive_consensus) = self
            .trusted_dns
            .as_ref()
            .map(|dns| (dns, true))
            .unwrap_or((&self.dns, false));
        wildcard_profile_observed(
            &self.database,
            dns,
            zone,
            self.options.wildcard_refresh,
            self.options.refresh_cache,
            require_positive_consensus,
        )
        .await
        .signature
    }

    async fn wildcard_signatures_cached(
        &self,
        zones: Vec<String>,
    ) -> BTreeMap<String, BTreeSet<String>> {
        let scanner = self;
        stream::iter(zones)
            .map(|zone| async move {
                let signature = scanner
                    .wildcard_signature_cached(&zone)
                    .await
                    .unwrap_or_else(indeterminate_wildcard_signature);
                (zone, signature)
            })
            .buffer_unordered(16)
            .collect()
            .await
    }

    async fn wildcard_signature_cached_bounded(
        &self,
        zone: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> (BTreeSet<String>, bool) {
        match deadline {
            Some(deadline) if deadline <= tokio::time::Instant::now() => {
                (indeterminate_wildcard_signature(), true)
            }
            Some(deadline) => {
                match tokio::time::timeout_at(deadline, self.wildcard_signature_cached(zone)).await
                {
                    Ok(signature) => (
                        signature.unwrap_or_else(indeterminate_wildcard_signature),
                        false,
                    ),
                    Err(_) => (indeterminate_wildcard_signature(), true),
                }
            }
            None => (
                self.wildcard_signature_cached(zone)
                    .await
                    .unwrap_or_else(indeterminate_wildcard_signature),
                false,
            ),
        }
    }

    async fn wildcard_signatures_cached_bounded(
        &self,
        zones: Vec<String>,
        deadline: Option<tokio::time::Instant>,
    ) -> (BTreeMap<String, BTreeSet<String>>, bool) {
        if zones.is_empty() {
            return (BTreeMap::new(), false);
        }
        if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            return (
                zones
                    .into_iter()
                    .map(|zone| (zone, indeterminate_wildcard_signature()))
                    .collect(),
                true,
            );
        }
        let result = match deadline {
            Some(deadline) => {
                tokio::time::timeout_at(deadline, self.wildcard_signatures_cached(zones.clone()))
                    .await
                    .ok()
            }
            None => Some(self.wildcard_signatures_cached(zones.clone()).await),
        };
        match result {
            Some(signatures) => (signatures, false),
            None => (
                zones
                    .into_iter()
                    .map(|zone| (zone, indeterminate_wildcard_signature()))
                    .collect(),
                true,
            ),
        }
    }

    async fn register_wildcard_parents_bounded(
        &self,
        hosts: &[String],
        domain: &str,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        limit: usize,
        deadline: Option<tokio::time::Instant>,
    ) -> bool {
        let mut counts = HashMap::<String, usize>::new();
        for host in hosts {
            if let Some(parent) = Self::parent_zone(host, domain) {
                parent_by_host.insert(host.clone(), parent.clone());
            }
            for ancestor in Self::ancestor_zones(host, domain) {
                let count = counts.entry(ancestor).or_default();
                *count = count.saturating_add(1);
            }
        }
        let mut parents = counts.into_iter().collect::<Vec<_>>();
        parents.sort_by_key(|(parent, count)| {
            (Reverse(*count), parent.split('.').count(), parent.clone())
        });
        let parents = parents
            .into_iter()
            .map(|(parent, _)| parent)
            .filter(|parent| !wildcard_by_parent.contains_key(parent))
            .take(limit)
            .collect::<Vec<_>>();
        let selected = parents.iter().cloned().collect::<BTreeSet<_>>();
        let omitted_deepest =
            unprofiled_deepest_parents(parent_by_host, wildcard_by_parent, &selected);
        let (signatures, timed_out) = self
            .wildcard_signatures_cached_bounded(parents, deadline)
            .await;
        wildcard_by_parent.extend(signatures);
        for parent in &omitted_deepest {
            wildcard_by_parent
                .entry(parent.clone())
                .or_insert_with(indeterminate_wildcard_signature);
        }
        timed_out || !omitted_deepest.is_empty()
    }

    async fn register_wildcard_parents_with_budget(
        &self,
        hosts: &[String],
        domain: &str,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        limit: usize,
        remaining: &mut Option<Duration>,
    ) -> bool {
        let started = Instant::now();
        let timed_out = self
            .register_wildcard_parents_bounded(
                hosts,
                domain,
                parent_by_host,
                wildcard_by_parent,
                limit,
                phase_deadline(*remaining),
            )
            .await;
        consume_phase_budget(remaining, started.elapsed());
        if timed_out && remaining.is_some() {
            *remaining = Some(Duration::ZERO);
        }
        timed_out
    }

    fn tls_endpoints(
        &self,
        domain: &str,
        answers: &BTreeMap<String, ResolvedHost>,
        services: &[ServiceEndpoint],
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Vec<(String, u16, String)> {
        let hinted = services
            .iter()
            .filter(|service| {
                matches!(
                    service.transport.as_str(),
                    "tcp-tls" | "smtp-starttls" | "imap-starttls" | "pop3-starttls"
                )
            })
            .map(|service| {
                (
                    service.hostname.clone(),
                    service.port,
                    service.transport.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        let mut endpoints = answers
            .values()
            .filter(|answer| {
                Self::is_strict_enrichment_seed(answer, root_wildcard, wildcard_by_parent)
            })
            .map(|answer| {
                (
                    answer.fqdn.clone(),
                    self.options.tls_port,
                    "tcp-tls".to_owned(),
                )
            })
            .collect::<Vec<_>>();
        endpoints.push((
            domain.to_owned(),
            self.options.tls_port,
            "tcp-tls".to_owned(),
        ));
        endpoints.extend(hinted.iter().cloned());
        endpoints.sort_by_key(|(host, port, transport)| {
            let relative = host
                .strip_suffix(&format!(".{domain}"))
                .unwrap_or(host.as_str());
            let first = relative.split('.').next().unwrap_or_default();
            let priority = if hinted.contains(&(host.clone(), *port, transport.clone())) {
                0
            } else {
                match first {
                    "www" => 0,
                    "api" | "auth" | "login" | "account" | "accounts" => 1,
                    "admin" | "portal" | "app" | "dashboard" => 2,
                    "mail" | "webmail" | "smtp" | "imap" => 3,
                    _ if host == domain => 0,
                    _ => 4,
                }
            };
            (
                priority,
                relative.split('.').count(),
                relative.len(),
                host.clone(),
                *port,
                transport.clone(),
            )
        });
        endpoints.dedup();
        endpoints.truncate(self.options.tls_max_hosts);
        endpoints
    }

    fn ordered_candidates<'a>(
        &self,
        domain: &str,
        observed_names: impl IntoIterator<Item = (&'a str, i64)>,
        limit: usize,
    ) -> Result<Vec<CandidateProposal>> {
        let limit = limit.min(100_000);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let observation_keep_cap = limit.min(MUTATION_OBSERVATION_KEEP_CAP);
        let observation_scan_cap = observation_keep_cap
            .saturating_mul(4)
            .min(MUTATION_OBSERVATION_SCAN_CAP);
        let observed_names = select_bounded_mutation_observations(
            domain,
            observed_names,
            observation_scan_cap,
            observation_keep_cap,
        );
        let mut candidates = Vec::new();
        let mut seen = BTreeSet::new();
        let mut add = |candidate: CandidateProposal| {
            if seen.insert(candidate.relative_name.clone()) && candidates.len() < limit {
                candidates.push(candidate);
            }
        };
        let observations = observed_names
            .iter()
            .cloned()
            .map(|fqdn| NameObservation::new(fqdn, None))
            .collect::<Vec<_>>();
        let grammar_config = IntelligenceConfig {
            max_candidates: limit.min(5_000),
            ..IntelligenceConfig::default()
        };
        if let Ok(intelligence) = learn_and_generate(domain, &observations, &grammar_config) {
            self.database
                .store_name_templates(domain, &intelligence.grammar.templates)?;
            for candidate in intelligence.candidates {
                add(CandidateProposal {
                    relative_name: candidate.relative_name,
                    generator: format!("grammar:{}", candidate.template_id),
                    score: 100_000_i64.saturating_add(candidate.score),
                });
            }
        }
        for candidate in generate_contextual_with_rules(
            domain,
            observed_names,
            &self.database.generator_scores(domain)?,
            &self.options.mutation_rules,
            limit.min(2_000),
        ) {
            add(candidate);
        }
        for (rank, pattern) in self
            .database
            .ranked_patterns(limit)?
            .into_iter()
            .enumerate()
        {
            add(CandidateProposal {
                relative_name: pattern,
                generator: "learned-pattern".to_owned(),
                score: 50_000_i64.saturating_sub(rank as i64),
            });
        }
        for (rank, word) in self.database.ranked_words(limit)?.into_iter().enumerate() {
            add(CandidateProposal {
                relative_name: word,
                generator: "learned-word".to_owned(),
                score: 40_000_i64.saturating_sub(rank as i64),
            });
        }
        Ok(candidates)
    }

    /// Keep only a small, durable page in SQLite. Expensive corpora are fed on
    /// demand after the previous DNS wave completes, so DNS starts without a
    /// one-million-row insertion pause.
    fn refill_candidate_queue(
        &self,
        scan_id: i64,
        domain: &str,
        observed_names: &BTreeMap<String, BTreeSet<String>>,
        target_queued: usize,
        allow_generated: bool,
    ) -> Result<usize> {
        let queued = self.database.pending_scan_candidate_count(scan_id)?.max(0) as usize;
        let total = self.database.scan_candidate_budget_count(scan_id)?.max(0) as usize;
        if queued >= target_queued || total >= self.options.max_words {
            return Ok(queued);
        }

        let mut capacity =
            candidate_refill_capacity(queued, total, target_queued, self.options.max_words);
        let mut inserted = 0_usize;

        if let Some(path) = &self.options.wordlist
            && capacity > 0
            && !self
                .database
                .scan_candidate_feed_exhausted(scan_id, "wordlist")?
        {
            let (added, exhausted) = self
                .database
                .refill_wordlist_candidates(scan_id, domain, path, capacity)?;
            inserted += added;
            capacity = capacity.saturating_sub(added);
            // A user-supplied wordlist has priority over the embedded corpus.
            // If this bounded page contained only duplicates/invalid lines,
            // keep its remaining budget for the next cursor page instead of
            // letting built-ins consume `max_words` first.
            if !exhausted {
                return Ok(queued.saturating_add(inserted));
            }
        }

        // An expired active budget stops only newly generated expansion.
        // Durable explicit wordlist pages above remain eligible, while already
        // attempted transient failures are drained by the normal claim path.
        if !allow_generated {
            return Ok(queued.saturating_add(inserted));
        }

        const HIGH_VALUE_WINDOW: usize = 5_000;
        let high_value_exhausted = self
            .database
            .scan_candidate_feed_exhausted(scan_id, "high-value")?;
        if high_value_window_needs_materialization(capacity, high_value_exhausted) {
            let prioritized = self.ordered_candidates(
                domain,
                observed_names
                    .iter()
                    .map(|(name, sources)| (name.as_str(), seed_candidate_priority(sources))),
                HIGH_VALUE_WINDOW,
            )?;
            let payload = prioritized
                .into_iter()
                .map(|candidate| {
                    (
                        candidate.relative_name,
                        candidate.generator,
                        candidate.score,
                    )
                })
                .collect::<Vec<_>>();
            // Materialize the complete bounded high-value window once. A
            // smaller DNS target queue must not cause the same grammar and
            // mutation model to be rebuilt on every wave. The cumulative
            // active budget remains the hard upper bound across resumes.
            let persist_limit = high_value_window_persist_limit(
                total,
                inserted,
                self.options.max_words,
                payload.len(),
            );
            let added = self.database.persist_scan_candidates_bounded(
                scan_id,
                domain,
                &payload,
                persist_limit,
            )?;
            // Either the full bounded payload was examined, or `persist_limit`
            // unique rows filled the remaining max-words budget. In both cases
            // no high-value item can be usefully resumed from this window.
            self.database
                .mark_scan_candidate_feed_exhausted(scan_id, "high-value")?;
            inserted += added;
            capacity = capacity.saturating_sub(added);
        }

        if capacity > 0 {
            inserted += self
                .database
                .persist_prior_candidates_to_scan(scan_id, domain, capacity)?;
        }
        Ok(queued.saturating_add(inserted))
    }

    fn candidate_feeds_have_more(&self, scan_id: i64) -> Result<bool> {
        if self.database.scan_candidate_budget_count(scan_id)?.max(0) as usize
            >= self.options.max_words
        {
            return Ok(false);
        }
        if self.options.wordlist.is_some()
            && !self
                .database
                .scan_candidate_feed_exhausted(scan_id, "wordlist")?
        {
            return Ok(true);
        }
        if !self
            .database
            .scan_candidate_feed_exhausted(scan_id, "high-value")?
        {
            return Ok(true);
        }
        Ok(!self
            .database
            .scan_candidate_feed_exhausted(scan_id, "builtin")?)
    }

    fn explicit_wordlist_has_more(&self, scan_id: i64) -> Result<bool> {
        Ok(self.options.wordlist.is_some()
            && (self.database.scan_candidate_budget_count(scan_id)?.max(0) as usize)
                < self.options.max_words
            && !self
                .database
                .scan_candidate_feed_exhausted(scan_id, "wordlist")?)
    }

    fn recursive_wordlist(&self) -> Result<Vec<String>> {
        let mut words = Vec::new();
        let mut seen = BTreeSet::new();
        for word in self.database.ranked_words(self.options.recursive_words)? {
            if !word.contains('.') && seen.insert(word.clone()) {
                words.push(word);
            }
        }
        for word in self
            .database
            .prior_candidates(self.options.recursive_words.saturating_mul(2))?
        {
            if !word.contains('.') && seen.insert(word.clone()) {
                words.push(word);
            }
            if words.len() >= self.options.recursive_words {
                break;
            }
        }
        words.truncate(self.options.recursive_words);
        Ok(words)
    }

    async fn collect_passive(
        &self,
        domain: &str,
        passive_deadline: Option<tokio::time::Instant>,
        sources: &mut BTreeMap<String, BTreeSet<String>>,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let now = now_epoch();
        let freshness = self.options.passive_refresh.as_secs().min(i64::MAX as u64) as i64;
        let connector_working_set_limit =
            passive_connector_working_set_limit(self.options.max_passive);
        let mut passive_union_omitted = 0_usize;
        // Candidate-wave adaptivity and provider health are independent. An
        // exhaustive brute-force scan must not repeatedly block on a provider
        // that the automatic source scheduler already knows is unhealthy.
        let mut cooldowns = if self.options.automatic_source_selection {
            self.database
                .source_cooldowns(Duration::from_secs(24 * 3_600))?
        } else {
            BTreeSet::new()
        };
        let diagnostics = self
            .database
            .source_diagnostics(Duration::from_secs(24 * 3_600))?;
        let credential_retry_sources = self
            .options
            .passive_sources
            .iter()
            .filter(|source| {
                should_retry_source_after_key_added(
                    source,
                    self.options.api_keys.has(source),
                    diagnostics
                        .get(source.as_str())
                        .and_then(|diagnostic| diagnostic.last_error.as_deref()),
                )
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        for source in &credential_retry_sources {
            cooldowns.remove(source);
        }
        let mut external_pauses = BTreeMap::new();
        if self.options.automatic_source_selection {
            for source in &self.options.passive_sources {
                if credential_retry_sources.contains(source) {
                    continue;
                }
                let key = format!("source.retry_until.{source}");
                if let Some(retry_until) = self
                    .database
                    .source_metadata(&key, Duration::from_secs(365 * 24 * 3_600))?
                    .and_then(|value| value.parse::<i64>().ok())
                    .filter(|retry_until| *retry_until > now)
                {
                    external_pauses.insert(source.clone(), retry_until);
                }
            }
        }
        let mut refresh = Vec::new();
        let mut prior_passive_fingerprints = BTreeMap::<String, Vec<u64>>::new();
        for source in &self.options.passive_sources {
            let cached =
                self.database
                    .passive_cache_bounded(domain, source, connector_working_set_limit)?;
            if source_requires_api_key(source) && !self.options.api_keys.has(source) {
                let names = cached.map(|entry| entry.names).unwrap_or_default();
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    status: "clé API absente, source ignorée, mémoire permanente".to_owned(),
                    names: names.len(),
                });
                passive_union_omitted =
                    passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                        sources,
                        names,
                        source,
                        Some("missing-key"),
                        self.options.max_passive,
                    ));
                continue;
            }
            if cooldowns.contains(source) || external_pauses.contains_key(source) {
                let names = cached.map(|entry| entry.names).unwrap_or_default();
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    status: external_pauses
                        .get(source)
                        .map(|retry_until| external_pause_status(retry_until.saturating_sub(now)))
                        .unwrap_or_else(|| "pause adaptative, mémoire permanente".to_owned()),
                    names: names.len(),
                });
                passive_union_omitted =
                    passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                        sources,
                        names,
                        source,
                        Some("cooldown"),
                        self.options.max_passive,
                    ));
                continue;
            }
            if let Some(entry) = &cached
                && now.saturating_sub(entry.updated_at) < freshness
            {
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    status: "cache frais".to_owned(),
                    names: entry.names.len(),
                });
                passive_union_omitted =
                    passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                        sources,
                        entry.names.iter().cloned(),
                        source,
                        Some("cache"),
                        self.options.max_passive,
                    ));
            } else {
                if let Some(entry) = &cached {
                    prior_passive_fingerprints
                        .insert(source.clone(), passive_name_fingerprints(&entry.names));
                }
                refresh.push(source.clone());
            }
        }

        if refresh.iter().any(|source| source == "commoncrawl")
            && let Some(endpoint) = self.database.source_metadata(
                "commoncrawl.latest_endpoint",
                Duration::from_secs(30 * 24 * 3_600),
            )?
        {
            seed_commoncrawl_endpoint(endpoint);
        }
        let keys = self.options.api_keys.clone();
        let source_scores = self.database.source_scores()?;
        refresh.sort_by_key(|source| {
            (
                Reverse(
                    source_scores
                        .get(source)
                        .copied()
                        .unwrap_or_else(|| source_bootstrap_score(source)),
                ),
                source.clone(),
            )
        });
        let mut unfinished_sources = refresh.iter().cloned().collect::<BTreeSet<_>>();
        let active_sources = Arc::new(Mutex::new(BTreeMap::<String, Instant>::new()));
        let refresh_total = refresh.len();
        let mut refresh_finished = 0_usize;
        let mut phase_timed_out = false;
        let mut results = stream::iter(refresh)
            .map(|source| {
                let keys = keys.clone();
                let active_sources = active_sources.clone();
                let passive_request_slots = self.passive_request_slots.clone();
                let database = self.database.clone();
                let root_domain = domain.to_owned();
                async move {
                    let _permit = passive_request_slots
                        .acquire_owned()
                        .await
                        .expect("le sémaphore passif reste ouvert pendant le scan");
                    let policy = source_policy(&source);
                    let remaining = passive_deadline
                        .map(|deadline| {
                            deadline
                                .saturating_duration_since(tokio::time::Instant::now())
                                .saturating_sub(Duration::from_millis(250))
                        })
                        .unwrap_or(policy.total_timeout)
                        .min(policy.total_timeout);
                    if remaining.is_zero() {
                        return (source, 0, None);
                    }
                    if let Ok(mut active_sources) = active_sources.lock() {
                        active_sources.insert(source.clone(), Instant::now());
                    }
                    let started = Instant::now();
                    let sink_source = source.clone();
                    let page_sink: PassivePageSink = Arc::new(move |names| {
                        database
                            .store_passive_observation_page(&root_domain, &sink_source, names)
                            .map(|_| ())
                    });
                    let result = fetch_passive_bounded(
                        &source,
                        domain,
                        policy.timeout,
                        &keys,
                        remaining,
                        connector_working_set_limit,
                        page_sink,
                    )
                    .await;
                    (source, started.elapsed().as_millis(), Some(result))
                }
            })
            // Providers use independent host-specific throttles; a slightly
            // wider scheduler avoids one slow service holding unrelated fast
            // sources while keeping the network footprint bounded.
            .buffer_unordered(PASSIVE_REQUEST_CONCURRENCY);
        let deadline_sleep = async move {
            if let Some(deadline) = passive_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(deadline_sleep);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let poll = tokio::select! {
                biased;
                _ = &mut deadline_sleep => None,
                _ = heartbeat.tick() => {
                    let active = active_sources
                        .lock()
                        .map(|sources| sources.len())
                        .unwrap_or_default();
                    let remaining = passive_deadline
                        .map(|deadline| format!("{}s", deadline.saturating_duration_since(tokio::time::Instant::now()).as_secs()))
                        .unwrap_or_else(|| "illimité".to_owned());
                    self.emit(ProgressEvent::Phase {
                        name: "passif".to_owned(),
                        detail: format!(
                            "{refresh_finished}/{refresh_total} source(s), {active} active(s), budget restant {remaining}"
                        ),
                    });
                    continue;
                }
                next = results.next() => Some(next),
            };
            let Some(next) = poll else {
                let unfinished = refresh_total.saturating_sub(refresh_finished);
                let warning = format!(
                    "budget passif de {:.1}s atteint; {unfinished} source(s) lente(s) annulée(s), mémoire permanente conservée",
                    self.options.passive_phase_timeout.as_secs_f64()
                );
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
                phase_timed_out = true;
                break;
            };
            let Some((source, duration_ms, result)) = next else {
                break;
            };
            refresh_finished = refresh_finished.saturating_add(1);
            unfinished_sources.remove(&source);
            if let Ok(mut active_sources) = active_sources.lock() {
                active_sources.remove(&source);
            }
            let previously_known = prior_passive_fingerprints
                .remove(&source)
                .unwrap_or_default();
            let stale = self.database.passive_cache_bounded(
                domain,
                &source,
                connector_working_set_limit,
            )?;
            let Some(result) = result else {
                let names = stale.map(|entry| entry.names).unwrap_or_default();
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    status: "cache périmé, source différée par le budget".to_owned(),
                    names: names.len(),
                });
                passive_union_omitted =
                    passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                        sources,
                        names,
                        &source,
                        Some("stale"),
                        self.options.max_passive,
                    ));
                continue;
            };
            match result {
                Ok(fetch) => {
                    let partial_warning = fetch.partial_warning;
                    let working_set_truncated = fetch.working_set_truncated;
                    let network_names = fetch.decoded_names;
                    let names = fetch.names;
                    let novel_names = names
                        .iter()
                        .filter(|name| {
                            !sources.contains_key(*name)
                                && !passive_name_was_known(&previously_known, name)
                        })
                        .count();
                    if partial_warning
                        .as_deref()
                        .is_some_and(|warning| warning.contains("persistance SQLite"))
                    {
                        // Retry the bounded working set once when the page sink
                        // itself failed. Successful sinks must not increment
                        // observation counters a second time.
                        self.database
                            .store_passive_observation_page(domain, &source, &names)?;
                    }
                    self.database.mark_passive_cache_refresh(
                        domain,
                        &source,
                        partial_warning.is_none(),
                    )?;
                    let stale_names = stale.map(|entry| entry.names).unwrap_or_default();
                    let retained_names = names
                        .len()
                        .saturating_add(
                            stale_names
                                .iter()
                                .filter(|name| !names.contains(name.as_str()))
                                .count(),
                        )
                        .min(connector_working_set_limit);
                    if source == "commoncrawl"
                        && let Some(endpoint) = current_commoncrawl_endpoint()
                    {
                        self.database
                            .store_source_metadata("commoncrawl.latest_endpoint", &endpoint)?;
                    }
                    match partial_warning.as_deref() {
                        Some(warning) if network_names == 0 => {
                            self.database
                                .record_source_deferred(&source, duration_ms, warning)?;
                        }
                        Some(warning) => {
                            self.database.record_source_degraded_with_counts(
                                &source,
                                network_names,
                                novel_names,
                                duration_ms,
                                warning,
                            )?;
                        }
                        None => {
                            self.database.record_source_result_with_counts(
                                &source,
                                network_names,
                                novel_names,
                                duration_ms,
                                None,
                            )?;
                        }
                    }
                    if let Some(partial_warning) = &partial_warning {
                        if let Some(delay) = external_deferral_seconds(partial_warning) {
                            let retry_until = now_epoch()
                                .saturating_add(delay.min(i64::MAX as u64) as i64)
                                .to_string();
                            self.database.store_source_metadata(
                                &format!("source.retry_until.{source}"),
                                &retry_until,
                            )?;
                        }
                        let warning = format!(
                            "{source}: {partial_warning}; {} nom(s) frais conservé(s)",
                            network_names
                        );
                        self.emit(ProgressEvent::Warning(warning.clone()));
                        warnings.push(warning);
                    }
                    if working_set_truncated {
                        let warning = format!(
                            "{source}: {network_names} nom(s) décodé(s), ensemble de travail limité à {connector_working_set_limit}; les pages complètes restent dans SQLite"
                        );
                        self.emit(ProgressEvent::Warning(warning.clone()));
                        warnings.push(warning);
                    }
                    self.emit(ProgressEvent::PassiveSource {
                        source: source.clone(),
                        status: if partial_warning.is_some() {
                            "réseau partiel + mémoire permanente".to_owned()
                        } else {
                            "réseau + mémoire permanente".to_owned()
                        },
                        names: retained_names,
                    });
                    let qualifier = if partial_warning.is_some() {
                        Some("partial")
                    } else {
                        None
                    };
                    passive_union_omitted =
                        passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                            sources,
                            names,
                            &source,
                            qualifier,
                            self.options.max_passive,
                        ));
                    passive_union_omitted =
                        passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                            sources,
                            stale_names,
                            &source,
                            Some("stale"),
                            self.options.max_passive,
                        ));
                }
                Err(error) => {
                    let safe_error =
                        sanitize_external_error(&format!("{error:#}"), &self.options.api_keys);
                    let warning = format!("{source}: {safe_error}");
                    if let Some(delay) = external_deferral_seconds(&safe_error) {
                        let retry_until = now_epoch()
                            .saturating_add(delay.min(i64::MAX as u64) as i64)
                            .to_string();
                        self.database.store_source_metadata(
                            &format!("source.retry_until.{source}"),
                            &retry_until,
                        )?;
                    }
                    if source_error_is_deferred(&safe_error) {
                        self.database
                            .record_source_deferred(&source, duration_ms, &safe_error)?;
                    } else {
                        self.database.record_source_result(
                            &source,
                            0,
                            duration_ms,
                            Some(&safe_error),
                        )?;
                    }
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                    if let Some(stale) = stale {
                        let names = stale.names;
                        self.emit(ProgressEvent::PassiveSource {
                            source: source.clone(),
                            status: "cache périmé".to_owned(),
                            names: names.len(),
                        });
                        passive_union_omitted = passive_union_omitted.saturating_add(
                            merge_passive_source_names_bounded(
                                sources,
                                names,
                                &source,
                                Some("stale"),
                                self.options.max_passive,
                            ),
                        );
                    }
                }
            }
        }
        drop(results);
        if phase_timed_out {
            let active_sources = active_sources
                .lock()
                .map(|sources| sources.clone())
                .unwrap_or_default();
            for source in unfinished_sources {
                let started_at = active_sources.get(&source).copied();
                let started = started_at.is_some();
                prior_passive_fingerprints.remove(&source);
                let names = self
                    .database
                    .passive_cache_bounded(domain, &source, connector_working_set_limit)?
                    .map(|entry| entry.names)
                    .unwrap_or_default();
                if let Some(started_at) = started_at {
                    self.database.record_source_deferred(
                        &source,
                        started_at.elapsed().as_millis(),
                        "source cancelled when the shared passive budget ended",
                    )?;
                }
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    status: if started {
                        "cache périmé, requête lente annulée".to_owned()
                    } else {
                        "cache périmé, source différée par le budget".to_owned()
                    },
                    names: names.len(),
                });
                passive_union_omitted =
                    passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                        sources,
                        names,
                        &source,
                        Some("stale"),
                        self.options.max_passive,
                    ));
            }
        }
        let mut durable_sources = self.options.passive_sources.clone();
        durable_sources.sort_by_key(|source| {
            (
                Reverse(
                    source_scores
                        .get(source)
                        .copied()
                        .unwrap_or_else(|| source_bootstrap_score(source)),
                ),
                source.clone(),
            )
        });
        let refilled = refill_passive_union_from_cache(
            &self.database,
            domain,
            &durable_sources,
            sources,
            self.options.max_passive,
        )?;
        passive_union_omitted = passive_union_omitted.saturating_sub(refilled);
        if passive_union_omitted > 0 {
            let warning = format!(
                "budget passif en mémoire atteint: {passive_union_omitted} nom(s) supplémentaires conservé(s) uniquement dans SQLite"
            );
            self.emit(ProgressEvent::Warning(warning.clone()));
            warnings.push(warning);
        }
        if self.options.automatic_source_selection {
            let anubis_limit = automatic_bulk_source_limit(self.options.max_passive);
            let (anubis_total, anubis_kept) =
                cap_exclusive_bulk_source_names(domain, sources, "passive:anubisdb", anubis_limit);
            if anubis_kept < anubis_total {
                let warning = format!(
                    "garde-fou AnubisDB: {anubis_kept}/{anubis_total} noms exclusifs planifiés pour validation; réponse complète conservée en cache permanent"
                );
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
        }
        if sources.len() > self.options.max_passive {
            let source_scores = self.database.source_scores()?;
            let prior_rank = self
                .database
                .prior_candidates(self.options.max_passive.saturating_mul(2))?
                .into_iter()
                .enumerate()
                .map(|(rank, candidate)| (candidate, rank))
                .collect::<HashMap<_, _>>();
            let mut ranked = sources.keys().cloned().collect::<Vec<_>>();
            ranked.sort_by_key(|name| {
                let relative = name
                    .strip_suffix(&format!(".{domain}"))
                    .unwrap_or(name.as_str());
                let origins = sources.get(name).cloned().unwrap_or_default();
                let trusted = origins
                    .iter()
                    .any(|source| !source.contains("anubisdb") && !source.ends_with(":stale"));
                let reliability = origins
                    .iter()
                    .filter_map(|origin| {
                        origin
                            .strip_prefix("passive:")
                            .and_then(|source| source.split(':').next())
                            .and_then(|source| source_scores.get(source))
                    })
                    .copied()
                    .max()
                    .unwrap_or_default();
                (
                    Reverse(origins.len()),
                    !trusted,
                    Reverse(reliability),
                    prior_rank.get(relative).copied().unwrap_or(usize::MAX),
                    !learnable_relative_name(relative),
                    relative.split('.').count(),
                    relative.len(),
                    name.clone(),
                )
            });
            let keep = ranked
                .into_iter()
                .take(self.options.max_passive)
                .collect::<BTreeSet<_>>();
            sources.retain(|name, _| keep.contains(name));
            let warning = format!(
                "résultats passifs limités à {} noms par --max-passive",
                self.options.max_passive
            );
            self.emit(ProgressEvent::Warning(warning.clone()));
            warnings.push(warning);
        }
        Ok(())
    }

    fn cap_seed_sources(
        &self,
        domain: &str,
        sources: &mut BTreeMap<String, BTreeSet<String>>,
        warnings: &mut Vec<String>,
    ) {
        if sources.len() <= self.options.max_passive {
            return;
        }
        let before = sources.len();
        let mut ranked = sources.keys().cloned().collect::<Vec<_>>();
        ranked.sort_by_key(|name| {
            let origins = sources.get(name).cloned().unwrap_or_default();
            let families = evidence_families(&origins);
            let authoritative = families.contains(&crate::model::EvidenceFamily::Authoritative);
            let independent = families
                .iter()
                .any(|family| *family != crate::model::EvidenceFamily::LiveDns);
            let stale_only = origins
                .iter()
                .all(|origin| origin.contains(":stale") || origin.contains(":cache"));
            let relative = name
                .strip_suffix(&format!(".{domain}"))
                .unwrap_or(name.as_str());
            (
                !authoritative,
                !independent,
                stale_only,
                Reverse(origins.len()),
                relative.split('.').count(),
                relative.len(),
                name.clone(),
            )
        });
        let keep = ranked
            .into_iter()
            .take(self.options.max_passive)
            .collect::<BTreeSet<_>>();
        sources.retain(|name, _| keep.contains(name));
        let warning = format!(
            "budget global de découverte appliqué: {} noms conservés sur {before}",
            sources.len()
        );
        self.emit(ProgressEvent::Warning(warning.clone()));
        warnings.push(warning);
    }

    fn inferred_passive_zones(
        &self,
        root_domain: &str,
        names: impl IntoIterator<Item = String>,
        limit: usize,
    ) -> Vec<String> {
        let mut yields = BTreeMap::<String, usize>::new();
        for name in names {
            let Some(relative) = name.strip_suffix(&format!(".{root_domain}")) else {
                continue;
            };
            let labels = relative.split('.').collect::<Vec<_>>();
            if labels.len() < 2 {
                continue;
            }
            let parent = format!("{}.{root_domain}", labels[1..].join("."));
            *yields.entry(parent).or_default() += 1;
        }
        let mut zones = yields
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .collect::<Vec<_>>();
        zones.sort_by_key(|(zone, count)| (Reverse(*count), zone.clone()));
        zones
            .into_iter()
            .take(limit)
            .map(|(zone, _)| zone)
            .collect()
    }

    async fn collect_passive_recursively(
        &self,
        root_domain: &str,
        zones: impl IntoIterator<Item = String>,
        passive_deadline: Option<tokio::time::Instant>,
        queried_zones: &mut BTreeSet<String>,
        sources: &mut BTreeMap<String, BTreeSet<String>>,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<String>> {
        let zone_limit = match self.options.profile.as_str() {
            "deep" | "passive" => 20,
            "balanced" => 5,
            _ => 3,
        };
        let before = sources.keys().cloned().collect::<BTreeSet<_>>();
        let mut tasks = Vec::new();
        for zone in zones
            .into_iter()
            .filter(|zone| zone != root_domain)
            .filter(|zone| queried_zones.insert(zone.clone()))
            .take(zone_limit)
        {
            let child_query = zone.ends_with(&format!(".{root_domain}"));
            let parent_query = root_domain.ends_with(&format!(".{zone}"));
            if !child_query && !parent_query {
                continue;
            }
            let compatible_sources = self
                .options
                .passive_sources
                .iter()
                .filter(|source| {
                    let metadata = source_metadata(source);
                    (child_query && metadata.recursive_children)
                        || (parent_query && metadata.recursive_parents)
                })
                .cloned()
                .collect::<Vec<_>>();
            if compatible_sources.is_empty() {
                continue;
            }
            let mut options = self.options.clone();
            options.passive_sources = compatible_sources;
            let recursive_scanner = Scanner {
                database: self.database.clone(),
                dns: self.dns.clone(),
                trusted_dns: self.trusted_dns.clone(),
                options,
                progress: self.progress.clone(),
                passive_request_slots: self.passive_request_slots.clone(),
            };
            tasks.push((zone, child_query, recursive_scanner));
        }

        let zone_total = tasks.len();
        let mut zone_completed = 0_usize;
        let recursive_deadline = passive_deadline;
        let mut pending = stream::iter(tasks)
            .map(|(zone, child_query, recursive_scanner)| async move {
                recursive_scanner.emit(ProgressEvent::Phase {
                    name: "passif récursif".to_owned(),
                    detail: format!(
                        "zone {zone} ({})",
                        if child_query { "fille" } else { "parente" }
                    ),
                });
                let mut zone_sources = BTreeMap::new();
                let mut zone_warnings = Vec::new();
                let result = recursive_scanner
                    .collect_passive(
                        &zone,
                        passive_deadline,
                        &mut zone_sources,
                        &mut zone_warnings,
                    )
                    .await;
                (zone, zone_sources, zone_warnings, result)
            })
            .buffer_unordered(self.options.passive_zone_concurrency.clamp(1, 32));
        loop {
            let next = if let Some(deadline) = recursive_deadline {
                match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(next) => next,
                    Err(_) => {
                        let unfinished = zone_total.saturating_sub(zone_completed);
                        let warning = format!(
                            "budget passif récursif de {:.1}s atteint; {unfinished} zone(s) restante(s) annulée(s)",
                            self.options.passive_phase_timeout.as_secs_f64()
                        );
                        self.emit(ProgressEvent::Warning(warning.clone()));
                        warnings.push(warning);
                        break;
                    }
                }
            } else {
                pending.next().await
            };
            let Some((zone, zone_sources, zone_warnings, result)) = next else {
                break;
            };
            result?;
            zone_completed = zone_completed.saturating_add(1);
            warnings.extend(
                zone_warnings
                    .into_iter()
                    .map(|warning| format!("{zone}: {warning}")),
            );
            let mut truncated = 0_usize;
            for (name, origins) in zone_sources {
                if normalize_observed_name(&name, root_domain).is_some() {
                    if let Some(entry) = sources.get_mut(&name) {
                        entry.extend(
                            origins
                                .into_iter()
                                .map(|origin| format!("{origin}:recursive")),
                        );
                    } else if sources.len() < self.options.max_passive {
                        sources.insert(
                            name,
                            origins
                                .into_iter()
                                .map(|origin| format!("{origin}:recursive"))
                                .collect(),
                        );
                    } else {
                        truncated += 1;
                    }
                }
            }
            if truncated > 0 {
                let warning = format!(
                    "{zone}: {truncated} nom(s) récursif(s) ignoré(s), budget global atteint"
                );
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
                break;
            }
        }
        Ok(sources
            .keys()
            .filter(|name| !before.contains(*name))
            .cloned()
            .collect())
    }

    fn finding_for_answer(
        &self,
        answer: &ResolvedHost,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        _parent_by_host: &HashMap<String, String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Option<Finding> {
        let mut answer_sources = sources.get(&answer.fqdn).cloned().unwrap_or_default();
        if answer.authoritative_validation {
            answer_sources.insert("authoritative-validation".to_owned());
        }
        let families = evidence_families(&answer_sources);
        let strong_observation = families.len() >= 2
            || answer_sources.iter().any(|source| {
                source.starts_with("axfr:")
                    || source.starts_with("tls-cert:")
                    || source.starts_with("dnssec-nsec:")
                    || source.starts_with("dns-graph:")
                    || source.starts_with("passive:ct-direct")
                    || source.starts_with("passive:crtsh")
                    || source.starts_with("passive:certspotter")
            });
        let wildcard_signature =
            Self::applicable_wildcard_signature(&answer.fqdn, root_wildcard, wildcard_by_parent);
        let wildcard_indeterminate = wildcard_signature_is_indeterminate(wildcard_signature);
        let wildcard = wildcard_signature_is_confirmed(wildcard_signature)
            && DnsEngine::matches_wildcard(answer, wildcard_signature);
        let wildcard_ambiguous = wildcard || wildcard_indeterminate;
        if wildcard && !self.options.include_wildcard {
            return None;
        }
        if wildcard_indeterminate && !self.options.include_wildcard && !strong_observation {
            return None;
        }
        let recently_verified = was_recently_verified(
            answer.last_verified_at,
            self.options.verification_max_age,
            crate::util::now_epoch(),
        );
        let state = if wildcard_ambiguous {
            crate::model::ObservationState::Unverified
        } else if !answer.from_cache || recently_verified {
            crate::model::ObservationState::Live
        } else {
            crate::model::ObservationState::Historical
        };
        let confidence = assess_confidence(
            &answer_sources,
            wildcard_ambiguous,
            state,
            !answer.from_cache,
        );
        let discovery_score = confidence.score as f64 / 100.0;
        let generation_path = answer_sources
            .iter()
            .filter(|source| {
                source.starts_with("candidate:")
                    || source.starts_with("grammar:")
                    || source.starts_with("dns-wave-")
                    || source.starts_with("metadata:")
            })
            .cloned()
            .collect::<Vec<_>>();
        Some(Finding {
            fqdn: answer.fqdn.clone(),
            records: answer.records.clone(),
            sources: answer_sources,
            wildcard: wildcard_ambiguous,
            from_cache: answer.from_cache,
            confidence,
            state,
            last_verified_at: (!wildcard_ambiguous)
                .then_some(answer.last_verified_at)
                .flatten(),
            evidence_families: families,
            authoritative_validation: answer.authoritative_validation,
            wildcard_verdict: if wildcard_ambiguous {
                WildcardVerdict::Ambiguous
            } else {
                WildcardVerdict::ExactOwner
            },
            owner_proofs: if answer.authoritative_validation {
                BTreeSet::from([OwnerProof::AuthoritativeDistinct])
            } else if !wildcard_ambiguous {
                BTreeSet::from([OwnerProof::ControlDistribution])
            } else {
                BTreeSet::new()
            },
            generation_path,
            discovery_score: Some(discovery_score),
        })
    }

    fn finding_for_unresolved_seed(
        &self,
        fqdn: String,
        sources: BTreeSet<String>,
        fallback_state: crate::model::ObservationState,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Finding {
        let families = evidence_families(&sources);
        let authoritative = families.contains(&crate::model::EvidenceFamily::Authoritative);
        let signature =
            Self::applicable_wildcard_signature(&fqdn, root_wildcard, wildcard_by_parent);
        let wildcard_ambiguous = !authoritative
            && (wildcard_signature_is_confirmed(signature)
                || wildcard_signature_is_indeterminate(signature));
        let state = if authoritative {
            crate::model::ObservationState::Live
        } else {
            fallback_state
        };
        let from_cache = sources
            .iter()
            .all(|source| source.contains(":cache") || source.contains(":stale"));
        let confidence = assess_confidence(
            &sources,
            wildcard_ambiguous,
            state,
            authoritative && !from_cache,
        );
        let discovery_score = confidence.score as f64 / 100.0;
        Finding {
            fqdn,
            records: Vec::new(),
            sources,
            wildcard: wildcard_ambiguous,
            from_cache,
            confidence,
            state,
            last_verified_at: None,
            evidence_families: families,
            authoritative_validation: authoritative,
            wildcard_verdict: if wildcard_ambiguous {
                WildcardVerdict::Ambiguous
            } else if authoritative {
                WildcardVerdict::ExactOwner
            } else {
                WildcardVerdict::NotProfiled
            },
            owner_proofs: authoritative
                .then_some(OwnerProof::AuthoritativeDistinct)
                .into_iter()
                .collect(),
            generation_path: Vec::new(),
            discovery_score: Some(discovery_score),
        }
    }

    fn append_persistent_inventory(
        &self,
        domain: &str,
        findings: &mut Vec<Finding>,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<usize> {
        let mut known = findings
            .iter()
            .map(|finding| finding.fqdn.clone())
            .collect::<BTreeSet<_>>();
        let before = findings.len();
        let mut cursor = None::<String>;
        loop {
            let inventory =
                self.database
                    .inventory_page(domain, false, cursor.as_deref(), 4_096)?;
            if inventory.is_empty() {
                break;
            }
            cursor = inventory.last().map(|entry| entry.fqdn.clone());
            let missing_names = inventory
                .iter()
                .filter(|entry| !known.contains(&entry.fqdn))
                .map(|entry| entry.fqdn.clone())
                .collect::<Vec<_>>();
            let cached = self.database.fresh_cache(&missing_names)?;
            for entry in inventory {
                if !known.insert(entry.fqdn.clone()) {
                    continue;
                }
                let answer = cached.get(&entry.fqdn).and_then(|cached| match cached {
                    CachedAnswer::Positive(answer) => Some(answer),
                    CachedAnswer::Negative => None,
                });
                let signature = Self::applicable_wildcard_signature(
                    &entry.fqdn,
                    root_wildcard,
                    wildcard_by_parent,
                );
                let wildcard_indeterminate = wildcard_signature_is_indeterminate(signature);
                let confirmed_wildcard_match = wildcard_signature_is_confirmed(signature)
                    && answer.is_some_and(|answer| DnsEngine::matches_wildcard(answer, signature));
                let wildcard = wildcard_indeterminate || confirmed_wildcard_match;
                if confirmed_wildcard_match && !self.options.include_wildcard {
                    continue;
                }
                let state = if wildcard {
                    crate::model::ObservationState::Unverified
                } else {
                    entry.state
                };
                let families = evidence_families(&entry.sources);
                let confidence = assess_confidence(&entry.sources, wildcard, state, false);
                let discovery_score = confidence.score as f64 / 100.0;
                findings.push(Finding {
                    fqdn: entry.fqdn,
                    records: answer
                        .map(|answer| answer.records.clone())
                        .unwrap_or_default(),
                    sources: entry.sources,
                    wildcard,
                    from_cache: true,
                    confidence,
                    state,
                    last_verified_at: (!wildcard).then_some(entry.last_verified_at).flatten(),
                    evidence_families: families,
                    authoritative_validation: answer
                        .is_some_and(|answer| answer.authoritative_validation),
                    wildcard_verdict: if wildcard {
                        WildcardVerdict::Ambiguous
                    } else {
                        WildcardVerdict::NotProfiled
                    },
                    owner_proofs: BTreeSet::new(),
                    generation_path: vec!["persistent_inventory".to_owned()],
                    discovery_score: Some(discovery_score),
                });
            }
        }
        findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        Ok(findings.len().saturating_sub(before))
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_batch(
        &self,
        scan_id: i64,
        domain: &str,
        hosts: &[String],
        phase: &str,
        scan_started: &Instant,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        parent_by_host: &HashMap<String, String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<(Vec<ResolvedHost>, usize, usize)> {
        let result = self
            .resolve_batch_with_deadline(
                scan_id,
                domain,
                hosts,
                phase,
                scan_started,
                sources,
                root_wildcard,
                parent_by_host,
                wildcard_by_parent,
                None,
                BatchDnsMode::Conservative,
            )
            .await?;
        Ok((
            result.answers,
            result.cache_hits,
            result.resolved_from_network,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_batch_with_deadline(
        &self,
        scan_id: i64,
        domain: &str,
        hosts: &[String],
        phase: &str,
        scan_started: &Instant,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        parent_by_host: &HashMap<String, String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
        deadline: Option<tokio::time::Instant>,
        mode: BatchDnsMode,
    ) -> Result<BatchResolution> {
        let cached = if self.options.refresh_cache {
            HashMap::new()
        } else {
            self.database.fresh_cache(hosts)?
        };
        let batch_started = Instant::now();
        let total = hosts.len();
        let mut answers = Vec::new();
        let mut cache_hits = 0;
        let mut network_hosts = Vec::new();
        let mut processed = 0;
        let mut found = 0;
        for host in hosts {
            match cached.get(host) {
                Some(CachedAnswer::Positive(answer)) => {
                    // A fresh positive cache entry is not independent evidence
                    // against a confirmed wildcard profile. Revalidate it on
                    // the network so a historical wildcard response cannot
                    // survive forever merely because positive cache rows do
                    // not expire. An indeterminate profile intentionally does
                    // not enter this destructive path.
                    let cached_wildcard_match = Self::answer_matches_confirmed_wildcard_signature(
                        answer,
                        root_wildcard,
                        wildcard_by_parent,
                    );
                    if cached_wildcard_match
                        || cache_requires_revalidation(
                            answer,
                            self.options.verification_max_age,
                            now_epoch(),
                            self.trusted_dns.is_some(),
                        )
                    {
                        network_hosts.push(host.clone());
                        continue;
                    }
                    cache_hits += 1;
                    processed += 1;
                    if let Some(finding) = self.finding_for_answer(
                        answer,
                        sources,
                        root_wildcard,
                        parent_by_host,
                        wildcard_by_parent,
                    ) {
                        answers.push(answer.clone());
                        found += 1;
                        self.emit(ProgressEvent::Finding(finding));
                    }
                }
                Some(CachedAnswer::Negative) => {
                    cache_hits += 1;
                    processed += 1;
                }
                None => network_hosts.push(host.clone()),
            }
        }
        if processed > 0 || total == 0 {
            self.emit(ProgressEvent::DnsProgress {
                phase: phase.to_owned(),
                processed,
                total,
                found,
                cache_hits,
                rate: processed as f64 / batch_started.elapsed().as_secs_f64().max(0.001),
                elapsed_ms: scan_started.elapsed().as_millis(),
            });
        }
        let mut last_report = Instant::now();
        let mut last_reported = processed;
        let dns = self.dns.clone();
        let network_batch = collect_dns_outcomes_until(
            network_hosts.clone(),
            self.dns.concurrency(),
            deadline,
            move |host, network_attempted| {
                let dns = dns.clone();
                async move { mode.resolve_host(&dns, &host, network_attempted).await }
            },
            |outcome| {
                processed += 1;
                let found_now = (self.trusted_dns.is_none())
                    .then_some(outcome.answer())
                    .flatten()
                    .and_then(|answer| {
                        self.finding_for_answer(
                            answer,
                            sources,
                            root_wildcard,
                            parent_by_host,
                            wildcard_by_parent,
                        )
                    })
                    .map(|finding| {
                        found += 1;
                        self.emit(ProgressEvent::Finding(finding));
                    })
                    .is_some();
                if found_now
                    || processed == total
                    || last_report.elapsed() >= Duration::from_millis(250)
                {
                    self.emit(ProgressEvent::DnsProgress {
                        phase: phase.to_owned(),
                        processed,
                        total,
                        found,
                        cache_hits,
                        rate: processed as f64 / batch_started.elapsed().as_secs_f64().max(0.001),
                        elapsed_ms: scan_started.elapsed().as_millis(),
                    });
                    last_report = Instant::now();
                    last_reported = processed;
                }
            },
        )
        .await;
        // A scheduled future can spend its whole phase budget waiting for a
        // shared rate or socket slot. Charge the retry only after the transport
        // confirms that a packet left; a post-send cancellation still counts.
        let attempted_hosts = network_batch.attempted.clone();
        self.database
            .mark_scan_candidates_started(scan_id, &attempted_hosts)?;
        self.database
            .mark_scan_seed_candidates_started(scan_id, &attempted_hosts)?;
        self.database
            .requeue_unstarted_scan_seed_candidates(scan_id, &network_batch.not_started)?;
        let mut deadline_exhausted = network_batch.deadline_exhausted;
        let not_started = network_batch.not_started;
        let routed = route_dns_outcomes(mode, network_batch.completed, network_batch.cancelled);
        let mut network_answers = routed.positives;
        let mut definitive_negative = routed.cacheable_negatives;
        let mut discovery_negative = routed.discovery_negatives;
        let mut indeterminate = routed.indeterminate;
        // Capture every current answer shaped by a confirmed wildcard before
        // output filtering can discard it. Exact consensus matches may later
        // authorize quarantine; supersets and one-resolver answers may not.
        let mut current_wildcard_answers = BTreeMap::<String, ResolvedHost>::new();
        let mut current_exact_wildcard_matches = BTreeMap::<String, ResolvedHost>::new();
        if self.trusted_dns.is_none() {
            for answer in &network_answers {
                if Self::answer_matches_confirmed_wildcard_signature(
                    answer,
                    root_wildcard,
                    wildcard_by_parent,
                ) {
                    current_wildcard_answers.insert(answer.fqdn.clone(), answer.clone());
                }
                if Self::answer_matches_confirmed_wildcard(
                    answer,
                    root_wildcard,
                    wildcard_by_parent,
                ) {
                    current_exact_wildcard_matches.insert(answer.fqdn.clone(), answer.clone());
                }
            }
        }
        let dnssec_suspects =
            Self::dnssec_wildcard_suspects(&network_answers, root_wildcard, wildcard_by_parent);
        let dnssec_nonexistent = self
            .quarantine_dnssec_wildcard_suspects(scan_id, domain, dnssec_suspects, deadline)
            .await?;
        if !dnssec_nonexistent.is_empty() {
            // These names are removed only after a locally validated denial.
            // Inconclusive, ENT, positive, unsigned, and AD-only outcomes stay
            // on the pre-existing wildcard path unchanged.
            network_answers.retain(|answer| !dnssec_nonexistent.contains(&answer.fqdn));
            answers.retain(|answer| !dnssec_nonexistent.contains(&answer.fqdn));
        }
        let mut wildcard_answers = Vec::new();
        let mut validation_candidates = Vec::new();
        let mut suppressed_wildcard = 0_usize;
        for answer in network_answers {
            if self.trusted_dns.is_some()
                || Self::is_strict_enrichment_seed(&answer, root_wildcard, wildcard_by_parent)
            {
                validation_candidates.push(answer);
            } else if self
                .finding_for_answer(
                    &answer,
                    sources,
                    root_wildcard,
                    parent_by_host,
                    wildcard_by_parent,
                )
                .is_some()
            {
                wildcard_answers.push(answer);
            } else {
                suppressed_wildcard += 1;
            }
        }
        if suppressed_wildcard > 0 {
            self.emit(ProgressEvent::Phase {
                name: "wildcard".to_owned(),
                detail: format!(
                    "{suppressed_wildcard} réponse(s) wildcard ambiguë(s) écartée(s) du cache"
                ),
            });
        }
        if let Some(trusted_dns) = &self.trusted_dns {
            let validation_total = validation_candidates.len();
            let validation_started = Instant::now();
            let validation_hosts = validation_candidates
                .iter()
                .map(|answer| answer.fqdn.clone())
                .collect::<Vec<_>>();
            let mut validation_processed = 0_usize;
            let mut validation_found = 0_usize;
            let mut last_validation_report = Instant::now();
            let trusted_concurrency = trusted_dns.concurrency().clamp(1, 32);
            let validation_dns = trusted_dns.clone();
            let authoritative_dns = trusted_dns.clone();
            let validation_batch = collect_dns_outcomes_until(
                validation_hosts,
                trusted_concurrency,
                deadline,
                move |fqdn, network_attempted| {
                    let validation_dns = validation_dns.clone();
                    async move {
                        validation_dns
                            .resolve_host_consensus_classified_with_network_signal(
                                &fqdn,
                                network_attempted,
                            )
                            .await
                    }
                },
                |outcome| {
                    validation_processed += 1;
                    validation_found += usize::from(outcome.answer().is_some());
                    if validation_processed == validation_total
                        || last_validation_report.elapsed() >= Duration::from_millis(250)
                    {
                        self.emit(ProgressEvent::DnsProgress {
                            phase: format!("{phase} trusted"),
                            processed: validation_processed,
                            total: validation_total,
                            found: validation_found,
                            cache_hits: 0,
                            rate: validation_processed as f64
                                / validation_started.elapsed().as_secs_f64().max(0.001),
                            elapsed_ms: scan_started.elapsed().as_millis(),
                        });
                        last_validation_report = Instant::now();
                    }
                },
            )
            .await;
            deadline_exhausted |= validation_batch.deadline_exhausted;
            let mut validated = Vec::new();
            for outcome in validation_batch.completed {
                match outcome {
                    DnsResolutionOutcome::Positive(consensus) => validated.push(consensus),
                    DnsResolutionOutcome::Negative { fqdn }
                    | DnsResolutionOutcome::Indeterminate { fqdn } => indeterminate.push(fqdn),
                }
            }
            indeterminate.extend(validation_batch.cancelled);
            indeterminate.extend(validation_batch.not_started);
            validated.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
            enrich_authoritative_answers(&authoritative_dns, &mut validated, deadline).await;
            for answer in validated {
                if Self::answer_matches_confirmed_wildcard_signature(
                    &answer,
                    root_wildcard,
                    wildcard_by_parent,
                ) {
                    current_wildcard_answers.insert(answer.fqdn.clone(), answer.clone());
                }
                if Self::answer_matches_confirmed_wildcard(
                    &answer,
                    root_wildcard,
                    wildcard_by_parent,
                ) {
                    current_exact_wildcard_matches.insert(answer.fqdn.clone(), answer.clone());
                }
                if self
                    .finding_for_answer(
                        &answer,
                        sources,
                        root_wildcard,
                        parent_by_host,
                        wildcard_by_parent,
                    )
                    .is_some()
                {
                    wildcard_answers.push(answer);
                } else {
                    suppressed_wildcard = suppressed_wildcard.saturating_add(1);
                }
            }
            wildcard_answers.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
            for answer in &wildcard_answers {
                if let Some(finding) = self.finding_for_answer(
                    answer,
                    sources,
                    root_wildcard,
                    parent_by_host,
                    wildcard_by_parent,
                ) {
                    found += 1;
                    self.emit(ProgressEvent::Finding(finding));
                }
            }
            network_answers = wildcard_answers;
        } else {
            wildcard_answers.extend(validation_candidates);
            wildcard_answers.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
            network_answers = wildcard_answers;
        }
        if last_reported != processed {
            self.emit(ProgressEvent::DnsProgress {
                phase: phase.to_owned(),
                processed,
                total,
                found,
                cache_hits,
                rate: processed as f64 / batch_started.elapsed().as_secs_f64().max(0.001),
                elapsed_ms: scan_started.elapsed().as_millis(),
            });
        }
        let current_wildcard_answers = current_wildcard_answers.into_values().collect::<Vec<_>>();
        let current_wildcard_names = current_wildcard_answers
            .iter()
            .map(|answer| answer.fqdn.clone())
            .collect::<BTreeSet<_>>();
        // Quarantine is authorized only by an exact response confirmed by at
        // least two resolvers or by the authoritative server. Everything
        // weaker is journaled as indeterminate and leaves the previous
        // cache/inventory untouched for the next scan.
        let quarantine_answers = current_exact_wildcard_matches
            .into_values()
            .filter(|answer| answer.resolver_count >= 2 || answer.authoritative_validation)
            .collect::<Vec<_>>();
        let quarantine_names = quarantine_answers
            .iter()
            .map(|answer| answer.fqdn.clone())
            .collect::<BTreeSet<_>>();
        let preserved_wildcard_names = current_wildcard_names
            .difference(&quarantine_names)
            .cloned()
            .collect::<BTreeSet<_>>();
        indeterminate.extend(preserved_wildcard_names.iter().cloned());
        definitive_negative.sort();
        definitive_negative.dedup();
        discovery_negative.sort();
        discovery_negative.dedup();
        indeterminate.sort();
        indeterminate.dedup();
        if !indeterminate.is_empty() {
            self.emit(ProgressEvent::Warning(format!(
                "DNS {phase}: {} nom(s) indéterminé(s), cache et état actif préservés",
                indeterminate.len()
            )));
        }
        // Output and audit may retain wildcard rows with --include-wildcard,
        // but reusable positive state must never receive them.
        let cacheable_network_answers = network_answers
            .iter()
            .filter(|answer| !current_wildcard_names.contains(&answer.fqdn))
            .cloned()
            .collect::<Vec<_>>();
        // Commit the dedicated proof marker and quarantine before any general
        // cache write, minimizing the crash window in which an old wildcard
        // positive could remain reusable.
        self.database
            .record_current_wildcard_matches(scan_id, &quarantine_answers)?;
        let purged_wildcards = self.database.purge_confirmed_wildcard_false_positives(
            scan_id,
            domain,
            &quarantine_names.into_iter().collect::<Vec<_>>(),
        )?;
        if !purged_wildcards.is_empty() {
            self.emit(ProgressEvent::Phase {
                name: "wildcard".to_owned(),
                detail: format!(
                    "{} faux positif(s) wildcard confirmé(s) purgé(s) du cache actif",
                    purged_wildcards.len()
                ),
            });
        }
        persist_routed_dns_outcomes(
            &self.database,
            scan_id,
            &cacheable_network_answers,
            &definitive_negative,
            &discovery_negative,
            &indeterminate,
            self.options.negative_ttl,
        )?;
        // A weak/superset wildcard observation stays journal-only. Keeping it
        // in BatchResolution would let the final scan snapshot or a later
        // persistence wave demote the preserved historical inventory despite
        // the insufficient proof.
        network_answers.retain(|answer| !preserved_wildcard_names.contains(&answer.fqdn));
        let resolved_from_network = network_answers.len();
        answers.extend(network_answers);
        let incremental_findings = answers
            .iter()
            .filter(|answer| !preserved_wildcard_names.contains(&answer.fqdn))
            .filter_map(|answer| {
                self.finding_for_answer(
                    answer,
                    sources,
                    root_wildcard,
                    parent_by_host,
                    wildcard_by_parent,
                )
            })
            .collect::<Vec<_>>();
        self.database.persist_findings(
            scan_id,
            domain,
            &incremental_findings,
            self.options.ttl_cap,
        )?;
        Ok(BatchResolution {
            answers,
            cache_hits,
            resolved_from_network,
            deadline_exhausted,
            indeterminate_hosts: indeterminate,
            not_started_hosts: not_started,
            attempted_hosts,
        })
    }

    pub async fn scan(&self, target: &str) -> Result<ScanResult> {
        let domain = normalize_domain(target)?;
        let options_json = json!({
            "max_words": self.options.max_words,
            "active_phase_timeout_seconds": self.options.active_phase_timeout.as_secs(),
            "passive": self.options.passive,
            "passive_sources": self.options.passive_sources,
            "automatic_source_selection": self.options.automatic_source_selection,
            "adaptive": self.options.adaptive,
            "pipeline": self.options.pipeline,
            "pipeline_rounds": self.options.pipeline_rounds,
            "pipeline_budget": self.options.pipeline_budget,
            "passive_refresh_seconds": self.options.passive_refresh.as_secs(),
            "passive_phase_timeout_seconds": self.options.passive_phase_timeout.as_secs(),
            "passive_zone_concurrency": self.options.passive_zone_concurrency,
            "passive_concurrency": self.options.passive_concurrency,
            "max_passive": self.options.max_passive,
            "passive_only": self.options.passive_only,
            "axfr": self.options.axfr,
            "refresh_cache": self.options.refresh_cache,
            "verification_max_age_seconds": self.options.verification_max_age.as_secs(),
            "only_live": self.options.only_live,
            "profile": self.options.profile,
            "checkpoint_every_seconds": self.options.checkpoint_every.as_secs(),
            "ttl_cap": self.options.ttl_cap,
            "negative_ttl": self.options.negative_ttl,
            "include_wildcard": self.options.include_wildcard,
            "wildcard_refresh_seconds": self.options.wildcard_refresh.as_secs(),
            "recursive_depth": self.options.recursive_depth,
            "recursive_words": self.options.recursive_words,
            "recursive_hosts": self.options.recursive_hosts,
            "tls_certificates": self.options.tls_certificates,
            "tls_port": self.options.tls_port,
            "tls_timeout_ms": self.options.tls_timeout.as_millis(),
            "tls_refresh_seconds": self.options.tls_refresh.as_secs(),
            "tls_max_hosts": self.options.tls_max_hosts,
            "tls_concurrency": self.options.tls_concurrency,
            "dns_graph": self.options.dns_graph,
            "graph_max_hosts": self.options.graph_max_hosts,
            "service_discovery": self.options.service_discovery,
            "ptr_pivot": self.options.ptr_pivot,
            "ptr_max_ips": self.options.ptr_max_ips,
            "dnssec_nsec": self.options.dnssec_nsec,
            "nsec_timeout_ms": self.options.nsec_timeout.as_millis(),
            "nsec_refresh_seconds": self.options.nsec_refresh.as_secs(),
            "nsec_max_names": self.options.nsec_max_names,
            "nsec_phase_timeout_seconds": self.options.nsec_phase_timeout.as_secs(),
            "ct_monitor": self.options.ct_monitor,
            "ct_timeout_ms": self.options.ct_timeout.as_millis(),
            "ct_phase_timeout_seconds": self.options.ct_phase_timeout.as_secs(),
            "ct_max_logs": self.options.ct_max_logs,
            "ct_entries_per_log": self.options.ct_entries_per_log,
            "ct_initial_backfill": self.options.ct_initial_backfill,
            "metadata_discovery": self.options.metadata_discovery,
            "metadata_all_hosts": self.options.metadata_all_hosts,
            "metadata_max_requests": self.options.metadata_max_requests,
            "web_discovery": self.options.web_discovery,
            "web_max_hosts": self.options.web_max_hosts,
            "web_timeout_ms": self.options.web_timeout.as_millis(),
            "web_phase_timeout_seconds": self.options.web_phase_timeout.as_secs(),
            "web_refresh_seconds": self.options.web_refresh.as_secs(),
            "web_concurrency": self.options.web_concurrency,
            "web_max_bytes": self.options.web_max_bytes,
            "web_assets_per_host": self.options.web_assets_per_host,
            "wordlist": self.options.wordlist.as_ref().map(|path| path.display().to_string()),
            "mutation_rules": self.options.mutation_rules,
        });
        let options_hash = domain_hash(&serde_json::to_string(&options_json)?);
        let resuming = self.options.resume.is_some();
        let scan_id = if let Some(selector) = &self.options.resume {
            let checkpoint = self
                .database
                .resumable_checkpoint(&domain, selector)?
                .ok_or_else(|| {
                    anyhow::anyhow!("aucun checkpoint incomplet '{}' pour {}", selector, domain)
                })?;
            if checkpoint.options_hash != options_hash {
                bail!(
                    "le checkpoint #{} utilise des options différentes; relancez avec les mêmes options",
                    checkpoint.scan_id
                );
            }
            self.database.reopen_scan(checkpoint.scan_id)?;
            checkpoint.scan_id
        } else {
            self.database.create_scan(&domain, &options_json)?
        };
        self.database
            .upsert_checkpoint(scan_id, &domain, "running", &options_hash)?;
        let superseded_candidates = if resuming {
            0
        } else {
            self.database.supersede_incomplete_candidate_queues(
                &domain,
                scan_id,
                Duration::from_secs(120),
            )?
        };
        let started = Instant::now();
        self.emit(ProgressEvent::Started {
            scan_id,
            domain: domain.clone(),
        });
        if superseded_candidates > 0 {
            self.emit(ProgressEvent::Phase {
                name: "candidats".to_owned(),
                detail: format!(
                    "{superseded_candidates} ancien(s) candidat(s) abandonné(s) remplacé(s)"
                ),
            });
        }
        let checkpoint_heartbeat = CheckpointHeartbeat::start(
            self.database.clone(),
            scan_id,
            domain.clone(),
            options_hash,
            self.options.checkpoint_every,
        );
        let mut run_guard = ScanRunGuard::new(self.database.clone(), scan_id, started);
        let result = self.scan_inner(scan_id, &domain, started).await;
        match &result {
            Ok(_) => {
                // scan_inner has already committed either a completed or a
                // resumable partial terminal state.
                run_guard.disarm();
            }
            Err(error) => {
                self.emit(ProgressEvent::Warning(format!(
                    "scan interrompu: {error:#}"
                )));
                if self
                    .database
                    .finish_scan(
                        scan_id,
                        "failed",
                        0,
                        0,
                        0,
                        started.elapsed().as_millis(),
                        &[format!("{error:#}")],
                    )
                    .is_ok()
                {
                    run_guard.disarm();
                }
            }
        }
        checkpoint_heartbeat.stop().await;
        self.emit(ProgressEvent::Complete);
        result
    }

    async fn collect_incremental_ct(&self, domain: &str) -> Result<(CtMonitorResult, Vec<String>)> {
        let mut ct_monitor = CtMonitorResult::default();
        let mut ct_warnings = Vec::new();
        if !self.options.ct_monitor {
            return Ok((ct_monitor, ct_warnings));
        }

        let phase_started = Instant::now();
        let phase_budget = if self.options.ct_phase_timeout.is_zero() {
            "unlimited".to_owned()
        } else {
            format!("{} s", self.options.ct_phase_timeout.as_secs())
        };
        self.emit(ProgressEvent::Phase {
            name: "CT incrémental".to_owned(),
            detail: format!(
                "indexation opportuniste en arrière-plan: {} journal(aux), {} entrées maximum par journal, budget {phase_budget}",
                self.options.ct_max_logs, self.options.ct_entries_per_log,
            ),
        });
        let ct_progress = self.progress.clone().map(|progress| {
            Arc::new(move |event: CtProgressEvent| {
                progress(ProgressEvent::Phase {
                    name: "CT incrémental".to_owned(),
                    detail: event.to_string(),
                });
            }) as CtProgressCallback
        });
        match self
            .await_with_phase_heartbeat(
                "CT incrémental",
                "indexation opportuniste; les autres sources continuent en parallèle",
                monitor_ct_logs_bounded_with_progress_and_limit(
                    &self.database,
                    domain,
                    self.options.ct_timeout,
                    self.options.ct_max_logs,
                    self.options.ct_entries_per_log,
                    self.options.ct_initial_backfill,
                    self.options.ct_phase_timeout,
                    self.options.max_passive.min(100_000),
                    ct_progress,
                ),
            )
            .await
        {
            Ok(result) => ct_monitor = result,
            Err(error) => {
                let warning = format!("CT incrémental: {error:#}");
                self.emit(ProgressEvent::Warning(warning.clone()));
                ct_warnings.push(warning);
            }
        }
        if !self.options.ct_phase_timeout.is_zero()
            && phase_started.elapsed() >= self.options.ct_phase_timeout
        {
            let warning =
                "CT incrémental: budget cumulé atteint; résultats partiels conservés".to_owned();
            self.emit(ProgressEvent::Warning(warning.clone()));
            ct_warnings.push(warning);
        }
        self.emit(ProgressEvent::CtMonitor {
            logs: ct_monitor.logs_checked,
            entries: ct_monitor.entries_processed,
            failures: ct_monitor.failures,
            names: ct_monitor.names.len(),
            duration_ms: ct_monitor.duration_ms,
        });
        Ok((ct_monitor, ct_warnings))
    }

    async fn scan_inner(&self, scan_id: i64, domain: &str, started: Instant) -> Result<ScanResult> {
        let mut warnings = Vec::new();
        let mut pipeline_metrics = PipelineMetrics::default();
        let mut phase_timings = Vec::new();
        let mut sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut passive_budget_remaining = (!self.options.passive_phase_timeout.is_zero())
            .then_some(self.options.passive_phase_timeout);
        let mut nsec_budget_remaining =
            (!self.options.nsec_phase_timeout.is_zero()).then_some(self.options.nsec_phase_timeout);
        let mut nsec_budget_warning_emitted = false;
        let mut web_budget_remaining =
            (!self.options.web_phase_timeout.is_zero()).then_some(self.options.web_phase_timeout);
        let mut web_budget_exhausted = false;
        let initial_discovery_started = Instant::now();
        let resume_from_discovery_checkpoint = self.options.resume.is_some()
            && (self.database.scan_seed_candidate_count(scan_id)? > 0
                || self.database.scan_candidate_count(scan_id)? > 0
                || self.database.scan_recursive_has_more(scan_id)?);

        // These discovery families are independent network operations. Running
        // them together turns their cold-start wall time into the slowest one,
        // instead of adding three unrelated waits before DNS validation starts.
        let passive_phase = async {
            let mut passive_sources = BTreeMap::new();
            let mut passive_warnings = Vec::new();
            let mut queried_zones = BTreeSet::from([domain.to_owned()]);
            let passive_phase_started = Instant::now();
            let deadline = phase_deadline(passive_budget_remaining);
            if self.options.passive {
                self.emit(ProgressEvent::Phase {
                    name: "passif".to_owned(),
                    detail: format!(
                        "{} source(s), cache {} h",
                        self.options.passive_sources.len(),
                        self.options.passive_refresh.as_secs() / 3_600
                    ),
                });
                self.collect_passive(
                    domain,
                    deadline,
                    &mut passive_sources,
                    &mut passive_warnings,
                )
                .await?;
                let mut inferred = self.inferred_passive_zones(
                    domain,
                    passive_sources.keys().cloned(),
                    self.options.recursive_hosts.min(20),
                );
                if let Some(parent) = crate::util::registrable_domain(domain)
                    && parent != domain
                {
                    inferred.insert(0, parent);
                }
                self.collect_passive_recursively(
                    domain,
                    inferred,
                    deadline,
                    &mut queried_zones,
                    &mut passive_sources,
                    &mut passive_warnings,
                )
                .await?;
            }
            Ok::<_, anyhow::Error>((
                passive_sources,
                passive_warnings,
                queried_zones,
                passive_phase_started.elapsed(),
            ))
        };

        let ct_task_started = Instant::now();
        let mut ct_tasks = tokio::task::JoinSet::new();
        if !resume_from_discovery_checkpoint && self.options.ct_monitor {
            let scanner = self.clone();
            let ct_domain = domain.to_owned();
            ct_tasks.spawn(async move { scanner.collect_incremental_ct(&ct_domain).await });
        }

        let axfr_phase = async {
            if !self.options.axfr {
                return (Vec::new(), Vec::new());
            }
            self.emit(ProgressEvent::Phase {
                name: "AXFR".to_owned(),
                detail: "résolution des NS et transfert TCP".to_owned(),
            });
            let (attempts, axfr_warnings) = self
                .await_with_phase_heartbeat(
                    "AXFR",
                    "essais bornés sur les serveurs autoritaires",
                    attempt_axfr(&self.dns, domain, self.options.axfr_timeout),
                )
                .await;
            for warning in &axfr_warnings {
                self.emit(ProgressEvent::Warning(warning.clone()));
            }
            for attempt in &attempts {
                self.emit(ProgressEvent::AxfrAttempt(attempt.clone()));
            }
            (attempts, axfr_warnings)
        };

        let (
            passive_sources,
            passive_warnings,
            mut passive_zones_queried,
            passive_elapsed,
            axfr_attempts,
            axfr_warnings,
        ) = if resume_from_discovery_checkpoint {
            drop(passive_phase);
            drop(axfr_phase);
            self.emit(ProgressEvent::Phase {
                name: "reprise".to_owned(),
                detail: "sources passives, CT et AXFR restaurées depuis le checkpoint".to_owned(),
            });
            let restored_sources = self
                .database
                .scan_seed_candidates_for_output(scan_id)?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            let mut restored_zones = BTreeSet::from([domain.to_owned()]);
            restored_zones.extend(self.inferred_passive_zones(
                domain,
                restored_sources.keys().cloned(),
                self.options.recursive_hosts.min(20),
            ));
            (
                restored_sources,
                Vec::new(),
                restored_zones,
                Duration::ZERO,
                Vec::new(),
                Vec::new(),
            )
        } else {
            let (passive_result, (axfr_attempts, axfr_warnings)) =
                tokio::join!(passive_phase, axfr_phase);
            let (passive_sources, passive_warnings, passive_zones_queried, passive_elapsed) =
                passive_result?;
            (
                passive_sources,
                passive_warnings,
                passive_zones_queried,
                passive_elapsed,
                axfr_attempts,
                axfr_warnings,
            )
        };

        let mut ct_task_pending = false;
        let (mut ct_monitor, ct_warnings) = if resume_from_discovery_checkpoint
            || !self.options.ct_monitor
        {
            (CtMonitorResult::default(), Vec::new())
        } else {
            match ct_tasks.try_join_next() {
                Some(Ok(Ok(result))) => result,
                Some(Ok(Err(error))) => {
                    let warning = format!("CT incrémental: {error:#}");
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    (CtMonitorResult::default(), vec![warning])
                }
                Some(Err(error)) => {
                    let warning = format!("CT incrémental: tâche interrompue: {error}");
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    (CtMonitorResult::default(), vec![warning])
                }
                None => {
                    ct_task_pending = true;
                    let result = CtMonitorResult {
                        duration_ms: initial_discovery_started.elapsed().as_millis(),
                        ..CtMonitorResult::default()
                    };
                    self.emit(ProgressEvent::Phase {
                        name: "CT incrémental".to_owned(),
                        detail: format!(
                            "continue pendant la validation DNS; {} nom(s) ciblé(s) déjà indexé(s) disponibles immédiatement",
                            result.names.len()
                        ),
                    });
                    (result, Vec::new())
                }
            }
        };
        if self.options.passive {
            consume_phase_budget(&mut passive_budget_remaining, passive_elapsed);
        }
        warnings.extend(passive_warnings);
        warnings.extend(ct_warnings);
        warnings.extend(axfr_warnings);
        for (name, origins) in passive_sources {
            sources.entry(name).or_default().extend(origins);
        }
        for name in &ct_monitor.names {
            sources
                .entry(name.clone())
                .or_default()
                .insert("passive:ct-direct".to_owned());
        }
        for attempt in &axfr_attempts {
            if attempt.status == crate::model::AxfrStatus::Success {
                for name in &attempt.names {
                    sources
                        .entry(name.clone())
                        .or_default()
                        .insert(format!("axfr:{}", attempt.nameserver));
                }
            }
        }
        self.database.save_axfr_attempts(scan_id, &axfr_attempts)?;
        self.cap_seed_sources(domain, &mut sources, &mut warnings);
        phase_timings.push(PhaseTiming {
            phase: "initial_discovery".to_owned(),
            duration_ms: initial_discovery_started.elapsed().as_millis(),
        });

        let candidate_dns_started = Instant::now();
        self.emit(ProgressEvent::Phase {
            name: "candidats".to_owned(),
            detail: "fusion du passif, AXFR, apprentissage et wordlist".to_owned(),
        });
        let mut seed_payload = sources
            .iter()
            .map(|(fqdn, origins)| {
                (
                    fqdn.clone(),
                    origins.clone(),
                    seed_candidate_priority(origins),
                )
            })
            .collect::<Vec<_>>();
        seed_payload.sort_by_key(|(fqdn, _, priority)| (Reverse(*priority), fqdn.clone()));
        // CT runs opportunistically beside DNS. Keep a small bounded slice of
        // the durable seed queue available until that task joins, then refill
        // any unused capacity with the already ranked initial discoveries.
        let late_ct_reserve = late_ct_seed_reserve(self.options.max_passive, ct_task_pending);
        let initial_seed_limit = self.options.max_passive.saturating_sub(late_ct_reserve);
        self.database
            .persist_scan_seed_candidates(scan_id, &seed_payload, initial_seed_limit)?;
        let resumed_live_answers = if self.options.resume.is_some() {
            self.database.live_scan_answers(scan_id)?
        } else {
            Vec::new()
        };
        for (answer, persisted_sources) in &resumed_live_answers {
            sources
                .entry(answer.fqdn.clone())
                .or_default()
                .extend(persisted_sources.iter().cloned());
        }
        let mut generated_candidates_enabled = !self.options.passive_only;
        let mut active_budget_remaining = (!self.options.active_phase_timeout.is_zero())
            .then_some(self.options.active_phase_timeout);
        let mut recursive_budget_exhausted = false;
        let mut candidate_expansion_stopped_naturally = false;
        let mut active_budget_warning_emitted = false;
        let mut resume_candidate_queue_draining = self.options.resume.is_some()
            && self.database.pending_scan_candidate_count(scan_id)?.max(0) as usize > 0;
        let mut conservative_candidate_retries = BTreeSet::<String>::new();
        let first_batch_limit = if self.options.adaptive { 500 } else { 5_000 };
        let first_seed_limit = seed_share(first_batch_limit, !self.options.passive_only);
        let first_seed_candidates = self
            .database
            .pending_scan_seed_candidates(scan_id, first_seed_limit)?;
        let first_seed_hosts = first_seed_candidates
            .iter()
            .map(|(fqdn, _, _)| fqdn.clone())
            .collect::<BTreeSet<_>>();
        for (fqdn, persisted_sources, _) in &first_seed_candidates {
            sources
                .entry(fqdn.clone())
                .or_default()
                .extend(persisted_sources.iter().cloned());
        }
        let first_candidate_limit = first_batch_limit.saturating_sub(first_seed_hosts.len());
        let candidates = if self.options.passive_only {
            Vec::new()
        } else {
            if !resume_candidate_queue_draining {
                self.refill_candidate_queue(
                    scan_id,
                    domain,
                    &sources,
                    first_candidate_limit,
                    generated_candidates_enabled,
                )?;
            }
            self.database
                .pending_scan_candidates_eligible(
                    scan_id,
                    first_candidate_limit,
                    active_candidate_work_allowed(active_budget_remaining),
                )?
                .into_iter()
                .map(|(relative_name, generator, score)| CandidateProposal {
                    relative_name,
                    generator,
                    score,
                })
                .collect()
        };
        let mut attempted_words = BTreeSet::new();
        let mut generator_attempts = HashMap::<String, usize>::new();
        let mut generator_successes = HashMap::<String, usize>::new();
        let first_candidate_hosts = {
            let mut add_candidates = |wave: &[CandidateProposal], label: &str| {
                let mut hosts = Vec::new();
                for candidate in wave {
                    let fqdn = format!("{}.{domain}", candidate.relative_name);
                    hosts.push(fqdn.clone());
                    sources.entry(fqdn.clone()).or_default().extend([
                        label.to_owned(),
                        format!("candidate:{}", candidate.generator),
                    ]);
                    let count = generator_attempts
                        .entry(candidate.generator.clone())
                        .or_default();
                    *count = count.saturating_add(1);
                    if candidate.generator != "builtin" && attempted_words.len() < 100_000 {
                        attempted_words.extend(
                            candidate
                                .relative_name
                                .split('.')
                                .filter(|label| learnable_label(label))
                                .map(ToOwned::to_owned),
                        );
                    }
                }
                hosts
            };
            add_candidates(&candidates, "dns")
        };
        let known_first_candidate_hosts = self
            .database
            .known_discovery_names(&first_candidate_hosts)?;
        let first_wordlist_hosts = candidates
            .iter()
            .filter(|candidate| candidate.generator == "wordlist")
            .filter_map(|candidate| {
                let fqdn = format!("{}.{domain}", candidate.relative_name);
                (!first_seed_hosts.contains(&fqdn)).then_some(fqdn)
            })
            .collect::<Vec<_>>();
        let first_generated_hosts = candidates
            .iter()
            .filter_map(|candidate| {
                let fqdn = format!("{}.{domain}", candidate.relative_name);
                (candidate_uses_discovery_fast_path(
                    candidate,
                    true,
                    resume_candidate_queue_draining,
                    false,
                    known_first_candidate_hosts.contains(&fqdn),
                ) && !first_seed_hosts.contains(&fqdn))
                .then_some(fqdn)
            })
            .collect::<Vec<_>>();
        let first_known_generated_hosts = candidates
            .iter()
            .filter_map(|candidate| {
                let fqdn = format!("{}.{domain}", candidate.relative_name);
                (candidate_uses_discovery_fast_path(
                    candidate,
                    true,
                    resume_candidate_queue_draining,
                    false,
                    false,
                ) && known_first_candidate_hosts.contains(&fqdn)
                    && !first_seed_hosts.contains(&fqdn))
                .then_some(fqdn)
            })
            .collect::<Vec<_>>();
        let first_retry_hosts = candidates
            .iter()
            .filter(|candidate| {
                resume_candidate_queue_draining && candidate.generator != "wordlist"
            })
            .filter_map(|candidate| {
                let fqdn = format!("{}.{domain}", candidate.relative_name);
                (!first_seed_hosts.contains(&fqdn)).then_some(fqdn)
            })
            .collect::<BTreeSet<_>>();

        let initial_hosts = first_seed_hosts
            .iter()
            .cloned()
            .chain(first_candidate_hosts.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let initial_wildcard_hosts = initial_hosts
            .iter()
            .cloned()
            .chain(
                resumed_live_answers
                    .iter()
                    .map(|(answer, _)| answer.fqdn.clone()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        self.emit(ProgressEvent::Phase {
            name: "wildcard".to_owned(),
            detail: "sondes aléatoires sur la racine et les sous-zones observées".to_owned(),
        });
        let wildcard_budget_started = Instant::now();
        let wildcard_deadline = phase_deadline(active_budget_remaining);
        let (root_wildcard, root_wildcard_timed_out) = self
            .wildcard_signature_cached_bounded(domain, wildcard_deadline)
            .await;
        let mut wildcard_by_parent = BTreeMap::from([(domain.to_owned(), root_wildcard.clone())]);
        let mut parent_by_host = HashMap::new();
        let parent_wildcard_timed_out = self
            .register_wildcard_parents_bounded(
                &initial_wildcard_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                64,
                wildcard_deadline,
            )
            .await;
        consume_phase_budget(
            &mut active_budget_remaining,
            wildcard_budget_started.elapsed(),
        );
        if (root_wildcard_timed_out || parent_wildcard_timed_out)
            && active_budget_remaining.is_some()
        {
            active_budget_remaining = Some(Duration::ZERO);
        }
        let wildcard_parent_count = wildcard_by_parent
            .iter()
            .filter(|(zone, signature)| {
                *zone != domain && wildcard_signature_is_confirmed(signature)
            })
            .count();
        let indeterminate_parent_count = wildcard_by_parent
            .iter()
            .filter(|(zone, signature)| {
                *zone != domain && wildcard_signature_is_indeterminate(signature)
            })
            .count();
        self.emit(ProgressEvent::Phase {
            name: "wildcard".to_owned(),
            detail: format!(
                "racine {}, {} sous-zone(s) wildcard, {} indéterminée(s)",
                if wildcard_signature_is_indeterminate(&root_wildcard) {
                    "indéterminée"
                } else if root_wildcard.is_empty() {
                    "normale"
                } else {
                    "wildcard"
                },
                wildcard_parent_count,
                indeterminate_parent_count
            ),
        });
        self.emit(ProgressEvent::Phase {
            name: "DNS niveau 1".to_owned(),
            detail: format!("{} candidat(s) à valider", initial_hosts.len()),
        });
        let mut initial_resolution = BatchResolution::default();
        let first_seed_batch = first_seed_hosts.iter().cloned().collect::<Vec<_>>();
        if !first_seed_batch.is_empty() {
            let (answers, cache_hits, resolved_from_network) = self
                .resolve_batch(
                    scan_id,
                    domain,
                    &first_seed_batch,
                    "DNS niveau 1 passif",
                    &started,
                    &sources,
                    &root_wildcard,
                    &parent_by_host,
                    &wildcard_by_parent,
                )
                .await?;
            initial_resolution.merge(BatchResolution {
                answers,
                cache_hits,
                resolved_from_network,
                deadline_exhausted: false,
                indeterminate_hosts: Vec::new(),
                not_started_hosts: Vec::new(),
                attempted_hosts: Vec::new(),
            });
        }
        if !first_wordlist_hosts.is_empty() {
            let active_wordlist_started = Instant::now();
            let conservative_resolution = self
                .resolve_batch_with_deadline(
                    scan_id,
                    domain,
                    &first_wordlist_hosts,
                    "DNS niveau 1 wordlist",
                    &started,
                    &sources,
                    &root_wildcard,
                    &parent_by_host,
                    &wildcard_by_parent,
                    phase_deadline(active_budget_remaining),
                    BatchDnsMode::Conservative,
                )
                .await?;
            consume_phase_budget(
                &mut active_budget_remaining,
                active_wordlist_started.elapsed(),
            );
            if conservative_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                active_budget_remaining = Some(Duration::ZERO);
            }
            initial_resolution.merge(conservative_resolution);
        }
        if !first_retry_hosts.is_empty() {
            let active_retry_started = Instant::now();
            let retry_hosts = first_retry_hosts.iter().cloned().collect::<Vec<_>>();
            let conservative_resolution = self
                .resolve_batch_with_deadline(
                    scan_id,
                    domain,
                    &retry_hosts,
                    "DNS niveau 1 retry actif",
                    &started,
                    &sources,
                    &root_wildcard,
                    &parent_by_host,
                    &wildcard_by_parent,
                    phase_deadline(active_budget_remaining),
                    BatchDnsMode::Conservative,
                )
                .await?;
            consume_phase_budget(&mut active_budget_remaining, active_retry_started.elapsed());
            if conservative_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                active_budget_remaining = Some(Duration::ZERO);
            }
            conservative_candidate_retries.extend(
                conservative_resolution
                    .indeterminate_hosts
                    .iter()
                    .filter(|host| first_retry_hosts.contains(*host))
                    .cloned(),
            );
            initial_resolution.merge(conservative_resolution);
        }
        if !first_known_generated_hosts.is_empty() {
            let active_wave_started = Instant::now();
            let conservative_resolution = self
                .resolve_batch_with_deadline(
                    scan_id,
                    domain,
                    &first_known_generated_hosts,
                    "DNS niveau 1 actif connu",
                    &started,
                    &sources,
                    &root_wildcard,
                    &parent_by_host,
                    &wildcard_by_parent,
                    phase_deadline(active_budget_remaining),
                    BatchDnsMode::Conservative,
                )
                .await?;
            consume_phase_budget(&mut active_budget_remaining, active_wave_started.elapsed());
            if conservative_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                active_budget_remaining = Some(Duration::ZERO);
            }
            conservative_candidate_retries
                .extend(conservative_resolution.indeterminate_hosts.iter().cloned());
            initial_resolution.merge(conservative_resolution);
        }
        if !first_generated_hosts.is_empty() {
            let active_wave_started = Instant::now();
            let generated_resolution = self
                .resolve_batch_with_deadline(
                    scan_id,
                    domain,
                    &first_generated_hosts,
                    "DNS niveau 1 actif",
                    &started,
                    &sources,
                    &root_wildcard,
                    &parent_by_host,
                    &wildcard_by_parent,
                    phase_deadline(active_budget_remaining),
                    BatchDnsMode::GeneratedDiscovery,
                )
                .await?;
            consume_phase_budget(&mut active_budget_remaining, active_wave_started.elapsed());
            if generated_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                active_budget_remaining = Some(Duration::ZERO);
            }
            conservative_candidate_retries
                .extend(generated_resolution.indeterminate_hosts.iter().cloned());
            initial_resolution.merge(generated_resolution);
        }
        if (!first_known_generated_hosts.is_empty() || !first_generated_hosts.is_empty())
            && active_candidate_budget_exhausted(active_budget_remaining)
        {
            generated_candidates_enabled = false;
            if !active_budget_warning_emitted {
                let detail = format!(
                    "budget DNS actif de {}s atteint après {} candidat(s); expansion générée arrêtée, résultats terminés conservés et requêtes inachevées remises en file",
                    self.options.active_phase_timeout.as_secs(),
                    generator_attempts.values().sum::<usize>()
                );
                self.emit(ProgressEvent::Phase {
                    name: "adaptation".to_owned(),
                    detail: detail.clone(),
                });
                warnings.push(detail);
                active_budget_warning_emitted = true;
            }
        }
        conservative_candidate_retries.extend(
            initial_resolution
                .indeterminate_hosts
                .iter()
                .filter(|host| first_candidate_hosts.contains(*host))
                .cloned(),
        );
        let BatchResolution {
            answers: initial_answers,
            mut cache_hits,
            resolved_from_network: mut network_resolved,
            indeterminate_hosts: initial_indeterminate,
            not_started_hosts: initial_not_started,
            ..
        } = initial_resolution;
        let initial_not_started_set = initial_not_started.iter().cloned().collect::<BTreeSet<_>>();
        let initial_unclassified = initial_not_started
            .iter()
            .chain(initial_indeterminate.iter())
            .cloned()
            .collect::<BTreeSet<_>>();
        let initial_answer_names = initial_answers
            .iter()
            .filter(|answer| {
                Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            })
            .map(|answer| answer.fqdn.clone())
            .collect::<BTreeSet<_>>();
        self.database.record_scan_candidate_results(
            scan_id,
            &candidates
                .iter()
                .filter_map(|candidate| {
                    let fqdn = format!("{}.{domain}", candidate.relative_name);
                    (!initial_unclassified.contains(&fqdn)).then_some((
                        fqdn.clone(),
                        candidate.relative_name.clone(),
                        candidate.generator.clone(),
                        initial_answer_names.contains(&fqdn),
                    ))
                })
                .collect::<Vec<_>>(),
        )?;
        let initial_terminal_hosts = initial_hosts
            .iter()
            .filter(|host| !initial_not_started_set.contains(*host))
            .cloned()
            .collect::<Vec<_>>();
        self.database
            .mark_scan_candidates_done(scan_id, &initial_terminal_hosts)?;
        self.database
            .requeue_unstarted_scan_candidates(scan_id, &initial_not_started)?;
        self.database
            .mark_scan_seed_candidates_done(scan_id, &initial_hosts)?;
        let mut answers: BTreeMap<String, ResolvedHost> = initial_answers
            .into_iter()
            .map(|answer| (answer.fqdn.clone(), answer))
            .collect();
        for (answer, _) in resumed_live_answers {
            answers.entry(answer.fqdn.clone()).or_insert(answer);
        }
        record_candidate_wave_results(&candidates, domain, &answers, &mut generator_successes);
        discard_failed_candidate_origins(&candidates, domain, &answers, &mut sources);
        let mut pipeline = DiscoveryPipeline::new(self.options.pipeline_budget);
        pipeline.mark_processed(answers.keys().cloned());
        let mut validation_rounds = 0_usize;
        let mut pipeline_names_validated = 0_usize;
        let mut graph_processed = BTreeSet::new();
        let mut web_processed = BTreeSet::new();
        let mut tls_processed = BTreeSet::new();

        let mut previous_positive = first_generated_hosts
            .iter()
            .filter_map(|host| answers.get(host))
            .filter(|answer| {
                Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            })
            .count();
        let mut previous_attempted = first_generated_hosts
            .iter()
            .filter(|host| !initial_unclassified.contains(*host))
            .count();
        let passive_positive = first_seed_hosts
            .iter()
            .filter_map(|host| answers.get(host))
            .filter(|answer| {
                Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            })
            .count();
        let required_yield_waves = if self.options.profile == "turbo" {
            2
        } else {
            3
        };
        let minimum_statistical_attempts = match self.options.profile.as_str() {
            "turbo" => 512,
            "balanced" => 1_500,
            _ => 3_000,
        };
        let mut adaptive_yield_window = VecDeque::new();
        if previous_attempted > 0 {
            adaptive_yield_window.push_back((previous_attempted, previous_positive));
        }
        let mut remaining_yield_upper_bound: f64;
        let mut wave_number = 2;
        loop {
            if resume_candidate_queue_draining
                && self
                    .database
                    .pending_scan_candidate_count_eligible(
                        scan_id,
                        active_candidate_work_allowed(active_budget_remaining),
                    )?
                    .max(0) as usize
                    == 0
            {
                // No generated refill occurs while this flag is true, so zero
                // here means every inherited row still eligible for this scan
                // has been drained. Generated rows left by an exhausted active
                // deadline remain queued for a future --resume.
                resume_candidate_queue_draining = false;
            }
            let explicit_wordlist_pending = self.explicit_wordlist_has_more(scan_id)?;
            let active_work_allowed = active_candidate_work_allowed(active_budget_remaining);
            if generated_candidates_enabled
                && active_candidate_budget_exhausted(active_budget_remaining)
            {
                generated_candidates_enabled = false;
                if !active_budget_warning_emitted {
                    let detail = format!(
                        "budget DNS actif de {}s atteint après {} candidat(s); expansion générée arrêtée, résultats terminés conservés et requêtes inachevées remises en file",
                        self.options.active_phase_timeout.as_secs(),
                        generator_attempts.values().sum::<usize>()
                    );
                    self.emit(ProgressEvent::Phase {
                        name: "adaptation".to_owned(),
                        detail: detail.clone(),
                    });
                    warnings.push(detail);
                    active_budget_warning_emitted = true;
                }
            }
            let rolling_attempted = adaptive_yield_window
                .iter()
                .map(|(attempted, _)| *attempted)
                .sum::<usize>();
            let rolling_positive = adaptive_yield_window
                .iter()
                .map(|(_, positive)| *positive)
                .sum::<usize>();
            remaining_yield_upper_bound = wilson_upper_bound(rolling_positive, rolling_attempted);
            if generated_candidates_enabled
                && self.options.adaptive
                && !explicit_wordlist_pending
                && rolling_attempted >= minimum_statistical_attempts
                && adaptive_yield_window.len() >= required_yield_waves
                && !should_expand_adaptive_wave(
                    !wildcard_signature_is_indeterminate(&root_wildcard),
                    rolling_positive,
                    rolling_attempted,
                    wave_number,
                    passive_positive,
                )
            {
                self.emit(ProgressEvent::Phase {
                    name: "adaptation".to_owned(),
                    detail: format!(
                        "arrêt statistique après {} mots: borne haute {:.2} nouveau nom / 1000 paquets",
                        generator_attempts.values().sum::<usize>(),
                        remaining_yield_upper_bound * 1_000.0
                    ),
                });
                generated_candidates_enabled = false;
                candidate_expansion_stopped_naturally = true;
            }
            let wave_limit = if self.options.adaptive && wave_number == 2 {
                1_500
            } else {
                1_000
            };
            let queued_candidate_work = self
                .database
                .pending_scan_candidate_count_eligible(scan_id, active_work_allowed)?
                .max(0) as usize
                > 0;
            let candidate_work_enabled = active_work_allowed
                && (generated_candidates_enabled
                    || explicit_wordlist_pending
                    || queued_candidate_work);
            let wave_seed_candidates = self.database.pending_scan_seed_candidates(
                scan_id,
                seed_share(wave_limit, candidate_work_enabled),
            )?;
            let wave_seed_hosts = wave_seed_candidates
                .iter()
                .map(|(fqdn, _, _)| fqdn.clone())
                .collect::<BTreeSet<_>>();
            for (fqdn, persisted_sources, _) in &wave_seed_candidates {
                sources
                    .entry(fqdn.clone())
                    .or_default()
                    .extend(persisted_sources.iter().cloned());
            }

            let candidate_limit = wave_limit.saturating_sub(wave_seed_hosts.len());
            let wave_candidates = if candidate_limit == 0 {
                Vec::new()
            } else {
                if active_work_allowed
                    && !resume_candidate_queue_draining
                    && (generated_candidates_enabled || explicit_wordlist_pending)
                {
                    self.refill_candidate_queue(
                        scan_id,
                        domain,
                        &sources,
                        candidate_limit,
                        generated_candidates_enabled,
                    )?;
                }
                self.database
                    .pending_scan_candidates_eligible(
                        scan_id,
                        candidate_limit,
                        active_work_allowed,
                    )?
                    .into_iter()
                    .map(|(relative_name, generator, score)| CandidateProposal {
                        relative_name,
                        generator,
                        score,
                    })
                    .collect::<Vec<_>>()
            };
            let wave_candidate_names = wave_candidates
                .iter()
                .map(|candidate| format!("{}.{domain}", candidate.relative_name))
                .collect::<Vec<_>>();
            let known_wave_candidate_hosts =
                self.database.known_discovery_names(&wave_candidate_names)?;
            let mut wave_candidate_hosts = BTreeSet::new();
            let mut wave_wordlist_hosts = Vec::new();
            let mut wave_generated_hosts = Vec::new();
            let mut wave_known_generated_hosts = Vec::new();
            let mut wave_retry_hosts = Vec::new();
            for candidate in &wave_candidates {
                let fqdn = format!("{}.{domain}", candidate.relative_name);
                wave_candidate_hosts.insert(fqdn.clone());
                if !wave_seed_hosts.contains(&fqdn) {
                    if candidate.generator == "wordlist" {
                        wave_wordlist_hosts.push(fqdn.clone());
                    } else {
                        let is_retry = conservative_candidate_retries.contains(&fqdn);
                        if candidate_uses_discovery_fast_path(
                            candidate,
                            generated_candidates_enabled,
                            resume_candidate_queue_draining,
                            is_retry,
                            false,
                        ) {
                            if known_wave_candidate_hosts.contains(&fqdn) {
                                wave_known_generated_hosts.push(fqdn.clone());
                            } else {
                                wave_generated_hosts.push(fqdn.clone());
                            }
                        } else {
                            // Resumed rows and transient retries use conservative
                            // DNS, but remain inside the same active deadline as
                            // the generated work that created them.
                            wave_retry_hosts.push(fqdn.clone());
                        }
                    }
                }
                sources.entry(fqdn.clone()).or_default().extend([
                    format!("dns-wave-{wave_number}"),
                    format!("candidate:{}", candidate.generator),
                ]);
                let count = generator_attempts
                    .entry(candidate.generator.clone())
                    .or_default();
                *count = count.saturating_add(1);
                if candidate.generator != "builtin" && attempted_words.len() < 100_000 {
                    attempted_words.extend(
                        candidate
                            .relative_name
                            .split('.')
                            .filter(|label| learnable_label(label))
                            .map(ToOwned::to_owned),
                    );
                }
            }

            let wave_hosts = wave_seed_hosts
                .iter()
                .cloned()
                .chain(wave_candidate_hosts.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if wave_hosts.is_empty() {
                if active_work_allowed
                    && ((generated_candidates_enabled
                        && self.candidate_feeds_have_more(scan_id)?)
                        || self.explicit_wordlist_has_more(scan_id)?)
                {
                    self.emit(ProgressEvent::Phase {
                        name: "candidats".to_owned(),
                        detail: "page sans nouveau nom; reprise au curseur suivant".to_owned(),
                    });
                    continue;
                }
                break;
            }
            let remaining_seeds = self
                .database
                .pending_scan_seed_candidate_count(scan_id)?
                .max(0) as usize;
            self.emit(ProgressEvent::Phase {
                name: format!("vague DNS {wave_number}"),
                detail: format!(
                    "{} passif(s), {} généré(s), {} wordlist/retry, {} passif(s) restant(s)",
                    wave_seed_hosts.len(),
                    wave_generated_hosts.len() + wave_known_generated_hosts.len(),
                    wave_wordlist_hosts.len() + wave_retry_hosts.len(),
                    remaining_seeds
                ),
            });
            let wave_wildcard_started = Instant::now();
            let wave_wildcard_timed_out = self
                .register_wildcard_parents_bounded(
                    &wave_hosts,
                    domain,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    20,
                    phase_deadline(active_budget_remaining),
                )
                .await;
            consume_phase_budget(
                &mut active_budget_remaining,
                wave_wildcard_started.elapsed(),
            );
            if wave_wildcard_timed_out && active_budget_remaining.is_some() {
                active_budget_remaining = Some(Duration::ZERO);
            }
            let mut wave_resolution = BatchResolution::default();
            let wave_seed_batch = wave_seed_hosts.iter().cloned().collect::<Vec<_>>();
            if !wave_seed_batch.is_empty() {
                let (answers, cache_hits, resolved_from_network) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &wave_seed_batch,
                        &format!("DNS vague {wave_number} passive"),
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                wave_resolution.merge(BatchResolution {
                    answers,
                    cache_hits,
                    resolved_from_network,
                    deadline_exhausted: false,
                    indeterminate_hosts: Vec::new(),
                    not_started_hosts: Vec::new(),
                    attempted_hosts: Vec::new(),
                });
            }
            if !wave_wordlist_hosts.is_empty() {
                let active_wordlist_started = Instant::now();
                let conservative_resolution = self
                    .resolve_batch_with_deadline(
                        scan_id,
                        domain,
                        &wave_wordlist_hosts,
                        &format!("DNS vague {wave_number} wordlist"),
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                        phase_deadline(active_budget_remaining),
                        BatchDnsMode::Conservative,
                    )
                    .await?;
                consume_phase_budget(
                    &mut active_budget_remaining,
                    active_wordlist_started.elapsed(),
                );
                if conservative_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                wave_resolution.merge(conservative_resolution);
            }
            if !wave_retry_hosts.is_empty() {
                for host in &wave_retry_hosts {
                    conservative_candidate_retries.remove(host);
                }
                let active_retry_started = Instant::now();
                let conservative_resolution = self
                    .resolve_batch_with_deadline(
                        scan_id,
                        domain,
                        &wave_retry_hosts,
                        &format!("DNS vague {wave_number} retry actif"),
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                        phase_deadline(active_budget_remaining),
                        BatchDnsMode::Conservative,
                    )
                    .await?;
                consume_phase_budget(&mut active_budget_remaining, active_retry_started.elapsed());
                if conservative_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                conservative_candidate_retries.extend(
                    conservative_resolution
                        .indeterminate_hosts
                        .iter()
                        .filter(|host| wave_retry_hosts.contains(*host))
                        .cloned(),
                );
                wave_resolution.merge(conservative_resolution);
            }
            if !wave_known_generated_hosts.is_empty() {
                let active_wave_started = Instant::now();
                let conservative_resolution = self
                    .resolve_batch_with_deadline(
                        scan_id,
                        domain,
                        &wave_known_generated_hosts,
                        &format!("DNS vague {wave_number} active connue"),
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                        phase_deadline(active_budget_remaining),
                        BatchDnsMode::Conservative,
                    )
                    .await?;
                consume_phase_budget(&mut active_budget_remaining, active_wave_started.elapsed());
                if conservative_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                conservative_candidate_retries
                    .extend(conservative_resolution.indeterminate_hosts.iter().cloned());
                wave_resolution.merge(conservative_resolution);
            }
            if !wave_generated_hosts.is_empty() {
                let active_wave_started = Instant::now();
                let generated_resolution = self
                    .resolve_batch_with_deadline(
                        scan_id,
                        domain,
                        &wave_generated_hosts,
                        &format!("DNS vague {wave_number} active"),
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                        phase_deadline(active_budget_remaining),
                        BatchDnsMode::GeneratedDiscovery,
                    )
                    .await?;
                consume_phase_budget(&mut active_budget_remaining, active_wave_started.elapsed());
                if generated_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                conservative_candidate_retries
                    .extend(generated_resolution.indeterminate_hosts.iter().cloned());
                wave_resolution.merge(generated_resolution);
            }
            if (!wave_known_generated_hosts.is_empty() || !wave_generated_hosts.is_empty())
                && active_candidate_budget_exhausted(active_budget_remaining)
            {
                generated_candidates_enabled = false;
                if !active_budget_warning_emitted {
                    let detail = format!(
                        "budget DNS actif de {}s atteint après {} candidat(s); expansion générée arrêtée, résultats terminés conservés et requêtes inachevées remises en file",
                        self.options.active_phase_timeout.as_secs(),
                        generator_attempts.values().sum::<usize>()
                    );
                    self.emit(ProgressEvent::Phase {
                        name: "adaptation".to_owned(),
                        detail: detail.clone(),
                    });
                    warnings.push(detail);
                    active_budget_warning_emitted = true;
                }
            }
            let BatchResolution {
                answers: wave_answers,
                cache_hits: wave_cache_hits,
                resolved_from_network: wave_network_resolved,
                indeterminate_hosts: wave_indeterminate,
                not_started_hosts: wave_not_started,
                ..
            } = wave_resolution;
            let wave_not_started_set = wave_not_started.iter().cloned().collect::<BTreeSet<_>>();
            let wave_unclassified = wave_not_started
                .iter()
                .chain(wave_indeterminate.iter())
                .cloned()
                .collect::<BTreeSet<_>>();
            let wave_answer_names = wave_answers
                .iter()
                .filter(|answer| {
                    Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .map(|answer| answer.fqdn.clone())
                .collect::<BTreeSet<_>>();
            self.database.record_scan_candidate_results(
                scan_id,
                &wave_candidates
                    .iter()
                    .filter_map(|candidate| {
                        let fqdn = format!("{}.{domain}", candidate.relative_name);
                        (!wave_unclassified.contains(&fqdn)).then_some((
                            fqdn.clone(),
                            candidate.relative_name.clone(),
                            candidate.generator.clone(),
                            wave_answer_names.contains(&fqdn),
                        ))
                    })
                    .collect::<Vec<_>>(),
            )?;
            let wave_terminal_hosts = wave_hosts
                .iter()
                .filter(|host| !wave_not_started_set.contains(*host))
                .cloned()
                .collect::<Vec<_>>();
            self.database
                .mark_scan_candidates_done(scan_id, &wave_terminal_hosts)?;
            self.database
                .requeue_unstarted_scan_candidates(scan_id, &wave_not_started)?;
            self.database
                .mark_scan_seed_candidates_done(scan_id, &wave_hosts)?;
            cache_hits = cache_hits.saturating_add(wave_cache_hits);
            network_resolved = network_resolved.saturating_add(wave_network_resolved);
            if !wave_generated_hosts.is_empty() {
                previous_positive = wave_answers
                    .iter()
                    .filter(|answer| wave_generated_hosts.contains(&answer.fqdn))
                    .filter(|answer| {
                        Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                    })
                    .count();
                previous_attempted = wave_generated_hosts
                    .iter()
                    .filter(|host| !wave_unclassified.contains(*host))
                    .count();
                adaptive_yield_window.push_back((previous_attempted, previous_positive));
                while adaptive_yield_window.len() > required_yield_waves {
                    adaptive_yield_window.pop_front();
                }
            }
            for answer in wave_answers {
                answers.insert(answer.fqdn.clone(), answer);
            }
            record_candidate_wave_results(
                &wave_candidates,
                domain,
                &answers,
                &mut generator_successes,
            );
            discard_failed_candidate_origins(&wave_candidates, domain, &answers, &mut sources);
            wave_number += 1;
        }

        if ct_task_pending {
            let minimum_runtime = if self.options.ct_phase_timeout.is_zero() {
                Duration::from_secs(3)
            } else {
                self.options.ct_phase_timeout.min(Duration::from_secs(3))
            };
            let grace = minimum_runtime.saturating_sub(ct_task_started.elapsed());
            if !grace.is_zero() {
                self.emit(ProgressEvent::Phase {
                    name: "CT incrémental".to_owned(),
                    detail: format!(
                        "courte fenêtre finale bornée à {:.1}s; DNS déjà terminé",
                        grace.as_secs_f64()
                    ),
                });
            }
            let (joined_ct, ct_aborted_without_join) =
                finish_pending_ct_task_after_grace(&mut ct_tasks, grace).await;
            let mut late_ct = match joined_ct {
                Some(Ok(Ok((result, late_warnings)))) => {
                    warnings.extend(late_warnings);
                    result
                }
                Some(Ok(Err(error))) => {
                    let warning = format!("CT incrémental: {error:#}");
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                    CtMonitorResult::default()
                }
                Some(Err(error)) => {
                    let warning = format!("CT incrémental: tâche interrompue: {error}");
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                    CtMonitorResult::default()
                }
                None => {
                    let result = CtMonitorResult {
                        names: ct_monitor.names.clone(),
                        duration_ms: ct_task_started.elapsed().as_millis(),
                        ..CtMonitorResult::default()
                    };
                    self.emit(ProgressEvent::Phase {
                        name: "CT incrémental".to_owned(),
                        detail: format!(
                            "arrêt opportuniste après la phase DNS; {} nom(s) ciblé(s) indexé(s) conservé(s)",
                            result.names.len()
                        ),
                    });
                    self.emit(ProgressEvent::CtMonitor {
                        logs: result.logs_checked,
                        entries: result.entries_processed,
                        failures: result.failures,
                        names: result.names.len(),
                        duration_ms: result.duration_ms,
                    });
                    result
                }
            };
            late_ct.names.extend(ct_monitor.names.iter().cloned());
            ct_monitor = late_ct;

            // Prefer the indexed recency order, then append any names that
            // were recovered only from the per-domain cache. The final stable
            // priority sort still promotes names corroborated by other
            // evidence families before the bounded validation slice.
            let mut late_names = if ct_aborted_without_join {
                Vec::new()
            } else {
                self.database
                    .ct_names_for_domain(domain, self.options.max_passive.min(100_000))?
                    .into_iter()
                    .filter(|name| normalize_observed_name(name, domain).is_some())
                    .collect::<Vec<_>>()
            };
            let mut late_seen = late_names.iter().cloned().collect::<BTreeSet<_>>();
            for name in &ct_monitor.names {
                if late_names.len() >= self.options.max_passive {
                    break;
                }
                if normalize_observed_name(name, domain).is_some() && late_seen.insert(name.clone())
                {
                    late_names.push(name.clone());
                }
            }
            for name in &late_names {
                sources
                    .entry(name.clone())
                    .or_default()
                    .insert("passive:ct-direct".to_owned());
            }
            let mut late_payload = late_names
                .iter()
                .filter_map(|name| {
                    sources.get(name).map(|origins| {
                        (
                            name.clone(),
                            origins.clone(),
                            seed_candidate_priority(origins),
                        )
                    })
                })
                .collect::<Vec<_>>();
            late_payload.sort_by_key(|(fqdn, _, priority)| (Reverse(*priority), fqdn.clone()));
            self.database.persist_scan_seed_candidates(
                scan_id,
                &late_payload,
                self.options.max_passive,
            )?;

            // If CT yielded fewer names than the reserve, fill the remaining
            // slots with the initial discoveries that were deliberately held
            // back. Existing rows are merged, so this also preserves CT
            // provenance for names already validated through another source.
            let mut refill_payload = sources
                .iter()
                .map(|(fqdn, origins)| {
                    (
                        fqdn.clone(),
                        origins.clone(),
                        seed_candidate_priority(origins),
                    )
                })
                .collect::<Vec<_>>();
            refill_payload.sort_by_key(|(fqdn, _, priority)| (Reverse(*priority), fqdn.clone()));
            self.database.persist_scan_seed_candidates(
                scan_id,
                &refill_payload,
                self.options.max_passive,
            )?;

            let accepted_seeds = self
                .database
                .scan_seed_candidates_for_output(scan_id)?
                .into_iter()
                .map(|(name, _)| name)
                .collect::<BTreeSet<_>>();
            let validation_hosts = late_payload
                .iter()
                .map(|(name, _, _)| name.clone())
                .filter(|name| accepted_seeds.contains(name))
                .filter(|name| !answers.contains_key(name))
                .take(2_000)
                .collect::<Vec<_>>();
            let validation_hosts = self
                .database
                .claim_scan_seed_candidates_by_name(scan_id, &validation_hosts)?;
            if !validation_hosts.is_empty() {
                let late_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                let parent_timed_out = self
                    .register_wildcard_parents_bounded(
                        &validation_hosts,
                        domain,
                        &mut parent_by_host,
                        &mut wildcard_by_parent,
                        20,
                        Some(late_deadline),
                    )
                    .await;
                let late_resolution = self
                    .resolve_batch_with_deadline(
                        scan_id,
                        domain,
                        &validation_hosts,
                        "DNS CT tardif",
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                        Some(late_deadline),
                        BatchDnsMode::Conservative,
                    )
                    .await?;
                let not_started = late_resolution
                    .not_started_hosts
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let terminal = validation_hosts
                    .iter()
                    .filter(|name| !not_started.contains(*name))
                    .cloned()
                    .collect::<Vec<_>>();
                self.database
                    .mark_scan_seed_candidates_done(scan_id, &terminal)?;
                cache_hits += late_resolution.cache_hits;
                network_resolved += late_resolution.resolved_from_network;
                for answer in late_resolution.answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
                if parent_timed_out || late_resolution.deadline_exhausted {
                    let warning = format!(
                        "CT incrémental: validation tardive bornée à 5s; {} nom(s) non démarré(s) restent non vérifiés",
                        late_resolution.not_started_hosts.len()
                    );
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                }
            }
        }
        phase_timings.push(PhaseTiming {
            phase: "candidate_dns".to_owned(),
            duration_ms: candidate_dns_started.elapsed().as_millis(),
        });

        let enrichment_started = Instant::now();
        let mut dns_edges = Vec::<DiscoveryEdge>::new();
        let mut child_zones = BTreeSet::new();
        let mut service_endpoints = Vec::<ServiceEndpoint>::new();
        if self.options.dns_graph {
            self.emit(ProgressEvent::Phase {
                name: "graphe DNS".to_owned(),
                detail: "MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB et zones enfants".to_owned(),
            });
            let graph_input = answers
                .values()
                .filter(|answer| {
                    Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .take(self.options.graph_max_hosts)
                .map(|answer| answer.fqdn.clone())
                .collect::<Vec<_>>();
            graph_processed.extend(graph_input.iter().cloned());
            let mut graph = self
                .await_with_phase_heartbeat(
                    "graphe DNS",
                    "interrogation des enregistrements et délégations",
                    discover_dns_graph(
                        &self.dns,
                        domain,
                        graph_input,
                        self.options.graph_max_hosts,
                        self.options.service_discovery,
                    ),
                )
                .await;
            for answer in answers.values().filter(|answer| {
                Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            }) {
                for record in &answer.records {
                    let target = (record.record_type == "CNAME")
                        .then(|| normalize_observed_name(&record.value, domain))
                        .flatten();
                    if let Some(target) = &target {
                        graph.names.insert(target.clone());
                    }
                    graph.edges.insert(DiscoveryEdge {
                        owner: answer.fqdn.clone(),
                        record_type: record.record_type.clone(),
                        value: record.value.clone(),
                        target,
                    });
                }
            }
            if self.options.ptr_pivot {
                let addresses = answers
                    .values()
                    .filter(|answer| {
                        Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                    })
                    .flat_map(|answer| answer.records.iter())
                    .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
                    .filter_map(|record| record.value.parse().ok())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .take(self.options.ptr_max_ips)
                    .collect::<Vec<_>>();
                graph.queried += addresses.len();
                let reverse_names = self
                    .await_with_phase_heartbeat(
                        "graphe DNS",
                        "résolution inverse PTR",
                        self.dns.reverse_names(addresses),
                    )
                    .await;
                for (address, names) in reverse_names {
                    for name in names {
                        if let Some(name) = normalize_observed_name(&name, domain) {
                            graph.names.insert(name.clone());
                            graph.edges.insert(DiscoveryEdge {
                                owner: address.to_string(),
                                record_type: "PTR".to_owned(),
                                value: name.clone(),
                                target: Some(name),
                            });
                        }
                    }
                }
            }
            self.database.store_discovery_graph(
                domain,
                &graph.edges,
                &graph.service_endpoints,
                &graph.child_zones,
            )?;
            self.emit(ProgressEvent::DnsGraph {
                queries: graph.queried,
                edges: graph.edges.len(),
                names: graph.names.len(),
                child_zones: graph.child_zones.len(),
                services: graph.service_endpoints.len(),
                duration_ms: graph.duration_ms,
            });
            for edge in &graph.edges {
                if let Some(target) = &edge.target {
                    sources.entry(target.clone()).or_default().insert(format!(
                        "dns-graph:{}:{}",
                        edge.record_type.to_ascii_lowercase(),
                        edge.owner
                    ));
                }
            }
            for name in &graph.names {
                pipeline.enqueue(name.clone(), 90);
            }
            let graph_hosts = if self.options.pipeline {
                pipeline.drain(self.options.pipeline_budget)
            } else {
                graph
                    .names
                    .iter()
                    .filter(|name| !answers.contains_key(*name))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            if !graph_hosts.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += graph_hosts.len();
            }
            self.register_wildcard_parents_with_budget(
                &graph_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
                &mut active_budget_remaining,
            )
            .await;
            if !graph_hosts.is_empty() {
                let (graph_answers, graph_cache_hits, graph_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &graph_hosts,
                        "DNS graphe",
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += graph_cache_hits;
                network_resolved += graph_network_resolved;
                for answer in graph_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
            dns_edges = graph.edges.into_iter().collect();
            child_zones = graph.child_zones;
            service_endpoints = graph.service_endpoints.into_iter().collect();
        }

        if self.options.passive && !child_zones.is_empty() {
            let passive_phase_started = Instant::now();
            let deadline = phase_deadline(passive_budget_remaining);
            let recursive_names = self
                .collect_passive_recursively(
                    domain,
                    child_zones.iter().cloned(),
                    deadline,
                    &mut passive_zones_queried,
                    &mut sources,
                    &mut warnings,
                )
                .await?;
            consume_phase_budget(
                &mut passive_budget_remaining,
                passive_phase_started.elapsed(),
            );
            let recursive_names = recursive_names
                .into_iter()
                .filter(|name| !answers.contains_key(name))
                .collect::<Vec<_>>();
            self.register_wildcard_parents_with_budget(
                &recursive_names,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
                &mut active_budget_remaining,
            )
            .await;
            if !recursive_names.is_empty() {
                let (recursive_answers, recursive_cache_hits, recursive_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &recursive_names,
                        "DNS passif récursif",
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += recursive_cache_hits;
                network_resolved += recursive_network_resolved;
                for answer in recursive_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
        }

        let mut dnssec_walks = Vec::<DnssecWalkResult>::new();
        if self.options.dnssec_nsec {
            let zones = std::iter::once(domain.to_owned())
                .chain(child_zones.iter().cloned())
                .collect::<BTreeSet<_>>();
            let phase_started = Instant::now();
            let deadline = phase_deadline(nsec_budget_remaining);
            let phase_budget = nsec_budget_remaining
                .map(|remaining| format!("{} s restantes", remaining.as_secs()))
                .unwrap_or_else(|| "illimité".to_owned());
            self.emit(ProgressEvent::Phase {
                name: "DNSSEC NSEC".to_owned(),
                detail: format!(
                    "{} zone(s), parcours borné, cache permanent, budget {phase_budget}",
                    zones.len()
                ),
            });
            let walks = self
                .await_with_phase_heartbeat(
                    "DNSSEC NSEC",
                    "parcours des zones",
                    discover_nsec_bounded(
                        &self.database,
                        &self.dns,
                        domain,
                        zones,
                        self.options.nsec_timeout,
                        self.options.nsec_refresh,
                        self.options.nsec_max_names,
                        deadline,
                    ),
                )
                .await;
            consume_phase_budget(&mut nsec_budget_remaining, phase_started.elapsed());
            if nsec_budget_remaining.is_some_and(|remaining| remaining.is_zero()) {
                let warning =
                    "DNSSEC NSEC: budget cumulé atteint; résultats partiels conservés".to_owned();
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
                nsec_budget_warning_emitted = true;
            }
            let nsec_names = walks
                .iter()
                .flat_map(|walk| walk.names.iter().cloned())
                .collect::<BTreeSet<_>>();
            self.emit(ProgressEvent::Dnssec {
                zones: walks.len(),
                walked: walks
                    .iter()
                    .filter(|walk| matches!(walk.status.as_str(), "walked" | "partial"))
                    .count(),
                protected: walks
                    .iter()
                    .filter(|walk| {
                        matches!(
                            walk.status.as_str(),
                            "nsec3-protected" | "nsec-minimal-protected"
                        )
                    })
                    .count(),
                queries: walks.iter().map(|walk| walk.queries).sum(),
                names: nsec_names.len(),
            });
            for walk in &walks {
                for name in &walk.names {
                    sources
                        .entry(name.clone())
                        .or_default()
                        .insert(format!("dnssec-nsec:{}", walk.nameserver));
                }
            }
            for name in nsec_names {
                pipeline.enqueue(name, 120);
            }
            let nsec_hosts = if self.options.pipeline {
                pipeline.drain(self.options.pipeline_budget)
            } else {
                pipeline.drain(usize::MAX)
            };
            if !nsec_hosts.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += nsec_hosts.len();
            }
            self.register_wildcard_parents_with_budget(
                &nsec_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
                &mut active_budget_remaining,
            )
            .await;
            if !nsec_hosts.is_empty() {
                let (nsec_answers, nsec_cache_hits, nsec_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &nsec_hosts,
                        "DNS NSEC",
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += nsec_cache_hits;
                network_resolved += nsec_network_resolved;
                for answer in nsec_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
            dnssec_walks = walks;
        }

        let mut web_observations = Vec::<WebObservation>::new();
        let mut measured_http_requests = 0_u64;
        let mut measured_http_bytes = 0_u64;
        let mut measured_tls_connections = 0_u64;
        if self.options.metadata_discovery {
            let metadata_phase_started = Instant::now();
            let metadata_budget = metadata_phase_budget(web_budget_remaining);
            let metadata_deadline = tokio::time::Instant::now() + metadata_budget;
            let mut metadata_hosts = vec![domain.to_owned()];
            metadata_hosts.extend(
                answers
                    .values()
                    .filter(|answer| {
                        Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                    })
                    .map(|answer| answer.fqdn.clone())
                    .filter(|host| {
                        if self.options.metadata_all_hosts {
                            return true;
                        }
                        let relative = host
                            .strip_suffix(&format!(".{domain}"))
                            .unwrap_or(host.as_str());
                        matches!(
                            relative.split('.').next().unwrap_or_default(),
                            "api"
                                | "auth"
                                | "login"
                                | "sso"
                                | "developer"
                                | "dev"
                                | "mail"
                                | "account"
                                | "accounts"
                        )
                    }),
            );
            metadata_hosts.sort();
            metadata_hosts.dedup();
            metadata_hosts.truncate(self.options.metadata_max_requests.div_ceil(6).max(1));
            self.emit(ProgressEvent::Phase {
                name: "métadonnées standardisées".to_owned(),
                detail: format!(
                    "{} hôte(s), {} requêtes HTTPS maximum, budget partagé {}s",
                    metadata_hosts.len(),
                    self.options.metadata_max_requests,
                    metadata_budget.as_secs()
                ),
            });
            let metadata_config = MetadataDiscoveryConfig {
                max_body_bytes: 512 * 1024,
                max_redirects: 2,
                max_requests: self.options.metadata_max_requests,
                request_timeout: self.options.web_timeout.min(Duration::from_secs(8)),
                phase_deadline: Some(metadata_deadline),
                dns_concurrency: METADATA_DNS_CONCURRENCY,
            };
            let metadata_dns = self.trusted_dns.as_ref().unwrap_or(&self.dns);
            let metadata_result = self
                .await_with_phase_heartbeat(
                    "métadonnées standardisées",
                    "API Catalog, identité, Terraform et SSH",
                    discover_metadata(metadata_dns, domain, metadata_hosts, metadata_config),
                )
                .await;
            consume_phase_budget(&mut web_budget_remaining, metadata_phase_started.elapsed());
            web_budget_exhausted |=
                web_budget_remaining.is_some_and(|remaining| remaining.is_zero());
            match metadata_result {
                Ok(metadata) => {
                    measured_http_requests =
                        measured_http_requests.saturating_add(metadata.network_requests as u64);
                    measured_http_bytes =
                        measured_http_bytes.saturating_add(metadata.bytes_transferred);
                    for observation in &metadata.observations {
                        for name in &observation.names {
                            sources.entry(name.clone()).or_default().insert(format!(
                                "{}:{}",
                                observation.endpoint.source_name(),
                                observation.url
                            ));
                        }
                        web_observations.push(WebObservation {
                            url: observation.url.clone(),
                            status: observation.status,
                            names: observation.names.clone(),
                            from_cache: false,
                        });
                    }
                    for name in metadata.unique_names {
                        pipeline.enqueue(name, 130);
                    }
                    let metadata_candidates = if self.options.pipeline {
                        pipeline.drain(self.options.pipeline_budget)
                    } else {
                        pipeline.drain(usize::MAX)
                    };
                    if !metadata_candidates.is_empty() {
                        validation_rounds += 1;
                        pipeline_names_validated += metadata_candidates.len();
                        self.register_wildcard_parents_with_budget(
                            &metadata_candidates,
                            domain,
                            &mut parent_by_host,
                            &mut wildcard_by_parent,
                            12,
                            &mut active_budget_remaining,
                        )
                        .await;
                        let (metadata_answers, metadata_cache_hits, metadata_network_resolved) =
                            self.resolve_batch(
                                scan_id,
                                domain,
                                &metadata_candidates,
                                "DNS métadonnées",
                                &started,
                                &sources,
                                &root_wildcard,
                                &parent_by_host,
                                &wildcard_by_parent,
                            )
                            .await?;
                        cache_hits += metadata_cache_hits;
                        network_resolved += metadata_network_resolved;
                        for answer in metadata_answers {
                            answers.insert(answer.fqdn.clone(), answer);
                        }
                    }
                    if metadata.budget_exhausted {
                        warnings.push(
                            "métadonnées standardisées: budget atteint, résultats partiels conservés"
                                .to_owned(),
                        );
                    }
                    if !metadata.failures.is_empty() {
                        self.emit(ProgressEvent::Phase {
                            name: "métadonnées standardisées".to_owned(),
                            detail: format!(
                                "{} requête(s), {} échec(s), {} nom(s)",
                                metadata.network_requests,
                                metadata.failures.len(),
                                sources
                                    .values()
                                    .filter(|origins| origins
                                        .iter()
                                        .any(|origin| { origin.starts_with("metadata:") }))
                                    .count()
                            ),
                        });
                    }
                }
                Err(error) => {
                    let warning = format!("métadonnées standardisées indisponibles: {error:#}");
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                }
            }
        }
        if self.options.web_discovery {
            let mut web_hosts = answers
                .values()
                .filter(|answer| {
                    Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                })
                .map(|answer| answer.fqdn.clone())
                .collect::<Vec<_>>();
            web_hosts.push(domain.to_owned());
            web_hosts.sort_by_key(|host| {
                let relative = host
                    .strip_suffix(&format!(".{domain}"))
                    .unwrap_or(host.as_str());
                let first = relative.split('.').next().unwrap_or_default();
                let priority = match first {
                    "www" => 0,
                    "api" | "auth" | "login" | "account" | "accounts" => 1,
                    "admin" | "portal" | "app" | "dashboard" => 2,
                    _ if host == domain => 0,
                    _ => 3,
                };
                (priority, relative.split('.').count(), host.clone())
            });
            web_hosts.dedup();
            web_hosts.truncate(self.options.web_max_hosts);
            web_processed.extend(web_hosts.iter().cloned());
            let web_phase_started = Instant::now();
            let web_deadline = phase_deadline(web_budget_remaining);
            let web_budget = web_budget_remaining
                .map(|remaining| format!("{} s restantes", remaining.as_secs()))
                .unwrap_or_else(|| "illimité".to_owned());
            self.emit(ProgressEvent::Phase {
                name: "web/JavaScript".to_owned(),
                detail: format!(
                    "{} hôte(s), {} asset(s) maximum par hôte, budget {web_budget}",
                    web_hosts.len(),
                    self.options.web_assets_per_host
                ),
            });
            let web = self
                .await_with_phase_heartbeat(
                    "web/JavaScript",
                    "collecte des pages et assets",
                    discover_web_bounded(
                        &self.database,
                        &self.dns,
                        domain,
                        web_hosts.clone(),
                        self.options.web_timeout,
                        self.options.web_refresh,
                        self.options.web_concurrency,
                        self.options.web_max_bytes,
                        self.options.web_assets_per_host,
                        web_deadline,
                    ),
                )
                .await?;
            measured_http_requests =
                measured_http_requests.saturating_add(web.network_requests as u64);
            measured_http_bytes = measured_http_bytes.saturating_add(web.bytes_transferred);
            consume_phase_budget(&mut web_budget_remaining, web_phase_started.elapsed());
            web_budget_exhausted = web.budget_exhausted
                || web_budget_remaining.is_some_and(|remaining| remaining.is_zero());
            if web_budget_exhausted {
                let warning = "Web/JavaScript: budget cumulé atteint; résultats partiels conservés et travaux restants ignorés"
                    .to_owned();
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
            self.emit(ProgressEvent::WebDiscovery {
                hosts: web_hosts.len(),
                requests: web.network_requests,
                cache_hits: web.cache_hits,
                failures: web.failures,
                names: web.unique_names.len(),
                duration_ms: web.duration_ms,
            });
            for observation in &web.observations {
                for name in &observation.names {
                    sources
                        .entry(name.clone())
                        .or_default()
                        .insert(format!("web:{}", observation.url));
                }
            }
            for name in &web.unique_names {
                pipeline.enqueue(name.clone(), 100);
            }
            let web_hosts_to_validate = if self.options.pipeline {
                pipeline.drain(self.options.pipeline_budget)
            } else {
                pipeline.drain(usize::MAX)
            };
            if !web_hosts_to_validate.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += web_hosts_to_validate.len();
            }
            self.register_wildcard_parents_with_budget(
                &web_hosts_to_validate,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
                &mut active_budget_remaining,
            )
            .await;
            if !web_hosts_to_validate.is_empty() {
                let (web_answers, web_cache_hits, web_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &web_hosts_to_validate,
                        "DNS web/JS",
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += web_cache_hits;
                network_resolved += web_network_resolved;
                for answer in web_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
            web_observations.extend(web.observations);
        }

        let mut tls_certificates = Vec::new();
        if self.options.tls_certificates {
            let endpoints = self.tls_endpoints(
                domain,
                &answers,
                &service_endpoints,
                &root_wildcard,
                &wildcard_by_parent,
            );
            tls_processed.extend(
                endpoints
                    .iter()
                    .map(|(host, port, transport)| format!("{host}:{port}:{transport}")),
            );
            let ports = endpoints
                .iter()
                .map(|(_, port, _)| *port)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(",");
            self.emit(ProgressEvent::Phase {
                name: "certificats TLS".to_owned(),
                detail: format!(
                    "{} endpoint(s), port(s) {}, extraction SAN/CN",
                    endpoints.len(),
                    ports
                ),
            });
            let discovery = self
                .await_with_phase_heartbeat(
                    "certificats TLS",
                    "connexions TLS/STARTTLS et extraction SAN/CN",
                    discover_tls_certificates(
                        &self.database,
                        &self.dns,
                        domain,
                        endpoints.clone(),
                        self.options.tls_timeout,
                        self.options.tls_refresh,
                        self.options.tls_concurrency,
                    ),
                )
                .await?;
            measured_tls_connections = measured_tls_connections.saturating_add(
                discovery
                    .attempted_network
                    .saturating_add(discovery.differential_attempted) as u64,
            );
            self.emit(ProgressEvent::TlsCertificates {
                endpoints: endpoints.len(),
                network: discovery.attempted_network,
                successes: discovery.successful_network,
                failures: discovery.failed_network,
                cache_hits: discovery.cache_hits,
                names: discovery.unique_names.len(),
                duration_ms: discovery.duration_ms,
            });

            let selected_names = discovery
                .unique_names
                .iter()
                .take(self.options.max_passive)
                .cloned()
                .collect::<BTreeSet<_>>();
            for observation in &discovery.observations {
                for name in observation
                    .names
                    .iter()
                    .filter(|name| selected_names.contains(*name))
                {
                    sources.entry(name.clone()).or_default().insert(format!(
                        "tls-cert:{}:{}",
                        observation.endpoint, observation.port
                    ));
                }
            }
            for name in selected_names {
                pipeline.enqueue(name, 110);
            }
            let tls_hosts = if self.options.pipeline {
                pipeline.drain(self.options.pipeline_budget)
            } else {
                pipeline.drain(usize::MAX)
            };
            if !tls_hosts.is_empty() {
                validation_rounds += 1;
                pipeline_names_validated += tls_hosts.len();
            }
            self.register_wildcard_parents_with_budget(
                &tls_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
                &mut active_budget_remaining,
            )
            .await;
            if !tls_hosts.is_empty() {
                self.emit(ProgressEvent::Phase {
                    name: "DNS certificats TLS".to_owned(),
                    detail: format!("{} nouveau(x) nom(s) SAN/CN à valider", tls_hosts.len()),
                });
                let (tls_answers, tls_cache_hits, tls_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &tls_hosts,
                        "DNS certificats TLS",
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += tls_cache_hits;
                network_resolved += tls_network_resolved;
                for answer in tls_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
            tls_certificates = discovery.observations;
        }

        if self.options.pipeline {
            for round in 1..=self.options.pipeline_rounds {
                let graph_remaining = self
                    .options
                    .graph_max_hosts
                    .saturating_sub(graph_processed.len());
                let web_remaining = if self.options.web_discovery && !web_budget_exhausted {
                    self.options
                        .web_max_hosts
                        .saturating_sub(web_processed.len())
                } else {
                    0
                };
                let tls_remaining = self
                    .options
                    .tls_max_hosts
                    .saturating_sub(tls_processed.len());
                let graph_hosts = answers
                    .values()
                    .filter(|answer| {
                        Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                    })
                    .map(|answer| &answer.fqdn)
                    .filter(|host| !graph_processed.contains(*host))
                    .take(graph_remaining)
                    .cloned()
                    .collect::<Vec<_>>();
                let web_hosts = answers
                    .values()
                    .filter(|answer| {
                        Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                    })
                    .map(|answer| &answer.fqdn)
                    .filter(|host| !web_processed.contains(*host))
                    .take(web_remaining)
                    .cloned()
                    .collect::<Vec<_>>();
                if graph_hosts.is_empty() && web_hosts.is_empty() && tls_remaining == 0 {
                    break;
                }
                self.emit(ProgressEvent::Phase {
                    name: format!("pipeline événementiel {round}"),
                    detail: format!(
                        "{} hôte(s) graphe, {} hôte(s) web, budget TLS {}",
                        graph_hosts.len(),
                        web_hosts.len(),
                        tls_remaining
                    ),
                });

                if self.options.dns_graph && !graph_hosts.is_empty() {
                    graph_processed.extend(graph_hosts.iter().cloned());
                    let graph = self
                        .await_with_phase_heartbeat(
                            format!("pipeline événementiel {round}"),
                            "enrichissement du graphe DNS",
                            discover_dns_graph(
                                &self.dns,
                                domain,
                                graph_hosts,
                                graph_remaining,
                                false,
                            ),
                        )
                        .await;
                    self.database.store_discovery_graph(
                        domain,
                        &graph.edges,
                        &graph.service_endpoints,
                        &graph.child_zones,
                    )?;
                    self.emit(ProgressEvent::DnsGraph {
                        queries: graph.queried,
                        edges: graph.edges.len(),
                        names: graph.names.len(),
                        child_zones: graph.child_zones.len(),
                        services: graph.service_endpoints.len(),
                        duration_ms: graph.duration_ms,
                    });
                    for edge in &graph.edges {
                        if let Some(target) = &edge.target {
                            sources.entry(target.clone()).or_default().insert(format!(
                                "dns-graph:{}:{}",
                                edge.record_type.to_ascii_lowercase(),
                                edge.owner
                            ));
                        }
                    }
                    for name in graph.names {
                        pipeline.enqueue(name, 90);
                    }
                    dns_edges.extend(graph.edges);
                    dns_edges.sort();
                    dns_edges.dedup();
                    child_zones.extend(graph.child_zones);
                    service_endpoints.extend(graph.service_endpoints);
                    service_endpoints.sort();
                    service_endpoints.dedup();
                }

                if self.options.web_discovery && !web_hosts.is_empty() {
                    web_processed.extend(web_hosts.iter().cloned());
                    let web_phase_started = Instant::now();
                    let web_deadline = phase_deadline(web_budget_remaining);
                    let web = self
                        .await_with_phase_heartbeat(
                            format!("pipeline événementiel {round}"),
                            "collecte web/JavaScript",
                            discover_web_bounded(
                                &self.database,
                                &self.dns,
                                domain,
                                web_hosts.clone(),
                                self.options.web_timeout,
                                self.options.web_refresh,
                                self.options.web_concurrency,
                                self.options.web_max_bytes,
                                self.options.web_assets_per_host,
                                web_deadline,
                            ),
                        )
                        .await?;
                    measured_http_requests =
                        measured_http_requests.saturating_add(web.network_requests as u64);
                    measured_http_bytes = measured_http_bytes.saturating_add(web.bytes_transferred);
                    consume_phase_budget(&mut web_budget_remaining, web_phase_started.elapsed());
                    if web.budget_exhausted
                        || web_budget_remaining.is_some_and(|remaining| remaining.is_zero())
                    {
                        web_budget_exhausted = true;
                        let warning = "Web/JavaScript: budget cumulé atteint pendant le pipeline; résultats partiels conservés et travaux restants ignorés"
                            .to_owned();
                        self.emit(ProgressEvent::Warning(warning.clone()));
                        warnings.push(warning);
                    }
                    self.emit(ProgressEvent::WebDiscovery {
                        hosts: web_hosts.len(),
                        requests: web.network_requests,
                        cache_hits: web.cache_hits,
                        failures: web.failures,
                        names: web.unique_names.len(),
                        duration_ms: web.duration_ms,
                    });
                    for observation in &web.observations {
                        for name in &observation.names {
                            sources
                                .entry(name.clone())
                                .or_default()
                                .insert(format!("web:{}", observation.url));
                        }
                    }
                    for name in web.unique_names {
                        pipeline.enqueue(name, 100);
                    }
                    web_observations.extend(web.observations);
                    web_observations.sort_by(|left, right| left.url.cmp(&right.url));
                    web_observations.dedup_by(|left, right| left.url == right.url);
                }

                if self.options.tls_certificates && tls_remaining > 0 {
                    let endpoints = self
                        .tls_endpoints(
                            domain,
                            &answers,
                            &service_endpoints,
                            &root_wildcard,
                            &wildcard_by_parent,
                        )
                        .into_iter()
                        .filter(|(host, port, transport)| {
                            !tls_processed.contains(&format!("{host}:{port}:{transport}"))
                        })
                        .take(tls_remaining)
                        .collect::<Vec<_>>();
                    tls_processed.extend(
                        endpoints
                            .iter()
                            .map(|(host, port, transport)| format!("{host}:{port}:{transport}")),
                    );
                    if !endpoints.is_empty() {
                        let discovery = self
                            .await_with_phase_heartbeat(
                                format!("pipeline événementiel {round}"),
                                "collecte des certificats TLS/STARTTLS",
                                discover_tls_certificates(
                                    &self.database,
                                    &self.dns,
                                    domain,
                                    endpoints.clone(),
                                    self.options.tls_timeout,
                                    self.options.tls_refresh,
                                    self.options.tls_concurrency,
                                ),
                            )
                            .await?;
                        measured_tls_connections = measured_tls_connections.saturating_add(
                            discovery
                                .attempted_network
                                .saturating_add(discovery.differential_attempted)
                                as u64,
                        );
                        self.emit(ProgressEvent::TlsCertificates {
                            endpoints: endpoints.len(),
                            network: discovery.attempted_network,
                            successes: discovery.successful_network,
                            failures: discovery.failed_network,
                            cache_hits: discovery.cache_hits,
                            names: discovery.unique_names.len(),
                            duration_ms: discovery.duration_ms,
                        });
                        for observation in &discovery.observations {
                            for name in &observation.names {
                                sources.entry(name.clone()).or_default().insert(format!(
                                    "tls-cert:{}:{}",
                                    observation.endpoint, observation.port
                                ));
                            }
                        }
                        for name in discovery.unique_names {
                            pipeline.enqueue(name, 110);
                        }
                        tls_certificates.extend(discovery.observations);
                        tls_certificates.sort_by(|left, right| {
                            (&left.endpoint, left.port).cmp(&(&right.endpoint, right.port))
                        });
                        tls_certificates.dedup_by(|left, right| {
                            left.endpoint == right.endpoint && left.port == right.port
                        });
                    }
                }

                let new_hosts = pipeline.drain(self.options.pipeline_budget);
                if new_hosts.is_empty() {
                    break;
                }
                validation_rounds += 1;
                pipeline_names_validated += new_hosts.len();
                self.register_wildcard_parents_with_budget(
                    &new_hosts,
                    domain,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    20,
                    &mut active_budget_remaining,
                )
                .await;
                let (new_answers, new_cache_hits, new_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        domain,
                        &new_hosts,
                        &format!("DNS pipeline {round}"),
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += new_cache_hits;
                network_resolved += new_network_resolved;
                for answer in new_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
            }
        }

        if self.options.dnssec_nsec {
            let completed_zones = dnssec_walks
                .iter()
                .map(|walk| walk.zone.clone())
                .collect::<BTreeSet<_>>();
            let late_zones = child_zones
                .iter()
                .filter(|zone| !completed_zones.contains(*zone))
                .cloned()
                .collect::<BTreeSet<_>>();
            if !late_zones.is_empty() {
                let phase_started = Instant::now();
                let deadline = phase_deadline(nsec_budget_remaining);
                let walks = self
                    .await_with_phase_heartbeat(
                        "DNSSEC NSEC zones filles",
                        "parcours des nouvelles zones déléguées",
                        discover_nsec_bounded(
                            &self.database,
                            &self.dns,
                            domain,
                            late_zones,
                            self.options.nsec_timeout,
                            self.options.nsec_refresh,
                            self.options.nsec_max_names,
                            deadline,
                        ),
                    )
                    .await;
                consume_phase_budget(&mut nsec_budget_remaining, phase_started.elapsed());
                if !nsec_budget_warning_emitted
                    && nsec_budget_remaining.is_some_and(|remaining| remaining.is_zero())
                {
                    let warning =
                        "DNSSEC NSEC: budget cumulé atteint; résultats partiels conservés"
                            .to_owned();
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                }
                for walk in &walks {
                    for name in &walk.names {
                        sources
                            .entry(name.clone())
                            .or_default()
                            .insert(format!("dnssec-nsec:{}", walk.nameserver));
                        pipeline.enqueue(name.clone(), 120);
                    }
                }
                dnssec_walks.extend(walks);
                dnssec_walks.sort_by(|left, right| left.zone.cmp(&right.zone));
                let hosts = pipeline.drain(self.options.pipeline_budget);
                if !hosts.is_empty() {
                    validation_rounds += 1;
                    pipeline_names_validated += hosts.len();
                    self.register_wildcard_parents_with_budget(
                        &hosts,
                        domain,
                        &mut parent_by_host,
                        &mut wildcard_by_parent,
                        20,
                        &mut active_budget_remaining,
                    )
                    .await;
                    let (resolved, extra_cache_hits, extra_network) = self
                        .resolve_batch(
                            scan_id,
                            domain,
                            &hosts,
                            "DNS NSEC zones filles",
                            &started,
                            &sources,
                            &root_wildcard,
                            &parent_by_host,
                            &wildcard_by_parent,
                        )
                        .await?;
                    cache_hits += extra_cache_hits;
                    network_resolved += extra_network;
                    for answer in resolved {
                        answers.insert(answer.fqdn.clone(), answer);
                    }
                }
            }
        }

        if !self.options.passive_only && self.options.recursive_depth > 1 {
            let mut recursive_words = self.recursive_wordlist()?;
            if self.options.adaptive {
                recursive_words.truncate(50);
            }
            let recursive_words = self
                .database
                .ensure_scan_recursive_words(scan_id, &recursive_words)?;
            let recursive_batch_limit = if self.options.adaptive { 1_000 } else { 5_000 };
            for depth in 2..=self.options.recursive_depth {
                let mut parents = answers
                    .values()
                    .filter(|answer| {
                        answer
                            .fqdn
                            .strip_suffix(&format!(".{domain}"))
                            .is_some_and(|relative| relative.split('.').count() == depth - 1)
                    })
                    .filter(|answer| {
                        Self::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
                    })
                    .map(|answer| answer.fqdn.clone())
                    .collect::<Vec<_>>();
                parents.sort();
                let parent_limit = if self.options.adaptive {
                    self.options.recursive_hosts.min(20)
                } else {
                    self.options.recursive_hosts
                };
                parents.truncate(parent_limit);
                self.database
                    .persist_scan_recursive_parents(scan_id, depth, &parents)?;
                let persisted_parents = self.database.scan_recursive_parents(scan_id, depth)?;
                if persisted_parents.is_empty() || recursive_words.is_empty() {
                    break;
                }
                if active_candidate_budget_exhausted(active_budget_remaining) {
                    break;
                }
                self.emit(ProgressEvent::Phase {
                    name: format!("récursion niveau {depth}"),
                    detail: format!(
                        "{} parent(s), {} mot(s) par parent",
                        persisted_parents.len(),
                        recursive_words.len()
                    ),
                });
                let recursive_profiles_started = Instant::now();
                let unprofiled_parents = persisted_parents
                    .iter()
                    .filter(|parent| !wildcard_by_parent.contains_key(*parent))
                    .cloned()
                    .collect::<Vec<_>>();
                let (recursive_profiles, recursive_profiles_timed_out) = self
                    .wildcard_signatures_cached_bounded(
                        unprofiled_parents,
                        phase_deadline(active_budget_remaining),
                    )
                    .await;
                wildcard_by_parent.extend(recursive_profiles);
                consume_phase_budget(
                    &mut active_budget_remaining,
                    recursive_profiles_started.elapsed(),
                );
                if recursive_profiles_timed_out && active_budget_remaining.is_some() {
                    active_budget_remaining = Some(Duration::ZERO);
                }
                if active_candidate_budget_exhausted(active_budget_remaining) {
                    break;
                }
                let mut depth_yield = 0_usize;
                loop {
                    if active_candidate_budget_exhausted(active_budget_remaining) {
                        recursive_budget_exhausted = self
                            .database
                            .scan_recursive_depth_has_more(scan_id, depth)?;
                        break;
                    }
                    let refill_started = Instant::now();
                    self.database.refill_scan_recursive_candidates(
                        scan_id,
                        depth,
                        recursive_batch_limit,
                    )?;
                    consume_phase_budget(&mut active_budget_remaining, refill_started.elapsed());
                    if active_candidate_budget_exhausted(active_budget_remaining) {
                        recursive_budget_exhausted = self
                            .database
                            .scan_recursive_depth_has_more(scan_id, depth)?;
                        break;
                    }
                    let recursive_candidates = self.database.pending_scan_recursive_candidates(
                        scan_id,
                        depth,
                        recursive_batch_limit,
                    )?;
                    if recursive_candidates.is_empty() {
                        if self
                            .database
                            .scan_recursive_depth_has_more(scan_id, depth)?
                        {
                            continue;
                        }
                        break;
                    }
                    let mut recursive_hosts = Vec::with_capacity(recursive_candidates.len());
                    let mut already_answered = Vec::new();
                    for (fqdn, parent, _) in &recursive_candidates {
                        sources
                            .entry(fqdn.clone())
                            .or_default()
                            .insert("dns-recursive".to_owned());
                        parent_by_host.insert(fqdn.clone(), parent.clone());
                        if answers.contains_key(fqdn) {
                            already_answered.push(fqdn.clone());
                        } else {
                            recursive_hosts.push(fqdn.clone());
                        }
                    }
                    self.database
                        .complete_scan_recursive_candidates(scan_id, &already_answered)?;
                    if recursive_hosts.is_empty() {
                        continue;
                    }

                    let phase = format!("DNS niveau {depth}");
                    let recursive_dns_started = Instant::now();
                    let round_resolution = self
                        .resolve_batch_with_deadline(
                            scan_id,
                            domain,
                            &recursive_hosts,
                            &phase,
                            &started,
                            &sources,
                            &root_wildcard,
                            &parent_by_host,
                            &wildcard_by_parent,
                            phase_deadline(active_budget_remaining),
                            BatchDnsMode::Conservative,
                        )
                        .await?;
                    consume_phase_budget(
                        &mut active_budget_remaining,
                        recursive_dns_started.elapsed(),
                    );
                    if round_resolution.deadline_exhausted && active_budget_remaining.is_some() {
                        active_budget_remaining = Some(Duration::ZERO);
                    }
                    let BatchResolution {
                        answers: round_answers,
                        cache_hits: round_cache_hits,
                        resolved_from_network: round_network_resolved,
                        not_started_hosts,
                        attempted_hosts,
                        ..
                    } = round_resolution;
                    self.database
                        .mark_scan_recursive_candidates_started(scan_id, &attempted_hosts)?;
                    let not_started = not_started_hosts.iter().cloned().collect::<BTreeSet<_>>();
                    let terminal_hosts = recursive_hosts
                        .iter()
                        .filter(|host| !not_started.contains(*host))
                        .cloned()
                        .collect::<Vec<_>>();
                    self.database
                        .mark_scan_recursive_candidates_done(scan_id, &terminal_hosts)?;
                    self.database
                        .requeue_unstarted_scan_recursive_candidates(scan_id, &not_started_hosts)?;
                    cache_hits += round_cache_hits;
                    network_resolved += round_network_resolved;
                    depth_yield = depth_yield.saturating_add(round_answers.len());
                    for answer in round_answers {
                        answers.insert(answer.fqdn.clone(), answer);
                    }
                    if active_candidate_budget_exhausted(active_budget_remaining) {
                        recursive_budget_exhausted = self
                            .database
                            .scan_recursive_depth_has_more(scan_id, depth)?;
                        break;
                    }
                }
                if recursive_budget_exhausted {
                    break;
                }
                if self.options.adaptive && depth_yield < 2 {
                    self.emit(ProgressEvent::Phase {
                        name: "adaptation".to_owned(),
                        detail: format!(
                            "récursion arrêtée au niveau {depth}: rendement {depth_yield}"
                        ),
                    });
                    break;
                }
            }
        }
        phase_timings.push(PhaseTiming {
            phase: "enrichment".to_owned(),
            duration_ms: enrichment_started.elapsed().as_millis(),
        });
        let finalization_started = Instant::now();
        let pending_seed_candidates = self
            .database
            .pending_scan_seed_candidate_count(scan_id)?
            .max(0) as usize;
        let pending_active_candidates =
            self.database.pending_scan_candidate_count(scan_id)?.max(0) as usize;
        let recursive_work_remaining = self.database.scan_recursive_has_more(scan_id)?;
        let candidate_feed_remaining =
            !candidate_expansion_stopped_naturally && self.candidate_feeds_have_more(scan_id)?;
        let active_resume_required = active_resume_required(
            active_budget_remaining,
            pending_seed_candidates,
            pending_active_candidates,
            candidate_feed_remaining,
            recursive_work_remaining,
        );
        if active_resume_required {
            let warning = format!(
                "travail DNS borné; {pending_seed_candidates} nom(s) passif(s) et {pending_active_candidates} candidat(s) actif(s) restent conservés pour --resume latest"
            );
            if !warnings.contains(&warning) {
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
            }
        }

        let mut findings = Vec::new();
        for answer in answers.into_values() {
            if let Some(finding) = self.finding_for_answer(
                &answer,
                &sources,
                &root_wildcard,
                &parent_by_host,
                &wildcard_by_parent,
            ) {
                findings.push(finding);
            }
        }
        let mut known_findings = findings
            .iter()
            .map(|finding| finding.fqdn.clone())
            .collect::<BTreeSet<_>>();
        let seed_candidates = self.database.scan_seed_candidates_for_output(scan_id)?;
        let seed_cache = self.database.fresh_cache(
            &seed_candidates
                .iter()
                .map(|(fqdn, _)| fqdn.clone())
                .collect::<Vec<_>>(),
        )?;
        for (fqdn, seed_sources) in seed_candidates {
            if !known_findings.insert(fqdn.clone()) {
                continue;
            }
            match seed_cache.get(&fqdn) {
                Some(CachedAnswer::Positive(answer)) => {
                    let signature = Self::applicable_wildcard_signature(
                        &fqdn,
                        &root_wildcard,
                        &wildcard_by_parent,
                    );
                    if wildcard_signature_is_confirmed(signature)
                        && DnsEngine::matches_wildcard(answer, signature)
                        && !self.options.include_wildcard
                    {
                        continue;
                    }
                    let persisted_sources = BTreeMap::from([(fqdn.clone(), seed_sources.clone())]);
                    if let Some(finding) = self.finding_for_answer(
                        answer,
                        &persisted_sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    ) {
                        findings.push(finding);
                    }
                }
                Some(CachedAnswer::Negative) => {
                    findings.push(self.finding_for_unresolved_seed(
                        fqdn,
                        seed_sources,
                        crate::model::ObservationState::Historical,
                        &root_wildcard,
                        &wildcard_by_parent,
                    ));
                }
                None => {
                    findings.push(self.finding_for_unresolved_seed(
                        fqdn,
                        seed_sources,
                        crate::model::ObservationState::Unverified,
                        &root_wildcard,
                        &wildcard_by_parent,
                    ));
                }
            }
        }
        findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));

        let durable_learning = self.database.scan_candidate_learning(scan_id)?;
        generator_attempts = durable_learning.generator_attempts;
        // Only definitive candidate outcomes are present in durable learning.
        // Replacing the eagerly collected working set prevents deadline-
        // cancelled or indeterminate labels from poisoning future rankings.
        attempted_words = durable_learning.attempted_words;
        let durable_candidate_attempts = durable_learning.total_attempts;

        self.emit(ProgressEvent::Phase {
            name: "SQLite".to_owned(),
            detail: "inventaire, cache et apprentissage local".to_owned(),
        });
        let mut successful_words = BTreeSet::new();
        let mut successful_patterns = BTreeSet::new();
        let mut successful_names = self.database.live_scan_finding_names(scan_id)?;
        successful_names.extend(
            findings
                .iter()
                .filter(|finding| {
                    !finding.wildcard && finding.state == crate::model::ObservationState::Live
                })
                .map(|finding| finding.fqdn.clone()),
        );
        for fqdn in successful_names {
            successful_words.extend(
                labels_from_name(&fqdn, domain)
                    .into_iter()
                    .filter(|label| learnable_label(label)),
            );
            if let Some(relative) = fqdn.strip_suffix(&format!(".{domain}"))
                && learnable_relative_name(relative)
            {
                successful_patterns.insert(relative.to_owned());
            }
        }
        pipeline_metrics.rounds = validation_rounds;
        pipeline_metrics.events_enqueued = pipeline.enqueued;
        pipeline_metrics.duplicates_suppressed = pipeline.duplicates;
        pipeline_metrics.names_validated = pipeline_names_validated;
        pipeline_metrics.budget_exhausted = pipeline.budget_exhausted;
        let confirmed_sources = findings
            .iter()
            .map(|finding| (finding.fqdn.clone(), finding.sources.clone()))
            .collect::<BTreeMap<_, _>>();
        self.database
            .store_scan_observations(domain, &confirmed_sources)?;
        self.database
            .persist_findings(scan_id, domain, &findings, self.options.ttl_cap)?;
        let restored_inventory = self.append_persistent_inventory(
            domain,
            &mut findings,
            &root_wildcard,
            &wildcard_by_parent,
        )?;
        if restored_inventory > 0 {
            self.emit(ProgressEvent::Phase {
                name: "inventaire permanent".to_owned(),
                detail: format!(
                    "{restored_inventory} résultat(s) historique(s) ou non revérifié(s) ajouté(s) à la sortie"
                ),
            });
        }
        if self.options.only_live {
            findings.retain(|finding| finding.state == crate::model::ObservationState::Live);
        }
        self.database.persist_scan_snapshot(scan_id, &findings)?;
        let resolver_metrics = merge_resolver_metrics(
            self.dns.take_metrics(),
            self.trusted_dns
                .as_ref()
                .map(DnsEngine::take_metrics)
                .unwrap_or_default(),
        );
        self.database.store_resolver_metrics(&resolver_metrics)?;
        self.database
            .store_pipeline_metrics(scan_id, &pipeline_metrics)?;
        let exclusive_generator_successes = self.database.exclusive_generator_successes(scan_id)?;
        let exclusive_discoveries = self.database.exclusive_live_count(scan_id)?;
        let dns_queries = resolver_metrics
            .iter()
            .map(|metric| metric.requests)
            .sum::<u64>();
        let elapsed_seconds = started.elapsed().as_secs_f64().max(0.001);
        let effective_qps = dns_queries as f64 / elapsed_seconds;
        let governor = self.dns.network_governor_snapshot();
        let stop_reason = if active_resume_required {
            StopReason::BudgetExhausted
        } else if candidate_expansion_stopped_naturally {
            StopReason::PosteriorLowYield
        } else if governor.degraded {
            StopReason::NetworkDegraded
        } else {
            StopReason::QueueDrained
        };
        let scheduler_metrics = SchedulerMetrics {
            dns_queries,
            tcp_connections: measured_tls_connections.saturating_add(axfr_attempts.len() as u64),
            http_requests: measured_http_requests,
            tls_connections: measured_tls_connections,
            bytes_transferred: measured_http_bytes,
            exclusive_discoveries,
            exploration_actions: generator_attempts.values().copied().sum(),
            backoffs: governor.backoffs,
            effective_qps_min: if governor.minimum_rate_seen == 0 {
                effective_qps
            } else {
                governor.minimum_rate_seen as f64
            },
            effective_qps_max: if governor.maximum_rate_seen == 0 {
                effective_qps
            } else {
                governor.maximum_rate_seen as f64
            },
            remaining_yield_upper_bound,
            stop_reason: Some(stop_reason),
        };
        let duration_before_learning_ms = started.elapsed().as_millis();
        let discovered_seed_count =
            self.database.scan_seed_candidate_count(scan_id)?.max(0) as usize;
        let candidate_count = discovered_seed_count.saturating_add(durable_candidate_attempts);
        if active_resume_required {
            self.database.pause_scan(
                scan_id,
                candidate_count,
                findings.len(),
                cache_hits,
                duration_before_learning_ms,
                &warnings,
            )?;
        } else {
            self.database.finalize_scan_with_learning(
                scan_id,
                domain,
                &generator_attempts,
                &exclusive_generator_successes,
                &attempted_words,
                &successful_words,
                &successful_patterns,
                candidate_count,
                findings.len(),
                cache_hits,
                duration_before_learning_ms,
                &warnings,
            )?;
        }
        phase_timings.push(PhaseTiming {
            phase: "finalization".to_owned(),
            duration_ms: finalization_started.elapsed().as_millis(),
        });
        let duration_ms = started.elapsed().as_millis();
        Ok(ScanResult {
            scan_id,
            domain: domain.to_owned(),
            status: if active_resume_required {
                "partial".to_owned()
            } else {
                "completed".to_owned()
            },
            resumable: active_resume_required,
            candidates: candidate_count,
            resolved_from_network: network_resolved,
            cache_hits,
            duration_ms,
            phase_timings,
            wildcard_detected: wildcard_signature_is_confirmed(&root_wildcard)
                || wildcard_by_parent
                    .values()
                    .any(wildcard_signature_is_confirmed),
            findings,
            axfr_attempts,
            tls_certificates,
            dns_edges,
            child_zones,
            service_endpoints,
            web_observations,
            dnssec_walks,
            ct_monitor,
            pipeline: pipeline_metrics,
            resolver_metrics,
            scheduler_metrics,
            warnings,
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RefreshResult {
    pub scan_id: i64,
    pub domain: String,
    pub status: String,
    pub total: usize,
    pub checked: usize,
    pub active: usize,
    pub inactive: usize,
    pub unverified: usize,
    pub indeterminate: usize,
    pub purged_wildcards: usize,
    pub duration_ms: u128,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct RefreshOptions {
    pub max_runtime: Duration,
    pub wildcard_phase_timeout: Duration,
    pub batch_size: usize,
}

impl Default for RefreshOptions {
    fn default() -> Self {
        Self {
            max_runtime: Duration::from_secs(300),
            wildcard_phase_timeout: Duration::from_secs(30),
            batch_size: 256,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RefreshProgress {
    pub checked: usize,
    pub total: usize,
    pub active: usize,
    pub inactive: usize,
    pub indeterminate: usize,
}

pub type RefreshProgressCallback = Arc<dyn Fn(RefreshProgress) + Send + Sync>;

struct RefreshRunGuard {
    database: Database,
    scan_id: i64,
    started: Instant,
    total: usize,
    checked: usize,
    found: usize,
    armed: bool,
}

impl RefreshRunGuard {
    fn new(database: Database, scan_id: i64, started: Instant, total: usize) -> Self {
        Self {
            database,
            scan_id,
            started,
            total,
            checked: 0,
            found: 0,
            armed: true,
        }
    }

    fn update(&mut self, checked: usize, found: usize) {
        self.checked = checked;
        self.found = found;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshRunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self
            .database
            .discard_refresh_wildcard_candidates(self.scan_id);
        let warning = format!(
            "actualisation interrompue après {}/{} nom(s); état des noms non traités préservé et purge wildcard ignorée",
            self.checked, self.total
        );
        let _ = self.database.finalize_non_resumable_scan(
            self.scan_id,
            "interrupted",
            self.checked,
            self.found,
            0,
            self.started.elapsed().as_millis(),
            &[warning],
        );
    }
}

async fn before_refresh_deadline<T, F>(
    deadline: Option<tokio::time::Instant>,
    future: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    match deadline {
        Some(deadline) if deadline <= tokio::time::Instant::now() => None,
        Some(deadline) => tokio::time::timeout_at(deadline, future).await.ok(),
        None => Some(future.await),
    }
}

fn refresh_deadline(max_runtime: Duration) -> Option<tokio::time::Instant> {
    (!max_runtime.is_zero()).then(|| {
        let now = tokio::time::Instant::now();
        now.checked_add(max_runtime).unwrap_or(now)
    })
}

fn capped_phase_deadline(
    global: Option<tokio::time::Instant>,
    phase_timeout: Duration,
) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    let phase = now.checked_add(phase_timeout).unwrap_or(now);
    global.map(|deadline| deadline.min(phase)).unwrap_or(phase)
}

fn refresh_allows_wildcard_purge(status: &str, classification_reliable: bool) -> bool {
    status == "completed" && classification_reliable
}

fn refresh_can_demote_wildcard_ambiguity(classification_reliable: bool) -> bool {
    classification_reliable
}

struct RefreshCleanupCancellation {
    cancelled: Arc<AtomicBool>,
    completion: Option<mpsc::Receiver<()>>,
    armed: bool,
}

impl RefreshCleanupCancellation {
    fn new(cancelled: Arc<AtomicBool>, completion: mpsc::Receiver<()>) -> Self {
        Self {
            cancelled,
            completion: Some(completion),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for RefreshCleanupCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
        }
        if let Some(completion) = self.completion.take() {
            let _ = completion.recv();
        }
    }
}

struct SignalRefreshCleanupCompletion(Option<mpsc::SyncSender<()>>);

impl Drop for SignalRefreshCleanupCompletion {
    fn drop(&mut self) {
        if let Some(completion) = self.0.take() {
            let _ = completion.send(());
        }
    }
}

async fn apply_completed_refresh_wildcard_cleanup(
    database: &Database,
    scan_id: i64,
    domain: &str,
    deadline: Option<tokio::time::Instant>,
    page_size: usize,
) -> Result<Option<(usize, usize)>> {
    if database.refresh_wildcard_candidate_count(scan_id)? == 0 {
        return Ok(Some((0, 0)));
    }
    if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
        database.discard_refresh_wildcard_candidates(scan_id)?;
        return Ok(None);
    }

    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let worker_database = database.clone();
    let worker_domain = domain.to_owned();
    let (completion_tx, completion_rx) = mpsc::sync_channel(1);
    let mut task = tokio::task::spawn_blocking(move || {
        let _completion = SignalRefreshCleanupCompletion(Some(completion_tx));
        worker_database.apply_staged_refresh_wildcard_cleanup(
            scan_id,
            &worker_domain,
            page_size,
            &worker_cancelled,
        )
    });
    let mut cancellation = RefreshCleanupCancellation::new(Arc::clone(&cancelled), completion_rx);
    let joined = match deadline {
        Some(deadline) => match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(joined) => joined?,
            Err(_) => {
                cancelled.store(true, Ordering::Release);
                let outcome = task.await??;
                cancellation.disarm();
                if let Some(result) = outcome {
                    return Ok(Some((result.purged, result.retained_unverified)));
                }
                database.discard_refresh_wildcard_candidates(scan_id)?;
                return Ok(None);
            }
        },
        None => task.await?,
    }?;
    cancellation.disarm();
    match joined {
        Some(result) => Ok(Some((result.purged, result.retained_unverified))),
        None => {
            database.discard_refresh_wildcard_candidates(scan_id)?;
            Ok(None)
        }
    }
}

fn record_bounded_parent_candidate(
    counts: &mut HashMap<String, usize>,
    parent: String,
    capacity: usize,
) -> bool {
    if let Some(count) = counts.get_mut(&parent) {
        *count = count.saturating_add(1);
        return false;
    }
    if counts.len() < capacity.max(1) {
        counts.insert(parent, 1);
        return false;
    }
    counts.retain(|_, count| {
        *count = count.saturating_sub(1);
        *count > 0
    });
    true
}

fn refresh_wildcard_profile_is_reliable(profile: Option<&BTreeSet<String>>) -> bool {
    profile.is_some_and(|signature| !wildcard_signature_is_indeterminate(signature))
}

fn refresh_wildcard_observation_is_reliable(
    observation: Option<&WildcardProfileObservation>,
) -> bool {
    observation.is_some_and(|observation| {
        observation.current_probe_reliable
            && refresh_wildcard_profile_is_reliable(observation.signature.as_ref())
    })
}

fn refresh_parent_selection_is_complete(candidate_count: usize, overflowed: bool) -> bool {
    !overflowed && candidate_count <= 64
}

pub async fn refresh_inventory(
    database: &Database,
    dns: &DnsEngine,
    target: &str,
    ttl_cap: u32,
    negative_ttl: u32,
) -> Result<RefreshResult> {
    refresh_inventory_with_trusted(database, dns, None, target, ttl_cap, negative_ttl).await
}

pub async fn refresh_inventory_with_trusted(
    database: &Database,
    dns: &DnsEngine,
    trusted_dns: Option<&DnsEngine>,
    target: &str,
    ttl_cap: u32,
    negative_ttl: u32,
) -> Result<RefreshResult> {
    refresh_inventory_bounded(
        database,
        dns,
        trusted_dns,
        target,
        ttl_cap,
        negative_ttl,
        RefreshOptions::default(),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn refresh_inventory_bounded(
    database: &Database,
    dns: &DnsEngine,
    trusted_dns: Option<&DnsEngine>,
    target: &str,
    ttl_cap: u32,
    negative_ttl: u32,
    options: RefreshOptions,
    progress: Option<RefreshProgressCallback>,
) -> Result<RefreshResult> {
    let domain = normalize_domain(target)?;
    let started = Instant::now();
    let global_deadline = refresh_deadline(options.max_runtime);
    let inventory_total = database.known_subdomain_count(&domain, true)?;
    let cache_only_total = database.positive_cache_only_count(&domain)?;
    let total = inventory_total.saturating_add(cache_only_total);
    let scan_id = database.create_scan(
        &domain,
        &json!({
            "mode": "refresh",
            "max_runtime_seconds": options.max_runtime.as_secs(),
            "wildcard_phase_timeout_seconds": options.wildcard_phase_timeout.as_secs(),
            "batch_size": options.batch_size.max(1),
        }),
    )?;
    let options_hash = domain_hash(&format!(
        "refresh:v4:{ttl_cap}:{negative_ttl}:{}:{}:{}",
        options.max_runtime.as_secs(),
        options.wildcard_phase_timeout.as_secs(),
        options.batch_size.max(1)
    ));
    database.upsert_checkpoint(scan_id, &domain, "running", &options_hash)?;
    // Refresh is deliberately non-resumable. Close its compatibility
    // checkpoint immediately so `scan --resume` can never select it.
    database.complete_checkpoint(scan_id)?;
    let mut run_guard = RefreshRunGuard::new(database.clone(), scan_id, started, total);
    let wildcard_deadline = capped_phase_deadline(global_deadline, options.wildcard_phase_timeout);
    let mut warnings = Vec::new();
    let wildcard_dns = trusted_dns.unwrap_or(dns);
    let require_wildcard_consensus = trusted_dns.is_some();

    let root_result = before_refresh_deadline(
        Some(wildcard_deadline),
        wildcard_profile_observed(
            database,
            wildcard_dns,
            &domain,
            Duration::from_secs(6 * 3_600),
            true,
            require_wildcard_consensus,
        ),
    )
    .await;
    let mut wildcard_phase_complete =
        refresh_wildcard_observation_is_reliable(root_result.as_ref());
    let root_wildcard = root_result
        .and_then(|observation| observation.signature)
        .unwrap_or_else(indeterminate_wildcard_signature);
    let mut wildcard_by_parent = BTreeMap::from([(domain.clone(), root_wildcard.clone())]);
    let mut parent_counts = HashMap::<String, usize>::new();
    let mut parent_candidates_truncated = false;
    const REFRESH_PAGE_SIZE: usize = 4_096;
    const PARENT_CANDIDATE_CAPACITY: usize = 4_096;
    let mut setup_timed_out = false;
    let mut inventory_cursor = None::<String>;
    loop {
        if wildcard_deadline <= tokio::time::Instant::now() {
            setup_timed_out = true;
            break;
        }
        let page = database.known_subdomains_page(
            &domain,
            true,
            inventory_cursor.as_deref(),
            REFRESH_PAGE_SIZE,
        )?;
        if page.is_empty() {
            break;
        }
        inventory_cursor = page.last().cloned();
        for host in page {
            for parent in Scanner::ancestor_zones(&host, &domain) {
                parent_candidates_truncated |= record_bounded_parent_candidate(
                    &mut parent_counts,
                    parent,
                    PARENT_CANDIDATE_CAPACITY,
                );
            }
        }
    }
    let mut cache_cursor = None::<String>;
    while !setup_timed_out {
        if wildcard_deadline <= tokio::time::Instant::now() {
            setup_timed_out = true;
            break;
        }
        let page = database.positive_cache_only_names_page(
            &domain,
            cache_cursor.as_deref(),
            REFRESH_PAGE_SIZE,
        )?;
        if page.is_empty() {
            break;
        }
        cache_cursor = page.last().cloned();
        for host in page {
            for parent in Scanner::ancestor_zones(&host, &domain) {
                parent_candidates_truncated |= record_bounded_parent_candidate(
                    &mut parent_counts,
                    parent,
                    PARENT_CANDIDATE_CAPACITY,
                );
            }
        }
    }
    if setup_timed_out {
        wildcard_phase_complete = false;
        warnings.push(
            "budget partagé des profils wildcard atteint pendant la préparation paginée des zones parentes"
                .to_owned(),
        );
    }
    let mut parents = parent_counts.into_iter().collect::<Vec<_>>();
    parents.sort_by_key(|(parent, count)| {
        (Reverse(*count), parent.split('.').count(), parent.clone())
    });
    let parent_candidates = parents
        .into_iter()
        .map(|(parent, _)| parent)
        .filter(|parent| parent != &domain)
        .collect::<Vec<_>>();
    parent_candidates_truncated =
        !refresh_parent_selection_is_complete(parent_candidates.len(), parent_candidates_truncated);
    if parent_candidates_truncated {
        wildcard_phase_complete = false;
        warnings.push(
            "plus de 64 zones parentes pertinentes observées; classification wildcard volontairement partielle et purge désactivée"
                .to_owned(),
        );
    }
    let selected_parents = parent_candidates.into_iter().take(64).collect::<Vec<_>>();
    let selected_parent_set = selected_parents.iter().cloned().collect::<BTreeSet<_>>();
    let mut pending_profiles = stream::iter(selected_parents)
        .map(|parent| async move {
            let observation = wildcard_profile_observed(
                database,
                wildcard_dns,
                &parent,
                Duration::from_secs(6 * 3_600),
                true,
                require_wildcard_consensus,
            )
            .await;
            (parent, observation)
        })
        .buffer_unordered(16);
    let mut profiles = BTreeMap::new();
    loop {
        match tokio::time::timeout_at(wildcard_deadline, pending_profiles.next()).await {
            Ok(Some((parent, observation))) => {
                if !refresh_wildcard_observation_is_reliable(Some(&observation)) {
                    wildcard_phase_complete = false;
                }
                let signature = observation
                    .signature
                    .unwrap_or_else(indeterminate_wildcard_signature);
                profiles.insert(parent, signature);
            }
            Ok(None) => break,
            Err(_) => {
                wildcard_phase_complete = false;
                break;
            }
        }
    }
    // timeout_at cancels only the current `next()` future. Drop the buffered
    // stream as well so unfinished wildcard probes release DNS/rate-limit
    // resources before inventory validation starts.
    drop(pending_profiles);
    let completed_parents = profiles.keys().cloned().collect::<BTreeSet<_>>();
    for parent in selected_parent_set.difference(&completed_parents) {
        profiles.insert(parent.clone(), indeterminate_wildcard_signature());
    }
    if !wildcard_phase_complete {
        warnings.push(format!(
            "classification wildcard incomplète ou budget partagé de {} s atteint; profils manquants traités comme indéterminés",
            options.wildcard_phase_timeout.as_secs()
        ));
    }
    wildcard_by_parent.extend(profiles);
    let wildcard_classification_reliable = trusted_dns.is_some()
        && !wildcard_signature_is_indeterminate(&root_wildcard)
        && wildcard_by_parent
            .values()
            .all(|signature| !wildcard_signature_is_indeterminate(signature));
    let mut checked = 0_usize;
    let mut active = 0_usize;
    let mut inactive_count = 0_usize;
    let mut indeterminate_count = 0_usize;
    let mut timed_out = !wildcard_phase_complete
        && global_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now());
    let batch_size = options.batch_size.max(1);
    let mut inventory_cursor = None::<String>;

    loop {
        if global_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
            timed_out = true;
            break;
        }
        let batch = database.known_subdomains_page(
            &domain,
            true,
            inventory_cursor.as_deref(),
            batch_size,
        )?;
        if batch.is_empty() {
            break;
        }
        // Only current network answers can authorize wildcard quarantine.
        // Cache contents are deliberately absent from this decision.
        let mut batch_purge_candidates = BTreeSet::new();
        let mut current_wildcard_matches = Vec::new();
        let mut current_wildcard_ambiguities = Vec::new();
        let mut wildcard_ambiguity_count = 0_usize;
        let network_batch =
            collect_refresh_dns_outcomes(dns, trusted_dns, batch.clone(), global_deadline).await;
        let completed_count = network_batch.completed.len();
        let mut resolved = Vec::new();
        let mut inactive = Vec::new();
        let mut indeterminate = Vec::new();
        for outcome in network_batch.completed {
            match outcome {
                DnsResolutionOutcome::Positive(answer)
                    if Scanner::answer_is_wildcard_ambiguous(
                        &answer,
                        &root_wildcard,
                        &wildcard_by_parent,
                    ) =>
                {
                    if Scanner::answer_matches_confirmed_wildcard(
                        &answer,
                        &root_wildcard,
                        &wildcard_by_parent,
                    ) {
                        batch_purge_candidates.insert(answer.fqdn.clone());
                        current_wildcard_matches.push(answer.clone());
                        wildcard_ambiguity_count = wildcard_ambiguity_count.saturating_add(1);
                    } else if refresh_can_demote_wildcard_ambiguity(
                        wildcard_classification_reliable,
                    ) {
                        current_wildcard_ambiguities.push(answer.clone());
                        wildcard_ambiguity_count = wildcard_ambiguity_count.saturating_add(1);
                    } else {
                        // A failed or incomplete wildcard probe cannot revoke
                        // a previously live cache/inventory record. Journal an
                        // indeterminate validation and preserve the old state;
                        // a later reliable refresh may classify it exactly.
                        indeterminate.push(answer.fqdn.clone());
                    }
                }
                DnsResolutionOutcome::Positive(answer) => {
                    resolved.push(answer);
                }
                DnsResolutionOutcome::Negative { fqdn } => inactive.push(fqdn),
                DnsResolutionOutcome::Indeterminate { fqdn } => {
                    indeterminate.push(fqdn);
                }
            }
        }
        // A deadline-cancelled resolver is explicitly indeterminate. Hosts
        // that never started are untouched and create no cache journal entry.
        let cancelled_count = network_batch.cancelled.len();
        indeterminate.extend(network_batch.cancelled);
        let deadline_exhausted = network_batch.deadline_exhausted;
        enrich_authoritative_answers(wildcard_dns, &mut resolved, global_deadline).await;
        resolved.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        inactive.sort();
        inactive.dedup();
        indeterminate.sort();
        indeterminate.dedup();
        database.record_current_wildcard_matches(scan_id, &current_wildcard_matches)?;
        database.record_current_wildcard_ambiguities(
            scan_id,
            &domain,
            &current_wildcard_ambiguities,
        )?;
        database.update_cache_outcomes(
            Some(scan_id),
            &resolved,
            &inactive,
            &indeterminate,
            negative_ttl,
        )?;
        let findings = resolved
            .iter()
            .map(|answer| Finding {
                fqdn: answer.fqdn.clone(),
                records: answer.records.clone(),
                sources: BTreeSet::from(["refresh".to_owned()]),
                wildcard: false,
                from_cache: false,
                confidence: assess_confidence(
                    &BTreeSet::from(["refresh".to_owned()]),
                    false,
                    crate::model::ObservationState::Live,
                    true,
                ),
                state: crate::model::ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                authoritative_validation: answer.authoritative_validation,
                wildcard_verdict: WildcardVerdict::ExactOwner,
                owner_proofs: answer
                    .authoritative_validation
                    .then_some(OwnerProof::AuthoritativeDistinct)
                    .into_iter()
                    .collect(),
                generation_path: vec!["refresh".to_owned()],
                discovery_score: Some(1.0),
            })
            .collect::<Vec<_>>();
        database.persist_findings(scan_id, &domain, &findings, ttl_cap)?;
        database.stage_refresh_wildcard_candidates(
            scan_id,
            &batch_purge_candidates.into_iter().collect::<Vec<_>>(),
        )?;
        checked = checked.saturating_add(completed_count.saturating_add(cancelled_count));
        active = active.saturating_add(findings.len());
        inactive_count = inactive_count.saturating_add(inactive.len());
        indeterminate_count = indeterminate_count
            .saturating_add(indeterminate.len())
            .saturating_add(wildcard_ambiguity_count);
        run_guard.update(checked, active);
        if let Some(progress) = &progress {
            progress(RefreshProgress {
                checked,
                total,
                active,
                inactive: inactive_count,
                indeterminate: indeterminate_count,
            });
        }
        inventory_cursor = batch.last().cloned();
        if deadline_exhausted
            || global_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now())
        {
            timed_out = true;
            break;
        }
    }

    if !timed_out && wildcard_phase_complete {
        let mut cache_only_cursor = None::<String>;
        loop {
            if global_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
                timed_out = true;
                break;
            }
            let page = database.positive_cache_only_names_page(
                &domain,
                cache_only_cursor.as_deref(),
                REFRESH_PAGE_SIZE.min(batch_size),
            )?;
            if page.is_empty() {
                break;
            }
            let current =
                collect_refresh_dns_outcomes(dns, trusted_dns, page.clone(), global_deadline).await;
            let deadline_exhausted = current.deadline_exhausted;
            let completed_count = current.completed.len();
            let cancelled_count = current.cancelled.len();
            let mut resolved = Vec::new();
            let mut negative = Vec::new();
            let mut indeterminate = current.cancelled;
            let mut current_wildcard_matches = Vec::new();
            let mut current_wildcard_ambiguities = Vec::new();
            let mut wildcard_ambiguity_count = 0_usize;
            let mut staged_page = BTreeSet::new();
            for outcome in current.completed {
                match outcome {
                    DnsResolutionOutcome::Positive(answer)
                        if Scanner::answer_is_wildcard_ambiguous(
                            &answer,
                            &root_wildcard,
                            &wildcard_by_parent,
                        ) =>
                    {
                        if Scanner::answer_matches_confirmed_wildcard(
                            &answer,
                            &root_wildcard,
                            &wildcard_by_parent,
                        ) {
                            staged_page.insert(answer.fqdn.clone());
                            current_wildcard_matches.push(answer.clone());
                            wildcard_ambiguity_count = wildcard_ambiguity_count.saturating_add(1);
                        } else if refresh_can_demote_wildcard_ambiguity(
                            wildcard_classification_reliable,
                        ) {
                            current_wildcard_ambiguities.push(answer.clone());
                            wildcard_ambiguity_count = wildcard_ambiguity_count.saturating_add(1);
                        } else {
                            indeterminate.push(answer.fqdn.clone());
                        }
                    }
                    DnsResolutionOutcome::Positive(answer) => resolved.push(answer),
                    DnsResolutionOutcome::Negative { fqdn } => negative.push(fqdn),
                    DnsResolutionOutcome::Indeterminate { fqdn } => indeterminate.push(fqdn),
                }
            }
            enrich_authoritative_answers(wildcard_dns, &mut resolved, global_deadline).await;
            negative.sort();
            negative.dedup();
            indeterminate.sort();
            indeterminate.dedup();
            database.record_current_wildcard_matches(scan_id, &current_wildcard_matches)?;
            database.record_current_wildcard_ambiguities(
                scan_id,
                &domain,
                &current_wildcard_ambiguities,
            )?;
            database.update_cache_outcomes(
                Some(scan_id),
                &resolved,
                &negative,
                &indeterminate,
                negative_ttl,
            )?;
            let findings = resolved
                .iter()
                .map(|answer| Finding {
                    fqdn: answer.fqdn.clone(),
                    records: answer.records.clone(),
                    sources: BTreeSet::from(["refresh".to_owned()]),
                    wildcard: false,
                    from_cache: false,
                    confidence: assess_confidence(
                        &BTreeSet::from(["refresh".to_owned()]),
                        false,
                        crate::model::ObservationState::Live,
                        true,
                    ),
                    state: crate::model::ObservationState::Live,
                    last_verified_at: answer.last_verified_at,
                    evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                    authoritative_validation: answer.authoritative_validation,
                    wildcard_verdict: WildcardVerdict::ExactOwner,
                    owner_proofs: answer
                        .authoritative_validation
                        .then_some(OwnerProof::AuthoritativeDistinct)
                        .into_iter()
                        .collect(),
                    generation_path: vec!["refresh".to_owned()],
                    discovery_score: Some(1.0),
                })
                .collect::<Vec<_>>();
            database.persist_findings(scan_id, &domain, &findings, ttl_cap)?;
            database.stage_refresh_wildcard_candidates(
                scan_id,
                &staged_page.into_iter().collect::<Vec<_>>(),
            )?;
            checked = checked.saturating_add(completed_count.saturating_add(cancelled_count));
            active = active.saturating_add(findings.len());
            inactive_count = inactive_count.saturating_add(negative.len());
            indeterminate_count = indeterminate_count
                .saturating_add(indeterminate.len())
                .saturating_add(wildcard_ambiguity_count);
            run_guard.update(checked, active);
            if let Some(progress) = &progress {
                progress(RefreshProgress {
                    checked,
                    total,
                    active,
                    inactive: inactive_count,
                    indeterminate: indeterminate_count,
                });
            }
            cache_only_cursor = page.last().cloned();
            if deadline_exhausted
                || global_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now())
            {
                timed_out = true;
                break;
            }
        }
    }
    let mut status = if timed_out || checked < total || !wildcard_phase_complete {
        "partial".to_owned()
    } else {
        "completed".to_owned()
    };
    if timed_out || checked < total {
        warnings.push(format!(
            "budget global atteint après {checked}/{total} nom(s); état des noms non traités préservé"
        ));
    }
    if indeterminate_count > 0 {
        warnings.push(format!(
            "{indeterminate_count} nom(s) indéterminé(s); état précédent préservé"
        ));
    }
    let staged_wildcards = database.refresh_wildcard_candidate_count(scan_id)?;
    let (purged_wildcards, unverified_count) = if refresh_allows_wildcard_purge(
        &status,
        wildcard_classification_reliable,
    ) {
        match apply_completed_refresh_wildcard_cleanup(
            database,
            scan_id,
            &domain,
            global_deadline,
            batch_size,
        )
        .await?
        {
            Some(counts) => counts,
            None => {
                status = "partial".to_owned();
                warnings.push(
                    "budget global atteint pendant la purge wildcard atomique; aucune suppression appliquée"
                        .to_owned(),
                );
                (0, 0)
            }
        }
    } else {
        if staged_wildcards > 0 {
            warnings.push(
                "purge wildcard ignorée car l'actualisation ou la classification wildcard est incomplète"
                    .to_owned(),
            );
        }
        database.discard_refresh_wildcard_candidates(scan_id)?;
        (0, 0)
    };
    database.store_resolver_metrics(&dns.take_metrics())?;
    if let Some(trusted_dns) = trusted_dns {
        database.store_resolver_metrics(&trusted_dns.take_metrics())?;
    }
    let duration_ms = started.elapsed().as_millis();
    database.finalize_non_resumable_scan(
        scan_id,
        &status,
        checked,
        active,
        0,
        duration_ms,
        &warnings,
    )?;
    run_guard.disarm();
    Ok(RefreshResult {
        scan_id,
        domain,
        status,
        total,
        checked,
        active,
        inactive: inactive_count,
        unverified: unverified_count,
        indeterminate: indeterminate_count,
        purged_wildcards,
        duration_ms,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        BatchDnsMode, RefreshCleanupCancellation, RefreshOptions, RefreshRunGuard, ScanOptions,
        ScanRunGuard, Scanner, SignalRefreshCleanupCompletion, active_candidate_budget_exhausted,
        active_candidate_work_allowed, active_resume_required,
        apply_completed_refresh_wildcard_cleanup, assess_dnssec_suspects_bounded,
        automatic_bulk_source_limit, before_refresh_deadline, cache_requires_revalidation,
        candidate_refill_capacity, candidate_uses_active_budget,
        candidate_uses_discovery_fast_path, cap_exclusive_bulk_source_names, capped_phase_deadline,
        collect_dns_outcomes_until, consume_phase_budget, dnssec_assessment_proves_nonexistence,
        external_deferral_seconds, external_pause_status, external_retry_after_seconds,
        finish_pending_ct_task_after_grace_with_hook, high_value_window_needs_materialization,
        high_value_window_persist_limit, indeterminate_wildcard_signature,
        is_missing_api_key_error, is_preflight_auth_error, late_ct_seed_reserve,
        materialize_ct_fallback_bounded, merge_ct_fallback_names, merge_passive_names_bounded,
        merge_resolver_metrics, metadata_phase_budget, passive_connector_working_set_limit,
        persist_routed_dns_outcomes, phase_deadline, record_bounded_parent_candidate,
        refill_passive_union_from_cache, refresh_allows_wildcard_purge,
        refresh_can_demote_wildcard_ambiguity, refresh_deadline,
        refresh_parent_selection_is_complete, refresh_wildcard_observation_is_reliable,
        refresh_wildcard_profile_is_reliable, route_dns_outcomes,
        select_bounded_mutation_observations, should_expand_adaptive_wave,
        should_retry_source_after_key_added, source_bootstrap_score, source_error_is_deferred,
        source_requires_api_key, unprofiled_deepest_parents, was_recently_verified,
        wildcard_cache_algorithm_is_current, wildcard_profile_after_probe,
        wildcard_profile_observed, wilson_upper_bound,
    };
    use crate::candidate::CandidateProposal;
    use crate::db::Database;
    use crate::dns::{DnsEngine, DnsResolutionOutcome, WildcardProbeOutcome};
    use crate::dnssec_proof::{DnssecOwnerState, DnssecProofAssessment, DnssecProofKind};
    use crate::model::{
        CtMonitorResult, DnsRecord, Finding, ObservationState, ResolvedHost, ResolverMetric,
    };
    use hickory_net::proto::op::{Message, MessageType, ResponseCode};
    use hickory_net::proto::rr::rdata::A;
    use hickory_net::proto::rr::{RData, Record, RecordType};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    fn scanner_test_options(include_wildcard: bool) -> ScanOptions {
        ScanOptions {
            wordlist: None,
            mutation_rules: Vec::new(),
            max_words: 1,
            active_phase_timeout: Duration::from_secs(2),
            passive: false,
            passive_sources: Vec::new(),
            api_keys: crate::passive::ApiKeyStore::default(),
            automatic_source_selection: false,
            passive_refresh: Duration::from_secs(60),
            passive_phase_timeout: Duration::from_secs(1),
            passive_zone_concurrency: 1,
            passive_concurrency: 1,
            max_passive: 1,
            passive_only: false,
            axfr: false,
            axfr_timeout: Duration::from_millis(100),
            refresh_cache: false,
            verification_max_age: Duration::from_secs(86_400),
            only_live: false,
            profile: "balanced".to_owned(),
            checkpoint_every: Duration::from_secs(30),
            resume: None,
            ttl_cap: 86_400,
            negative_ttl: 300,
            include_wildcard,
            wildcard_refresh: Duration::from_secs(300),
            recursive_depth: 0,
            recursive_words: 0,
            recursive_hosts: 0,
            adaptive: false,
            pipeline: false,
            pipeline_rounds: 0,
            pipeline_budget: 0,
            tls_certificates: false,
            tls_port: 443,
            tls_timeout: Duration::from_millis(100),
            tls_refresh: Duration::from_secs(300),
            tls_max_hosts: 0,
            tls_concurrency: 1,
            dns_graph: false,
            graph_max_hosts: 0,
            service_discovery: false,
            ptr_pivot: false,
            ptr_max_ips: 0,
            dnssec_nsec: false,
            nsec_timeout: Duration::from_millis(100),
            nsec_refresh: Duration::from_secs(300),
            nsec_max_names: 0,
            nsec_phase_timeout: Duration::from_millis(100),
            ct_monitor: false,
            ct_timeout: Duration::from_millis(100),
            ct_phase_timeout: Duration::from_millis(100),
            ct_max_logs: 0,
            ct_entries_per_log: 0,
            ct_initial_backfill: 0,
            metadata_discovery: false,
            metadata_all_hosts: false,
            metadata_max_requests: 0,
            web_discovery: false,
            web_max_hosts: 0,
            web_timeout: Duration::from_millis(100),
            web_phase_timeout: Duration::from_millis(100),
            web_refresh: Duration::from_secs(300),
            web_concurrency: 1,
            web_max_bytes: 0,
            web_assets_per_host: 0,
        }
    }

    async fn wildcard_test_resolver() -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let mut packet = [0_u8; 2_048];
                let Ok((length, peer)) = socket.recv_from(&mut packet).await else {
                    break;
                };
                request_count.fetch_add(1, Ordering::SeqCst);
                let mut response = Message::from_vec(&packet[..length]).unwrap();
                let query = response.queries[0].clone();
                response.metadata.message_type = MessageType::Response;
                response.metadata.response_code = ResponseCode::NoError;
                response.metadata.recursion_available = true;
                if query.query_type() == RecordType::A {
                    response.answers.push(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A("192.0.2.44".parse().unwrap())),
                    ));
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        (address, requests, task)
    }

    fn proven_dnssec_denial(kind: DnssecProofKind) -> DnssecProofAssessment {
        DnssecProofAssessment {
            state: DnssecOwnerState::DoesNotExist,
            proofs: BTreeSet::from([kind]),
            ..DnssecProofAssessment::default()
        }
    }

    #[tokio::test]
    async fn confirmed_wildcard_revalidates_fresh_cache_and_never_restores_live_state() {
        for include_wildcard in [false, true] {
            let (primary_address, primary_requests, primary_task) = wildcard_test_resolver().await;
            let (trusted_one, _, trusted_one_task) = wildcard_test_resolver().await;
            let (trusted_two, _, trusted_two_task) = wildcard_test_resolver().await;
            let primary = DnsEngine::new_with_socket_addresses(
                8,
                Duration::from_millis(250),
                &[primary_address],
                0,
            )
            .unwrap();
            let trusted = DnsEngine::new_with_socket_addresses(
                8,
                Duration::from_millis(250),
                &[trusted_one, trusted_two],
                0,
            )
            .unwrap();
            let database = Database::in_memory().unwrap();
            let domain = "example.com";
            let fqdn = "cached-wildcard.example.com".to_owned();
            let cached_answer = ResolvedHost {
                fqdn: fqdn.clone(),
                records: vec![DnsRecord {
                    record_type: "A".to_owned(),
                    value: "192.0.2.44".to_owned(),
                    ttl: 60,
                }],
                from_cache: false,
                last_verified_at: Some(crate::util::now_epoch()),
                authoritative_validation: false,
                resolver_count: 2,
            };
            let seed_scan = database
                .create_scan(domain, &json!({"seed": true}))
                .unwrap();
            database
                .persist_findings(
                    seed_scan,
                    domain,
                    &[Finding {
                        fqdn: fqdn.clone(),
                        records: cached_answer.records.clone(),
                        sources: BTreeSet::from(["dns:seed".to_owned()]),
                        state: ObservationState::Live,
                        last_verified_at: cached_answer.last_verified_at,
                        ..Finding::default()
                    }],
                    86_400,
                )
                .unwrap();
            database
                .update_cache_outcomes(
                    Some(seed_scan),
                    std::slice::from_ref(&cached_answer),
                    &[],
                    &[],
                    300,
                )
                .unwrap();
            let scan_id = database
                .create_scan(domain, &json!({"include_wildcard": include_wildcard}))
                .unwrap();
            let scanner = Scanner::new(
                database.clone(),
                primary,
                scanner_test_options(include_wildcard),
            )
            .with_trusted_dns(trusted);
            let sources =
                BTreeMap::from([(fqdn.clone(), BTreeSet::from(["dns-wave-1".to_owned()]))]);
            let root_wildcard = BTreeSet::from(["A:192.0.2.44".to_owned()]);

            let result = scanner
                .resolve_batch_with_deadline(
                    scan_id,
                    domain,
                    std::slice::from_ref(&fqdn),
                    "wildcard regression",
                    &Instant::now(),
                    &sources,
                    &root_wildcard,
                    &HashMap::new(),
                    &BTreeMap::new(),
                    Some(tokio::time::Instant::now() + Duration::from_secs(2)),
                    BatchDnsMode::Conservative,
                )
                .await
                .unwrap();

            assert_eq!(result.cache_hits, 0, "include_wildcard={include_wildcard}");
            assert!(
                primary_requests.load(Ordering::SeqCst) > 0,
                "the fresh wildcard-shaped cache entry bypassed network revalidation"
            );
            assert_eq!(
                result.answers.iter().any(|answer| answer.fqdn == fqdn),
                include_wildcard,
                "include_wildcard must affect output only"
            );
            assert!(
                !database
                    .fresh_cache(std::slice::from_ref(&fqdn))
                    .unwrap()
                    .contains_key(&fqdn),
                "a current wildcard match remained reusable in dns_cache"
            );
            assert!(database.inventory(Some(domain), false).unwrap().is_empty());
            assert!(
                database
                    .live_scan_finding_names(scan_id)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                database.explain(&fqdn).unwrap()["quarantine"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );

            primary_task.abort();
            trusted_one_task.abort();
            trusted_two_task.abort();
        }
    }

    #[tokio::test]
    async fn indeterminate_wildcard_profile_preserves_fresh_cache_and_live_inventory() {
        let (address, requests, server_task) = wildcard_test_resolver().await;
        let primary =
            DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[address], 0)
                .unwrap();
        let trusted =
            DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[address], 0)
                .unwrap();
        let database = Database::in_memory().unwrap();
        let domain = "example.com";
        let fqdn = "cached-indeterminate.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(crate::util::now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let seed_scan = database
            .create_scan(domain, &json!({"seed": true}))
            .unwrap();
        database
            .persist_findings(
                seed_scan,
                domain,
                &[Finding {
                    fqdn: fqdn.clone(),
                    records: answer.records.clone(),
                    sources: BTreeSet::from(["dns:seed".to_owned()]),
                    state: ObservationState::Live,
                    last_verified_at: answer.last_verified_at,
                    ..Finding::default()
                }],
                86_400,
            )
            .unwrap();
        database
            .update_cache_outcomes(
                Some(seed_scan),
                std::slice::from_ref(&answer),
                &[],
                &[],
                300,
            )
            .unwrap();
        let scan_id = database
            .create_scan(domain, &json!({"indeterminate": true}))
            .unwrap();
        let scanner = Scanner::new(database.clone(), primary, scanner_test_options(false))
            .with_trusted_dns(trusted);
        let sources = BTreeMap::from([(fqdn.clone(), BTreeSet::from(["dns:cache".to_owned()]))]);
        let scan_started = Instant::now();
        let root_wildcard = indeterminate_wildcard_signature();
        let result = scanner
            .resolve_batch_with_deadline(
                scan_id,
                domain,
                std::slice::from_ref(&fqdn),
                "indeterminate wildcard regression",
                &scan_started,
                &sources,
                &root_wildcard,
                &HashMap::new(),
                &BTreeMap::new(),
                Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                BatchDnsMode::Conservative,
            )
            .await
            .unwrap();

        assert_eq!(result.cache_hits, 1);
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        // Without --include-wildcard an indeterminate cached name may stay
        // hidden from this scan, but its durable state must remain untouched.
        assert!(result.answers.is_empty());
        assert!(matches!(
            database
                .fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .get(&fqdn),
            Some(crate::db::CachedAnswer::Positive(_))
        ));
        let inventory = database.inventory(Some(domain), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state, ObservationState::Live);
        assert!(
            database.explain(&fqdn).unwrap()["quarantine"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        let insufficient = "single-resolver-wildcard.example.com".to_owned();
        let insufficient_answer = ResolvedHost {
            fqdn: insufficient.clone(),
            records: [
                answer.records.clone(),
                vec![DnsRecord {
                    record_type: "CNAME".to_owned(),
                    value: "legacy.example.net".to_owned(),
                    ttl: 60,
                }],
            ]
            .concat(),
            ..answer.clone()
        };
        database
            .persist_findings(
                seed_scan,
                domain,
                &[Finding {
                    fqdn: insufficient.clone(),
                    records: insufficient_answer.records.clone(),
                    sources: BTreeSet::from(["dns:seed".to_owned()]),
                    state: ObservationState::Live,
                    last_verified_at: insufficient_answer.last_verified_at,
                    ..Finding::default()
                }],
                86_400,
            )
            .unwrap();
        database
            .update_cache_outcomes(
                Some(seed_scan),
                std::slice::from_ref(&insufficient_answer),
                &[],
                &[],
                300,
            )
            .unwrap();
        let insufficient_scan = database
            .create_scan(domain, &json!({"trusted": false}))
            .unwrap();
        let primary =
            DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[address], 0)
                .unwrap();
        let scanner = Scanner::new(database.clone(), primary, scanner_test_options(true));
        let sources = BTreeMap::from([(
            insufficient.clone(),
            BTreeSet::from(["dns:cache".to_owned()]),
        )]);
        let before_requests = requests.load(Ordering::SeqCst);
        let scan_started = Instant::now();
        let result = scanner
            .resolve_batch_with_deadline(
                insufficient_scan,
                domain,
                std::slice::from_ref(&insufficient),
                "single resolver wildcard regression",
                &scan_started,
                &sources,
                &BTreeSet::from(["A:192.0.2.44".to_owned()]),
                &HashMap::new(),
                &BTreeMap::new(),
                Some(tokio::time::Instant::now() + Duration::from_secs(1)),
                BatchDnsMode::Conservative,
            )
            .await
            .unwrap();
        assert_eq!(result.cache_hits, 0);
        assert!(requests.load(Ordering::SeqCst) > before_requests);
        assert!(result.answers.is_empty());
        database
            .persist_scan_snapshot(
                insufficient_scan,
                &[Finding {
                    fqdn: insufficient.clone(),
                    records: insufficient_answer.records.clone(),
                    sources: BTreeSet::from(["dns:single-resolver-audit".to_owned()]),
                    wildcard: true,
                    state: ObservationState::Unverified,
                    ..Finding::default()
                }],
            )
            .unwrap();
        assert!(matches!(
            database
                .fresh_cache(std::slice::from_ref(&insufficient))
                .unwrap()
                .get(&insufficient),
            Some(crate::db::CachedAnswer::Positive(_))
        ));
        assert!(
            database
                .inventory(Some(domain), false)
                .unwrap()
                .iter()
                .any(|entry| entry.fqdn == insufficient && entry.state == ObservationState::Live)
        );
        assert!(
            database.explain(&insufficient).unwrap()["quarantine"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        server_task.abort();
    }

    #[test]
    fn resolver_cost_metrics_include_primary_and_trusted_engines() {
        let metrics = merge_resolver_metrics(
            vec![ResolverMetric {
                resolver: "1.1.1.1".to_owned(),
                requests: 2,
                successes: 2,
                failures: 0,
                average_ms: 10,
                consecutive_failures: 0,
            }],
            vec![ResolverMetric {
                resolver: "1.1.1.1".to_owned(),
                requests: 1,
                successes: 0,
                failures: 1,
                average_ms: 40,
                consecutive_failures: 1,
            }],
        );
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].requests, 3);
        assert_eq!(metrics[0].successes, 2);
        assert_eq!(metrics[0].failures, 1);
        assert_eq!(metrics[0].average_ms, 20);
        assert_eq!(metrics[0].consecutive_failures, 1);
    }

    #[test]
    fn metadata_uses_the_remaining_web_budget_with_a_hard_cap() {
        assert_eq!(metadata_phase_budget(None), Duration::from_secs(30));
        assert_eq!(
            metadata_phase_budget(Some(Duration::from_secs(90))),
            Duration::from_secs(30)
        );
        assert_eq!(
            metadata_phase_budget(Some(Duration::from_secs(7))),
            Duration::from_secs(7)
        );
        assert!(metadata_phase_budget(Some(Duration::ZERO)).is_zero());
    }

    #[test]
    fn dnssec_quarantine_requires_a_concrete_local_denial_proof() {
        let state_only = DnssecProofAssessment {
            state: DnssecOwnerState::DoesNotExist,
            ..DnssecProofAssessment::default()
        };
        assert!(!dnssec_assessment_proves_nonexistence(&state_only));
        assert!(dnssec_assessment_proves_nonexistence(
            &proven_dnssec_denial(DnssecProofKind::NxnameNsec)
        ));
        assert!(dnssec_assessment_proves_nonexistence(
            &proven_dnssec_denial(DnssecProofKind::NxnameNsec3)
        ));
        assert!(dnssec_assessment_proves_nonexistence(
            &proven_dnssec_denial(DnssecProofKind::NsecRangeDenial)
        ));
        assert!(!dnssec_assessment_proves_nonexistence(
            &proven_dnssec_denial(DnssecProofKind::Nsec3RangeDenial)
        ));
        let ent = DnssecProofAssessment {
            state: DnssecOwnerState::EmptyNonTerminal,
            proofs: BTreeSet::from([DnssecProofKind::EmptyNonTerminal]),
            ..DnssecProofAssessment::default()
        };
        assert!(!dnssec_assessment_proves_nonexistence(&ent));
    }

    #[tokio::test]
    async fn dnssec_suspect_assessment_is_parallel_scoped_and_capped_at_four() {
        let calls = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let maximum_in_flight = Arc::new(AtomicUsize::new(0));
        let mut suspects = (0..8)
            .rev()
            .map(|index| format!("host-{index:02}.example.com"))
            .collect::<Vec<_>>();
        suspects.extend([
            "HOST-00.EXAMPLE.COM.".to_owned(),
            "outside.test".to_owned(),
            "example.com".to_owned(),
        ]);

        let nonexistent = assess_dnssec_suspects_bounded(
            "example.com",
            suspects,
            tokio::time::Instant::now() + Duration::from_secs(1),
            {
                let calls = Arc::clone(&calls);
                let in_flight = Arc::clone(&in_flight);
                let maximum_in_flight = Arc::clone(&maximum_in_flight);
                move |fqdn| {
                    let calls = Arc::clone(&calls);
                    let in_flight = Arc::clone(&in_flight);
                    let maximum_in_flight = Arc::clone(&maximum_in_flight);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        maximum_in_flight.fetch_max(current, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        if fqdn.starts_with("host-00") {
                            proven_dnssec_denial(DnssecProofKind::NxnameNsec)
                        } else if fqdn.starts_with("host-01") {
                            // A state without locally validated proof material
                            // must not authorize quarantine (including AD-only).
                            DnssecProofAssessment {
                                state: DnssecOwnerState::DoesNotExist,
                                ..DnssecProofAssessment::default()
                            }
                        } else if fqdn.starts_with("host-03") {
                            proven_dnssec_denial(DnssecProofKind::NsecRangeDenial)
                        } else {
                            DnssecProofAssessment::default()
                        }
                    }
                }
            },
        )
        .await;

        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert!(maximum_in_flight.load(Ordering::SeqCst) > 1);
        assert_eq!(
            nonexistent,
            BTreeSet::from([
                "host-00.example.com".to_owned(),
                "host-03.example.com".to_owned(),
            ])
        );
    }

    #[tokio::test]
    async fn dnssec_suspect_assessment_uses_one_absolute_deadline() {
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let nonexistent = assess_dnssec_suspects_bounded(
            "example.com",
            (0..8).map(|index| format!("slow-{index}.example.com")),
            tokio::time::Instant::now() + Duration::from_millis(35),
            {
                let calls = Arc::clone(&calls);
                move |_fqdn| {
                    let calls = Arc::clone(&calls);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        proven_dnssec_denial(DnssecProofKind::NxnameNsec3)
                    }
                }
            },
        )
        .await;

        assert!(nonexistent.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "les évaluations ont reçu des deadlines individuelles"
        );
    }

    #[test]
    fn dnssec_quarantine_purges_only_proven_name_and_preserves_audit() {
        let database = Database::in_memory().unwrap();
        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        let make_finding = |fqdn: &str| Finding {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            sources: BTreeSet::from(["dns-wave-1".to_owned()]),
            state: ObservationState::Live,
            last_verified_at: Some(1),
            ..Finding::default()
        };
        let proven = "proven.example.com";
        let retained = "retained.example.com";
        database
            .persist_findings(
                scan_id,
                "example.com",
                &[make_finding(proven), make_finding(retained)],
                86_400,
            )
            .unwrap();
        let cached = [proven, retained]
            .into_iter()
            .map(|fqdn| ResolvedHost {
                fqdn: fqdn.to_owned(),
                records: make_finding(fqdn).records,
                from_cache: false,
                last_verified_at: Some(1),
                authoritative_validation: false,
                resolver_count: 2,
            })
            .collect::<Vec<_>>();
        database
            .update_cache_outcomes(Some(scan_id), &cached, &[], &[], 300)
            .unwrap();

        assert_eq!(
            database
                .quarantine_dnssec_nonexistent(scan_id, "example.com", &[proven.to_owned()])
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .inventory(Some("example.com"), false)
                .unwrap()
                .into_iter()
                .map(|entry| entry.fqdn)
                .collect::<Vec<_>>(),
            vec![retained]
        );
        let cache = database
            .fresh_cache(&[proven.to_owned(), retained.to_owned()])
            .unwrap();
        assert!(!cache.contains_key(proven));
        assert!(cache.contains_key(retained));
        let explanation = database.explain(proven).unwrap();
        assert_eq!(
            explanation["quarantine"][0]["reason"],
            "dnssec_validated_nonexistence"
        );
        assert!(
            explanation["dns_verifications"]
                .as_array()
                .unwrap()
                .iter()
                .any(|verification| {
                    verification["outcome"] == "negative"
                        && verification["details"]["reason"] == "dnssec_validated_nonexistence"
                })
        );
        assert_eq!(explanation["scan_history"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn ct_error_fallback_merges_indexed_and_cached_names_in_scope() {
        assert_eq!(
            merge_ct_fallback_names(
                "example.com",
                vec![
                    "api.example.com".to_owned(),
                    "shared.example.com".to_owned(),
                    "outside.test".to_owned(),
                ],
                vec![
                    "cached.example.com".to_owned(),
                    "SHARED.EXAMPLE.COM.".to_owned(),
                ],
            ),
            vec![
                "api.example.com".to_owned(),
                "cached.example.com".to_owned(),
                "shared.example.com".to_owned(),
            ]
        );
    }

    #[test]
    fn ct_error_fallback_is_read_only_and_respects_max_passive() {
        let db = Database::in_memory().unwrap();
        let names = (0..500)
            .map(|index| format!("host-{index:04}.example.com"))
            .collect::<BTreeSet<_>>();
        db.store_ct_global_batch("https://ct.example/log/", 500, &names)
            .unwrap();

        let recovered = materialize_ct_fallback_bounded(&db, "example.com", 23).unwrap();

        assert_eq!(recovered.len(), 23);
        assert_eq!(
            db.ct_names_for_domain("example.com", 1_000).unwrap().len(),
            500
        );
        assert!(
            db.observation_names("example.com", "passive:ct-direct")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn late_ct_reserve_is_bounded_and_old_wildcard_caches_are_rejected() {
        assert_eq!(late_ct_seed_reserve(10_000, true), 2_000);
        assert_eq!(late_ct_seed_reserve(100, true), 20);
        assert_eq!(late_ct_seed_reserve(100, false), 0);
        assert!(!wildcard_cache_algorithm_is_current(3, 5));
        assert!(wildcard_cache_algorithm_is_current(5, 5));
    }

    #[tokio::test]
    async fn final_ct_drain_preserves_a_result_completed_in_the_abort_race() {
        let mut tasks = tokio::task::JoinSet::new();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            release_rx.await.unwrap();
            let result = CtMonitorResult {
                entries_processed: 7,
                names: BTreeSet::from(["late.example.com".to_owned()]),
                ..CtMonitorResult::default()
            };
            let _ = completed_tx.send(());
            Ok((result, vec!["late warning".to_owned()]))
        });

        let (joined, aborted_without_result) =
            finish_pending_ct_task_after_grace_with_hook(&mut tasks, Duration::ZERO, async move {
                release_tx.send(()).unwrap();
                completed_rx.await.unwrap();
            })
            .await;

        assert!(!aborted_without_result);
        let (result, warnings) = joined.unwrap().unwrap().unwrap();
        assert_eq!(result.entries_processed, 7);
        assert!(result.names.contains("late.example.com"));
        assert_eq!(warnings, vec!["late warning"]);
    }

    #[test]
    fn automatic_anubis_guard_caps_only_source_exclusive_names() {
        assert_eq!(automatic_bulk_source_limit(25_000), 2_500);
        let mut sources = BTreeMap::from([
            (
                "a.example.com".to_owned(),
                BTreeSet::from(["passive:anubisdb".to_owned()]),
            ),
            (
                "b.example.com".to_owned(),
                BTreeSet::from(["passive:anubisdb:partial".to_owned()]),
            ),
            (
                "trusted.example.com".to_owned(),
                BTreeSet::from([
                    "passive:anubisdb".to_owned(),
                    "passive:certspotter".to_owned(),
                ]),
            ),
        ]);
        let (before, kept) =
            cap_exclusive_bulk_source_names("example.com", &mut sources, "passive:anubisdb", 1);
        assert_eq!((before, kept), (2, 1));
        assert_eq!(sources.len(), 2);
        assert!(sources.contains_key("trusted.example.com"));
    }

    #[test]
    fn passive_union_cap_keeps_existing_multi_source_provenance() {
        assert_eq!(passive_connector_working_set_limit(25_000), 3_125);
        let mut sources = BTreeMap::new();
        assert_eq!(
            merge_passive_names_bounded(
                &mut sources,
                [
                    "one.example.com".to_owned(),
                    "shared.example.com".to_owned()
                ],
                "passive:first".to_owned(),
                2,
            ),
            0
        );
        assert_eq!(
            merge_passive_names_bounded(
                &mut sources,
                [
                    "shared.example.com".to_owned(),
                    "two.example.com".to_owned()
                ],
                "passive:second".to_owned(),
                2,
            ),
            1
        );
        assert_eq!(sources.len(), 2);
        assert_eq!(
            sources.get("shared.example.com"),
            Some(&BTreeSet::from([
                "passive:first".to_owned(),
                "passive:second".to_owned(),
            ]))
        );
        assert!(!sources.contains_key("two.example.com"));
    }

    #[test]
    fn durable_passive_refill_recovers_coverage_beyond_the_connector_cap() {
        let db = Database::in_memory().unwrap();
        let all_names = (0..20)
            .map(|index| format!("host-{index:02}.example.com"))
            .collect::<BTreeSet<_>>();
        db.store_passive_observation_page("example.com", "fixture", &all_names)
            .unwrap();
        let mut sources = all_names
            .iter()
            .take(3)
            .cloned()
            .map(|name| (name, BTreeSet::from(["passive:fixture".to_owned()])))
            .collect::<BTreeMap<_, _>>();

        let added = refill_passive_union_from_cache(
            &db,
            "example.com",
            &["fixture".to_owned()],
            &mut sources,
            10,
        )
        .unwrap();

        assert_eq!(added, 7);
        assert_eq!(sources.len(), 10);
        assert_eq!(
            sources.get("host-00.example.com"),
            Some(&BTreeSet::from(["passive:fixture".to_owned()]))
        );
        assert_eq!(
            db.passive_cache("example.com", "fixture")
                .unwrap()
                .unwrap()
                .names
                .len(),
            20
        );
    }

    #[test]
    fn omitted_child_wildcard_parents_are_marked_indeterminate() {
        let parent_by_host = HashMap::from([
            (
                "a.prod.example.com".to_owned(),
                "prod.example.com".to_owned(),
            ),
            ("b.dev.example.com".to_owned(), "dev.example.com".to_owned()),
        ]);
        let profiled = BTreeMap::new();
        let selected = BTreeSet::from(["prod.example.com".to_owned()]);
        assert_eq!(
            unprofiled_deepest_parents(&parent_by_host, &profiled, &selected),
            BTreeSet::from(["dev.example.com".to_owned()])
        );
    }

    #[test]
    fn verification_max_age_requeues_stale_permanent_cache_entries() {
        let mut answer = ResolvedHost {
            fqdn: "api.example.com".to_owned(),
            records: Vec::new(),
            from_cache: true,
            last_verified_at: Some(1_000),
            authoritative_validation: false,
            resolver_count: 1,
        };
        assert!(!cache_requires_revalidation(
            &answer,
            Duration::from_secs(101),
            1_100,
            false,
        ));
        assert!(cache_requires_revalidation(
            &answer,
            Duration::from_secs(99),
            1_100,
            false,
        ));
        assert!(cache_requires_revalidation(
            &answer,
            Duration::ZERO,
            1_000,
            false,
        ));
        answer.last_verified_at = None;
        assert!(cache_requires_revalidation(
            &answer,
            Duration::from_secs(3_600),
            1_100,
            false,
        ));
        answer.last_verified_at = Some(1_100);
        assert!(cache_requires_revalidation(
            &answer,
            Duration::from_secs(3_600),
            1_100,
            true,
        ));
        answer.resolver_count = 2;
        assert!(!cache_requires_revalidation(
            &answer,
            Duration::from_secs(3_600),
            1_100,
            true,
        ));
        assert!(was_recently_verified(
            Some(i64::MIN),
            Duration::MAX,
            i64::MAX,
        ));
        assert!(!was_recently_verified(Some(1_100), Duration::ZERO, 1_100,));
    }

    #[test]
    fn lazy_refills_are_batch_bounded_and_honor_the_total_word_budget() {
        assert_eq!(candidate_refill_capacity(0, 0, 500, 1_000_000), 500);
        assert_eq!(candidate_refill_capacity(0, 500, 1_500, 1_000), 500);
        assert_eq!(candidate_refill_capacity(1_200, 1_200, 1_500, 10_000), 300);
        assert_eq!(candidate_refill_capacity(500, 500, 500, 10_000), 0);
        assert_eq!(candidate_refill_capacity(0, 10_000, 5_000, 10_000), 0);
    }

    #[test]
    fn high_value_window_is_materialized_once_without_using_the_dns_queue_gap_as_its_cap() {
        // A 128-row DNS queue gap still persists the complete bounded 5,000
        // candidate window once; subsequent waves observe the durable feed
        // marker and skip grammar/mutation recomputation.
        assert!(high_value_window_needs_materialization(128, false));
        assert_eq!(high_value_window_persist_limit(0, 0, 20_000, 5_000), 5_000);
        assert!(!high_value_window_needs_materialization(128, true));

        // If max_words has less room than the window, filling that remaining
        // room is exhaustive for this scan and never crosses the hard budget.
        assert_eq!(
            high_value_window_persist_limit(9_700, 100, 10_000, 5_000),
            200
        );
        assert_eq!(
            high_value_window_persist_limit(usize::MAX, usize::MAX, 10, 5_000),
            0
        );
    }

    #[test]
    fn mutation_observation_selection_bounds_huge_iterators_and_is_deterministic() {
        struct HugeObservationIterator<'a> {
            names: &'a [String],
            offset: usize,
            remaining: usize,
            polls: Arc<AtomicUsize>,
        }

        impl<'a> Iterator for HugeObservationIterator<'a> {
            type Item = (&'a str, i64);

            fn next(&mut self) -> Option<Self::Item> {
                if self.remaining == 0 {
                    return None;
                }
                self.remaining -= 1;
                let index = self.offset % self.names.len();
                self.offset = self.offset.saturating_add(1);
                self.polls.fetch_add(1, Ordering::SeqCst);
                Some((self.names[index].as_str(), (index % 5) as i64))
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (self.remaining, Some(self.remaining))
            }
        }

        let names = [
            "api.example.com",
            "api.dev.example.com",
            "worker-01.example.com",
            "worker-02.prod.example.com",
            "mail.example.com",
            "admin.eu.example.com",
            "cdn-legacy.example.com",
            "vpn2.apac.example.com",
            "status.example.com",
            "auth.staging.example.com",
            "db-03.internal.example.com",
            "shop.example.com",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let scan_cap = 32;
        let keep_cap = 8;
        let first_polls = Arc::new(AtomicUsize::new(0));
        let first = select_bounded_mutation_observations(
            "example.com",
            HugeObservationIterator {
                names: &names,
                offset: 0,
                remaining: 1_000_000,
                polls: Arc::clone(&first_polls),
            },
            scan_cap,
            keep_cap,
        );
        let second_polls = Arc::new(AtomicUsize::new(0));
        let second = select_bounded_mutation_observations(
            "example.com",
            HugeObservationIterator {
                names: &names,
                offset: 0,
                remaining: 1_000_000,
                polls: Arc::clone(&second_polls),
            },
            scan_cap,
            keep_cap,
        );

        assert_eq!(first_polls.load(Ordering::SeqCst), scan_cap);
        assert_eq!(second_polls.load(Ordering::SeqCst), scan_cap);
        assert_eq!(first, second);
        assert_eq!(first.len(), keep_cap);
        assert!(first.iter().any(|name| name.contains(".prod.")));
        assert!(first.iter().any(|name| name.contains(".apac.")));
        assert!(first.iter().any(|name| name.contains("worker-")));
    }

    #[test]
    fn unseen_targeted_sources_start_ahead_of_expensive_archives() {
        assert!(source_bootstrap_score("securitytrails") > source_bootstrap_score("wayback"));
        assert!(source_bootstrap_score("merklemap") > source_bootstrap_score("commoncrawl"));
    }

    #[test]
    fn phase_budget_is_cumulative_and_saturates_at_zero() {
        let mut remaining = Some(Duration::from_secs(10));
        consume_phase_budget(&mut remaining, Duration::from_secs(4));
        assert_eq!(remaining, Some(Duration::from_secs(6)));
        consume_phase_budget(&mut remaining, Duration::from_secs(7));
        assert_eq!(remaining, Some(Duration::ZERO));

        let mut unlimited = None;
        consume_phase_budget(&mut unlimited, Duration::from_secs(99));
        assert_eq!(unlimited, None);
    }

    #[test]
    fn web_budget_is_shared_across_initial_and_pipeline_rounds() {
        let mut remaining = Some(Duration::from_secs(45));
        consume_phase_budget(&mut remaining, Duration::from_secs(30));
        assert_eq!(remaining, Some(Duration::from_secs(15)));
        consume_phase_budget(&mut remaining, Duration::from_secs(20));
        assert_eq!(remaining, Some(Duration::ZERO));
    }

    #[test]
    fn explicit_active_budget_is_independent_of_adaptive_mode_and_includes_wordlists() {
        // The scanner budget no longer receives an `adaptive` flag: an
        // explicit non-zero --active-max-runtime therefore remains effective
        // with --no-adaptive. A profile/default value of zero is represented
        // as None and remains unlimited.
        assert!(active_candidate_budget_exhausted(Some(Duration::ZERO)));
        assert!(!active_candidate_budget_exhausted(None));
        assert!(!active_candidate_work_allowed(Some(Duration::ZERO)));
        assert!(active_candidate_work_allowed(None));

        let generated = CandidateProposal {
            relative_name: "api".to_owned(),
            generator: "builtin".to_owned(),
            score: 1,
        };
        let wordlist = CandidateProposal {
            relative_name: "custom".to_owned(),
            generator: "wordlist".to_owned(),
            score: 1,
        };
        assert!(candidate_uses_active_budget(&generated));
        assert!(candidate_uses_active_budget(&wordlist));
        assert!(candidate_uses_discovery_fast_path(
            &generated, true, false, false, false
        ));
        assert!(!candidate_uses_discovery_fast_path(
            &wordlist, true, false, false, false
        ));
        assert!(!candidate_uses_discovery_fast_path(
            &generated, true, false, true, false
        ));
        assert!(!candidate_uses_discovery_fast_path(
            &generated, true, true, false, false
        ));
        assert!(!candidate_uses_discovery_fast_path(
            &generated, true, false, false, true
        ));
        // Expansion state changes fast-path eligibility, not budget ownership:
        // resumed/generated retries must remain under the active deadline.
        assert!(candidate_uses_active_budget(&generated));
        assert!(!candidate_uses_discovery_fast_path(
            &generated, false, false, false, false
        ));
    }

    #[test]
    fn completed_last_recursive_depth_does_not_create_a_false_partial() {
        assert!(!active_resume_required(
            Some(Duration::ZERO),
            0,
            0,
            false,
            false,
        ));
        assert!(active_resume_required(
            Some(Duration::ZERO),
            0,
            0,
            false,
            true,
        ));
        assert!(active_resume_required(
            Some(Duration::ZERO),
            0,
            1,
            false,
            false,
        ));
        assert!(active_resume_required(None, 1, 0, false, false,));
    }

    #[test]
    fn generated_fast_negatives_route_only_to_the_discovery_journal() {
        let positive = ResolvedHost {
            fqdn: "live.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.10".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let routed = route_dns_outcomes(
            BatchDnsMode::GeneratedDiscovery,
            [
                DnsResolutionOutcome::Positive(positive.clone()),
                DnsResolutionOutcome::Negative {
                    fqdn: "missing.example.com".to_owned(),
                },
                DnsResolutionOutcome::Indeterminate {
                    fqdn: "uncertain.example.com".to_owned(),
                },
            ],
            ["deadline.example.com".to_owned()],
        );
        assert_eq!(routed.positives.len(), 1);
        assert_eq!(routed.positives[0].fqdn, positive.fqdn);
        assert_eq!(routed.positives[0].records, positive.records);
        assert!(routed.cacheable_negatives.is_empty());
        assert_eq!(
            routed.discovery_negatives,
            vec!["missing.example.com".to_owned()]
        );
        assert_eq!(
            routed.indeterminate,
            vec![
                "deadline.example.com".to_owned(),
                "uncertain.example.com".to_owned()
            ]
        );

        let conservative = route_dns_outcomes(
            BatchDnsMode::Conservative,
            [DnsResolutionOutcome::Negative {
                fqdn: "missing.example.com".to_owned(),
            }],
            [],
        );
        assert_eq!(
            conservative.cacheable_negatives,
            vec!["missing.example.com".to_owned()]
        );
        assert!(conservative.discovery_negatives.is_empty());
    }

    #[test]
    fn discovery_negative_is_terminal_without_poisoning_an_existing_positive_cache() {
        let database = Database::in_memory().unwrap();
        let history_scan = database.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "api.example.com".to_owned();
        let positive = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 2,
        };
        database
            .update_cache_outcomes(
                Some(history_scan),
                std::slice::from_ref(&positive),
                &[],
                &[],
                300,
            )
            .unwrap();

        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        database
            .persist_scan_candidates_bounded(
                scan_id,
                "example.com",
                &[("api".to_owned(), "builtin".to_owned(), 1)],
                1,
            )
            .unwrap();
        assert_eq!(
            database.pending_scan_candidates(scan_id, 1).unwrap().len(),
            1
        );

        persist_routed_dns_outcomes(
            &database,
            scan_id,
            &[],
            &[],
            std::slice::from_ref(&fqdn),
            &[],
            300,
        )
        .unwrap();
        database
            .mark_scan_candidates_done(scan_id, std::slice::from_ref(&fqdn))
            .unwrap();

        assert_eq!(database.pending_scan_candidate_count(scan_id).unwrap(), 0);
        let cached = database.fresh_cache(std::slice::from_ref(&fqdn)).unwrap();
        let Some(crate::db::CachedAnswer::Positive(answer)) = cached.get(&fqdn) else {
            panic!("discovery-only negative replaced the positive cache");
        };
        assert_eq!(answer.records, positive.records);
    }

    #[tokio::test]
    async fn active_deadline_persists_completed_outcomes_and_requeues_unfinished_work() {
        let fast = "fast.example.com".to_owned();
        let slow = "slow.example.com".to_owned();
        let started = Instant::now();
        let batch = collect_dns_outcomes_until(
            vec![fast.clone(), slow.clone()],
            2,
            Some(tokio::time::Instant::now() + Duration::from_millis(60)),
            |fqdn, network_attempted| async move {
                network_attempted.store(true, Ordering::Release);
                if fqdn.starts_with("fast.") {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    DnsResolutionOutcome::Positive(ResolvedHost {
                        fqdn,
                        records: vec![DnsRecord {
                            record_type: "A".to_owned(),
                            value: "192.0.2.10".to_owned(),
                            ttl: 60,
                        }],
                        from_cache: false,
                        last_verified_at: Some(1),
                        authoritative_validation: false,
                        resolver_count: 2,
                    })
                } else {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    DnsResolutionOutcome::Negative { fqdn }
                }
            },
            |_| {},
        )
        .await;

        assert!(batch.deadline_exhausted);
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(batch.completed.len(), 1);
        assert_eq!(batch.completed[0].fqdn(), fast);
        assert_eq!(batch.cancelled, vec![slow.clone()]);
        assert!(batch.not_started.is_empty());
        assert_eq!(batch.attempted, vec![fast.clone(), slow.clone()]);

        let database = Database::in_memory().unwrap();
        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        database
            .persist_scan_candidates_bounded(
                scan_id,
                "example.com",
                &[
                    ("fast".to_owned(), "builtin".to_owned(), 2),
                    ("slow".to_owned(), "builtin".to_owned(), 1),
                ],
                2,
            )
            .unwrap();
        assert_eq!(
            database.pending_scan_candidates(scan_id, 2).unwrap().len(),
            2
        );

        let attempted_hosts = batch.attempted.clone();
        let completed = batch
            .completed
            .into_iter()
            .filter_map(|outcome| match outcome {
                DnsResolutionOutcome::Positive(answer) => Some(answer),
                _ => None,
            })
            .collect::<Vec<_>>();
        database
            .mark_scan_candidates_started(scan_id, &attempted_hosts)
            .unwrap();
        database
            .update_cache_outcomes(Some(scan_id), &completed, &[], &batch.cancelled, 300)
            .unwrap();
        database
            .record_scan_candidate_results(
                scan_id,
                &[(fast.clone(), "fast".to_owned(), "builtin".to_owned(), true)],
            )
            .unwrap();
        database
            .mark_scan_candidates_done(scan_id, &[fast.clone(), slow.clone()])
            .unwrap();

        let cache = database.fresh_cache(&[fast.clone(), slow.clone()]).unwrap();
        assert!(matches!(
            cache.get(&fast),
            Some(crate::db::CachedAnswer::Positive(_))
        ));
        assert!(!cache.contains_key(&slow));
        // The unfinished generated row remains durable, but an exhausted
        // active budget cannot claim it again during this scan.
        assert!(
            database
                .pending_scan_candidates_eligible(scan_id, 10, false)
                .unwrap()
                .is_empty()
        );
        assert_eq!(database.pending_scan_candidate_count(scan_id).unwrap(), 1);
        let retry = database
            .pending_scan_candidates_eligible(scan_id, 10, true)
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].0, "slow");
        let learning = database.scan_candidate_learning(scan_id).unwrap();
        // Candidate learning is recorded only once a row becomes terminal;
        // the cancelled packet consumed a retry but remains eligible here.
        assert_eq!(learning.total_attempts, 1);
        assert_eq!(learning.generator_attempts.get("builtin"), Some(&1));
    }

    #[tokio::test]
    async fn expired_deadline_never_starts_an_immediately_ready_backlog() {
        let starts = Arc::new(AtomicUsize::new(0));
        let hosts = (0..10_000)
            .map(|index| format!("{index}.example.com"))
            .collect::<Vec<_>>();
        let counter = starts.clone();
        let batch = collect_dns_outcomes_until(
            hosts.clone(),
            64,
            Some(tokio::time::Instant::now() - Duration::from_millis(1)),
            move |fqdn, _network_attempted| {
                counter.fetch_add(1, Ordering::SeqCst);
                async move { DnsResolutionOutcome::Negative { fqdn } }
            },
            |_| {},
        )
        .await;

        assert!(batch.deadline_exhausted);
        assert_eq!(starts.load(Ordering::SeqCst), 0);
        assert!(batch.completed.is_empty());
        assert!(batch.cancelled.is_empty());
        assert_eq!(batch.not_started.len(), hosts.len());

        let database = Database::in_memory().unwrap();
        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        database
            .persist_scan_candidates(
                scan_id,
                "example.com",
                &[("never-sent".to_owned(), "builtin".to_owned(), 1)],
            )
            .unwrap();
        database.pending_scan_candidates(scan_id, 1).unwrap();
        database
            .requeue_unstarted_scan_candidates(scan_id, &["never-sent.example.com".to_owned()])
            .unwrap();
        assert_eq!(database.pending_scan_candidate_count(scan_id).unwrap(), 1);
    }

    #[tokio::test]
    async fn a_scheduled_future_that_never_sends_does_not_consume_a_retry() {
        let host = "waiting-for-transport.example.com".to_owned();
        let polled = Arc::new(AtomicBool::new(false));
        let observed_poll = Arc::clone(&polled);
        let batch = collect_dns_outcomes_until(
            vec![host.clone()],
            1,
            Some(tokio::time::Instant::now() + Duration::from_millis(25)),
            move |fqdn, _network_attempted| {
                let observed_poll = Arc::clone(&observed_poll);
                async move {
                    observed_poll.store(true, Ordering::Release);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    DnsResolutionOutcome::Negative { fqdn }
                }
            },
            |_| {},
        )
        .await;

        assert!(polled.load(Ordering::Acquire));
        assert!(batch.deadline_exhausted);
        assert!(batch.completed.is_empty());
        assert!(batch.attempted.is_empty());
        assert!(batch.cancelled.is_empty());
        assert_eq!(batch.not_started, vec![host]);
    }

    #[test]
    fn refresh_defaults_are_bounded_and_batch_persistence_is_small() {
        let options = RefreshOptions::default();
        assert_eq!(options.max_runtime, Duration::from_secs(300));
        assert_eq!(options.wildcard_phase_timeout, Duration::from_secs(30));
        assert_eq!(options.batch_size, 256);
    }

    #[tokio::test]
    async fn expired_refresh_deadline_cancels_without_network() {
        let result = before_refresh_deadline(
            Some(tokio::time::Instant::now() - Duration::from_millis(1)),
            std::future::pending::<()>(),
        )
        .await;
        assert!(result.is_none());
    }

    #[test]
    fn global_refresh_deadline_caps_the_shared_wildcard_phase() {
        let global = tokio::time::Instant::now() + Duration::from_secs(1);
        let capped = capped_phase_deadline(Some(global), Duration::from_secs(30));
        assert_eq!(capped, global);
    }

    #[test]
    fn pathological_library_durations_expire_instead_of_panicking() {
        let before = tokio::time::Instant::now();
        let phase = phase_deadline(Some(Duration::MAX)).unwrap();
        let refresh = refresh_deadline(Duration::MAX).unwrap();
        let capped = capped_phase_deadline(None, Duration::MAX);
        let after = tokio::time::Instant::now();
        for deadline in [phase, refresh, capped] {
            assert!(deadline >= before && deadline <= after);
        }
    }

    #[test]
    fn wildcard_purge_requires_a_complete_reliable_refresh() {
        assert!(refresh_allows_wildcard_purge("completed", true));
        assert!(!refresh_allows_wildcard_purge("partial", true));
        assert!(!refresh_allows_wildcard_purge("interrupted", true));
        assert!(!refresh_allows_wildcard_purge("completed", false));
        assert!(refresh_can_demote_wildcard_ambiguity(true));
        assert!(!refresh_can_demote_wildcard_ambiguity(false));
    }

    #[test]
    fn indeterminate_root_or_child_profile_makes_refresh_partial() {
        let indeterminate = super::indeterminate_wildcard_signature();
        let normal = BTreeSet::new();
        assert!(!refresh_wildcard_profile_is_reliable(None));
        assert!(!refresh_wildcard_profile_is_reliable(Some(&indeterminate)));
        assert!(refresh_wildcard_profile_is_reliable(Some(&normal)));
    }

    #[test]
    fn stale_wildcard_profile_never_authorizes_refresh_cleanup() {
        let stale = BTreeSet::from(["A:192.0.2.44".to_owned()]);
        let observation =
            wildcard_profile_after_probe(Some(stale.clone()), WildcardProbeOutcome::Indeterminate);

        // The old signature remains available to classify matching answers
        // conservatively, but the failed current probe makes cleanup unsafe.
        assert_eq!(observation.signature.as_ref(), Some(&stale));
        assert!(refresh_wildcard_profile_is_reliable(
            observation.signature.as_ref()
        ));
        assert!(!observation.current_probe_reliable);
        assert!(!refresh_wildcard_observation_is_reliable(Some(
            &observation
        )));

        let current =
            wildcard_profile_after_probe(None, WildcardProbeOutcome::Wildcard(stale.clone()));
        assert!(refresh_wildcard_observation_is_reliable(Some(&current)));
    }

    #[tokio::test]
    async fn failed_current_probe_keeps_stale_wildcard_non_destructive() {
        let database = Database::in_memory().unwrap();
        let stale = BTreeSet::from(["A:192.0.2.44".to_owned()]);
        database
            .store_wildcard_cache("example.test", &stale, None, Duration::ZERO, true)
            .unwrap();
        let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns = DnsEngine::new_with_socket_addresses(
            8,
            Duration::from_millis(10),
            &[silent.local_addr().unwrap()],
            0,
        )
        .unwrap();

        let observation = tokio::time::timeout(
            Duration::from_secs(1),
            wildcard_profile_observed(
                &database,
                &dns,
                "example.test",
                Duration::from_secs(3_600),
                true,
                false,
            ),
        )
        .await
        .expect("bounded wildcard probes must terminate");

        assert_eq!(observation.signature.as_ref(), Some(&stale));
        assert!(!observation.current_probe_reliable);
        assert!(!refresh_wildcard_observation_is_reliable(Some(
            &observation
        )));
    }

    #[test]
    fn more_than_sixty_four_parent_zones_disables_cleanup() {
        assert!(refresh_parent_selection_is_complete(64, false));
        assert!(!refresh_parent_selection_is_complete(65, false));
        assert!(!refresh_parent_selection_is_complete(1, true));
    }

    #[test]
    fn trusted_positive_matching_wildcard_is_not_live() {
        let signature = BTreeSet::from(["A:192.0.2.44".to_owned()]);
        let answer = ResolvedHost {
            fqdn: "api.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 3,
        };
        assert!(Scanner::answer_is_wildcard_ambiguous(
            &answer,
            &signature,
            &BTreeMap::new(),
        ));
    }

    #[test]
    fn parent_heavy_hitters_stay_memory_bounded() {
        let mut counts = HashMap::new();
        for index in 0..100 {
            record_bounded_parent_candidate(&mut counts, format!("{index}.example.com"), 8);
        }
        for _ in 0..50 {
            record_bounded_parent_candidate(&mut counts, "prod.example.com".to_owned(), 8);
        }
        assert!(counts.len() <= 8);
        assert!(counts.contains_key("prod.example.com"));
    }

    #[tokio::test]
    async fn completed_cleanup_quarantines_exact_matches_with_passive_evidence() {
        let database = Database::in_memory().unwrap();
        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        let make = |fqdn: &str, source: &str| Finding {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            sources: BTreeSet::from([source.to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from([source.to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: Some(1),
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        };
        let weak = "weak.example.com";
        let corroborated = "ct.example.com";
        database
            .persist_findings(
                scan_id,
                "example.com",
                &[
                    make(weak, "bruteforce"),
                    make(corroborated, "passive:crtsh"),
                ],
                86_400,
            )
            .unwrap();
        database
            .record_current_wildcard_matches(
                scan_id,
                &[weak, corroborated]
                    .into_iter()
                    .map(|fqdn| ResolvedHost {
                        fqdn: fqdn.to_owned(),
                        records: vec![DnsRecord {
                            record_type: "A".to_owned(),
                            value: "192.0.2.44".to_owned(),
                            ttl: 60,
                        }],
                        from_cache: false,
                        last_verified_at: Some(1),
                        authoritative_validation: false,
                        resolver_count: 2,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        database
            .stage_refresh_wildcard_candidates(scan_id, &[weak.to_owned(), corroborated.to_owned()])
            .unwrap();
        let (purged, retained) =
            apply_completed_refresh_wildcard_cleanup(&database, scan_id, "example.com", None, 1)
                .await
                .unwrap()
                .unwrap();
        assert_eq!((purged, retained), (2, 0));
        assert!(
            database
                .inventory(Some("example.com"), false)
                .unwrap()
                .is_empty()
        );
        let explanation = database.explain(corroborated).unwrap();
        assert_eq!(explanation["quarantine"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn expired_cleanup_deadline_keeps_inventory_unchanged() {
        let database = Database::in_memory().unwrap();
        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "weak.example.com";
        let finding = Finding {
            fqdn: fqdn.to_owned(),
            records: Vec::new(),
            sources: BTreeSet::from(["dns-wave-2".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["dns-wave-2".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: Some(1),
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        };
        database
            .persist_findings(scan_id, "example.com", &[finding], 86_400)
            .unwrap();
        database
            .stage_refresh_wildcard_candidates(scan_id, &[fqdn.to_owned()])
            .unwrap();

        let result = apply_completed_refresh_wildcard_cleanup(
            &database,
            scan_id,
            "example.com",
            Some(tokio::time::Instant::now() - Duration::from_millis(1)),
            1,
        )
        .await
        .unwrap();
        assert!(result.is_none());
        assert_eq!(
            database.refresh_wildcard_candidate_count(scan_id).unwrap(),
            0
        );
        let inventory = database.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state, ObservationState::Live);
    }

    #[test]
    fn dropping_refresh_cleanup_guard_waits_for_worker_completion() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _completion = SignalRefreshCleanupCompletion(Some(completion_tx));
            while !worker_cancelled.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            std::thread::sleep(Duration::from_millis(10));
            worker_finished.store(true, Ordering::Release);
        });

        {
            let _guard = RefreshCleanupCancellation::new(cancelled, completion_rx);
        }

        assert!(finished.load(Ordering::Acquire));
        worker.join().unwrap();
    }

    #[test]
    fn dropped_refresh_closes_its_non_resumable_checkpoint() {
        let database = Database::in_memory().unwrap();
        let scan_id = database
            .create_scan("example.com", &json!({"mode": "refresh"}))
            .unwrap();
        database
            .upsert_checkpoint(scan_id, "example.com", "running", "refresh")
            .unwrap();
        {
            let _guard = RefreshRunGuard::new(database.clone(), scan_id, Instant::now(), 12);
        }
        assert!(
            database
                .resumable_checkpoint("example.com", "latest")
                .unwrap()
                .is_none()
        );
        assert_eq!(database.history(1).unwrap()[0]["status"], "interrupted");
    }

    #[test]
    fn dropping_a_running_scan_marks_it_interrupted_and_keeps_the_checkpoint() {
        let database = Database::in_memory().unwrap();
        let scan_id = database.create_scan("example.com", &json!({})).unwrap();
        database
            .upsert_checkpoint(scan_id, "example.com", "running", "options-hash")
            .unwrap();
        {
            let _guard = ScanRunGuard::new(database.clone(), scan_id, Instant::now());
        }

        let history = database.history(1).unwrap();
        assert_eq!(history[0]["status"], "interrupted");
        assert!(
            database
                .resumable_checkpoint("example.com", "latest")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn deepest_known_wildcard_ancestor_applies_to_all_descendants() {
        let root = BTreeSet::new();
        let prod = BTreeSet::from(["A:192.0.2.29".to_owned()]);
        let mut by_parent = BTreeMap::from([
            ("example.com".to_owned(), root.clone()),
            ("prod.example.com".to_owned(), prod.clone()),
        ]);
        assert_eq!(
            Scanner::applicable_wildcard_signature("a.b.c.prod.example.com", &root, &by_parent),
            &prod
        );

        by_parent.insert("c.prod.example.com".to_owned(), BTreeSet::new());
        assert!(
            Scanner::applicable_wildcard_signature("a.b.c.prod.example.com", &root, &by_parent)
                .is_empty()
        );
    }

    #[test]
    fn only_matching_or_indeterminate_wildcard_answers_are_terminal_seeds() {
        let normal_root = BTreeSet::new();
        let wildcard = BTreeSet::from(["A:192.0.2.29".to_owned()]);
        let indeterminate = super::indeterminate_wildcard_signature();
        let by_parent = BTreeMap::from([
            ("example.com".to_owned(), normal_root.clone()),
            ("prod.example.com".to_owned(), wildcard),
            ("unknown.example.com".to_owned(), indeterminate),
        ]);
        let answer = |fqdn: &str, address: &str| ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: vec![crate::model::DnsRecord {
                record_type: "A".to_owned(),
                value: address.to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: None,
            authoritative_validation: false,
            resolver_count: 1,
        };

        assert!(Scanner::is_strict_enrichment_seed(
            &answer("api.example.com", "192.0.2.10"),
            &normal_root,
            &by_parent
        ));
        assert!(!Scanner::is_strict_enrichment_seed(
            &answer("random.prod.example.com", "192.0.2.29"),
            &normal_root,
            &by_parent
        ));
        assert!(
            Scanner::is_strict_enrichment_seed(
                &answer("mail.prod.example.com", "192.0.2.10"),
                &normal_root,
                &by_parent
            ),
            "a legitimate answer with records distinct from the wildcard must remain usable"
        );
        assert!(!Scanner::is_strict_enrichment_seed(
            &answer("api.unknown.example.com", "192.0.2.10"),
            &normal_root,
            &by_parent
        ));
    }

    #[test]
    fn wildcard_sampling_counts_intermediate_ancestors() {
        assert_eq!(
            Scanner::ancestor_zones("a.b.prod.example.com", "example.com"),
            vec!["b.prod.example.com", "prod.example.com"]
        );
    }

    #[test]
    fn adaptive_waves_require_a_minimum_yield_rate() {
        assert!(should_expand_adaptive_wave(true, 0, 500, 2, 5));
        assert!(should_expand_adaptive_wave(true, 1, 500, 3, 10));
        assert!(should_expand_adaptive_wave(true, 2, 1_000, 3, 0));
        assert!(should_expand_adaptive_wave(true, 3, 1_500, 3, 0));
        assert!(!should_expand_adaptive_wave(true, 0, 3_000, 3, 0));
        assert!(!should_expand_adaptive_wave(false, 20, 500, 2, 20));
    }

    #[test]
    fn statistical_yield_bound_is_conservative_and_monotonic() {
        assert_eq!(wilson_upper_bound(0, 0), 1.0);
        assert!(wilson_upper_bound(1, 500) > 0.001);
        assert!(wilson_upper_bound(0, 3_000) < 0.001);
        assert!(wilson_upper_bound(0, 6_000) < wilson_upper_bound(0, 3_000));
        assert!(wilson_upper_bound(5, 3_000) > wilson_upper_bound(0, 3_000));
    }

    #[test]
    fn adding_credentials_bypasses_only_legacy_missing_key_cooldowns() {
        assert!(source_requires_api_key("censys"));
        assert!(!source_requires_api_key("crtsh"));
        assert!(is_missing_api_key_error(
            "BINARYEDGE_API_KEY absent pour la source binaryedge"
        ));
        assert!(!is_missing_api_key_error(
            "binaryedge: HTTP 401 invalid api key"
        ));
        assert!(is_preflight_auth_error(
            "CENSYS_API_KEY doit être au format API_ID:API_SECRET"
        ));
        assert!(source_error_is_deferred(
            "BINARYEDGE_API_KEY absent pour la source binaryedge"
        ));
        assert!(source_error_is_deferred(
            "CENSYS_API_KEY doit être au format API_ID:API_SECRET"
        ));
        assert!(!source_error_is_deferred(
            "censys: HTTP 401 invalid api key"
        ));

        assert!(should_retry_source_after_key_added(
            "binaryedge",
            true,
            Some("BINARYEDGE_API_KEY absent pour la source binaryedge")
        ));
        assert!(!should_retry_source_after_key_added(
            "binaryedge",
            false,
            Some("BINARYEDGE_API_KEY absent pour la source binaryedge")
        ));
        assert!(should_retry_source_after_key_added(
            "otx",
            true,
            Some("OTX limite l'accès anonyme (HTTP 429)")
        ));
        assert!(!should_retry_source_after_key_added(
            "otx",
            false,
            Some("OTX limite l'accès anonyme (HTTP 429)")
        ));
        assert!(!should_retry_source_after_key_added(
            "otx",
            true,
            Some("OTX refuse la clé fournie (HTTP 429)")
        ));
        assert!(!should_retry_source_after_key_added(
            "otx",
            true,
            Some("OTX indisponible (HTTP 503)")
        ));
    }

    #[test]
    fn external_retry_after_becomes_a_precise_adaptive_pause() {
        assert_eq!(
            external_retry_after_seconds(
                "urlscan: HTTP 429 avec Retry-After=3661s; nouvelle tentative différée"
            ),
            Some(3661)
        );
        assert_eq!(
            external_pause_status(61),
            "source externe différée, reprise dans 2 min, mémoire permanente"
        );
        assert_eq!(external_retry_after_seconds("HTTP 503"), None);
        assert_eq!(
            external_deferral_seconds("Driftnet: HTTP 403: quota exceeded"),
            Some(900)
        );
        assert_eq!(external_deferral_seconds("HTTP 403 unauthorized"), None);
    }
}
