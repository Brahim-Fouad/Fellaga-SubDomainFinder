use crate::axfr::attempt_axfr;
use crate::candidate::{CandidateProposal, MutationRule, generate_contextual_with_rules};
use crate::confidence::{assess_with_context as assess_confidence, evidence_families};
use crate::ct_monitor::monitor_ct_logs;
use crate::db::{CachedAnswer, Database};
use crate::discovery::discover_dns_graph;
use crate::dns::{DnsEngine, DnsResolutionOutcome, WildcardProbeOutcome};
use crate::dnssec::discover_nsec;
use crate::model::{
    CtMonitorResult, DiscoveryEdge, DnssecWalkResult, Finding, PipelineMetrics, ResolvedHost,
    ScanResult, ServiceEndpoint, WebObservation,
};
use crate::passive::{
    ApiKeyStore, current_commoncrawl_endpoint, fetch as fetch_passive, sanitize_external_error,
    seed_commoncrawl_endpoint, source_metadata, source_policy,
};
use crate::pipeline::DiscoveryPipeline;
use crate::tls::discover as discover_tls_certificates;
use crate::util::{
    domain_hash, labels_from_name, learnable_label, learnable_relative_name, normalize_domain,
    normalize_observed_name, now_epoch,
};
use crate::web_discovery::discover_web;
use anyhow::{Result, bail};
use futures_util::{StreamExt, stream};
use serde_json::json;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    pub passive: bool,
    pub passive_sources: Vec<String>,
    pub api_keys: ApiKeyStore,
    pub automatic_source_selection: bool,
    pub passive_refresh: Duration,
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
    pub ct_monitor: bool,
    pub ct_timeout: Duration,
    pub ct_max_logs: usize,
    pub ct_entries_per_log: usize,
    pub ct_initial_backfill: usize,
    pub web_discovery: bool,
    pub web_max_hosts: usize,
    pub web_timeout: Duration,
    pub web_refresh: Duration,
    pub web_concurrency: usize,
    pub web_max_bytes: usize,
    pub web_assets_per_host: usize,
}

pub struct Scanner {
    database: Database,
    dns: DnsEngine,
    trusted_dns: Option<DnsEngine>,
    options: ScanOptions,
    progress: Option<ProgressCallback>,
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
        let every = every
            .min(Duration::from_secs(30))
            .max(Duration::from_secs(1));
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
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

async fn wildcard_profile_cached(
    database: &Database,
    dns: &DnsEngine,
    zone: &str,
    freshness: Duration,
    force_probe: bool,
) -> Option<BTreeSet<String>> {
    let cached = database
        .wildcard_cache(zone)
        .ok()
        .flatten()
        .filter(|cache| cache.algorithm_version >= 2);
    if !force_probe
        && let Some(cache) = &cached
        && cache.expires_at > now_epoch()
    {
        return Some(cache.signature.clone());
    }
    let serial = dns.soa_serial(zone).await;
    match dns.wildcard_probe(zone).await {
        WildcardProbeOutcome::Wildcard(signature) => {
            let _ = database.store_wildcard_cache(zone, &signature, serial, freshness, true);
            Some(signature)
        }
        WildcardProbeOutcome::Normal => {
            let signature = BTreeSet::new();
            let _ = database.store_wildcard_cache(zone, &signature, serial, freshness, true);
            Some(signature)
        }
        // Un ancien profil "normal" ne permet pas de conclure lorsque les
        // sondes actuelles échouent : le réutiliser ferait redevenir live un
        // faux positif si un wildcard a été activé entre-temps. Un ancien
        // wildcard confirmé reste en revanche une garde conservatrice sûre.
        WildcardProbeOutcome::Indeterminate => cached
            .filter(|cache| wildcard_signature_is_confirmed(&cache.signature))
            .map(|cache| cache.signature),
    }
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

fn should_expand_adaptive_wave(
    root_is_normal: bool,
    previous_positive: usize,
    wave_number: usize,
    passive_positive: usize,
) -> bool {
    root_is_normal && (previous_positive >= 2 || (wave_number == 2 && passive_positive >= 5))
}

fn should_retry_otx_after_key_added(key_configured: bool, last_error: Option<&str>) -> bool {
    key_configured
        && last_error.is_some_and(|error| {
            error.contains("429")
                && error.contains("accès anonyme")
                && !error.contains("clé fournie")
        })
}

fn cache_requires_revalidation(
    answer: &ResolvedHost,
    verification_max_age: Duration,
    now: i64,
) -> bool {
    if verification_max_age.is_zero() {
        return true;
    }
    let max_age = verification_max_age.as_secs().min(i64::MAX as u64) as i64;
    answer
        .last_verified_at
        .is_none_or(|verified_at| verified_at < now.saturating_sub(max_age))
}

fn external_retry_after_seconds(error: &str) -> Option<u64> {
    let (_, suffix) = error.split_once("Retry-After=")?;
    let digits = suffix
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

fn external_pause_status(retry_in_seconds: i64) -> String {
    let minutes = retry_in_seconds.max(1).saturating_add(59) / 60;
    format!("quota externe, reprise dans {minutes} min, mémoire permanente")
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
            *successes.entry(candidate.generator.clone()).or_default() += 1;
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

impl Scanner {
    pub fn new(database: Database, dns: DnsEngine, options: ScanOptions) -> Self {
        Self {
            database,
            dns,
            trusted_dns: None,
            options,
            progress: None,
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

    fn reclassify_cached_wildcard_matches(
        &self,
        scan_id: i64,
        domain: &str,
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<(usize, usize)> {
        let inventory = self.database.inventory(Some(domain), false)?;
        let mut confirmed = Vec::new();
        let mut uncertain = Vec::new();
        for entry in inventory {
            let signature =
                Self::applicable_wildcard_signature(&entry.fqdn, root_wildcard, wildcard_by_parent);
            if wildcard_signature_is_confirmed(signature) {
                confirmed.push(entry.fqdn);
            } else if wildcard_signature_is_indeterminate(signature)
                && entry.state != crate::model::ObservationState::Unverified
            {
                uncertain.push(entry.fqdn);
            }
        }
        for fqdn in self.database.positive_cache_names(domain)? {
            let signature =
                Self::applicable_wildcard_signature(&fqdn, root_wildcard, wildcard_by_parent);
            if wildcard_signature_is_confirmed(signature) {
                confirmed.push(fqdn);
            }
        }
        confirmed.sort();
        confirmed.dedup();
        let purged = self
            .database
            .purge_confirmed_wildcard_false_positives(domain, &confirmed)?;
        let purged = purged.into_iter().collect::<BTreeSet<_>>();
        let mut ambiguous = confirmed
            .into_iter()
            .filter(|host| !purged.contains(host))
            .chain(uncertain)
            .collect::<Vec<_>>();
        ambiguous.sort();
        ambiguous.dedup();
        self.database
            .mark_unverified(Some(scan_id), &ambiguous, "wildcard_ancestor_match")?;
        Ok((ambiguous.len(), purged.len()))
    }

    async fn wildcard_signature_cached(&self, zone: &str) -> Option<BTreeSet<String>> {
        wildcard_profile_cached(
            &self.database,
            &self.dns,
            zone,
            self.options.wildcard_refresh,
            self.options.refresh_cache,
        )
        .await
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

    async fn register_wildcard_parents(
        &self,
        hosts: &[String],
        domain: &str,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        limit: usize,
    ) {
        let mut counts = HashMap::<String, usize>::new();
        for host in hosts {
            if let Some(parent) = Self::parent_zone(host, domain) {
                parent_by_host.insert(host.clone(), parent.clone());
            }
            for ancestor in Self::ancestor_zones(host, domain) {
                *counts.entry(ancestor).or_default() += 1;
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
        wildcard_by_parent.extend(self.wildcard_signatures_cached(parents).await);
    }

    fn tls_endpoints(
        &self,
        domain: &str,
        answers: &BTreeMap<String, ResolvedHost>,
        services: &[ServiceEndpoint],
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
            .keys()
            .cloned()
            .map(|host| (host, self.options.tls_port, "tcp-tls".to_owned()))
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

    fn ordered_candidates(
        &self,
        domain: &str,
        observed_names: impl IntoIterator<Item = String>,
        limit: usize,
    ) -> Result<Vec<CandidateProposal>> {
        let limit = limit.min(100_000);
        let mut candidates = Vec::new();
        let mut seen = BTreeSet::new();
        let mut add = |candidate: CandidateProposal| {
            if seen.insert(candidate.relative_name.clone()) && candidates.len() < limit {
                candidates.push(candidate);
            }
        };
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
        sources: &mut BTreeMap<String, BTreeSet<String>>,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let now = now_epoch();
        let freshness = self.options.passive_refresh.as_secs().min(i64::MAX as u64) as i64;
        let mut cooldowns = if self.options.adaptive && self.options.automatic_source_selection {
            self.database
                .source_cooldowns(Duration::from_secs(24 * 3_600))?
        } else {
            BTreeSet::new()
        };
        if let Some(diagnostic) = self
            .database
            .source_diagnostics(Duration::from_secs(24 * 3_600))?
            .remove("otx")
            && should_retry_otx_after_key_added(
                self.options.api_keys.has("otx"),
                diagnostic.last_error.as_deref(),
            )
        {
            cooldowns.remove("otx");
        }
        let mut external_pauses = BTreeMap::new();
        if self.options.adaptive && self.options.automatic_source_selection {
            for source in &self.options.passive_sources {
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
        for source in &self.options.passive_sources {
            let cached = self.database.passive_cache(domain, source)?;
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
                for name in names {
                    sources
                        .entry(name)
                        .or_default()
                        .insert(format!("passive:{source}:cooldown"));
                }
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
                for name in &entry.names {
                    sources
                        .entry(name.clone())
                        .or_default()
                        .insert(format!("passive:{source}:cache"));
                }
            } else {
                refresh.push((source.clone(), cached.map(|entry| entry.names)));
            }
        }

        if refresh.iter().any(|(source, _)| source == "commoncrawl")
            && let Some(endpoint) = self.database.source_metadata(
                "commoncrawl.latest_endpoint",
                Duration::from_secs(30 * 24 * 3_600),
            )?
        {
            seed_commoncrawl_endpoint(endpoint);
        }
        let keys = self.options.api_keys.clone();
        let source_scores = self.database.source_scores()?;
        refresh.sort_by_key(|(source, _)| {
            (
                Reverse(source_scores.get(source).copied().unwrap_or_default()),
                source.clone(),
            )
        });
        let mut results = stream::iter(refresh)
            .map(|(source, stale)| {
                let keys = keys.clone();
                async move {
                    let started = Instant::now();
                    let result =
                        fetch_passive(&source, domain, source_policy(&source).timeout, &keys).await;
                    (source, stale, started.elapsed().as_millis(), result)
                }
            })
            .buffer_unordered(5);
        while let Some((source, stale, duration_ms, result)) = results.next().await {
            match result {
                Ok(names) => {
                    let names = names.into_iter().collect::<Vec<_>>();
                    let network_names = names.len();
                    let names = self.database.store_passive_cache(domain, &source, &names)?;
                    if source == "commoncrawl"
                        && let Some(endpoint) = current_commoncrawl_endpoint()
                    {
                        self.database
                            .store_source_metadata("commoncrawl.latest_endpoint", &endpoint)?;
                    }
                    self.database.record_source_result(
                        &source,
                        network_names,
                        duration_ms,
                        None,
                    )?;
                    self.emit(ProgressEvent::PassiveSource {
                        source: source.clone(),
                        status: "réseau + mémoire permanente".to_owned(),
                        names: names.len(),
                    });
                    for name in names {
                        sources
                            .entry(name)
                            .or_default()
                            .insert(format!("passive:{source}"));
                    }
                }
                Err(error) => {
                    let safe_error =
                        sanitize_external_error(&format!("{error:#}"), &self.options.api_keys);
                    let warning = format!("{source}: {safe_error}");
                    if let Some(delay) = external_retry_after_seconds(&safe_error) {
                        let retry_until = now_epoch()
                            .saturating_add(delay.min(i64::MAX as u64) as i64)
                            .to_string();
                        self.database.store_source_metadata(
                            &format!("source.retry_until.{source}"),
                            &retry_until,
                        )?;
                    }
                    self.database.record_source_result(
                        &source,
                        0,
                        duration_ms,
                        Some(&safe_error),
                    )?;
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                    if let Some(names) = stale {
                        self.emit(ProgressEvent::PassiveSource {
                            source: source.clone(),
                            status: "cache périmé".to_owned(),
                            names: names.len(),
                        });
                        for name in names {
                            sources
                                .entry(name)
                                .or_default()
                                .insert(format!("passive:{source}:stale"));
                        }
                    }
                }
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
            };
            self.emit(ProgressEvent::Phase {
                name: "passif récursif".to_owned(),
                detail: format!(
                    "zone {zone} ({})",
                    if child_query { "fille" } else { "parente" }
                ),
            });
            let mut zone_sources = BTreeMap::new();
            let mut zone_warnings = Vec::new();
            recursive_scanner
                .collect_passive(&zone, &mut zone_sources, &mut zone_warnings)
                .await?;
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
        let wildcard = wildcard_signature_is_confirmed(wildcard_signature);
        let wildcard_ambiguous = wildcard || wildcard_indeterminate;
        if wildcard_ambiguous && !self.options.include_wildcard && !strong_observation {
            return None;
        }
        let recently_verified = answer.last_verified_at.is_some_and(|checked_at| {
            checked_at
                >= crate::util::now_epoch()
                    .saturating_sub(self.options.verification_max_age.as_secs() as i64)
        });
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
        })
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
        let inventory = self.database.inventory(Some(domain), false)?;
        let missing_names = inventory
            .iter()
            .filter(|entry| !known.contains(&entry.fqdn))
            .map(|entry| entry.fqdn.clone())
            .collect::<Vec<_>>();
        let cached = self.database.fresh_cache(&missing_names)?;
        let before = findings.len();
        for entry in inventory {
            if !known.insert(entry.fqdn.clone()) {
                continue;
            }
            let answer = cached.get(&entry.fqdn).and_then(|cached| match cached {
                CachedAnswer::Positive(answer) => Some(answer),
                CachedAnswer::Negative => None,
            });
            let signature =
                Self::applicable_wildcard_signature(&entry.fqdn, root_wildcard, wildcard_by_parent);
            let wildcard = wildcard_signature_is_confirmed(signature)
                || wildcard_signature_is_indeterminate(signature);
            let state = if wildcard {
                crate::model::ObservationState::Unverified
            } else {
                entry.state
            };
            let families = evidence_families(&entry.sources);
            let confidence = assess_confidence(&entry.sources, wildcard, state, false);
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
            });
        }
        findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
        Ok(findings.len().saturating_sub(before))
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_batch(
        &self,
        scan_id: i64,
        hosts: &[String],
        phase: &str,
        scan_started: &Instant,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        parent_by_host: &HashMap<String, String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<(Vec<ResolvedHost>, usize, usize)> {
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
                    if cache_requires_revalidation(
                        answer,
                        self.options.verification_max_age,
                        now_epoch(),
                    ) {
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
        let network_outcomes = self
            .dns
            .resolve_many_classified_with_progress(network_hosts.clone(), |outcome| {
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
            })
            .await;
        let mut network_answers = Vec::new();
        let mut definitive_negative = Vec::new();
        let mut indeterminate = Vec::new();
        for outcome in network_outcomes {
            match outcome {
                DnsResolutionOutcome::Positive(answer) => network_answers.push(answer),
                DnsResolutionOutcome::Negative { fqdn } => definitive_negative.push(fqdn),
                DnsResolutionOutcome::Indeterminate { fqdn } => indeterminate.push(fqdn),
            }
        }
        let mut wildcard_answers = Vec::new();
        let mut validation_candidates = Vec::new();
        let mut suppressed_wildcard = 0_usize;
        for answer in network_answers {
            let signature = Self::applicable_wildcard_signature(
                &answer.fqdn,
                root_wildcard,
                wildcard_by_parent,
            );
            if signature.is_empty() {
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
                    "{suppressed_wildcard} réponse(s) candidate-only écartée(s) avant consensus et cache"
                ),
            });
        }
        if let Some(trusted_dns) = &self.trusted_dns {
            let validations = stream::iter(validation_candidates)
                .map(|answer| async move {
                    let fqdn = answer.fqdn.clone();
                    let outcome = trusted_dns.resolve_host_consensus_classified(&fqdn).await;
                    (fqdn, outcome)
                })
                .buffer_unordered(trusted_dns.concurrency().min(64))
                .collect::<Vec<_>>()
                .await;
            let mut validated = Vec::new();
            for (fqdn, outcome) in validations {
                match outcome {
                    DnsResolutionOutcome::Positive(mut consensus) => {
                        consensus.authoritative_validation =
                            trusted_dns.authoritative_confirms(&consensus.fqdn).await;
                        validated.push(consensus);
                    }
                    DnsResolutionOutcome::Negative { .. }
                    | DnsResolutionOutcome::Indeterminate { .. } => {
                        indeterminate.push(fqdn);
                    }
                }
            }
            validated.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
            wildcard_answers.extend(validated);
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
        definitive_negative.sort();
        definitive_negative.dedup();
        indeterminate.sort();
        indeterminate.dedup();
        if !indeterminate.is_empty() {
            self.emit(ProgressEvent::Warning(format!(
                "DNS {phase}: {} nom(s) indéterminé(s), cache et état actif préservés",
                indeterminate.len()
            )));
        }
        self.database.update_cache_outcomes(
            Some(scan_id),
            &network_answers,
            &definitive_negative,
            &indeterminate,
            self.options.negative_ttl,
        )?;
        let resolved_from_network = network_answers.len();
        answers.extend(network_answers);
        Ok((answers, cache_hits, resolved_from_network))
    }

    pub async fn scan(&self, target: &str) -> Result<ScanResult> {
        let domain = normalize_domain(target)?;
        let options_json = json!({
            "max_words": self.options.max_words,
            "passive": self.options.passive,
            "passive_sources": self.options.passive_sources,
            "automatic_source_selection": self.options.automatic_source_selection,
            "adaptive": self.options.adaptive,
            "pipeline": self.options.pipeline,
            "pipeline_rounds": self.options.pipeline_rounds,
            "pipeline_budget": self.options.pipeline_budget,
            "passive_refresh_seconds": self.options.passive_refresh.as_secs(),
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
            "ct_monitor": self.options.ct_monitor,
            "ct_timeout_ms": self.options.ct_timeout.as_millis(),
            "ct_max_logs": self.options.ct_max_logs,
            "ct_entries_per_log": self.options.ct_entries_per_log,
            "ct_initial_backfill": self.options.ct_initial_backfill,
            "web_discovery": self.options.web_discovery,
            "web_max_hosts": self.options.web_max_hosts,
            "web_timeout_ms": self.options.web_timeout.as_millis(),
            "web_refresh_seconds": self.options.web_refresh.as_secs(),
            "web_concurrency": self.options.web_concurrency,
            "web_max_bytes": self.options.web_max_bytes,
            "web_assets_per_host": self.options.web_assets_per_host,
            "wordlist": self.options.wordlist.as_ref().map(|path| path.display().to_string()),
            "mutation_rules": self.options.mutation_rules,
        });
        let options_hash = domain_hash(&serde_json::to_string(&options_json)?);
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
        let started = Instant::now();
        self.emit(ProgressEvent::Started {
            scan_id,
            domain: domain.clone(),
        });
        let checkpoint_heartbeat = CheckpointHeartbeat::start(
            self.database.clone(),
            scan_id,
            domain.clone(),
            options_hash,
            self.options.checkpoint_every,
        );
        let mut run_guard = ScanRunGuard::new(self.database.clone(), scan_id, started);
        let result = self.scan_inner(scan_id, &domain, started).await;
        run_guard.disarm();
        checkpoint_heartbeat.stop().await;
        if let Err(error) = &result {
            self.emit(ProgressEvent::Warning(format!(
                "scan interrompu: {error:#}"
            )));
            let _ = self.database.finish_scan(
                scan_id,
                "failed",
                0,
                0,
                0,
                started.elapsed().as_millis(),
                &[format!("{error:#}")],
            );
        }
        self.emit(ProgressEvent::Complete);
        result
    }

    async fn scan_inner(&self, scan_id: i64, domain: &str, started: Instant) -> Result<ScanResult> {
        let mut warnings = Vec::new();
        let mut pipeline_metrics = PipelineMetrics::default();
        let mut sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut passive_zones_queried = BTreeSet::from([domain.to_owned()]);
        if self.options.passive {
            self.emit(ProgressEvent::Phase {
                name: "passif".to_owned(),
                detail: format!(
                    "{} source(s), cache {} h",
                    self.options.passive_sources.len(),
                    self.options.passive_refresh.as_secs() / 3_600
                ),
            });
            self.collect_passive(domain, &mut sources, &mut warnings)
                .await?;
            let mut inferred = self.inferred_passive_zones(
                domain,
                sources.keys().cloned(),
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
                &mut passive_zones_queried,
                &mut sources,
                &mut warnings,
            )
            .await?;
        }

        let mut ct_monitor = CtMonitorResult::default();
        if self.options.ct_monitor {
            self.emit(ProgressEvent::Phase {
                name: "CT incrémental".to_owned(),
                detail: format!(
                    "{} journal(aux), {} entrées maximum par journal",
                    self.options.ct_max_logs, self.options.ct_entries_per_log
                ),
            });
            match monitor_ct_logs(
                &self.database,
                domain,
                self.options.ct_timeout,
                self.options.ct_max_logs,
                self.options.ct_entries_per_log,
                self.options.ct_initial_backfill,
            )
            .await
            {
                Ok(result) => ct_monitor = result,
                Err(error) => {
                    let warning = format!("CT incrémental: {error:#}");
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                    if let Some(cache) = self.database.passive_cache(domain, "ct-direct")? {
                        ct_monitor.names = cache.names.into_iter().collect();
                    }
                }
            }
            for name in &ct_monitor.names {
                sources
                    .entry(name.clone())
                    .or_default()
                    .insert("passive:ct-direct".to_owned());
            }
            self.emit(ProgressEvent::CtMonitor {
                logs: ct_monitor.logs_checked,
                entries: ct_monitor.entries_processed,
                failures: ct_monitor.failures,
                names: ct_monitor.names.len(),
                duration_ms: ct_monitor.duration_ms,
            });
        }

        let axfr_attempts = if self.options.axfr {
            self.emit(ProgressEvent::Phase {
                name: "AXFR".to_owned(),
                detail: "résolution des NS et transfert TCP".to_owned(),
            });
            let (attempts, axfr_warnings) =
                attempt_axfr(&self.dns, domain, self.options.axfr_timeout).await;
            for warning in &axfr_warnings {
                self.emit(ProgressEvent::Warning(warning.clone()));
            }
            warnings.extend(axfr_warnings);
            for attempt in &attempts {
                self.emit(ProgressEvent::AxfrAttempt(attempt.clone()));
                if attempt.status == crate::model::AxfrStatus::Success {
                    for name in &attempt.names {
                        sources
                            .entry(name.clone())
                            .or_default()
                            .insert(format!("axfr:{}", attempt.nameserver));
                    }
                }
            }
            attempts
        } else {
            Vec::new()
        };
        self.database.save_axfr_attempts(scan_id, &axfr_attempts)?;
        self.cap_seed_sources(domain, &mut sources, &mut warnings);

        self.emit(ProgressEvent::Phase {
            name: "candidats".to_owned(),
            detail: "fusion du passif, AXFR, apprentissage et wordlist".to_owned(),
        });
        let discovered_seed_count = sources.len();
        let first_batch_limit = if self.options.adaptive { 500 } else { 50_000 };
        let candidates = if self.options.passive_only {
            Vec::new()
        } else {
            if self.database.scan_candidate_count(scan_id)? == 0 {
                if let Some(path) = &self.options.wordlist {
                    self.database.persist_wordlist_candidates(
                        scan_id,
                        domain,
                        path,
                        self.options.max_words,
                    )?;
                }
                let queued = self.database.scan_candidate_count(scan_id)?.max(0) as usize;
                let prioritized = self.ordered_candidates(
                    domain,
                    sources.keys().cloned(),
                    self.options.max_words.saturating_sub(queued),
                )?;
                self.database.persist_scan_candidates(
                    scan_id,
                    domain,
                    &prioritized
                        .iter()
                        .map(|candidate| {
                            (
                                candidate.relative_name.clone(),
                                candidate.generator.clone(),
                                candidate.score,
                            )
                        })
                        .collect::<Vec<_>>(),
                )?;
                let queued = self.database.scan_candidate_count(scan_id)?.max(0) as usize;
                self.database.persist_prior_candidates_to_scan(
                    scan_id,
                    domain,
                    self.options.max_words.saturating_sub(queued),
                )?;
            }
            self.database
                .pending_scan_candidates(scan_id, first_batch_limit)?
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
        let first_wave_hosts = {
            let mut add_candidates = |wave: &[CandidateProposal], label: &str| {
                let mut hosts = Vec::new();
                for candidate in wave {
                    let fqdn = format!("{}.{domain}", candidate.relative_name);
                    if !sources.contains_key(&fqdn) {
                        hosts.push(fqdn.clone());
                    }
                    sources.entry(fqdn.clone()).or_default().extend([
                        label.to_owned(),
                        format!("candidate:{}", candidate.generator),
                    ]);
                    *generator_attempts
                        .entry(candidate.generator.clone())
                        .or_default() += 1;
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

        let initial_hosts = sources.keys().cloned().collect::<Vec<_>>();
        self.emit(ProgressEvent::Phase {
            name: "wildcard".to_owned(),
            detail: "sondes aléatoires sur la racine et les sous-zones observées".to_owned(),
        });
        let root_wildcard = self
            .wildcard_signature_cached(domain)
            .await
            .unwrap_or_else(indeterminate_wildcard_signature);
        let mut wildcard_by_parent = BTreeMap::from([(domain.to_owned(), root_wildcard.clone())]);
        let mut parent_by_host = HashMap::new();
        self.register_wildcard_parents(
            &initial_hosts,
            domain,
            &mut parent_by_host,
            &mut wildcard_by_parent,
            64,
        )
        .await;
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
        let (reclassified, purged_wildcards) = self.reclassify_cached_wildcard_matches(
            scan_id,
            domain,
            &root_wildcard,
            &wildcard_by_parent,
        )?;
        self.emit(ProgressEvent::Phase {
            name: "wildcard".to_owned(),
            detail: format!(
                "racine {}, {} sous-zone(s) wildcard, {} indéterminée(s), {} reclassé(s), {} faux positif(s) purgé(s)",
                if wildcard_signature_is_indeterminate(&root_wildcard) {
                    "indéterminée"
                } else if root_wildcard.is_empty() {
                    "normale"
                } else {
                    "wildcard"
                },
                wildcard_parent_count,
                indeterminate_parent_count,
                reclassified,
                purged_wildcards
            ),
        });
        self.emit(ProgressEvent::Phase {
            name: "DNS niveau 1".to_owned(),
            detail: format!("{} candidat(s) à valider", initial_hosts.len()),
        });
        let (initial_answers, mut cache_hits, mut network_resolved) = self
            .resolve_batch(
                scan_id,
                &initial_hosts,
                "DNS niveau 1",
                &started,
                &sources,
                &root_wildcard,
                &parent_by_host,
                &wildcard_by_parent,
            )
            .await?;
        self.database
            .mark_scan_candidates_done(scan_id, &initial_hosts)?;
        let mut answers: BTreeMap<String, ResolvedHost> = initial_answers
            .into_iter()
            .map(|answer| (answer.fqdn.clone(), answer))
            .collect();
        record_candidate_wave_results(&candidates, domain, &answers, &mut generator_successes);
        discard_failed_candidate_origins(&candidates, domain, &answers, &mut sources);
        let mut pipeline = DiscoveryPipeline::new(self.options.pipeline_budget);
        pipeline.mark_processed(answers.keys().cloned());
        let mut validation_rounds = 0_usize;
        let mut pipeline_names_validated = 0_usize;
        let mut graph_processed = BTreeSet::new();
        let mut web_processed = BTreeSet::new();
        let mut tls_processed = BTreeSet::new();

        let mut previous_positive = first_wave_hosts
            .iter()
            .filter(|host| answers.contains_key(*host))
            .count();
        let passive_positive = answers.len().saturating_sub(previous_positive);
        let mut wave_number = 2;
        while !self.options.passive_only && self.database.pending_scan_candidate_count(scan_id)? > 0
        {
            if self.options.adaptive
                && !should_expand_adaptive_wave(
                    root_wildcard.is_empty(),
                    previous_positive,
                    wave_number,
                    passive_positive,
                )
            {
                self.emit(ProgressEvent::Phase {
                    name: "adaptation".to_owned(),
                    detail: format!(
                        "arrêt naturel après {} mots: rendement DNS insuffisant",
                        generator_attempts.values().sum::<usize>()
                    ),
                });
                break;
            }
            let wave_limit = if wave_number == 2 { 1_500 } else { 50_000 };
            let wave_candidates = self
                .database
                .pending_scan_candidates(scan_id, wave_limit)?
                .into_iter()
                .map(|(relative_name, generator, score)| CandidateProposal {
                    relative_name,
                    generator,
                    score,
                })
                .collect::<Vec<_>>();
            if wave_candidates.is_empty() {
                break;
            }
            let mut wave_hosts = Vec::new();
            let mut wave_names = Vec::with_capacity(wave_candidates.len());
            for candidate in &wave_candidates {
                let fqdn = format!("{}.{domain}", candidate.relative_name);
                wave_names.push(fqdn.clone());
                if !sources.contains_key(&fqdn) {
                    wave_hosts.push(fqdn.clone());
                }
                sources.entry(fqdn).or_default().extend([
                    format!("dns-wave-{wave_number}"),
                    format!("candidate:{}", candidate.generator),
                ]);
                *generator_attempts
                    .entry(candidate.generator.clone())
                    .or_default() += 1;
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
            self.emit(ProgressEvent::Phase {
                name: format!("vague DNS {wave_number}"),
                detail: format!("{} nouveau(x) candidat(s)", wave_hosts.len()),
            });
            self.register_wildcard_parents(
                &wave_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
            )
            .await;
            let (wave_answers, wave_cache_hits, wave_network_resolved) = self
                .resolve_batch(
                    scan_id,
                    &wave_hosts,
                    &format!("DNS vague {wave_number}"),
                    &started,
                    &sources,
                    &root_wildcard,
                    &parent_by_host,
                    &wildcard_by_parent,
                )
                .await?;
            self.database
                .mark_scan_candidates_done(scan_id, &wave_names)?;
            cache_hits += wave_cache_hits;
            network_resolved += wave_network_resolved;
            previous_positive = wave_answers.len();
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

        let mut dns_edges = Vec::<DiscoveryEdge>::new();
        let mut child_zones = BTreeSet::new();
        let mut service_endpoints = Vec::<ServiceEndpoint>::new();
        if self.options.dns_graph {
            self.emit(ProgressEvent::Phase {
                name: "graphe DNS".to_owned(),
                detail: "MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB et zones enfants".to_owned(),
            });
            let graph_input = answers
                .keys()
                .take(self.options.graph_max_hosts)
                .cloned()
                .collect::<Vec<_>>();
            graph_processed.extend(graph_input.iter().cloned());
            let mut graph = discover_dns_graph(
                &self.dns,
                domain,
                graph_input,
                self.options.graph_max_hosts,
                self.options.service_discovery,
            )
            .await;
            for answer in answers.values() {
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
                    .flat_map(|answer| answer.records.iter())
                    .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
                    .filter_map(|record| record.value.parse().ok())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .take(self.options.ptr_max_ips)
                    .collect::<Vec<_>>();
                graph.queried += addresses.len();
                for (address, names) in self.dns.reverse_names(addresses).await {
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
            self.register_wildcard_parents(
                &graph_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
            )
            .await;
            if !graph_hosts.is_empty() {
                let (graph_answers, graph_cache_hits, graph_network_resolved) = self
                    .resolve_batch(
                        scan_id,
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
            let recursive_names = self
                .collect_passive_recursively(
                    domain,
                    child_zones.iter().cloned(),
                    &mut passive_zones_queried,
                    &mut sources,
                    &mut warnings,
                )
                .await?;
            let recursive_names = recursive_names
                .into_iter()
                .filter(|name| !answers.contains_key(name))
                .collect::<Vec<_>>();
            self.register_wildcard_parents(
                &recursive_names,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
            )
            .await;
            if !recursive_names.is_empty() {
                let (recursive_answers, recursive_cache_hits, recursive_network_resolved) = self
                    .resolve_batch(
                        scan_id,
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
            self.emit(ProgressEvent::Phase {
                name: "DNSSEC NSEC".to_owned(),
                detail: format!("{} zone(s), parcours borné et cache permanent", zones.len()),
            });
            let walks = discover_nsec(
                &self.database,
                &self.dns,
                domain,
                zones,
                self.options.nsec_timeout,
                self.options.nsec_refresh,
                self.options.nsec_max_names,
            )
            .await;
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
            self.register_wildcard_parents(
                &nsec_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
            )
            .await;
            if !nsec_hosts.is_empty() {
                let (nsec_answers, nsec_cache_hits, nsec_network_resolved) = self
                    .resolve_batch(
                        scan_id,
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
        if self.options.web_discovery {
            let mut web_hosts = answers.keys().cloned().collect::<Vec<_>>();
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
            self.emit(ProgressEvent::Phase {
                name: "web/JavaScript".to_owned(),
                detail: format!(
                    "{} hôte(s), {} asset(s) maximum par hôte",
                    web_hosts.len(),
                    self.options.web_assets_per_host
                ),
            });
            let web = discover_web(
                &self.database,
                domain,
                web_hosts.clone(),
                self.options.web_timeout,
                self.options.web_refresh,
                self.options.web_concurrency,
                self.options.web_max_bytes,
                self.options.web_assets_per_host,
            )
            .await?;
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
            self.register_wildcard_parents(
                &web_hosts_to_validate,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
            )
            .await;
            if !web_hosts_to_validate.is_empty() {
                let (web_answers, web_cache_hits, web_network_resolved) = self
                    .resolve_batch(
                        scan_id,
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
            web_observations = web.observations;
        }

        let mut tls_certificates = Vec::new();
        if self.options.tls_certificates {
            let endpoints = self.tls_endpoints(domain, &answers, &service_endpoints);
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
            let discovery = discover_tls_certificates(
                &self.database,
                domain,
                endpoints.clone(),
                self.options.tls_timeout,
                self.options.tls_refresh,
                self.options.tls_concurrency,
            )
            .await?;
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
            self.register_wildcard_parents(
                &tls_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                20,
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
                let web_remaining = self
                    .options
                    .web_max_hosts
                    .saturating_sub(web_processed.len());
                let tls_remaining = self
                    .options
                    .tls_max_hosts
                    .saturating_sub(tls_processed.len());
                let graph_hosts = answers
                    .keys()
                    .filter(|host| !graph_processed.contains(*host))
                    .take(graph_remaining)
                    .cloned()
                    .collect::<Vec<_>>();
                let web_hosts = answers
                    .keys()
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
                    let graph =
                        discover_dns_graph(&self.dns, domain, graph_hosts, graph_remaining, false)
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
                    let web = discover_web(
                        &self.database,
                        domain,
                        web_hosts.clone(),
                        self.options.web_timeout,
                        self.options.web_refresh,
                        self.options.web_concurrency,
                        self.options.web_max_bytes,
                        self.options.web_assets_per_host,
                    )
                    .await?;
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
                        .tls_endpoints(domain, &answers, &service_endpoints)
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
                        let discovery = discover_tls_certificates(
                            &self.database,
                            domain,
                            endpoints.clone(),
                            self.options.tls_timeout,
                            self.options.tls_refresh,
                            self.options.tls_concurrency,
                        )
                        .await?;
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
                self.register_wildcard_parents(
                    &new_hosts,
                    domain,
                    &mut parent_by_host,
                    &mut wildcard_by_parent,
                    20,
                )
                .await;
                let (new_answers, new_cache_hits, new_network_resolved) = self
                    .resolve_batch(
                        scan_id,
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
                let walks = discover_nsec(
                    &self.database,
                    &self.dns,
                    domain,
                    late_zones,
                    self.options.nsec_timeout,
                    self.options.nsec_refresh,
                    self.options.nsec_max_names,
                )
                .await;
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
                    self.register_wildcard_parents(
                        &hosts,
                        domain,
                        &mut parent_by_host,
                        &mut wildcard_by_parent,
                        20,
                    )
                    .await;
                    let (resolved, extra_cache_hits, extra_network) = self
                        .resolve_batch(
                            scan_id,
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
                        let signature = Self::applicable_wildcard_signature(
                            &answer.fqdn,
                            &root_wildcard,
                            &wildcard_by_parent,
                        );
                        signature.is_empty()
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
                if parents.is_empty() {
                    break;
                }
                self.emit(ProgressEvent::Phase {
                    name: format!("récursion niveau {depth}"),
                    detail: format!(
                        "{} parent(s), {} mot(s) par parent",
                        parents.len(),
                        recursive_words.len()
                    ),
                });
                wildcard_by_parent.extend(self.wildcard_signatures_cached(parents.clone()).await);
                let mut recursive_hosts = Vec::new();
                for parent in parents {
                    for word in &recursive_words {
                        let fqdn = format!("{word}.{parent}");
                        if sources.contains_key(&fqdn) {
                            continue;
                        }
                        sources
                            .entry(fqdn.clone())
                            .or_default()
                            .insert("dns-recursive".to_owned());
                        parent_by_host.insert(fqdn.clone(), parent.clone());
                        attempted_words.insert(word.clone());
                        recursive_hosts.push(fqdn);
                    }
                }
                let phase = format!("DNS niveau {depth}");
                let (round_answers, round_cache_hits, round_network_resolved) = self
                    .resolve_batch(
                        scan_id,
                        &recursive_hosts,
                        &phase,
                        &started,
                        &sources,
                        &root_wildcard,
                        &parent_by_host,
                        &wildcard_by_parent,
                    )
                    .await?;
                cache_hits += round_cache_hits;
                network_resolved += round_network_resolved;
                let round_yield = round_answers.len();
                for answer in round_answers {
                    answers.insert(answer.fqdn.clone(), answer);
                }
                if self.options.adaptive && round_yield < 2 {
                    self.emit(ProgressEvent::Phase {
                        name: "adaptation".to_owned(),
                        detail: format!(
                            "récursion arrêtée au niveau {depth}: rendement {round_yield}"
                        ),
                    });
                    break;
                }
            }
        }

        // Later discovery phases can expose a child zone that was not present
        // during the initial wildcard sampling. Re-run the persistent
        // reclassification once all sampled zones are known.
        let (final_reclassified, final_purged) = self.reclassify_cached_wildcard_matches(
            scan_id,
            domain,
            &root_wildcard,
            &wildcard_by_parent,
        )?;
        if final_reclassified > 0 || final_purged > 0 {
            self.emit(ProgressEvent::Phase {
                name: "wildcard final".to_owned(),
                detail: format!(
                    "{final_reclassified} ancien(s) résultat(s) reclassé(s), {final_purged} faux positif(s) purgé(s)"
                ),
            });
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
        findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));

        self.database.record_generator_results(
            domain,
            &generator_attempts,
            &generator_successes,
        )?;

        self.emit(ProgressEvent::Phase {
            name: "SQLite".to_owned(),
            detail: "inventaire, cache et apprentissage local".to_owned(),
        });
        let mut successful_words = BTreeSet::new();
        let mut successful_patterns = BTreeSet::new();
        for finding in &findings {
            if finding.wildcard {
                continue;
            }
            successful_words.extend(
                labels_from_name(&finding.fqdn, domain)
                    .into_iter()
                    .filter(|label| learnable_label(label)),
            );
            if let Some(relative) = finding.fqdn.strip_suffix(&format!(".{domain}"))
                && learnable_relative_name(relative)
            {
                successful_patterns.insert(relative.to_owned());
            }
        }
        self.database
            .record_word_results(domain, &attempted_words, &successful_words)?;
        self.database
            .record_patterns(domain, &successful_patterns)?;
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
        let resolver_metrics = self.dns.take_metrics();
        self.database.store_resolver_metrics(&resolver_metrics)?;
        self.database
            .store_pipeline_metrics(scan_id, &pipeline_metrics)?;
        let duration_ms = started.elapsed().as_millis();
        let candidate_count =
            discovered_seed_count.saturating_add(generator_attempts.values().sum::<usize>());
        self.database.finalize_scan(
            scan_id,
            candidate_count,
            findings.len(),
            cache_hits,
            duration_ms,
            &warnings,
        )?;
        Ok(ScanResult {
            scan_id,
            domain: domain.to_owned(),
            candidates: candidate_count,
            resolved_from_network: network_resolved,
            cache_hits,
            duration_ms,
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
            warnings,
        })
    }
}

#[derive(Debug, serde::Serialize)]
pub struct RefreshResult {
    pub scan_id: i64,
    pub domain: String,
    pub checked: usize,
    pub active: usize,
    pub inactive: usize,
    pub unverified: usize,
    pub indeterminate: usize,
    pub purged_wildcards: usize,
    pub duration_ms: u128,
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
    let domain = normalize_domain(target)?;
    let hosts = database.known_subdomains(Some(&domain), true)?;
    let classification_hosts = hosts
        .iter()
        .cloned()
        .chain(database.positive_cache_names(&domain)?)
        .collect::<BTreeSet<_>>();
    let scan_id = database.create_scan(&domain, &json!({"mode": "refresh"}))?;
    let options_hash = domain_hash(&format!("refresh:v2:{ttl_cap}:{negative_ttl}"));
    database.upsert_checkpoint(scan_id, &domain, "running", &options_hash)?;
    let checkpoint_heartbeat = CheckpointHeartbeat::start(
        database.clone(),
        scan_id,
        domain.clone(),
        options_hash,
        Duration::from_secs(30),
    );
    let started = Instant::now();
    let mut run_guard = ScanRunGuard::new(database.clone(), scan_id, started);

    let root_wildcard =
        wildcard_profile_cached(database, dns, &domain, Duration::from_secs(6 * 3_600), true)
            .await
            .unwrap_or_else(indeterminate_wildcard_signature);
    let mut wildcard_by_parent = BTreeMap::from([(domain.clone(), root_wildcard.clone())]);
    let mut parent_counts = HashMap::<String, usize>::new();
    for host in &classification_hosts {
        for parent in Scanner::ancestor_zones(host, &domain) {
            *parent_counts.entry(parent).or_default() += 1;
        }
    }
    let mut parents = parent_counts.into_iter().collect::<Vec<_>>();
    parents.sort_by_key(|(parent, count)| {
        (Reverse(*count), parent.split('.').count(), parent.clone())
    });
    let profiles = stream::iter(parents.into_iter().take(64).map(|(parent, _)| parent))
        .map(|parent| async move {
            let signature = wildcard_profile_cached(
                database,
                dns,
                &parent,
                Duration::from_secs(6 * 3_600),
                true,
            )
            .await
            .unwrap_or_else(indeterminate_wildcard_signature);
            (parent, signature)
        })
        .buffer_unordered(16)
        .collect::<BTreeMap<_, _>>()
        .await;
    wildcard_by_parent.extend(profiles);
    let wildcard_hosts = classification_hosts
        .iter()
        .filter(|host| {
            wildcard_signature_is_confirmed(Scanner::applicable_wildcard_signature(
                host,
                &root_wildcard,
                &wildcard_by_parent,
            ))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let uncertain_wildcard_hosts = classification_hosts
        .iter()
        .filter(|host| {
            wildcard_signature_is_indeterminate(Scanner::applicable_wildcard_signature(
                host,
                &root_wildcard,
                &wildcard_by_parent,
            ))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let purged_wildcards = database
        .purge_confirmed_wildcard_false_positives(
            &domain,
            &wildcard_hosts.iter().cloned().collect::<Vec<_>>(),
        )?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let retained_wildcard_hosts = wildcard_hosts
        .difference(&purged_wildcards)
        .cloned()
        .collect::<BTreeSet<_>>();
    let ambiguous_hosts = retained_wildcard_hosts
        .union(&uncertain_wildcard_hosts)
        .cloned()
        .collect::<Vec<_>>();
    database.mark_unverified(Some(scan_id), &ambiguous_hosts, "refresh_wildcard_zone")?;

    let outcomes = dns
        .resolve_many_classified_with_progress(hosts.clone(), |_| {})
        .await;
    let mut resolved = Vec::new();
    let mut wildcard_resolved = Vec::new();
    let mut inactive = Vec::new();
    let mut indeterminate = Vec::new();
    for outcome in outcomes {
        match outcome {
            DnsResolutionOutcome::Positive(answer) if purged_wildcards.contains(&answer.fqdn) => {}
            DnsResolutionOutcome::Positive(answer)
                if retained_wildcard_hosts.contains(&answer.fqdn)
                    || uncertain_wildcard_hosts.contains(&answer.fqdn) =>
            {
                wildcard_resolved.push(answer);
            }
            DnsResolutionOutcome::Positive(answer) => resolved.push(answer),
            DnsResolutionOutcome::Negative { fqdn } if purged_wildcards.contains(&fqdn) => {}
            DnsResolutionOutcome::Negative { fqdn }
                if retained_wildcard_hosts.contains(&fqdn)
                    || uncertain_wildcard_hosts.contains(&fqdn) =>
            {
                indeterminate.push(fqdn);
            }
            DnsResolutionOutcome::Negative { fqdn } => inactive.push(fqdn),
            DnsResolutionOutcome::Indeterminate { fqdn } if purged_wildcards.contains(&fqdn) => {}
            DnsResolutionOutcome::Indeterminate { fqdn } => indeterminate.push(fqdn),
        }
    }
    if let Some(trusted_dns) = trusted_dns {
        let validations = stream::iter(resolved)
            .map(|answer| async move {
                let fqdn = answer.fqdn.clone();
                (
                    fqdn.clone(),
                    trusted_dns.resolve_host_consensus_classified(&fqdn).await,
                )
            })
            .buffer_unordered(32)
            .collect::<Vec<_>>()
            .await;
        resolved = Vec::new();
        for (fqdn, outcome) in validations {
            match outcome {
                DnsResolutionOutcome::Positive(mut answer) => {
                    answer.authoritative_validation =
                        trusted_dns.authoritative_confirms(&answer.fqdn).await;
                    resolved.push(answer);
                }
                DnsResolutionOutcome::Negative { .. }
                | DnsResolutionOutcome::Indeterminate { .. } => indeterminate.push(fqdn),
            }
        }
    }
    resolved.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
    wildcard_resolved.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));
    inactive.sort();
    inactive.dedup();
    indeterminate.sort();
    indeterminate.dedup();
    let mut cached_answers = resolved.clone();
    cached_answers.extend(wildcard_resolved.iter().cloned());
    database.update_cache_outcomes(
        Some(scan_id),
        &cached_answers,
        &inactive,
        &indeterminate,
        negative_ttl,
    )?;
    let mut findings: Vec<Finding> = resolved
        .into_iter()
        .map(|answer| Finding {
            fqdn: answer.fqdn,
            records: answer.records,
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
        })
        .collect();
    findings.extend(wildcard_resolved.into_iter().map(|answer| Finding {
        fqdn: answer.fqdn,
        records: answer.records,
        sources: BTreeSet::from(["refresh:wildcard".to_owned()]),
        wildcard: true,
        from_cache: false,
        confidence: assess_confidence(
            &BTreeSet::from(["refresh:wildcard".to_owned()]),
            true,
            crate::model::ObservationState::Unverified,
            true,
        ),
        state: crate::model::ObservationState::Unverified,
        last_verified_at: None,
        evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
        authoritative_validation: false,
    }));
    database.store_resolver_metrics(&dns.take_metrics())?;
    if let Some(trusted_dns) = trusted_dns {
        database.store_resolver_metrics(&trusted_dns.take_metrics())?;
    }
    database.persist_findings(scan_id, &domain, &findings, ttl_cap)?;
    let duration_ms = started.elapsed().as_millis();
    let warnings = (!indeterminate.is_empty())
        .then(|| {
            format!(
                "{} nom(s) indéterminé(s), état précédent préservé",
                indeterminate.len()
            )
        })
        .into_iter()
        .collect::<Vec<_>>();
    checkpoint_heartbeat.stop().await;
    database.finalize_scan(
        scan_id,
        hosts.len(),
        findings.len(),
        0,
        duration_ms,
        &warnings,
    )?;
    run_guard.disarm();
    Ok(RefreshResult {
        scan_id,
        domain,
        checked: hosts.len(),
        active: findings
            .iter()
            .filter(|finding| finding.state == crate::model::ObservationState::Live)
            .count(),
        inactive: inactive.len(),
        unverified: findings
            .iter()
            .filter(|finding| finding.state == crate::model::ObservationState::Unverified)
            .count(),
        indeterminate: indeterminate.len(),
        purged_wildcards: purged_wildcards.len(),
        duration_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ScanRunGuard, Scanner, cache_requires_revalidation, external_pause_status,
        external_retry_after_seconds, should_expand_adaptive_wave,
        should_retry_otx_after_key_added,
    };
    use crate::db::Database;
    use crate::model::ResolvedHost;
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::{Duration, Instant};

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
        ));
        assert!(cache_requires_revalidation(
            &answer,
            Duration::from_secs(99),
            1_100,
        ));
        assert!(cache_requires_revalidation(&answer, Duration::ZERO, 1_000,));
        answer.last_verified_at = None;
        assert!(cache_requires_revalidation(
            &answer,
            Duration::from_secs(3_600),
            1_100,
        ));
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
    fn wildcard_sampling_counts_intermediate_ancestors() {
        assert_eq!(
            Scanner::ancestor_zones("a.b.prod.example.com", "example.com"),
            vec!["b.prod.example.com", "prod.example.com"]
        );
    }

    #[test]
    fn adaptive_waves_require_two_recent_hits_after_the_second_wave() {
        assert!(should_expand_adaptive_wave(true, 0, 2, 5));
        assert!(!should_expand_adaptive_wave(true, 1, 3, 10));
        assert!(should_expand_adaptive_wave(true, 2, 3, 0));
        assert!(!should_expand_adaptive_wave(false, 20, 2, 20));
    }

    #[test]
    fn adding_an_otx_key_bypasses_only_the_anonymous_rate_limit_cooldown() {
        assert!(should_retry_otx_after_key_added(
            true,
            Some("OTX limite l'accès anonyme (HTTP 429)")
        ));
        assert!(!should_retry_otx_after_key_added(
            false,
            Some("OTX limite l'accès anonyme (HTTP 429)")
        ));
        assert!(!should_retry_otx_after_key_added(
            true,
            Some("OTX refuse la clé fournie (HTTP 429)")
        ));
        assert!(!should_retry_otx_after_key_added(
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
            "quota externe, reprise dans 2 min, mémoire permanente"
        );
        assert_eq!(external_retry_after_seconds("HTTP 503"), None);
    }
}
