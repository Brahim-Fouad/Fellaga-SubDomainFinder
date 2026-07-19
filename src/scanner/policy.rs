use super::*;

#[derive(Debug, Clone)]
pub(super) struct WildcardProfileObservation {
    pub(super) signature: Option<BTreeSet<String>>,
    pub(super) current_probe_reliable: bool,
}

#[derive(Debug, Default)]
pub(super) struct WildcardProfilesBatch {
    pub(super) signatures: BTreeMap<String, BTreeSet<String>>,
    pub(super) reliable_zones: BTreeSet<String>,
    pub(super) deadline_exhausted: bool,
}

pub(super) fn wildcard_profile_after_probe(
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

pub(super) async fn wildcard_profile_observed(
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

pub(super) fn wildcard_cache_algorithm_is_current(
    cached_version: i64,
    required_version: i64,
) -> bool {
    cached_version >= required_version
}

pub(super) fn unprofiled_deepest_parents(
    parents: impl IntoIterator<Item = String>,
    wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
    selected: &BTreeSet<String>,
) -> BTreeSet<String> {
    parents
        .into_iter()
        .filter(|parent| {
            wildcard_by_parent
                .get(parent)
                .is_none_or(wildcard_signature_is_deferred)
                && !selected.contains(parent)
        })
        .collect()
}

const WILDCARD_INDETERMINATE: &str = "FELLAGA:WILDCARD_INDETERMINATE";
const WILDCARD_DEFERRED: &str = "FELLAGA:WILDCARD_DEFERRED";

pub(super) fn indeterminate_wildcard_signature() -> BTreeSet<String> {
    BTreeSet::from([WILDCARD_INDETERMINATE.to_owned()])
}

pub(super) fn deferred_wildcard_signature() -> BTreeSet<String> {
    BTreeSet::from([WILDCARD_DEFERRED.to_owned()])
}

pub(super) fn wildcard_signature_is_indeterminate(signature: &BTreeSet<String>) -> bool {
    signature.contains(WILDCARD_INDETERMINATE) || wildcard_signature_is_deferred(signature)
}

pub(super) fn wildcard_signature_is_deferred(signature: &BTreeSet<String>) -> bool {
    signature.contains(WILDCARD_DEFERRED)
}

pub(super) fn wildcard_signature_is_confirmed(signature: &BTreeSet<String>) -> bool {
    !signature.is_empty() && !wildcard_signature_is_indeterminate(signature)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WildcardParentRegistration {
    pub(super) deadline_exhausted: bool,
    pub(super) deferred_parents: usize,
}

pub(super) fn wilson_upper_bound(successes: usize, trials: usize) -> f64 {
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

pub(super) fn should_expand_adaptive_wave(
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

pub(super) fn source_requires_api_key(source: &str) -> bool {
    source_metadata(source).authentication == "required"
}

pub(super) fn is_missing_api_key_error(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains(" absent pour la source ")
        || error.contains("missing api key for source")
        || error.contains("api key missing for source")
        || error.contains("clé api absente pour la source")
}

pub(super) fn is_preflight_auth_error(error: &str) -> bool {
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

pub(super) fn should_retry_source_after_key_added(
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

pub(super) fn cache_requires_revalidation(
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

pub(super) fn verification_cutoff(now: i64, verification_max_age: Duration) -> i64 {
    i64::try_from(verification_max_age.as_secs())
        .map_or(i64::MIN, |max_age| now.saturating_sub(max_age))
}

pub(super) fn was_recently_verified(
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

pub(super) async fn enrich_authoritative_answers(
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

pub(super) fn external_retry_after_seconds(error: &str) -> Option<u64> {
    let (_, suffix) = error.split_once("Retry-After=")?;
    let digits = suffix
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty()).then(|| digits.parse().ok()).flatten()
}

pub(super) fn external_deferral_seconds(error: &str) -> Option<u64> {
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

pub(super) fn source_error_is_deferred(error: &str) -> bool {
    external_deferral_seconds(error).is_some() || is_preflight_auth_error(error)
}

pub(super) fn external_pause_status(retry_in_seconds: i64) -> String {
    let minutes = retry_in_seconds.max(1).saturating_add(59) / 60;
    format!("source externe différée, reprise dans {minutes} min, mémoire permanente")
}

pub(super) fn record_candidate_wave_results(
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

pub(super) fn discard_failed_candidate_origins(
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

pub(super) fn candidate_refill_capacity(
    queued: usize,
    total: usize,
    target_queued: usize,
    max_words: usize,
) -> usize {
    target_queued
        .saturating_sub(queued)
        .min(max_words.saturating_sub(total))
}

pub(super) fn high_value_window_needs_materialization(capacity: usize, exhausted: bool) -> bool {
    capacity > 0 && !exhausted
}

pub(super) fn high_value_window_persist_limit(
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
pub(super) const MUTATION_OBSERVATION_SCAN_CAP: usize = 20_000;
pub(super) const MUTATION_OBSERVATION_KEEP_CAP: usize = 5_000;

#[derive(Clone, Copy)]
pub(super) struct MutationObservationRef<'a> {
    fqdn: &'a str,
    parent_relative: &'a str,
    shape: u8,
    evidence_score: i64,
}

pub(super) fn mutation_observation_shape(relative: &str) -> u8 {
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

pub(super) fn select_bounded_mutation_observations<'a>(
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

pub(super) fn seed_candidate_priority(sources: &BTreeSet<String>) -> i64 {
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
pub(super) fn merge_ct_fallback_names(
    domain: &str,
    indexed: Vec<String>,
    cached: Vec<String>,
) -> Vec<String> {
    indexed
        .into_iter()
        .chain(cached)
        .filter_map(|name| normalize_observed_name(&name, domain))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
pub(super) fn materialize_ct_fallback_bounded(
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

pub(super) fn source_bootstrap_score(source: &str) -> i64 {
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
    // High-volume providers need the full phase window on a cold database.
    // Their learned marginal yield replaces this bootstrap bonus after the
    // first run, so local evidence remains authoritative over time.
    let cold_start_yield = match source {
        "submd" => 550,
        "thc" => 450,
        _ => 0,
    };
    family + cost + cold_start_yield + if metadata.experimental { -150 } else { 50 }
}

const MAX_PASSIVE_REQUEST_CONCURRENCY: usize = 32;

pub(super) fn effective_passive_concurrency(configured: usize) -> usize {
    configured.clamp(1, MAX_PASSIVE_REQUEST_CONCURRENCY)
}

pub(super) fn passive_connector_working_set_limit(max_passive: usize, concurrency: usize) -> usize {
    let concurrency = effective_passive_concurrency(concurrency);
    max_passive
        .saturating_add(concurrency - 1)
        .saturating_div(concurrency)
}

#[cfg(test)]
pub(super) fn merge_passive_names_bounded(
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

pub(super) fn passive_origin_matches_source(origin: &str, source: &str) -> bool {
    origin
        .strip_prefix("passive:")
        .and_then(|origin| origin.split(':').next())
        == Some(source)
}

pub(super) fn merge_passive_source_names_bounded(
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

pub(super) fn refill_passive_union_from_cache(
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

pub(super) fn automatic_bulk_source_limit(max_passive: usize) -> usize {
    max_passive
        .saturating_div(10)
        .clamp(500, 10_000)
        .min(max_passive)
}

pub(super) fn cap_exclusive_bulk_source_names(
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

pub(super) fn seed_share(batch_limit: usize, active_candidates_enabled: bool) -> usize {
    if !active_candidates_enabled {
        return batch_limit;
    }
    batch_limit.saturating_mul(3).saturating_div(4).max(1)
}

pub(super) fn late_ct_seed_reserve(max_passive: usize, ct_task_pending: bool) -> usize {
    if !ct_task_pending || max_passive <= 1 {
        return 0;
    }
    max_passive.saturating_div(5).clamp(1, 2_000)
}

pub(super) type CtTaskJoinResult =
    std::result::Result<Result<(CtMonitorResult, Vec<String>)>, tokio::task::JoinError>;

pub(super) async fn finish_pending_ct_task_after_grace_with_hook<F>(
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

pub(super) async fn finish_pending_ct_task_after_grace(
    tasks: &mut tokio::task::JoinSet<Result<(CtMonitorResult, Vec<String>)>>,
    grace: Duration,
) -> (Option<CtTaskJoinResult>, bool) {
    finish_pending_ct_task_after_grace_with_hook(tasks, grace, std::future::ready(())).await
}

pub(super) async fn finish_pending_ct_task(
    tasks: &mut tokio::task::JoinSet<Result<(CtMonitorResult, Vec<String>)>>,
    final_grace: Option<Duration>,
) -> (Option<CtTaskJoinResult>, bool) {
    if let Some(grace) = final_grace {
        return finish_pending_ct_task_after_grace(tasks, grace).await;
    }

    // A zero CT phase timeout means that only the log/entry/backfill caps stop
    // the task. Waiting here preserves the parallel overlap with DNS without
    // discarding a structurally bounded CT result at the end of the scan.
    let joined = tasks.join_next().await;
    let completed_without_result = joined.is_none();
    (joined, completed_without_result)
}

pub(super) fn phase_deadline(remaining: Option<Duration>) -> Option<tokio::time::Instant> {
    remaining.map(|remaining| {
        let now = tokio::time::Instant::now();
        // Fail closed for invalid library-provided durations instead of
        // panicking or silently turning a bounded phase into an unbounded one.
        now.checked_add(remaining).unwrap_or(now)
    })
}

pub(super) fn consume_phase_budget(remaining: &mut Option<Duration>, elapsed: Duration) {
    if let Some(budget) = remaining {
        *budget = budget.saturating_sub(elapsed);
    }
}

pub(super) fn active_candidate_budget_exhausted(remaining: Option<Duration>) -> bool {
    remaining.is_some_and(|remaining| remaining.is_zero())
}

pub(super) fn active_candidate_work_allowed(remaining: Option<Duration>) -> bool {
    !active_candidate_budget_exhausted(remaining)
}

pub(super) fn active_resume_required(
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

pub(super) fn candidate_uses_active_budget(_candidate: &CandidateProposal) -> bool {
    true
}

pub(super) fn candidate_uses_discovery_fast_path(
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
