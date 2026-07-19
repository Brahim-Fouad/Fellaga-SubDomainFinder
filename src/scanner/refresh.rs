use super::*;

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
            max_runtime: Duration::ZERO,
            wildcard_phase_timeout: Duration::ZERO,
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

pub(super) struct RefreshRunGuard {
    database: Database,
    scan_id: i64,
    started: Instant,
    total: usize,
    checked: usize,
    found: usize,
    armed: bool,
}

impl RefreshRunGuard {
    pub(super) fn new(database: Database, scan_id: i64, started: Instant, total: usize) -> Self {
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

    pub(super) fn update(&mut self, checked: usize, found: usize) {
        self.checked = checked;
        self.found = found;
    }

    pub(super) fn disarm(&mut self) {
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

pub(super) async fn before_refresh_deadline<T, F>(
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

pub(super) fn refresh_deadline(max_runtime: Duration) -> Option<tokio::time::Instant> {
    (!max_runtime.is_zero()).then(|| {
        let now = tokio::time::Instant::now();
        now.checked_add(max_runtime).unwrap_or(now)
    })
}

pub(super) fn capped_phase_deadline(
    global: Option<tokio::time::Instant>,
    phase_timeout: Duration,
) -> Option<tokio::time::Instant> {
    let phase = refresh_deadline(phase_timeout);
    match (global, phase) {
        (Some(global), Some(phase)) => Some(global.min(phase)),
        (Some(global), None) => Some(global),
        (None, Some(phase)) => Some(phase),
        (None, None) => None,
    }
}

pub(super) fn refresh_allows_wildcard_purge(status: &str, classification_reliable: bool) -> bool {
    status == "completed" && classification_reliable
}

pub(super) fn refresh_can_demote_wildcard_ambiguity(classification_reliable: bool) -> bool {
    classification_reliable
}

pub(super) struct RefreshCleanupCancellation {
    cancelled: Arc<AtomicBool>,
    completion: Option<mpsc::Receiver<()>>,
    armed: bool,
}

impl RefreshCleanupCancellation {
    pub(super) fn new(cancelled: Arc<AtomicBool>, completion: mpsc::Receiver<()>) -> Self {
        Self {
            cancelled,
            completion: Some(completion),
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
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

pub(super) struct SignalRefreshCleanupCompletion(pub(super) Option<mpsc::SyncSender<()>>);

impl Drop for SignalRefreshCleanupCompletion {
    fn drop(&mut self) {
        if let Some(completion) = self.0.take() {
            let _ = completion.send(());
        }
    }
}

pub(super) async fn apply_completed_refresh_wildcard_cleanup(
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

pub(super) fn record_bounded_parent_candidate(
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

pub(super) fn refresh_wildcard_profile_is_reliable(profile: Option<&BTreeSet<String>>) -> bool {
    profile.is_some_and(|signature| !wildcard_signature_is_indeterminate(signature))
}

pub(super) fn refresh_wildcard_observation_is_reliable(
    observation: Option<&WildcardProfileObservation>,
) -> bool {
    observation.is_some_and(|observation| {
        observation.current_probe_reliable
            && refresh_wildcard_profile_is_reliable(observation.signature.as_ref())
    })
}

pub(super) fn refresh_parent_selection_is_complete(
    candidate_count: usize,
    overflowed: bool,
) -> bool {
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
        wildcard_deadline,
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
    let mut wildcard_deadline_reached = root_result.is_none() && wildcard_deadline.is_some();
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
        if wildcard_deadline
            .as_ref()
            .is_some_and(|deadline| *deadline <= tokio::time::Instant::now())
        {
            setup_timed_out = true;
            wildcard_deadline_reached = true;
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
        if wildcard_deadline
            .as_ref()
            .is_some_and(|deadline| *deadline <= tokio::time::Instant::now())
        {
            setup_timed_out = true;
            wildcard_deadline_reached = true;
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
    while profiles.len() < selected_parent_set.len() {
        match before_refresh_deadline(wildcard_deadline, pending_profiles.next()).await {
            Some(Some((parent, observation))) => {
                if !refresh_wildcard_observation_is_reliable(Some(&observation)) {
                    wildcard_phase_complete = false;
                }
                let signature = observation
                    .signature
                    .unwrap_or_else(indeterminate_wildcard_signature);
                profiles.insert(parent, signature);
            }
            Some(None) => {
                wildcard_phase_complete = false;
                break;
            }
            None => {
                wildcard_phase_complete = false;
                wildcard_deadline_reached = true;
                break;
            }
        }
    }
    // The optional deadline wrapper cancels only the current `next()` future.
    // Drop the buffered stream as well so unfinished wildcard probes release
    // DNS/rate-limit resources before inventory validation starts.
    drop(pending_profiles);
    let completed_parents = profiles.keys().cloned().collect::<BTreeSet<_>>();
    for parent in selected_parent_set.difference(&completed_parents) {
        profiles.insert(parent.clone(), indeterminate_wildcard_signature());
    }
    if wildcard_deadline_reached {
        warnings.push(
            "limite cumulative atteinte pendant la classification wildcard; profils manquants traités comme indéterminés"
                .to_owned(),
        );
    } else if !wildcard_phase_complete {
        warnings.push(
            "classification wildcard incomplète; profils indéterminés conservés et purge désactivée"
                .to_owned(),
        );
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
    if timed_out && global_deadline.is_some() {
        warnings.push(format!(
            "limite cumulative globale atteinte après {checked}/{total} nom(s); état des noms non traités préservé"
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
                    "limite cumulative globale atteinte pendant la purge wildcard atomique; aucune suppression appliquée"
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
