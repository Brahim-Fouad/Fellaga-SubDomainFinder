use super::*;

struct AbortOnDropJoinHandle<T> {
    handle: tokio::task::JoinHandle<T>,
}

impl<T> AbortOnDropJoinHandle<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self { handle }
    }

    async fn join(&mut self) -> std::result::Result<T, tokio::task::JoinError> {
        (&mut self.handle).await
    }
}

impl<T> Drop for AbortOnDropJoinHandle<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub(super) async fn passive_sqlite_operation<T, F>(context: &'static str, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .with_context(|| format!("{context}: travailleur SQLite interrompu"))?
}

pub(super) fn passive_sqlite_callback<T>(operation: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            // Numeric pagination exposes synchronous callbacks. `block_in_place`
            // lets Tokio replace this connector worker while SQLite waits, so
            // the scanner task can keep rendering its heartbeat.
            tokio::task::block_in_place(operation)
        }
        _ => operation(),
    }
}

async fn release_passive_lease(lease: Arc<PassiveRefreshLeaseGuard>) {
    let _ = tokio::task::spawn_blocking(move || lease.release_or_schedule()).await;
}

pub(super) const fn passive_completion_phase_required(
    phase_timed_out: bool,
    refresh_total: usize,
    refresh_finished: usize,
) -> bool {
    !phase_timed_out && refresh_total > 0 && refresh_finished == refresh_total
}

pub(super) fn passive_active_source_status(
    active_sources: &BTreeMap<String, Instant>,
    refresh_finished: usize,
    refresh_total: usize,
) -> String {
    let active = active_sources.len();
    let queued = refresh_total.saturating_sub(refresh_finished.saturating_add(active));
    let Some((source, started)) = active_sources.iter().min_by_key(|(_, started)| **started) else {
        return if queued > 0 {
            format!("{queued} en attente")
        } else {
            "0 active".to_owned()
        };
    };
    let activity = if active == 1 {
        String::new()
    } else {
        format!("{active} act · ")
    };
    let source_timeout = source_policy(source).total_timeout.as_secs();
    let source_elapsed = started.elapsed().as_secs();
    let queued = if queued > 0 {
        format!(" · {queued} file")
    } else {
        String::new()
    };
    format!("{activity}{source} a={source_elapsed}s/{source_timeout}s{queued}")
}

pub(super) fn passive_persistence_status(
    persisted_pages: usize,
    persisted_names: usize,
    novel_names: usize,
) -> String {
    format!("{persisted_pages}p · {persisted_names} lus · +{novel_names}")
}

pub(super) fn passive_source_warning(source: &str, message: &str) -> String {
    let message = message.trim();
    let prefix = format!("{source}:");
    if message.starts_with(&prefix) {
        message.to_owned()
    } else {
        format!("{source}: {message}")
    }
}

pub(super) fn passive_local_deadline(
    global_deadline: Option<Instant>,
    local_window: Duration,
) -> Instant {
    let local_deadline = Instant::now() + local_window;
    global_deadline.map_or(local_deadline, |global| global.min(local_deadline))
}

pub(super) fn passive_bookkeeping_result<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_passive_bookkeeping_deferred_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn passive_bookkeeping_warning(source: &str) -> String {
    format!(
        "{source}: statistiques/cache SQLite occupés; mise à jour interne différée, observations déjà validées conservées"
    )
}

fn defer_passive_bookkeeping(
    scanner: &Scanner,
    source: &str,
    warnings: &mut Vec<String>,
    deferred: &mut bool,
) {
    if *deferred {
        return;
    }
    let warning = passive_bookkeeping_warning(source);
    scanner.emit(ProgressEvent::Warning(warning.clone()));
    warnings.push(warning);
    *deferred = true;
}

impl Scanner {
    pub(super) async fn collect_passive(
        &self,
        domain: &str,
        contact_root_domain: &str,
        passive_deadline: Option<tokio::time::Instant>,
        sources: &mut BTreeMap<String, BTreeSet<String>>,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let passive_started = Instant::now();
        let passive_phase_name = if domain == contact_root_domain {
            "passif".to_owned()
        } else {
            format!("passif {domain}")
        };
        let configured_source_count = self.options.passive_sources.len();
        self.emit(ProgressEvent::Phase {
            name: passive_phase_name.clone(),
            detail: format!("cache local 0/{configured_source_count} · préparation"),
        });
        let passive_storage_deadline = passive_deadline.map(|deadline| {
            Instant::now() + deadline.saturating_duration_since(tokio::time::Instant::now())
        });
        let health_deadline =
            passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
        let mut preflight_bookkeeping_deferred = false;
        let now = now_epoch();
        let freshness = self.options.passive_refresh.as_secs().min(i64::MAX as u64) as i64;
        let passive_concurrency = effective_passive_concurrency(self.options.passive_concurrency);
        let connector_working_set_limit =
            passive_connector_working_set_limit(self.options.max_passive, passive_concurrency);
        let mut passive_union_omitted = 0_usize;
        // Candidate-wave adaptivity and provider health are independent. An
        // exhaustive brute-force scan must not repeatedly block on a provider
        // that the automatic source scheduler already knows is unhealthy.
        let mut cooldowns = if self.options.automatic_source_selection {
            match passive_bookkeeping_result(
                self.database
                    .source_cooldowns_until(Duration::from_secs(24 * 3_600), health_deadline),
            )? {
                Some(cooldowns) => cooldowns,
                None => {
                    defer_passive_bookkeeping(
                        self,
                        "préparation passive",
                        warnings,
                        &mut preflight_bookkeeping_deferred,
                    );
                    BTreeSet::new()
                }
            }
        } else {
            BTreeSet::new()
        };
        let diagnostics = match passive_bookkeeping_result(
            self.database
                .source_diagnostics_until(Duration::from_secs(24 * 3_600), health_deadline),
        )? {
            Some(diagnostics) => diagnostics,
            None => {
                defer_passive_bookkeeping(
                    self,
                    "préparation passive",
                    warnings,
                    &mut preflight_bookkeeping_deferred,
                );
                BTreeMap::new()
            }
        };
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
                let retry_until =
                    match passive_bookkeeping_result(self.database.source_metadata_until(
                        &key,
                        Duration::from_secs(365 * 24 * 3_600),
                        health_deadline,
                    ))? {
                        Some(value) => value,
                        None => {
                            defer_passive_bookkeeping(
                                self,
                                "préparation passive",
                                warnings,
                                &mut preflight_bookkeeping_deferred,
                            );
                            break;
                        }
                    };
                if let Some(retry_until) = retry_until
                    .and_then(|value| value.parse::<i64>().ok())
                    .filter(|retry_until| *retry_until > now)
                {
                    external_pauses.insert(source.clone(), retry_until);
                }
            }
        }
        let mut refresh = Vec::new();
        let mut cache_preflight_deferred = preflight_bookkeeping_deferred;
        let cache_deadline =
            passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
        for (source_index, source) in self.options.passive_sources.iter().enumerate() {
            self.emit(ProgressEvent::Phase {
                name: passive_phase_name.clone(),
                detail: format!("cache local {source_index}/{configured_source_count} · {source}"),
            });
            let cached =
                match passive_bookkeeping_result(self.database.passive_cache_bounded_until(
                    domain,
                    source,
                    connector_working_set_limit,
                    cache_deadline,
                ))? {
                    Some(cached) => cached,
                    None => {
                        defer_passive_bookkeeping(
                            self,
                            "cache local",
                            warnings,
                            &mut cache_preflight_deferred,
                        );
                        None
                    }
                };
            let metadata = source_metadata(source);
            if !metadata.available {
                let names = cached.map(|entry| entry.names).unwrap_or_default();
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    outcome: PassiveSourceOutcome::Skipped,
                    status: format!(
                        "source indisponible, aucune requête: {}",
                        metadata
                            .unavailable_reason
                            .unwrap_or("source non enregistrée")
                    ),
                    names: names.len(),
                });
                passive_union_omitted =
                    passive_union_omitted.saturating_add(merge_passive_source_names_bounded(
                        sources,
                        names,
                        source,
                        Some("unavailable"),
                        self.options.max_passive,
                    ));
                continue;
            }
            if source_requires_api_key(source) && !self.options.api_keys.has(source) {
                let names = cached.map(|entry| entry.names).unwrap_or_default();
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    outcome: PassiveSourceOutcome::Skipped,
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
                    outcome: PassiveSourceOutcome::Deferred,
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
                    outcome: PassiveSourceOutcome::Cached,
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
                refresh.push(source.clone());
            }
        }
        self.emit(ProgressEvent::Phase {
            name: passive_phase_name.clone(),
            detail: format!(
                "cache local {configured_source_count}/{configured_source_count} · planification"
            ),
        });

        let scheduling_deadline =
            passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
        if refresh.iter().any(|source| source == "commoncrawl") {
            match passive_bookkeeping_result(self.database.source_metadata_until(
                "commoncrawl.latest_endpoint",
                Duration::from_secs(30 * 24 * 3_600),
                scheduling_deadline,
            ))? {
                Some(Some(endpoint)) => seed_commoncrawl_endpoint(endpoint),
                Some(None) => {}
                None => defer_passive_bookkeeping(
                    self,
                    "préparation passive",
                    warnings,
                    &mut cache_preflight_deferred,
                ),
            }
        }
        let keys = self.options.api_keys.clone();
        let source_scores = match passive_bookkeeping_result(
            self.database.source_scores_until(scheduling_deadline),
        )? {
            Some(scores) => scores,
            None => {
                defer_passive_bookkeeping(
                    self,
                    "préparation passive",
                    warnings,
                    &mut cache_preflight_deferred,
                );
                HashMap::new()
            }
        };
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
        let external_target_guard = self
            .options
            .no_target_contact
            .then(|| contact_root_domain.to_owned());
        let refresh_total = refresh.len();
        let mut refresh_finished = 0_usize;
        let heartbeat_refresh_finished = Arc::new(AtomicUsize::new(0));
        let mut phase_timed_out = false;
        let persisted_pages = Arc::new(AtomicUsize::new(0));
        let persisted_names = Arc::new(AtomicUsize::new(0));
        let persisted_novel_names = Arc::new(AtomicUsize::new(0));
        let mut results = stream::iter(refresh)
            .map(|source| {
                let keys = keys.clone();
                let active_sources = active_sources.clone();
                let persisted_pages = Arc::clone(&persisted_pages);
                let persisted_names = Arc::clone(&persisted_names);
                let persisted_novel_names = Arc::clone(&persisted_novel_names);
                let passive_request_slots = self.passive_request_slots.clone();
                let database = self.database.clone();
                let root_domain = domain.to_owned();
                let external_target_guard = external_target_guard.clone();
                async move {
                    let _permit = passive_request_slots
                        .acquire_owned()
                        .await
                        .expect("le sémaphore passif reste ouvert pendant le scan");
                    let policy = source_policy(&source);
                    let (remaining, lease_ttl) = passive_connector_timing(
                        passive_deadline,
                        policy.timeout,
                        policy.total_timeout,
                    );
                    if remaining.is_zero() {
                        return (source, 0, None, 0);
                    }
                    let connector_deadline = Instant::now() + remaining;
                    let started = Instant::now();
                    if let Ok(mut active_sources) = active_sources.lock() {
                        // The lease wait is real work covered by the connector
                        // deadline. Expose it immediately instead of leaving the
                        // source looking queued while SQLite is contended.
                        active_sources.insert(source.clone(), started);
                    }
                    let lease_database = database.clone();
                    let lease_domain = domain.to_owned();
                    let lease_source = source.clone();
                    let lease = match passive_sqlite_operation(
                        "acquisition du lease de rafraîchissement passif",
                        move || {
                            PassiveRefreshLeaseGuard::try_acquire(
                                lease_database,
                                &lease_domain,
                                &lease_source,
                                lease_ttl,
                                connector_deadline,
                            )
                        },
                    )
                    .await
                    {
                        Ok(Some(lease)) => Arc::new(lease),
                        Ok(None) => {
                            return (
                                source,
                                started.elapsed().as_millis(),
                                Some(Ok(PassiveFetchResult {
                                    names: BTreeSet::new(),
                                    partial_warning: Some(
                                        "rafraîchissement déjà actif dans un autre processus; cache conservé"
                                            .to_owned(),
                                    ),
                                    decoded_names: 0,
                                    working_set_truncated: false,
                                })),
                                0,
                            );
                        }
                        Err(error) => {
                            return (
                                source,
                                started.elapsed().as_millis(),
                                Some(Err(error.context(
                                    "acquisition du lease de rafraîchissement passif",
                                ))),
                                0,
                            );
                        }
                    };
                    let durable_novel_names = Arc::new(AtomicUsize::new(0));
                    let sink_source = source.clone();
                    let observation_database = database.clone();
                    let observation_lease = Arc::clone(&lease);
                    let page_novel_names = Arc::clone(&durable_novel_names);
                    let page_persisted_pages = Arc::clone(&persisted_pages);
                    let page_persisted_names = Arc::clone(&persisted_names);
                    let page_persisted_novel_names = Arc::clone(&persisted_novel_names);
                    let page_sink: ControlledPassivePageSink = Arc::new(move |names, control| {
                        passive_sqlite_callback(|| {
                            control.ensure_active()?;
                            observation_lease.ensure_owned()?;
                            let persistence_deadline = control.deadline().map_or(
                                connector_deadline,
                                |deadline| deadline.min(connector_deadline),
                            );
                            let novel =
                                observation_database.store_passive_observation_page_until(
                                    &root_domain,
                                    &sink_source,
                                    names,
                                    persistence_deadline,
                                )?;
                            page_novel_names.fetch_add(novel, Ordering::Relaxed);
                            page_persisted_names.fetch_add(names.len(), Ordering::Relaxed);
                            page_persisted_novel_names.fetch_add(novel, Ordering::Relaxed);
                            page_persisted_pages.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        })
                    });
                    let pagination_contracts = numeric_pagination_contracts(&source, domain);
                    let pagination_context = if pagination_contracts.is_empty() {
                        None
                    } else {
                        let prepare_database = database.clone();
                        let prepare_domain = domain.to_owned();
                        let prepare_source = source.clone();
                        let prepare_contracts = pagination_contracts.clone();
                        if let Err(error) = passive_sqlite_operation(
                            "préparation de la reprise de pagination passive",
                            move || {
                                let expected = prepare_contracts
                                    .iter()
                                    .map(|contract| {
                                        (
                                            contract.lane,
                                            contract.contract_version,
                                            contract.query_hash.as_str(),
                                        )
                                    })
                                    .collect::<Vec<_>>();
                                prepare_database.prepare_passive_pagination_source_until(
                                    &prepare_domain,
                                    &prepare_source,
                                    &expected,
                                    connector_deadline,
                                )
                            },
                        )
                        .await
                        {
                            release_passive_lease(Arc::clone(&lease)).await;
                            return (
                                source,
                                started.elapsed().as_millis(),
                                Some(Err(error
                                    .context("préparation de la reprise de pagination passive"))),
                                0,
                            );
                        }
                        let mut context = PassivePaginationContext::empty();
                        for contract in pagination_contracts.iter().cloned() {
                            let resume_database = database.clone();
                            let resume_domain = domain.to_owned();
                            let resume_source = source.clone();
                            let resume_lane = contract.lane;
                            let resume_contract_version = contract.contract_version;
                            let resume_query_hash = contract.query_hash.clone();
                            let resume = match passive_sqlite_operation(
                                "chargement de la reprise de pagination passive",
                                move || {
                                    resume_database.passive_pagination_resume_until(
                                        &resume_domain,
                                        &resume_source,
                                        resume_lane,
                                        resume_contract_version,
                                        &resume_query_hash,
                                        connector_deadline,
                                    )
                                },
                            )
                            .await
                            {
                                Ok(resume) => resume,
                                Err(error) => {
                                    release_passive_lease(Arc::clone(&lease)).await;
                                    return (
                                        source,
                                        started.elapsed().as_millis(),
                                        Some(Err(error.context(
                                            "chargement de la reprise de pagination passive",
                                        ))),
                                        0,
                                    );
                                }
                            };
                            let page_database = database.clone();
                            let page_domain = domain.to_owned();
                            let page_source = source.clone();
                            let page_lane = contract.lane;
                            let page_contract_version = contract.contract_version;
                            let page_query_hash = contract.query_hash.clone();
                            let page_lease = Arc::clone(&lease);
                            let pagination_novel_names = Arc::clone(&durable_novel_names);
                            let pagination_persisted_pages = Arc::clone(&persisted_pages);
                            let pagination_persisted_names = Arc::clone(&persisted_names);
                            let pagination_persisted_novel_names =
                                Arc::clone(&persisted_novel_names);
                            let numeric_page_sink: PassivePaginationPageSink =
                                Arc::new(move |page, names| {
                                    passive_sqlite_callback(|| {
                                        page_lease.ensure_owned()?;
                                        let novel = page_database
                                            .commit_passive_pagination_page_until(
                                            &page_domain,
                                            &page_source,
                                            page_lane,
                                            page_contract_version,
                                            &page_query_hash,
                                            page,
                                            names,
                                            connector_deadline,
                                        )?;
                                        pagination_novel_names.fetch_add(novel, Ordering::Relaxed);
                                        pagination_persisted_names
                                            .fetch_add(names.len(), Ordering::Relaxed);
                                        pagination_persisted_novel_names
                                            .fetch_add(novel, Ordering::Relaxed);
                                        pagination_persisted_pages
                                            .fetch_add(1, Ordering::Relaxed);
                                        Ok(())
                                    })
                                });
                            let finish_database = database.clone();
                            let finish_domain = domain.to_owned();
                            let finish_source = source.clone();
                            let finish_lane = contract.lane;
                            let finish_contract_version = contract.contract_version;
                            let finish_query_hash = contract.query_hash.clone();
                            let finish_lease = Arc::clone(&lease);
                            let finish_sink: PassivePaginationFinishSink = Arc::new(move || {
                                passive_sqlite_callback(|| {
                                    finish_lease.ensure_owned()?;
                                    finish_database.finish_passive_pagination_until(
                                        &finish_domain,
                                        &finish_source,
                                        finish_lane,
                                        finish_contract_version,
                                        &finish_query_hash,
                                        connector_deadline,
                                    )
                                })
                            });
                            if let Err(error) =
                                context.insert(contract, resume, numeric_page_sink, finish_sink)
                            {
                                release_passive_lease(Arc::clone(&lease)).await;
                                return (
                                    source,
                                    started.elapsed().as_millis(),
                                    Some(Err(error.context(
                                        "construction du contexte de pagination passive",
                                    ))),
                                    0,
                                );
                            }
                        }
                        debug_assert!(!context.is_empty());
                        Some(context)
                    };
                    let fetch_budget =
                        connector_deadline.saturating_duration_since(Instant::now());
                    let result = if fetch_budget.is_zero() {
                        Ok(PassiveFetchResult {
                            names: BTreeSet::new(),
                            partial_warning: Some(
                                "délai total du connecteur passif atteint avant la lecture réseau; mémoire permanente conservée"
                                    .to_owned(),
                            ),
                            decoded_names: 0,
                            working_set_truncated: false,
                        })
                    } else {
                        let fetch = async {
                            if let Some(pagination_context) = pagination_context {
                                fetch_passive_paginated(
                                    &source,
                                    domain,
                                    policy.timeout,
                                    &keys,
                                    fetch_budget,
                                    connector_working_set_limit,
                                    page_sink,
                                    pagination_context,
                                )
                                .await
                            } else {
                                fetch_passive_bounded(
                                    &source,
                                    domain,
                                    policy.timeout,
                                    &keys,
                                    fetch_budget,
                                    connector_working_set_limit,
                                    page_sink,
                                )
                                .await
                            }
                        };
                        with_external_target_guard(external_target_guard, fetch).await
                    };
                    let result = match result {
                        Ok(mut fetch) if fetch.partial_warning.is_none() => {
                            let completion_database = database.clone();
                            let completion_domain = domain.to_owned();
                            let completion_source = source.clone();
                            let completion_contracts = pagination_contracts.clone();
                            let completion_lease = Arc::clone(&lease);
                            let completion = passive_sqlite_operation(
                                "finalisation atomique de la source passive",
                                move || {
                                    completion_lease.ensure_owned()?;
                                    if completion_contracts.is_empty() {
                                        completion_database.mark_passive_cache_refresh_until(
                                            &completion_domain,
                                            &completion_source,
                                            true,
                                            connector_deadline,
                                        )
                                    } else {
                                        let expected = completion_contracts
                                            .iter()
                                            .map(|contract| {
                                                (
                                                    contract.lane,
                                                    contract.contract_version,
                                                    contract.query_hash.as_str(),
                                                )
                                            })
                                            .collect::<Vec<_>>();
                                        completion_database
                                            .complete_passive_pagination_source_until(
                                                &completion_domain,
                                                &completion_source,
                                                &expected,
                                                connector_deadline,
                                            )
                                    }
                                },
                            )
                            .await;
                            match completion {
                                Ok(()) => Ok(fetch),
                                Err(error) if is_passive_persistence_deadline_error(&error) => {
                                    fetch.partial_warning = Some(
                                        "délai du connecteur atteint avant la finalisation du cache; observations durables conservées, reprise au prochain scan"
                                            .to_owned(),
                                    );
                                    Ok(fetch)
                                }
                                Err(error) => Err(error)
                                    .context("finalisation atomique de la source passive"),
                            }
                        }
                        Ok(fetch) => {
                            let partial_database = database.clone();
                            let partial_domain = domain.to_owned();
                            let partial_source = source.clone();
                            match passive_sqlite_operation(
                                "conservation du rafraîchissement passif partiel",
                                move || {
                                    partial_database.mark_passive_cache_refresh_until(
                                        &partial_domain,
                                        &partial_source,
                                        false,
                                        connector_deadline,
                                    )
                                },
                            )
                            .await
                            {
                                Ok(()) => Ok(fetch),
                                // The completed pages are already durable. Once the
                                // connector wall-clock deadline is exhausted, leave
                                // the refresh generation resumable instead of
                                // discarding the partial in-memory result merely
                                // because its final marker could not be written.
                                Err(error) if is_passive_persistence_deadline_error(&error) => {
                                    Ok(fetch)
                                }
                                Err(error) => Err(error)
                                    .context("conservation du rafraîchissement passif partiel"),
                            }
                        }
                        Err(error) => Err(error),
                    };
                    release_passive_lease(lease).await;
                    (
                        source,
                        started.elapsed().as_millis(),
                        Some(result),
                        durable_novel_names.load(Ordering::Relaxed),
                    )
                }
            })
            // Providers use independent host-specific throttles; a slightly
            // wider scheduler avoids one slow service holding unrelated fast
            // sources while keeping the network footprint bounded.
            .buffer_unordered(passive_concurrency);
        let (heartbeat_stop, mut heartbeat_stop_rx) = tokio::sync::oneshot::channel();
        let heartbeat_scanner = self.clone();
        let heartbeat_active_sources = Arc::clone(&active_sources);
        let heartbeat_task_refresh_finished = Arc::clone(&heartbeat_refresh_finished);
        let heartbeat_persisted_pages = Arc::clone(&persisted_pages);
        let heartbeat_persisted_names = Arc::clone(&persisted_names);
        let heartbeat_persisted_novel_names = Arc::clone(&persisted_novel_names);
        let heartbeat_phase_name = passive_phase_name.clone();
        let mut heartbeat_task = AbortOnDropJoinHandle::new(tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(1),
                Duration::from_secs(1),
            );
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = &mut heartbeat_stop_rx => break,
                    _ = heartbeat.tick() => {
                        let (active, refresh_finished) = heartbeat_active_sources
                            .lock()
                            .map(|sources| {
                                let refresh_finished =
                                    heartbeat_task_refresh_finished.load(Ordering::Relaxed);
                                (
                                    passive_active_source_status(
                                    &sources,
                                    refresh_finished,
                                    refresh_total,
                                    ),
                                    refresh_finished,
                                )
                            })
                            .unwrap_or_else(|_| {
                                (
                                    "état des sources indisponible".to_owned(),
                                    heartbeat_task_refresh_finished.load(Ordering::Relaxed),
                                )
                            });
                        let persistence = passive_persistence_status(
                            heartbeat_persisted_pages.load(Ordering::Relaxed),
                            heartbeat_persisted_names.load(Ordering::Relaxed),
                            heartbeat_persisted_novel_names.load(Ordering::Relaxed),
                        );
                        let remaining = passive_deadline
                            .map(|deadline| {
                                format!(
                                    " · g≤{}s",
                                    deadline
                                        .saturating_duration_since(tokio::time::Instant::now())
                                        .as_secs()
                                )
                            })
                            .unwrap_or_default();
                        heartbeat_scanner.emit(ProgressEvent::Phase {
                            name: heartbeat_phase_name.clone(),
                            detail: format!(
                                "{refresh_finished}/{refresh_total} · {active} · {persistence}{remaining}",
                            ),
                        });
                    }
                }
            }
        }));
        let deadline_sleep = async move {
            if let Some(deadline) = passive_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(deadline_sleep);
        loop {
            let poll = tokio::select! {
                biased;
                _ = &mut deadline_sleep => None,
                next = results.next() => Some(next),
            };
            let Some(next) = poll else {
                let unfinished = refresh_total.saturating_sub(refresh_finished);
                let warning = format!(
                    "limite cumulative passive de {:.1}s atteinte; {unfinished} source(s) lente(s) annulée(s), mémoire permanente conservée",
                    self.options.passive_phase_timeout.as_secs_f64()
                );
                self.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
                phase_timed_out = true;
                break;
            };
            let Some((source, duration_ms, result, durable_novel_names)) = next else {
                break;
            };
            refresh_finished = refresh_finished.saturating_add(1);
            unfinished_sources.remove(&source);
            if let Ok(mut active_sources) = active_sources.lock() {
                active_sources.remove(&source);
                heartbeat_refresh_finished.store(refresh_finished, Ordering::Relaxed);
            } else {
                heartbeat_refresh_finished.store(refresh_finished, Ordering::Relaxed);
            }
            let bookkeeping_deadline =
                passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
            let mut bookkeeping_deferred = false;
            let stale = match passive_bookkeeping_result(passive_sqlite_callback(|| {
                self.database.passive_cache_bounded_until(
                    domain,
                    &source,
                    connector_working_set_limit,
                    bookkeeping_deadline,
                )
            }))? {
                Some(stale) => stale,
                None => {
                    defer_passive_bookkeeping(self, &source, warnings, &mut bookkeeping_deferred);
                    None
                }
            };
            let Some(result) = result else {
                let names = stale.map(|entry| entry.names).unwrap_or_default();
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    outcome: PassiveSourceOutcome::Deferred,
                    status: "cache périmé, source différée par la limite cumulative".to_owned(),
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
                    let novel_names = durable_novel_names;
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
                    if !bookkeeping_deferred {
                        let recorded =
                            passive_sqlite_callback(|| match partial_warning.as_deref() {
                                Some(warning) if network_names == 0 => {
                                    self.database.record_source_deferred_until(
                                        &source,
                                        duration_ms,
                                        warning,
                                        bookkeeping_deadline,
                                    )
                                }
                                Some(warning) => {
                                    self.database.record_source_degraded_with_counts_until(
                                        &source,
                                        network_names,
                                        novel_names,
                                        duration_ms,
                                        warning,
                                        bookkeeping_deadline,
                                    )
                                }
                                None => self.database.record_source_result_with_counts_until(
                                    &source,
                                    network_names,
                                    novel_names,
                                    duration_ms,
                                    None,
                                    bookkeeping_deadline,
                                ),
                            });
                        if passive_bookkeeping_result(recorded)?.is_none() {
                            defer_passive_bookkeeping(
                                self,
                                &source,
                                warnings,
                                &mut bookkeeping_deferred,
                            );
                        }
                    }
                    if !bookkeeping_deferred
                        && source == "commoncrawl"
                        && let Some(endpoint) = current_commoncrawl_endpoint()
                        && passive_bookkeeping_result(passive_sqlite_callback(|| {
                            self.database.store_source_metadata_until(
                                "commoncrawl.latest_endpoint",
                                &endpoint,
                                bookkeeping_deadline,
                            )
                        }))?
                        .is_none()
                    {
                        defer_passive_bookkeeping(
                            self,
                            &source,
                            warnings,
                            &mut bookkeeping_deferred,
                        );
                    }
                    if let Some(partial_warning) = &partial_warning {
                        if !bookkeeping_deferred
                            && let Some(delay) = external_deferral_seconds(partial_warning)
                        {
                            let retry_until = now_epoch()
                                .saturating_add(delay.min(i64::MAX as u64) as i64)
                                .to_string();
                            if passive_bookkeeping_result(passive_sqlite_callback(|| {
                                self.database.store_source_metadata_until(
                                    &format!("source.retry_until.{source}"),
                                    &retry_until,
                                    bookkeeping_deadline,
                                )
                            }))?
                            .is_none()
                            {
                                defer_passive_bookkeeping(
                                    self,
                                    &source,
                                    warnings,
                                    &mut bookkeeping_deferred,
                                );
                            }
                        }
                        let warning = format!(
                            "{}; {} nom(s) conservé(s) pour ce scan",
                            passive_source_warning(&source, partial_warning),
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
                        outcome: if partial_warning.is_some() {
                            PassiveSourceOutcome::Partial
                        } else {
                            PassiveSourceOutcome::Success
                        },
                        status: if partial_warning.is_some() {
                            if partial_warning
                                .as_deref()
                                .is_some_and(|warning| warning.contains("persistance SQLite"))
                            {
                                "réseau partiel + SQLite partiel".to_owned()
                            } else {
                                "réseau partiel + mémoire permanente".to_owned()
                            }
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
                    let warning = passive_source_warning(&source, &safe_error);
                    if !bookkeeping_deferred
                        && let Some(delay) = external_deferral_seconds(&safe_error)
                    {
                        let retry_until = now_epoch()
                            .saturating_add(delay.min(i64::MAX as u64) as i64)
                            .to_string();
                        if passive_bookkeeping_result(passive_sqlite_callback(|| {
                            self.database.store_source_metadata_until(
                                &format!("source.retry_until.{source}"),
                                &retry_until,
                                bookkeeping_deadline,
                            )
                        }))?
                        .is_none()
                        {
                            defer_passive_bookkeeping(
                                self,
                                &source,
                                warnings,
                                &mut bookkeeping_deferred,
                            );
                        }
                    }
                    if !bookkeeping_deferred {
                        let recorded = passive_sqlite_callback(|| {
                            if source_error_is_deferred(&safe_error) {
                                self.database.record_source_deferred_until(
                                    &source,
                                    duration_ms,
                                    &safe_error,
                                    bookkeeping_deadline,
                                )
                            } else {
                                self.database.record_source_result_until(
                                    &source,
                                    0,
                                    duration_ms,
                                    Some(&safe_error),
                                    bookkeeping_deadline,
                                )
                            }
                        });
                        if passive_bookkeeping_result(recorded)?.is_none() {
                            defer_passive_bookkeeping(
                                self,
                                &source,
                                warnings,
                                &mut bookkeeping_deferred,
                            );
                        }
                    }
                    self.emit(ProgressEvent::Warning(warning.clone()));
                    warnings.push(warning);
                    if let Some(stale) = stale {
                        let names = stale.names;
                        self.emit(ProgressEvent::PassiveSource {
                            source: source.clone(),
                            outcome: PassiveSourceOutcome::Stale,
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
        let _ = heartbeat_stop.send(());
        let _ = heartbeat_task.join().await;
        self.emit(ProgressEvent::Phase {
            name: passive_phase_name.clone(),
            detail: format!(
                "{refresh_finished}/{refresh_total} · finalisation cache · {}",
                passive_persistence_status(
                    persisted_pages.load(Ordering::Relaxed),
                    persisted_names.load(Ordering::Relaxed),
                    persisted_novel_names.load(Ordering::Relaxed),
                )
            ),
        });
        if phase_timed_out {
            let timeout_bookkeeping_deadline =
                passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
            let mut timeout_bookkeeping_deferred = false;
            let active_sources = active_sources
                .lock()
                .map(|sources| sources.clone())
                .unwrap_or_default();
            for source in unfinished_sources {
                let started_at = active_sources.get(&source).copied();
                let started = started_at.is_some();
                let names =
                    match passive_bookkeeping_result(self.database.passive_cache_bounded_until(
                        domain,
                        &source,
                        connector_working_set_limit,
                        timeout_bookkeeping_deadline,
                    ))? {
                        Some(cached) => cached.map(|entry| entry.names).unwrap_or_default(),
                        None => {
                            defer_passive_bookkeeping(
                                self,
                                "finalisation passive",
                                warnings,
                                &mut timeout_bookkeeping_deferred,
                            );
                            Vec::new()
                        }
                    };
                if let Some(started_at) = started_at
                    && !timeout_bookkeeping_deferred
                    && passive_bookkeeping_result(self.database.record_source_deferred_until(
                        &source,
                        started_at.elapsed().as_millis(),
                        "source cancelled when the configured passive deadline was reached",
                        timeout_bookkeeping_deadline,
                    ))?
                    .is_none()
                {
                    defer_passive_bookkeeping(
                        self,
                        "finalisation passive",
                        warnings,
                        &mut timeout_bookkeeping_deferred,
                    );
                }
                self.emit(ProgressEvent::PassiveSource {
                    source: source.clone(),
                    outcome: PassiveSourceOutcome::Deferred,
                    status: if started {
                        "cache périmé, requête lente annulée".to_owned()
                    } else {
                        "cache périmé, source différée par la limite cumulative configurée"
                            .to_owned()
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
        let refill_deadline =
            passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
        let before_refill = sources.len();
        let refill_result = passive_bookkeeping_result(refill_passive_union_from_cache_until(
            &self.database,
            domain,
            &durable_sources,
            sources,
            self.options.max_passive,
            refill_deadline,
        ))?;
        if refill_result.is_none() {
            let mut deferred = false;
            defer_passive_bookkeeping(self, "finalisation passive", warnings, &mut deferred);
        }
        let refilled = sources.len().saturating_sub(before_refill);
        passive_union_omitted = passive_union_omitted.saturating_sub(refilled);
        if passive_union_omitted > 0 {
            let warning = format!(
                "limite --max-passive atteinte: {passive_union_omitted} nom(s) supplémentaires conservé(s) uniquement dans SQLite"
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
            let ranking_deadline =
                passive_local_deadline(passive_storage_deadline, PASSIVE_BOOKKEEPING_BUDGET);
            let mut ranking_deferred = false;
            let source_scores = match passive_bookkeeping_result(
                self.database.source_scores_until(ranking_deadline),
            )? {
                Some(scores) => scores,
                None => {
                    defer_passive_bookkeeping(
                        self,
                        "classement passif",
                        warnings,
                        &mut ranking_deferred,
                    );
                    HashMap::new()
                }
            };
            let prior_candidates =
                match passive_bookkeeping_result(self.database.prior_candidates_until(
                    self.options.max_passive.saturating_mul(2),
                    ranking_deadline,
                ))? {
                    Some(candidates) => candidates,
                    None => {
                        defer_passive_bookkeeping(
                            self,
                            "classement passif",
                            warnings,
                            &mut ranking_deferred,
                        );
                        Vec::new()
                    }
                };
            let prior_rank = prior_candidates
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
        let completion = if passive_completion_phase_required(
            phase_timed_out,
            refresh_total,
            refresh_finished,
        ) {
            "terminé"
        } else if phase_timed_out {
            "terminé après la limite globale"
        } else {
            "terminé"
        };
        self.emit(ProgressEvent::Phase {
            name: passive_phase_name,
            detail: format!(
                "{refresh_finished}/{refresh_total} sources · {} · {completion} en {}s",
                passive_persistence_status(
                    persisted_pages.load(Ordering::Relaxed),
                    persisted_names.load(Ordering::Relaxed),
                    persisted_novel_names.load(Ordering::Relaxed),
                ),
                passive_started.elapsed().as_secs()
            ),
        });
        Ok(())
    }

    pub(super) fn cap_seed_sources(
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
            "limite globale de candidats appliquée: {} noms conservés sur {before}",
            sources.len()
        );
        self.emit(ProgressEvent::Warning(warning.clone()));
        warnings.push(warning);
    }

    pub(super) fn inferred_passive_zones(
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

    pub(super) async fn collect_passive_recursively(
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
        for zone in zones.into_iter().filter(|zone| zone != root_domain) {
            if tasks.len() >= zone_limit {
                break;
            }
            if queried_zones.contains(&zone) {
                continue;
            }
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
            // A zone becomes "queried" only when a network task is actually
            // scheduled. Zones beyond the batch cap or without a compatible
            // connector must remain eligible for a later recursive pass.
            queried_zones.insert(zone.clone());
            let mut options = self.options.raw().clone();
            options.passive_sources = compatible_sources;
            let recursive_scanner = Scanner {
                database: self.database.clone(),
                dns: self.dns.clone(),
                trusted_dns: self.trusted_dns.clone(),
                options: ScanPlan::new(options),
                progress: self.progress.clone(),
                passive_request_slots: self.passive_request_slots.clone(),
            };
            tasks.push((zone, child_query, recursive_scanner));
        }

        let zone_total = tasks.len();
        let mut zone_completed = 0_usize;
        let recursive_deadline = passive_deadline;
        let contact_root_domain = root_domain.to_owned();
        let mut pending = stream::iter(tasks)
            .map(|(zone, child_query, recursive_scanner)| {
                let contact_root_domain = contact_root_domain.clone();
                async move {
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
                            &contact_root_domain,
                            passive_deadline,
                            &mut zone_sources,
                            &mut zone_warnings,
                        )
                        .await;
                    (zone, zone_sources, zone_warnings, result)
                }
            })
            .buffer_unordered(self.options.passive_zone_concurrency.clamp(1, 32));
        loop {
            let next = if let Some(deadline) = recursive_deadline {
                match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(next) => next,
                    Err(_) => {
                        let unfinished = zone_total.saturating_sub(zone_completed);
                        let warning = format!(
                            "limite cumulative passive de {:.1}s atteinte; {unfinished} zone(s) restante(s) annulée(s)",
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
                    "{zone}: {truncated} nom(s) récursif(s) ignoré(s), limite globale atteinte"
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
}
