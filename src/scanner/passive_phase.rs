use super::*;

pub(super) const fn passive_completion_snapshot_required(
    phase_timed_out: bool,
    refresh_total: usize,
    refresh_finished: usize,
    is_root_zone: bool,
) -> bool {
    !phase_timed_out && refresh_total > 0 && refresh_finished == refresh_total && is_root_zone
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
        for source in &self.options.passive_sources {
            let cached =
                self.database
                    .passive_cache_bounded(domain, source, connector_working_set_limit)?;
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
        let external_target_guard = self
            .options
            .no_target_contact
            .then(|| contact_root_domain.to_owned());
        let refresh_total = refresh.len();
        let mut refresh_finished = 0_usize;
        let mut phase_timed_out = false;
        let refresh_started = Instant::now();
        let mut results = stream::iter(refresh)
            .map(|source| {
                let keys = keys.clone();
                let active_sources = active_sources.clone();
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
                    if passive_deadline.is_some() && remaining.is_zero() {
                        return (source, 0, None, 0);
                    }
                    let started = Instant::now();
                    let lease = match PassiveRefreshLeaseGuard::try_acquire(
                        database.clone(),
                        domain,
                        &source,
                        lease_ttl,
                    ) {
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
                    if let Ok(mut active_sources) = active_sources.lock() {
                        active_sources.insert(source.clone(), Instant::now());
                    }
                    let durable_novel_names = Arc::new(AtomicUsize::new(0));
                    let sink_source = source.clone();
                    let observation_database = database.clone();
                    let observation_lease = Arc::clone(&lease);
                    let page_novel_names = Arc::clone(&durable_novel_names);
                    let page_sink: PassivePageSink = Arc::new(move |names| {
                        observation_lease.ensure_owned()?;
                        let novel = observation_database.store_passive_observation_page(
                            &root_domain,
                            &sink_source,
                            names,
                        )?;
                        page_novel_names.fetch_add(novel, Ordering::Relaxed);
                        Ok(())
                    });
                    let pagination_contracts = numeric_pagination_contracts(&source, domain);
                    let pagination_context = if pagination_contracts.is_empty() {
                        None
                    } else {
                        let expected = pagination_contracts
                            .iter()
                            .map(|contract| {
                                (
                                    contract.lane,
                                    contract.contract_version,
                                    contract.query_hash.as_str(),
                                )
                            })
                            .collect::<Vec<_>>();
                        if let Err(error) =
                            database.prepare_passive_pagination_source(domain, &source, &expected)
                        {
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
                            let resume = match database.passive_pagination_resume(
                                domain,
                                &source,
                                contract.lane,
                                contract.contract_version,
                                &contract.query_hash,
                            ) {
                                Ok(resume) => resume,
                                Err(error) => {
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
                            let numeric_page_sink: PassivePaginationPageSink =
                                Arc::new(move |page, names| {
                                    page_lease.ensure_owned()?;
                                    let novel = page_database.commit_passive_pagination_page(
                                        &page_domain,
                                        &page_source,
                                        page_lane,
                                        page_contract_version,
                                        &page_query_hash,
                                        page,
                                        names,
                                    )?;
                                    pagination_novel_names.fetch_add(novel, Ordering::Relaxed);
                                    Ok(())
                                });
                            let finish_database = database.clone();
                            let finish_domain = domain.to_owned();
                            let finish_source = source.clone();
                            let finish_lane = contract.lane;
                            let finish_contract_version = contract.contract_version;
                            let finish_query_hash = contract.query_hash.clone();
                            let finish_lease = Arc::clone(&lease);
                            let finish_sink: PassivePaginationFinishSink = Arc::new(move || {
                                finish_lease.ensure_owned()?;
                                finish_database.finish_passive_pagination(
                                    &finish_domain,
                                    &finish_source,
                                    finish_lane,
                                    finish_contract_version,
                                    &finish_query_hash,
                                )
                            });
                            if let Err(error) =
                                context.insert(contract, resume, numeric_page_sink, finish_sink)
                            {
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
                    let fetch = async {
                        if let Some(pagination_context) = pagination_context {
                            fetch_passive_paginated(
                                &source,
                                domain,
                                policy.timeout,
                                &keys,
                                remaining,
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
                                remaining,
                                connector_working_set_limit,
                                page_sink,
                            )
                            .await
                        }
                    };
                    let result = with_external_target_guard(external_target_guard, fetch).await;
                    let result = match result {
                        Ok(fetch) if fetch.partial_warning.is_none() => {
                            let completion = lease.ensure_owned().and_then(|()| {
                                if pagination_contracts.is_empty() {
                                    database.mark_passive_cache_refresh(domain, &source, true)
                                } else {
                                    let expected = pagination_contracts
                                        .iter()
                                        .map(|contract| {
                                            (
                                                contract.lane,
                                                contract.contract_version,
                                                contract.query_hash.as_str(),
                                            )
                                        })
                                        .collect::<Vec<_>>();
                                    database.complete_passive_pagination_source(
                                        domain, &source, &expected,
                                    )
                                }
                            });
                            completion
                                .context("finalisation atomique de la source passive")
                                .map(|()| fetch)
                        }
                        Ok(fetch) => database
                            .mark_passive_cache_refresh(domain, &source, false)
                            .context("conservation du rafraîchissement passif partiel")
                            .map(|()| fetch),
                        Err(error) => Err(error),
                    };
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
                        .map(|deadline| format!("limite cumulative dans {}s", deadline.saturating_duration_since(tokio::time::Instant::now()).as_secs()))
                        .unwrap_or_else(|| "sans limite cumulative".to_owned());
                    self.emit(ProgressEvent::Phase {
                        name: "passif".to_owned(),
                        detail: format!(
                            "{refresh_finished}/{refresh_total} source(s), {active} active(s), en cours depuis {}s, {remaining}",
                            refresh_started.elapsed().as_secs()
                        ),
                    });
                    continue;
                }
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
            }
            let stale = self.database.passive_cache_bounded(
                domain,
                &source,
                connector_working_set_limit,
            )?;
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
                    let mut novel_names = durable_novel_names;
                    if partial_warning
                        .as_deref()
                        .is_some_and(|warning| warning.contains("persistance SQLite"))
                    {
                        // Retry the bounded working set once when the page sink
                        // itself failed. Successful sinks must not increment
                        // observation counters a second time.
                        novel_names = novel_names.saturating_add(
                            self.database
                                .store_passive_observation_page(domain, &source, &names)?,
                        );
                    }
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
                        outcome: if partial_warning.is_some() {
                            PassiveSourceOutcome::Partial
                        } else {
                            PassiveSourceOutcome::Success
                        },
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
        if passive_completion_snapshot_required(
            phase_timed_out,
            refresh_total,
            refresh_finished,
            domain == contact_root_domain,
        ) {
            self.emit(ProgressEvent::Phase {
                name: "passif".to_owned(),
                detail: format!(
                    "{refresh_finished}/{refresh_total} source(s), terminé en {}s",
                    refresh_started.elapsed().as_secs()
                ),
            });
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
                let names = self
                    .database
                    .passive_cache_bounded(domain, &source, connector_working_set_limit)?
                    .map(|entry| entry.names)
                    .unwrap_or_default();
                if let Some(started_at) = started_at {
                    self.database.record_source_deferred(
                        &source,
                        started_at.elapsed().as_millis(),
                        "source cancelled when the configured passive deadline was reached",
                    )?;
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
