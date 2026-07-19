use super::*;

impl Scanner {
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
            "no_target_contact": self.options.no_target_contact,
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
            "internetdb_pivot": self.options.internetdb_pivot,
            "internetdb_max_ips": self.options.internetdb_max_ips,
            "internetdb_phase_timeout_seconds": self.options.internetdb_phase_timeout.as_secs(),
            "internetdb_refresh_seconds": self.options.internetdb_refresh.as_secs(),
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

    pub(super) async fn collect_incremental_ct(
        &self,
        domain: &str,
    ) -> Result<(CtMonitorResult, Vec<String>)> {
        let mut ct_monitor = CtMonitorResult::default();
        let mut ct_warnings = Vec::new();
        if !self.options.ct_monitor {
            return Ok((ct_monitor, ct_warnings));
        }

        let phase_started = Instant::now();
        let phase_limit = self.options.limits.certificate_transparency.label();
        self.emit(ProgressEvent::Phase {
            name: "CT incrémental".to_owned(),
            detail: format!(
                "indexation en arrière-plan: {} journal(aux), {} entrées maximum par journal, {phase_limit}",
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
        if self
            .options
            .limits
            .certificate_transparency
            .reached(phase_started)
        {
            let warning = "CT incrémental: limite cumulative configurée atteinte; résultats partiels conservés"
                .to_owned();
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

    pub(super) async fn scan_inner(
        &self,
        scan_id: i64,
        domain: &str,
        started: Instant,
    ) -> Result<ScanResult> {
        let execution = ScanExecution::new(self, scan_id, domain, started);
        let initial = initial_discovery::run(execution).await?;
        if self.options.no_target_contact {
            debug_assert!(!initial.ct_task_pending);
            let InitialDiscoveryState {
                execution,
                sources,
                ct_monitor,
                pipeline_metrics,
                phase_timings,
                warnings,
                ..
            } = initial;
            return execution.scanner.finalize_no_target_contact_scan(
                execution.scan_id,
                execution.domain,
                execution.started,
                sources,
                ct_monitor,
                pipeline_metrics,
                phase_timings,
                warnings,
            );
        }

        let active = active_validation::run(initial).await?;
        let enriched = enrichment::run(active).await?;
        finalization::run(enriched)
    }
}
