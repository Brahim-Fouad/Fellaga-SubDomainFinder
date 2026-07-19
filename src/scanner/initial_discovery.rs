use super::*;

pub(super) async fn run<'scan>(
    execution: ScanExecution<'scan>,
) -> Result<InitialDiscoveryState<'scan>> {
    let scanner = execution.scanner;
    let scan_id = execution.scan_id;
    let domain = execution.domain;
    let mut warnings = Vec::new();
    let pipeline_metrics = PipelineMetrics::default();
    let mut phase_timings = Vec::new();
    let mut sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut passive_budget_remaining = scanner.options.limits.passive.remaining();
    let nsec_budget_remaining = scanner.options.limits.dnssec.remaining();
    let nsec_budget_warning_emitted = false;
    let web_budget_remaining = scanner.options.limits.web.remaining();
    let web_budget_exhausted = false;
    let initial_discovery_started = Instant::now();
    let resume_has_discovery_state = scanner.options.resume.is_some()
        && (scanner.database.scan_seed_candidate_count(scan_id)? > 0
            || scanner.database.scan_candidate_count(scan_id)? > 0
            || scanner.database.scan_recursive_has_more(scan_id)?);

    // These discovery families are independent network operations. Running
    // them together turns their cold-start wall time into the slowest one,
    // instead of adding three unrelated waits before DNS validation starts.
    let passive_phase = async {
        let mut passive_sources = BTreeMap::new();
        let mut passive_warnings = Vec::new();
        let mut queried_zones = BTreeSet::from([domain.to_owned()]);
        let passive_phase_started = Instant::now();
        let deadline = phase_deadline(passive_budget_remaining);
        if scanner.options.passive {
            scanner.emit(ProgressEvent::Phase {
                name: "passif".to_owned(),
                detail: format!(
                    "{} source(s), cache {} h",
                    scanner.options.passive_sources.len(),
                    scanner.options.passive_refresh.as_secs() / 3_600
                ),
            });
            scanner
                .collect_passive(
                    domain,
                    domain,
                    deadline,
                    &mut passive_sources,
                    &mut passive_warnings,
                )
                .await?;
            let mut inferred = scanner.inferred_passive_zones(
                domain,
                passive_sources.keys().cloned(),
                scanner.options.recursive_hosts.min(20),
            );
            if let Some(parent) = crate::util::registrable_domain(domain)
                && parent != domain
            {
                inferred.insert(0, parent);
            }
            scanner
                .collect_passive_recursively(
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
    if scanner.options.ct_monitor && !scanner.options.no_target_contact {
        let scanner = scanner.clone();
        let ct_domain = domain.to_owned();
        ct_tasks.spawn(async move { scanner.collect_incremental_ct(&ct_domain).await });
    }

    let axfr_phase = async {
        if !scanner.options.axfr || scanner.options.no_target_contact {
            return (Vec::new(), Vec::new());
        }
        scanner.emit(ProgressEvent::Phase {
            name: "AXFR".to_owned(),
            detail: "résolution des NS et transfert TCP".to_owned(),
        });
        let (attempts, axfr_warnings) = scanner
            .await_with_phase_heartbeat(
                "AXFR",
                "essais bornés sur les serveurs autoritaires",
                attempt_axfr(&scanner.dns, domain, scanner.options.axfr_timeout),
            )
            .await;
        for warning in &axfr_warnings {
            scanner.emit(ProgressEvent::Warning(warning.clone()));
        }
        for attempt in &attempts {
            scanner.emit(ProgressEvent::AxfrAttempt(attempt.clone()));
        }
        (attempts, axfr_warnings)
    };

    let (
        passive_sources,
        passive_warnings,
        passive_zones_queried,
        passive_elapsed,
        axfr_attempts,
        axfr_warnings,
    ) = if resume_has_discovery_state {
        scanner.emit(ProgressEvent::Phase {
            name: "reprise".to_owned(),
            detail: "cache passif réconcilié; CT incrémental et AXFR repris de façon idempotente"
                .to_owned(),
        });
        // A completed connector is served from its fresh SQLite cache,
        // while a source whose pagination was cancelled or partial keeps
        // an old/zero freshness timestamp and is retried.  Never skip the
        // whole passive phase merely because an active candidate queue
        // exists: that previously made partial provider results permanent
        // after `--resume`.
        let (passive_result, (axfr_attempts, axfr_warnings)) =
            tokio::join!(passive_phase, axfr_phase);
        let (
            mut passive_sources,
            mut passive_warnings,
            mut passive_zones_queried,
            mut passive_elapsed,
        ) = passive_result?;
        let restored_sources = scanner
            .database
            .scan_seed_candidates_for_output(scan_id)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for (name, origins) in &restored_sources {
            passive_sources
                .entry(name.clone())
                .or_default()
                .extend(origins.iter().cloned());
        }
        if scanner.options.passive {
            let restored_zones = scanner.inferred_passive_zones(
                domain,
                restored_sources.keys().cloned(),
                scanner.options.recursive_hosts.min(20),
            );
            let recursive_started = Instant::now();
            let recursive_budget =
                passive_budget_remaining.map(|budget| budget.saturating_sub(passive_elapsed));
            scanner
                .collect_passive_recursively(
                    domain,
                    restored_zones,
                    phase_deadline(recursive_budget),
                    &mut passive_zones_queried,
                    &mut passive_sources,
                    &mut passive_warnings,
                )
                .await?;
            passive_elapsed = passive_elapsed.saturating_add(recursive_started.elapsed());
        }
        (
            passive_sources,
            passive_warnings,
            passive_zones_queried,
            passive_elapsed,
            axfr_attempts,
            axfr_warnings,
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
    let (ct_monitor, ct_warnings) = if !scanner.options.ct_monitor
        || scanner.options.no_target_contact
    {
        let ct_warnings = if scanner.options.no_target_contact && scanner.options.ct_monitor {
            let warning = "no-target-contact: direct CT-log collection disabled; CT provider connectors remain available".to_owned();
            scanner.emit(ProgressEvent::Warning(warning.clone()));
            vec![warning]
        } else {
            Vec::new()
        };
        (CtMonitorResult::default(), ct_warnings)
    } else {
        match ct_tasks.try_join_next() {
            Some(Ok(Ok(result))) => result,
            Some(Ok(Err(error))) => {
                let warning = format!("CT incrémental: {error:#}");
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                (CtMonitorResult::default(), vec![warning])
            }
            Some(Err(error)) => {
                let warning = format!("CT incrémental: tâche interrompue: {error}");
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                (CtMonitorResult::default(), vec![warning])
            }
            None => {
                ct_task_pending = true;
                let result = CtMonitorResult {
                    duration_ms: initial_discovery_started.elapsed().as_millis(),
                    ..CtMonitorResult::default()
                };
                scanner.emit(ProgressEvent::Phase {
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
    if scanner.options.passive {
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
    scanner
        .database
        .save_axfr_attempts(scan_id, &axfr_attempts)?;
    scanner.cap_seed_sources(domain, &mut sources, &mut warnings);
    phase_timings.push(PhaseTiming {
        phase: "initial_discovery".to_owned(),
        duration_ms: initial_discovery_started.elapsed().as_millis(),
    });
    Ok(InitialDiscoveryState {
        execution,
        warnings,
        pipeline_metrics,
        phase_timings,
        sources,
        passive_budget_remaining,
        nsec_budget_remaining,
        nsec_budget_warning_emitted,
        web_budget_remaining,
        web_budget_exhausted,
        passive_zones_queried,
        ct_task_started,
        ct_tasks,
        ct_task_pending,
        ct_monitor,
        axfr_attempts,
    })
}
