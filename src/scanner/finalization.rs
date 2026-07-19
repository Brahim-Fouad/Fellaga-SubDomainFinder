use super::*;

pub(super) fn run(state: EnrichmentState<'_>) -> Result<ScanResult> {
    let EnrichmentState {
        execution,
        mut warnings,
        mut pipeline_metrics,
        mut phase_timings,
        sources,
        ct_monitor,
        axfr_attempts,
        active_budget_remaining,
        candidate_expansion_stopped_naturally,
        root_wildcard,
        wildcard_by_parent,
        parent_by_host,
        answers,
        pipeline,
        validation_rounds,
        pipeline_names_validated,
        remaining_yield_upper_bound,
        cache_hits,
        network_resolved,
        dns_edges,
        child_zones,
        service_endpoints,
        dnssec_walks,
        web_observations,
        measured_http_requests,
        measured_http_bytes,
        measured_tls_connections,
        tls_certificates,
    } = state;
    let scanner = execution.scanner;
    let scan_id = execution.scan_id;
    let domain = execution.domain;
    let started = execution.started;
    let finalization_started = Instant::now();
    let pending_seed_candidates = scanner
        .database
        .pending_scan_seed_candidate_count(scan_id)?
        .max(0) as usize;
    let pending_active_candidates = scanner
        .database
        .pending_scan_candidate_count(scan_id)?
        .max(0) as usize;
    let recursive_work_remaining = scanner.database.scan_recursive_has_more(scan_id)?;
    let candidate_feed_remaining =
        !candidate_expansion_stopped_naturally && scanner.candidate_feeds_have_more(scan_id)?;
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
            scanner.emit(ProgressEvent::Warning(warning.clone()));
            warnings.push(warning);
        }
    }

    let answer_hosts = answers.keys().cloned().collect::<Vec<_>>();
    let current_answer_names = scanner
        .database
        .current_seed_output_names(domain, &answer_hosts)?;
    let mut suppressed_sources = BTreeMap::<String, BTreeSet<String>>::new();
    let mut findings = Vec::new();
    for answer in answers.into_values() {
        if !current_answer_names.contains(&answer.fqdn) {
            suppressed_sources
                .entry(answer.fqdn.clone())
                .or_default()
                .extend(sources.get(&answer.fqdn).cloned().unwrap_or_default());
            continue;
        }
        if let Some(finding) = scanner.finding_for_answer(
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
    let seed_candidates = scanner.database.scan_seed_candidates_for_output(scan_id)?;
    let current_seed_names = scanner.database.current_seed_output_names(
        domain,
        &seed_candidates
            .iter()
            .map(|(fqdn, _)| fqdn.clone())
            .collect::<Vec<_>>(),
    )?;
    let seed_cache = scanner.database.fresh_cache(
        &seed_candidates
            .iter()
            .map(|(fqdn, _)| fqdn.clone())
            .collect::<Vec<_>>(),
    )?;
    for (fqdn, seed_sources) in seed_candidates {
        if !current_seed_names.contains(&fqdn) {
            suppressed_sources
                .entry(fqdn)
                .or_default()
                .extend(seed_sources);
            continue;
        }
        if !known_findings.insert(fqdn.clone()) {
            continue;
        }
        match seed_cache.get(&fqdn) {
            Some(CachedAnswer::Positive(answer)) => {
                let signature = Scanner::applicable_wildcard_signature(
                    &fqdn,
                    &root_wildcard,
                    &wildcard_by_parent,
                );
                if wildcard_signature_is_confirmed(signature)
                    && DnsEngine::matches_wildcard(answer, signature)
                    && !scanner.options.include_wildcard
                {
                    continue;
                }
                let persisted_sources = BTreeMap::from([(fqdn.clone(), seed_sources.clone())]);
                if let Some(finding) = scanner.finding_for_answer(
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
                suppressed_sources
                    .entry(fqdn)
                    .or_default()
                    .extend(seed_sources);
            }
            None => {
                findings.push(scanner.finding_for_unresolved_seed(
                    fqdn,
                    seed_sources,
                    crate::model::ObservationState::Unverified,
                    &root_wildcard,
                    &wildcard_by_parent,
                ));
            }
        }
    }
    let suppressed_findings = suppressed_sources
        .into_iter()
        .map(|(fqdn, sources)| {
            Scanner::unverified_seed_audit_finding(fqdn, sources, "suppressed_current_result")
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| left.fqdn.cmp(&right.fqdn));

    let durable_learning = scanner.database.scan_candidate_learning(scan_id)?;
    let generator_attempts = durable_learning.generator_attempts;
    // Only definitive candidate outcomes are present in durable learning.
    // Replacing the eagerly collected working set prevents deadline-
    // cancelled or indeterminate labels from poisoning future rankings.
    let attempted_words = durable_learning.attempted_words;
    let durable_candidate_attempts = durable_learning.total_attempts;

    scanner.emit(ProgressEvent::Phase {
        name: "SQLite".to_owned(),
        detail: "inventaire, cache et apprentissage local".to_owned(),
    });
    let mut successful_words = BTreeSet::new();
    let mut successful_patterns = BTreeSet::new();
    let mut successful_names = scanner.database.live_scan_finding_names(scan_id)?;
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
    if pipeline.budget_exhausted {
        let warning = format!(
            "pipeline événementiel: limite explicite de {} événement(s) atteinte; utilisez --pipeline-limit 0 pour drainer toute la file finie",
            scanner.options.pipeline_budget
        );
        scanner.emit(ProgressEvent::Warning(warning.clone()));
        warnings.push(warning);
    }
    let mut confirmed_sources = BTreeMap::<String, BTreeSet<String>>::new();
    for finding in findings.iter().chain(&suppressed_findings) {
        confirmed_sources
            .entry(finding.fqdn.clone())
            .or_default()
            .extend(finding.sources.iter().cloned());
    }
    scanner
        .database
        .store_scan_observations(domain, &confirmed_sources)?;
    scanner
        .database
        .persist_unverified_findings_preserving_state(scan_id, domain, &suppressed_findings)?;
    scanner
        .database
        .persist_findings(scan_id, domain, &findings, scanner.options.ttl_cap)?;
    let restored_inventory = scanner.append_persistent_inventory(
        domain,
        &mut findings,
        &root_wildcard,
        &wildcard_by_parent,
    )?;
    if restored_inventory > 0 {
        scanner.emit(ProgressEvent::Phase {
                name: "inventaire permanent".to_owned(),
                detail: format!(
                    "{restored_inventory} observation(s) permanente(s) encore pertinente(s) ajoutée(s) au résultat structuré"
                ),
            });
    }
    if scanner.options.only_live {
        findings.retain(|finding| finding.state == crate::model::ObservationState::Live);
    }
    scanner.database.persist_scan_snapshot(scan_id, &findings)?;
    let resolver_metrics = merge_resolver_metrics(
        scanner.dns.take_metrics(),
        scanner
            .trusted_dns
            .as_ref()
            .map(DnsEngine::take_metrics)
            .unwrap_or_default(),
    );
    scanner.database.store_resolver_metrics(&resolver_metrics)?;
    scanner
        .database
        .store_pipeline_metrics(scan_id, &pipeline_metrics)?;
    let exclusive_generator_successes = scanner.database.exclusive_generator_successes(scan_id)?;
    let exclusive_discoveries = scanner.database.exclusive_live_count(scan_id)?;
    let dns_queries = resolver_metrics
        .iter()
        .map(|metric| metric.requests)
        .sum::<u64>();
    let elapsed_seconds = started.elapsed().as_secs_f64().max(0.001);
    let effective_qps = dns_queries as f64 / elapsed_seconds;
    let governor = scanner.dns.network_governor_snapshot();
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
        scanner.database.scan_seed_candidate_count(scan_id)?.max(0) as usize;
    let candidate_count = discovered_seed_count.saturating_add(durable_candidate_attempts);
    if active_resume_required {
        scanner.database.pause_scan(
            scan_id,
            candidate_count,
            findings.len(),
            cache_hits,
            duration_before_learning_ms,
            &warnings,
        )?;
    } else {
        scanner.database.finalize_scan_with_learning(
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
