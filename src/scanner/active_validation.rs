use super::*;

pub(super) async fn run<'scan>(
    state: InitialDiscoveryState<'scan>,
) -> Result<ActiveValidationState<'scan>> {
    let InitialDiscoveryState {
        execution,
        mut warnings,
        pipeline_metrics,
        mut phase_timings,
        mut sources,
        passive_budget_remaining,
        nsec_budget_remaining,
        nsec_budget_warning_emitted,
        web_budget_remaining,
        web_budget_exhausted,
        passive_zones_queried,
        ct_task_started,
        mut ct_tasks,
        ct_task_pending,
        mut ct_monitor,
        axfr_attempts,
    } = state;
    let scanner = execution.scanner;
    let scan_id = execution.scan_id;
    let domain = execution.domain;
    let started = execution.started;
    let candidate_dns_started = Instant::now();
    scanner.emit(ProgressEvent::Phase {
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
    let late_ct_reserve = late_ct_seed_reserve(scanner.options.max_passive, ct_task_pending);
    let initial_seed_limit = scanner.options.max_passive.saturating_sub(late_ct_reserve);
    scanner
        .database
        .persist_scan_seed_candidates(scan_id, &seed_payload, initial_seed_limit)?;
    let mut resumed_live_answers = if scanner.options.resume.is_some() {
        scanner.database.live_scan_answers(scan_id)?
    } else {
        Vec::new()
    };
    for (answer, persisted_sources) in &resumed_live_answers {
        sources
            .entry(answer.fqdn.clone())
            .or_default()
            .extend(persisted_sources.iter().cloned());
    }
    let mut generated_candidates_enabled = !scanner.options.passive_only;
    let mut active_budget_remaining = scanner.options.limits.active.remaining();
    let recursive_budget_exhausted = false;
    let mut candidate_expansion_stopped_naturally = false;
    let mut active_budget_warning_emitted = false;
    let mut resume_candidate_queue_draining = scanner.options.resume.is_some()
        && scanner
            .database
            .pending_scan_candidate_count(scan_id)?
            .max(0) as usize
            > 0;
    let mut conservative_candidate_retries = BTreeSet::<String>::new();
    let first_batch_limit = if scanner.options.adaptive { 500 } else { 5_000 };
    let first_seed_limit = seed_share(first_batch_limit, !scanner.options.passive_only);
    let first_seed_candidates = scanner
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
    let candidates = if scanner.options.passive_only {
        Vec::new()
    } else {
        if !resume_candidate_queue_draining {
            scanner.refill_candidate_queue(
                scan_id,
                domain,
                &sources,
                first_candidate_limit,
                generated_candidates_enabled,
            )?;
        }
        scanner
            .database
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
    let known_first_candidate_hosts = scanner
        .database
        .known_discovery_names(&first_candidate_hosts)?;
    let mut first_wordlist_hosts = candidates
        .iter()
        .filter(|candidate| candidate.generator == "wordlist")
        .filter_map(|candidate| {
            let fqdn = format!("{}.{domain}", candidate.relative_name);
            (!first_seed_hosts.contains(&fqdn)).then_some(fqdn)
        })
        .collect::<Vec<_>>();
    let mut first_generated_hosts = candidates
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
    let mut first_known_generated_hosts = candidates
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
    let mut first_retry_hosts = candidates
        .iter()
        .filter(|candidate| resume_candidate_queue_draining && candidate.generator != "wordlist")
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
    scanner.emit(ProgressEvent::Phase {
        name: "wildcard".to_owned(),
        detail: "sondes aléatoires sur la racine et les sous-zones observées".to_owned(),
    });
    let wildcard_budget_started = Instant::now();
    let wildcard_deadline = phase_deadline(active_budget_remaining);
    let (root_wildcard_observation, root_wildcard_timed_out) = scanner
        .wildcard_profile_cached_bounded(domain, wildcard_deadline)
        .await;
    let root_wildcard_reliable = root_wildcard_observation.current_probe_reliable;
    let root_wildcard = root_wildcard_observation
        .signature
        .unwrap_or_else(indeterminate_wildcard_signature);
    let mut wildcard_by_parent = BTreeMap::from([(domain.to_owned(), root_wildcard.clone())]);
    let mut reliable_wildcard_zones = if root_wildcard_reliable {
        BTreeSet::from([domain.to_owned()])
    } else {
        BTreeSet::new()
    };
    let mut parent_by_host = HashMap::new();
    let parent_wildcard_registration = scanner
        .register_wildcard_parents_bounded(
            &initial_wildcard_hosts,
            domain,
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            64,
            wildcard_deadline,
        )
        .await;
    consume_phase_budget(
        &mut active_budget_remaining,
        wildcard_budget_started.elapsed(),
    );
    if parent_wildcard_registration.deferred_parents > 0 {
        scanner.emit(ProgressEvent::Phase {
                name: "wildcard".to_owned(),
                detail: format!(
                    "{} sous-zone(s) au-delà du lot initial restent indéterminées et pourront être profilées dans une vague suivante",
                    parent_wildcard_registration.deferred_parents
                ),
            });
    }
    if (root_wildcard_timed_out || parent_wildcard_registration.deadline_exhausted)
        && active_budget_remaining.is_some()
    {
        active_budget_remaining = Some(Duration::ZERO);
    }
    let resumed_wildcard_suspects = resumed_live_answers
        .iter()
        .filter(|(answer, _)| {
            Scanner::answer_matches_confirmed_wildcard(answer, &root_wildcard, &wildcard_by_parent)
                && Scanner::has_reliable_wildcard_profile(
                    &answer.fqdn,
                    &wildcard_by_parent,
                    &reliable_wildcard_zones,
                )
        })
        .map(|(answer, origins)| {
            (
                answer.fqdn.clone(),
                origins.clone(),
                seed_candidate_priority(origins),
            )
        })
        .collect::<Vec<_>>();
    if !resumed_wildcard_suspects.is_empty() {
        scanner.database.demote_and_requeue_scan_findings(
                scan_id,
                &resumed_wildcard_suspects,
                "stored live answer matches a reliable current wildcard profile; fresh DNS validation required",
            )?;
        let suspect_names = resumed_wildcard_suspects
            .iter()
            .map(|(fqdn, _, _)| fqdn.clone())
            .collect::<BTreeSet<_>>();
        resumed_live_answers.retain(|(answer, _)| !suspect_names.contains(&answer.fqdn));
        scanner.emit(ProgressEvent::Phase {
            name: "wildcard".to_owned(),
            detail: format!(
                "{} ancien(s) résultat(s) live déclassé(s) et remis en validation fraîche",
                resumed_wildcard_suspects.len()
            ),
        });
    }
    let initial_deferred_hosts = Scanner::deferred_wildcard_hosts(
        initial_hosts.iter().cloned(),
        &root_wildcard,
        &wildcard_by_parent,
    );
    first_wordlist_hosts.retain(|host| !initial_deferred_hosts.contains(host));
    first_generated_hosts.retain(|host| !initial_deferred_hosts.contains(host));
    first_known_generated_hosts.retain(|host| !initial_deferred_hosts.contains(host));
    first_retry_hosts.retain(|host| !initial_deferred_hosts.contains(host));
    let wildcard_parent_count = wildcard_by_parent
        .iter()
        .filter(|(zone, signature)| *zone != domain && wildcard_signature_is_confirmed(signature))
        .count();
    let indeterminate_parent_count = wildcard_by_parent
        .iter()
        .filter(|(zone, signature)| {
            *zone != domain && wildcard_signature_is_indeterminate(signature)
        })
        .count();
    scanner.emit(ProgressEvent::Phase {
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
    scanner.emit(ProgressEvent::Phase {
        name: "DNS niveau 1".to_owned(),
        detail: format!("{} candidat(s) à valider", initial_hosts.len()),
    });
    let mut initial_resolution = BatchResolution::default();
    let first_seed_batch = first_seed_hosts
        .iter()
        .filter(|host| !initial_deferred_hosts.contains(*host))
        .cloned()
        .collect::<Vec<_>>();
    if !first_seed_batch.is_empty() {
        let (answers, cache_hits, resolved_from_network) = scanner
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
                &reliable_wildcard_zones,
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
        let conservative_resolution = scanner
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
                &reliable_wildcard_zones,
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
        let conservative_resolution = scanner
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
                &reliable_wildcard_zones,
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
        let conservative_resolution = scanner
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
                &reliable_wildcard_zones,
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
        let generated_resolution = scanner
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
                &reliable_wildcard_zones,
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
                "limite cumulative DNS active de {}s atteinte après {} candidat(s); expansion générée arrêtée, résultats terminés conservés et requêtes inachevées remises en file",
                scanner.options.active_phase_timeout.as_secs(),
                generator_attempts.values().sum::<usize>()
            );
            scanner.emit(ProgressEvent::Phase {
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
    initial_resolution
        .not_started_hosts
        .extend(initial_deferred_hosts.iter().cloned());
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
            Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
        })
        .map(|answer| answer.fqdn.clone())
        .collect::<BTreeSet<_>>();
    scanner.database.record_scan_candidate_results(
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
    scanner
        .database
        .mark_scan_candidates_done(scan_id, &initial_terminal_hosts)?;
    scanner
        .database
        .requeue_unstarted_scan_candidates(scan_id, &initial_not_started)?;
    scanner
        .database
        .requeue_unstarted_scan_seed_candidates(scan_id, &initial_not_started)?;
    scanner
        .database
        .mark_scan_seed_candidates_done(scan_id, &initial_terminal_hosts)?;
    let mut answers: BTreeMap<String, ResolvedHost> = initial_answers
        .into_iter()
        .map(|answer| (answer.fqdn.clone(), answer))
        .collect();
    for (answer, _) in resumed_live_answers {
        answers.entry(answer.fqdn.clone()).or_insert(answer);
    }
    record_candidate_wave_results(&candidates, domain, &answers, &mut generator_successes);
    discard_failed_candidate_origins(&candidates, domain, &answers, &mut sources);
    let mut pipeline = DiscoveryPipeline::new(scanner.options.pipeline_budget);
    pipeline.mark_processed(answers.keys().cloned());
    let validation_rounds = 0_usize;
    let pipeline_names_validated = 0_usize;
    let graph_processed = BTreeSet::new();
    let web_processed = BTreeSet::new();
    let tls_processed = BTreeSet::new();

    let mut previous_positive = first_generated_hosts
        .iter()
        .filter_map(|host| answers.get(host))
        .filter(|answer| {
            Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
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
            Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
        })
        .count();
    let required_yield_waves = if scanner.options.profile == "turbo" {
        2
    } else {
        3
    };
    let minimum_statistical_attempts = match scanner.options.profile.as_str() {
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
            && scanner
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
        let explicit_wordlist_pending = scanner.explicit_wordlist_has_more(scan_id)?;
        let active_work_allowed = active_candidate_work_allowed(active_budget_remaining);
        if generated_candidates_enabled
            && active_candidate_budget_exhausted(active_budget_remaining)
        {
            generated_candidates_enabled = false;
            if !active_budget_warning_emitted {
                let detail = format!(
                    "limite cumulative DNS active de {}s atteinte après {} candidat(s); expansion générée arrêtée, résultats terminés conservés et requêtes inachevées remises en file",
                    scanner.options.active_phase_timeout.as_secs(),
                    generator_attempts.values().sum::<usize>()
                );
                scanner.emit(ProgressEvent::Phase {
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
            && scanner.options.adaptive
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
            scanner.emit(ProgressEvent::Phase {
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
        let wave_limit = if scanner.options.adaptive && wave_number == 2 {
            1_500
        } else {
            1_000
        };
        let queued_candidate_work = scanner
            .database
            .pending_scan_candidate_count_eligible(scan_id, active_work_allowed)?
            .max(0) as usize
            > 0;
        let candidate_work_enabled = active_work_allowed
            && (generated_candidates_enabled || explicit_wordlist_pending || queued_candidate_work);
        let wave_seed_candidates = scanner.database.pending_scan_seed_candidates(
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
                scanner.refill_candidate_queue(
                    scan_id,
                    domain,
                    &sources,
                    candidate_limit,
                    generated_candidates_enabled,
                )?;
            }
            scanner
                .database
                .pending_scan_candidates_eligible(scan_id, candidate_limit, active_work_allowed)?
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
        let known_wave_candidate_hosts = scanner
            .database
            .known_discovery_names(&wave_candidate_names)?;
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
                && ((generated_candidates_enabled && scanner.candidate_feeds_have_more(scan_id)?)
                    || scanner.explicit_wordlist_has_more(scan_id)?)
            {
                scanner.emit(ProgressEvent::Phase {
                    name: "candidats".to_owned(),
                    detail: "page sans nouveau nom; reprise au curseur suivant".to_owned(),
                });
                continue;
            }
            break;
        }
        let remaining_seeds = scanner
            .database
            .pending_scan_seed_candidate_count(scan_id)?
            .max(0) as usize;
        scanner.emit(ProgressEvent::Phase {
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
        let wave_wildcard_registration = scanner
            .register_wildcard_parents_bounded(
                &wave_hosts,
                domain,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                &mut reliable_wildcard_zones,
                20,
                phase_deadline(active_budget_remaining),
            )
            .await;
        consume_phase_budget(
            &mut active_budget_remaining,
            wave_wildcard_started.elapsed(),
        );
        if wave_wildcard_registration.deferred_parents > 0 {
            scanner.emit(ProgressEvent::Phase {
                name: "wildcard".to_owned(),
                detail: format!(
                    "{} sous-zone(s) différée(s) par le lot de profilage de la vague {wave_number}",
                    wave_wildcard_registration.deferred_parents
                ),
            });
        }
        if wave_wildcard_registration.deadline_exhausted && active_budget_remaining.is_some() {
            active_budget_remaining = Some(Duration::ZERO);
        }
        let wave_deferred_hosts = Scanner::deferred_wildcard_hosts(
            wave_hosts.iter().cloned(),
            &root_wildcard,
            &wildcard_by_parent,
        );
        wave_wordlist_hosts.retain(|host| !wave_deferred_hosts.contains(host));
        wave_generated_hosts.retain(|host| !wave_deferred_hosts.contains(host));
        wave_known_generated_hosts.retain(|host| !wave_deferred_hosts.contains(host));
        wave_retry_hosts.retain(|host| !wave_deferred_hosts.contains(host));
        let mut wave_resolution = BatchResolution::default();
        let wave_seed_batch = wave_seed_hosts
            .iter()
            .filter(|host| !wave_deferred_hosts.contains(*host))
            .cloned()
            .collect::<Vec<_>>();
        if !wave_seed_batch.is_empty() {
            let (answers, cache_hits, resolved_from_network) = scanner
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
                    &reliable_wildcard_zones,
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
            let conservative_resolution = scanner
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
                    &reliable_wildcard_zones,
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
            let conservative_resolution = scanner
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
                    &reliable_wildcard_zones,
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
            let conservative_resolution = scanner
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
                    &reliable_wildcard_zones,
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
            let generated_resolution = scanner
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
                    &reliable_wildcard_zones,
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
        wave_resolution
            .not_started_hosts
            .extend(wave_deferred_hosts.iter().cloned());
        if (!wave_known_generated_hosts.is_empty() || !wave_generated_hosts.is_empty())
            && active_candidate_budget_exhausted(active_budget_remaining)
        {
            generated_candidates_enabled = false;
            if !active_budget_warning_emitted {
                let detail = format!(
                    "limite cumulative DNS active de {}s atteinte après {} candidat(s); expansion générée arrêtée, résultats terminés conservés et requêtes inachevées remises en file",
                    scanner.options.active_phase_timeout.as_secs(),
                    generator_attempts.values().sum::<usize>()
                );
                scanner.emit(ProgressEvent::Phase {
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
                Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
            })
            .map(|answer| answer.fqdn.clone())
            .collect::<BTreeSet<_>>();
        scanner.database.record_scan_candidate_results(
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
        scanner
            .database
            .mark_scan_candidates_done(scan_id, &wave_terminal_hosts)?;
        scanner
            .database
            .requeue_unstarted_scan_candidates(scan_id, &wave_not_started)?;
        scanner
            .database
            .requeue_unstarted_scan_seed_candidates(scan_id, &wave_not_started)?;
        scanner
            .database
            .mark_scan_seed_candidates_done(scan_id, &wave_terminal_hosts)?;
        cache_hits = cache_hits.saturating_add(wave_cache_hits);
        network_resolved = network_resolved.saturating_add(wave_network_resolved);
        if !wave_generated_hosts.is_empty() {
            previous_positive = wave_answers
                .iter()
                .filter(|answer| wave_generated_hosts.contains(&answer.fqdn))
                .filter(|answer| {
                    Scanner::is_strict_enrichment_seed(answer, &root_wildcard, &wildcard_by_parent)
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
        record_candidate_wave_results(&wave_candidates, domain, &answers, &mut generator_successes);
        discard_failed_candidate_origins(&wave_candidates, domain, &answers, &mut sources);
        wave_number += 1;
    }

    if ct_task_pending {
        let final_grace = if scanner.options.ct_phase_timeout.is_zero() {
            scanner.emit(ProgressEvent::Phase {
                    name: "CT incrémental".to_owned(),
                    detail: "validation DNS terminée; attente de la collecte CT bornée par les journaux et les entrées"
                        .to_owned(),
                });
            None
        } else {
            let minimum_runtime = scanner.options.ct_phase_timeout.min(Duration::from_secs(3));
            let grace = minimum_runtime.saturating_sub(ct_task_started.elapsed());
            if !grace.is_zero() {
                scanner.emit(ProgressEvent::Phase {
                    name: "CT incrémental".to_owned(),
                    detail: format!(
                        "courte fenêtre finale bornée à {:.1}s; DNS déjà terminé",
                        grace.as_secs_f64()
                    ),
                });
            }
            Some(grace)
        };
        let (joined_ct, ct_aborted_without_join) =
            finish_pending_ct_task(&mut ct_tasks, final_grace).await;
        let mut late_ct = match joined_ct {
            Some(Ok(Ok((result, late_warnings)))) => {
                warnings.extend(late_warnings);
                result
            }
            Some(Ok(Err(error))) => {
                let warning = format!("CT incrémental: {error:#}");
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
                CtMonitorResult::default()
            }
            Some(Err(error)) => {
                let warning = format!("CT incrémental: tâche interrompue: {error}");
                scanner.emit(ProgressEvent::Warning(warning.clone()));
                warnings.push(warning);
                CtMonitorResult::default()
            }
            None => {
                let result = CtMonitorResult {
                    names: ct_monitor.names.clone(),
                    duration_ms: ct_task_started.elapsed().as_millis(),
                    ..CtMonitorResult::default()
                };
                scanner.emit(ProgressEvent::Phase {
                        name: "CT incrémental".to_owned(),
                        detail: format!(
                            "arrêt opportuniste après la phase DNS; {} nom(s) ciblé(s) indexé(s) conservé(s)",
                            result.names.len()
                        ),
                    });
                scanner.emit(ProgressEvent::CtMonitor {
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
            scanner
                .database
                .ct_names_for_domain(domain, scanner.options.max_passive.min(100_000))?
                .into_iter()
                .filter(|name| normalize_observed_name(name, domain).is_some())
                .collect::<Vec<_>>()
        };
        let mut late_seen = late_names.iter().cloned().collect::<BTreeSet<_>>();
        for name in &ct_monitor.names {
            if late_names.len() >= scanner.options.max_passive {
                break;
            }
            if normalize_observed_name(name, domain).is_some() && late_seen.insert(name.clone()) {
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
        scanner.database.persist_scan_seed_candidates(
            scan_id,
            &late_payload,
            scanner.options.max_passive,
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
        scanner.database.persist_scan_seed_candidates(
            scan_id,
            &refill_payload,
            scanner.options.max_passive,
        )?;

        // CT finished after the ordinary candidate loop. Drain every
        // accepted durable seed page now instead of applying a hidden 5 s
        // tail deadline or requiring one resume per 2 000 names. A
        // user-configured active deadline remains cumulative because the
        // shared `active_budget_remaining` value is charged page by page.
        let late_drain = scanner
            .drain_late_ct_seed_validation(
                scan_id,
                domain,
                &started,
                &sources,
                &root_wildcard,
                &mut parent_by_host,
                &mut wildcard_by_parent,
                &mut reliable_wildcard_zones,
                &mut answers,
                &mut active_budget_remaining,
                ENRICHMENT_VALIDATION_BATCH_SIZE,
            )
            .await?;
        cache_hits += late_drain.cache_hits;
        network_resolved += late_drain.resolved_from_network;
        if late_drain.pending > 0 && late_drain.deadline_exhausted {
            let warning = format!(
                "CT incrémental: limite cumulative DNS active configurée atteinte; {} nom(s) restent conservés pour --resume latest",
                late_drain.pending
            );
            scanner.emit(ProgressEvent::Warning(warning.clone()));
            warnings.push(warning);
        }
    }
    phase_timings.push(PhaseTiming {
        phase: "candidate_dns".to_owned(),
        duration_ms: candidate_dns_started.elapsed().as_millis(),
    });

    Ok(ActiveValidationState {
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
        ct_monitor,
        axfr_attempts,
        active_budget_remaining,
        recursive_budget_exhausted,
        candidate_expansion_stopped_naturally,
        root_wildcard,
        wildcard_by_parent,
        reliable_wildcard_zones,
        parent_by_host,
        answers,
        pipeline,
        validation_rounds,
        pipeline_names_validated,
        graph_processed,
        web_processed,
        tls_processed,
        remaining_yield_upper_bound,
        cache_hits,
        network_resolved,
    })
}
