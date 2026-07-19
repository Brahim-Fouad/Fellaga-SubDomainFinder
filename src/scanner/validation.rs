use super::*;

impl Scanner {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn resolve_batch(
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
        reliable_wildcard_zones: &BTreeSet<String>,
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
                reliable_wildcard_zones,
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

    /// Validate names produced by late discovery stages without letting them
    /// escape the active DNS budget. Every name is first persisted in the
    /// durable seed queue; only a bounded accepted slice is claimed now. A
    /// deferred wildcard parent, an unstarted DNS future, or an indeterminate
    /// answer is returned to SQLite for a later `--resume` run.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn validate_enrichment_batch_bounded(
        &self,
        scan_id: i64,
        domain: &str,
        hosts: &[String],
        phase: &str,
        scan_started: &Instant,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        reliable_wildcard_zones: &mut BTreeSet<String>,
        wildcard_parent_limit: usize,
        remaining: &mut Option<Duration>,
    ) -> Result<BatchResolution> {
        if hosts.is_empty() {
            return Ok(BatchResolution::default());
        }

        let mut payload = hosts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|fqdn| {
                let origins = sources.get(&fqdn).cloned().unwrap_or_default();
                let priority = seed_candidate_priority(&origins);
                (fqdn, origins, priority)
            })
            .collect::<Vec<_>>();
        payload.sort_by_key(|(fqdn, _, priority)| (Reverse(*priority), fqdn.clone()));
        self.database
            .persist_scan_seed_candidates(scan_id, &payload, self.options.max_passive)?;

        // The named-claim API is intentionally bounded. Walk the ranked
        // input until one validation page is full so already-terminal or
        // cap-rejected names cannot starve later accepted names.
        let ranked_hosts = payload
            .iter()
            .map(|(fqdn, _, _)| fqdn.clone())
            .collect::<Vec<_>>();
        let mut claimed = Vec::new();
        let mut offset = 0_usize;
        while claimed.len() < ENRICHMENT_VALIDATION_BATCH_SIZE && offset < ranked_hosts.len() {
            let take =
                (ENRICHMENT_VALIDATION_BATCH_SIZE - claimed.len()).min(ranked_hosts.len() - offset);
            let end = offset + take;
            claimed.extend(
                self.database
                    .claim_scan_seed_candidates_by_name(scan_id, &ranked_hosts[offset..end])?,
            );
            offset = end;
        }
        claimed.sort();
        claimed.dedup();
        if claimed.is_empty() {
            return Ok(BatchResolution::default());
        }

        self.validate_claimed_seed_batch_bounded(
            scan_id,
            domain,
            &claimed,
            phase,
            scan_started,
            sources,
            root_wildcard,
            parent_by_host,
            wildcard_by_parent,
            reliable_wildcard_zones,
            wildcard_parent_limit,
            remaining,
        )
        .await
    }

    /// Validate one page that has already been atomically claimed from the
    /// durable seed queue. Keeping claim and validation separate lets late CT
    /// drain every accepted page in the current run when no active deadline is
    /// configured, without repeatedly materializing the complete CT payload.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn validate_claimed_seed_batch_bounded(
        &self,
        scan_id: i64,
        domain: &str,
        claimed: &[String],
        phase: &str,
        scan_started: &Instant,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        reliable_wildcard_zones: &mut BTreeSet<String>,
        wildcard_parent_limit: usize,
        remaining: &mut Option<Duration>,
    ) -> Result<BatchResolution> {
        if claimed.is_empty() {
            return Ok(BatchResolution::default());
        }

        let registration = self
            .register_wildcard_parents_with_budget(
                claimed,
                domain,
                parent_by_host,
                wildcard_by_parent,
                reliable_wildcard_zones,
                wildcard_parent_limit,
                remaining,
            )
            .await;
        if registration.deferred_parents > 0 {
            self.emit(ProgressEvent::Phase {
                name: "wildcard".to_owned(),
                detail: format!(
                    "{} sous-zone(s) différée(s); leurs noms restent dans la file SQLite",
                    registration.deferred_parents
                ),
            });
        }

        let deferred = Self::deferred_wildcard_hosts(
            claimed.iter().cloned(),
            root_wildcard,
            wildcard_by_parent,
        );
        let runnable = claimed
            .iter()
            .filter(|host| !deferred.contains(*host))
            .cloned()
            .collect::<Vec<_>>();
        let dns_started = Instant::now();
        let mut resolution = if runnable.is_empty() {
            BatchResolution::default()
        } else {
            self.resolve_batch_with_deadline(
                scan_id,
                domain,
                &runnable,
                phase,
                scan_started,
                sources,
                root_wildcard,
                parent_by_host,
                wildcard_by_parent,
                reliable_wildcard_zones,
                phase_deadline(*remaining),
                BatchDnsMode::Conservative,
            )
            .await?
        };
        consume_phase_budget(remaining, dns_started.elapsed());
        if (registration.deadline_exhausted || resolution.deadline_exhausted) && remaining.is_some()
        {
            *remaining = Some(Duration::ZERO);
        }

        let outstanding = deferred
            .iter()
            .cloned()
            .chain(resolution.not_started_hosts.iter().cloned())
            .chain(resolution.indeterminate_hosts.iter().cloned())
            .collect::<BTreeSet<_>>();
        let outstanding_hosts = outstanding.iter().cloned().collect::<Vec<_>>();
        self.database
            .requeue_unstarted_scan_seed_candidates(scan_id, &outstanding_hosts)?;
        let terminal = claimed
            .iter()
            .filter(|host| !outstanding.contains(*host))
            .cloned()
            .collect::<Vec<_>>();
        self.database
            .mark_scan_seed_candidates_done(scan_id, &terminal)?;
        resolution
            .not_started_hosts
            .extend(deferred.iter().cloned());
        resolution.not_started_hosts.sort();
        resolution.not_started_hosts.dedup();
        Ok(resolution)
    }

    /// Drain the durable seed tail created when CT joins after the ordinary
    /// candidate loop. With `remaining == None`, structural queue and retry
    /// bounds are the only stopping conditions. A configured active deadline
    /// is shared across every page and leaves unstarted work resumable.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn drain_late_ct_seed_validation(
        &self,
        scan_id: i64,
        domain: &str,
        scan_started: &Instant,
        sources: &BTreeMap<String, BTreeSet<String>>,
        root_wildcard: &BTreeSet<String>,
        parent_by_host: &mut HashMap<String, String>,
        wildcard_by_parent: &mut BTreeMap<String, BTreeSet<String>>,
        reliable_wildcard_zones: &mut BTreeSet<String>,
        answers: &mut BTreeMap<String, ResolvedHost>,
        remaining: &mut Option<Duration>,
        batch_size: usize,
    ) -> Result<LateCtValidationDrain> {
        let mut drain = LateCtValidationDrain::default();
        let batch_size = batch_size.clamp(1, ENRICHMENT_VALIDATION_BATCH_SIZE);
        loop {
            if active_candidate_budget_exhausted(*remaining) {
                drain.deadline_exhausted = true;
                break;
            }
            let claimed = self
                .database
                .pending_scan_seed_candidates(scan_id, batch_size)?;
            if claimed.is_empty() {
                break;
            }
            let (already_answered, validation_hosts): (Vec<_>, Vec<_>) = claimed
                .into_iter()
                .map(|(fqdn, _, _)| fqdn)
                .partition(|fqdn| answers.contains_key(fqdn));
            self.database
                .mark_scan_seed_candidates_done(scan_id, &already_answered)?;
            if validation_hosts.is_empty() {
                continue;
            }

            let resolution = self
                .validate_claimed_seed_batch_bounded(
                    scan_id,
                    domain,
                    &validation_hosts,
                    "DNS CT tardif",
                    scan_started,
                    sources,
                    root_wildcard,
                    parent_by_host,
                    wildcard_by_parent,
                    reliable_wildcard_zones,
                    20,
                    remaining,
                )
                .await?;
            drain.cache_hits = drain.cache_hits.saturating_add(resolution.cache_hits);
            drain.resolved_from_network = drain
                .resolved_from_network
                .saturating_add(resolution.resolved_from_network);
            drain.deadline_exhausted |= resolution.deadline_exhausted;
            for answer in resolution.answers {
                answers.insert(answer.fqdn.clone(), answer);
            }
            if drain.deadline_exhausted || active_candidate_budget_exhausted(*remaining) {
                drain.deadline_exhausted = true;
                break;
            }
        }
        drain.pending = self
            .database
            .pending_scan_seed_candidate_count(scan_id)?
            .max(0) as usize;
        Ok(drain)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn resolve_batch_with_deadline(
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
        reliable_wildcard_zones: &BTreeSet<String>,
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
            .filter(|answer| {
                Self::has_reliable_wildcard_profile(
                    &answer.fqdn,
                    wildcard_by_parent,
                    reliable_wildcard_zones,
                ) && (answer.resolver_count >= 2 || answer.authoritative_validation)
            })
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
}
