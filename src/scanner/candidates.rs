use super::*;

impl Scanner {
    pub(super) fn tls_endpoints(
        &self,
        domain: &str,
        answers: &BTreeMap<String, ResolvedHost>,
        services: &[ServiceEndpoint],
        root_wildcard: &BTreeSet<String>,
        wildcard_by_parent: &BTreeMap<String, BTreeSet<String>>,
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
            .values()
            .filter(|answer| {
                Self::is_strict_enrichment_seed(answer, root_wildcard, wildcard_by_parent)
            })
            .map(|answer| {
                (
                    answer.fqdn.clone(),
                    self.options.tls_port,
                    "tcp-tls".to_owned(),
                )
            })
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

    pub(super) fn ordered_candidates<'a>(
        &self,
        domain: &str,
        observed_names: impl IntoIterator<Item = (&'a str, i64)>,
        limit: usize,
    ) -> Result<Vec<CandidateProposal>> {
        let limit = limit.min(100_000);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let observation_keep_cap = limit.min(MUTATION_OBSERVATION_KEEP_CAP);
        let observation_scan_cap = observation_keep_cap
            .saturating_mul(4)
            .min(MUTATION_OBSERVATION_SCAN_CAP);
        let observed_names = select_bounded_mutation_observations(
            domain,
            observed_names,
            observation_scan_cap,
            observation_keep_cap,
        );
        let mut candidates = Vec::new();
        let mut seen = BTreeSet::new();
        let mut add = |candidate: CandidateProposal| {
            if seen.insert(candidate.relative_name.clone()) && candidates.len() < limit {
                candidates.push(candidate);
            }
        };
        let observations = observed_names
            .iter()
            .cloned()
            .map(|fqdn| NameObservation::new(fqdn, None))
            .collect::<Vec<_>>();
        let grammar_config = IntelligenceConfig {
            max_candidates: limit.min(5_000),
            ..IntelligenceConfig::default()
        };
        if let Ok(intelligence) = learn_and_generate(domain, &observations, &grammar_config) {
            self.database
                .store_name_templates(domain, &intelligence.grammar.templates)?;
            for candidate in intelligence.candidates {
                add(CandidateProposal {
                    relative_name: candidate.relative_name,
                    generator: format!("grammar:{}", candidate.template_id),
                    score: 100_000_i64.saturating_add(candidate.score),
                });
            }
        }
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

    /// Keep only a small, durable page in SQLite. Expensive corpora are fed on
    /// demand after the previous DNS wave completes, so DNS starts without a
    /// one-million-row insertion pause.
    pub(super) fn refill_candidate_queue(
        &self,
        scan_id: i64,
        domain: &str,
        observed_names: &BTreeMap<String, BTreeSet<String>>,
        target_queued: usize,
        allow_generated: bool,
    ) -> Result<usize> {
        let queued = self.database.pending_scan_candidate_count(scan_id)?.max(0) as usize;
        let total = self.database.scan_candidate_budget_count(scan_id)?.max(0) as usize;
        if queued >= target_queued || total >= self.options.max_words {
            return Ok(queued);
        }

        let mut capacity =
            candidate_refill_capacity(queued, total, target_queued, self.options.max_words);
        let mut inserted = 0_usize;

        if let Some(path) = &self.options.wordlist
            && capacity > 0
            && !self
                .database
                .scan_candidate_feed_exhausted(scan_id, "wordlist")?
        {
            let (added, exhausted) = self
                .database
                .refill_wordlist_candidates(scan_id, domain, path, capacity)?;
            inserted += added;
            capacity = capacity.saturating_sub(added);
            // A user-supplied wordlist has priority over the embedded corpus.
            // If this bounded page contained only duplicates/invalid lines,
            // keep its remaining budget for the next cursor page instead of
            // letting built-ins consume `max_words` first.
            if !exhausted {
                return Ok(queued.saturating_add(inserted));
            }
        }

        // An expired active budget stops only newly generated expansion.
        // Durable explicit wordlist pages above remain eligible, while already
        // attempted transient failures are drained by the normal claim path.
        if !allow_generated {
            return Ok(queued.saturating_add(inserted));
        }

        const HIGH_VALUE_WINDOW: usize = 5_000;
        let high_value_exhausted = self
            .database
            .scan_candidate_feed_exhausted(scan_id, "high-value")?;
        if high_value_window_needs_materialization(capacity, high_value_exhausted) {
            let prioritized = self.ordered_candidates(
                domain,
                observed_names
                    .iter()
                    .map(|(name, sources)| (name.as_str(), seed_candidate_priority(sources))),
                HIGH_VALUE_WINDOW,
            )?;
            let payload = prioritized
                .into_iter()
                .map(|candidate| {
                    (
                        candidate.relative_name,
                        candidate.generator,
                        candidate.score,
                    )
                })
                .collect::<Vec<_>>();
            // Materialize the complete bounded high-value window once. A
            // smaller DNS target queue must not cause the same grammar and
            // mutation model to be rebuilt on every wave. The cumulative
            // active budget remains the hard upper bound across resumes.
            let persist_limit = high_value_window_persist_limit(
                total,
                inserted,
                self.options.max_words,
                payload.len(),
            );
            let added = self.database.persist_scan_candidates_bounded(
                scan_id,
                domain,
                &payload,
                persist_limit,
            )?;
            // Either the full bounded payload was examined, or `persist_limit`
            // unique rows filled the remaining max-words budget. In both cases
            // no high-value item can be usefully resumed from this window.
            self.database
                .mark_scan_candidate_feed_exhausted(scan_id, "high-value")?;
            inserted += added;
            capacity = capacity.saturating_sub(added);
        }

        if capacity > 0 {
            inserted += self
                .database
                .persist_prior_candidates_to_scan(scan_id, domain, capacity)?;
        }
        Ok(queued.saturating_add(inserted))
    }

    pub(super) fn candidate_feeds_have_more(&self, scan_id: i64) -> Result<bool> {
        if self.database.scan_candidate_budget_count(scan_id)?.max(0) as usize
            >= self.options.max_words
        {
            return Ok(false);
        }
        if self.options.wordlist.is_some()
            && !self
                .database
                .scan_candidate_feed_exhausted(scan_id, "wordlist")?
        {
            return Ok(true);
        }
        if !self
            .database
            .scan_candidate_feed_exhausted(scan_id, "high-value")?
        {
            return Ok(true);
        }
        Ok(!self
            .database
            .scan_candidate_feed_exhausted(scan_id, "builtin")?)
    }

    pub(super) fn explicit_wordlist_has_more(&self, scan_id: i64) -> Result<bool> {
        Ok(self.options.wordlist.is_some()
            && (self.database.scan_candidate_budget_count(scan_id)?.max(0) as usize)
                < self.options.max_words
            && !self
                .database
                .scan_candidate_feed_exhausted(scan_id, "wordlist")?)
    }

    pub(super) fn recursive_wordlist(&self) -> Result<Vec<String>> {
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
}
