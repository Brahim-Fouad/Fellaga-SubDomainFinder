use super::*;

impl Database {
    pub fn record_word_results(
        &self,
        domain: &str,
        attempted: &BTreeSet<String>,
        successful: &BTreeSet<String>,
    ) -> Result<()> {
        let now = now_epoch();
        let hashed_domain =
            domain_hash(&registrable_domain(domain).unwrap_or_else(|| domain.to_ascii_lowercase()));
        let all_words: BTreeSet<&String> = attempted.iter().chain(successful.iter()).collect();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for word in all_words {
            let attempts = i64::from(attempted.contains(word));
            let successes = i64::from(successful.contains(word));
            transaction.execute(
                r#"INSERT INTO word_stats(
                   word, attempts, successes, unique_domains, first_seen, last_seen
                   ) VALUES (?1, ?2, ?3, 0, ?4, ?4)
                   ON CONFLICT(word) DO UPDATE SET attempts=attempts+excluded.attempts,
                   successes=successes+excluded.successes, last_seen=excluded.last_seen"#,
                params![word, attempts, successes, now],
            )?;
            if successes > 0 {
                let inserted = transaction.execute(
                    "INSERT OR IGNORE INTO word_domains(word, domain_hash, first_seen) VALUES (?1, ?2, ?3)",
                    params![word, hashed_domain, now],
                )?;
                if inserted > 0 {
                    transaction.execute(
                        "UPDATE word_stats SET unique_domains=unique_domains+1 WHERE word=?1",
                        [word],
                    )?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn ranked_words(&self, limit: usize) -> Result<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT word,
               (successes * 12.0 + unique_domains * 20.0 +
                ((successes + 1.0) / (attempts + 4.0)) * 5.0) AS rank
               FROM word_stats
               ORDER BY rank DESC, word ASC LIMIT ?1"#,
        )?;
        let rows = statement.query_map([limit as i64], |row| row.get::<_, String>(0))?;
        let mut seen = BTreeSet::new();
        let mut words = Vec::new();
        for row in rows {
            let word = row?;
            if seen.insert(word.clone()) {
                words.push(word);
            }
        }
        Ok(words)
    }

    pub fn record_patterns(&self, domain: &str, patterns: &BTreeSet<String>) -> Result<()> {
        if patterns.is_empty() {
            return Ok(());
        }
        let now = now_epoch();
        let hashed_domain =
            domain_hash(&registrable_domain(domain).unwrap_or_else(|| domain.to_ascii_lowercase()));
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for pattern in patterns {
            transaction.execute(
                r#"INSERT INTO relative_patterns(
                   relative_name, successes, unique_domains, first_seen, last_seen
                   ) VALUES (?1, 1, 0, ?2, ?2)
                   ON CONFLICT(relative_name) DO UPDATE SET
                   successes=successes+1, last_seen=excluded.last_seen"#,
                params![pattern, now],
            )?;
            let inserted = transaction.execute(
                r#"INSERT OR IGNORE INTO pattern_domains(relative_name, domain_hash, first_seen)
                   VALUES (?1, ?2, ?3)"#,
                params![pattern, hashed_domain, now],
            )?;
            if inserted > 0 {
                transaction.execute(
                    r#"UPDATE relative_patterns SET unique_domains=unique_domains+1
                       WHERE relative_name=?1"#,
                    [pattern],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn ranked_patterns(&self, limit: usize) -> Result<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT relative_name FROM relative_patterns
               ORDER BY (successes * 12 + unique_domains * 25) DESC,
               length(relative_name) ASC, relative_name ASC LIMIT ?1"#,
        )?;
        statement
            .query_map([limit as i64], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn prior_candidates(&self, limit: usize) -> Result<Vec<String>> {
        self.prior_candidates_before(limit, None)
    }

    pub fn prior_candidates_until(&self, limit: usize, deadline: Instant) -> Result<Vec<String>> {
        self.prior_candidates_before(limit, Some(deadline))
    }

    fn prior_candidates_before(
        &self,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Vec<String>> {
        ensure_passive_persistence_deadline(deadline)?;
        let connection = self.lock_passive_until(deadline)?;
        let mut statement = connection.prepare(
            r#"SELECT relative_name FROM candidate_priors
               ORDER BY priority DESC, relative_name ASC LIMIT ?1"#,
        )?;
        let mut rows = statement.query([limit.min(i64::MAX as usize) as i64])?;
        let mut candidates = Vec::with_capacity(limit.min(4_096));
        while let Some(row) = rows.next()? {
            if candidates.len().is_multiple_of(256) {
                ensure_passive_persistence_deadline(deadline)?;
            }
            candidates.push(row.get::<_, String>(0)?);
        }
        ensure_passive_persistence_deadline(deadline)?;
        Ok(candidates)
    }

    pub fn enqueue_discovery_actions(
        &self,
        scan_id: i64,
        actions: &[DiscoveryActionInput],
    ) -> Result<usize> {
        if actions.len() > MAX_DISCOVERY_ACTIONS {
            bail!(
                "trop de discovery_actions dans un lot: {} > {MAX_DISCOVERY_ACTIONS}",
                actions.len()
            );
        }
        for action in actions {
            validate_discovery_action(action)?;
        }
        if actions.is_empty() {
            return Ok(0);
        }
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut changed = 0_usize;
        {
            let mut insert = transaction.prepare(
                r#"INSERT INTO discovery_actions(
                       scan_id, fqdn, zone, kind, generator, context_key,
                       priority_class, predicted_unique_live, predicted_cost,
                       state, created_at, updated_at
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'queued', ?10, ?10)
                   ON CONFLICT(scan_id, kind, fqdn, zone, generator) DO UPDATE SET
                       context_key=excluded.context_key,
                       priority_class=excluded.priority_class,
                       predicted_unique_live=excluded.predicted_unique_live,
                       predicted_cost=excluded.predicted_cost,
                       updated_at=excluded.updated_at
                   WHERE discovery_actions.state='queued'"#,
            )?;
            for action in actions {
                changed = changed.saturating_add(insert.execute(params![
                    scan_id,
                    action.fqdn.as_deref().unwrap_or(""),
                    action.zone,
                    action.kind,
                    action.generator,
                    action.context_key,
                    i64::from(action.priority_class),
                    action.predicted_unique_live,
                    action.predicted_cost,
                    now
                ])?);
            }
        }
        transaction.commit()?;
        Ok(changed)
    }

    /// Atomically claims the highest expected exclusive-live yield per unit
    /// cost. At most 512 actions are returned in one call.
    pub fn claim_discovery_actions(
        &self,
        scan_id: i64,
        limit: usize,
    ) -> Result<Vec<DiscoveryActionRecord>> {
        let limit = limit.min(MAX_DISCOVERY_ACTION_CLAIM);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let selected = {
            let mut statement = transaction.prepare(
                r#"SELECT id, NULLIF(fqdn, ''), zone, kind, generator, context_key,
                          priority_class, predicted_unique_live, predicted_cost
                   FROM discovery_actions
                   WHERE scan_id=?1 AND state='queued'
                   ORDER BY priority_class ASC,
                            predicted_unique_live / MAX(predicted_cost, 0.000001) DESC,
                            predicted_unique_live DESC, id ASC
                   LIMIT ?2"#,
            )?;
            statement
                .query_map(params![scan_id, limit as i64], |row| {
                    Ok(DiscoveryActionRecord {
                        id: row.get(0)?,
                        fqdn: row.get(1)?,
                        zone: row.get(2)?,
                        kind: row.get(3)?,
                        generator: row.get(4)?,
                        context_key: row.get(5)?,
                        priority_class: row.get::<_, i64>(6)?.clamp(0, 3) as u8,
                        predicted_unique_live: row.get(7)?,
                        predicted_cost: row.get(8)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let now = now_epoch();
        let mut claimed = Vec::with_capacity(selected.len());
        for action in selected {
            if transaction.execute(
                r#"UPDATE discovery_actions SET state='processing', updated_at=?2
                   WHERE id=?1 AND state='queued'"#,
                params![action.id, now],
            )? == 1
            {
                claimed.push(action);
            }
        }
        transaction.commit()?;
        Ok(claimed)
    }

    /// Completes an action and applies its scheduler reward in the same
    /// transaction. Replaying an already completed action is idempotent.
    pub fn complete_discovery_action(
        &self,
        action_id: i64,
        outcome: &SchedulerOutcome,
        details: &Value,
    ) -> Result<bool> {
        validate_scheduler_outcome(outcome)?;
        let outcome_json = serde_json::to_string(&json!({
            "attempts": outcome.attempts,
            "exclusive_live": outcome.exclusive_live,
            "packets": outcome.packets,
            "total_cost": outcome.total_cost,
            "details": details,
        }))?;
        if outcome_json.len() > MAX_DISCOVERY_OUTCOME_JSON {
            bail!("résultat discovery_action supérieur à {MAX_DISCOVERY_OUTCOME_JSON} octets");
        }
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let action = transaction
            .query_row(
                r#"SELECT generator, context_key, state FROM discovery_actions WHERE id=?1"#,
                [action_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((generator, context, state)) = action else {
            bail!("discovery_action #{action_id} introuvable");
        };
        if state == "done" {
            return Ok(false);
        }
        if state == "deferred" {
            bail!("discovery_action #{action_id} déjà différée");
        }
        if generator != outcome.generator {
            bail!("générateur incohérent pour discovery_action #{action_id}");
        }
        let updated = transaction.execute(
            r#"UPDATE discovery_actions
               SET state='done', outcome_json=?2, updated_at=?3
               WHERE id=?1 AND state IN ('queued', 'processing')"#,
            params![action_id, outcome_json, now],
        )?;
        if updated != 1 {
            return Ok(false);
        }
        upsert_scheduler_arm(&transaction, &context, outcome, now)?;
        if context != "global" {
            upsert_scheduler_arm(&transaction, "global", outcome, now)?;
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Atomically persists a bounded set of exclusive-live scheduler results
    /// into all contexts relevant to `domain`.
    pub fn record_scheduler_outcomes(
        &self,
        domain: &str,
        outcomes: &[SchedulerOutcome],
    ) -> Result<()> {
        if outcomes.len() > MAX_SCHEDULER_OUTCOMES {
            bail!(
                "trop de résultats scheduler dans un lot: {} > {MAX_SCHEDULER_OUTCOMES}",
                outcomes.len()
            );
        }
        let mut aggregated = BTreeMap::<String, SchedulerOutcome>::new();
        for outcome in outcomes {
            validate_scheduler_outcome(outcome)?;
            let entry = aggregated
                .entry(outcome.generator.clone())
                .or_insert_with(|| SchedulerOutcome {
                    generator: outcome.generator.clone(),
                    attempts: 0,
                    exclusive_live: 0,
                    packets: 0,
                    total_cost: 0.0,
                });
            entry.attempts = entry
                .attempts
                .checked_add(outcome.attempts)
                .context("dépassement du compteur d'essais scheduler")?;
            entry.exclusive_live = entry
                .exclusive_live
                .checked_add(outcome.exclusive_live)
                .context("dépassement du compteur de récompenses scheduler")?;
            entry.packets = entry
                .packets
                .checked_add(outcome.packets)
                .context("dépassement du compteur de paquets scheduler")?;
            entry.total_cost += outcome.total_cost;
            validate_scheduler_outcome(entry)?;
        }
        if aggregated.is_empty() {
            return Ok(());
        }

        let now = now_epoch();
        let mut connection = self.lock()?;
        let contexts = candidate_contexts(&connection, domain)?;
        let transaction = connection.transaction()?;
        for outcome in aggregated.values() {
            for context in &contexts {
                upsert_scheduler_arm(&transaction, context, outcome, now)?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns deterministic, cost-aware Beta-UCB priorities. Reads are
    /// bounded per context so a very old local database cannot stall startup.
    pub fn scheduler_rankings(
        &self,
        domain: &str,
        generators: &[String],
        limit: usize,
    ) -> Result<Vec<SchedulerArmRanking>> {
        if generators.len() > MAX_SCHEDULER_GENERATORS {
            bail!(
                "trop de générateurs à classer: {} > {MAX_SCHEDULER_GENERATORS}",
                generators.len()
            );
        }
        if limit == 0 || generators.is_empty() {
            return Ok(Vec::new());
        }
        let generator_set = generators
            .iter()
            .map(|generator| {
                validate_scheduler_identifier(generator, "generator")?;
                Ok(generator.clone())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let connection = self.lock()?;
        let contexts = candidate_contexts(&connection, domain)?;
        let mut aggregates = generator_set
            .iter()
            .map(|generator| (generator.clone(), SchedulerArmAggregate::default()))
            .collect::<BTreeMap<_, _>>();
        let placeholders = std::iter::repeat_n("?", generator_set.len())
            .collect::<Vec<_>>()
            .join(",");

        for context in contexts {
            let weight = scheduler_context_weight(&context);
            let sql = format!(
                r#"SELECT generator, alpha, beta, packets,
                          exclusive_rewards, total_cost
                   FROM scheduler_arms
                   WHERE context=? AND generator IN ({placeholders})"#
            );
            let mut statement = connection.prepare(&sql)?;
            let parameters =
                std::iter::once(context.as_str()).chain(generator_set.iter().map(String::as_str));
            let rows = statement.query_map(rusqlite::params_from_iter(parameters), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, f64>(5)?,
                ))
            })?;
            for row in rows {
                let (generator, alpha, beta, packets, rewards, total_cost) = row?;
                let Some(aggregate) = aggregates.get_mut(&generator) else {
                    continue;
                };
                let alpha = if alpha.is_finite() {
                    alpha.clamp(1.0, MAX_SCHEDULER_TOTAL)
                } else {
                    1.0
                };
                let beta = if beta.is_finite() {
                    beta.clamp(1.0, MAX_SCHEDULER_TOTAL)
                } else {
                    1.0
                };
                let successes = (alpha - 1.0).max(0.0);
                let failures = (beta - 1.0).max(0.0);
                let attempts = successes + failures;
                let packets = packets.max(0) as u64;
                let rewards = (rewards.max(0) as u64).min(attempts.round().max(0.0) as u64);
                let total_cost = if total_cost.is_finite() {
                    total_cost.clamp(0.0, MAX_SCHEDULER_TOTAL)
                } else {
                    0.0
                };
                aggregate.weighted_successes += successes * weight;
                aggregate.weighted_failures += failures * weight;
                aggregate.weighted_attempts += attempts * weight;
                aggregate.weighted_packets += packets as f64 * weight;
                aggregate.weighted_rewards += rewards as f64 * weight;
                aggregate.weighted_cost += total_cost * weight;
                aggregate.max_packets = aggregate.max_packets.max(packets);
                aggregate.max_rewards = aggregate.max_rewards.max(rewards);
                aggregate.contexts_matched = aggregate.contexts_matched.saturating_add(1);
            }
        }

        let mut rankings = aggregates
            .into_iter()
            .map(|(generator, aggregate)| {
                let alpha = 1.0 + aggregate.weighted_successes;
                let beta = 1.0 + aggregate.weighted_failures;
                let total = (alpha + beta).max(2.0);
                let posterior_mean = alpha / total;
                let variance = (alpha * beta / (total * total * (total + 1.0))).max(0.0);
                let posterior_upper = (posterior_mean + 1.645 * variance.sqrt()).min(1.0);
                let average_cost = if aggregate.weighted_attempts > 0.0
                    && aggregate.weighted_cost > 0.0
                {
                    (aggregate.weighted_cost / aggregate.weighted_attempts).clamp(0.05, 1_000_000.0)
                } else {
                    1.0
                };
                let priority_milli = ((posterior_upper / average_cost) * 1_000.0)
                    .round()
                    .clamp(0.0, 100_000.0) as i64;
                let exclusive_per_1000_cost = if aggregate.weighted_cost > 0.0 {
                    aggregate.weighted_rewards * 1_000.0 / aggregate.weighted_cost
                } else {
                    0.0
                };
                SchedulerArmRanking {
                    generator,
                    priority_milli,
                    posterior_mean,
                    posterior_upper,
                    average_cost,
                    exclusive_per_1000_cost,
                    packets: aggregate.max_packets,
                    exclusive_live: aggregate.max_rewards,
                    contexts_matched: aggregate.contexts_matched,
                }
            })
            .collect::<Vec<_>>();
        rankings.sort_by(|left, right| {
            right
                .priority_milli
                .cmp(&left.priority_milli)
                .then_with(|| {
                    right
                        .exclusive_per_1000_cost
                        .total_cmp(&left.exclusive_per_1000_cost)
                })
                .then_with(|| left.generator.cmp(&right.generator))
        });
        rankings.truncate(limit.min(MAX_SCHEDULER_GENERATORS));
        Ok(rankings)
    }

    pub fn generator_scores(&self, domain: &str) -> Result<HashMap<String, i64>> {
        let generators = [
            "environment-swap",
            "number-neighbor",
            "token-order",
            "service-environment",
        ];
        let mut scores = generators
            .into_iter()
            .map(|generator| (generator.to_owned(), 650_i64))
            .collect::<HashMap<_, _>>();
        let generator_names = generators
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let rankings = self.scheduler_rankings(domain, &generator_names, generator_names.len())?;
        let scheduler_generators = rankings
            .iter()
            .filter(|ranking| ranking.contexts_matched > 0)
            .map(|ranking| ranking.generator.clone())
            .collect::<BTreeSet<_>>();
        for ranking in rankings {
            if ranking.contexts_matched > 0 {
                *scores.entry(ranking.generator).or_default() += ranking.priority_milli;
            }
        }

        // Old databases and same-process legacy API calls may not yet have a
        // scheduler_arms row. Retain the historical score only for those
        // generators, avoiding double-counting once v9 learning is available.
        let connection = self.lock()?;
        let contexts = candidate_contexts(&connection, domain)?;
        let placeholders = std::iter::repeat_n("?", generator_names.len())
            .collect::<Vec<_>>()
            .join(",");
        for bandit_context in contexts {
            let sql = format!(
                r#"SELECT generator, alpha, beta, pulls
                   FROM generator_bandits
                   WHERE context=? AND generator IN ({placeholders})"#
            );
            let mut statement = connection.prepare(&sql)?;
            let parameters = std::iter::once(bandit_context.as_str())
                .chain(generator_names.iter().map(String::as_str));
            let rows = statement.query_map(rusqlite::params_from_iter(parameters), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
            for row in rows {
                let (generator, alpha, beta, pulls) = row?;
                if scheduler_generators.contains(&generator) {
                    continue;
                }
                // Pre-v9 rows had no CHECK constraints. Treat negative,
                // infinite or NaN posteriors as an untrained arm instead of
                // allowing invalid floats or integer overflow into ranking.
                let alpha = if alpha.is_finite() {
                    alpha.clamp(1.0, MAX_SCHEDULER_TOTAL)
                } else {
                    1.0
                };
                let beta = if beta.is_finite() {
                    beta.clamp(1.0, MAX_SCHEDULER_TOTAL)
                } else {
                    1.0
                };
                let pulls = pulls.max(0);
                let total = (alpha + beta).clamp(2.0, MAX_SCHEDULER_TOTAL * 2.0);
                let mean = (alpha / total).clamp(0.0, 1.0);
                let variance = (alpha * beta / (total * total * (total + 1.0))).max(0.0);
                let uncertainty = if variance.is_finite() {
                    variance.sqrt()
                } else {
                    0.0
                };
                let exploration = if pulls < 5 { 0.35 } else { 0.12 };
                let posterior_score =
                    ((mean + exploration * uncertainty).clamp(0.0, 1.0) * 1_000.0).round() as i64;
                let weight = scheduler_context_weight(&bandit_context).round() as i64;
                let weighted_score = posterior_score.saturating_mul(weight);
                let score = scores.entry(generator).or_default();
                *score = score.saturating_add(weighted_score);
            }
        }
        Ok(scores)
    }

    /// Returns rewards that are genuinely new for this scan. A generator is
    /// rewarded only when it produced a strict live, non-wildcard name whose
    /// permanent inventory row was first created by the same scan.
    pub fn exclusive_generator_successes(&self, scan_id: i64) -> Result<HashMap<String, usize>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT candidate.generator, COUNT(DISTINCT candidate.fqdn)
               FROM scan_candidates candidate
               JOIN subdomains inventory ON inventory.fqdn=candidate.fqdn
               JOIN scan_findings finding
                 ON finding.scan_id=candidate.scan_id AND finding.fqdn=candidate.fqdn
               WHERE candidate.scan_id=?1
                 AND inventory.first_scan_id=?1
                 AND finding.state='live'
                 AND finding.wildcard=0
                 AND finding.wildcard_verdict<>'synthesized'
               GROUP BY candidate.generator"#,
        )?;
        let rows = statement.query_map([scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut rewards = HashMap::new();
        for row in rows {
            let (generator, count) = row?;
            rewards.insert(generator, count.max(0) as usize);
        }
        Ok(rewards)
    }

    pub fn exclusive_live_count(&self, scan_id: i64) -> Result<usize> {
        let count: i64 = self.lock()?.query_row(
            r#"SELECT COUNT(*)
               FROM scan_findings finding
               JOIN subdomains inventory ON inventory.fqdn=finding.fqdn
               WHERE finding.scan_id=?1
                 AND inventory.first_scan_id=?1
                 AND finding.state='live'
                 AND finding.wildcard=0
                 AND finding.wildcard_verdict<>'synthesized'"#,
            [scan_id],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn store_name_templates(
        &self,
        root_domain: &str,
        templates: &[crate::intelligence::NameTemplate],
    ) -> Result<()> {
        if templates.is_empty() {
            return Ok(());
        }
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for template in templates.iter().take(1_024) {
            let parent_zone = if template.parent_relative.is_empty() {
                root_domain.to_owned()
            } else {
                format!("{}.{}", template.parent_relative, root_domain)
            };
            let serialized = serde_json::to_string(template)?;
            let score =
                template.support as f64 + f64::from(template.temporal_score_milli) / 1_000.0;
            transaction.execute(
                r#"INSERT INTO name_templates(
                       root_domain, parent_zone, template, support, successes,
                       score, first_seen, last_seen
                   ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?6)
                   ON CONFLICT(root_domain, parent_zone, template) DO UPDATE SET
                   support=excluded.support,
                   score=excluded.score,
                   last_seen=excluded.last_seen"#,
                params![
                    root_domain,
                    parent_zone,
                    serialized,
                    template.support as i64,
                    score,
                    now
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn record_generator_results(
        &self,
        domain: &str,
        attempts: &HashMap<String, usize>,
        successes: &HashMap<String, usize>,
    ) -> Result<()> {
        let now = now_epoch();
        let hashed_domain =
            domain_hash(&registrable_domain(domain).unwrap_or_else(|| domain.to_ascii_lowercase()));
        let context = format!(
            "suffix:{}",
            public_suffix(domain).unwrap_or_else(|| domain.to_owned())
        );
        let mut connection = self.lock()?;
        let bandit_contexts = candidate_contexts(&connection, domain)?;
        let transaction = connection.transaction()?;
        for (generator, attempt_count) in attempts {
            let success_count = successes.get(generator).copied().unwrap_or_default();
            transaction.execute(
                r#"INSERT INTO generator_stats(
                   generator, attempts, successes, unique_domains, first_seen, last_seen
                   ) VALUES (?1, ?2, ?3, 0, ?4, ?4)
                   ON CONFLICT(generator) DO UPDATE SET
                   attempts=generator_stats.attempts+excluded.attempts,
                   successes=generator_stats.successes+excluded.successes,
                   last_seen=excluded.last_seen"#,
                params![generator, *attempt_count as i64, success_count as i64, now],
            )?;
            let failures = attempt_count.saturating_sub(success_count);
            for bandit_context in &bandit_contexts {
                transaction.execute(
                    r#"INSERT INTO generator_bandits(
                       context, generator, alpha, beta, pulls, rewards, last_seen
                       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                       ON CONFLICT(context, generator) DO UPDATE SET
                       alpha=generator_bandits.alpha+excluded.alpha-1.0,
                       beta=generator_bandits.beta+excluded.beta-1.0,
                       pulls=generator_bandits.pulls+excluded.pulls,
                       rewards=generator_bandits.rewards+excluded.rewards,
                       last_seen=excluded.last_seen"#,
                    params![
                        bandit_context,
                        generator,
                        1.0 + success_count as f64,
                        1.0 + failures as f64,
                        *attempt_count as i64,
                        success_count as i64,
                        now
                    ],
                )?;
            }
            transaction.execute(
                r#"INSERT INTO generator_context_stats(
                   context, generator, attempts, successes, last_seen
                   ) VALUES (?1, ?2, ?3, ?4, ?5)
                   ON CONFLICT(context, generator) DO UPDATE SET
                   attempts=generator_context_stats.attempts+excluded.attempts,
                   successes=generator_context_stats.successes+excluded.successes,
                   last_seen=excluded.last_seen"#,
                params![
                    context,
                    generator,
                    *attempt_count as i64,
                    success_count as i64,
                    now
                ],
            )?;
            if success_count > 0 {
                let inserted = transaction.execute(
                    r#"INSERT OR IGNORE INTO generator_domains(
                       generator, domain_hash, first_seen
                       ) VALUES (?1, ?2, ?3)"#,
                    params![generator, hashed_domain, now],
                )?;
                if inserted > 0 {
                    transaction.execute(
                        r#"UPDATE generator_stats
                           SET unique_domains=unique_domains+1 WHERE generator=?1"#,
                        [generator],
                    )?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_scan_with_learning(
        &self,
        scan_id: i64,
        domain: &str,
        generator_attempts: &HashMap<String, usize>,
        generator_successes: &HashMap<String, usize>,
        attempted_words: &BTreeSet<String>,
        successful_words: &BTreeSet<String>,
        successful_patterns: &BTreeSet<String>,
        candidates: usize,
        found: usize,
        cache_hits: usize,
        duration_ms: u128,
        warnings: &[String],
    ) -> Result<()> {
        let now = now_epoch();
        let registrable = registrable_domain(domain).unwrap_or_else(|| domain.to_ascii_lowercase());
        let hashed_domain = domain_hash(&registrable);
        let generator_context = format!(
            "suffix:{}",
            public_suffix(domain).unwrap_or_else(|| domain.to_owned())
        );
        let mut connection = self.lock()?;
        let bandit_contexts = candidate_contexts(&connection, domain)?;
        let transaction = connection.transaction()?;
        let claimed = transaction.execute(
            "UPDATE scans SET learning_applied=1 WHERE id=?1 AND learning_applied=0",
            [scan_id],
        )?;
        if claimed == 0 {
            bail!("l'apprentissage du scan #{scan_id} a déjà été finalisé");
        }

        for (generator, attempt_count) in generator_attempts {
            let success_count = generator_successes
                .get(generator)
                .copied()
                .unwrap_or_default();
            transaction.execute(
                r#"INSERT INTO generator_stats(
                   generator, attempts, successes, unique_domains, first_seen, last_seen
                   ) VALUES (?1, ?2, ?3, 0, ?4, ?4)
                   ON CONFLICT(generator) DO UPDATE SET
                   attempts=generator_stats.attempts+excluded.attempts,
                   successes=generator_stats.successes+excluded.successes,
                   last_seen=excluded.last_seen"#,
                params![generator, *attempt_count as i64, success_count as i64, now],
            )?;
            let failures = attempt_count.saturating_sub(success_count);
            for bandit_context in &bandit_contexts {
                transaction.execute(
                    r#"INSERT INTO generator_bandits(
                       context, generator, alpha, beta, pulls, rewards, last_seen
                       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                       ON CONFLICT(context, generator) DO UPDATE SET
                       alpha=generator_bandits.alpha+excluded.alpha-1.0,
                       beta=generator_bandits.beta+excluded.beta-1.0,
                       pulls=generator_bandits.pulls+excluded.pulls,
                       rewards=generator_bandits.rewards+excluded.rewards,
                       last_seen=excluded.last_seen"#,
                    params![
                        bandit_context,
                        generator,
                        1.0 + success_count as f64,
                        1.0 + failures as f64,
                        *attempt_count as i64,
                        success_count as i64,
                        now
                    ],
                )?;
            }
            transaction.execute(
                r#"INSERT INTO generator_context_stats(
                   context, generator, attempts, successes, last_seen
                   ) VALUES (?1, ?2, ?3, ?4, ?5)
                   ON CONFLICT(context, generator) DO UPDATE SET
                   attempts=generator_context_stats.attempts+excluded.attempts,
                   successes=generator_context_stats.successes+excluded.successes,
                   last_seen=excluded.last_seen"#,
                params![
                    generator_context,
                    generator,
                    *attempt_count as i64,
                    success_count as i64,
                    now
                ],
            )?;
            if success_count > 0 {
                let inserted = transaction.execute(
                    r#"INSERT OR IGNORE INTO generator_domains(
                       generator, domain_hash, first_seen
                       ) VALUES (?1, ?2, ?3)"#,
                    params![generator, hashed_domain, now],
                )?;
                if inserted > 0 {
                    transaction.execute(
                        "UPDATE generator_stats SET unique_domains=unique_domains+1 WHERE generator=?1",
                        [generator],
                    )?;
                }
            }
        }

        for (generator, attempt_count) in generator_attempts {
            let success_count = generator_successes
                .get(generator)
                .copied()
                .unwrap_or_default();
            let attempts = u64::try_from(*attempt_count)
                .context("compteur d'essais generator supérieur à u64")?;
            let exclusive_live = u64::try_from(success_count)
                .context("compteur de récompenses generator supérieur à u64")?;
            let outcome = SchedulerOutcome {
                generator: generator.clone(),
                attempts,
                exclusive_live,
                packets: attempts,
                total_cost: attempts as f64,
            };
            for scheduler_context in &bandit_contexts {
                upsert_scheduler_arm(&transaction, scheduler_context, &outcome, now)?;
            }
        }

        let all_words = attempted_words
            .iter()
            .chain(successful_words.iter())
            .collect::<BTreeSet<_>>();
        // A deep scan can contribute up to 100k words. Reuse the compiled
        // statements instead of asking SQLite to prepare the same SQL several
        // hundred thousand times while the user waits for finalization.
        {
            let mut upsert_word = transaction.prepare(
                r#"INSERT INTO word_stats(
                   word, attempts, successes, unique_domains, first_seen, last_seen
                   ) VALUES (?1, ?2, ?3, 0, ?4, ?4)
                   ON CONFLICT(word) DO UPDATE SET attempts=attempts+excluded.attempts,
                   successes=successes+excluded.successes, last_seen=excluded.last_seen"#,
            )?;
            let mut insert_word_domain = transaction.prepare(
                "INSERT OR IGNORE INTO word_domains(word, domain_hash, first_seen) VALUES (?1, ?2, ?3)",
            )?;
            let mut increment_word_domains = transaction
                .prepare("UPDATE word_stats SET unique_domains=unique_domains+1 WHERE word=?1")?;
            for word in all_words {
                let attempts = i64::from(attempted_words.contains(word));
                let successes = i64::from(successful_words.contains(word));
                upsert_word.execute(params![word, attempts, successes, now])?;
                if successes > 0
                    && insert_word_domain.execute(params![word, hashed_domain, now])? > 0
                {
                    increment_word_domains.execute([word])?;
                }
            }
        }

        {
            let mut upsert_pattern = transaction.prepare(
                r#"INSERT INTO relative_patterns(
                   relative_name, successes, unique_domains, first_seen, last_seen
                   ) VALUES (?1, 1, 0, ?2, ?2)
                   ON CONFLICT(relative_name) DO UPDATE SET
                   successes=successes+1, last_seen=excluded.last_seen"#,
            )?;
            let mut insert_pattern_domain = transaction.prepare(
                r#"INSERT OR IGNORE INTO pattern_domains(relative_name, domain_hash, first_seen)
                   VALUES (?1, ?2, ?3)"#,
            )?;
            let mut increment_pattern_domains = transaction.prepare(
                "UPDATE relative_patterns SET unique_domains=unique_domains+1 WHERE relative_name=?1",
            )?;
            for pattern in successful_patterns {
                upsert_pattern.execute(params![pattern, now])?;
                if insert_pattern_domain.execute(params![pattern, hashed_domain, now])? > 0 {
                    increment_pattern_domains.execute([pattern])?;
                }
            }
        }

        transaction.execute(
            "DELETE FROM scan_generator_stats WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_attempted_words WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            r#"UPDATE scans SET finished_at=?1, status='completed', candidates=?2,
               found=?3, cache_hits=?4, duration_ms=?5, warnings_json=?6 WHERE id=?7"#,
            params![
                now_epoch(),
                usize_to_i64_saturating(candidates),
                usize_to_i64_saturating(found),
                usize_to_i64_saturating(cache_hits),
                duration_ms.min(i64::MAX as u128) as i64,
                serde_json::to_string(warnings)?,
                scan_id
            ],
        )?;
        transaction.execute(
            "UPDATE scan_checkpoints SET stage='complete', updated_at=?1, completed=1 WHERE scan_id=?2",
            params![now_epoch(), scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_candidate_feeds WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_seed_candidates WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_recursive_candidates WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_recursive_parents WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_recursive_words WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.commit()?;
        drop(connection);
        let _ = self.prune_superseded_candidate_queues(2_000);
        Ok(())
    }
}
