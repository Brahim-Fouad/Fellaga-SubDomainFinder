use super::*;

impl Database {
    pub fn store_observations(
        &self,
        root_domain: &str,
        observations: Vec<ObservationInput>,
    ) -> Result<usize> {
        Ok(self
            .store_observations_with_stats(root_domain, observations)?
            .written)
    }

    fn store_observations_with_stats(
        &self,
        root_domain: &str,
        observations: Vec<ObservationInput>,
    ) -> Result<ObservationWriteStats> {
        if let Some(writer) = &self.writer {
            writer.submit_with_stats(root_domain, observations)
        } else {
            let mut connection = self.lock()?;
            insert_observations_with_stats(&mut connection, root_domain, &observations)
        }
    }

    pub fn store_scan_observations(
        &self,
        root_domain: &str,
        sources: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<usize> {
        let observations = sources
            .iter()
            .flat_map(|(fqdn, origins)| {
                origins.iter().map(move |source| {
                    let kind = source.split(':').next().unwrap_or("discovery").to_owned();
                    ObservationInput {
                        fqdn: fqdn.clone(),
                        kind,
                        source: source.clone(),
                        value: String::new(),
                    }
                })
            })
            .collect();
        self.store_observations(root_domain, observations)
    }

    pub fn observation_names(&self, root_domain: &str, source: &str) -> Result<Vec<String>> {
        self.observation_names_bounded(root_domain, source, usize::MAX)
    }

    pub fn observation_names_bounded(
        &self,
        root_domain: &str,
        source: &str,
        limit: usize,
    ) -> Result<Vec<String>> {
        self.observation_names_bounded_before(root_domain, source, limit, None)
    }

    pub fn observation_names_bounded_until(
        &self,
        root_domain: &str,
        source: &str,
        limit: usize,
        deadline: Instant,
    ) -> Result<Vec<String>> {
        self.observation_names_bounded_before(root_domain, source, limit, Some(deadline))
    }

    fn observation_names_bounded_before(
        &self,
        root_domain: &str,
        source: &str,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        ensure_passive_persistence_deadline(deadline)?;
        let connection = self.lock_passive_until(deadline)?;
        let mut statement = connection.prepare(
            r#"SELECT e.name_id, n.fqdn FROM observation_evidence e
               JOIN observed_names n ON n.id=e.name_id
               WHERE e.root_domain=?1 AND e.source=?2 AND e.name_id>?3
               ORDER BY e.name_id LIMIT ?4"#,
        )?;
        let mut names = BTreeSet::new();
        let mut last_name_id = 0_i64;
        while names.len() < limit {
            ensure_passive_persistence_deadline(deadline)?;
            let page_limit = limit
                .saturating_sub(names.len())
                .clamp(1, 4_096)
                .min(i64::MAX as usize) as i64;
            let mut rows =
                statement.query(params![root_domain, source, last_name_id, page_limit])?;
            let mut page_last_name_id = None;
            let mut page_rows = 0_usize;
            while let Some(row) = rows.next()? {
                if page_rows.is_multiple_of(256) {
                    ensure_passive_persistence_deadline(deadline)?;
                }
                let name_id = row.get::<_, i64>(0)?;
                page_last_name_id = Some(name_id);
                names.insert(row.get::<_, String>(1)?);
                page_rows = page_rows.saturating_add(1);
            }
            drop(rows);
            let Some(page_last_name_id) = page_last_name_id else {
                break;
            };
            last_name_id = page_last_name_id;
        }
        ensure_passive_persistence_deadline(deadline)?;
        // The observation index is ordered by (root_domain, source, name_id),
        // so every page can stop without first sorting every matching FQDN.
        // Moving the keyset cursor past the last name_id also skips any
        // remaining evidence variants for an already collected name.
        Ok(names.into_iter().collect())
    }

    pub fn wildcard_cache(&self, zone: &str) -> Result<Option<WildcardCacheEntry>> {
        let connection = self.lock()?;
        let row: Option<(String, Option<i64>, i64, i64)> = connection
            .query_row(
                r#"SELECT signature_json, soa_serial, expires_at, algorithm_version
                   FROM wildcard_cache WHERE zone=?1"#,
                [zone],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(signature, serial, expires_at, algorithm_version)| {
            Ok(WildcardCacheEntry {
                signature: serde_json::from_str::<Vec<String>>(&signature)?
                    .into_iter()
                    .filter(|item| !item.ends_with(":*"))
                    .collect(),
                soa_serial: serial.map(|value| value.max(0) as u64),
                expires_at,
                algorithm_version,
            })
        })
        .transpose()
    }

    pub fn store_wildcard_cache(
        &self,
        zone: &str,
        signature: &BTreeSet<String>,
        soa_serial: Option<u64>,
        freshness: std::time::Duration,
        probed: bool,
    ) -> Result<()> {
        self.store_wildcard_cache_with_algorithm(zone, signature, soa_serial, freshness, probed, 4)
    }

    pub fn store_wildcard_cache_with_algorithm(
        &self,
        zone: &str,
        signature: &BTreeSet<String>,
        soa_serial: Option<u64>,
        freshness: std::time::Duration,
        probed: bool,
        algorithm_version: i64,
    ) -> Result<()> {
        if !(2..=5).contains(&algorithm_version) {
            bail!("version d'algorithme wildcard non prise en charge: {algorithm_version}");
        }
        let now = now_epoch();
        let expires_at = now.saturating_add(freshness.as_secs().min(i64::MAX as u64) as i64);
        self.lock()?.execute(
            r#"INSERT INTO wildcard_cache(
               zone, signature_json, soa_serial, updated_at, expires_at, probe_count,
               algorithm_version
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(zone) DO UPDATE SET
               signature_json=excluded.signature_json,
               soa_serial=excluded.soa_serial,
               updated_at=excluded.updated_at,
               expires_at=excluded.expires_at,
               probe_count=CASE
                   WHEN wildcard_cache.probe_count<0 THEN excluded.probe_count
                   WHEN wildcard_cache.probe_count>=9223372036854775807-excluded.probe_count
                   THEN 9223372036854775807
                   ELSE wildcard_cache.probe_count+excluded.probe_count
               END,
               algorithm_version=excluded.algorithm_version"#,
            params![
                zone,
                serde_json::to_string(&signature.iter().cloned().collect::<Vec<_>>())?,
                soa_serial.map(|value| value.min(i64::MAX as u64) as i64),
                now,
                expires_at,
                i64::from(probed),
                algorithm_version
            ],
        )?;
        Ok(())
    }

    pub fn resolver_history(&self) -> Result<HashMap<String, ResolverMetric>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT resolver, requests, successes, failures,
               CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END,
               consecutive_failures FROM resolver_stats"#,
        )?;
        statement
            .query_map([], |row| {
                let metric = ResolverMetric {
                    resolver: row.get(0)?,
                    requests: row.get::<_, i64>(1)?.max(0) as u64,
                    successes: row.get::<_, i64>(2)?.max(0) as u64,
                    failures: row.get::<_, i64>(3)?.max(0) as u64,
                    average_ms: row.get::<_, i64>(4)?.max(0) as u64,
                    consecutive_failures: row.get::<_, i64>(5)?.max(0) as u64,
                };
                Ok((metric.resolver.clone(), metric))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(Into::into)
    }

    pub fn store_resolver_metrics(&self, metrics: &[ResolverMetric]) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for metric in metrics {
            let requests = u64_to_i64_saturating(metric.requests);
            let successes = u64_to_i64_saturating(metric.successes);
            let failures = u64_to_i64_saturating(metric.failures);
            let total_ms = u64_to_i64_saturating(metric.average_ms.saturating_mul(metric.requests));
            let consecutive_failures = u64_to_i64_saturating(metric.consecutive_failures);
            transaction.execute(
                r#"INSERT INTO resolver_stats(
                   resolver, requests, successes, failures, total_ms,
                   consecutive_failures, last_used
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                   ON CONFLICT(resolver) DO UPDATE SET
                   requests=CASE
                       WHEN MAX(resolver_stats.requests, 0)>9223372036854775807-excluded.requests
                       THEN 9223372036854775807
                       ELSE MAX(resolver_stats.requests, 0)+excluded.requests END,
                   successes=CASE
                       WHEN MAX(resolver_stats.successes, 0)>9223372036854775807-excluded.successes
                       THEN 9223372036854775807
                       ELSE MAX(resolver_stats.successes, 0)+excluded.successes END,
                   failures=CASE
                       WHEN MAX(resolver_stats.failures, 0)>9223372036854775807-excluded.failures
                       THEN 9223372036854775807
                       ELSE MAX(resolver_stats.failures, 0)+excluded.failures END,
                   total_ms=CASE
                       WHEN MAX(resolver_stats.total_ms, 0)>9223372036854775807-excluded.total_ms
                       THEN 9223372036854775807
                       ELSE MAX(resolver_stats.total_ms, 0)+excluded.total_ms END,
                   consecutive_failures=excluded.consecutive_failures,
                   last_used=excluded.last_used"#,
                params![
                    metric.resolver,
                    requests,
                    successes,
                    failures,
                    total_ms,
                    consecutive_failures,
                    now
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn fresh_cache(&self, hosts: &[String]) -> Result<HashMap<String, CachedAnswer>> {
        let now = now_epoch();
        let connection = self.lock()?;
        let mut answers = HashMap::new();
        for chunk in hosts.chunks(500) {
            if chunk.is_empty() {
                continue;
            }
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT fqdn, status, records_json, last_checked, resolver_count, authoritative FROM dns_cache \
                 WHERE fqdn IN ({placeholders}) \
                 AND (status='positive' OR expires_at>{now})"
            );
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(rusqlite::params_from_iter(chunk.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            for row in rows {
                let (host, status, records_json, last_checked, resolver_count, authoritative) =
                    row?;
                if status == "positive" {
                    let Ok(records) =
                        serde_json::from_str::<Vec<crate::model::DnsRecord>>(&records_json)
                    else {
                        continue;
                    };
                    if records.is_empty() {
                        continue;
                    }
                    answers.insert(
                        host.clone(),
                        CachedAnswer::Positive(ResolvedHost {
                            fqdn: host.clone(),
                            records,
                            from_cache: true,
                            last_verified_at: Some(last_checked),
                            authoritative_validation: authoritative != 0,
                            resolver_count: resolver_count.clamp(0, i64::from(u16::MAX)) as u16,
                        }),
                    );
                } else {
                    answers.insert(host.clone(), CachedAnswer::Negative);
                }
            }
        }
        Ok(answers)
    }

    pub fn positive_cache_names(&self, domain: &str) -> Result<Vec<String>> {
        let suffix = format!("%.{domain}");
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT fqdn FROM dns_cache
               WHERE status='positive' AND (fqdn=?1 OR fqdn LIKE ?2)
               ORDER BY fqdn"#,
        )?;
        statement
            .query_map(params![domain, suffix], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Return candidates that have durable positive or observational history.
    ///
    /// The discovery-only one-resolver shortcut is safe only for names that
    /// Fellaga has never seen. Expiry and active state are intentionally
    /// ignored: retained inventory, normalized observations, and positive DNS
    /// cache entries always require the conservative resolver path.
    pub fn known_discovery_names(&self, hosts: &[String]) -> Result<BTreeSet<String>> {
        const LOOKUP_BATCH_SIZE: usize = 500;

        let connection = self.lock()?;
        let mut known = BTreeSet::new();
        for batch in hosts.chunks(LOOKUP_BATCH_SIZE) {
            if batch.is_empty() {
                continue;
            }
            let placeholders = std::iter::repeat_n("?", batch.len())
                .collect::<Vec<_>>()
                .join(",");
            for query in [
                format!("SELECT fqdn FROM subdomains WHERE fqdn IN ({placeholders})"),
                format!(
                    "SELECT DISTINCT names.fqdn FROM observed_names names \
                     JOIN observation_evidence evidence ON evidence.name_id=names.id \
                     WHERE names.fqdn IN ({placeholders})"
                ),
                format!(
                    "SELECT fqdn FROM dns_cache \
                     WHERE status='positive' AND fqdn IN ({placeholders})"
                ),
            ] {
                let mut statement = connection.prepare(&query)?;
                let rows = statement
                    .query_map(rusqlite::params_from_iter(batch.iter()), |row| {
                        row.get::<_, String>(0)
                    })?;
                for row in rows {
                    known.insert(row?);
                }
            }
        }
        Ok(known)
    }

    pub fn update_cache(
        &self,
        queried_hosts: &[String],
        resolved: &[ResolvedHost],
        _ttl_cap: u32,
        negative_ttl: u32,
    ) -> Result<()> {
        let positive = resolved
            .iter()
            .map(|answer| answer.fqdn.as_str())
            .collect::<BTreeSet<_>>();
        let negative = queried_hosts
            .iter()
            .filter(|host| !positive.contains(host.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        self.update_cache_outcomes(None, resolved, &negative, &[], negative_ttl)
    }

    /// Persist definitive negatives produced by the discovery-only fast path.
    ///
    /// These observations are deliberately journal-only: they may terminate a
    /// candidate in the current scan, but they must not poison the reusable DNS
    /// cache or demote permanent inventory that was validated previously.
    pub fn record_discovery_negatives(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }

        const WRITE_BATCH_SIZE: usize = 500;
        const DETAILS_JSON: &str =
            r#"{"scope":"discovery-only","cache_write":false,"inventory_write":false}"#;

        // Sorting references keeps duplicate inputs from creating duplicate
        // journal events without cloning a potentially large hostname batch.
        let mut unique_hosts = hosts.iter().map(String::as_str).collect::<Vec<_>>();
        unique_hosts.sort_unstable();
        unique_hosts.dedup();

        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        {
            // The statement has a fixed parameter count. Chunking bounds each
            // write wave even when the caller supplies millions of candidates.
            let mut statement = transaction.prepare(
                r#"INSERT INTO dns_verifications(
                       scan_id, fqdn, checked_at, outcome, resolver_count,
                       authoritative, records_hash, details_json
                   ) VALUES (?1, ?2, ?3, 'negative', 1, 0, NULL, ?4)"#,
            )?;
            for batch in unique_hosts.chunks(WRITE_BATCH_SIZE) {
                for host in batch {
                    statement.execute(params![scan_id, *host, now, DETAILS_JSON])?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Journal current-scan network positives that match a confirmed wildcard.
    ///
    /// This marker is the authorization boundary for wildcard quarantine
    /// cleanup. Cached or single-resolver answers cannot create it, and
    /// recording it does not mutate the reusable cache, inventory, or
    /// historical DNS records.
    pub fn record_current_wildcard_matches(
        &self,
        scan_id: i64,
        answers: &[ResolvedHost],
    ) -> Result<usize> {
        let network_answers = answers
            .iter()
            .filter(|answer| {
                !answer.from_cache
                    && !answer.records.is_empty()
                    && (answer.resolver_count >= 2 || answer.authoritative_validation)
            })
            .collect::<Vec<_>>();
        if network_answers.is_empty() {
            return Ok(0);
        }

        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut inserted = 0_usize;
        {
            let mut statement = transaction.prepare(
                r#"INSERT INTO dns_verifications(
                       scan_id, fqdn, checked_at, outcome, resolver_count,
                       authoritative, records_hash, details_json
                   ) VALUES (?1, ?2, ?3, 'unverified', ?4, ?5, ?6, ?7)"#,
            )?;
            for answer in network_answers {
                let records_hash = canonical_dns_records_hash(&answer.records)?;
                inserted = inserted.saturating_add(statement.execute(params![
                    scan_id,
                    answer.fqdn,
                    now,
                    i64::from(answer.resolver_count),
                    i64::from(answer.authoritative_validation),
                    records_hash,
                    CURRENT_SCAN_WILDCARD_MATCH_DETAILS
                ])?);
            }
        }
        transaction.commit()?;
        Ok(inserted)
    }

    /// Quarantines names whose non-existence was established by a locally
    /// validated DNSSEC NSEC/NSEC3 proof.  This is intentionally separate from
    /// heuristic wildcard cleanup: the caller must supply only cryptographic
    /// proof outcomes, and every mutation remains scoped to one root domain.
    pub fn quarantine_dnssec_nonexistent(
        &self,
        scan_id: i64,
        root_domain: &str,
        hosts: &[String],
    ) -> Result<usize> {
        let suffix = format!(".{root_domain}");
        let hosts = hosts
            .iter()
            .filter(|host| host.ends_with(&suffix))
            .take(64)
            .collect::<BTreeSet<_>>();
        if hosts.is_empty() {
            return Ok(0);
        }
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut journal = transaction.prepare(
            r#"INSERT INTO dns_verifications(
                   scan_id, fqdn, checked_at, outcome, resolver_count,
                   authoritative, records_hash, details_json
               ) VALUES (?1, ?2, ?3, 'negative', 1, 0, NULL,
                         '{"reason":"dnssec_validated_nonexistence","cache":"never_for_compact_denial"}')"#,
        )?;
        for host in &hosts {
            quarantine_wildcard_host(
                &transaction,
                root_domain,
                host,
                scan_id,
                "dnssec_validated_nonexistence",
                now,
            )?;
            journal.execute(params![scan_id, *host, now])?;
        }
        drop(journal);
        transaction.commit()?;
        Ok(hosts.len())
    }

    /// Records a current positive response that remains ambiguous against a
    /// freshly completed wildcard classification. The caller must never use
    /// this destructive demotion after an indeterminate/incomplete profile.
    /// Unlike the exact-match marker above, this never authorizes quarantine.
    /// It removes reusable positive cache material and demotes only the
    /// materialized inventory for this root while retaining records, sources,
    /// and append-only history.
    pub fn record_current_wildcard_ambiguities(
        &self,
        scan_id: i64,
        root_domain: &str,
        answers: &[ResolvedHost],
    ) -> Result<usize> {
        let network_answers = answers
            .iter()
            .filter(|answer| !answer.from_cache && !answer.records.is_empty())
            .collect::<Vec<_>>();
        if network_answers.is_empty() {
            return Ok(0);
        }

        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let scan = transaction
            .query_row(
                "SELECT domain, status FROM scans WHERE id=?1",
                [scan_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if scan.as_ref().map(|(domain, _)| domain.as_str()) != Some(root_domain) {
            bail!("la zone d'ambiguïté wildcard ne correspond pas au scan {scan_id}");
        }
        if scan.as_ref().map(|(_, status)| status.as_str()) != Some("running") {
            bail!("le scan {scan_id} n'est plus actif pour une ambiguïté wildcard");
        }
        if let Some(answer) = network_answers
            .iter()
            .find(|answer| !is_strict_subdomain(&answer.fqdn, root_domain))
        {
            bail!("réponse wildcard hors zone refusée: {}", answer.fqdn);
        }
        let mut inserted = 0_usize;
        {
            let mut statement = transaction.prepare(
                r#"INSERT INTO dns_verifications(
                       scan_id, fqdn, checked_at, outcome, resolver_count,
                       authoritative, records_hash, details_json
                   ) VALUES (?1, ?2, ?3, 'unverified', ?4, ?5, ?6, ?7)"#,
            )?;
            for answer in &network_answers {
                let records_hash = canonical_dns_records_hash(&answer.records)?;
                inserted = inserted.saturating_add(statement.execute(params![
                    scan_id,
                    answer.fqdn,
                    now,
                    i64::from(answer.resolver_count),
                    i64::from(answer.authoritative_validation),
                    records_hash,
                    CURRENT_SCAN_WILDCARD_AMBIGUITY_DETAILS
                ])?);
            }
        }
        {
            let mut delete_cache = transaction.prepare("DELETE FROM dns_cache WHERE fqdn=?1")?;
            let mut demote_inventory = transaction.prepare(
                r#"UPDATE subdomains
                   SET active=0, verification_state='unverified', last_verified_at=NULL
                   WHERE root_domain=?1 AND fqdn=?2"#,
            )?;
            let mut demote_records =
                transaction.prepare("UPDATE dns_records SET active=0 WHERE fqdn=?1")?;
            for answer in network_answers {
                delete_cache.execute([answer.fqdn.as_str()])?;
                if demote_inventory.execute(params![root_domain, answer.fqdn])? > 0 {
                    demote_records.execute([answer.fqdn.as_str()])?;
                }
            }
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn update_cache_outcomes(
        &self,
        scan_id: Option<i64>,
        resolved: &[ResolvedHost],
        definitive_negative: &[String],
        indeterminate: &[String],
        negative_ttl: u32,
    ) -> Result<()> {
        let now = now_epoch();
        // A live answer is the strongest outcome in one validation wave.  Bad
        // caller input must not let a duplicate negative/error overwrite its
        // permanent cache entry or demote the inventory in the same commit.
        let positive_hosts = resolved
            .iter()
            .map(|answer| answer.fqdn.as_str())
            .collect::<BTreeSet<_>>();
        let definitive_negative = definitive_negative
            .iter()
            .map(String::as_str)
            .filter(|host| !positive_hosts.contains(host))
            .collect::<BTreeSet<_>>();
        let indeterminate = indeterminate
            .iter()
            .map(String::as_str)
            .filter(|host| !positive_hosts.contains(host) && !definitive_negative.contains(host))
            .collect::<BTreeSet<_>>();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                r#"INSERT INTO dns_cache(
                   fqdn, status, records_json, expires_at, last_checked,
                   resolver_count, authoritative
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                   ON CONFLICT(fqdn) DO UPDATE SET status=excluded.status,
                   records_json=excluded.records_json, expires_at=excluded.expires_at,
                   last_checked=excluded.last_checked,
                   resolver_count=excluded.resolver_count,
                   authoritative=excluded.authoritative"#,
            )?;
            for answer in resolved {
                statement.execute(params![
                    answer.fqdn,
                    "positive",
                    serde_json::to_string(&answer.records)?,
                    PERMANENT_EXPIRY,
                    now,
                    answer.resolver_count,
                    i64::from(answer.authoritative_validation)
                ])?;
            }
            for host in &definitive_negative {
                statement.execute(params![
                    *host,
                    "negative",
                    "[]",
                    now.saturating_add(i64::from(negative_ttl.max(30))),
                    now,
                    0,
                    0
                ])?;
            }
        }
        {
            let mut statement = transaction.prepare(
                r#"INSERT INTO dns_verifications(
                   scan_id, fqdn, checked_at, outcome, resolver_count,
                   authoritative, records_hash, details_json
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            )?;
            for answer in resolved {
                let records_hash = canonical_dns_records_hash(&answer.records)?;
                statement.execute(params![
                    scan_id,
                    answer.fqdn,
                    now,
                    "live",
                    i64::from(answer.resolver_count),
                    answer.authoritative_validation as i64,
                    records_hash,
                    "{}"
                ])?;
            }
            for host in &definitive_negative {
                statement.execute(params![
                    scan_id,
                    *host,
                    now,
                    "negative",
                    1,
                    0,
                    Option::<String>::None,
                    "{}"
                ])?;
            }
            for host in &indeterminate {
                statement.execute(params![
                    scan_id,
                    *host,
                    now,
                    "error",
                    0,
                    0,
                    Option::<String>::None,
                    r#"{"reason":"resolver_or_quorum_unavailable"}"#
                ])?;
            }
        }
        let definitive_negative = definitive_negative.into_iter().collect::<Vec<_>>();
        for chunk in definitive_negative.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            transaction.execute(
                &format!(
                    "UPDATE subdomains SET active=0, verification_state='historical' \
                     WHERE fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(chunk.iter().copied()),
            )?;
            transaction.execute(
                &format!("UPDATE dns_records SET active=0 WHERE fqdn IN ({placeholders})"),
                rusqlite::params_from_iter(chunk.iter().copied()),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn persist_findings(
        &self,
        scan_id: i64,
        domain: &str,
        findings: &[Finding],
        _ttl_cap: u32,
    ) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for finding in findings {
            if finding.state == ObservationState::Live && !finding.wildcard {
                transaction.execute(
                    "DELETE FROM wildcard_quarantine WHERE root_domain=?1 AND fqdn=?2",
                    params![domain, finding.fqdn],
                )?;
            }
            let mut combined_sources = finding.sources.clone();
            if let Some(existing) = transaction
                .query_row(
                    "SELECT sources FROM subdomains WHERE fqdn=?1",
                    [&finding.fqdn],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                combined_sources.extend(
                    existing
                        .split(',')
                        .filter(|source| !source.is_empty())
                        .map(ToOwned::to_owned),
                );
            }
            let sources = combined_sources
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            // Wildcard-positive rows remain in scan_findings for audit, but
            // must never materialize as reusable live inventory/DNS records if
            // a later cleanup phase is cancelled or crashes.
            let materialized_live = finding.state == ObservationState::Live && !finding.wildcard;
            if finding.wildcard {
                // update_cache_outcomes runs before wildcard classification.
                // Remove that provisional positive in this same transaction as
                // the inventory demotion so it cannot be reused by a later scan.
                transaction.execute("DELETE FROM dns_cache WHERE fqdn=?1", [&finding.fqdn])?;
            }
            let inventory_state = if materialized_live {
                ObservationState::Live
            } else if finding.state == ObservationState::Historical {
                ObservationState::Historical
            } else {
                ObservationState::Unverified
            };
            let verified_at = materialized_live
                .then_some(finding.last_verified_at)
                .flatten();
            transaction.execute(
                r#"INSERT INTO subdomains(
                   fqdn, root_domain, first_seen, last_seen, first_scan_id, last_scan_id, times_seen, active,
                   sources, verification_state, last_verified_at
                   ) VALUES (?1, ?2, ?3, ?3, ?4, ?4, 1, ?5, ?6, ?7, ?8)
                   ON CONFLICT(fqdn) DO UPDATE SET last_seen=excluded.last_seen,
                   last_scan_id=excluded.last_scan_id,
                   times_seen=times_seen + CASE
                       WHEN subdomains.last_scan_id<>excluded.last_scan_id THEN 1 ELSE 0 END,
                   active=excluded.active, sources=excluded.sources,
                   verification_state=excluded.verification_state,
                   last_verified_at=CASE WHEN ?9<>0 THEN NULL
                       ELSE COALESCE(excluded.last_verified_at, subdomains.last_verified_at) END"#,
                params![
                    finding.fqdn,
                    domain,
                    now,
                    scan_id,
                    i64::from(materialized_live),
                    sources,
                    inventory_state.as_str(),
                    verified_at,
                    i64::from(finding.wildcard)
                ],
            )?;
            transaction.execute(
                r#"INSERT OR REPLACE INTO scan_findings(
                   scan_id, fqdn, wildcard, from_cache,
                   confidence_score, confidence_label, confidence_reasons_json,
                   state, last_verified_at, evidence_families_json, authoritative_validation,
                   wildcard_verdict, owner_proofs_json, generation_path_json, discovery_score
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
                params![
                    scan_id,
                    finding.fqdn,
                    finding.wildcard as i64,
                    finding.from_cache as i64,
                    i64::from(finding.confidence.score),
                    finding.confidence.label,
                    serde_json::to_string(&finding.confidence.reasons)?,
                    finding.state.as_str(),
                    verified_at,
                    serde_json::to_string(&finding.evidence_families)?,
                    finding.authoritative_validation as i64,
                    finding.wildcard_verdict.as_str(),
                    serde_json::to_string(&finding.owner_proofs)?,
                    serde_json::to_string(&finding.generation_path)?,
                    finding.discovery_score
                ],
            )?;
            transaction.execute(
                "UPDATE dns_records SET active=0 WHERE fqdn=?1",
                [&finding.fqdn],
            )?;
            for record in &finding.records {
                transaction.execute(
                    r#"INSERT INTO dns_records(
                       fqdn, record_type, value, ttl, expires_at, first_seen, last_seen, active
                       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
                       ON CONFLICT(fqdn, record_type, value) DO UPDATE SET
                       ttl=excluded.ttl, expires_at=excluded.expires_at,
                       last_seen=excluded.last_seen, active=excluded.active"#,
                    params![
                        finding.fqdn,
                        record.record_type,
                        record.value,
                        record.ttl,
                        PERMANENT_EXPIRY,
                        now,
                        i64::from(materialized_live)
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Merge provider-only observations into the permanent inventory without
    /// treating the absence of a DNS validation as a negative validation.
    ///
    /// A no-target-contact scan can establish that a name was observed, but it
    /// cannot establish that a previously live name stopped resolving.  New
    /// names therefore start as unverified while existing live/historical
    /// state, verification time and DNS-record activity remain unchanged.
    pub fn persist_unverified_findings_preserving_state(
        &self,
        scan_id: i64,
        domain: &str,
        findings: &[Finding],
    ) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for finding in findings {
            if finding.state != ObservationState::Unverified
                || finding.wildcard
                || !finding.records.is_empty()
                || finding.last_verified_at.is_some()
                || finding.authoritative_validation
                || finding.wildcard_verdict != WildcardVerdict::NotProfiled
                || !finding.owner_proofs.is_empty()
            {
                bail!(
                    "provider-only persistence requires an unverified, unprofiled finding without DNS records: {}",
                    finding.fqdn
                );
            }
            let mut combined_sources = finding.sources.clone();
            if let Some(existing) = transaction
                .query_row(
                    "SELECT sources FROM subdomains WHERE fqdn=?1",
                    [&finding.fqdn],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                combined_sources.extend(
                    existing
                        .split(',')
                        .filter(|source| !source.is_empty())
                        .map(ToOwned::to_owned),
                );
            }
            let sources = combined_sources.into_iter().collect::<Vec<_>>().join(",");
            transaction.execute(
                r#"INSERT INTO subdomains(
                   fqdn, root_domain, first_seen, last_seen, first_scan_id, last_scan_id,
                   times_seen, active, sources, verification_state, last_verified_at
                   ) VALUES (?1, ?2, ?3, ?3, ?4, ?4, 1, 0, ?5, 'unverified', NULL)
                   ON CONFLICT(fqdn) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   last_scan_id=excluded.last_scan_id,
                   times_seen=times_seen + CASE
                       WHEN subdomains.last_scan_id<>excluded.last_scan_id THEN 1 ELSE 0 END,
                   sources=excluded.sources"#,
                params![finding.fqdn, domain, now, scan_id, sources],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Stores the exact result set shown for a scan without changing the
    /// permanent inventory counters or DNS record activity.
    pub fn persist_scan_snapshot(&self, scan_id: i64, findings: &[Finding]) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM scan_findings WHERE scan_id=?1", [scan_id])?;
        for finding in findings {
            transaction.execute(
                r#"INSERT OR REPLACE INTO scan_findings(
                   scan_id, fqdn, wildcard, from_cache,
                   confidence_score, confidence_label, confidence_reasons_json,
                   state, last_verified_at, evidence_families_json, authoritative_validation,
                   wildcard_verdict, owner_proofs_json, generation_path_json, discovery_score
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"#,
                params![
                    scan_id,
                    finding.fqdn,
                    finding.wildcard as i64,
                    finding.from_cache as i64,
                    i64::from(finding.confidence.score),
                    finding.confidence.label,
                    serde_json::to_string(&finding.confidence.reasons)?,
                    finding.state.as_str(),
                    finding.last_verified_at,
                    serde_json::to_string(&finding.evidence_families)?,
                    finding.authoritative_validation as i64,
                    finding.wildcard_verdict.as_str(),
                    serde_json::to_string(&finding.owner_proofs)?,
                    serde_json::to_string(&finding.generation_path)?,
                    finding.discovery_score
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_inactive(&self, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for host in hosts {
            transaction.execute(
                "UPDATE subdomains SET active=0, verification_state='historical' WHERE fqdn=?1",
                [host],
            )?;
            transaction.execute("UPDATE dns_records SET active=0 WHERE fqdn=?1", [host])?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_unverified(
        &self,
        scan_id: Option<i64>,
        hosts: &[String],
        reason: &str,
    ) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let now = now_epoch();
        let details = serde_json::to_string(&json!({ "reason": reason }))?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for host in hosts {
            transaction.execute(
                "UPDATE subdomains SET active=0, verification_state='unverified' WHERE fqdn=?1",
                [host],
            )?;
            transaction.execute("UPDATE dns_records SET active=0 WHERE fqdn=?1", [host])?;
            transaction.execute(
                r#"INSERT INTO dns_verifications(
                   scan_id, fqdn, checked_at, outcome, resolver_count,
                   authoritative, records_hash, details_json
                   ) VALUES (?1, ?2, ?3, 'unverified', 0, 0, NULL, ?4)"#,
                params![scan_id, host, now, details],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Atomically demote completed findings whose stored positive now matches
    /// a reliable wildcard profile and reopen them for bounded DNS
    /// revalidation. The positive cache is intentionally retained: the scan
    /// resolver recognizes a wildcard-shaped cached answer and forces a fresh
    /// network check before it can become live again.
    pub fn demote_and_requeue_scan_findings(
        &self,
        scan_id: i64,
        candidates: &[(String, BTreeSet<String>, i64)],
        reason: &str,
    ) -> Result<()> {
        if candidates.is_empty() {
            return Ok(());
        }
        let now = now_epoch();
        let details = serde_json::to_string(&json!({ "reason": reason }))?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        {
            let mut select_seed = transaction.prepare(
                "SELECT sources_json, priority FROM scan_seed_candidates WHERE scan_id=?1 AND fqdn=?2",
            )?;
            let mut update_seed = transaction.prepare(
                r#"UPDATE scan_seed_candidates
                   SET sources_json=?3, priority=?4, status='queued', attempts=0
                   WHERE scan_id=?1 AND fqdn=?2"#,
            )?;
            let mut insert_seed = transaction.prepare(
                r#"INSERT INTO scan_seed_candidates(
                       scan_id, fqdn, priority, sources_json, status, attempts
                   ) VALUES (?1, ?2, ?3, ?4, 'queued', 0)"#,
            )?;
            for (fqdn, sources, priority) in candidates {
                transaction.execute(
                    "UPDATE subdomains SET active=0, verification_state='unverified', last_verified_at=NULL WHERE fqdn=?1",
                    [fqdn],
                )?;
                transaction.execute("UPDATE dns_records SET active=0 WHERE fqdn=?1", [fqdn])?;
                transaction.execute(
                    r#"UPDATE scan_findings
                       SET state='unverified', last_verified_at=NULL,
                           authoritative_validation=0, wildcard_verdict='ambiguous'
                       WHERE scan_id=?1 AND fqdn=?2"#,
                    params![scan_id, fqdn],
                )?;
                transaction.execute(
                    r#"INSERT INTO dns_verifications(
                       scan_id, fqdn, checked_at, outcome, resolver_count,
                       authoritative, records_hash, details_json
                       ) VALUES (?1, ?2, ?3, 'unverified', 0, 0, NULL, ?4)"#,
                    params![scan_id, fqdn, now, details],
                )?;

                if let Some((sources_json, existing_priority)) = select_seed
                    .query_row(params![scan_id, fqdn], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                    .optional()?
                {
                    let mut merged = serde_json::from_str::<BTreeSet<String>>(&sources_json)
                        .context("provenance de candidat passif SQLite invalide")?;
                    merged.extend(sources.iter().cloned());
                    update_seed.execute(params![
                        scan_id,
                        fqdn,
                        serde_json::to_string(&merged)?,
                        existing_priority.max(*priority)
                    ])?;
                } else {
                    insert_seed.execute(params![
                        scan_id,
                        fqdn,
                        priority,
                        serde_json::to_string(sources)?
                    ])?;
                }
                transaction.execute(
                    "DELETE FROM scan_candidates WHERE scan_id=?1 AND fqdn=?2",
                    params![scan_id, fqdn],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn stage_refresh_wildcard_candidates(
        &self,
        scan_id: i64,
        hosts: &[String],
    ) -> Result<usize> {
        if hosts.is_empty() {
            return Ok(0);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut inserted = 0_usize;
        {
            let mut statement = transaction.prepare(
                r#"INSERT OR IGNORE INTO refresh_wildcard_candidates(scan_id, fqdn)
                   VALUES (?1, ?2)"#,
            )?;
            for host in hosts {
                inserted = inserted.saturating_add(statement.execute(params![scan_id, host])?);
            }
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn discard_refresh_wildcard_candidates(&self, scan_id: i64) -> Result<usize> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM refresh_wildcard_affected_scans WHERE refresh_scan_id=?1",
            [scan_id],
        )?;
        let removed = transaction.execute(
            "DELETE FROM refresh_wildcard_candidates WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.commit()?;
        Ok(removed)
    }

    pub fn refresh_wildcard_candidate_count(&self, scan_id: i64) -> Result<usize> {
        let count = self.lock()?.query_row(
            "SELECT COUNT(*) FROM refresh_wildcard_candidates WHERE scan_id=?1",
            [scan_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn apply_staged_refresh_wildcard_cleanup(
        &self,
        scan_id: i64,
        root_domain: &str,
        page_size: usize,
        cancelled: &AtomicBool,
    ) -> Result<Option<WildcardCleanupResult>> {
        self.apply_staged_refresh_wildcard_cleanup_with_cancel(
            scan_id,
            root_domain,
            page_size,
            |_: usize| cancelled.load(Ordering::Acquire),
        )
    }

    pub(super) fn apply_staged_refresh_wildcard_cleanup_with_cancel<F>(
        &self,
        scan_id: i64,
        root_domain: &str,
        page_size: usize,
        mut should_cancel: F,
    ) -> Result<Option<WildcardCleanupResult>>
    where
        F: FnMut(usize) -> bool,
    {
        let mut connection = loop {
            if should_cancel(0) {
                return Ok(None);
            }
            match self.connection.try_lock() {
                Ok(connection) => break connection,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    bail!("verrou SQLite empoisonné")
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(CT_MATERIALIZATION_LOCK_RETRY);
                }
            }
        };
        if should_cancel(0) {
            return Ok(None);
        }
        let transaction = connection.transaction()?;
        let scan_domain = transaction
            .query_row("SELECT domain FROM scans WHERE id=?1", [scan_id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if scan_domain.as_deref() != Some(root_domain) {
            bail!("la zone de purge wildcard ne correspond pas au scan {scan_id}");
        }
        let page_size = page_size.clamp(1, 400);
        let now = now_epoch();
        let root_suffix = format!(".{root_domain}");
        let mut cursor = None::<String>;
        let mut processed = 0_usize;
        let mut purged = 0_usize;
        let mut retained_unverified = 0_usize;

        loop {
            if should_cancel(processed) {
                transaction.rollback()?;
                return Ok(None);
            }
            let page = {
                let mut statement = transaction.prepare(
                    r#"SELECT fqdn FROM refresh_wildcard_candidates
                       WHERE scan_id=?1 AND (?2 IS NULL OR fqdn>?2)
                       ORDER BY fqdn LIMIT ?3"#,
                )?;
                statement
                    .query_map(
                        params![scan_id, cursor.as_deref(), page_size as i64],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            if page.is_empty() {
                break;
            }
            let (mut stored_sources, independent_sources) =
                wildcard_cleanup_evidence_for_hosts(&transaction, root_domain, &page)?;

            for host in &page {
                if should_cancel(processed) {
                    transaction.rollback()?;
                    return Ok(None);
                }
                if host != root_domain && !host.ends_with(&root_suffix) {
                    bail!("candidat wildcard hors zone refusé: {host}");
                }
                let current_network_match =
                    has_current_scan_wildcard_match(&transaction, scan_id, host)?;
                if !current_network_match {
                    let merged = stored_sources.entry(host.clone()).or_default();
                    if let Some(independent) = independent_sources.get(host) {
                        merged.extend(independent.iter().cloned());
                    }
                    let inventory_changed = transaction.execute(
                        r#"UPDATE subdomains
                           SET active=0, verification_state='unverified', sources=?1,
                               last_verified_at=NULL
                           WHERE fqdn=?2 AND root_domain=?3"#,
                        params![
                            merged.iter().cloned().collect::<Vec<_>>().join(","),
                            host,
                            root_domain
                        ],
                    )?;
                    if inventory_changed > 0 {
                        transaction
                            .execute("UPDATE dns_records SET active=0 WHERE fqdn=?1", [host])?;
                    }
                    transaction.execute(
                        r#"INSERT INTO dns_verifications(
                           scan_id, fqdn, checked_at, outcome, resolver_count,
                           authoritative, records_hash, details_json
                           ) VALUES (?1, ?2, ?3, 'unverified', 0, 0, NULL, ?4)"#,
                        params![
                            scan_id,
                            host,
                            now,
                            serde_json::to_string(&json!({
                                "reason": "cached_wildcard_match_without_current_network_confirmation"
                            }))?
                        ],
                    )?;
                    retained_unverified = retained_unverified.saturating_add(1);
                } else {
                    quarantine_wildcard_host(
                        &transaction,
                        root_domain,
                        host,
                        scan_id,
                        "refresh_confirmed_wildcard_match",
                        now,
                    )?;
                    purged = purged.saturating_add(1);
                }
                processed = processed.saturating_add(1);
            }
            cursor = page.last().cloned();
        }

        if should_cancel(processed) {
            transaction.rollback()?;
            return Ok(None);
        }
        transaction.execute(
            "DELETE FROM refresh_wildcard_affected_scans WHERE refresh_scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM refresh_wildcard_candidates WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.commit()?;
        Ok(Some(WildcardCleanupResult {
            purged,
            retained_unverified,
        }))
    }

    /// Quarantines exact current-network matches under a confirmed wildcard
    /// zone. Passive and historical evidence remains available through
    /// `explain`, but cannot make an indistinguishable wildcard answer visible.
    /// A later non-wildcard live finding lifts the root-specific quarantine.
    pub fn purge_confirmed_wildcard_false_positives(
        &self,
        scan_id: i64,
        root_domain: &str,
        hosts: &[String],
    ) -> Result<Vec<String>> {
        if hosts.is_empty() {
            return Ok(Vec::new());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let scan_domain = transaction
            .query_row("SELECT domain FROM scans WHERE id=?1", [scan_id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        if scan_domain.as_deref() != Some(root_domain) {
            bail!("la zone de purge wildcard ne correspond pas au scan {scan_id}");
        }
        let mut purged = Vec::new();
        let root_suffix = format!(".{root_domain}");
        for host in hosts {
            if host != root_domain && !host.ends_with(&root_suffix) {
                bail!("candidat wildcard hors zone refusé: {host}");
            }
        }

        let now = now_epoch();
        for page in hosts.chunks(400) {
            let (mut stored_sources, independent_sources) =
                wildcard_cleanup_evidence_for_hosts(&transaction, root_domain, page)?;
            for host in page {
                let current_network_match =
                    has_current_scan_wildcard_match(&transaction, scan_id, host)?;
                if current_network_match {
                    quarantine_wildcard_host(
                        &transaction,
                        root_domain,
                        host,
                        scan_id,
                        "confirmed_wildcard_match",
                        now,
                    )?;
                    purged.push(host.clone());
                    continue;
                }

                let merged = stored_sources.entry(host.clone()).or_default();
                if let Some(independent) = independent_sources.get(host) {
                    merged.extend(independent.iter().cloned());
                }
                let inventory_changed = transaction.execute(
                    r#"UPDATE subdomains
                       SET active=0, verification_state='unverified', sources=?1,
                           last_verified_at=NULL
                       WHERE fqdn=?2 AND root_domain=?3"#,
                    params![
                        merged.iter().cloned().collect::<Vec<_>>().join(","),
                        host,
                        root_domain
                    ],
                )?;
                if inventory_changed > 0 {
                    transaction.execute("UPDATE dns_records SET active=0 WHERE fqdn=?1", [host])?;
                }
                transaction.execute(
                    r#"INSERT INTO dns_verifications(
                       scan_id, fqdn, checked_at, outcome, resolver_count,
                       authoritative, records_hash, details_json
                       ) VALUES (?1, ?2, ?3, 'unverified', 0, 0, NULL, ?4)"#,
                    params![
                        scan_id,
                        host,
                        now,
                        serde_json::to_string(&json!({
                            "reason": "wildcard_match_without_current_network_confirmation"
                        }))?
                    ],
                )?;
            }
        }
        transaction.commit()?;
        purged.sort();
        purged.dedup();
        Ok(purged)
    }
}
