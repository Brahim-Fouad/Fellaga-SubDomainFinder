use super::*;

impl Database {
    pub fn known_subdomains(&self, domain: Option<&str>, all: bool) -> Result<Vec<String>> {
        let connection = self.lock()?;
        let sql = match (domain.is_some(), all) {
            (true, true) => "SELECT fqdn FROM subdomains WHERE root_domain=?1 ORDER BY fqdn",
            (true, false) => {
                "SELECT fqdn FROM subdomains WHERE root_domain=?1 AND active=1 ORDER BY fqdn"
            }
            (false, true) => "SELECT fqdn FROM subdomains ORDER BY fqdn",
            (false, false) => "SELECT fqdn FROM subdomains WHERE active=1 ORDER BY fqdn",
        };
        let mut statement = connection.prepare(sql)?;
        let result = if let Some(domain) = domain {
            statement
                .query_map([domain], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        } else {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(result)
    }

    pub fn known_subdomain_count(&self, domain: &str, all: bool) -> Result<usize> {
        let connection = self.lock()?;
        let count = if all {
            connection.query_row(
                "SELECT COUNT(*) FROM subdomains WHERE root_domain=?1",
                [domain],
                |row| row.get::<_, i64>(0),
            )?
        } else {
            connection.query_row(
                "SELECT COUNT(*) FROM subdomains WHERE root_domain=?1 AND active=1",
                [domain],
                |row| row.get::<_, i64>(0),
            )?
        };
        Ok(count.max(0) as usize)
    }

    pub fn known_subdomains_page(
        &self,
        domain: &str,
        all: bool,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let connection = self.lock()?;
        let sql = if all {
            r#"SELECT fqdn FROM subdomains
               WHERE root_domain=?1 AND (?2 IS NULL OR fqdn>?2)
               ORDER BY fqdn LIMIT ?3"#
        } else {
            r#"SELECT fqdn FROM subdomains
               WHERE root_domain=?1 AND active=1 AND (?2 IS NULL OR fqdn>?2)
               ORDER BY fqdn LIMIT ?3"#
        };
        let mut statement = connection.prepare(sql)?;
        statement
            .query_map(params![domain, after, limit as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn positive_cache_only_names_page(
        &self,
        domain: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let suffix = format!("%.{domain}");
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT cache.fqdn FROM dns_cache cache
               WHERE cache.status='positive'
                 AND (cache.fqdn=?1 OR cache.fqdn LIKE ?2)
                 AND (?3 IS NULL OR cache.fqdn>?3)
                 AND NOT EXISTS (
                     SELECT 1 FROM subdomains inventory WHERE inventory.fqdn=cache.fqdn
                 )
               ORDER BY cache.fqdn LIMIT ?4"#,
        )?;
        statement
            .query_map(params![domain, suffix, after, limit as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn positive_cache_only_count(&self, domain: &str) -> Result<usize> {
        let suffix = format!("%.{domain}");
        let count = self.lock()?.query_row(
            r#"SELECT COUNT(*) FROM dns_cache cache
               WHERE cache.status='positive'
                 AND (cache.fqdn=?1 OR cache.fqdn LIKE ?2)
                 AND NOT EXISTS (
                     SELECT 1 FROM subdomains inventory WHERE inventory.fqdn=cache.fqdn
                 )"#,
            params![domain, suffix],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn inventory(&self, domain: Option<&str>, only_live: bool) -> Result<Vec<InventoryEntry>> {
        let connection = self.lock()?;
        let mut conditions = vec![
            "NOT EXISTS (SELECT 1 FROM wildcard_quarantine quarantine \
             WHERE quarantine.root_domain=subdomains.root_domain \
               AND quarantine.fqdn=subdomains.fqdn)",
        ];
        if domain.is_some() {
            conditions.push("subdomains.root_domain=?1");
        }
        if only_live {
            conditions.push("subdomains.verification_state='live'");
            conditions.push(
                "COALESCE((SELECT verification.outcome \
                 FROM dns_verifications AS verification \
                      INDEXED BY idx_dns_verifications_name \
                 WHERE verification.fqdn=subdomains.fqdn \
                   AND verification.outcome IN ('live','negative') \
                 ORDER BY verification.checked_at DESC, verification.id DESC LIMIT 1), '')<>'negative'",
            );
        }
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };
        let sql = format!(
            r#"SELECT fqdn, verification_state, last_verified_at,
               first_seen, last_seen, times_seen, sources
               FROM subdomains{where_clause} ORDER BY fqdn"#
        );
        let mut statement = connection.prepare(&sql)?;
        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<InventoryEntry> {
            let raw_state: String = row.get(1)?;
            let state = match raw_state.as_str() {
                "live" => ObservationState::Live,
                "historical" => ObservationState::Historical,
                _ => ObservationState::Unverified,
            };
            let sources = row
                .get::<_, String>(6)?
                .split(',')
                .filter(|source| !source.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            Ok(InventoryEntry {
                fqdn: row.get(0)?,
                state,
                last_verified_at: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                times_seen: row.get(5)?,
                sources,
            })
        };
        if let Some(domain) = domain {
            statement
                .query_map([domain], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        } else {
            statement
                .query_map([], map_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        }
    }

    pub fn inventory_page(
        &self,
        domain: &str,
        only_live: bool,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<InventoryEntry>> {
        self.inventory_page_filtered(domain, only_live, after, limit, false)
    }

    /// Returns the inventory that is safe to merge into current scan results.
    ///
    /// A retained historical or unverified name whose latest decisive DNS
    /// observation is negative stays available to `inventory`/`explain`, but
    /// is not presented as a current discovery. A later live observation makes
    /// the name visible again without deleting or rewriting history.
    pub fn current_inventory_page(
        &self,
        domain: &str,
        only_live: bool,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<InventoryEntry>> {
        self.inventory_page_filtered(domain, only_live, after, limit, true)
    }

    fn inventory_page_filtered(
        &self,
        domain: &str,
        only_live: bool,
        after: Option<&str>,
        limit: usize,
        hide_current_negatives: bool,
    ) -> Result<Vec<InventoryEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let live_clause = if only_live {
            " AND subdomains.verification_state='live'"
        } else {
            ""
        };
        let current_clause = if hide_current_negatives {
            r#" AND COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.fqdn=subdomains.fqdn
                       AND verification.outcome IN ('live','negative')
                     ORDER BY verification.checked_at DESC, verification.id DESC LIMIT 1
                 ), '')<>'negative'"#
        } else {
            ""
        };
        let sql = format!(
            r#"SELECT fqdn, verification_state, last_verified_at,
               first_seen, last_seen, times_seen, sources
               FROM subdomains
               WHERE subdomains.root_domain=?1
                 AND NOT EXISTS (
                     SELECT 1 FROM wildcard_quarantine quarantine
                     WHERE quarantine.root_domain=subdomains.root_domain
                       AND quarantine.fqdn=subdomains.fqdn
                 )
                 {current_clause}
                 AND (?2 IS NULL OR subdomains.fqdn>?2){live_clause}
               ORDER BY subdomains.fqdn LIMIT ?3"#
        );
        let connection = self.lock()?;
        let mut statement = connection.prepare(&sql)?;
        statement
            .query_map(params![domain, after, limit as i64], |row| {
                let raw_state: String = row.get(1)?;
                let state = match raw_state.as_str() {
                    "live" => ObservationState::Live,
                    "historical" => ObservationState::Historical,
                    _ => ObservationState::Unverified,
                };
                let sources = row
                    .get::<_, String>(6)?
                    .split(',')
                    .filter(|source| !source.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
                Ok(InventoryEntry {
                    fqdn: row.get(0)?,
                    state,
                    last_verified_at: row.get(2)?,
                    first_seen: row.get(3)?,
                    last_seen: row.get(4)?,
                    times_seen: row.get(5)?,
                    sources,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn explain(&self, fqdn: &str) -> Result<Value> {
        let connection = self.lock()?;
        let inventory = connection
            .query_row(
                r#"SELECT root_domain, first_seen, last_seen, times_seen,
                   verification_state, last_verified_at, sources
                   FROM subdomains WHERE fqdn=?1"#,
                [fqdn],
                |row| {
                    Ok(json!({
                        "root_domain": row.get::<_, String>(0)?,
                        "first_seen": row.get::<_, i64>(1)?,
                        "last_seen": row.get::<_, i64>(2)?,
                        "times_seen": row.get::<_, i64>(3)?,
                        "state": row.get::<_, String>(4)?,
                        "last_verified_at": row.get::<_, Option<i64>>(5)?,
                        "sources": row.get::<_, String>(6)?
                            .split(',')
                            .filter(|source| !source.is_empty())
                            .collect::<Vec<_>>()
                    }))
                },
            )
            .optional()?;
        let quarantine = {
            let mut statement = connection.prepare(
                r#"SELECT root_domain, scan_id, reason, quarantined_at
                   FROM wildcard_quarantine WHERE fqdn=?1
                   ORDER BY quarantined_at DESC, root_domain"#,
            )?;
            statement
                .query_map([fqdn], |row| {
                    Ok(json!({
                        "root_domain": row.get::<_, String>(0)?,
                        "scan_id": row.get::<_, i64>(1)?,
                        "reason": row.get::<_, String>(2)?,
                        "quarantined_at": row.get::<_, i64>(3)?
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        if inventory.is_none() && quarantine.is_empty() {
            return Ok(json!({"known": false, "fqdn": fqdn}));
        }

        let dns_records = {
            let mut statement = connection.prepare(
                r#"SELECT record_type, value, ttl, first_seen, last_seen, active
                   FROM dns_records WHERE fqdn=?1 ORDER BY record_type, value"#,
            )?;
            statement
                .query_map([fqdn], |row| {
                    Ok(json!({
                        "record_type": row.get::<_, String>(0)?,
                        "value": row.get::<_, String>(1)?,
                        "ttl": row.get::<_, i64>(2)?,
                        "first_seen": row.get::<_, i64>(3)?,
                        "last_seen": row.get::<_, i64>(4)?,
                        "active": row.get::<_, i64>(5)? != 0
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let evidence = {
            let mut statement = connection.prepare(
                r#"SELECT e.kind, e.source, e.value, e.first_seen, e.last_seen, e.times_seen
                   FROM observation_evidence e
                   JOIN observed_names n ON n.id=e.name_id
                   WHERE n.fqdn=?1 ORDER BY e.last_seen DESC, e.source"#,
            )?;
            statement
                .query_map([fqdn], |row| {
                    Ok(json!({
                        "kind": row.get::<_, String>(0)?,
                        "source": row.get::<_, String>(1)?,
                        "value": row.get::<_, String>(2)?,
                        "first_seen": row.get::<_, i64>(3)?,
                        "last_seen": row.get::<_, i64>(4)?,
                        "times_seen": row.get::<_, i64>(5)?
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let dns_verifications = {
            let mut statement = connection.prepare(
                r#"SELECT scan_id, checked_at, outcome, resolver_count, authoritative,
                   records_hash, latency_ms, details_json
                   FROM dns_verifications WHERE fqdn=?1
                   ORDER BY checked_at DESC, id DESC LIMIT 100"#,
            )?;
            statement
                .query_map([fqdn], |row| {
                    let details: String = row.get(7)?;
                    Ok(json!({
                        "scan_id": row.get::<_, Option<i64>>(0)?,
                        "checked_at": row.get::<_, i64>(1)?,
                        "outcome": row.get::<_, String>(2)?,
                        "resolver_count": row.get::<_, i64>(3)?,
                        "authoritative": row.get::<_, i64>(4)? != 0,
                        "records_hash": row.get::<_, Option<String>>(5)?,
                        "latency_ms": row.get::<_, Option<i64>>(6)?,
                        "details": serde_json::from_str::<Value>(&details).unwrap_or(json!({}))
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let scan_history = {
            let mut statement = connection.prepare(
                r#"SELECT f.scan_id, s.started_at, s.finished_at, f.state,
                   f.confidence_score, f.confidence_label, f.evidence_families_json,
                   f.authoritative_validation
                   FROM scan_findings f JOIN scans s ON s.id=f.scan_id
                   WHERE f.fqdn=?1 ORDER BY s.started_at DESC LIMIT 100"#,
            )?;
            statement
                .query_map([fqdn], |row| {
                    let families: String = row.get(6)?;
                    Ok(json!({
                        "scan_id": row.get::<_, i64>(0)?,
                        "started_at": row.get::<_, i64>(1)?,
                        "finished_at": row.get::<_, Option<i64>>(2)?,
                        "state": row.get::<_, String>(3)?,
                        "confidence_score": row.get::<_, i64>(4)?,
                        "confidence_label": row.get::<_, String>(5)?,
                        "evidence_families": serde_json::from_str::<Value>(&families).unwrap_or(json!([])),
                        "authoritative_validation": row.get::<_, i64>(7)? != 0
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        Ok(json!({
            "known": true,
            "fqdn": fqdn,
            "inventory": inventory,
            "quarantine": quarantine,
            "dns_records": dns_records,
            "evidence": evidence,
            "dns_verifications": dns_verifications,
            "scan_history": scan_history
        }))
    }

    pub fn import_inventory(
        &self,
        root_domain: &str,
        names: &BTreeSet<String>,
        source: &str,
    ) -> Result<usize> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut written = 0_usize;
        for fqdn in names {
            written += transaction.execute(
                r#"INSERT INTO subdomains(
                   fqdn, root_domain, first_seen, last_seen, times_seen, active,
                   sources, verification_state, last_verified_at
                   ) VALUES (?1, ?2, ?3, ?3, 1, 0, ?4, 'unverified', NULL)
                   ON CONFLICT(fqdn) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   times_seen=subdomains.times_seen+1,
                   sources=CASE
                       WHEN instr(',' || subdomains.sources || ',', ',' || excluded.sources || ',') > 0
                       THEN subdomains.sources
                       WHEN subdomains.sources='' THEN excluded.sources
                       ELSE subdomains.sources || ',' || excluded.sources
                   END"#,
                params![fqdn, root_domain, now, source],
            )?;
        }
        transaction.commit()?;
        drop(connection);
        self.store_observations(
            root_domain,
            names
                .iter()
                .map(|fqdn| ObservationInput {
                    fqdn: fqdn.clone(),
                    kind: "import".to_owned(),
                    source: source.to_owned(),
                    value: String::new(),
                })
                .collect(),
        )?;
        Ok(written)
    }

    pub fn history(&self, limit: usize) -> Result<Vec<Value>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT id, domain, started_at, finished_at, status, candidates, found,
               cache_hits, duration_ms FROM scans ORDER BY id DESC LIMIT ?1"#,
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok(json!({
                "id": row.get::<_, i64>(0)?,
                "domain": row.get::<_, String>(1)?,
                "started_at": row.get::<_, i64>(2)?,
                "finished_at": row.get::<_, Option<i64>>(3)?,
                "status": row.get::<_, String>(4)?,
                "candidates": row.get::<_, i64>(5)?,
                "found": row.get::<_, i64>(6)?,
                "cache_hits": row.get::<_, i64>(7)?,
                "duration_ms": row.get::<_, i64>(8)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn stats(&self) -> Result<Stats> {
        let connection = self.lock()?;
        let count =
            |sql: &str| -> Result<i64> { Ok(connection.query_row(sql, [], |row| row.get(0))?) };
        let mut top_statement = connection.prepare(
            r#"SELECT word, attempts, successes, unique_domains FROM word_stats
               ORDER BY successes DESC, unique_domains DESC, word ASC LIMIT 15"#,
        )?;
        let top_words = top_statement
            .query_map([], |row| {
                let mut item = BTreeMap::new();
                item.insert("word".to_owned(), json!(row.get::<_, String>(0)?));
                item.insert("attempts".to_owned(), json!(row.get::<_, i64>(1)?));
                item.insert("successes".to_owned(), json!(row.get::<_, i64>(2)?));
                item.insert("unique_domains".to_owned(), json!(row.get::<_, i64>(3)?));
                Ok(item)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Stats {
            database: self.path.display().to_string(),
            scans: count("SELECT COUNT(*) FROM scans")?,
            known_subdomains: count("SELECT COUNT(*) FROM subdomains")?,
            active_subdomains: count("SELECT COUNT(*) FROM subdomains WHERE active=1")?,
            live_subdomains: count(
                "SELECT COUNT(*) FROM subdomains WHERE verification_state='live'",
            )?,
            historical_subdomains: count(
                "SELECT COUNT(*) FROM subdomains WHERE verification_state='historical'",
            )?,
            unverified_subdomains: count(
                "SELECT COUNT(*) FROM subdomains WHERE verification_state='unverified'",
            )?,
            dns_verifications: count("SELECT COUNT(*) FROM dns_verifications")?,
            learned_words: count("SELECT COUNT(*) FROM word_stats")?,
            learned_patterns: count("SELECT COUNT(*) FROM relative_patterns")?,
            passive_cache_entries: count("SELECT COUNT(*) FROM passive_cache")?,
            builtin_candidates: count("SELECT COUNT(*) FROM candidate_priors")?,
            cache_entries: count("SELECT COUNT(*) FROM dns_cache")?,
            fresh_cache_entries: count(&format!(
                "SELECT COUNT(*) FROM dns_cache WHERE status='positive' OR expires_at>{}",
                now_epoch()
            ))?,
            axfr_attempts: count("SELECT COUNT(*) FROM axfr_attempts")?,
            successful_axfr: count("SELECT COUNT(*) FROM axfr_attempts WHERE status='success'")?,
            tls_certificate_entries: count("SELECT COUNT(*) FROM tls_certificate_cache")?,
            discovery_edges: count("SELECT COUNT(*) FROM discovery_edges")?,
            service_endpoints: count("SELECT COUNT(*) FROM service_endpoints")?,
            child_zones: count("SELECT COUNT(*) FROM child_zones")?,
            candidate_generators: count("SELECT COUNT(*) FROM generator_stats")?,
            web_cache_entries: count("SELECT COUNT(*) FROM web_discovery_cache")?,
            dnssec_zone_entries: count("SELECT COUNT(*) FROM dnssec_walk_cache")?,
            ct_log_cursors: count("SELECT COUNT(*) FROM ct_global_state")?,
            wildcard_cache_entries: count("SELECT COUNT(*) FROM wildcard_cache")?,
            normalized_names: count("SELECT COUNT(*) FROM observed_names")?,
            normalized_observations: count("SELECT COUNT(*) FROM observation_evidence")?,
            global_ct_names: count("SELECT COUNT(*) FROM ct_names")?,
            resolver_profiles: count("SELECT COUNT(*) FROM resolver_stats")?,
            generator_bandits: count("SELECT COUNT(*) FROM generator_bandits")?,
            top_words,
        })
    }

    pub fn prune_cache(&self) -> Result<usize> {
        Ok(self.lock()?.execute(
            "DELETE FROM dns_cache WHERE status='negative' AND expires_at<=?1",
            [now_epoch()],
        )?)
    }

    pub fn knowledge(&self, limit: usize) -> Result<Value> {
        let connection = self.lock()?;
        let mut words_statement = connection.prepare(
            r#"SELECT word, attempts, successes, unique_domains, last_seen
               FROM word_stats ORDER BY successes DESC, unique_domains DESC, word ASC LIMIT ?1"#,
        )?;
        let words = words_statement
            .query_map([limit as i64], |row| {
                Ok(json!({
                    "word": row.get::<_, String>(0)?,
                    "attempts": row.get::<_, i64>(1)?,
                    "successes": row.get::<_, i64>(2)?,
                    "unique_domains": row.get::<_, i64>(3)?,
                    "last_seen": row.get::<_, i64>(4)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut patterns_statement = connection.prepare(
            r#"SELECT relative_name, successes, unique_domains, last_seen
               FROM relative_patterns
               ORDER BY successes DESC, unique_domains DESC, relative_name ASC LIMIT ?1"#,
        )?;
        let patterns = patterns_statement
            .query_map([limit as i64], |row| {
                Ok(json!({
                    "relative_name": row.get::<_, String>(0)?,
                    "successes": row.get::<_, i64>(1)?,
                    "unique_domains": row.get::<_, i64>(2)?,
                    "last_seen": row.get::<_, i64>(3)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut sources_statement = connection.prepare(
            r#"SELECT substr(e.source, 9) AS source,
               COUNT(DISTINCT e.root_domain) AS domains,
               COUNT(DISTINCT e.name_id) AS names
               FROM observation_evidence e
               WHERE e.kind='passive' AND e.source LIKE 'passive:%'
               GROUP BY e.source ORDER BY e.source"#,
        )?;
        let passive_sources = sources_statement
            .query_map([], |row| {
                Ok(json!({
                    "source": row.get::<_, String>(0)?,
                    "cached_domains": row.get::<_, i64>(1)?,
                    "cached_names": row.get::<_, i64>(2)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut priors_statement = connection.prepare(
            r#"SELECT relative_name, priority, source FROM candidate_priors
               ORDER BY priority DESC LIMIT ?1"#,
        )?;
        let builtin_candidates = priors_statement
            .query_map([limit as i64], |row| {
                Ok(json!({
                    "relative_name": row.get::<_, String>(0)?,
                    "priority": row.get::<_, i64>(1)?,
                    "source": row.get::<_, String>(2)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut source_stats_statement = connection.prepare(
            r#"SELECT source, requests, successes, failures, degraded, deferred,
               consecutive_failures, names, novel_names, novel_requests,
               CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END AS average_ms,
               last_error, last_status, last_used
               FROM source_stats
               ORDER BY successes DESC, novel_names DESC, names DESC, source ASC"#,
        )?;
        let source_stats = source_stats_statement
            .query_map([], |row| {
                Ok(json!({
                    "source": row.get::<_, String>(0)?,
                    "requests": row.get::<_, i64>(1)?,
                    "successes": row.get::<_, i64>(2)?,
                    "failures": row.get::<_, i64>(3)?,
                    "degraded": row.get::<_, i64>(4)?,
                    "deferred": row.get::<_, i64>(5)?,
                    "consecutive_failures": row.get::<_, i64>(6)?,
                    "names": row.get::<_, i64>(7)?,
                    "novel_names": row.get::<_, i64>(8)?,
                    "novel_requests": row.get::<_, i64>(9)?,
                    "average_ms": row.get::<_, i64>(10)?,
                    "last_error": row.get::<_, Option<String>>(11)?,
                    "last_status": row.get::<_, String>(12)?,
                    "last_used": row.get::<_, i64>(13)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut tls_statement = connection.prepare(
            r#"SELECT t.endpoint, t.port, t.fingerprint_sha256,
               json_array_length(t.names_json) + (
                   SELECT COUNT(DISTINCT e.name_id) FROM observation_evidence e
                   WHERE e.root_domain=t.root_domain
                     AND e.source='tls:' || t.endpoint || ':' || t.port
               ), t.updated_at
               FROM tls_certificate_cache t
               ORDER BY updated_at DESC, endpoint ASC LIMIT ?1"#,
        )?;
        let tls_certificates = tls_statement
            .query_map([limit as i64], |row| {
                Ok(json!({
                    "endpoint": row.get::<_, String>(0)?,
                    "port": row.get::<_, i64>(1)?,
                    "fingerprint_sha256": row.get::<_, String>(2)?,
                    "cached_names": row.get::<_, i64>(3)?,
                    "updated_at": row.get::<_, i64>(4)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut generator_statement = connection.prepare(
            r#"SELECT generator, attempts, successes, unique_domains,
               CASE WHEN attempts=0 THEN 0 ELSE successes * 1000 / attempts END AS permille
               FROM generator_stats
               ORDER BY permille DESC, successes DESC, generator ASC"#,
        )?;
        let candidate_generators = generator_statement
            .query_map([], |row| {
                Ok(json!({
                    "generator": row.get::<_, String>(0)?,
                    "attempts": row.get::<_, i64>(1)?,
                    "successes": row.get::<_, i64>(2)?,
                    "unique_domains": row.get::<_, i64>(3)?,
                    "success_permille": row.get::<_, i64>(4)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut resolver_statement = connection.prepare(
            r#"SELECT resolver, requests, successes, failures,
               CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END,
               consecutive_failures, last_used
               FROM resolver_stats ORDER BY failures ASC, resolver ASC"#,
        )?;
        let resolver_profiles = resolver_statement
            .query_map([], |row| {
                Ok(json!({
                    "resolver": row.get::<_, String>(0)?,
                    "requests": row.get::<_, i64>(1)?,
                    "successes": row.get::<_, i64>(2)?,
                    "failures": row.get::<_, i64>(3)?,
                    "average_ms": row.get::<_, i64>(4)?,
                    "consecutive_failures": row.get::<_, i64>(5)?,
                    "last_used": row.get::<_, i64>(6)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut bandit_statement = connection.prepare(
            r#"SELECT context, generator, alpha, beta, pulls, rewards, last_seen
               FROM generator_bandits
               ORDER BY context, generator LIMIT ?1"#,
        )?;
        let generator_bandits = bandit_statement
            .query_map([limit as i64], |row| {
                let alpha = row.get::<_, f64>(2)?;
                let beta = row.get::<_, f64>(3)?;
                Ok(json!({
                    "context": row.get::<_, String>(0)?,
                    "generator": row.get::<_, String>(1)?,
                    "alpha": alpha,
                    "beta": beta,
                    "posterior_mean": alpha / (alpha + beta).max(1.0),
                    "pulls": row.get::<_, i64>(4)?,
                    "rewards": row.get::<_, i64>(5)?,
                    "last_seen": row.get::<_, i64>(6)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut scheduler_statement = connection.prepare(
            r#"SELECT context, generator, alpha, beta, packets,
                      exclusive_rewards, total_cost, last_seen
               FROM scheduler_arms
               ORDER BY context, generator LIMIT ?1"#,
        )?;
        let scheduler_arms = scheduler_statement
            .query_map([limit as i64], |row| {
                let alpha = row.get::<_, f64>(2)?;
                let beta = row.get::<_, f64>(3)?;
                let total_cost = row.get::<_, f64>(6)?;
                let rewards = row.get::<_, i64>(5)?.max(0);
                Ok(json!({
                    "context": row.get::<_, String>(0)?,
                    "generator": row.get::<_, String>(1)?,
                    "alpha": alpha,
                    "beta": beta,
                    "posterior_mean": alpha / (alpha + beta).max(1.0),
                    "packets": row.get::<_, i64>(4)?,
                    "exclusive_rewards": rewards,
                    "total_cost": total_cost,
                    "exclusive_per_1000_cost": if total_cost > 0.0 {
                        rewards as f64 * 1_000.0 / total_cost
                    } else {
                        0.0
                    },
                    "last_seen": row.get::<_, i64>(7)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!({
            "local_only": true,
            "builtin_candidates": builtin_candidates,
            "words": words,
            "relative_patterns": patterns,
            "passive_sources": passive_sources,
            "source_stats": source_stats,
            "tls_certificates": tls_certificates,
            "candidate_generators": candidate_generators,
            "generator_bandits": generator_bandits,
            "scheduler_arms": scheduler_arms,
            "resolver_profiles": resolver_profiles,
            "wildcard_cache_entries": connection.query_row(
                "SELECT COUNT(*) FROM wildcard_cache", [], |row| row.get::<_, i64>(0)
            )?,
            "global_ct_names": connection.query_row(
                "SELECT COUNT(*) FROM ct_names", [], |row| row.get::<_, i64>(0)
            )?
        }))
    }
}
