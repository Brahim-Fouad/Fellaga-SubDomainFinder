use super::*;

impl Database {
    pub fn create_scan(&self, domain: &str, options: &Value) -> Result<i64> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO scans(domain, started_at, status, options_json) VALUES (?1, ?2, 'running', ?3)",
            params![domain, now_epoch(), serde_json::to_string(options)?],
        )?;
        Ok(connection.last_insert_rowid())
    }

    pub fn reconcile_stale_scans(&self, stale_after: std::time::Duration) -> Result<usize> {
        let now = now_epoch();
        let cutoff = now.saturating_sub(stale_after.as_secs().min(i64::MAX as u64) as i64);
        let warning = serde_json::to_string(&vec![
            "scan interrompu sans fermeture; checkpoint conservé pour --resume".to_owned(),
        ])?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            r#"UPDATE scans
               SET status='interrupted', finished_at=?1, warnings_json=?2
               WHERE status='running' AND (
                   EXISTS (
                       SELECT 1 FROM scan_checkpoints checkpoint
                       WHERE checkpoint.scan_id=scans.id
                         AND checkpoint.completed=0
                         AND checkpoint.updated_at<?3
                   )
                   OR (
                       NOT EXISTS (
                           SELECT 1 FROM scan_checkpoints checkpoint
                           WHERE checkpoint.scan_id=scans.id
                             AND checkpoint.completed=0
                       )
                       AND started_at<?3
                   )
               )"#,
            params![now, warning, cutoff],
        )?;
        transaction.execute(
            r#"DELETE FROM refresh_wildcard_affected_scans
               WHERE refresh_scan_id IN (SELECT id FROM scans WHERE status<>'running')"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM refresh_wildcard_candidates
               WHERE scan_id IN (SELECT id FROM scans WHERE status<>'running')"#,
            [],
        )?;
        transaction.commit()?;
        Ok(changed)
    }

    pub fn upsert_checkpoint(
        &self,
        scan_id: i64,
        domain: &str,
        stage: &str,
        options_hash: &str,
    ) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let scan = transaction
            .query_row(
                "SELECT domain, status FROM scans WHERE id=?1",
                [scan_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((scan_domain, status)) = scan else {
            bail!("scan #{scan_id} introuvable pour le checkpoint");
        };
        if scan_domain != domain {
            bail!("le domaine du checkpoint ne correspond pas au scan #{scan_id}");
        }
        if status != "running" {
            // A late heartbeat is expected while shutdown is racing with the
            // checkpoint worker. It must be harmless and must never reopen a
            // completed checkpoint.
            return Ok(());
        }
        transaction.execute(
            r#"INSERT INTO scan_checkpoints(
               scan_id, domain, stage, options_hash, updated_at, completed
               ) VALUES (?1, ?2, ?3, ?4, ?5, 0)
               ON CONFLICT(scan_id) DO UPDATE SET
               stage=excluded.stage, options_hash=excluded.options_hash,
               updated_at=excluded.updated_at, completed=0
               WHERE scan_checkpoints.completed=0 AND EXISTS (
                   SELECT 1 FROM scans
                   WHERE scans.id=excluded.scan_id AND scans.status='running'
                     AND scans.domain=excluded.domain
               )"#,
            params![scan_id, domain, stage, options_hash, now_epoch()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_checkpoint(&self, scan_id: i64) -> Result<()> {
        self.lock()?.execute(
            "UPDATE scan_checkpoints SET stage='complete', updated_at=?1, completed=1 WHERE scan_id=?2",
            params![now_epoch(), scan_id],
        )?;
        Ok(())
    }

    pub fn resumable_checkpoint(
        &self,
        domain: &str,
        selector: &str,
    ) -> Result<Option<ScanCheckpoint>> {
        let connection = self.lock()?;
        let row = if selector == "latest" {
            connection
                .query_row(
                    r#"SELECT scan_id, domain, stage, options_hash, updated_at
                       FROM scan_checkpoints
                       WHERE domain=?1 AND completed=0
                       ORDER BY updated_at DESC LIMIT 1"#,
                    [domain],
                    |row| {
                        Ok(ScanCheckpoint {
                            scan_id: row.get(0)?,
                            domain: row.get(1)?,
                            stage: row.get(2)?,
                            options_hash: row.get(3)?,
                            updated_at: row.get(4)?,
                        })
                    },
                )
                .optional()?
        } else if let Ok(scan_id) = selector.parse::<i64>() {
            connection
                .query_row(
                    r#"SELECT scan_id, domain, stage, options_hash, updated_at
                       FROM scan_checkpoints
                       WHERE scan_id=?1 AND domain=?2 AND completed=0"#,
                    params![scan_id, domain],
                    |row| {
                        Ok(ScanCheckpoint {
                            scan_id: row.get(0)?,
                            domain: row.get(1)?,
                            stage: row.get(2)?,
                            options_hash: row.get(3)?,
                            updated_at: row.get(4)?,
                        })
                    },
                )
                .optional()?
        } else {
            None
        };
        Ok(row)
    }

    pub fn reopen_scan(&self, scan_id: i64) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let state: Option<(String, i64)> = transaction
            .query_row(
                r#"SELECT scans.status, checkpoint.updated_at
                   FROM scans
                   JOIN scan_checkpoints checkpoint ON checkpoint.scan_id=scans.id
                   WHERE scans.id=?1 AND checkpoint.completed=0"#,
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((status, updated_at)) = state else {
            bail!("le scan #{scan_id} n'a pas de checkpoint incomplet");
        };
        if status == "completed" {
            bail!("le scan #{scan_id} est déjà terminé");
        }
        if status == "running" && now.saturating_sub(updated_at) < 120 {
            bail!("le scan #{scan_id} semble encore actif; attendez la fin de son bail");
        }
        transaction.execute(
            "UPDATE scans SET status='running', finished_at=NULL WHERE id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "UPDATE scan_checkpoints SET stage='running', updated_at=?1 WHERE scan_id=?2 AND completed=0",
            params![now, scan_id],
        )?;
        // A claimed candidate without a terminal DNS outcome is safe to retry
        // only while retry budget remains. Exhausted queued rows can be left by
        // an older binary or an interrupted finalization and must become
        // terminal before the scan is resumed.
        transaction.execute(
            r#"UPDATE scan_candidates
               SET status=CASE WHEN attempts>=3 THEN 'done' ELSE 'queued' END
               WHERE scan_id=?1 AND status IN ('queued', 'processing')"#,
            [scan_id],
        )?;
        transaction.execute(
            r#"UPDATE scan_seed_candidates
               SET status=CASE WHEN attempts>=3 THEN 'done' ELSE 'queued' END
               WHERE scan_id=?1 AND status IN ('queued', 'processing')"#,
            [scan_id],
        )?;
        transaction.execute(
            r#"UPDATE scan_recursive_candidates
               SET status=CASE WHEN attempts>=3 THEN 'done' ELSE 'queued' END
               WHERE scan_id=?1 AND status IN ('queued', 'processing')"#,
            [scan_id],
        )?;
        transaction.execute(
            "UPDATE discovery_actions SET state='queued', updated_at=?2 WHERE scan_id=?1 AND state='processing'",
            params![scan_id, now],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Supersede abandoned candidate queues for a domain after a new scan has
    /// acquired its checkpoint. A scan with a fresh running lease is excluded
    /// so two live processes cannot silently delete each other's work.
    pub fn supersede_incomplete_candidate_queues(
        &self,
        domain: &str,
        keep_scan_id: i64,
        active_lease: std::time::Duration,
    ) -> Result<usize> {
        let now = now_epoch();
        let cutoff = now.saturating_sub(active_lease.as_secs().min(i64::MAX as u64) as i64);
        let warning = serde_json::to_string(&vec![format!(
            "file de candidats remplacée par le scan #{keep_scan_id}"
        )])?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;

        transaction.execute_batch(
            r#"CREATE TEMP TABLE IF NOT EXISTS fellaga_superseded_scans(
                   scan_id INTEGER PRIMARY KEY
               );
               DELETE FROM fellaga_superseded_scans;"#,
        )?;
        transaction.execute(
            r#"INSERT INTO fellaga_superseded_scans(scan_id)
               SELECT scan.id
               FROM scans AS scan
               WHERE scan.domain=?1
                 AND scan.id<>?2
                 AND scan.id<?2
                 AND scan.status NOT IN ('completed', 'superseded')
                 AND NOT EXISTS (
                     SELECT 1 FROM scan_checkpoints AS completed
                     WHERE completed.scan_id=scan.id AND completed.completed=1
                 )
                 AND NOT (
                     scan.status='running'
                     AND (
                         scan.started_at>=?3
                         OR EXISTS (
                             SELECT 1 FROM scan_checkpoints AS lease
                             WHERE lease.scan_id=scan.id
                               AND lease.completed=0
                               AND lease.updated_at>=?3
                         )
                     )
                 )"#,
            params![domain, keep_scan_id, cutoff],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_candidate_feeds
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_seed_candidates
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_generator_stats
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_attempted_words
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_recursive_candidates
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_recursive_parents
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"DELETE FROM scan_recursive_words
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [],
        )?;
        transaction.execute(
            r#"UPDATE scan_checkpoints
               SET stage='superseded', updated_at=?1, completed=1
               WHERE scan_id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            [now],
        )?;
        transaction.execute(
            r#"UPDATE scans
               SET status='superseded', finished_at=?1, warnings_json=?2
               WHERE id IN (SELECT scan_id FROM fellaga_superseded_scans)"#,
            params![now, warning],
        )?;
        transaction.execute("DELETE FROM fellaga_superseded_scans", [])?;
        transaction.commit()?;
        drop(connection);

        // Never make a new scan wait while SQLite removes millions of rows
        // from abandoned queues.  A small page is reclaimed here; the rest is
        // eligible for incremental maintenance through `cache prune`.
        Ok(self
            .prune_superseded_candidate_queues(2_000)
            .unwrap_or_default())
    }

    /// Reclaim at most one page of temporary candidates belonging to scans
    /// that are completed or superseded. Permanent observations, DNS cache
    /// entries and learning tables are deliberately outside this operation.
    pub fn prune_superseded_candidate_queues(&self, limit: usize) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let connection = self.lock()?;
        Ok(connection.execute(
            r#"DELETE FROM scan_candidates
               WHERE rowid IN (
                   SELECT rowid
                   FROM scan_candidates
                   WHERE scan_id IN (
                       SELECT id FROM scans WHERE status IN ('completed', 'superseded')
                   )
                   LIMIT ?1
               )"#,
            [limit.min(i64::MAX as usize) as i64],
        )?)
    }

    pub fn persist_scan_candidates(
        &self,
        scan_id: i64,
        domain: &str,
        candidates: &[(String, String, i64)],
    ) -> Result<usize> {
        self.persist_scan_candidates_bounded(scan_id, domain, candidates, candidates.len())
    }

    /// Persist externally discovered names before DNS validation.  Keeping
    /// this queue separate from brute-force candidates means passive coverage
    /// does not consume `max_words`, while each bounded wave remains durable
    /// and resumable.
    pub fn persist_scan_seed_candidates(
        &self,
        scan_id: i64,
        candidates: &[(String, BTreeSet<String>, i64)],
        max_total: usize,
    ) -> Result<usize> {
        if candidates.is_empty() || max_total == 0 {
            return Ok(0);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut total = transaction
            .query_row(
                "SELECT COUNT(*) FROM scan_seed_candidates WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )?
            .max(0) as usize;
        let mut inserted = 0_usize;
        {
            // A passive-only scan may persist hundreds of thousands of names.
            // Compile each hot statement once so this phase scales with rows,
            // rather than with rows multiplied by SQLite parser work.
            let mut select_existing = transaction.prepare(
                r#"SELECT sources_json, priority
                       FROM scan_seed_candidates WHERE scan_id=?1 AND fqdn=?2"#,
            )?;
            let mut update_existing = transaction.prepare(
                r#"UPDATE scan_seed_candidates
                   SET sources_json=?3, priority=?4
                   WHERE scan_id=?1 AND fqdn=?2"#,
            )?;
            let mut select_lowest = transaction.prepare(
                r#"SELECT fqdn, priority FROM scan_seed_candidates
                   WHERE scan_id=?1 AND status='queued' AND attempts=0
                   ORDER BY priority, fqdn DESC LIMIT 1"#,
            )?;
            let mut delete_seed = transaction
                .prepare("DELETE FROM scan_seed_candidates WHERE scan_id=?1 AND fqdn=?2")?;
            let mut insert_seed = transaction.prepare(
                r#"INSERT INTO scan_seed_candidates(
                       scan_id, fqdn, priority, sources_json, status
                   ) VALUES (?1, ?2, ?3, ?4, 'queued')"#,
            )?;
            for (fqdn, sources, priority) in candidates {
                let existing = select_existing
                    .query_row(params![scan_id, fqdn], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                    .optional()?;
                if let Some((sources_json, existing_priority)) = existing {
                    let mut merged = serde_json::from_str::<BTreeSet<String>>(&sources_json)
                        .context("provenance de candidat passif SQLite invalide")?;
                    merged.extend(sources.iter().cloned());
                    update_existing.execute(params![
                        scan_id,
                        fqdn,
                        serde_json::to_string(&merged)?,
                        existing_priority.max(*priority)
                    ])?;
                    continue;
                }

                if total >= max_total {
                    let lowest = select_lowest
                        .query_row([scan_id], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                        })
                        .optional()?;
                    let Some((lowest_fqdn, lowest_priority)) = lowest else {
                        continue;
                    };
                    if *priority <= lowest_priority {
                        continue;
                    }
                    delete_seed.execute(params![scan_id, lowest_fqdn])?;
                    total = total.saturating_sub(1);
                }

                inserted += insert_seed.execute(params![
                    scan_id,
                    fqdn,
                    priority,
                    serde_json::to_string(sources)?
                ])?;
                total = total.saturating_add(1);
            }
        }
        transaction.execute(
            r#"DELETE FROM scan_candidates
               WHERE scan_id=?1
                 AND EXISTS (
                     SELECT 1 FROM scan_seed_candidates seed
                     WHERE seed.scan_id=scan_candidates.scan_id
                       AND seed.fqdn=scan_candidates.fqdn
                 )"#,
            [scan_id],
        )?;
        transaction.commit()?;
        Ok(inserted)
    }

    /// Atomically claim the next bounded page of passive/authoritative seeds.
    pub fn pending_scan_seed_candidates(
        &self,
        scan_id: i64,
        limit: usize,
    ) -> Result<Vec<(String, BTreeSet<String>, i64)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut rows = {
            let mut statement = transaction.prepare(
                r#"UPDATE scan_seed_candidates
                   SET status='processing'
                   WHERE rowid IN (
                       SELECT rowid FROM scan_seed_candidates
                       WHERE scan_id=?1 AND status='queued' AND attempts<3
                       ORDER BY priority DESC, fqdn
                       LIMIT ?2
                   )
                     AND scan_id=?1 AND status='queued' AND attempts<3
                   RETURNING fqdn, sources_json, priority"#,
            )?;
            statement
                .query_map(
                    params![scan_id, limit.min(i64::MAX as usize) as i64],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
        transaction.commit()?;
        rows.into_iter()
            .map(|(fqdn, sources_json, priority)| {
                Ok((
                    fqdn,
                    serde_json::from_str::<BTreeSet<String>>(&sources_json)
                        .context("provenance de candidat passif SQLite invalide")?,
                    priority,
                ))
            })
            .collect()
    }

    /// Réserve atomiquement un petit ensemble de graines déjà sélectionnées
    /// par un producteur tardif (par exemple CT). Seules les lignes encore
    /// queued sont renvoyées, ce qui empêche une seconde validation concurrente
    /// de réclamer les mêmes noms.
    pub fn claim_scan_seed_candidates_by_name(
        &self,
        scan_id: i64,
        hosts: &[String],
    ) -> Result<Vec<String>> {
        if hosts.is_empty() {
            return Ok(Vec::new());
        }
        if hosts.len() > MAX_NAMED_SEED_CLAIM {
            bail!(
                "trop de graines à réclamer par nom: {} > {MAX_NAMED_SEED_CLAIM}",
                hosts.len()
            );
        }
        let unique_hosts = hosts.iter().collect::<BTreeSet<_>>();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut claimed = Vec::with_capacity(unique_hosts.len());
        for chunk in unique_hosts.iter().copied().collect::<Vec<_>>().chunks(400) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().map(|host| (*host).clone().into()));
            let mut statement = transaction.prepare(&format!(
                "UPDATE scan_seed_candidates SET status='processing' \
                 WHERE scan_id=? AND status='queued' AND attempts<3 \
                   AND fqdn IN ({placeholders}) \
                 RETURNING fqdn"
            ))?;
            claimed.extend(
                statement
                    .query_map(rusqlite::params_from_iter(values), |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            );
        }
        claimed.sort();
        transaction.commit()?;
        Ok(claimed)
    }

    /// Charge une tentative seulement pour les graines dont une requête DNS a
    /// réellement démarré. La réservation SQLite est volontairement séparée
    /// de ce compteur afin qu'une deadline déjà épuisée ne consomme jamais un
    /// retry sans paquet réseau.
    pub fn mark_scan_seed_candidates_started(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "UPDATE scan_seed_candidates SET attempts=CASE \
                         WHEN attempts>=9223372036854775807 THEN 9223372036854775807 \
                         ELSE MAX(attempts, 0)+1 END \
                     WHERE scan_id=? AND status='processing' AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Rend immédiatement à la file les graines explicitement signalées comme
    /// réservées mais non démarrées. Les tentatives de vagues précédentes sont
    /// conservées; seule la réservation courante est annulée.
    pub fn requeue_unstarted_scan_seed_candidates(
        &self,
        scan_id: i64,
        hosts: &[String],
    ) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "UPDATE scan_seed_candidates SET status='queued' \
                     WHERE scan_id=? AND status='processing' \
                       AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn pending_scan_seed_candidate_count(&self, scan_id: i64) -> Result<i64> {
        Ok(self.lock()?.query_row(
            "SELECT COUNT(*) FROM scan_seed_candidates WHERE scan_id=?1 AND status='queued' AND attempts<3",
            [scan_id],
            |row| row.get(0),
        )?)
    }

    pub fn scan_seed_candidate_count(&self, scan_id: i64) -> Result<i64> {
        Ok(self.lock()?.query_row(
            "SELECT COUNT(*) FROM scan_seed_candidates WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?)
    }

    pub fn mark_scan_seed_candidates_done(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                r#"UPDATE scan_seed_candidates SET status=CASE
                       WHEN COALESCE((
                         SELECT verification.outcome
                         FROM dns_verifications AS verification
                              INDEXED BY idx_dns_verifications_name
                         WHERE verification.scan_id=?
                           AND verification.fqdn=scan_seed_candidates.fqdn
                         ORDER BY verification.checked_at DESC, verification.id DESC
                         LIMIT 1
                       ), '')='error' AND attempts<3 THEN 'queued'
                       ELSE 'done'
                   END
                   WHERE scan_id=? AND status='processing'
                     AND fqdn IN ({placeholders})"#
            );
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 2);
            values.push(scan_id.into());
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn persist_scan_candidates_bounded(
        &self,
        scan_id: i64,
        domain: &str,
        candidates: &[(String, String, i64)],
        limit: usize,
    ) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            r#"INSERT OR IGNORE INTO scan_candidates(
               scan_id, fqdn, relative_name, priority, generator, status
               ) SELECT ?1, ?2, ?3, ?4, ?5, 'queued'
                 WHERE NOT EXISTS (
                     SELECT 1 FROM scan_seed_candidates
                     WHERE scan_id=?1 AND fqdn=?2
                 )"#,
        )?;
        let mut inserted = 0_usize;
        for (relative_name, generator, priority) in candidates {
            inserted += statement.execute(params![
                scan_id,
                format!("{relative_name}.{domain}"),
                relative_name,
                priority,
                generator
            ])?;
            if inserted >= limit {
                break;
            }
        }
        drop(statement);
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn persist_wordlist_candidates(
        &self,
        scan_id: i64,
        domain: &str,
        path: &Path,
        limit: usize,
    ) -> Result<usize> {
        Ok(self
            .refill_wordlist_candidates(scan_id, domain, path, limit)?
            .0)
    }

    /// Read only the next wordlist page. File I/O is performed without holding
    /// the SQLite mutex, then the byte cursor and inserted rows are committed
    /// together, making large custom lists both bounded and resumable.
    pub fn refill_wordlist_candidates(
        &self,
        scan_id: i64,
        domain: &str,
        path: &Path,
        limit: usize,
    ) -> Result<(usize, bool)> {
        if limit == 0 {
            return Ok((0, false));
        }
        let starting_feed = {
            let connection = self.lock()?;
            connection
                .query_row(
                    r#"SELECT cursor, cursor_text, exhausted FROM scan_candidate_feeds
                       WHERE scan_id=?1 AND source='wordlist'"#,
                    [scan_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)? != 0,
                        ))
                    },
                )
                .optional()?
        };
        let (cursor, cursor_text, already_exhausted) =
            starting_feed.clone().unwrap_or((0, String::new(), false));
        if already_exhausted {
            return Ok((0, true));
        }
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("ouverture de la wordlist {}", path.display()))?;
        let file_size = file.metadata()?.len();
        let cursor = cursor.max(0) as u64;
        file.seek(SeekFrom::Start(cursor))?;
        let mut reader = std::io::BufReader::new(file);
        let mut next_cursor = cursor;
        let mut rank = 0_u64;
        let mut examined_lines = 0_usize;
        let mut examined_bytes = 0_usize;
        // Match the common scheduler wave so a 4,096-candidate batch does not
        // require four file reopens and four feed transactions. Small calls
        // retain enough read headroom for invalid-heavy lists, while the hard
        // line and byte caps keep memory bounded for very large batches.
        const MIN_WORDLIST_PAGE_LINES: usize = 1_024;
        const MAX_WORDLIST_PAGE_LINES: usize = 16_384;
        let page_line_limit = limit.clamp(MIN_WORDLIST_PAGE_LINES, MAX_WORDLIST_PAGE_LINES);
        const MAX_WORDLIST_PAGE_BYTES: usize = 4 * 1024 * 1024;
        let mut exhausted = false;
        let mut discarding_oversized_line = cursor_text == "discard";
        let mut raw = Vec::new();
        let mut candidates = Vec::new();
        while examined_lines < page_line_limit && examined_bytes < MAX_WORDLIST_PAGE_BYTES {
            let remaining_bytes = MAX_WORDLIST_PAGE_BYTES.saturating_sub(examined_bytes);
            if discarding_oversized_line {
                raw.clear();
                let bytes = Read::by_ref(&mut reader)
                    .take(remaining_bytes as u64)
                    .read_until(b'\n', &mut raw)?;
                if bytes == 0 {
                    exhausted = true;
                    discarding_oversized_line = false;
                    break;
                }
                next_cursor = next_cursor.saturating_add(bytes as u64);
                examined_bytes = examined_bytes.saturating_add(bytes);
                if raw.ends_with(b"\n") || next_cursor >= file_size {
                    discarding_oversized_line = false;
                    exhausted = next_cursor >= file_size;
                }
                continue;
            }
            raw.clear();
            let bytes = Read::by_ref(&mut reader)
                .take(remaining_bytes as u64)
                .read_until(b'\n', &mut raw)?;
            if bytes == 0 {
                exhausted = true;
                break;
            }
            next_cursor = next_cursor.saturating_add(bytes as u64);
            examined_lines = examined_lines.saturating_add(1);
            examined_bytes = examined_bytes.saturating_add(bytes);
            if !raw.ends_with(b"\n") && next_cursor < file_size {
                discarding_oversized_line = true;
                continue;
            }
            let candidate = String::from_utf8_lossy(&raw)
                .split('#')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if !valid_relative_name(&candidate) {
                continue;
            }
            candidates.push((
                candidate,
                next_cursor,
                2_000_000_000_i64
                    .saturating_sub(cursor.saturating_add(rank).min(i64::MAX as u64) as i64),
            ));
            rank = rank.saturating_add(1);
        }
        exhausted |= next_cursor >= file_size && !discarding_oversized_line;

        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let current_feed = transaction
            .query_row(
                r#"SELECT cursor, cursor_text, exhausted FROM scan_candidate_feeds
                   WHERE scan_id=?1 AND source='wordlist'"#,
                [scan_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        if current_feed != starting_feed {
            let current_exhausted = current_feed.is_some_and(|(_, _, exhausted)| exhausted);
            transaction.commit()?;
            return Ok((0, current_exhausted));
        }

        let mut statement = transaction.prepare(
            r#"INSERT OR IGNORE INTO scan_candidates(
               scan_id, fqdn, relative_name, priority, generator, status
               ) SELECT ?1, ?2, ?3, ?4, 'wordlist', 'queued'
                 WHERE NOT EXISTS (
                     SELECT 1 FROM scan_seed_candidates
                     WHERE scan_id=?1 AND fqdn=?2
                 )"#,
        )?;
        let mut inserted = 0_usize;
        let mut committed_cursor = next_cursor;
        let mut committed_discard = discarding_oversized_line;
        let mut committed_exhausted = exhausted;
        for (candidate, candidate_cursor, priority) in candidates {
            inserted += statement.execute(params![
                scan_id,
                format!("{candidate}.{domain}"),
                candidate,
                priority,
            ])?;
            if inserted >= limit {
                committed_cursor = candidate_cursor;
                committed_discard = false;
                committed_exhausted = candidate_cursor >= file_size;
                break;
            }
        }
        drop(statement);
        transaction.execute(
            r#"INSERT INTO scan_candidate_feeds(
                   scan_id, source, cursor, cursor_text, exhausted
               ) VALUES (?1, 'wordlist', ?2, ?3, ?4)
               ON CONFLICT(scan_id, source) DO UPDATE SET
                   cursor=excluded.cursor, cursor_text=excluded.cursor_text,
                   exhausted=excluded.exhausted"#,
            params![
                scan_id,
                committed_cursor.min(i64::MAX as u64) as i64,
                if committed_discard { "discard" } else { "" },
                i64::from(committed_exhausted)
            ],
        )?;
        transaction.commit()?;
        Ok((inserted, committed_exhausted))
    }

    pub fn scan_candidate_feed_exhausted(&self, scan_id: i64, source: &str) -> Result<bool> {
        Ok(self
            .lock()?
            .query_row(
                "SELECT exhausted FROM scan_candidate_feeds WHERE scan_id=?1 AND source=?2",
                params![scan_id, source],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|exhausted| exhausted != 0))
    }

    pub fn mark_scan_candidate_feed_exhausted(&self, scan_id: i64, source: &str) -> Result<()> {
        self.lock()?.execute(
            r#"INSERT INTO scan_candidate_feeds(scan_id, source, cursor, exhausted)
               VALUES (?1, ?2, 0, 1)
               ON CONFLICT(scan_id, source) DO UPDATE SET exhausted=1"#,
            params![scan_id, source],
        )?;
        Ok(())
    }

    pub fn persist_prior_candidates_to_scan(
        &self,
        scan_id: i64,
        domain: &str,
        limit: usize,
    ) -> Result<usize> {
        Ok(self
            .refill_prior_candidates_to_scan(scan_id, domain, limit)?
            .0)
    }

    /// Feed the embedded corpus with a durable priority cursor. This avoids a
    /// correlated `NOT EXISTS` walk over every earlier corpus row on every DNS
    /// wave while keeping the queue bounded and resumable.
    pub fn refill_prior_candidates_to_scan(
        &self,
        scan_id: i64,
        domain: &str,
        limit: usize,
    ) -> Result<(usize, bool)> {
        if limit == 0 {
            return Ok((0, false));
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let (stored_cursor, stored_cursor_text, already_exhausted) = transaction
            .query_row(
                r#"SELECT cursor, cursor_text, exhausted FROM scan_candidate_feeds
                   WHERE scan_id=?1 AND source='builtin'"#,
                [scan_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?
            .unwrap_or((0, String::new(), false));
        if already_exhausted {
            transaction.commit()?;
            return Ok((0, true));
        }

        let mut cursor = if stored_cursor > 0 {
            stored_cursor
        } else {
            i64::MAX
        };
        let mut cursor_text = stored_cursor_text;
        let mut inserted = 0_usize;
        let mut examined = 0_usize;
        let max_examined = limit.saturating_mul(8).clamp(5_000, 50_000);
        let mut exhausted = false;
        while inserted < limit && examined < max_examined {
            let page_size = limit
                .saturating_sub(inserted)
                .min(max_examined.saturating_sub(examined))
                .min(5_000);
            let rows = {
                let mut statement = transaction.prepare(
                    r#"SELECT relative_name, priority
                       FROM candidate_priors
                       WHERE priority < ?2
                          OR (priority=?2 AND relative_name>?3)
                       ORDER BY priority DESC, relative_name
                       LIMIT ?1"#,
                )?;
                statement
                    .query_map(
                        params![page_size.min(i64::MAX as usize) as i64, cursor, cursor_text],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            if rows.is_empty() {
                exhausted = true;
                break;
            }
            let row_count = rows.len();
            examined = examined.saturating_add(row_count);
            let mut insert = transaction.prepare(
                r#"INSERT OR IGNORE INTO scan_candidates(
                       scan_id, fqdn, relative_name, priority, generator, status
                   ) SELECT ?1, ?2, ?3, ?4, 'builtin', 'queued'
                     WHERE NOT EXISTS (
                         SELECT 1 FROM scan_seed_candidates
                         WHERE scan_id=?1 AND fqdn=?2
                     )"#,
            )?;
            for (relative_name, priority) in rows {
                cursor = priority;
                cursor_text.clone_from(&relative_name);
                inserted += insert.execute(params![
                    scan_id,
                    format!("{relative_name}.{domain}"),
                    relative_name,
                    priority.saturating_sub(1_000_000_000),
                ])?;
            }
            drop(insert);
            if row_count < page_size {
                exhausted = true;
                break;
            }
        }
        transaction.execute(
            r#"INSERT INTO scan_candidate_feeds(
                   scan_id, source, cursor, cursor_text, exhausted
               ) VALUES (?1, 'builtin', ?2, ?3, ?4)
               ON CONFLICT(scan_id, source) DO UPDATE SET
                   cursor=excluded.cursor, cursor_text=excluded.cursor_text,
                   exhausted=excluded.exhausted"#,
            params![scan_id, cursor, cursor_text, i64::from(exhausted)],
        )?;
        transaction.commit()?;
        Ok((inserted, exhausted))
    }

    pub fn pending_scan_candidates(
        &self,
        scan_id: i64,
        limit: usize,
    ) -> Result<Vec<(String, String, i64)>> {
        self.pending_scan_candidates_eligible(scan_id, limit, true)
    }

    /// Claim queued candidates that are still eligible for the current DNS
    /// budget. No active source, including an explicit wordlist, may bypass an
    /// exhausted deadline; every unclaimed row remains available to
    /// `--resume`.
    pub fn pending_scan_candidates_eligible(
        &self,
        scan_id: i64,
        limit: usize,
        include_active: bool,
    ) -> Result<Vec<(String, String, i64)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut candidates = {
            let mut statement = transaction.prepare(
                r#"UPDATE scan_candidates
                   SET status='processing'
                   WHERE rowid IN (
                        SELECT rowid FROM scan_candidates
                        WHERE scan_id=?1 AND status='queued' AND attempts<3
                          AND ?3<>0
                        ORDER BY priority DESC, fqdn
                        LIMIT ?2
                   )
                     AND scan_id=?1 AND status='queued' AND attempts<3
                   RETURNING fqdn, relative_name, generator, priority"#,
            )?;
            statement
                .query_map(
                    params![
                        scan_id,
                        limit.min(i64::MAX as usize) as i64,
                        i64::from(include_active)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        candidates.sort_by(|left, right| right.3.cmp(&left.3).then_with(|| left.0.cmp(&right.0)));
        transaction.commit()?;
        Ok(candidates
            .into_iter()
            .map(|(_, relative_name, generator, priority)| (relative_name, generator, priority))
            .collect())
    }

    /// Charge a retry uniquement lorsqu'une future DNS a réellement quitté la
    /// file d'attente. Une deadline déjà expirée ne doit jamais transformer un
    /// candidat non envoyé en échec réseau.
    pub fn mark_scan_candidates_started(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "UPDATE scan_candidates SET attempts=CASE \
                     WHEN attempts>=9223372036854775807 THEN 9223372036854775807 \
                     ELSE MAX(attempts, 0)+1 END \
                 WHERE scan_id=? AND status='processing' AND fqdn IN ({placeholders})"
            );
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn requeue_unstarted_scan_candidates(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "UPDATE scan_candidates SET status='queued' \
                 WHERE scan_id=? AND status='processing' AND fqdn IN ({placeholders})"
            );
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Freeze the recursive word order for the lifetime of a resumable scan.
    /// Global learning may change while a checkpoint is paused, so a durable
    /// ordinal list is required for parent cursors to remain exact.
    pub fn ensure_scan_recursive_words(
        &self,
        scan_id: i64,
        words: &[String],
    ) -> Result<Vec<String>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let existing: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM scan_recursive_words WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?;
        if existing == 0 {
            let mut insert = transaction.prepare(
                "INSERT OR IGNORE INTO scan_recursive_words(scan_id, ordinal, word) \
                 VALUES (?1, ?2, ?3)",
            )?;
            for (ordinal, word) in words.iter().enumerate() {
                insert.execute(params![
                    scan_id,
                    ordinal.min(i64::MAX as usize) as i64,
                    word
                ])?;
            }
        }
        let stored = {
            let mut statement = transaction.prepare(
                "SELECT word FROM scan_recursive_words WHERE scan_id=?1 ORDER BY ordinal",
            )?;
            statement
                .query_map([scan_id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        transaction.commit()?;
        Ok(stored)
    }

    pub fn persist_scan_recursive_parents(
        &self,
        scan_id: i64,
        depth: usize,
        parents: &[String],
    ) -> Result<usize> {
        if parents.is_empty() {
            return Ok(0);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut inserted = 0_usize;
        {
            let mut statement = transaction.prepare(
                r#"INSERT OR IGNORE INTO scan_recursive_parents(
                       scan_id, depth, parent, next_word, exhausted
                   ) VALUES (?1, ?2, ?3, 0, 0)"#,
            )?;
            for parent in parents {
                inserted = inserted.saturating_add(statement.execute(params![
                    scan_id,
                    depth.min(i64::MAX as usize) as i64,
                    parent
                ])?);
            }
        }
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn scan_recursive_parents(&self, scan_id: i64, depth: usize) -> Result<Vec<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT parent FROM scan_recursive_parents
               WHERE scan_id=?1 AND depth=?2 ORDER BY parent"#,
        )?;
        statement
            .query_map(
                params![scan_id, depth.min(i64::MAX as usize) as i64],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Materialize only one bounded page of the recursive Cartesian product.
    /// Parent cursors advance in the same transaction as queue insertion, so a
    /// crash can repeat a queued row but can never skip an unpersisted name.
    pub fn refill_scan_recursive_candidates(
        &self,
        scan_id: i64,
        depth: usize,
        target_queued: usize,
    ) -> Result<usize> {
        if target_queued == 0 {
            return Ok(0);
        }
        let depth = depth.min(i64::MAX as usize) as i64;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut active = transaction
            .query_row(
                r#"SELECT COUNT(*) FROM scan_recursive_candidates
                   WHERE scan_id=?1 AND depth=?2
                     AND status<>'done' AND attempts<3"#,
                params![scan_id, depth],
                |row| row.get::<_, i64>(0),
            )?
            .max(0) as usize;
        let word_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM scan_recursive_words WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )?
            .max(0);

        while active < target_queued {
            let parent_state = transaction
                .query_row(
                    r#"SELECT parent, next_word
                       FROM scan_recursive_parents
                       WHERE scan_id=?1 AND depth=?2 AND exhausted=0
                       ORDER BY parent LIMIT 1"#,
                    params![scan_id, depth],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?;
            let Some((parent, next_word)) = parent_state else {
                break;
            };
            let capacity = target_queued.saturating_sub(active).min(5_000);
            let words = {
                let mut statement = transaction.prepare(
                    r#"SELECT ordinal, word FROM scan_recursive_words
                       WHERE scan_id=?1 AND ordinal>=?2
                       ORDER BY ordinal LIMIT ?3"#,
                )?;
                statement
                    .query_map(
                        params![scan_id, next_word, capacity.min(i64::MAX as usize) as i64],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            if words.is_empty() {
                transaction.execute(
                    r#"UPDATE scan_recursive_parents SET exhausted=1
                       WHERE scan_id=?1 AND depth=?2 AND parent=?3"#,
                    params![scan_id, depth, parent],
                )?;
                continue;
            }

            let next_cursor = words
                .last()
                .map(|(ordinal, _)| ordinal.saturating_add(1))
                .unwrap_or(next_word);
            {
                let mut insert = transaction.prepare(
                    r#"INSERT OR IGNORE INTO scan_recursive_candidates(
                           scan_id, fqdn, parent, depth, word, status
                       ) VALUES (?1, ?2, ?3, ?4, ?5, 'queued')"#,
                )?;
                for (_, word) in &words {
                    active = active.saturating_add(insert.execute(params![
                        scan_id,
                        format!("{word}.{parent}"),
                        parent,
                        depth,
                        word
                    ])?);
                }
            }
            transaction.execute(
                r#"UPDATE scan_recursive_parents
                   SET next_word=?4, exhausted=?5
                   WHERE scan_id=?1 AND depth=?2 AND parent=?3"#,
                params![
                    scan_id,
                    depth,
                    parent,
                    next_cursor,
                    i64::from(next_cursor >= word_count)
                ],
            )?;
        }
        transaction.commit()?;
        Ok(active)
    }

    pub fn pending_scan_recursive_candidates(
        &self,
        scan_id: i64,
        depth: usize,
        limit: usize,
    ) -> Result<Vec<(String, String, String)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut rows = {
            let mut statement = transaction.prepare(
                r#"UPDATE scan_recursive_candidates SET status='processing'
                   WHERE rowid IN (
                       SELECT rowid FROM scan_recursive_candidates
                       WHERE scan_id=?1 AND depth=?2
                         AND status='queued' AND attempts<3
                       ORDER BY fqdn LIMIT ?3
                   )
                     AND scan_id=?1 AND depth=?2
                     AND status='queued' AND attempts<3
                   RETURNING fqdn, parent, word"#,
            )?;
            statement
                .query_map(
                    params![
                        scan_id,
                        depth.min(i64::MAX as usize) as i64,
                        limit.min(i64::MAX as usize) as i64
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        transaction.commit()?;
        Ok(rows)
    }

    pub fn mark_scan_recursive_candidates_started(
        &self,
        scan_id: i64,
        hosts: &[String],
    ) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "UPDATE scan_recursive_candidates SET attempts=CASE \
                         WHEN attempts>=9223372036854775807 THEN 9223372036854775807 \
                         ELSE MAX(attempts, 0)+1 END \
                     WHERE scan_id=? AND status='processing' AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;

            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "INSERT OR IGNORE INTO scan_attempted_words(scan_id, word) \
                     SELECT scan_id, word FROM scan_recursive_candidates \
                     WHERE scan_id=? AND status='processing' AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn requeue_unstarted_scan_recursive_candidates(
        &self,
        scan_id: i64,
        hosts: &[String],
    ) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "UPDATE scan_recursive_candidates SET status='queued' \
                     WHERE scan_id=? AND status='processing' AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_scan_recursive_candidates_done(
        &self,
        scan_id: i64,
        hosts: &[String],
    ) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                r#"UPDATE scan_recursive_candidates SET status=CASE
                       WHEN COALESCE((
                         SELECT verification.outcome
                         FROM dns_verifications AS verification
                              INDEXED BY idx_dns_verifications_name
                         WHERE verification.scan_id=?
                           AND verification.fqdn=scan_recursive_candidates.fqdn
                         ORDER BY verification.checked_at DESC, verification.id DESC
                         LIMIT 1
                       ), '')='error' AND attempts<3 THEN 'queued'
                       ELSE 'done'
                   END
                   WHERE scan_id=? AND fqdn IN ({placeholders})"#
            );
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 2);
            values.push(scan_id.into());
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;

            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "DELETE FROM scan_recursive_candidates \
                     WHERE scan_id=? AND status='done' AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Remove recursive rows whose positive answer was already persisted by
    /// this same scan. A later transient verification journal entry must not
    /// keep such a hydrated success in an endless retry loop.
    pub fn complete_scan_recursive_candidates(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(
                &format!(
                    "DELETE FROM scan_recursive_candidates \
                     WHERE scan_id=? AND fqdn IN ({placeholders})"
                ),
                rusqlite::params_from_iter(values),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn scan_recursive_depth_has_more(&self, scan_id: i64, depth: usize) -> Result<bool> {
        Ok(self.lock()?.query_row(
            r#"SELECT EXISTS(
                   SELECT 1 FROM scan_recursive_candidates
                   WHERE scan_id=?1 AND depth=?2
                     AND status<>'done' AND attempts<3
               ) OR EXISTS(
                   SELECT 1 FROM scan_recursive_parents
                   WHERE scan_id=?1 AND depth=?2 AND exhausted=0
               )"#,
            params![scan_id, depth.min(i64::MAX as usize) as i64],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn scan_recursive_has_more(&self, scan_id: i64) -> Result<bool> {
        Ok(self.lock()?.query_row(
            r#"SELECT EXISTS(
                   SELECT 1 FROM scan_recursive_candidates
                   WHERE scan_id=?1 AND status<>'done' AND attempts<3
               ) OR EXISTS(
                   SELECT 1 FROM scan_recursive_parents
                   WHERE scan_id=?1 AND exhausted=0
               )"#,
            [scan_id],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn pending_scan_candidate_count(&self, scan_id: i64) -> Result<i64> {
        Ok(self.lock()?.query_row(
            "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1 AND status='queued' AND attempts<3",
            [scan_id],
            |row| row.get(0),
        )?)
    }

    pub fn pending_scan_candidate_count_eligible(
        &self,
        scan_id: i64,
        include_active: bool,
    ) -> Result<i64> {
        Ok(self.lock()?.query_row(
            r#"SELECT COUNT(*) FROM scan_candidates
               WHERE scan_id=?1 AND status='queued' AND attempts<3
                 AND ?2<>0"#,
            params![scan_id, i64::from(include_active)],
            |row| row.get(0),
        )?)
    }

    pub fn scan_candidate_count(&self, scan_id: i64) -> Result<i64> {
        Ok(self.lock()?.query_row(
            "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1",
            [scan_id],
            |row| row.get(0),
        )?)
    }

    /// Cumulative active-enumeration budget. Terminal rows may be removed or
    /// promoted to passive seeds, so physical queue length alone is not a safe
    /// `--max-words` counter across resume.
    pub fn scan_candidate_budget_count(&self, scan_id: i64) -> Result<i64> {
        Ok(self.lock()?.query_row(
            r#"SELECT
                   COALESCE((SELECT SUM(attempts) FROM scan_generator_stats WHERE scan_id=?1), 0)
                 + COALESCE((SELECT COUNT(*) FROM scan_candidates
                             WHERE scan_id=?1 AND learning_recorded=0), 0)"#,
            [scan_id],
            |row| row.get(0),
        )?)
    }

    pub fn mark_scan_candidates_done(&self, scan_id: i64, hosts: &[String]) -> Result<()> {
        if hosts.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for chunk in hosts.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                r#"UPDATE scan_candidates SET status=CASE
                       WHEN COALESCE((
                         SELECT verification.outcome
                          FROM dns_verifications AS verification
                               INDEXED BY idx_dns_verifications_name
                         WHERE verification.scan_id=?
                           AND verification.fqdn=scan_candidates.fqdn
                         ORDER BY verification.checked_at DESC, verification.id DESC
                         LIMIT 1
                       ), '')='error' AND attempts<3 THEN 'queued'
                       ELSE 'done'
                   END
                   WHERE scan_id=?
                      AND fqdn IN ({placeholders})"#
            );
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 2);
            values.push(scan_id.into());
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Record candidate learning exactly once before a queue row becomes
    /// terminal.  The per-row flag makes the operation idempotent across a
    /// crash followed by `--resume`, while compact aggregate tables avoid a
    /// permanent million-row event journal.
    pub fn record_scan_candidate_results(
        &self,
        scan_id: i64,
        results: &[(String, String, String, bool)],
    ) -> Result<()> {
        if results.is_empty() {
            return Ok(());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut stored_words = transaction
            .query_row(
                "SELECT COUNT(*) FROM scan_attempted_words WHERE scan_id=?1",
                [scan_id],
                |row| row.get::<_, i64>(0),
            )?
            .max(0) as usize;
        for (fqdn, relative_name, generator, success) in results {
            let recorded = transaction.execute(
                r#"UPDATE scan_candidates SET learning_recorded=1
                   WHERE scan_id=?1 AND fqdn=?2 AND learning_recorded=0
                     AND (
                         attempts>=3
                         OR COALESCE((
                             SELECT verification.outcome
                              FROM dns_verifications AS verification
                                   INDEXED BY idx_dns_verifications_name
                             WHERE verification.scan_id=?1
                               AND verification.fqdn=scan_candidates.fqdn
                             ORDER BY verification.checked_at DESC, verification.id DESC
                             LIMIT 1
                         ), '')<>'error'
                     )"#,
                params![scan_id, fqdn],
            )?;
            if recorded == 0 {
                continue;
            }
            transaction.execute(
                r#"INSERT INTO scan_generator_stats(scan_id, generator, attempts, successes)
                   VALUES (?1, ?2, 1, ?3)
                   ON CONFLICT(scan_id, generator) DO UPDATE SET
                       attempts=attempts+1,
                       successes=successes+excluded.successes"#,
                params![scan_id, generator, i64::from(*success)],
            )?;
            if generator != "builtin" && stored_words < 100_000 {
                for word in relative_name
                    .split('.')
                    .filter(|label| learnable_label(label))
                {
                    let added = transaction.execute(
                        "INSERT OR IGNORE INTO scan_attempted_words(scan_id, word) VALUES (?1, ?2)",
                        params![scan_id, word],
                    )?;
                    stored_words = stored_words.saturating_add(added);
                    if stored_words >= 100_000 {
                        break;
                    }
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn scan_candidate_learning(&self, scan_id: i64) -> Result<ScanCandidateLearning> {
        let connection = self.lock()?;
        let mut attempts = HashMap::new();
        let mut successes = HashMap::new();
        let mut total = 0_usize;
        {
            let mut statement = connection.prepare(
                "SELECT generator, attempts, successes FROM scan_generator_stats WHERE scan_id=?1",
            )?;
            for row in statement.query_map([scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })? {
                let (generator, generator_attempts, generator_successes) = row?;
                let generator_attempts = generator_attempts.max(0) as usize;
                attempts.insert(generator.clone(), generator_attempts);
                successes.insert(generator, generator_successes.max(0) as usize);
                total = total.saturating_add(generator_attempts);
            }
        }
        let words = {
            let mut statement = connection
                .prepare("SELECT word FROM scan_attempted_words WHERE scan_id=?1 ORDER BY word")?;
            statement
                .query_map([scan_id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<BTreeSet<_>>>()?
        };
        Ok(ScanCandidateLearning {
            generator_attempts: attempts,
            generator_successes: successes,
            attempted_words: words,
            total_attempts: total,
        })
    }

    pub fn scan_seed_candidates_for_output(
        &self,
        scan_id: i64,
    ) -> Result<Vec<(String, BTreeSet<String>)>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT fqdn, sources_json FROM scan_seed_candidates
               WHERE scan_id=?1 ORDER BY fqdn"#,
        )?;
        statement
            .query_map([scan_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|row| {
                let (fqdn, sources_json) = row?;
                Ok((
                    fqdn,
                    serde_json::from_str::<BTreeSet<String>>(&sources_json)
                        .context("provenance de candidat passif SQLite invalide")?,
                ))
            })
            .collect()
    }

    /// Return the supplied names that may still be materialized as current
    /// scan results. Append-only DNS history is authoritative here: a retained
    /// positive cache row cannot override a later decisive negative verdict.
    pub fn current_output_names(&self, hosts: &[String]) -> Result<BTreeSet<String>> {
        self.current_output_names_filtered(None, hosts)
    }

    /// Apply the current-result DNS rule plus the root-scoped wildcard
    /// quarantine used for passive seed candidates.
    pub fn current_seed_output_names(
        &self,
        root_domain: &str,
        hosts: &[String],
    ) -> Result<BTreeSet<String>> {
        self.current_output_names_filtered(Some(root_domain), hosts)
    }

    fn current_output_names_filtered(
        &self,
        root_domain: Option<&str>,
        hosts: &[String],
    ) -> Result<BTreeSet<String>> {
        const QUERY_BATCH_SIZE: usize = 400;

        let connection = self.lock()?;
        let mut current = BTreeSet::new();
        for chunk in hosts.chunks(QUERY_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let candidate_values = std::iter::repeat_n("(?)", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let quarantine_clause = if root_domain.is_some() {
                r#"AND NOT EXISTS (
                       SELECT 1 FROM wildcard_quarantine quarantine
                       WHERE quarantine.root_domain=?
                         AND quarantine.fqdn=candidates.fqdn
                   )"#
            } else {
                ""
            };
            let sql = format!(
                r#"WITH candidates(fqdn) AS (VALUES {candidate_values})
                   SELECT candidates.fqdn FROM candidates
                   WHERE COALESCE((
                       SELECT verification.outcome
                       FROM dns_verifications AS verification
                            INDEXED BY idx_dns_verifications_name
                       WHERE verification.fqdn=candidates.fqdn
                         AND verification.outcome IN ('live','negative')
                       ORDER BY verification.checked_at DESC, verification.id DESC
                       LIMIT 1
                   ), '')<>'negative'
                   {quarantine_clause}"#
            );
            let mut values = chunk
                .iter()
                .cloned()
                .map(rusqlite::types::Value::from)
                .collect::<Vec<_>>();
            if let Some(root_domain) = root_domain {
                values.push(root_domain.to_owned().into());
            }
            let mut statement = connection.prepare(&sql)?;
            current.extend(
                statement
                    .query_map(rusqlite::params_from_iter(values), |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<BTreeSet<_>>>()?,
            );
        }
        Ok(current)
    }

    pub fn live_scan_finding_names(&self, scan_id: i64) -> Result<BTreeSet<String>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT fqdn FROM scan_findings WHERE scan_id=?1 AND state='live' AND wildcard=0 ORDER BY fqdn",
        )?;
        statement
            .query_map([scan_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .map_err(Into::into)
    }

    /// Rehydrate positive answers already completed by this same resumable
    /// scan. They are needed as recursive parents after a partial run because
    /// terminal seed/candidate queue rows are intentionally not replayed.
    pub fn live_scan_answers(&self, scan_id: i64) -> Result<Vec<(ResolvedHost, BTreeSet<String>)>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT finding.fqdn, cache.records_json, cache.last_checked,
                      cache.resolver_count, cache.authoritative, inventory.sources
               FROM scan_findings AS finding
               JOIN dns_cache AS cache ON cache.fqdn=finding.fqdn AND cache.status='positive'
               JOIN subdomains AS inventory ON inventory.fqdn=finding.fqdn
               WHERE finding.scan_id=?1 AND finding.state='live' AND finding.wildcard=0
               ORDER BY finding.fqdn"#,
        )?;
        statement
            .query_map([scan_id], |row| {
                let records_json = row.get::<_, String>(1)?;
                let records = serde_json::from_str(&records_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                let sources = row
                    .get::<_, String>(5)?
                    .split(',')
                    .filter(|source| !source.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                Ok((
                    ResolvedHost {
                        fqdn: row.get(0)?,
                        records,
                        from_cache: true,
                        last_verified_at: row.get(2)?,
                        resolver_count: row.get::<_, i64>(3)?.clamp(0, i64::from(u16::MAX)) as u16,
                        authoritative_validation: row.get::<_, i64>(4)? != 0,
                    },
                    sources,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn clear_scan_candidates(&self, scan_id: i64) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM scan_candidates WHERE scan_id=?1", [scan_id])?;
        transaction.execute(
            "DELETE FROM scan_candidate_feeds WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_seed_candidates WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_generator_stats WHERE scan_id=?1",
            [scan_id],
        )?;
        transaction.execute(
            "DELETE FROM scan_attempted_words WHERE scan_id=?1",
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
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finish_scan(
        &self,
        scan_id: i64,
        status: &str,
        candidates: usize,
        found: usize,
        cache_hits: usize,
        duration_ms: u128,
        warnings: &[String],
    ) -> Result<()> {
        self.lock()?.execute(
            r#"UPDATE scans SET finished_at=?1, status=?2, candidates=?3, found=?4,
               cache_hits=?5, duration_ms=?6, warnings_json=?7 WHERE id=?8"#,
            params![
                now_epoch(),
                status,
                usize_to_i64_saturating(candidates),
                usize_to_i64_saturating(found),
                usize_to_i64_saturating(cache_hits),
                duration_ms.min(i64::MAX as u128) as i64,
                serde_json::to_string(warnings)?,
                scan_id
            ],
        )?;
        Ok(())
    }

    /// Persist a successful partial result while deliberately keeping the
    /// checkpoint and candidate feeds resumable.
    #[allow(clippy::too_many_arguments)]
    pub fn pause_scan(
        &self,
        scan_id: i64,
        candidates: usize,
        found: usize,
        cache_hits: usize,
        duration_ms: u128,
        warnings: &[String],
    ) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"UPDATE scans SET finished_at=?1, status='interrupted', candidates=?2,
               found=?3, cache_hits=?4, duration_ms=?5, warnings_json=?6
               WHERE id=?7 AND learning_applied=0"#,
            params![
                now,
                usize_to_i64_saturating(candidates),
                usize_to_i64_saturating(found),
                usize_to_i64_saturating(cache_hits),
                duration_ms.min(i64::MAX as u128) as i64,
                serde_json::to_string(warnings)?,
                scan_id
            ],
        )?;
        transaction.execute(
            r#"UPDATE scan_checkpoints
               SET stage='paused', updated_at=?1, completed=0 WHERE scan_id=?2"#,
            params![now, scan_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finalize_scan(
        &self,
        scan_id: i64,
        candidates: usize,
        found: usize,
        cache_hits: usize,
        duration_ms: u128,
        warnings: &[String],
    ) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
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

    /// Finalizes work that is intentionally non-resumable, such as inventory
    /// refresh. Unlike `finish_scan`, this also closes the checkpoint so a
    /// cancelled refresh can never be selected by `scan --resume`.
    #[allow(clippy::too_many_arguments)]
    pub fn finalize_non_resumable_scan(
        &self,
        scan_id: i64,
        status: &str,
        candidates: usize,
        found: usize,
        cache_hits: usize,
        duration_ms: u128,
        warnings: &[String],
    ) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"UPDATE scans SET finished_at=?1, status=?2, candidates=?3,
               found=?4, cache_hits=?5, duration_ms=?6, warnings_json=?7 WHERE id=?8"#,
            params![
                now_epoch(),
                status,
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
        transaction.commit()?;
        Ok(())
    }
}
