use super::*;

impl Database {
    /// Atomically reserves one provider refresh for a single process/task.
    /// The lease is deliberately independent from permanent observations and
    /// expires after the caller's bounded source deadline if the process dies.
    pub fn try_acquire_passive_refresh_lease(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        ttl: Duration,
    ) -> Result<bool> {
        self.try_acquire_passive_refresh_lease_before(root_domain, source, owner, ttl, None)
    }

    pub fn try_acquire_passive_refresh_lease_until(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        ttl: Duration,
        deadline: Instant,
    ) -> Result<bool> {
        self.try_acquire_passive_refresh_lease_before(
            root_domain,
            source,
            owner,
            ttl,
            Some(deadline),
        )
    }

    fn try_acquire_passive_refresh_lease_before(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        ttl: Duration,
        deadline: Option<Instant>,
    ) -> Result<bool> {
        ensure_passive_persistence_deadline(deadline)?;
        if ttl.is_zero() {
            bail!("durée de lease passive nulle");
        }
        validate_passive_pagination_key(root_domain, source, "lease", 1, owner)?;
        let now = now_epoch();
        let expires_at = now.saturating_add(u64_to_i64_saturating(ttl.as_secs().max(1)));
        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        cleanup_expired_passive_refresh_leases(&transaction, now)?;
        let acquired = transaction.execute(
            r#"INSERT INTO passive_refresh_leases(
                   root_domain, source, owner, expires_at, updated_at
               ) VALUES (?1, ?2, ?3, ?4, ?5)
               ON CONFLICT(root_domain, source) DO UPDATE SET
                   owner=excluded.owner,
                   expires_at=excluded.expires_at,
                   updated_at=excluded.updated_at
               WHERE passive_refresh_leases.expires_at<=?5
                  OR passive_refresh_leases.owner=excluded.owner"#,
            params![root_domain, source, owner, expires_at, now],
        )? == 1;
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(acquired)
    }

    /// Extends a refresh lease only while the caller still owns it. A false
    /// result means another bounded task took over after expiry, so the stale
    /// task must stop before writing another provider page.
    pub fn renew_passive_refresh_lease(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        ttl: Duration,
    ) -> Result<bool> {
        self.renew_passive_refresh_lease_before(root_domain, source, owner, ttl, None)
    }

    pub fn renew_passive_refresh_lease_until(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        ttl: Duration,
        deadline: Instant,
    ) -> Result<bool> {
        self.renew_passive_refresh_lease_before(root_domain, source, owner, ttl, Some(deadline))
    }

    fn renew_passive_refresh_lease_before(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        ttl: Duration,
        deadline: Option<Instant>,
    ) -> Result<bool> {
        ensure_passive_persistence_deadline(deadline)?;
        if ttl.is_zero() {
            bail!("durée de renouvellement passive nulle");
        }
        validate_passive_pagination_key(root_domain, source, "lease", 1, owner)?;
        let now = now_epoch();
        let expires_at = now.saturating_add(u64_to_i64_saturating(ttl.as_secs().max(1)));
        let connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        Ok(connection.execute(
            r#"UPDATE passive_refresh_leases
               SET expires_at=?1, updated_at=?2
               WHERE root_domain=?3 AND source=?4 AND owner=?5"#,
            params![expires_at, now, root_domain, source, owner],
        )? == 1)
    }

    /// Releases a lease only for its owner. Releasing a stale guard can never
    /// remove a newer process's reservation.
    pub fn release_passive_refresh_lease(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
    ) -> Result<bool> {
        self.release_passive_refresh_lease_before(root_domain, source, owner, None)
    }

    pub fn release_passive_refresh_lease_until(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        deadline: Instant,
    ) -> Result<bool> {
        self.release_passive_refresh_lease_before(root_domain, source, owner, Some(deadline))
    }

    fn release_passive_refresh_lease_before(
        &self,
        root_domain: &str,
        source: &str,
        owner: &str,
        deadline: Option<Instant>,
    ) -> Result<bool> {
        ensure_passive_persistence_deadline(deadline)?;
        validate_passive_pagination_key(root_domain, source, "lease", 1, owner)?;
        let connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        Ok(connection.execute(
            r#"DELETE FROM passive_refresh_leases
               WHERE root_domain=?1 AND source=?2 AND owner=?3"#,
            params![root_domain, source, owner],
        )? == 1)
    }

    /// Removes only obsolete lane contracts before a source refresh starts.
    /// Valid unfinished or completed lanes remain durable across crashes.
    pub fn prepare_passive_pagination_source(
        &self,
        root_domain: &str,
        source: &str,
        expected_contracts: &[(&str, u32, &str)],
    ) -> Result<()> {
        self.prepare_passive_pagination_source_before(root_domain, source, expected_contracts, None)
    }

    pub fn prepare_passive_pagination_source_until(
        &self,
        root_domain: &str,
        source: &str,
        expected_contracts: &[(&str, u32, &str)],
        deadline: Instant,
    ) -> Result<()> {
        self.prepare_passive_pagination_source_before(
            root_domain,
            source,
            expected_contracts,
            Some(deadline),
        )
    }

    fn prepare_passive_pagination_source_before(
        &self,
        root_domain: &str,
        source: &str,
        expected_contracts: &[(&str, u32, &str)],
        deadline: Option<Instant>,
    ) -> Result<()> {
        if expected_contracts.is_empty() {
            bail!("aucun contrat attendu pour la préparation passive");
        }
        let mut expected = BTreeMap::new();
        for &(lane, contract_version, query_hash) in expected_contracts {
            validate_passive_pagination_key(
                root_domain,
                source,
                lane,
                contract_version,
                query_hash,
            )?;
            if expected
                .insert(lane.to_owned(), (contract_version, query_hash.to_owned()))
                .is_some()
            {
                bail!("voie de pagination passive attendue dupliquée: {lane}");
            }
        }

        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        cleanup_abandoned_passive_refresh_sessions(&transaction, now_epoch())?;
        let stored = {
            let mut statement = transaction.prepare(
                r#"SELECT lane, contract_version, query_hash
                   FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2"#,
            )?;
            statement
                .query_map(params![root_domain, source], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (lane, contract_version, query_hash) in stored {
            ensure_passive_persistence_deadline(deadline)?;
            let compatible =
                expected
                    .get(&lane)
                    .is_some_and(|(expected_version, expected_hash)| {
                        contract_version == i64::from(*expected_version)
                            && query_hash == *expected_hash
                    });
            if !compatible {
                transaction.execute(
                    r#"DELETE FROM passive_pagination_state
                       WHERE root_domain=?1 AND source=?2 AND lane=?3"#,
                    params![root_domain, source, lane],
                )?;
            }
        }
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(())
    }

    /// Loads a compatible numeric connector checkpoint. A contract or query
    /// change discards only the small progress row; permanent observations are
    /// intentionally untouched and the connector restarts from position one.
    pub fn passive_pagination_resume(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
    ) -> Result<Option<PassivePaginationState>> {
        self.passive_pagination_resume_before(
            root_domain,
            source,
            lane,
            contract_version,
            query_hash,
            None,
        )
    }

    pub fn passive_pagination_resume_until(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        deadline: Instant,
    ) -> Result<Option<PassivePaginationState>> {
        self.passive_pagination_resume_before(
            root_domain,
            source,
            lane,
            contract_version,
            query_hash,
            Some(deadline),
        )
    }

    fn passive_pagination_resume_before(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        deadline: Option<Instant>,
    ) -> Result<Option<PassivePaginationState>> {
        validate_passive_pagination_key(root_domain, source, lane, contract_version, query_hash)?;
        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        let row = transaction
            .query_row(
                r#"SELECT contract_version, query_hash, next_position, records_seen,
                          expected_records, expected_pages, last_page_hash,
                          last_page_records, done, updated_at
                   FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2 AND lane=?3"#,
                params![root_domain, source, lane],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            stored_contract,
            stored_query_hash,
            next_position,
            records_seen,
            expected_records,
            expected_pages,
            last_page_hash,
            last_page_records,
            done,
            updated_at,
        )) = row
        else {
            ensure_passive_persistence_deadline(deadline)?;
            transaction.commit()?;
            return Ok(None);
        };
        if stored_contract != i64::from(contract_version) || stored_query_hash != query_hash {
            transaction.execute(
                r#"DELETE FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2 AND lane=?3"#,
                params![root_domain, source, lane],
            )?;
            ensure_passive_persistence_deadline(deadline)?;
            transaction.commit()?;
            return Ok(None);
        }
        validate_passive_pagination_hash(&last_page_hash, "hash de dernière page")?;
        let to_u64 = |value: i64, field: &str| -> Result<u64> {
            u64::try_from(value)
                .with_context(|| format!("compteur {field} négatif dans la pagination passive"))
        };
        let state = PassivePaginationState {
            contract_version,
            query_hash: stored_query_hash,
            next_position: to_u64(next_position, "next_position")?,
            records_seen: to_u64(records_seen, "records_seen")?,
            expected_records: expected_records
                .map(|value| to_u64(value, "expected_records"))
                .transpose()?,
            expected_pages: expected_pages
                .map(|value| to_u64(value, "expected_pages"))
                .transpose()?,
            last_page_hash,
            last_page_records: to_u64(last_page_records, "last_page_records")?,
            done: done != 0,
            updated_at,
        };
        if state.next_position == 0 || state.last_page_records > state.records_seen {
            bail!("état de pagination passive incohérent");
        }
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(Some(state))
    }

    /// Atomically stores one validated provider page and advances its numeric
    /// resume position. Any SQLite error rolls back both evidence and progress,
    /// so the same page is retried on the next run.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_passive_pagination_page(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        page: &PassivePaginationPage,
        names: &BTreeSet<String>,
    ) -> Result<usize> {
        self.commit_passive_pagination_page_before(
            root_domain,
            source,
            lane,
            contract_version,
            query_hash,
            page,
            names,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_passive_pagination_page_until(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        page: &PassivePaginationPage,
        names: &BTreeSet<String>,
        deadline: Instant,
    ) -> Result<usize> {
        self.commit_passive_pagination_page_before(
            root_domain,
            source,
            lane,
            contract_version,
            query_hash,
            page,
            names,
            Some(deadline),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_passive_pagination_page_before(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        page: &PassivePaginationPage,
        names: &BTreeSet<String>,
        deadline: Option<Instant>,
    ) -> Result<usize> {
        ensure_passive_persistence_deadline(deadline)?;
        validate_passive_pagination_key(root_domain, source, lane, contract_version, query_hash)?;
        validate_passive_pagination_hash(&page.page_hash, "hash de page")?;
        if page.position == 0
            || page.next_position != page.position.saturating_add(1)
            || page.records_seen < page.page_records
            || page
                .expected_records
                .is_some_and(|expected| page.records_seen > expected)
            || page.expected_pages.is_some_and(|expected| {
                expected == 0
                    && (page.position != 1 || page.page_records != 0 || page.records_seen != 0)
            })
        {
            bail!("transition de page passive incohérente");
        }
        let position = passive_pagination_counter(page.position, "position")?;
        let next_position = passive_pagination_counter(page.next_position, "next_position")?;
        let records_seen = passive_pagination_counter(page.records_seen, "records_seen")?;
        let expected_records = page
            .expected_records
            .map(|value| passive_pagination_counter(value, "expected_records"))
            .transpose()?;
        let expected_pages = page
            .expected_pages
            .map(|value| passive_pagination_counter(value, "expected_pages"))
            .transpose()?;
        let page_records = passive_pagination_counter(page.page_records, "page_records")?;

        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        let mut overlap_replay = false;
        let current = transaction
            .query_row(
                r#"SELECT contract_version, query_hash, next_position, records_seen,
                          expected_records, expected_pages, last_page_hash,
                          last_page_records, done
                   FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2 AND lane=?3"#,
                params![root_domain, source, lane],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?;
        if let Some((
            stored_contract,
            stored_query_hash,
            stored_next_position,
            stored_records_seen,
            stored_expected_records,
            stored_expected_pages,
            stored_last_page_hash,
            stored_last_page_records,
            done,
        )) = current
        {
            if stored_contract != i64::from(contract_version)
                || stored_query_hash != query_hash
                || done != 0
            {
                bail!("contrat de pagination passive modifié pendant la collecte");
            }
            let forward = position == stored_next_position;
            let overlap = position.saturating_add(1) == stored_next_position
                && next_position == stored_next_position;
            if !forward && !overlap {
                bail!(
                    "position de pagination passive inattendue: {position}, attendue {stored_next_position}"
                );
            }
            if stored_expected_records.is_some() && stored_expected_records != expected_records
                || stored_expected_pages.is_some() && stored_expected_pages != expected_pages
            {
                bail!("totaux de pagination passive modifiés pendant la collecte");
            }
            let base_records = if overlap {
                if page.page_hash != stored_last_page_hash
                    || page_records != stored_last_page_records
                {
                    bail!("la page de chevauchement passive a changé depuis son commit");
                }
                overlap_replay = true;
                stored_records_seen
                    .checked_sub(stored_last_page_records)
                    .context("compteurs de chevauchement passif incohérents")?
            } else {
                stored_records_seen
            };
            if records_seen != base_records.saturating_add(page_records) {
                bail!("compteur de résultats passifs incohérent avec la page validée");
            }
        } else if position != 1 || records_seen != page_records {
            bail!("la pagination passive sans checkpoint doit commencer à la position 1");
        }

        if overlap_replay {
            // The previous transaction already made both evidence and progress
            // durable. Do not increment evidence counters for the deliberate
            // one-page overlap used to verify restart continuity.
            ensure_passive_persistence_deadline(deadline)?;
            transaction.commit()?;
            return Ok(0);
        }

        let observations = names
            .iter()
            .map(|fqdn| ObservationInput {
                fqdn: fqdn.clone(),
                kind: "passive".to_owned(),
                source: format!("passive:{source}"),
                value: String::new(),
            })
            .collect::<Vec<_>>();
        ensure_passive_persistence_deadline(deadline)?;
        let stats = insert_passive_observation_rows_with_stats_before(
            &transaction,
            root_domain,
            source,
            &observations,
            deadline,
        )?;
        ensure_passive_persistence_deadline(deadline)?;
        transaction.execute(
            r#"INSERT OR IGNORE INTO passive_cache(
                   root_domain, source, names_json, updated_at
               ) VALUES (?1, ?2, '[]', 0)"#,
            params![root_domain, source],
        )?;
        let now = now_epoch();
        transaction.execute(
            r#"INSERT INTO passive_pagination_state(
                   root_domain, source, lane, contract_version, query_hash,
                   next_position, records_seen, expected_records, expected_pages,
                   last_page_hash, last_page_records, done, updated_at
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12)
               ON CONFLICT(root_domain, source, lane) DO UPDATE SET
                   contract_version=excluded.contract_version,
                   query_hash=excluded.query_hash,
                   next_position=excluded.next_position,
                   records_seen=excluded.records_seen,
                   expected_records=excluded.expected_records,
                   expected_pages=excluded.expected_pages,
                   last_page_hash=excluded.last_page_hash,
                   last_page_records=excluded.last_page_records,
                   done=0,
                   updated_at=excluded.updated_at"#,
            params![
                root_domain,
                source,
                lane,
                i64::from(contract_version),
                query_hash,
                next_position,
                records_seen,
                expected_records,
                expected_pages,
                page.page_hash,
                page_records,
                now,
            ],
        )?;
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(stats.novel_names)
    }

    /// Marks one numeric lane complete without publishing source freshness.
    /// The durable `done` row is intentionally retained so a crash between
    /// connector completion and source completion cannot force a page-one
    /// replay or make a partial multi-lane refresh appear complete.
    pub fn finish_passive_pagination(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
    ) -> Result<()> {
        self.finish_passive_pagination_before(
            root_domain,
            source,
            lane,
            contract_version,
            query_hash,
            None,
        )
    }

    pub fn finish_passive_pagination_until(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        deadline: Instant,
    ) -> Result<()> {
        self.finish_passive_pagination_before(
            root_domain,
            source,
            lane,
            contract_version,
            query_hash,
            Some(deadline),
        )
    }

    fn finish_passive_pagination_before(
        &self,
        root_domain: &str,
        source: &str,
        lane: &str,
        contract_version: u32,
        query_hash: &str,
        deadline: Option<Instant>,
    ) -> Result<()> {
        ensure_passive_persistence_deadline(deadline)?;
        validate_passive_pagination_key(root_domain, source, lane, contract_version, query_hash)?;
        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        let now = now_epoch();
        let (records_seen, expected_records, next_position, expected_pages, last_page_records): (
            i64,
            Option<i64>,
            i64,
            Option<i64>,
            i64,
        ) = transaction
            .query_row(
                r#"SELECT records_seen, expected_records, next_position,
                          expected_pages, last_page_records
                   FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2 AND lane=?3
                     AND contract_version=?4 AND query_hash=?5"#,
                params![
                    root_domain,
                    source,
                    lane,
                    i64::from(contract_version),
                    query_hash
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .context("état de pagination passive absent lors de la finalisation")?;
        if expected_records.is_some_and(|expected| records_seen != expected) {
            bail!("total de résultats passifs incomplet lors de la finalisation");
        }
        if let Some(expected_pages) = expected_pages {
            let pages_complete = if expected_pages == 0 {
                records_seen == 0 && last_page_records == 0 && next_position == 2
            } else {
                next_position == expected_pages.saturating_add(1)
            };
            if !pages_complete {
                bail!("total de pages passives incomplet lors de la finalisation");
            }
        }
        let finished = transaction.execute(
            r#"UPDATE passive_pagination_state
               SET done=1, updated_at=?1
               WHERE root_domain=?2 AND source=?3 AND lane=?4
                 AND contract_version=?5 AND query_hash=?6"#,
            params![
                now,
                root_domain,
                source,
                lane,
                i64::from(contract_version),
                query_hash
            ],
        )?;
        if finished != 1 {
            bail!("état de pagination passive absent lors de la finalisation");
        }
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(())
    }

    /// Publishes one passive source refresh only when its durable lane set is
    /// exactly the expected contract set and every lane is marked complete.
    /// Freshness publication, checkpoint removal and refresh-marker cleanup
    /// form a single transaction.
    pub fn complete_passive_pagination_source(
        &self,
        root_domain: &str,
        source: &str,
        expected_contracts: &[(&str, u32, &str)],
    ) -> Result<()> {
        self.complete_passive_pagination_source_before(
            root_domain,
            source,
            expected_contracts,
            None,
        )
    }

    pub fn complete_passive_pagination_source_until(
        &self,
        root_domain: &str,
        source: &str,
        expected_contracts: &[(&str, u32, &str)],
        deadline: Instant,
    ) -> Result<()> {
        self.complete_passive_pagination_source_before(
            root_domain,
            source,
            expected_contracts,
            Some(deadline),
        )
    }

    fn complete_passive_pagination_source_before(
        &self,
        root_domain: &str,
        source: &str,
        expected_contracts: &[(&str, u32, &str)],
        deadline: Option<Instant>,
    ) -> Result<()> {
        ensure_passive_persistence_deadline(deadline)?;
        if expected_contracts.is_empty() {
            bail!("aucun contrat attendu pour la finalisation passive");
        }
        let mut expected = BTreeMap::new();
        for &(lane, contract_version, query_hash) in expected_contracts {
            validate_passive_pagination_key(
                root_domain,
                source,
                lane,
                contract_version,
                query_hash,
            )?;
            if expected
                .insert(lane.to_owned(), (contract_version, query_hash.to_owned()))
                .is_some()
            {
                bail!("voie de pagination passive attendue dupliquée: {lane}");
            }
        }

        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        let actual = {
            let mut statement = transaction.prepare(
                r#"SELECT lane, contract_version, query_hash, done
                   FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2
                   ORDER BY lane"#,
            )?;
            statement
                .query_map(params![root_domain, source], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        if actual.len() != expected.len() {
            bail!(
                "ensemble de voies passives incomplet: {} présente(s), {} attendue(s)",
                actual.len(),
                expected.len()
            );
        }
        for (lane, contract_version, query_hash, done) in &actual {
            ensure_passive_persistence_deadline(deadline)?;
            let Some((expected_version, expected_hash)) = expected.get(lane) else {
                bail!("voie de pagination passive inattendue: {lane}");
            };
            if *contract_version != i64::from(*expected_version)
                || query_hash != expected_hash
                || *done != 1
            {
                bail!("voie de pagination passive incomplète ou incompatible: {lane}");
            }
        }

        transaction.execute(
            r#"INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
               VALUES (?1, ?2, '[]', ?3)
               ON CONFLICT(root_domain, source) DO UPDATE SET
               updated_at=excluded.updated_at"#,
            params![root_domain, source, now_epoch()],
        )?;
        let removed = transaction.execute(
            r#"DELETE FROM passive_pagination_state
               WHERE root_domain=?1 AND source=?2"#,
            params![root_domain, source],
        )?;
        if removed != expected.len() {
            bail!("suppression incomplète des checkpoints de pagination passive");
        }
        clear_passive_refresh_session(&transaction, root_domain, source)?;
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn passive_cache(&self, domain: &str, source: &str) -> Result<Option<PassiveCacheEntry>> {
        self.passive_cache_bounded(domain, source, usize::MAX)
    }

    pub fn passive_cache_bounded(
        &self,
        domain: &str,
        source: &str,
        limit: usize,
    ) -> Result<Option<PassiveCacheEntry>> {
        self.passive_cache_bounded_before(domain, source, limit, None)
    }

    pub fn passive_cache_bounded_until(
        &self,
        domain: &str,
        source: &str,
        limit: usize,
        deadline: Instant,
    ) -> Result<Option<PassiveCacheEntry>> {
        self.passive_cache_bounded_before(domain, source, limit, Some(deadline))
    }

    fn passive_cache_bounded_before(
        &self,
        domain: &str,
        source: &str,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Option<PassiveCacheEntry>> {
        ensure_passive_persistence_deadline(deadline)?;
        let connection = self.lock_passive_until(deadline)?;
        let row: Option<(String, i64)> = connection
            .query_row(
                r#"SELECT names_json, updated_at FROM passive_cache
                   WHERE root_domain=?1 AND source=?2"#,
                params![domain, source],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        drop(connection);
        row.map(|(names_json, updated_at)| {
            ensure_passive_persistence_deadline(deadline)?;
            let observed = match deadline {
                Some(deadline) => self.observation_names_bounded_until(
                    domain,
                    &format!("passive:{source}"),
                    limit,
                    deadline,
                )?,
                None => {
                    self.observation_names_bounded(domain, &format!("passive:{source}"), limit)?
                }
            };
            let mut names = observed.into_iter().collect::<BTreeSet<_>>();
            if names.len() < limit {
                extend_legacy_passive_names_bounded(&names_json, &mut names, limit, deadline)?;
            }
            ensure_passive_persistence_deadline(deadline)?;
            Ok(PassiveCacheEntry {
                names: names.into_iter().collect(),
                updated_at,
            })
        })
        .transpose()
    }

    pub fn store_passive_cache(
        &self,
        domain: &str,
        source: &str,
        names: &[String],
    ) -> Result<Vec<String>> {
        self.store_passive_cache_with_completeness(domain, source, names, true)
    }

    pub fn store_partial_passive_cache(
        &self,
        domain: &str,
        source: &str,
        names: &[String],
    ) -> Result<Vec<String>> {
        self.store_passive_cache_with_completeness(domain, source, names, false)
    }

    fn store_passive_cache_with_completeness(
        &self,
        domain: &str,
        source: &str,
        names: &[String],
        complete: bool,
    ) -> Result<Vec<String>> {
        self.store_passive_observation_page(domain, source, &names.iter().cloned().collect())?;
        self.mark_passive_cache_refresh(domain, source, complete)?;
        Ok(self
            .passive_cache(domain, source)?
            .map(|entry| entry.names.into_iter().collect())
            .unwrap_or_default())
    }

    /// Persist one complete provider page and return the number of hostnames
    /// that were not present in the durable global name index beforehand.
    /// This count remains exact even when the connector retains only a small
    /// in-memory working set.
    pub fn store_passive_observation_page(
        &self,
        domain: &str,
        source: &str,
        names: &BTreeSet<String>,
    ) -> Result<usize> {
        self.store_passive_observation_page_before(domain, source, names, None)
    }

    pub fn store_passive_observation_page_until(
        &self,
        domain: &str,
        source: &str,
        names: &BTreeSet<String>,
        deadline: Instant,
    ) -> Result<usize> {
        self.store_passive_observation_page_before(domain, source, names, Some(deadline))
    }

    fn store_passive_observation_page_before(
        &self,
        domain: &str,
        source: &str,
        names: &BTreeSet<String>,
        deadline: Option<Instant>,
    ) -> Result<usize> {
        ensure_passive_persistence_deadline(deadline)?;
        let evidence_source = format!("passive:{source}");
        let mut observations = Vec::with_capacity(names.len());
        for (index, fqdn) in names.iter().enumerate() {
            if index.is_multiple_of(128) {
                ensure_passive_persistence_deadline(deadline)?;
            }
            observations.push(ObservationInput {
                fqdn: fqdn.clone(),
                kind: "passive".to_owned(),
                source: evidence_source.clone(),
                value: String::new(),
            });
        }
        ensure_passive_persistence_deadline(deadline)?;
        let stats = if let Some(writer) = &self.writer {
            match deadline {
                Some(deadline) => writer.submit_passive_page_with_stats_until(
                    domain,
                    source,
                    observations,
                    deadline,
                )?,
                None => writer.submit_passive_page_with_stats(domain, source, observations)?,
            }
        } else {
            let mut connection = self.lock_passive_until(deadline)?;
            ensure_passive_persistence_deadline(deadline)?;
            insert_passive_observations_with_stats(
                &mut connection,
                domain,
                source,
                &observations,
                deadline,
            )?
        };
        Ok(stats.novel_names)
    }

    fn store_passive_observation_page_if_absent(
        &self,
        domain: &str,
        source: &str,
        names: &BTreeSet<String>,
        complete: bool,
        deadline: Option<Instant>,
        cancellation: &AtomicBool,
    ) -> Result<usize> {
        ensure_ct_materialization_active(deadline, cancellation)?;
        let now = now_epoch();
        let evidence_source = format!("passive:{source}");
        let names = names.iter().collect::<Vec<_>>();
        let mut written = 0_usize;
        for page in names.chunks(CT_MATERIALIZATION_PAGE_SIZE) {
            ensure_ct_materialization_active(deadline, cancellation)?;
            let mut connection = self.lock_ct_materialization_until(deadline, cancellation)?;
            ensure_ct_materialization_active(deadline, cancellation)?;
            let bounded_busy = deadline.map(|deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(250))
                    .max(Duration::from_millis(1))
            });
            if let Some(busy) = bounded_busy {
                connection.busy_timeout(busy)?;
            }
            let page_result: Result<usize> = (|| {
                let transaction = connection.transaction()?;
                let mut page_written = 0_usize;
                for (index, fqdn) in page.iter().enumerate() {
                    if index % 32 == 0 {
                        ensure_ct_materialization_active(deadline, cancellation)?;
                    }
                    transaction.execute(
                        r#"INSERT OR IGNORE INTO observed_names(
                               fqdn, reversed_name, first_seen, last_seen
                           ) VALUES (?1, ?2, ?3, ?3)"#,
                        params![fqdn, reverse_hostname(fqdn), now],
                    )?;
                    let name_id: i64 = transaction.query_row(
                        "SELECT id FROM observed_names WHERE fqdn=?1",
                        [fqdn],
                        |row| row.get(0),
                    )?;
                    page_written = page_written.saturating_add(transaction.execute(
                        r#"INSERT OR IGNORE INTO observation_evidence(
                               root_domain, name_id, kind, source, value,
                               first_seen, last_seen, times_seen
                           ) VALUES (?1, ?2, 'passive', ?3, '', ?4, ?4, 1)"#,
                        params![domain, name_id, &evidence_source, now],
                    )?);
                }
                ensure_ct_materialization_active(deadline, cancellation)?;
                transaction.commit()?;
                Ok(page_written)
            })();
            if bounded_busy.is_some() {
                connection.busy_timeout(Duration::from_secs(5))?;
            }
            written = written.saturating_add(page_result?);
            drop(connection);
            ensure_ct_materialization_active(deadline, cancellation)?;
        }

        // Freshness is committed only after every evidence page completed.
        // A cancelled run can retain permanent observations, but it cannot
        // advertise a complete target materialization.
        let mut connection = self.lock_ct_materialization_until(deadline, cancellation)?;
        ensure_ct_materialization_active(deadline, cancellation)?;
        let transaction = connection.transaction()?;
        if complete {
            transaction.execute(
                r#"INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
                   VALUES (?1, ?2, '[]', ?3)
                   ON CONFLICT(root_domain, source) DO UPDATE SET
                   updated_at=excluded.updated_at"#,
                params![domain, source, now],
            )?;
        } else {
            transaction.execute(
                r#"INSERT OR IGNORE INTO passive_cache(
                       root_domain, source, names_json, updated_at
                   ) VALUES (?1, ?2, '[]', 0)"#,
                params![domain, source],
            )?;
        }
        ensure_ct_materialization_active(deadline, cancellation)?;
        transaction.commit()?;
        Ok(written)
    }

    pub fn mark_passive_cache_refresh(
        &self,
        domain: &str,
        source: &str,
        complete: bool,
    ) -> Result<()> {
        self.mark_passive_cache_refresh_before(domain, source, complete, None)
    }

    pub fn mark_passive_cache_refresh_until(
        &self,
        domain: &str,
        source: &str,
        complete: bool,
        deadline: Instant,
    ) -> Result<()> {
        self.mark_passive_cache_refresh_before(domain, source, complete, Some(deadline))
    }

    fn mark_passive_cache_refresh_before(
        &self,
        domain: &str,
        source: &str,
        complete: bool,
        deadline: Option<Instant>,
    ) -> Result<()> {
        ensure_passive_persistence_deadline(deadline)?;
        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        if complete {
            transaction.execute(
                r#"INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
                   VALUES (?1, ?2, '[]', ?3)
                   ON CONFLICT(root_domain, source) DO UPDATE SET
                   updated_at=excluded.updated_at"#,
                params![domain, source, now_epoch()],
            )?;
            // Freshness publication and replay-marker removal are one atomic
            // completion boundary. A crash can therefore expose either a
            // resumable unfinished generation or a fully fresh cache, never a
            // half-completed mix of both.
            clear_passive_refresh_session(&transaction, domain, source)?;
        } else {
            transaction.execute(
                r#"INSERT OR IGNORE INTO passive_cache(
                       root_domain, source, names_json, updated_at
                   ) VALUES (?1, ?2, '[]', 0)"#,
                params![domain, source],
            )?;
        }
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn ct_passive_names_bounded(&self, domain: &str, limit: usize) -> Result<Vec<String>> {
        self.ct_passive_names_bounded_until(domain, limit, None)
    }

    pub fn ct_passive_names_bounded_until(
        &self,
        domain: &str,
        limit: usize,
        deadline: Option<Instant>,
    ) -> Result<Vec<String>> {
        let cancellation = AtomicBool::new(false);
        self.ct_passive_names_bounded_until_cancelled(domain, limit, deadline, &cancellation)
    }

    fn ct_passive_names_bounded_until_cancelled(
        &self,
        domain: &str,
        limit: usize,
        deadline: Option<Instant>,
        cancellation: &AtomicBool,
    ) -> Result<Vec<String>> {
        ensure_ct_materialization_active(deadline, cancellation)?;
        let mut selected = Vec::with_capacity(limit.min(100_000));
        let mut seen = BTreeSet::new();
        if limit == 0 {
            return Ok(selected);
        }

        let reversed = reverse_hostname(domain);
        let lower = format!("{reversed}.");
        let upper = format!("{reversed}/");
        let mut ct_cursor = None::<(i64, String)>;
        while selected.len() < limit {
            ensure_ct_materialization_active(deadline, cancellation)?;
            let connection = self.lock_ct_materialization_until(deadline, cancellation)?;
            ensure_ct_materialization_active(deadline, cancellation)?;
            let page = if let Some((last_seen, fqdn)) = &ct_cursor {
                let mut statement = connection.prepare(
                    r#"SELECT fqdn, last_seen FROM ct_names
                       WHERE reversed_name>=?1 AND reversed_name<?2
                         AND (last_seen<?3 OR (last_seen=?3 AND fqdn>?4))
                       ORDER BY last_seen DESC, fqdn ASC LIMIT ?5"#,
                )?;
                statement
                    .query_map(
                        params![
                            lower,
                            upper,
                            last_seen,
                            fqdn,
                            usize_to_i64_saturating(
                                CT_MATERIALIZATION_PAGE_SIZE.min(limit - selected.len())
                            )
                        ],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            } else {
                let mut statement = connection.prepare(
                    r#"SELECT fqdn, last_seen FROM ct_names
                       WHERE reversed_name>=?1 AND reversed_name<?2
                       ORDER BY last_seen DESC, fqdn ASC LIMIT ?3"#,
                )?;
                statement
                    .query_map(
                        params![
                            lower,
                            upper,
                            usize_to_i64_saturating(
                                CT_MATERIALIZATION_PAGE_SIZE.min(limit - selected.len())
                            )
                        ],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            drop(connection);
            ensure_ct_materialization_active(deadline, cancellation)?;
            let Some((last_name, last_seen)) = page.last().cloned() else {
                break;
            };
            ct_cursor = Some((last_seen, last_name));
            for (name, _) in page {
                if let Some(name) = normalize_observed_name(&name, domain)
                    && seen.insert(name.clone())
                {
                    selected.push(name);
                    if selected.len() >= limit {
                        break;
                    }
                }
            }
        }

        if selected.len() < limit {
            let mut observation_cursor = None::<String>;
            while selected.len() < limit {
                ensure_ct_materialization_active(deadline, cancellation)?;
                let connection = self.lock_ct_materialization_until(deadline, cancellation)?;
                ensure_ct_materialization_active(deadline, cancellation)?;
                let mut statement = connection.prepare(
                    r#"SELECT DISTINCT n.fqdn FROM observation_evidence e
                       JOIN observed_names n ON n.id=e.name_id
                       WHERE e.root_domain=?1 AND e.source='passive:ct-direct'
                         AND (?2 IS NULL OR n.fqdn>?2)
                       ORDER BY n.fqdn LIMIT ?3"#,
                )?;
                let page = statement
                    .query_map(
                        params![
                            domain,
                            observation_cursor.as_deref(),
                            usize_to_i64_saturating(CT_MATERIALIZATION_PAGE_SIZE)
                        ],
                        |row| row.get::<_, String>(0),
                    )?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(statement);
                drop(connection);
                ensure_ct_materialization_active(deadline, cancellation)?;
                let Some(last_name) = page.last().cloned() else {
                    break;
                };
                observation_cursor = Some(last_name);
                for name in page {
                    if let Some(name) = normalize_observed_name(&name, domain)
                        && seen.insert(name.clone())
                    {
                        selected.push(name);
                        if selected.len() >= limit {
                            break;
                        }
                    }
                }
            }
        }
        Ok(selected)
    }

    /// Materializes the target-scoped CT index into durable passive evidence
    /// without ever loading the complete historical `ct-direct` cache.
    /// Repeated materialization is idempotent and never refreshes evidence
    /// timestamps or counters that were already present.
    pub fn materialize_ct_passive_cache_bounded(
        &self,
        domain: &str,
        limit: usize,
        complete: bool,
    ) -> Result<Vec<String>> {
        self.materialize_ct_passive_cache_bounded_until(domain, limit, complete, None)
    }

    pub fn materialize_ct_passive_cache_bounded_until(
        &self,
        domain: &str,
        limit: usize,
        complete: bool,
        deadline: Option<Instant>,
    ) -> Result<Vec<String>> {
        self.materialize_ct_passive_cache_bounded_until_cancelled(
            domain,
            limit,
            complete,
            deadline,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub(crate) fn materialize_ct_passive_cache_bounded_until_cancelled(
        &self,
        domain: &str,
        limit: usize,
        complete: bool,
        deadline: Option<Instant>,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Vec<String>> {
        ensure_ct_materialization_active(deadline, &cancellation)?;
        let selected =
            self.ct_passive_names_bounded_until_cancelled(domain, limit, deadline, &cancellation)?;
        let seen = selected.iter().cloned().collect::<BTreeSet<_>>();
        self.store_passive_observation_page_if_absent(
            domain,
            "ct-direct",
            &seen,
            complete,
            deadline,
            &cancellation,
        )?;
        ensure_ct_materialization_active(deadline, &cancellation)?;
        Ok(selected)
    }

    pub fn record_source_result(
        &self,
        source: &str,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
    ) -> Result<()> {
        self.record_source_result_counts(source, None, novel_names, duration_ms, error, None)
    }

    pub fn record_source_result_until(
        &self,
        source: &str,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
        deadline: Instant,
    ) -> Result<()> {
        self.record_source_result_counts(
            source,
            None,
            novel_names,
            duration_ms,
            error,
            Some(deadline),
        )
    }

    pub fn record_source_result_with_counts(
        &self,
        source: &str,
        names: usize,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
    ) -> Result<()> {
        self.record_source_result_counts(source, Some(names), novel_names, duration_ms, error, None)
    }

    pub fn record_source_result_with_counts_until(
        &self,
        source: &str,
        names: usize,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
        deadline: Instant,
    ) -> Result<()> {
        self.record_source_result_counts(
            source,
            Some(names),
            novel_names,
            duration_ms,
            error,
            Some(deadline),
        )
    }

    pub fn record_source_degraded(
        &self,
        source: &str,
        novel_names: usize,
        duration_ms: u128,
        warning: &str,
    ) -> Result<()> {
        self.record_source_outcome_counts(
            source,
            None,
            novel_names,
            duration_ms,
            Some(warning),
            SourceResultStatus::Degraded,
            true,
            None,
        )
    }

    pub fn record_source_degraded_with_counts(
        &self,
        source: &str,
        names: usize,
        novel_names: usize,
        duration_ms: u128,
        warning: &str,
    ) -> Result<()> {
        self.record_source_outcome_counts(
            source,
            Some(names),
            novel_names,
            duration_ms,
            Some(warning),
            SourceResultStatus::Degraded,
            true,
            None,
        )
    }

    pub fn record_source_degraded_with_counts_until(
        &self,
        source: &str,
        names: usize,
        novel_names: usize,
        duration_ms: u128,
        warning: &str,
        deadline: Instant,
    ) -> Result<()> {
        self.record_source_outcome_counts(
            source,
            Some(names),
            novel_names,
            duration_ms,
            Some(warning),
            SourceResultStatus::Degraded,
            true,
            Some(deadline),
        )
    }

    pub fn record_source_deferred(
        &self,
        source: &str,
        duration_ms: u128,
        reason: &str,
    ) -> Result<()> {
        self.record_source_outcome_counts(
            source,
            None,
            0,
            duration_ms,
            Some(reason),
            SourceResultStatus::Deferred,
            false,
            None,
        )
    }

    pub fn record_source_deferred_until(
        &self,
        source: &str,
        duration_ms: u128,
        reason: &str,
        deadline: Instant,
    ) -> Result<()> {
        self.record_source_outcome_counts(
            source,
            None,
            0,
            duration_ms,
            Some(reason),
            SourceResultStatus::Deferred,
            false,
            Some(deadline),
        )
    }

    fn record_source_result_counts(
        &self,
        source: &str,
        names: Option<usize>,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let status = if error.is_some() {
            SourceResultStatus::Failure
        } else {
            SourceResultStatus::Success
        };
        self.record_source_outcome_counts(
            source,
            names,
            novel_names,
            duration_ms,
            error,
            status,
            true,
            deadline,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_source_outcome_counts(
        &self,
        source: &str,
        names: Option<usize>,
        novel_names: usize,
        duration_ms: u128,
        detail: Option<&str>,
        status: SourceResultStatus,
        record_yield_sample: bool,
        deadline: Option<Instant>,
    ) -> Result<()> {
        ensure_passive_persistence_deadline(deadline)?;
        let success = i64::from(status == SourceResultStatus::Success);
        let failure = i64::from(status == SourceResultStatus::Failure);
        let degraded = i64::from(status == SourceResultStatus::Degraded);
        let deferred = i64::from(status == SourceResultStatus::Deferred);
        let duration_ms = duration_ms.min(i64::MAX as u128) as i64;
        let novel_requests = i64::from(record_yield_sample);
        let novel_total_ms = if record_yield_sample { duration_ms } else { 0 };
        let mut connection = self.lock_passive_until(deadline)?;
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"INSERT INTO source_stats(
               source, requests, successes, failures, degraded, deferred,
               consecutive_failures,
               names, novel_names, novel_requests, novel_total_ms,
               total_ms, last_error, last_status, last_used
               ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?3, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
               ON CONFLICT(source) DO UPDATE SET
               requests=CASE WHEN MAX(source_stats.requests, 0)>=9223372036854775807
                   THEN 9223372036854775807 ELSE MAX(source_stats.requests, 0)+1 END,
               successes=CASE
                   WHEN MAX(source_stats.successes, 0)>9223372036854775807-excluded.successes
                   THEN 9223372036854775807
                   ELSE MAX(source_stats.successes, 0)+excluded.successes END,
               failures=CASE
                   WHEN MAX(source_stats.failures, 0)>9223372036854775807-excluded.failures
                   THEN 9223372036854775807
                   ELSE MAX(source_stats.failures, 0)+excluded.failures END,
               degraded=CASE
                   WHEN MAX(source_stats.degraded, 0)>9223372036854775807-excluded.degraded
                   THEN 9223372036854775807
                   ELSE MAX(source_stats.degraded, 0)+excluded.degraded END,
               deferred=CASE
                   WHEN MAX(source_stats.deferred, 0)>9223372036854775807-excluded.deferred
                   THEN 9223372036854775807
                   ELSE MAX(source_stats.deferred, 0)+excluded.deferred END,
               consecutive_failures=CASE excluded.last_status
                   WHEN 'success' THEN 0
                   WHEN 'degraded' THEN 0
                   WHEN 'failure' THEN CASE
                       WHEN MAX(source_stats.consecutive_failures, 0)>=9223372036854775807
                       THEN 9223372036854775807
                       ELSE MAX(source_stats.consecutive_failures, 0)+1 END
                   ELSE MAX(source_stats.consecutive_failures, 0)
               END,
                names=CASE
                    WHEN MAX(source_stats.names, 0)>9223372036854775807-excluded.names
                    THEN 9223372036854775807
                    ELSE MAX(source_stats.names, 0)+excluded.names END,
                novel_names=CASE
                    WHEN MAX(source_stats.novel_names, 0)>9223372036854775807-excluded.novel_names
                    THEN 9223372036854775807
                    ELSE MAX(source_stats.novel_names, 0)+excluded.novel_names END,
                novel_requests=CASE
                    WHEN MAX(source_stats.novel_requests, 0)>9223372036854775807-excluded.novel_requests
                    THEN 9223372036854775807
                    ELSE MAX(source_stats.novel_requests, 0)+excluded.novel_requests END,
                novel_total_ms=CASE
                    WHEN MAX(source_stats.novel_total_ms, 0)>9223372036854775807-excluded.novel_total_ms
                    THEN 9223372036854775807
                    ELSE MAX(source_stats.novel_total_ms, 0)+excluded.novel_total_ms END,
                total_ms=CASE
                    WHEN MAX(source_stats.total_ms, 0)>9223372036854775807-excluded.total_ms
                    THEN 9223372036854775807
                    ELSE MAX(source_stats.total_ms, 0)+excluded.total_ms END,
                last_error=excluded.last_error,
                last_status=excluded.last_status,
                last_used=excluded.last_used"#,
            params![
                source,
                success,
                failure,
                degraded,
                deferred,
                i64::try_from(names.unwrap_or_default()).unwrap_or(i64::MAX),
                i64::try_from(novel_names).unwrap_or(i64::MAX),
                novel_requests,
                novel_total_ms,
                duration_ms,
                detail,
                status.as_str(),
                now_epoch()
            ],
        )?;
        if status == SourceResultStatus::Success {
            transaction.execute(
                "DELETE FROM source_metadata_cache WHERE key=?1",
                [format!("source.retry_until.{source}")],
            )?;
        }
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn source_metadata(
        &self,
        key: &str,
        max_age: std::time::Duration,
    ) -> Result<Option<String>> {
        self.source_metadata_before(key, max_age, None)
    }

    pub fn source_metadata_until(
        &self,
        key: &str,
        max_age: std::time::Duration,
        deadline: Instant,
    ) -> Result<Option<String>> {
        self.source_metadata_before(key, max_age, Some(deadline))
    }

    fn source_metadata_before(
        &self,
        key: &str,
        max_age: std::time::Duration,
        deadline: Option<Instant>,
    ) -> Result<Option<String>> {
        ensure_passive_persistence_deadline(deadline)?;
        let threshold = now_epoch().saturating_sub(max_age.as_secs().min(i64::MAX as u64) as i64);
        let value = self
            .lock_passive_until(deadline)?
            .query_row(
                "SELECT value FROM source_metadata_cache WHERE key=?1 AND updated_at>=?2",
                params![key, threshold],
                |row| row.get(0),
            )
            .optional()
            .map_err(anyhow::Error::from)?;
        ensure_passive_persistence_deadline(deadline)?;
        Ok(value)
    }

    pub fn store_source_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.store_source_metadata_before(key, value, None)
    }

    pub fn store_source_metadata_until(
        &self,
        key: &str,
        value: &str,
        deadline: Instant,
    ) -> Result<()> {
        self.store_source_metadata_before(key, value, Some(deadline))
    }

    fn store_source_metadata_before(
        &self,
        key: &str,
        value: &str,
        deadline: Option<Instant>,
    ) -> Result<()> {
        ensure_passive_persistence_deadline(deadline)?;
        self.lock_passive_until(deadline)?.execute(
            r#"INSERT INTO source_metadata_cache(key, value, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(key) DO UPDATE SET
               value=excluded.value, updated_at=excluded.updated_at"#,
            params![key, value, now_epoch()],
        )?;
        Ok(())
    }

    pub(crate) fn store_source_metadata_until_cancelled(
        &self,
        key: &str,
        value: &str,
        deadline: Option<Instant>,
        cancellation: &AtomicBool,
    ) -> Result<()> {
        ensure_ct_materialization_active(deadline, cancellation)?;
        let mut connection = self.lock_ct_materialization_until(deadline, cancellation)?;
        ensure_ct_materialization_active(deadline, cancellation)?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"INSERT INTO source_metadata_cache(key, value, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(key) DO UPDATE SET
               value=excluded.value, updated_at=excluded.updated_at"#,
            params![key, value, now_epoch()],
        )?;
        ensure_ct_materialization_active(deadline, cancellation)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn source_diagnostics(
        &self,
        cooldown: std::time::Duration,
    ) -> Result<BTreeMap<String, SourceDiagnostic>> {
        self.source_diagnostics_before(cooldown, None)
    }

    pub fn source_diagnostics_until(
        &self,
        cooldown: std::time::Duration,
        deadline: Instant,
    ) -> Result<BTreeMap<String, SourceDiagnostic>> {
        self.source_diagnostics_before(cooldown, Some(deadline))
    }

    fn source_diagnostics_before(
        &self,
        cooldown: std::time::Duration,
        deadline: Option<Instant>,
    ) -> Result<BTreeMap<String, SourceDiagnostic>> {
        ensure_passive_persistence_deadline(deadline)?;
        let now = now_epoch();
        let cooldown_seconds = cooldown.as_secs().min(i64::MAX as u64) as i64;
        let connection = self.lock_passive_until(deadline)?;
        let mut diagnostics = BTreeMap::new();
        {
            let mut statement = connection.prepare(
                r#"SELECT source, requests, successes, failures, degraded, deferred,
                   consecutive_failures, names, novel_names, novel_requests,
                   CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END,
                   last_error, last_status, last_used FROM source_stats ORDER BY source"#,
            )?;
            let mut rows = statement.query([])?;
            let mut index = 0_usize;
            while let Some(row) = rows.next()? {
                if index.is_multiple_of(64) {
                    ensure_passive_persistence_deadline(deadline)?;
                }
                let source = row.get::<_, String>(0)?;
                let consecutive_failures = row.get::<_, i64>(6)?;
                let last_status = row.get::<_, String>(12)?;
                let last_used = row.get::<_, i64>(13)?;
                let retry_at = last_used.saturating_add(cooldown_seconds);
                let next_retry =
                    (consecutive_failures >= 3 && last_status == "failure" && retry_at > now)
                        .then_some(retry_at);
                diagnostics.insert(
                    source,
                    SourceDiagnostic {
                        requests: row.get(1)?,
                        successes: row.get(2)?,
                        failures: row.get(3)?,
                        degraded: row.get(4)?,
                        deferred: row.get(5)?,
                        consecutive_failures,
                        names: row.get(7)?,
                        novel_names: row.get(8)?,
                        novel_requests: row.get(9)?,
                        average_ms: row.get(10)?,
                        last_error: row.get(11)?,
                        last_status,
                        last_used,
                        next_retry,
                        retry_in_seconds: next_retry.map(|retry| retry.saturating_sub(now)),
                    },
                );
                index = index.saturating_add(1);
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT key, value FROM source_metadata_cache WHERE key LIKE 'source.retry_until.%'",
            )?;
            let mut rows = statement.query([])?;
            let mut index = 0_usize;
            while let Some(row) = rows.next()? {
                if index.is_multiple_of(64) {
                    ensure_passive_persistence_deadline(deadline)?;
                }
                let key = row.get::<_, String>(0)?;
                let value = row.get::<_, String>(1)?;
                let Some(source) = key.strip_prefix("source.retry_until.") else {
                    index = index.saturating_add(1);
                    continue;
                };
                let Some(retry_until) = value.parse::<i64>().ok().filter(|retry| *retry > now)
                else {
                    index = index.saturating_add(1);
                    continue;
                };
                if let Some(diagnostic) = diagnostics.get_mut(source) {
                    diagnostic.next_retry = Some(
                        diagnostic
                            .next_retry
                            .map_or(retry_until, |current| current.max(retry_until)),
                    );
                    diagnostic.retry_in_seconds =
                        diagnostic.next_retry.map(|retry| retry.saturating_sub(now));
                }
                index = index.saturating_add(1);
            }
        }
        ensure_passive_persistence_deadline(deadline)?;
        Ok(diagnostics)
    }

    pub fn source_cooldowns(&self, cooldown: std::time::Duration) -> Result<BTreeSet<String>> {
        self.source_cooldowns_before(cooldown, None)
    }

    pub fn source_cooldowns_until(
        &self,
        cooldown: std::time::Duration,
        deadline: Instant,
    ) -> Result<BTreeSet<String>> {
        self.source_cooldowns_before(cooldown, Some(deadline))
    }

    fn source_cooldowns_before(
        &self,
        cooldown: std::time::Duration,
        deadline: Option<Instant>,
    ) -> Result<BTreeSet<String>> {
        ensure_passive_persistence_deadline(deadline)?;
        let threshold = now_epoch().saturating_sub(cooldown.as_secs().min(i64::MAX as u64) as i64);
        let connection = self.lock_passive_until(deadline)?;
        let mut statement = connection.prepare(
            r#"SELECT source FROM source_stats
               WHERE consecutive_failures>=3
                 AND last_status='failure'
                  AND last_used>=?1"#,
        )?;
        let mut rows = statement.query([threshold])?;
        let mut sources = BTreeSet::new();
        while let Some(row) = rows.next()? {
            if sources.len().is_multiple_of(64) {
                ensure_passive_persistence_deadline(deadline)?;
            }
            sources.insert(row.get::<_, String>(0)?);
        }
        ensure_passive_persistence_deadline(deadline)?;
        Ok(sources)
    }

    pub fn source_scores(&self) -> Result<HashMap<String, i64>> {
        self.source_scores_before(None)
    }

    pub fn source_scores_until(&self, deadline: Instant) -> Result<HashMap<String, i64>> {
        self.source_scores_before(Some(deadline))
    }

    fn source_scores_before(&self, deadline: Option<Instant>) -> Result<HashMap<String, i64>> {
        ensure_passive_persistence_deadline(deadline)?;
        let connection = self.lock_passive_until(deadline)?;
        let mut statement = connection.prepare(
            r#"SELECT source,
               CASE WHEN successes+failures+degraded=0 THEN 0 ELSE
                   CAST((successes * 400 + degraded * 250)
                        / (successes+failures+degraded) AS INTEGER) END
               + CASE WHEN novel_requests=0 THEN 0 ELSE
                   MIN(CAST(novel_names * 60 / novel_requests AS INTEGER), 600) END
               + CASE WHEN novel_requests=0 THEN 0 ELSE
                   MIN(CAST(novel_names * 100000 / MAX(novel_total_ms, 1) AS INTEGER), 500) END
               - MIN(CAST(total_ms / MAX(requests, 1) / 100 AS INTEGER), 300)
               - MIN(consecutive_failures * 250, 1000)
               - CASE WHEN novel_requests>0 AND novel_names=0 THEN 400 ELSE 0 END
               AS score
               FROM source_stats"#,
        )?;
        let mut rows = statement.query([])?;
        let mut scores = HashMap::new();
        while let Some(row) = rows.next()? {
            if scores.len().is_multiple_of(64) {
                ensure_passive_persistence_deadline(deadline)?;
            }
            scores.insert(row.get::<_, String>(0)?, row.get::<_, i64>(1)?);
        }
        ensure_passive_persistence_deadline(deadline)?;
        Ok(scores)
    }
}

fn extend_legacy_passive_names_bounded(
    names_json: &str,
    names: &mut BTreeSet<String>,
    limit: usize,
    deadline: Option<Instant>,
) -> Result<()> {
    if names.len() >= limit {
        return Ok(());
    }
    let bytes = names_json.as_bytes();
    let mut cursor = 0_usize;
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor = cursor.saturating_add(1);
    }
    if bytes.get(cursor) != Some(&b'[') {
        bail!("cache passif legacy invalide: tableau JSON attendu");
    }
    cursor = cursor.saturating_add(1);
    loop {
        ensure_passive_persistence_deadline(deadline)?;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor) == Some(&b']') {
            return Ok(());
        }
        if bytes.get(cursor) != Some(&b'\"') {
            bail!("cache passif legacy invalide: chaîne JSON attendue");
        }
        let string_start = cursor;
        cursor = cursor.saturating_add(1);
        let mut escaped = false;
        loop {
            if cursor.is_multiple_of(4_096) {
                ensure_passive_persistence_deadline(deadline)?;
            }
            let Some(byte) = bytes.get(cursor).copied() else {
                bail!("cache passif legacy invalide: chaîne JSON incomplète");
            };
            cursor = cursor.saturating_add(1);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'\"' {
                break;
            }
        }
        names.insert(serde_json::from_str::<String>(
            &names_json[string_start..cursor],
        )?);
        if names.len() >= limit {
            return Ok(());
        }
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor = cursor.saturating_add(1);
        }
        match bytes.get(cursor) {
            Some(b',') => cursor = cursor.saturating_add(1),
            Some(b']') => return Ok(()),
            _ => bail!("cache passif legacy invalide: séparateur JSON attendu"),
        }
    }
}
