use super::*;

impl Database {
    pub fn tls_cache(
        &self,
        domain: &str,
        endpoint: &str,
        port: u16,
    ) -> Result<Option<TlsCacheEntry>> {
        let connection = self.lock()?;
        let row: Option<(String, String, i64)> = connection
            .query_row(
                r#"SELECT fingerprint_sha256, names_json, updated_at
                   FROM tls_certificate_cache
                   WHERE root_domain=?1 AND endpoint=?2 AND port=?3"#,
                params![domain, endpoint, i64::from(port)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        drop(connection);
        row.map(|(fingerprint_sha256, names_json, updated_at)| {
            let names = serde_json::from_str::<Vec<String>>(&names_json)?;
            Ok(TlsCacheEntry {
                fingerprint_sha256,
                names,
                updated_at,
            })
        })
        .transpose()
    }

    pub fn store_tls_cache(
        &self,
        domain: &str,
        endpoint: &str,
        port: u16,
        fingerprint_sha256: &str,
        names: &BTreeSet<String>,
    ) -> Result<TlsCacheEntry> {
        let source = format!("tls:{endpoint}:{port}");
        self.store_observations(
            domain,
            names
                .iter()
                .map(|fqdn| ObservationInput {
                    fqdn: fqdn.clone(),
                    kind: "tls".to_owned(),
                    source: source.clone(),
                    value: fingerprint_sha256.to_owned(),
                })
                .collect(),
        )?;
        let connection = self.lock()?;
        let current_names = names.iter().cloned().collect::<Vec<_>>();
        let names_json = serde_json::to_string(&current_names)?;
        let updated_at = now_epoch();
        connection.execute(
            r#"INSERT INTO tls_certificate_cache(
               root_domain, endpoint, port, fingerprint_sha256, names_json, updated_at
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(root_domain, endpoint, port) DO UPDATE SET
               fingerprint_sha256=excluded.fingerprint_sha256,
               names_json=excluded.names_json,
               updated_at=excluded.updated_at"#,
            params![
                domain,
                endpoint,
                i64::from(port),
                fingerprint_sha256,
                names_json,
                updated_at
            ],
        )?;
        drop(connection);
        Ok(TlsCacheEntry {
            fingerprint_sha256: fingerprint_sha256.to_owned(),
            names: current_names,
            updated_at,
        })
    }

    pub fn web_cache(&self, domain: &str, url: &str) -> Result<Option<WebCacheEntry>> {
        let connection = self.lock()?;
        let row: Option<WebCacheRow> = connection
            .query_row(
                r#"SELECT status, names_json, assets_json, updated_at, etag, last_modified, content_hash
                   FROM web_discovery_cache
                   WHERE root_domain=?1 AND url=?2"#,
                params![domain, url],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        drop(connection);
        row.map(
            |(status, names_json, assets_json, updated_at, etag, last_modified, content_hash)| {
                let names = serde_json::from_str::<Vec<String>>(&names_json)?;
                let assets = serde_json::from_str::<Vec<String>>(&assets_json)?;
                Ok(WebCacheEntry {
                    status: u16::try_from(status).unwrap_or_default(),
                    names,
                    assets,
                    updated_at,
                    etag,
                    last_modified,
                    content_hash,
                })
            },
        )
        .transpose()
    }

    pub fn store_web_cache(
        &self,
        domain: &str,
        url: &str,
        status: u16,
        names: &BTreeSet<String>,
        assets: &[String],
        metadata: &WebCacheMetadata,
    ) -> Result<WebCacheEntry> {
        self.store_observations(
            domain,
            names
                .iter()
                .map(|fqdn| ObservationInput {
                    fqdn: fqdn.clone(),
                    kind: "web".to_owned(),
                    source: format!("web:{url}"),
                    value: metadata.content_hash.clone().unwrap_or_default(),
                })
                .collect(),
        )?;
        let connection = self.lock()?;
        let current_names = names.iter().cloned().collect::<Vec<_>>();
        let names_json = serde_json::to_string(&current_names)?;
        let assets = assets.iter().cloned().collect::<BTreeSet<_>>();
        let assets = assets.into_iter().collect::<Vec<_>>();
        let assets_json = serde_json::to_string(&assets)?;
        let updated_at = now_epoch();
        connection.execute(
            r#"INSERT INTO web_discovery_cache(
               root_domain, url, status, names_json, updated_at,
               etag, last_modified, content_hash, assets_json
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
               ON CONFLICT(root_domain, url) DO UPDATE SET
               status=excluded.status, names_json=excluded.names_json,
               assets_json=excluded.assets_json,
               updated_at=excluded.updated_at,
               etag=excluded.etag,
               last_modified=excluded.last_modified,
               content_hash=excluded.content_hash"#,
            params![
                domain,
                url,
                i64::from(status),
                names_json,
                updated_at,
                metadata.etag.as_deref(),
                metadata.last_modified.as_deref(),
                metadata.content_hash.as_deref(),
                assets_json
            ],
        )?;
        drop(connection);
        Ok(WebCacheEntry {
            status,
            names: current_names,
            assets,
            updated_at,
            etag: metadata.etag.clone(),
            last_modified: metadata.last_modified.clone(),
            content_hash: metadata.content_hash.clone(),
        })
    }

    pub fn dnssec_cache(&self, domain: &str, zone: &str) -> Result<Option<DnssecCacheEntry>> {
        let connection = self.lock()?;
        let row: Option<(String, String, String, i64)> = connection
            .query_row(
                r#"SELECT nameserver, status, names_json, updated_at
                   FROM dnssec_walk_cache WHERE root_domain=?1 AND zone=?2"#,
                params![domain, zone],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        drop(connection);
        row.map(|(nameserver, status, names_json, updated_at)| {
            let names = serde_json::from_str::<Vec<String>>(&names_json)?
                .into_iter()
                .chain(self.observation_names(domain, &format!("dnssec:{zone}"))?)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            Ok(DnssecCacheEntry {
                nameserver,
                status,
                names,
                updated_at,
            })
        })
        .transpose()
    }

    pub fn store_dnssec_cache(
        &self,
        domain: &str,
        zone: &str,
        nameserver: &str,
        status: &str,
        names: &BTreeSet<String>,
    ) -> Result<DnssecCacheEntry> {
        let source = format!("dnssec:{zone}");
        self.store_observations(
            domain,
            names
                .iter()
                .map(|fqdn| ObservationInput {
                    fqdn: fqdn.clone(),
                    kind: "dnssec".to_owned(),
                    source: source.clone(),
                    value: status.to_owned(),
                })
                .collect(),
        )?;
        let connection = self.lock()?;
        let existing: Option<String> = connection
            .query_row(
                r#"SELECT names_json FROM dnssec_walk_cache
                   WHERE root_domain=?1 AND zone=?2"#,
                params![domain, zone],
                |row| row.get(0),
            )
            .optional()?;
        let legacy = existing
            .as_deref()
            .map(serde_json::from_str::<Vec<String>>)
            .transpose()?
            .unwrap_or_default();
        let updated_at = now_epoch();
        connection.execute(
            r#"INSERT INTO dnssec_walk_cache(
               root_domain, zone, nameserver, status, names_json, updated_at
               ) VALUES (?1, ?2, ?3, ?4, '[]', ?5)
               ON CONFLICT(root_domain, zone) DO UPDATE SET
               nameserver=excluded.nameserver, status=excluded.status,
               updated_at=excluded.updated_at"#,
            params![domain, zone, nameserver, status, updated_at],
        )?;
        drop(connection);
        let merged = legacy
            .into_iter()
            .chain(self.observation_names(domain, &source)?)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(DnssecCacheEntry {
            nameserver: nameserver.to_owned(),
            status: status.to_owned(),
            names: merged,
            updated_at,
        })
    }

    pub fn ct_global_cursor(&self, log_url: &str) -> Result<Option<u64>> {
        let connection = self.lock()?;
        let cursor = connection
            .query_row(
                "SELECT next_index FROM ct_global_state WHERE log_url=?1",
                [log_url],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(cursor.map(|value| value.max(0) as u64))
    }

    pub fn ct_global_states(&self) -> Result<HashMap<String, (u64, i64)>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT log_url, next_index, updated_at FROM ct_global_state ORDER BY log_url",
        )?;
        Ok(statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (row.get::<_, i64>(1)?.max(0) as u64, row.get::<_, i64>(2)?),
                ))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()?)
    }

    /// Returns an immutable Static CT data tile only when it was committed
    /// under the exact checkpoint currently being processed.  The caller also
    /// rechecks `content_hash` before parsing, so local corruption falls back
    /// to a bounded network fetch instead of poisoning the durable cursor.
    pub fn ct_static_tile(
        &self,
        log_url: &str,
        tile_path: &str,
        checkpoint_size: u64,
        checkpoint_hash: &str,
    ) -> Result<Option<(String, Vec<u8>)>> {
        let connection = self.lock()?;
        connection
            .query_row(
                r#"SELECT content_hash, payload FROM ct_tiles
                   WHERE log_url=?1 AND tile_path=?2
                     AND checkpoint_size=?3 AND checkpoint_hash=?4"#,
                params![
                    log_url,
                    tile_path,
                    checkpoint_size.min(i64::MAX as u64) as i64,
                    checkpoint_hash
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Atomically commits a completely parsed Static CT delta: immutable tile
    /// payloads, extracted names and the next cursor become visible together.
    /// Any conflicting tile or SQLite error rolls the whole batch back, so the
    /// cursor is replayed on the next run.
    pub fn store_ct_static_batch(
        &self,
        log_url: &str,
        batch: &crate::ct_static::StaticCtBatch,
    ) -> Result<()> {
        let cancellation = AtomicBool::new(false);
        self.store_ct_static_batch_until_cancelled(log_url, batch, None, &cancellation)
    }

    pub(crate) fn store_ct_static_batch_until_cancelled(
        &self,
        log_url: &str,
        batch: &crate::ct_static::StaticCtBatch,
        deadline: Option<Instant>,
        cancellation: &AtomicBool,
    ) -> Result<()> {
        ensure_ct_materialization_active(deadline, cancellation)?;
        if batch.next_cursor > batch.checkpoint_size {
            bail!(
                "curseur CT statique {} supérieur au checkpoint {}",
                batch.next_cursor,
                batch.checkpoint_size
            );
        }
        if batch.checkpoint_hash.is_empty() {
            bail!("hash de checkpoint CT statique absent");
        }

        // Validate and hash potentially large immutable tiles before owning the
        // shared SQLite mutex.  Chunking keeps both the phase deadline and an
        // aborted async caller observable throughout this CPU-bound work.
        for tile in &batch.tiles {
            ensure_ct_materialization_active(deadline, cancellation)?;
            if tile.path.is_empty()
                || tile.checkpoint_size != batch.checkpoint_size
                || tile.checkpoint_hash != batch.checkpoint_hash
            {
                bail!("métadonnées de tuile CT statique incohérentes");
            }
            let computed_hash =
                ct_payload_sha256_until_cancelled(&tile.payload, deadline, cancellation)?;
            if computed_hash != tile.content_hash {
                bail!("hash de contenu invalide pour la tuile CT {}", tile.path);
            }
        }

        ensure_ct_materialization_active(deadline, cancellation)?;
        let now = now_epoch();
        let mut connection = self.lock_ct_materialization_until(deadline, cancellation)?;
        ensure_ct_materialization_active(deadline, cancellation)?;
        with_ct_commit_busy_timeout(&mut connection, deadline, |connection| {
            let transaction = connection.transaction()?;

            for tile in &batch.tiles {
                ensure_ct_materialization_active(deadline, cancellation)?;
                let existing = transaction
                    .query_row(
                        r#"SELECT content_hash, payload FROM ct_tiles
                       WHERE log_url=?1 AND tile_path=?2"#,
                        params![log_url, tile.path],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
                    )
                    .optional()?;
                ensure_ct_materialization_active(deadline, cancellation)?;
                if existing.as_ref().is_some_and(|(hash, payload)| {
                    hash != &tile.content_hash || payload != &tile.payload
                }) {
                    bail!("le journal CT a modifié la tuile immuable {}", tile.path);
                }
                transaction.execute(
                    r#"INSERT INTO ct_tiles(
                       log_url, tile_path, checkpoint_size, checkpoint_hash,
                       content_hash, payload, verified, updated_at
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)
                   ON CONFLICT(log_url, tile_path) DO UPDATE SET
                       checkpoint_size=excluded.checkpoint_size,
                       checkpoint_hash=excluded.checkpoint_hash,
                       updated_at=excluded.updated_at"#,
                    params![
                        log_url,
                        tile.path,
                        tile.checkpoint_size.min(i64::MAX as u64) as i64,
                        tile.checkpoint_hash,
                        tile.content_hash,
                        tile.payload,
                        now
                    ],
                )?;
            }

            {
                let mut insert_name = transaction.prepare(
                    r#"INSERT INTO ct_names(
                       fqdn, reversed_name, first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?3, 1)
                   ON CONFLICT(fqdn) DO UPDATE SET
                       last_seen=excluded.last_seen, times_seen=ct_names.times_seen+1"#,
                )?;
                for (index, name) in batch.names.iter().enumerate() {
                    if index % 32 == 0 {
                        ensure_ct_materialization_active(deadline, cancellation)?;
                    }
                    insert_name.execute(params![name, reverse_hostname(name), now])?;
                }
            }
            ensure_ct_materialization_active(deadline, cancellation)?;
            transaction.execute(
                r#"INSERT INTO ct_global_state(log_url, next_index, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(log_url) DO UPDATE SET
               next_index=CASE WHEN ?4<>0 THEN excluded.next_index
                               ELSE MAX(ct_global_state.next_index, excluded.next_index) END,
               updated_at=excluded.updated_at"#,
                params![
                    log_url,
                    batch.next_cursor.min(i64::MAX as u64) as i64,
                    now,
                    batch.reset_cursor as i64
                ],
            )?;
            ensure_ct_materialization_active(deadline, cancellation)?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn reset_ct_global_cursor(&self, log_url: &str, next: u64) -> Result<()> {
        self.lock()?.execute(
            r#"INSERT INTO ct_global_state(log_url, next_index, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(log_url) DO UPDATE SET
               next_index=excluded.next_index, updated_at=excluded.updated_at"#,
            params![log_url, next.min(i64::MAX as u64) as i64, now_epoch()],
        )?;
        Ok(())
    }

    pub fn store_ct_global_batch(
        &self,
        log_url: &str,
        next: u64,
        names: &BTreeSet<String>,
    ) -> Result<()> {
        let cancellation = AtomicBool::new(false);
        self.store_ct_global_batch_until_cancelled(log_url, next, names, None, &cancellation)
    }

    pub(crate) fn store_ct_global_batch_until_cancelled(
        &self,
        log_url: &str,
        next: u64,
        names: &BTreeSet<String>,
        deadline: Option<Instant>,
        cancellation: &AtomicBool,
    ) -> Result<()> {
        ensure_ct_materialization_active(deadline, cancellation)?;
        let now = now_epoch();
        let mut connection = self.lock_ct_materialization_until(deadline, cancellation)?;
        ensure_ct_materialization_active(deadline, cancellation)?;
        with_ct_commit_busy_timeout(&mut connection, deadline, |connection| {
            let transaction = connection.transaction()?;
            {
                let mut insert_name = transaction.prepare(
                    r#"INSERT INTO ct_names(
                   fqdn, reversed_name, first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?3, 1)
                   ON CONFLICT(fqdn) DO UPDATE SET
                   last_seen=excluded.last_seen, times_seen=ct_names.times_seen+1"#,
                )?;
                for (index, name) in names.iter().enumerate() {
                    if index % 32 == 0 {
                        ensure_ct_materialization_active(deadline, cancellation)?;
                    }
                    insert_name.execute(params![name, reverse_hostname(name), now])?;
                }
            }
            ensure_ct_materialization_active(deadline, cancellation)?;
            transaction.execute(
                r#"INSERT INTO ct_global_state(log_url, next_index, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(log_url) DO UPDATE SET
               next_index=MAX(ct_global_state.next_index, excluded.next_index),
               updated_at=excluded.updated_at"#,
                params![log_url, next.min(i64::MAX as u64) as i64, now],
            )?;
            ensure_ct_materialization_active(deadline, cancellation)?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn ct_names_for_domain(&self, domain: &str, limit: usize) -> Result<Vec<String>> {
        let reversed = reverse_hostname(domain);
        let lower = format!("{reversed}.");
        let upper = format!("{reversed}/");
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT fqdn FROM ct_names
               WHERE reversed_name>=?1 AND reversed_name<?2
               ORDER BY last_seen DESC, fqdn ASC LIMIT ?3"#,
        )?;
        statement
            .query_map(
                params![lower, upper, limit.min(i64::MAX as usize) as i64],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn store_pipeline_metrics(
        &self,
        scan_id: i64,
        metrics: &crate::model::PipelineMetrics,
    ) -> Result<()> {
        self.lock()?.execute(
            r#"INSERT OR REPLACE INTO scan_pipeline_metrics(
               scan_id, rounds, events_enqueued, duplicates_suppressed,
               names_validated, budget_exhausted
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                scan_id,
                metrics.rounds as i64,
                metrics.events_enqueued as i64,
                metrics.duplicates_suppressed as i64,
                metrics.names_validated as i64,
                i64::from(metrics.budget_exhausted)
            ],
        )?;
        Ok(())
    }

    pub fn ip_hostname_cache(
        &self,
        provider: &str,
        address: IpAddr,
        limit: usize,
    ) -> Result<Option<IpHostnameCacheEntry>> {
        validate_ip_hostname_provider(provider)?;
        let address = address.to_string();
        let connection = self.lock()?;
        let refresh = connection
            .query_row(
                r#"SELECT last_success_at, last_attempt_at, status
                   FROM ip_hostname_refresh
                   WHERE provider=?1 AND address=?2"#,
                params![provider, address],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((last_success_at, last_attempt_at, status)) = refresh else {
            return Ok(None);
        };
        let mut statement = connection.prepare(
            r#"SELECT hostname FROM ip_hostname_observations
               WHERE provider=?1 AND address=?2
               ORDER BY last_seen DESC, hostname ASC LIMIT ?3"#,
        )?;
        let hostnames = statement
            .query_map(
                params![
                    provider,
                    address,
                    limit.min(MAX_IP_HOSTNAME_CACHE_NAMES) as i64
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<BTreeSet<_>>>()?;
        Ok(Some(IpHostnameCacheEntry {
            hostnames,
            last_success_at,
            last_attempt_at,
            status,
        }))
    }

    pub fn store_ip_hostname_success(
        &self,
        provider: &str,
        address: IpAddr,
        hostnames: &BTreeSet<String>,
    ) -> Result<()> {
        validate_ip_hostname_provider(provider)?;
        let address = address.to_string();
        let hostnames = hostnames
            .iter()
            .filter_map(|hostname| normalize_hostname(hostname))
            .take(MAX_IP_HOSTNAME_CACHE_NAMES)
            .collect::<BTreeSet<_>>();
        let status = if hostnames.is_empty() {
            "empty"
        } else {
            "success"
        };
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                r#"INSERT INTO ip_hostname_observations(
                       provider, address, hostname, first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?4, ?4, 1)
                   ON CONFLICT(provider, address, hostname) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       times_seen=ip_hostname_observations.times_seen+1"#,
            )?;
            for hostname in &hostnames {
                statement.execute(params![provider, address, hostname, now])?;
            }
        }
        transaction.execute(
            r#"INSERT INTO ip_hostname_refresh(
                   provider, address, last_success_at, last_attempt_at, status, last_error
               ) VALUES (?1, ?2, ?3, ?3, ?4, NULL)
               ON CONFLICT(provider, address) DO UPDATE SET
                   last_success_at=excluded.last_success_at,
                   last_attempt_at=excluded.last_attempt_at,
                   status=excluded.status,
                   last_error=NULL"#,
            params![provider, address, now, status],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn store_ip_hostname_failure(
        &self,
        provider: &str,
        address: IpAddr,
        error: &str,
    ) -> Result<()> {
        validate_ip_hostname_provider(provider)?;
        let address = address.to_string();
        let now = now_epoch();
        let error = error.chars().take(1_024).collect::<String>();
        self.lock()?.execute(
            r#"INSERT INTO ip_hostname_refresh(
                   provider, address, last_success_at, last_attempt_at, status, last_error
               ) VALUES (?1, ?2, 0, ?3, 'error', ?4)
               ON CONFLICT(provider, address) DO UPDATE SET
                   last_attempt_at=excluded.last_attempt_at,
                   status='error',
                   last_error=excluded.last_error"#,
            params![provider, address, now, error],
        )?;
        Ok(())
    }

    pub fn store_discovery_graph(
        &self,
        domain: &str,
        edges: &BTreeSet<DiscoveryEdge>,
        services: &BTreeSet<ServiceEndpoint>,
        child_zones: &BTreeSet<String>,
    ) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for edge in edges {
            transaction.execute(
                r#"INSERT INTO discovery_edges(
                   root_domain, owner, record_type, value, target,
                   first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
                   ON CONFLICT(root_domain, owner, record_type, value, target)
                   DO UPDATE SET last_seen=excluded.last_seen,
                                 times_seen=discovery_edges.times_seen+1"#,
                params![
                    domain,
                    edge.owner,
                    edge.record_type,
                    edge.value,
                    edge.target.as_deref().unwrap_or_default(),
                    now
                ],
            )?;
        }
        for service in services {
            transaction.execute(
                r#"INSERT INTO service_endpoints(
                   root_domain, hostname, port, transport, source,
                   first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
                   ON CONFLICT(root_domain, hostname, port, transport, source)
                   DO UPDATE SET last_seen=excluded.last_seen,
                                 times_seen=service_endpoints.times_seen+1"#,
                params![
                    domain,
                    service.hostname,
                    i64::from(service.port),
                    service.transport,
                    service.source,
                    now
                ],
            )?;
        }
        for zone in child_zones {
            transaction.execute(
                r#"INSERT INTO child_zones(
                   root_domain, zone, first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?3, 1)
                   ON CONFLICT(root_domain, zone)
                   DO UPDATE SET last_seen=excluded.last_seen,
                                 times_seen=child_zones.times_seen+1"#,
                params![domain, zone, now],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn save_axfr_attempts(&self, scan_id: i64, attempts: &[AxfrAttempt]) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        // A resumed scan reruns AXFR because the previous phase may have been
        // interrupted at any point. Replace that scan's snapshot atomically so
        // retries do not inflate success/error counts with duplicate attempts.
        transaction.execute("DELETE FROM axfr_attempts WHERE scan_id=?1", [scan_id])?;
        for attempt in attempts {
            transaction.execute(
                r#"INSERT INTO axfr_attempts(
                   scan_id, nameserver, address, status, error, record_count, attempted_at
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                params![
                    scan_id,
                    attempt.nameserver,
                    attempt.address,
                    attempt.status.as_str(),
                    attempt.error,
                    attempt.records.len() as i64,
                    now
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}
