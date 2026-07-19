use super::*;

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        prepare_private_database_storage(path)?;
        let connection = Connection::open(path)
            .with_context(|| format!("ouverture de SQLite {}", path.display()))?;
        secure_existing_sqlite_files(path)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > 9 {
            bail!("base SQLite version {version} plus récente que cette version de Fellaga (v9)");
        }
        // Some pre-versioned Fellaga databases contain real user tables while
        // still reporting user_version=0.  They need the same safety backup as
        // numbered legacy databases; a genuinely empty/new file does not.
        let contains_legacy_schema = version == 0
            && connection.query_row(
                r#"SELECT EXISTS(
                       SELECT 1 FROM sqlite_schema
                       WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
                   )"#,
                [],
                |row| row.get::<_, i64>(0),
            )? != 0;
        if (1..9).contains(&version) || contains_legacy_schema {
            let backup = if version < 8 {
                next_v8_backup_path(path)?
            } else {
                next_v9_backup_path(path)?
            };
            if let Err(error) =
                connection.execute("VACUUM INTO ?1", [backup.to_string_lossy().as_ref()])
            {
                // next_schema_backup_path reserved this exact empty file. Do
                // not leave an empty artifact that looks like a valid backup.
                let _ = std::fs::remove_file(&backup);
                return Err(error).with_context(|| {
                    format!(
                        "sauvegarde SQLite pré-migration de {} vers {}",
                        path.display(),
                        backup.display()
                    )
                });
            }
            secure_existing_sqlite_files(&backup)?;
        }
        Self::from_connection(path.to_path_buf(), connection)
    }

    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        Self::from_connection(PathBuf::from(":memory:"), Connection::open_in_memory()?)
    }

    fn from_connection(path: PathBuf, mut connection: Connection) -> Result<Self> {
        let starting_version: i64 =
            connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if starting_version > 9 {
            bail!(
                "base SQLite version {starting_version} plus récente que cette version de Fellaga (v9)"
            );
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        if path != Path::new(":memory:") {
            secure_existing_sqlite_files(&path)?;
        }
        let migrating_to_v8 = starting_version < 8;
        let migrating_to_v9 = starting_version < 9;
        // Version upgrades and same-version additive repairs are one atomic
        // unit. A failed compatible migration must never leave half-created
        // tables or indexes behind for the next launch.
        connection.execute_batch("BEGIN IMMEDIATE")?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                status TEXT NOT NULL,
                candidates INTEGER NOT NULL DEFAULT 0,
                found INTEGER NOT NULL DEFAULT 0,
                cache_hits INTEGER NOT NULL DEFAULT 0,
                duration_ms INTEGER NOT NULL DEFAULT 0,
                options_json TEXT NOT NULL,
                warnings_json TEXT NOT NULL DEFAULT '[]',
                learning_applied INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                fqdn TEXT PRIMARY KEY,
                root_domain TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                first_scan_id INTEGER REFERENCES scans(id),
                last_scan_id INTEGER REFERENCES scans(id),
                times_seen INTEGER NOT NULL DEFAULT 1,
                active INTEGER NOT NULL DEFAULT 1,
                sources TEXT NOT NULL,
                verification_state TEXT NOT NULL DEFAULT 'live'
                    CHECK(verification_state IN ('live', 'historical', 'unverified')),
                last_verified_at INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_subdomains_root ON subdomains(root_domain, active);

            CREATE TABLE IF NOT EXISTS dns_records (
                fqdn TEXT NOT NULL REFERENCES subdomains(fqdn) ON DELETE CASCADE,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(fqdn, record_type, value)
            );

            CREATE TABLE IF NOT EXISTS scan_findings (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT NOT NULL REFERENCES subdomains(fqdn) ON DELETE CASCADE,
                wildcard INTEGER NOT NULL DEFAULT 0,
                from_cache INTEGER NOT NULL DEFAULT 0,
                confidence_score INTEGER NOT NULL DEFAULT 0,
                confidence_label TEXT NOT NULL DEFAULT 'faible',
                confidence_reasons_json TEXT NOT NULL DEFAULT '[]',
                state TEXT NOT NULL DEFAULT 'unverified'
                    CHECK(state IN ('live', 'historical', 'unverified')),
                last_verified_at INTEGER,
                evidence_families_json TEXT NOT NULL DEFAULT '[]',
                authoritative_validation INTEGER NOT NULL DEFAULT 0,
                wildcard_verdict TEXT NOT NULL DEFAULT 'not_profiled'
                    CHECK(wildcard_verdict IN ('exact_owner', 'synthesized', 'ambiguous', 'not_profiled')),
                owner_proofs_json TEXT NOT NULL DEFAULT '[]',
                generation_path_json TEXT NOT NULL DEFAULT '[]',
                discovery_score REAL,
                PRIMARY KEY(scan_id, fqdn)
            );

            CREATE TABLE IF NOT EXISTS dns_cache (
                fqdn TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK(status IN ('positive', 'negative')),
                records_json TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                last_checked INTEGER NOT NULL,
                resolver_count INTEGER NOT NULL DEFAULT 1,
                authoritative INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_cache_expiry ON dns_cache(expires_at);

            CREATE TABLE IF NOT EXISTS dns_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                fqdn TEXT NOT NULL,
                checked_at INTEGER NOT NULL,
                outcome TEXT NOT NULL
                    CHECK(outcome IN ('live', 'historical', 'unverified', 'negative', 'error')),
                resolver_count INTEGER NOT NULL DEFAULT 0,
                authoritative INTEGER NOT NULL DEFAULT 0,
                records_hash TEXT,
                latency_ms INTEGER,
                details_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_dns_verifications_name
                ON dns_verifications(fqdn, checked_at DESC);
            CREATE INDEX IF NOT EXISTS idx_dns_verifications_scan
                ON dns_verifications(scan_id, checked_at);
            CREATE TRIGGER IF NOT EXISTS dns_verifications_no_update
                BEFORE UPDATE ON dns_verifications
                BEGIN SELECT RAISE(ABORT, 'dns_verifications is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS dns_verifications_no_delete
                BEFORE DELETE ON dns_verifications
                BEGIN SELECT RAISE(ABORT, 'dns_verifications is append-only'); END;

            CREATE TABLE IF NOT EXISTS scan_checkpoints (
                scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                domain TEXT NOT NULL,
                stage TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_scan_checkpoints_latest
                ON scan_checkpoints(domain, completed, updated_at DESC);

            CREATE TABLE IF NOT EXISTS refresh_wildcard_candidates (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT NOT NULL,
                PRIMARY KEY(scan_id, fqdn)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS refresh_wildcard_affected_scans (
                refresh_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                affected_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                PRIMARY KEY(refresh_scan_id, affected_scan_id)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS wildcard_quarantine (
                root_domain TEXT NOT NULL,
                fqdn TEXT NOT NULL,
                scan_id INTEGER NOT NULL REFERENCES scans(id),
                reason TEXT NOT NULL,
                quarantined_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, fqdn)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_wildcard_quarantine_scan
                ON wildcard_quarantine(scan_id, quarantined_at);

            CREATE TABLE IF NOT EXISTS scan_candidates (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT NOT NULL,
                relative_name TEXT NOT NULL,
                priority INTEGER NOT NULL,
                generator TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                learning_recorded INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK(status IN ('queued', 'processing', 'done')),
                PRIMARY KEY(scan_id, fqdn)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_candidates_pending
                ON scan_candidates(scan_id, status, priority DESC, fqdn);
            CREATE INDEX IF NOT EXISTS idx_scan_candidates_relative
                ON scan_candidates(scan_id, relative_name);

            CREATE TABLE IF NOT EXISTS scan_recursive_words (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                word TEXT NOT NULL,
                PRIMARY KEY(scan_id, ordinal),
                UNIQUE(scan_id, word)
            );

            CREATE TABLE IF NOT EXISTS scan_recursive_parents (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                depth INTEGER NOT NULL,
                parent TEXT NOT NULL,
                next_word INTEGER NOT NULL DEFAULT 0,
                exhausted INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(scan_id, depth, parent)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_recursive_parents_pending
                ON scan_recursive_parents(scan_id, depth, exhausted, parent);

            CREATE TABLE IF NOT EXISTS scan_recursive_candidates (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT NOT NULL,
                parent TEXT NOT NULL,
                depth INTEGER NOT NULL,
                word TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK(status IN ('queued', 'processing', 'done')),
                PRIMARY KEY(scan_id, fqdn)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_recursive_candidates_pending
                ON scan_recursive_candidates(scan_id, depth, status, fqdn);

            CREATE TABLE IF NOT EXISTS scan_seed_candidates (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT NOT NULL,
                priority INTEGER NOT NULL,
                sources_json TEXT NOT NULL DEFAULT '[]',
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK(status IN ('queued', 'processing', 'done')),
                PRIMARY KEY(scan_id, fqdn)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_seed_candidates_pending
                ON scan_seed_candidates(scan_id, status, priority DESC, fqdn);
            CREATE INDEX IF NOT EXISTS idx_scan_seed_candidates_priority
                ON scan_seed_candidates(scan_id, priority, fqdn DESC);

            CREATE TABLE IF NOT EXISTS scan_candidate_feeds (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                source TEXT NOT NULL,
                cursor INTEGER NOT NULL DEFAULT 0,
                cursor_text TEXT NOT NULL DEFAULT '',
                exhausted INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(scan_id, source)
            );

            CREATE TABLE IF NOT EXISTS scan_generator_stats (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                generator TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(scan_id, generator)
            );

            CREATE TABLE IF NOT EXISTS scan_attempted_words (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                word TEXT NOT NULL,
                PRIMARY KEY(scan_id, word)
            );

            CREATE TABLE IF NOT EXISTS word_stats (
                word TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                unique_domains INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS word_domains (
                word TEXT NOT NULL REFERENCES word_stats(word) ON DELETE CASCADE,
                domain_hash TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                PRIMARY KEY(word, domain_hash)
            );

            CREATE TABLE IF NOT EXISTS relative_patterns (
                relative_name TEXT PRIMARY KEY,
                successes INTEGER NOT NULL DEFAULT 0,
                unique_domains INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pattern_domains (
                relative_name TEXT NOT NULL REFERENCES relative_patterns(relative_name) ON DELETE CASCADE,
                domain_hash TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                PRIMARY KEY(relative_name, domain_hash)
            );

            CREATE TABLE IF NOT EXISTS passive_cache (
                root_domain TEXT NOT NULL,
                source TEXT NOT NULL,
                names_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, source)
            );

            CREATE TABLE IF NOT EXISTS passive_pagination_state (
                root_domain TEXT NOT NULL,
                source TEXT NOT NULL,
                lane TEXT NOT NULL,
                contract_version INTEGER NOT NULL CHECK(contract_version > 0),
                query_hash TEXT NOT NULL CHECK(length(query_hash) = 64),
                next_position INTEGER NOT NULL CHECK(next_position > 0),
                records_seen INTEGER NOT NULL CHECK(records_seen >= 0),
                expected_records INTEGER CHECK(expected_records >= 0),
                expected_pages INTEGER CHECK(expected_pages >= 0),
                last_page_hash TEXT NOT NULL CHECK(length(last_page_hash) = 64),
                last_page_records INTEGER NOT NULL CHECK(last_page_records >= 0),
                done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0, 1)),
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, source, lane)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_passive_pagination_updated
                ON passive_pagination_state(updated_at);

            CREATE TABLE IF NOT EXISTS candidate_priors (
                relative_name TEXT PRIMARY KEY,
                priority INTEGER NOT NULL,
                source TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_candidate_priors_priority
                ON candidate_priors(priority DESC, relative_name);

            CREATE TABLE IF NOT EXISTS axfr_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                nameserver TEXT NOT NULL,
                address TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                record_count INTEGER NOT NULL,
                attempted_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS source_stats (
                source TEXT PRIMARY KEY,
                requests INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                degraded INTEGER NOT NULL DEFAULT 0,
                deferred INTEGER NOT NULL DEFAULT 0,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                names INTEGER NOT NULL DEFAULT 0,
                novel_names INTEGER NOT NULL DEFAULT 0,
                novel_requests INTEGER NOT NULL DEFAULT 0,
                novel_total_ms INTEGER NOT NULL DEFAULT 0,
                total_ms INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                last_status TEXT NOT NULL DEFAULT 'unknown'
                    CHECK(last_status IN ('unknown', 'success', 'failure', 'degraded', 'deferred')),
                last_used INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS source_metadata_cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tls_certificate_cache (
                root_domain TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                port INTEGER NOT NULL,
                fingerprint_sha256 TEXT NOT NULL,
                names_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, endpoint, port)
            );
            CREATE INDEX IF NOT EXISTS idx_tls_certificate_root
                ON tls_certificate_cache(root_domain, updated_at);

            CREATE TABLE IF NOT EXISTS discovery_edges (
                root_domain TEXT NOT NULL,
                owner TEXT NOT NULL,
                record_type TEXT NOT NULL,
                value TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(root_domain, owner, record_type, value, target)
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_edges_target
                ON discovery_edges(root_domain, target);

            CREATE TABLE IF NOT EXISTS ip_hostname_observations (
                provider TEXT NOT NULL,
                address TEXT NOT NULL,
                hostname TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(provider, address, hostname)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS ip_hostname_refresh (
                provider TEXT NOT NULL,
                address TEXT NOT NULL,
                last_success_at INTEGER NOT NULL DEFAULT 0,
                last_attempt_at INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('success', 'empty', 'error')),
                last_error TEXT,
                PRIMARY KEY(provider, address)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_ip_hostname_refresh_age
                ON ip_hostname_refresh(provider, last_success_at);

            CREATE TABLE IF NOT EXISTS service_endpoints (
                root_domain TEXT NOT NULL,
                hostname TEXT NOT NULL,
                port INTEGER NOT NULL,
                transport TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(root_domain, hostname, port, transport, source)
            );

            CREATE TABLE IF NOT EXISTS child_zones (
                root_domain TEXT NOT NULL,
                zone TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(root_domain, zone)
            );

            CREATE TABLE IF NOT EXISTS generator_stats (
                generator TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                unique_domains INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS generator_domains (
                generator TEXT NOT NULL REFERENCES generator_stats(generator) ON DELETE CASCADE,
                domain_hash TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                PRIMARY KEY(generator, domain_hash)
            );

            CREATE TABLE IF NOT EXISTS generator_context_stats (
                context TEXT NOT NULL,
                generator TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(context, generator)
            );

            CREATE TABLE IF NOT EXISTS web_discovery_cache (
                root_domain TEXT NOT NULL,
                url TEXT NOT NULL,
                status INTEGER NOT NULL,
                names_json TEXT NOT NULL,
                assets_json TEXT NOT NULL DEFAULT '[]',
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, url)
            );
            CREATE INDEX IF NOT EXISTS idx_web_discovery_root
                ON web_discovery_cache(root_domain, updated_at);

            CREATE TABLE IF NOT EXISTS dnssec_walk_cache (
                root_domain TEXT NOT NULL,
                zone TEXT NOT NULL,
                nameserver TEXT NOT NULL,
                status TEXT NOT NULL,
                names_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, zone)
            );

            CREATE TABLE IF NOT EXISTS ct_log_state (
                root_domain TEXT NOT NULL,
                log_url TEXT NOT NULL,
                next_index INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, log_url)
            );

            CREATE TABLE IF NOT EXISTS observed_names (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fqdn TEXT NOT NULL UNIQUE,
                reversed_name TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_observed_names_reversed
                ON observed_names(reversed_name);

            CREATE TABLE IF NOT EXISTS observation_evidence (
                root_domain TEXT NOT NULL,
                name_id INTEGER NOT NULL REFERENCES observed_names(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                source TEXT NOT NULL,
                value TEXT NOT NULL DEFAULT '',
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1,
                passive_refresh_generation INTEGER NOT NULL DEFAULT 0
                    CHECK(passive_refresh_generation >= 0),
                PRIMARY KEY(root_domain, name_id, kind, source, value)
            );
            CREATE INDEX IF NOT EXISTS idx_observation_root_source
                ON observation_evidence(root_domain, source, name_id);

            CREATE TABLE IF NOT EXISTS passive_refresh_sessions (
                root_domain TEXT NOT NULL,
                source TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0),
                active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
                PRIMARY KEY(root_domain, source)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_passive_refresh_sessions_updated
                ON passive_refresh_sessions(updated_at);

            CREATE TABLE IF NOT EXISTS passive_refresh_seen (
                root_domain TEXT NOT NULL,
                source TEXT NOT NULL,
                name_id INTEGER NOT NULL REFERENCES observed_names(id) ON DELETE CASCADE,
                seen_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, source, name_id),
                FOREIGN KEY(root_domain, source)
                    REFERENCES passive_refresh_sessions(root_domain, source)
                    ON DELETE CASCADE
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS passive_refresh_leases (
                root_domain TEXT NOT NULL,
                source TEXT NOT NULL,
                owner TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(root_domain, source)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_passive_refresh_leases_expires
                ON passive_refresh_leases(expires_at);

            CREATE TABLE IF NOT EXISTS wildcard_cache (
                zone TEXT PRIMARY KEY,
                signature_json TEXT NOT NULL,
                soa_serial INTEGER,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                probe_count INTEGER NOT NULL DEFAULT 0,
                algorithm_version INTEGER NOT NULL DEFAULT 4
            );

            CREATE TABLE IF NOT EXISTS resolver_stats (
                resolver TEXT PRIMARY KEY,
                requests INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                total_ms INTEGER NOT NULL DEFAULT 0,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                last_used INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS generator_bandits (
                context TEXT NOT NULL,
                generator TEXT NOT NULL,
                alpha REAL NOT NULL DEFAULT 1.0,
                beta REAL NOT NULL DEFAULT 1.0,
                pulls INTEGER NOT NULL DEFAULT 0,
                rewards INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(context, generator)
            );

            CREATE TABLE IF NOT EXISTS discovery_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT,
                zone TEXT NOT NULL,
                kind TEXT NOT NULL,
                generator TEXT NOT NULL,
                context_key TEXT NOT NULL DEFAULT 'global',
                priority_class INTEGER NOT NULL CHECK(priority_class BETWEEN 0 AND 3),
                predicted_unique_live REAL NOT NULL DEFAULT 0.0,
                predicted_cost REAL NOT NULL DEFAULT 1.0,
                state TEXT NOT NULL DEFAULT 'queued'
                    CHECK(state IN ('queued', 'processing', 'done', 'deferred')),
                outcome_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(scan_id, kind, fqdn, zone, generator)
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_actions_queue
                ON discovery_actions(scan_id, state, priority_class, predicted_unique_live DESC);
            CREATE INDEX IF NOT EXISTS idx_discovery_actions_yield
                ON discovery_actions(
                    scan_id, state, priority_class,
                    (predicted_unique_live / MAX(predicted_cost, 0.000001)) DESC,
                    id
                );

            CREATE TABLE IF NOT EXISTS intelligence_edges (
                root_domain TEXT NOT NULL,
                from_node TEXT NOT NULL,
                to_node TEXT NOT NULL,
                relation TEXT NOT NULL,
                weight REAL NOT NULL DEFAULT 1.0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY(root_domain, from_node, to_node, relation)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS name_templates (
                root_domain TEXT NOT NULL,
                parent_zone TEXT NOT NULL,
                template TEXT NOT NULL,
                support INTEGER NOT NULL DEFAULT 0,
                successes INTEGER NOT NULL DEFAULT 0,
                score REAL NOT NULL DEFAULT 0.0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(root_domain, parent_zone, template)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS dnssec_proofs (
                zone TEXT NOT NULL,
                owner TEXT NOT NULL,
                proof_type TEXT NOT NULL,
                next_owner TEXT,
                parameters_json TEXT NOT NULL DEFAULT '{}',
                validated INTEGER NOT NULL DEFAULT 0,
                compact_denial INTEGER NOT NULL DEFAULT 0,
                observed_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY(zone, owner, proof_type)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS idx_dnssec_proofs_range
                ON dnssec_proofs(zone, proof_type, validated, expires_at);

            CREATE TABLE IF NOT EXISTS ct_tiles (
                log_url TEXT NOT NULL,
                tile_path TEXT NOT NULL,
                checkpoint_size INTEGER NOT NULL,
                checkpoint_hash TEXT NOT NULL DEFAULT '',
                content_hash TEXT NOT NULL,
                payload BLOB NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(log_url, tile_path)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS scheduler_arms (
                context TEXT NOT NULL,
                generator TEXT NOT NULL,
                alpha REAL NOT NULL DEFAULT 1.0,
                beta REAL NOT NULL DEFAULT 1.0,
                packets INTEGER NOT NULL DEFAULT 0,
                exclusive_rewards INTEGER NOT NULL DEFAULT 0,
                total_cost REAL NOT NULL DEFAULT 0.0,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(context, generator)
            ) WITHOUT ROWID;

            CREATE TABLE IF NOT EXISTS ct_global_state (
                log_url TEXT PRIMARY KEY,
                next_index INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ct_names (
                fqdn TEXT PRIMARY KEY,
                reversed_name TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_ct_names_reversed
                ON ct_names(reversed_name);

            CREATE TABLE IF NOT EXISTS scan_pipeline_metrics (
                scan_id INTEGER PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                rounds INTEGER NOT NULL,
                events_enqueued INTEGER NOT NULL,
                duplicates_suppressed INTEGER NOT NULL,
                names_validated INTEGER NOT NULL,
                budget_exhausted INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS migration_state (
                name TEXT PRIMARY KEY,
                completed_at INTEGER NOT NULL
            );

            DROP TABLE IF EXISTS community_push_state;
            DROP TABLE IF EXISTS community_words;

            UPDATE axfr_attempts
               SET status='empty',
                   error=COALESCE(error, 'transfert historique sans enregistrement')
             WHERE status='success' AND record_count<2;
            UPDATE axfr_attempts
               SET status=CASE
                   WHEN lower(COALESCE(error, '')) LIKE '%timeout%' THEN 'timeout'
                   WHEN lower(COALESCE(error, '')) LIKE '%refus%' THEN 'refused'
                   WHEN error IS NULL AND record_count=0 THEN 'empty'
                   ELSE 'protocol_error'
               END
             WHERE status NOT IN ('success', 'refused', 'empty', 'timeout', 'protocol_error');

            "#,
        )?;
        let has_consecutive_failures = {
            let mut statement = connection.prepare("PRAGMA table_info(source_stats)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|column| column == "consecutive_failures")
        };
        if !has_consecutive_failures {
            connection.execute(
                "ALTER TABLE source_stats ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let table_has_column = |table: &str, column: &str| -> Result<bool> {
            let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
            Ok(statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|name| name == column))
        };
        for (table, column, definition) in [
            ("web_discovery_cache", "etag", "etag TEXT"),
            ("web_discovery_cache", "last_modified", "last_modified TEXT"),
            ("web_discovery_cache", "content_hash", "content_hash TEXT"),
            (
                "web_discovery_cache",
                "assets_json",
                "assets_json TEXT NOT NULL DEFAULT '[]'",
            ),
            (
                "scan_findings",
                "confidence_score",
                "confidence_score INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "scan_findings",
                "confidence_label",
                "confidence_label TEXT NOT NULL DEFAULT 'faible'",
            ),
            (
                "scan_findings",
                "confidence_reasons_json",
                "confidence_reasons_json TEXT NOT NULL DEFAULT '[]'",
            ),
            (
                "subdomains",
                "verification_state",
                "verification_state TEXT NOT NULL DEFAULT 'live' CHECK(verification_state IN ('live', 'historical', 'unverified'))",
            ),
            (
                "subdomains",
                "first_scan_id",
                "first_scan_id INTEGER REFERENCES scans(id)",
            ),
            ("subdomains", "last_verified_at", "last_verified_at INTEGER"),
            (
                "scan_findings",
                "state",
                "state TEXT NOT NULL DEFAULT 'unverified' CHECK(state IN ('live', 'historical', 'unverified'))",
            ),
            (
                "scan_findings",
                "last_verified_at",
                "last_verified_at INTEGER",
            ),
            (
                "scan_findings",
                "evidence_families_json",
                "evidence_families_json TEXT NOT NULL DEFAULT '[]'",
            ),
            (
                "scan_findings",
                "authoritative_validation",
                "authoritative_validation INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "scan_findings",
                "wildcard_verdict",
                "wildcard_verdict TEXT NOT NULL DEFAULT 'not_profiled' CHECK(wildcard_verdict IN ('exact_owner', 'synthesized', 'ambiguous', 'not_profiled'))",
            ),
            (
                "scan_findings",
                "owner_proofs_json",
                "owner_proofs_json TEXT NOT NULL DEFAULT '[]'",
            ),
            (
                "scan_findings",
                "generation_path_json",
                "generation_path_json TEXT NOT NULL DEFAULT '[]'",
            ),
            ("scan_findings", "discovery_score", "discovery_score REAL"),
            (
                "ct_tiles",
                "checkpoint_hash",
                "checkpoint_hash TEXT NOT NULL DEFAULT ''",
            ),
            (
                "dns_cache",
                "resolver_count",
                "resolver_count INTEGER NOT NULL DEFAULT 1",
            ),
            (
                "dns_cache",
                "authoritative",
                "authoritative INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "wildcard_cache",
                "algorithm_version",
                "algorithm_version INTEGER NOT NULL DEFAULT 1",
            ),
            (
                "scan_candidate_feeds",
                "cursor_text",
                "cursor_text TEXT NOT NULL DEFAULT ''",
            ),
            (
                "scan_candidates",
                "attempts",
                "attempts INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "scan_candidates",
                "learning_recorded",
                "learning_recorded INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "scan_seed_candidates",
                "attempts",
                "attempts INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "scans",
                "learning_applied",
                "learning_applied INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "observation_evidence",
                "passive_refresh_generation",
                "passive_refresh_generation INTEGER NOT NULL DEFAULT 0 CHECK(passive_refresh_generation >= 0)",
            ),
            (
                "passive_refresh_sessions",
                "generation",
                "generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0)",
            ),
            (
                "passive_refresh_sessions",
                "active",
                "active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1))",
            ),
            (
                "source_stats",
                "novel_names",
                "novel_names INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "source_stats",
                "novel_requests",
                "novel_requests INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "source_stats",
                "novel_total_ms",
                "novel_total_ms INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "source_stats",
                "degraded",
                "degraded INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "source_stats",
                "deferred",
                "deferred INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "source_stats",
                "last_status",
                "last_status TEXT NOT NULL DEFAULT 'unknown' CHECK(last_status IN ('unknown', 'success', 'failure', 'degraded', 'deferred'))",
            ),
        ] {
            if !table_has_column(table, column)? {
                connection.execute(&format!("ALTER TABLE {table} ADD COLUMN {definition}"), [])?;
            }
        }
        // Preserve useful pre-v9 learning without ever double-applying it.
        // Existing native scheduler rows win; missing rows receive the legacy
        // Beta posterior and a conservative unit cost per historical pull.
        // Legacy rewards were not proven exclusive-live, so that counter is
        // deliberately initialized to zero instead of relabeling old data.
        connection.execute(
            r#"INSERT OR IGNORE INTO scheduler_arms(
                   context, generator, alpha, beta, packets,
                   exclusive_rewards, total_cost, last_seen
               )
               SELECT context, generator,
                      MAX(COALESCE(alpha, 1.0), 1.0),
                      MAX(COALESCE(beta, 1.0), 1.0),
                      MAX(COALESCE(pulls, 0), 0),
                      0,
                      CAST(MAX(COALESCE(pulls, 0), 0) AS REAL),
                      last_seen
               FROM generator_bandits"#,
            [],
        )?;
        connection.execute(
            r#"UPDATE source_stats
                  SET last_status=CASE
                      WHEN failures>0 AND last_error IS NOT NULL THEN 'failure'
                      WHEN successes>0 THEN 'success'
                      ELSE 'unknown'
                  END
                WHERE last_status='unknown'"#,
            [],
        )?;
        // Existing v8 databases can already contain scan_candidates while
        // missing columns introduced by a later compatible release. Create
        // dependent indexes only after the additive column repair above.
        connection.execute(
            r#"CREATE INDEX IF NOT EXISTS idx_scan_candidates_unrecorded
               ON scan_candidates(scan_id) WHERE learning_recorded=0"#,
            [],
        )?;
        // Operational refresh markers are bounded independently from the
        // permanent observations they protect. Cleanup is additive and never
        // deletes observed_names or observation_evidence.
        cleanup_abandoned_passive_refresh_sessions(&connection, now_epoch())?;
        if migrating_to_v8 {
            connection.execute(
                "UPDATE dns_cache SET expires_at=?1 WHERE status='positive' AND expires_at<>?1",
                [PERMANENT_EXPIRY],
            )?;
            connection.execute(
                "UPDATE dns_records SET expires_at=?1 WHERE expires_at<>?1",
                [PERMANENT_EXPIRY],
            )?;
            connection.execute(
                r#"UPDATE dns_cache
               SET resolver_count=COALESCE((
                       SELECT resolver_count FROM dns_verifications verification
                       WHERE verification.fqdn=dns_cache.fqdn
                         AND verification.outcome='live'
                       ORDER BY checked_at DESC, id DESC LIMIT 1
                   ), resolver_count),
                   authoritative=COALESCE((
                       SELECT authoritative FROM dns_verifications verification
                       WHERE verification.fqdn=dns_cache.fqdn
                         AND verification.outcome='live'
                       ORDER BY checked_at DESC, id DESC LIMIT 1
                   ), authoritative)
               WHERE status='positive'"#,
                [],
            )?;
        }
        if migrating_to_v8 {
            connection.execute(
                r#"UPDATE subdomains
                   SET verification_state=CASE
                           WHEN active=1 THEN 'unverified'
                           ELSE 'historical'
                       END,
                       active=0,
                       last_verified_at=NULL"#,
                [],
            )?;
            connection.pragma_update(None, "user_version", 9)?;
        } else {
            connection.execute(
                r#"UPDATE subdomains
                   SET verification_state=CASE WHEN active=1 THEN 'live' ELSE 'historical' END
                   WHERE verification_state IS NULL
                      OR verification_state NOT IN ('live', 'historical', 'unverified')"#,
                [],
            )?;
            connection.execute(
                r#"UPDATE subdomains SET last_verified_at=last_seen
                   WHERE verification_state IN ('live', 'historical')
                     AND last_verified_at IS NULL"#,
                [],
            )?;
            connection.pragma_update(None, "user_version", 9)?;
        }
        if migrating_to_v9 {
            connection.execute(
                r#"INSERT INTO migration_state(name, completed_at)
                   VALUES ('intelligence-v9', ?1)
                   ON CONFLICT(name) DO UPDATE SET completed_at=excluded.completed_at"#,
                [now_epoch()],
            )?;
        }
        migrate_legacy_observations(&mut connection, true)?;
        connection.execute_batch("COMMIT")?;
        let writer = if path == Path::new(":memory:") {
            None
        } else {
            Some(Arc::new(ObservationWriter::start(path.clone())?))
        };
        let database = Self {
            path,
            connection: Arc::new(Mutex::new(connection)),
            writer,
        };
        database.reconcile_stale_scans(std::time::Duration::from_secs(120))?;
        database.seed_builtin_candidates()?;
        database.clean_noisy_knowledge()?;
        if database.path != Path::new(":memory:") {
            secure_existing_sqlite_files(&database.path)?;
        }
        Ok(database)
    }

    pub(super) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("verrou SQLite empoisonné"))
    }

    pub(super) fn lock_ct_materialization_until(
        &self,
        deadline: Option<Instant>,
        cancellation: &AtomicBool,
    ) -> Result<std::sync::MutexGuard<'_, Connection>> {
        loop {
            ensure_ct_materialization_active(deadline, cancellation)?;
            match self.connection.try_lock() {
                Ok(connection) => {
                    ensure_ct_materialization_active(deadline, cancellation)?;
                    return Ok(connection);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    bail!("verrou SQLite empoisonné")
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    let retry = deadline.map_or(CT_MATERIALIZATION_LOCK_RETRY, |deadline| {
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(CT_MATERIALIZATION_LOCK_RETRY)
                    });
                    if retry.is_zero() {
                        ensure_ct_materialization_active(deadline, cancellation)?;
                    }
                    std::thread::sleep(retry);
                }
            }
        }
    }

    fn seed_builtin_candidates(&self) -> Result<()> {
        if self
            .lock()?
            .query_row(
                "SELECT completed_at FROM migration_state WHERE name='builtin-corpus-v1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some()
        {
            return Ok(());
        }
        let words = include_str!("../../data/seed_words.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let patterns = include_str!("../../data/seed_patterns.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let mut candidates = words
            .chain(patterns)
            .map(|candidate| (candidate.to_owned(), "builtin"))
            .collect::<Vec<_>>();
        if !cfg!(test) {
            let corpus =
                zstd::stream::decode_all(&include_bytes!("../../data/candidates-1m.txt.zst")[..])
                    .context("décompression du corpus Fellaga 1M")?;
            let corpus = String::from_utf8(corpus).context("corpus Fellaga 1M non UTF-8")?;
            candidates.extend(
                corpus
                    .lines()
                    .filter(|candidate| valid_relative_name(candidate))
                    .map(|candidate| (candidate.to_owned(), "seclists-mit-v1")),
            );
        }
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            r#"INSERT OR IGNORE INTO candidate_priors(
                   relative_name, priority, source, created_at
                   ) VALUES (?1, ?2, ?3, ?4)"#,
        )?;
        for (index, (candidate, source)) in candidates.iter().enumerate() {
            statement.execute(params![
                candidate,
                (candidates.len() - index) as i64,
                source,
                now
            ])?;
        }
        drop(statement);
        transaction.execute(
            r#"INSERT INTO migration_state(name, completed_at)
               VALUES ('builtin-corpus-v1', ?1)
               ON CONFLICT(name) DO UPDATE SET completed_at=excluded.completed_at"#,
            [now],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn clean_noisy_knowledge(&self) -> Result<()> {
        let mut connection = self.lock()?;
        let noisy_words = {
            let mut statement = connection.prepare("SELECT word FROM word_stats")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|word| !learnable_label(word))
                .collect::<Vec<_>>()
        };
        let noisy_patterns = {
            let mut statement =
                connection.prepare("SELECT relative_name FROM relative_patterns")?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|pattern| !learnable_relative_name(pattern))
                .collect::<Vec<_>>()
        };
        let transaction = connection.transaction()?;
        for word in noisy_words {
            transaction.execute("DELETE FROM word_stats WHERE word=?1", [word])?;
        }
        for pattern in noisy_patterns {
            transaction.execute(
                "DELETE FROM relative_patterns WHERE relative_name=?1",
                [pattern],
            )?;
        }
        // Les profils v1 ne contiennent que des types DNS (A:*, AAAA:*) et
        // ne permettent pas de distinguer un vrai hôte d'un wildcard. Les
        // JSON corrompus ne doivent pas non plus bloquer les nouveaux probes.
        transaction.execute(
            "DELETE FROM wildcard_cache WHERE algorithm_version<2 OR json_valid(signature_json)=0",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }
}
