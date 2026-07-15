use crate::model::{
    AxfrAttempt, DiscoveryEdge, Finding, InventoryEntry, ObservationState, ResolvedHost,
    ResolverMetric, ServiceEndpoint, Stats,
};
use crate::util::{
    domain_hash, learnable_label, learnable_relative_name, now_epoch, public_suffix,
    registrable_domain, reverse_hostname, valid_relative_name,
};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

const PERMANENT_EXPIRY: i64 = i64::MAX;

fn next_v8_backup_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fellaga.db");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let timestamp = now_epoch();
    for suffix in 0_u32.. {
        let candidate_name = if suffix == 0 {
            format!("{file_name}.pre-v8-{timestamp}.bak")
        } else {
            format!("{file_name}.pre-v8-{timestamp}-{suffix}.bak")
        };
        let candidate = parent.join(candidate_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("la recherche d'un nom de sauvegarde libre est bornée par le système de fichiers")
}

#[derive(Debug, Clone)]
pub enum CachedAnswer {
    Positive(ResolvedHost),
    Negative,
}

#[derive(Debug, Clone)]
pub struct PassiveCacheEntry {
    pub names: Vec<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct ScanCheckpoint {
    pub scan_id: i64,
    pub domain: String,
    pub stage: String,
    pub options_hash: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct TlsCacheEntry {
    pub fingerprint_sha256: String,
    pub names: Vec<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct WebCacheEntry {
    pub status: u16,
    pub names: Vec<String>,
    pub updated_at: i64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct WebCacheMetadata {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_hash: Option<String>,
}

type WebCacheRow = (
    i64,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
);
type WebMetadataRow = (String, Option<String>, Option<String>, Option<String>);

#[derive(Debug, Clone)]
pub struct DnssecCacheEntry {
    pub nameserver: String,
    pub status: String,
    pub names: Vec<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct WildcardCacheEntry {
    pub signature: BTreeSet<String>,
    pub soa_serial: Option<u64>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceDiagnostic {
    pub requests: i64,
    pub successes: i64,
    pub failures: i64,
    pub consecutive_failures: i64,
    pub names: i64,
    pub average_ms: i64,
    pub last_error: Option<String>,
    pub last_used: i64,
    pub next_retry: Option<i64>,
    pub retry_in_seconds: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ObservationInput {
    pub fqdn: String,
    pub kind: String,
    pub source: String,
    pub value: String,
}

struct WriterMessage {
    root_domain: String,
    observations: Vec<ObservationInput>,
    reply: mpsc::Sender<std::result::Result<usize, String>>,
}

struct ObservationWriter {
    sender: mpsc::Sender<WriterMessage>,
}

impl ObservationWriter {
    fn start(path: PathBuf) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<WriterMessage>();
        std::thread::Builder::new()
            .name("fellaga-sqlite-writer".to_owned())
            .spawn(move || {
                let connection = Connection::open(path);
                let Ok(mut connection) = connection else {
                    for message in receiver {
                        let _ = message
                            .reply
                            .send(Err("ouverture du writer SQLite impossible".to_owned()));
                    }
                    return;
                };
                let _ = connection.pragma_update(None, "journal_mode", "WAL");
                let _ = connection.pragma_update(None, "synchronous", "NORMAL");
                let _ = connection.pragma_update(None, "foreign_keys", "ON");
                let _ = connection.busy_timeout(std::time::Duration::from_secs(30));
                for message in receiver {
                    let result = insert_observations(
                        &mut connection,
                        &message.root_domain,
                        &message.observations,
                    )
                    .map_err(|error| format!("{error:#}"));
                    let _ = message.reply.send(result);
                }
            })?;
        Ok(Self { sender })
    }

    fn submit(&self, root_domain: &str, observations: Vec<ObservationInput>) -> Result<usize> {
        if observations.is_empty() {
            return Ok(0);
        }
        let (reply, response) = mpsc::channel();
        self.sender
            .send(WriterMessage {
                root_domain: root_domain.to_owned(),
                observations,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("writer SQLite arrêté"))?;
        response
            .recv()
            .map_err(|_| anyhow::anyhow!("réponse du writer SQLite absente"))?
            .map_err(anyhow::Error::msg)
    }
}

fn insert_observations(
    connection: &mut Connection,
    root_domain: &str,
    observations: &[ObservationInput],
) -> Result<usize> {
    if observations.is_empty() {
        return Ok(0);
    }
    let transaction = connection.transaction()?;
    let written = insert_observation_rows(&transaction, root_domain, observations)?;
    transaction.commit()?;
    Ok(written)
}

fn insert_observation_rows(
    connection: &Connection,
    root_domain: &str,
    observations: &[ObservationInput],
) -> Result<usize> {
    let now = now_epoch();
    let mut written = 0;
    for observation in observations {
        connection.execute(
            r#"INSERT INTO observed_names(fqdn, reversed_name, first_seen, last_seen)
               VALUES (?1, ?2, ?3, ?3)
               ON CONFLICT(fqdn) DO UPDATE SET last_seen=excluded.last_seen"#,
            params![observation.fqdn, reverse_hostname(&observation.fqdn), now],
        )?;
        let name_id: i64 = connection.query_row(
            "SELECT id FROM observed_names WHERE fqdn=?1",
            [&observation.fqdn],
            |row| row.get(0),
        )?;
        connection.execute(
            r#"INSERT INTO observation_evidence(
               root_domain, name_id, kind, source, value,
               first_seen, last_seen, times_seen
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
               ON CONFLICT(root_domain, name_id, kind, source, value)
               DO UPDATE SET last_seen=excluded.last_seen,
                             times_seen=observation_evidence.times_seen+1"#,
            params![
                root_domain,
                name_id,
                observation.kind,
                observation.source,
                observation.value,
                now
            ],
        )?;
        written += 1;
    }
    Ok(written)
}

fn migrate_legacy_observations(
    connection: &mut Connection,
    inside_migration_transaction: bool,
) -> Result<()> {
    let migrated: Option<i64> = connection
        .query_row(
            "SELECT completed_at FROM migration_state WHERE name='normalized-v7'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if migrated.is_some() {
        return Ok(());
    }
    let mut batches = BTreeMap::<String, Vec<ObservationInput>>::new();
    {
        let mut statement =
            connection.prepare("SELECT root_domain, source, names_json FROM passive_cache")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (root, source, json) = row?;
            for fqdn in serde_json::from_str::<Vec<String>>(&json).unwrap_or_default() {
                batches
                    .entry(root.clone())
                    .or_default()
                    .push(ObservationInput {
                        fqdn,
                        kind: "passive".to_owned(),
                        source: format!("passive:{source}"),
                        value: String::new(),
                    });
            }
        }
    }
    {
        let mut statement =
            connection.prepare("SELECT root_domain, url, names_json FROM web_discovery_cache")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (root, url, json) = row?;
            for fqdn in serde_json::from_str::<Vec<String>>(&json).unwrap_or_default() {
                batches
                    .entry(root.clone())
                    .or_default()
                    .push(ObservationInput {
                        fqdn,
                        kind: "web".to_owned(),
                        source: format!("web:{url}"),
                        value: String::new(),
                    });
            }
        }
    }
    {
        let mut statement = connection.prepare(
            r#"SELECT root_domain, endpoint, port, fingerprint_sha256, names_json
               FROM tls_certificate_cache"#,
        )?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })? {
            let (root, endpoint, port, fingerprint, json) = row?;
            for fqdn in serde_json::from_str::<Vec<String>>(&json).unwrap_or_default() {
                batches
                    .entry(root.clone())
                    .or_default()
                    .push(ObservationInput {
                        fqdn,
                        kind: "tls".to_owned(),
                        source: format!("tls:{endpoint}:{port}"),
                        value: fingerprint.clone(),
                    });
            }
        }
    }
    {
        let mut statement = connection
            .prepare("SELECT root_domain, zone, status, names_json FROM dnssec_walk_cache")?;
        for row in statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })? {
            let (root, zone, status, json) = row?;
            for fqdn in serde_json::from_str::<Vec<String>>(&json).unwrap_or_default() {
                batches
                    .entry(root.clone())
                    .or_default()
                    .push(ObservationInput {
                        fqdn,
                        kind: "dnssec".to_owned(),
                        source: format!("dnssec:{zone}"),
                        value: status.clone(),
                    });
            }
        }
    }
    for (root, observations) in batches {
        if inside_migration_transaction {
            insert_observation_rows(connection, &root, &observations)?;
        } else {
            insert_observations(connection, &root, &observations)?;
        }
    }
    connection.execute(
        "INSERT INTO migration_state(name, completed_at) VALUES ('normalized-v7', ?1)",
        [now_epoch()],
    )?;
    Ok(())
}

fn candidate_contexts(connection: &Connection, domain: &str) -> Result<Vec<String>> {
    let mut contexts = vec![
        "global".to_owned(),
        format!(
            "suffix:{}",
            public_suffix(domain).unwrap_or_else(|| domain.to_owned())
        ),
        format!(
            "registrable:{}",
            registrable_domain(domain).unwrap_or_else(|| domain.to_owned())
        ),
    ];
    let mut depth = 1_usize;
    {
        let mut statement =
            connection.prepare("SELECT fqdn FROM subdomains WHERE root_domain=?1 LIMIT 1000")?;
        for row in statement.query_map([domain], |row| row.get::<_, String>(0))? {
            let fqdn = row?;
            let relative = fqdn.strip_suffix(&format!(".{domain}")).unwrap_or_default();
            depth = depth.max(relative.split('.').filter(|part| !part.is_empty()).count());
        }
    }
    contexts.push(format!("depth:{}", depth.min(4)));
    let nameserver: Option<String> = connection
        .query_row(
            r#"SELECT value FROM discovery_edges
               WHERE root_domain=?1 AND record_type='NS'
               ORDER BY last_seen DESC LIMIT 1"#,
            [domain],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(nameserver) = nameserver {
        let lower = nameserver.trim_end_matches('.').to_ascii_lowercase();
        let provider = if lower.contains("cloudflare") {
            "cloudflare".to_owned()
        } else if lower.contains("awsdns") {
            "route53".to_owned()
        } else if lower.contains("azure-dns") {
            "azure".to_owned()
        } else if lower.contains("googledomains") || lower.contains("google") {
            "google".to_owned()
        } else if lower.contains("ovh") {
            "ovh".to_owned()
        } else {
            lower
                .split('.')
                .rev()
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(".")
        };
        if !provider.is_empty() {
            contexts.push(format!("provider:{provider}"));
        }
    }
    contexts.sort();
    contexts.dedup();
    Ok(contexts)
}

#[derive(Clone)]
pub struct Database {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    writer: Option<Arc<ObservationWriter>>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création du dossier {}", parent.display()))?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("ouverture de SQLite {}", path.display()))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if (1..8).contains(&version) {
            let backup = next_v8_backup_path(path);
            connection
                .execute("VACUUM INTO ?1", [backup.to_string_lossy().as_ref()])
                .with_context(|| {
                    format!(
                        "sauvegarde SQLite pré-v8 de {} vers {}",
                        path.display(),
                        backup.display()
                    )
                })?;
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
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(30))?;
        let migrating_to_v8 = starting_version < 8;
        if migrating_to_v8 {
            connection.execute_batch("BEGIN IMMEDIATE")?;
        }
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
                warnings_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                fqdn TEXT PRIMARY KEY,
                root_domain TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
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

            CREATE TABLE IF NOT EXISTS scan_candidates (
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                fqdn TEXT NOT NULL,
                relative_name TEXT NOT NULL,
                priority INTEGER NOT NULL,
                generator TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK(status IN ('queued', 'processing', 'done')),
                PRIMARY KEY(scan_id, fqdn)
            );
            CREATE INDEX IF NOT EXISTS idx_scan_candidates_pending
                ON scan_candidates(scan_id, status, priority DESC, fqdn);

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

            CREATE TABLE IF NOT EXISTS candidate_priors (
                relative_name TEXT PRIMARY KEY,
                priority INTEGER NOT NULL,
                source TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

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
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                names INTEGER NOT NULL DEFAULT 0,
                total_ms INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
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
                PRIMARY KEY(root_domain, name_id, kind, source, value)
            );
            CREATE INDEX IF NOT EXISTS idx_observation_root_source
                ON observation_evidence(root_domain, source, name_id);

            CREATE TABLE IF NOT EXISTS wildcard_cache (
                zone TEXT PRIMARY KEY,
                signature_json TEXT NOT NULL,
                soa_serial INTEGER,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                probe_count INTEGER NOT NULL DEFAULT 0
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

            UPDATE dns_cache
               SET expires_at=9223372036854775807
             WHERE status='positive';
            UPDATE dns_records SET expires_at=9223372036854775807;

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
                "dns_cache",
                "resolver_count",
                "resolver_count INTEGER NOT NULL DEFAULT 1",
            ),
            (
                "dns_cache",
                "authoritative",
                "authoritative INTEGER NOT NULL DEFAULT 0",
            ),
        ] {
            if !table_has_column(table, column)? {
                connection.execute(&format!("ALTER TABLE {table} ADD COLUMN {definition}"), [])?;
            }
        }
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
        if migrating_to_v8 {
            connection.execute(
                r#"UPDATE subdomains
                   SET verification_state=CASE WHEN active=1 THEN 'live' ELSE 'historical' END,
                       last_verified_at=last_seen"#,
                [],
            )?;
            connection.pragma_update(None, "user_version", 8)?;
        } else {
            let transaction = connection.transaction()?;
            transaction.execute(
                r#"UPDATE subdomains
                   SET verification_state=CASE WHEN active=1 THEN 'live' ELSE 'historical' END
                   WHERE verification_state IS NULL
                      OR verification_state NOT IN ('live', 'historical', 'unverified')"#,
                [],
            )?;
            transaction.execute(
                r#"UPDATE subdomains SET last_verified_at=last_seen
                   WHERE verification_state IN ('live', 'historical')
                     AND last_verified_at IS NULL"#,
                [],
            )?;
            transaction.pragma_update(None, "user_version", 8)?;
            transaction.commit()?;
        }
        migrate_legacy_observations(&mut connection, migrating_to_v8)?;
        if migrating_to_v8 {
            connection.execute_batch("COMMIT")?;
        }
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
        database.seed_builtin_candidates()?;
        database.clean_noisy_knowledge()?;
        Ok(database)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("verrou SQLite empoisonné"))
    }

    pub fn store_observations(
        &self,
        root_domain: &str,
        observations: Vec<ObservationInput>,
    ) -> Result<usize> {
        if let Some(writer) = &self.writer {
            writer.submit(root_domain, observations)
        } else {
            let mut connection = self.lock()?;
            insert_observations(&mut connection, root_domain, &observations)
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
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT DISTINCT n.fqdn FROM observation_evidence e
               JOIN observed_names n ON n.id=e.name_id
               WHERE e.root_domain=?1 AND e.source=?2 ORDER BY n.fqdn"#,
        )?;
        statement
            .query_map(params![root_domain, source], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn wildcard_cache(&self, zone: &str) -> Result<Option<WildcardCacheEntry>> {
        let connection = self.lock()?;
        let row: Option<(String, Option<i64>, i64)> = connection
            .query_row(
                r#"SELECT signature_json, soa_serial, expires_at
                   FROM wildcard_cache WHERE zone=?1"#,
                [zone],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(signature, serial, expires_at)| {
            Ok(WildcardCacheEntry {
                signature: serde_json::from_str::<Vec<String>>(&signature)?
                    .into_iter()
                    .collect(),
                soa_serial: serial.map(|value| value.max(0) as u64),
                expires_at,
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
        let now = now_epoch();
        let expires_at = now.saturating_add(freshness.as_secs().min(i64::MAX as u64) as i64);
        self.lock()?.execute(
            r#"INSERT INTO wildcard_cache(
               zone, signature_json, soa_serial, updated_at, expires_at, probe_count
               ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(zone) DO UPDATE SET
               signature_json=excluded.signature_json,
               soa_serial=excluded.soa_serial,
               updated_at=excluded.updated_at,
               expires_at=excluded.expires_at,
               probe_count=wildcard_cache.probe_count+excluded.probe_count"#,
            params![
                zone,
                serde_json::to_string(&signature.iter().cloned().collect::<Vec<_>>())?,
                soa_serial.map(|value| value.min(i64::MAX as u64) as i64),
                now,
                expires_at,
                i64::from(probed)
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
            transaction.execute(
                r#"INSERT INTO resolver_stats(
                   resolver, requests, successes, failures, total_ms,
                   consecutive_failures, last_used
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                   ON CONFLICT(resolver) DO UPDATE SET
                   requests=resolver_stats.requests+excluded.requests,
                   successes=resolver_stats.successes+excluded.successes,
                   failures=resolver_stats.failures+excluded.failures,
                   total_ms=resolver_stats.total_ms+excluded.total_ms,
                   consecutive_failures=excluded.consecutive_failures,
                   last_used=excluded.last_used"#,
                params![
                    metric.resolver,
                    metric.requests as i64,
                    metric.successes as i64,
                    metric.failures as i64,
                    metric.average_ms.saturating_mul(metric.requests) as i64,
                    metric.consecutive_failures as i64,
                    now
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
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
        let words = include_str!("../data/seed_words.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let patterns = include_str!("../data/seed_patterns.txt")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty());
        let mut candidates = words
            .chain(patterns)
            .map(|candidate| (candidate.to_owned(), "builtin"))
            .collect::<Vec<_>>();
        if !cfg!(test) {
            let corpus =
                zstd::stream::decode_all(&include_bytes!("../data/candidates-1m.txt.zst")[..])
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
        transaction.commit()?;
        Ok(())
    }

    pub fn create_scan(&self, domain: &str, options: &Value) -> Result<i64> {
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO scans(domain, started_at, status, options_json) VALUES (?1, ?2, 'running', ?3)",
            params![domain, now_epoch(), serde_json::to_string(options)?],
        )?;
        Ok(connection.last_insert_rowid())
    }

    pub fn upsert_checkpoint(
        &self,
        scan_id: i64,
        domain: &str,
        stage: &str,
        options_hash: &str,
    ) -> Result<()> {
        self.lock()?.execute(
            r#"INSERT INTO scan_checkpoints(
               scan_id, domain, stage, options_hash, updated_at, completed
               ) VALUES (?1, ?2, ?3, ?4, ?5, 0)
               ON CONFLICT(scan_id) DO UPDATE SET
               stage=excluded.stage, options_hash=excluded.options_hash,
               updated_at=excluded.updated_at, completed=0"#,
            params![scan_id, domain, stage, options_hash, now_epoch()],
        )?;
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
        self.lock()?.execute(
            "UPDATE scans SET status='running', finished_at=NULL WHERE id=?1",
            [scan_id],
        )?;
        Ok(())
    }

    pub fn persist_scan_candidates(
        &self,
        scan_id: i64,
        domain: &str,
        candidates: &[(String, String, i64)],
    ) -> Result<()> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            r#"INSERT OR IGNORE INTO scan_candidates(
               scan_id, fqdn, relative_name, priority, generator, status
               ) VALUES (?1, ?2, ?3, ?4, ?5, 'queued')"#,
        )?;
        for (relative_name, generator, priority) in candidates {
            statement.execute(params![
                scan_id,
                format!("{relative_name}.{domain}"),
                relative_name,
                priority,
                generator
            ])?;
        }
        drop(statement);
        transaction.commit()?;
        Ok(())
    }

    pub fn persist_wordlist_candidates(
        &self,
        scan_id: i64,
        domain: &str,
        path: &Path,
        limit: usize,
    ) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let file = std::fs::File::open(path)
            .with_context(|| format!("ouverture de la wordlist {}", path.display()))?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let mut statement = transaction.prepare(
            r#"INSERT OR IGNORE INTO scan_candidates(
               scan_id, fqdn, relative_name, priority, generator, status
               ) VALUES (?1, ?2, ?3, ?4, 'wordlist', 'queued')"#,
        )?;
        let mut inserted = 0_usize;
        for (rank, line) in std::io::BufReader::new(file).lines().enumerate() {
            let raw = line?;
            let candidate = raw
                .split('#')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if !valid_relative_name(&candidate) {
                continue;
            }
            inserted += statement.execute(params![
                scan_id,
                format!("{candidate}.{domain}"),
                candidate,
                2_000_000_000_i64.saturating_sub(rank as i64),
            ])?;
            if inserted >= limit {
                break;
            }
        }
        drop(statement);
        transaction.commit()?;
        Ok(inserted)
    }

    pub fn persist_prior_candidates_to_scan(
        &self,
        scan_id: i64,
        domain: &str,
        limit: usize,
    ) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let connection = self.lock()?;
        let inserted = connection.execute(
            r#"INSERT OR IGNORE INTO scan_candidates(
                   scan_id, fqdn, relative_name, priority, generator, status
               )
               SELECT ?1, candidate.relative_name || '.' || ?2,
                      candidate.relative_name, candidate.priority - 1000000000,
                      'builtin', 'queued'
               FROM candidate_priors AS candidate
               WHERE NOT EXISTS (
                   SELECT 1 FROM scan_candidates AS queued
                   WHERE queued.scan_id=?1
                     AND queued.relative_name=candidate.relative_name
               )
               ORDER BY candidate.priority DESC, candidate.relative_name
               LIMIT ?3"#,
            params![scan_id, domain, limit.min(i64::MAX as usize) as i64],
        )?;
        Ok(inserted)
    }

    pub fn pending_scan_candidates(
        &self,
        scan_id: i64,
        limit: usize,
    ) -> Result<Vec<(String, String, i64)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let connection = self.lock()?;
        connection.execute(
            "UPDATE scan_candidates SET status='queued' WHERE scan_id=?1 AND status='processing'",
            [scan_id],
        )?;
        let mut statement = connection.prepare(
            r#"SELECT relative_name, generator, priority FROM scan_candidates
               WHERE scan_id=?1 AND status='queued'
               ORDER BY priority DESC, fqdn LIMIT ?2"#,
        )?;
        statement
            .query_map(
                params![scan_id, limit.min(i64::MAX as usize) as i64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn pending_scan_candidate_count(&self, scan_id: i64) -> Result<i64> {
        Ok(self.lock()?.query_row(
            "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1 AND status!='done'",
            [scan_id],
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
                "UPDATE scan_candidates SET status='done' WHERE scan_id=? AND fqdn IN ({placeholders})"
            );
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(scan_id.into());
            values.extend(chunk.iter().cloned().map(Into::into));
            transaction.execute(&sql, rusqlite::params_from_iter(values))?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn clear_scan_candidates(&self, scan_id: i64) -> Result<()> {
        self.lock()?
            .execute("DELETE FROM scan_candidates WHERE scan_id=?1", [scan_id])?;
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
                candidates as i64,
                found as i64,
                cache_hits as i64,
                duration_ms.min(i64::MAX as u128) as i64,
                serde_json::to_string(warnings)?,
                scan_id
            ],
        )?;
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
                    let records = serde_json::from_str(&records_json).unwrap_or_default();
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

    pub fn update_cache(
        &self,
        queried_hosts: &[String],
        resolved: &[ResolvedHost],
        _ttl_cap: u32,
        negative_ttl: u32,
    ) -> Result<()> {
        let now = now_epoch();
        let by_name: HashMap<&str, &ResolvedHost> = resolved
            .iter()
            .map(|answer| (answer.fqdn.as_str(), answer))
            .collect();
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
            for host in queried_hosts {
                if let Some(answer) = by_name.get(host.as_str()) {
                    statement.execute(params![
                        host,
                        "positive",
                        serde_json::to_string(&answer.records)?,
                        PERMANENT_EXPIRY,
                        now,
                        answer.resolver_count,
                        i64::from(answer.authoritative_validation)
                    ])?;
                } else {
                    statement.execute(params![
                        host,
                        "negative",
                        "[]",
                        now + i64::from(negative_ttl.max(30)),
                        now,
                        0,
                        0
                    ])?;
                }
            }
        }
        {
            let mut statement = transaction.prepare(
                r#"INSERT INTO dns_verifications(
                   scan_id, fqdn, checked_at, outcome, resolver_count,
                   authoritative, records_hash, details_json
                   ) VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?6, '{}')"#,
            )?;
            for host in queried_hosts {
                let answer = by_name.get(host.as_str()).copied();
                let records_hash = answer
                    .map(|value| serde_json::to_string(&value.records))
                    .transpose()?
                    .map(|json| domain_hash(&json));
                statement.execute(params![
                    host,
                    now,
                    if answer.is_some() { "live" } else { "negative" },
                    answer
                        .map(|value| i64::from(value.resolver_count))
                        .unwrap_or(1),
                    answer
                        .map(|value| value.authoritative_validation as i64)
                        .unwrap_or_default(),
                    records_hash
                ])?;
            }
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
            let sources = finding
                .sources
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            transaction.execute(
                r#"INSERT INTO subdomains(
                   fqdn, root_domain, first_seen, last_seen, last_scan_id, times_seen, active,
                   sources, verification_state, last_verified_at
                   ) VALUES (?1, ?2, ?3, ?3, ?4, 1, ?5, ?6, ?7, ?8)
                   ON CONFLICT(fqdn) DO UPDATE SET last_seen=excluded.last_seen,
                   last_scan_id=excluded.last_scan_id, times_seen=times_seen+1,
                   active=excluded.active, sources=excluded.sources,
                   verification_state=excluded.verification_state,
                   last_verified_at=COALESCE(excluded.last_verified_at, subdomains.last_verified_at)"#,
                params![
                    finding.fqdn,
                    domain,
                    now,
                    scan_id,
                    i64::from(finding.state == ObservationState::Live),
                    sources,
                    finding.state.as_str(),
                    finding.last_verified_at
                ],
            )?;
            transaction.execute(
                r#"INSERT OR REPLACE INTO scan_findings(
                   scan_id, fqdn, wildcard, from_cache,
                   confidence_score, confidence_label, confidence_reasons_json,
                   state, last_verified_at, evidence_families_json, authoritative_validation
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
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
                    finding.authoritative_validation as i64
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
                       ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
                       ON CONFLICT(fqdn, record_type, value) DO UPDATE SET
                       ttl=excluded.ttl, expires_at=excluded.expires_at,
                       last_seen=excluded.last_seen, active=1"#,
                    params![
                        finding.fqdn,
                        record.record_type,
                        record.value,
                        record.ttl,
                        PERMANENT_EXPIRY,
                        now
                    ],
                )?;
            }
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
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT relative_name FROM candidate_priors
               ORDER BY priority DESC, relative_name ASC LIMIT ?1"#,
        )?;
        statement
            .query_map([limit as i64], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn passive_cache(&self, domain: &str, source: &str) -> Result<Option<PassiveCacheEntry>> {
        let connection = self.lock()?;
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
            let names = serde_json::from_str::<Vec<String>>(&names_json)?
                .into_iter()
                .chain(self.observation_names(domain, &format!("passive:{source}"))?)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            Ok(PassiveCacheEntry { names, updated_at })
        })
        .transpose()
    }

    pub fn store_passive_cache(
        &self,
        domain: &str,
        source: &str,
        names: &[String],
    ) -> Result<Vec<String>> {
        self.store_observations(
            domain,
            names
                .iter()
                .map(|fqdn| ObservationInput {
                    fqdn: fqdn.clone(),
                    kind: "passive".to_owned(),
                    source: format!("passive:{source}"),
                    value: String::new(),
                })
                .collect(),
        )?;
        let connection = self.lock()?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT names_json FROM passive_cache WHERE root_domain=?1 AND source=?2",
                params![domain, source],
                |row| row.get(0),
            )
            .optional()?;
        let legacy = existing
            .as_deref()
            .map(serde_json::from_str::<Vec<String>>)
            .transpose()?
            .unwrap_or_default();
        connection.execute(
            r#"INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
               VALUES (?1, ?2, '[]', ?3)
               ON CONFLICT(root_domain, source) DO UPDATE SET
               updated_at=excluded.updated_at"#,
            params![domain, source, now_epoch()],
        )?;
        drop(connection);
        let merged = legacy
            .into_iter()
            .chain(self.observation_names(domain, &format!("passive:{source}"))?)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(merged)
    }

    pub fn record_source_result(
        &self,
        source: &str,
        names: usize,
        duration_ms: u128,
        error: Option<&str>,
    ) -> Result<()> {
        let success = i64::from(error.is_none());
        let failure = i64::from(error.is_some());
        let connection = self.lock()?;
        connection.execute(
            r#"INSERT INTO source_stats(
               source, requests, successes, failures, consecutive_failures,
               names, total_ms, last_error, last_used
               ) VALUES (?1, 1, ?2, ?3, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(source) DO UPDATE SET
               requests=requests+1,
               successes=successes+excluded.successes,
               failures=failures+excluded.failures,
               consecutive_failures=CASE WHEN excluded.successes=1
                   THEN 0 ELSE consecutive_failures+1 END,
               names=names+excluded.names,
               total_ms=total_ms+excluded.total_ms,
               last_error=excluded.last_error,
               last_used=excluded.last_used"#,
            params![
                source,
                success,
                failure,
                names as i64,
                duration_ms.min(i64::MAX as u128) as i64,
                error,
                now_epoch()
            ],
        )?;
        if error.is_none() {
            connection.execute(
                "DELETE FROM source_metadata_cache WHERE key=?1",
                [format!("source.retry_until.{source}")],
            )?;
        }
        Ok(())
    }

    pub fn source_metadata(
        &self,
        key: &str,
        max_age: std::time::Duration,
    ) -> Result<Option<String>> {
        let threshold = now_epoch().saturating_sub(max_age.as_secs().min(i64::MAX as u64) as i64);
        self.lock()?
            .query_row(
                "SELECT value FROM source_metadata_cache WHERE key=?1 AND updated_at>=?2",
                params![key, threshold],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn store_source_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.lock()?.execute(
            r#"INSERT INTO source_metadata_cache(key, value, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(key) DO UPDATE SET
               value=excluded.value, updated_at=excluded.updated_at"#,
            params![key, value, now_epoch()],
        )?;
        Ok(())
    }

    pub fn source_diagnostics(
        &self,
        cooldown: std::time::Duration,
    ) -> Result<BTreeMap<String, SourceDiagnostic>> {
        let now = now_epoch();
        let cooldown_seconds = cooldown.as_secs().min(i64::MAX as u64) as i64;
        let connection = self.lock()?;
        let mut diagnostics = {
            let mut statement = connection.prepare(
                r#"SELECT source, requests, successes, failures, consecutive_failures,
                   names, CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END,
                   last_error, last_used FROM source_stats ORDER BY source"#,
            )?;
            statement
                .query_map([], |row| {
                    let source = row.get::<_, String>(0)?;
                    let consecutive_failures = row.get::<_, i64>(4)?;
                    let last_used = row.get::<_, i64>(8)?;
                    let retry_at = last_used.saturating_add(cooldown_seconds);
                    let next_retry =
                        (consecutive_failures >= 3 && retry_at > now).then_some(retry_at);
                    Ok((
                        source,
                        SourceDiagnostic {
                            requests: row.get(1)?,
                            successes: row.get(2)?,
                            failures: row.get(3)?,
                            consecutive_failures,
                            names: row.get(5)?,
                            average_ms: row.get(6)?,
                            last_error: row.get(7)?,
                            last_used,
                            next_retry,
                            retry_in_seconds: next_retry.map(|retry| retry.saturating_sub(now)),
                        },
                    ))
                })?
                .collect::<rusqlite::Result<BTreeMap<_, _>>>()?
        };
        let mut statement = connection.prepare(
            "SELECT key, value FROM source_metadata_cache WHERE key LIKE 'source.retry_until.%'",
        )?;
        let retries = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (key, value) in retries {
            let Some(source) = key.strip_prefix("source.retry_until.") else {
                continue;
            };
            let Some(retry_until) = value.parse::<i64>().ok().filter(|retry| *retry > now) else {
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
        }
        Ok(diagnostics)
    }

    pub fn source_cooldowns(&self, cooldown: std::time::Duration) -> Result<BTreeSet<String>> {
        let threshold = now_epoch().saturating_sub(cooldown.as_secs().min(i64::MAX as u64) as i64);
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT source FROM source_stats
               WHERE consecutive_failures>=3 AND last_used>=?1"#,
        )?;
        statement
            .query_map([threshold], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .map_err(Into::into)
    }

    pub fn source_scores(&self) -> Result<HashMap<String, i64>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT source,
               CAST(successes * 1000 / MAX(requests, 1) AS INTEGER)
               + MIN(CAST(names * 10 / MAX(successes, 1) AS INTEGER), 500)
               - MIN(CAST(total_ms / MAX(requests, 1) / 100 AS INTEGER), 300)
               AS score
               FROM source_stats"#,
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(Into::into)
    }

    pub fn generator_scores(&self, domain: &str) -> Result<HashMap<String, i64>> {
        let connection = self.lock()?;
        let mut scores = [
            "environment-swap",
            "number-neighbor",
            "token-order",
            "service-environment",
        ]
        .into_iter()
        .map(|generator| (generator.to_owned(), 650_i64))
        .collect::<HashMap<_, _>>();
        let contexts = candidate_contexts(&connection, domain)?;
        let context_set = contexts.iter().cloned().collect::<BTreeSet<_>>();
        let mut statement = connection.prepare(
            r#"SELECT context, generator, alpha, beta, pulls
               FROM generator_bandits"#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        for row in rows {
            let (bandit_context, generator, alpha, beta, pulls) = row?;
            if !context_set.contains(&bandit_context) {
                continue;
            }
            let total = (alpha + beta).max(1.0);
            let mean = alpha / total;
            let uncertainty = (alpha * beta / (total * total * (total + 1.0))).sqrt();
            let exploration = if pulls < 5 { 0.35 } else { 0.12 };
            let posterior_score =
                ((mean + exploration * uncertainty).min(1.0) * 1_000.0).round() as i64;
            let weight = match bandit_context.split(':').next().unwrap_or_default() {
                "global" | "depth" => 1,
                "suffix" | "registrable" | "provider" => 2,
                _ => 1,
            };
            *scores.entry(generator).or_default() += posterior_score * weight;
        }
        Ok(scores)
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
        let source = format!("tls:{endpoint}:{port}");
        row.map(|(fingerprint_sha256, names_json, updated_at)| {
            let names = serde_json::from_str::<Vec<String>>(&names_json)?
                .into_iter()
                .chain(self.observation_names(domain, &source)?)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
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
        let existing: Option<String> = connection
            .query_row(
                r#"SELECT names_json FROM tls_certificate_cache
                   WHERE root_domain=?1 AND endpoint=?2 AND port=?3"#,
                params![domain, endpoint, i64::from(port)],
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
            r#"INSERT INTO tls_certificate_cache(
               root_domain, endpoint, port, fingerprint_sha256, names_json, updated_at
               ) VALUES (?1, ?2, ?3, ?4, '[]', ?5)
               ON CONFLICT(root_domain, endpoint, port) DO UPDATE SET
               fingerprint_sha256=excluded.fingerprint_sha256,
               updated_at=excluded.updated_at"#,
            params![
                domain,
                endpoint,
                i64::from(port),
                fingerprint_sha256,
                updated_at
            ],
        )?;
        drop(connection);
        let merged = legacy
            .into_iter()
            .chain(self.observation_names(domain, &source)?)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(TlsCacheEntry {
            fingerprint_sha256: fingerprint_sha256.to_owned(),
            names: merged,
            updated_at,
        })
    }

    pub fn web_cache(&self, domain: &str, url: &str) -> Result<Option<WebCacheEntry>> {
        let connection = self.lock()?;
        let row: Option<WebCacheRow> = connection
            .query_row(
                r#"SELECT status, names_json, updated_at, etag, last_modified, content_hash
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
                    ))
                },
            )
            .optional()?;
        drop(connection);
        row.map(
            |(status, names_json, updated_at, etag, last_modified, content_hash)| {
                let names = serde_json::from_str::<Vec<String>>(&names_json)?
                    .into_iter()
                    .chain(self.observation_names(domain, &format!("web:{url}"))?)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                Ok(WebCacheEntry {
                    status: u16::try_from(status).unwrap_or_default(),
                    names,
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
        let existing: Option<WebMetadataRow> = connection
            .query_row(
                r#"SELECT names_json, etag, last_modified, content_hash FROM web_discovery_cache
                   WHERE root_domain=?1 AND url=?2"#,
                params![domain, url],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let legacy = existing
            .as_ref()
            .map(|value| value.0.as_str())
            .map(serde_json::from_str::<Vec<String>>)
            .transpose()?
            .unwrap_or_default();
        let updated_at = now_epoch();
        connection.execute(
            r#"INSERT INTO web_discovery_cache(
               root_domain, url, status, names_json, updated_at,
               etag, last_modified, content_hash
               ) VALUES (?1, ?2, ?3, '[]', ?4, ?5, ?6, ?7)
               ON CONFLICT(root_domain, url) DO UPDATE SET
               status=excluded.status, updated_at=excluded.updated_at,
               etag=COALESCE(excluded.etag, web_discovery_cache.etag),
               last_modified=COALESCE(excluded.last_modified, web_discovery_cache.last_modified),
               content_hash=COALESCE(excluded.content_hash, web_discovery_cache.content_hash)"#,
            params![
                domain,
                url,
                i64::from(status),
                updated_at,
                metadata.etag.as_deref(),
                metadata.last_modified.as_deref(),
                metadata.content_hash.as_deref()
            ],
        )?;
        drop(connection);
        let merged = legacy
            .into_iter()
            .chain(self.observation_names(domain, &format!("web:{url}"))?)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Ok(WebCacheEntry {
            status,
            names: merged,
            updated_at,
            etag: metadata
                .etag
                .clone()
                .or_else(|| existing.as_ref().and_then(|value| value.1.clone())),
            last_modified: metadata
                .last_modified
                .clone()
                .or_else(|| existing.as_ref().and_then(|value| value.2.clone())),
            content_hash: metadata
                .content_hash
                .clone()
                .or_else(|| existing.as_ref().and_then(|value| value.3.clone())),
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

    pub fn store_ct_global_batch(
        &self,
        log_url: &str,
        next: u64,
        names: &BTreeSet<String>,
    ) -> Result<()> {
        let now = now_epoch();
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            r#"INSERT INTO ct_global_state(log_url, next_index, updated_at)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(log_url) DO UPDATE SET
               next_index=excluded.next_index, updated_at=excluded.updated_at"#,
            params![log_url, next.min(i64::MAX as u64) as i64, now],
        )?;
        for name in names {
            transaction.execute(
                r#"INSERT INTO ct_names(
                   fqdn, reversed_name, first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?3, 1)
                   ON CONFLICT(fqdn) DO UPDATE SET
                   last_seen=excluded.last_seen, times_seen=ct_names.times_seen+1"#,
                params![name, reverse_hostname(name), now],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn ct_names_for_domain(&self, domain: &str, limit: usize) -> Result<Vec<String>> {
        let reversed = reverse_hostname(domain);
        let prefix = format!("{reversed}.%");
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT fqdn FROM ct_names
               WHERE reversed_name LIKE ?1 ESCAPE '\'
               ORDER BY last_seen DESC, fqdn ASC LIMIT ?2"#,
        )?;
        statement
            .query_map(params![prefix, limit as i64], |row| row.get::<_, String>(0))?
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

    pub fn inventory(&self, domain: Option<&str>, only_live: bool) -> Result<Vec<InventoryEntry>> {
        let connection = self.lock()?;
        let mut conditions = Vec::new();
        if domain.is_some() {
            conditions.push("root_domain=?1");
        }
        if only_live {
            conditions.push("verification_state='live'");
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
        if inventory.is_none() {
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
            r#"SELECT source, requests, successes, failures, consecutive_failures, names,
               CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END AS average_ms,
               last_error, last_used
               FROM source_stats ORDER BY successes DESC, names DESC, source ASC"#,
        )?;
        let source_stats = source_stats_statement
            .query_map([], |row| {
                Ok(json!({
                    "source": row.get::<_, String>(0)?,
                    "requests": row.get::<_, i64>(1)?,
                    "successes": row.get::<_, i64>(2)?,
                    "failures": row.get::<_, i64>(3)?,
                    "consecutive_failures": row.get::<_, i64>(4)?,
                    "names": row.get::<_, i64>(5)?,
                    "average_ms": row.get::<_, i64>(6)?,
                    "last_error": row.get::<_, Option<String>>(7)?,
                    "last_used": row.get::<_, i64>(8)?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DnsRecord;

    #[test]
    fn v7_to_v8_preserves_5239_names_and_creates_a_consistent_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fellaga.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE subdomains (
                    fqdn TEXT PRIMARY KEY,
                    root_domain TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    last_scan_id INTEGER,
                    times_seen INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    sources TEXT NOT NULL
                );
                WITH RECURSIVE counter(value) AS (
                    SELECT 1 UNION ALL SELECT value + 1 FROM counter WHERE value < 5239
                )
                INSERT INTO subdomains(
                    fqdn, root_domain, first_seen, last_seen, times_seen, active, sources
                )
                SELECT printf('host-%d.example.com', value), 'example.com', 1, 2, 1,
                       CASE WHEN value % 10 = 0 THEN 0 ELSE 1 END, 'legacy'
                FROM counter;
                PRAGMA user_version=7;
                "#,
            )
            .unwrap();
        drop(connection);

        let db = Database::open(&path).unwrap();
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM subdomains", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            5_239
        );
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT verification_state FROM subdomains WHERE fqdn='host-10.example.com'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "historical"
        );
        drop(connection);
        drop(db);

        let backup = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("fellaga.db.pre-v8-"))
            })
            .expect("une sauvegarde pré-v8 doit exister");
        let backup_connection = Connection::open(backup).unwrap();
        assert_eq!(
            backup_connection
                .query_row("SELECT COUNT(*) FROM subdomains", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            5_239
        );
        assert_eq!(
            backup_connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            7
        );
    }

    #[test]
    fn version_six_database_is_normalized_once_without_losing_legacy_names() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE passive_cache (
                    root_domain TEXT NOT NULL,
                    source TEXT NOT NULL,
                    names_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(root_domain, source)
                );
                INSERT INTO passive_cache(root_domain, source, names_json, updated_at)
                VALUES ('example.com', 'crtsh', '["api.example.com"]', 1);
                PRAGMA user_version=6;
                "#,
            )
            .unwrap();
        drop(connection);

        let db = Database::open(temporary.path()).unwrap();
        assert_eq!(
            db.observation_names("example.com", "passive:crtsh")
                .unwrap(),
            vec!["api.example.com"]
        );
        assert_eq!(
            db.passive_cache("example.com", "crtsh")
                .unwrap()
                .unwrap()
                .names,
            vec!["api.example.com"]
        );
        let connection = db.lock().unwrap();
        let (version, migrations): (i64, i64) = (
            connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            connection
                .query_row(
                    "SELECT COUNT(*) FROM migration_state WHERE name='normalized-v7'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
        );
        assert_eq!(version, 8);
        assert_eq!(migrations, 1);
    }

    #[test]
    fn positive_cache_is_permanent_and_negative_cache_can_expire() {
        let db = Database::in_memory().unwrap();
        let hosts = vec!["www.example.com".to_owned(), "none.example.com".to_owned()];
        let answers = vec![ResolvedHost {
            fqdn: hosts[0].clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.1".to_owned(),
                ttl: 600,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: true,
            resolver_count: 3,
        }];
        db.update_cache(&hosts, &answers, 86_400, 300).unwrap();
        let positive_expiry = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT expires_at FROM dns_cache WHERE fqdn=?1",
                [&hosts[0]],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(positive_expiry, PERMANENT_EXPIRY);

        db.lock()
            .unwrap()
            .execute("UPDATE dns_cache SET expires_at=0", [])
            .unwrap();
        let cached = db.fresh_cache(&hosts).unwrap();
        assert!(matches!(cached[&hosts[0]], CachedAnswer::Positive(_)));
        let CachedAnswer::Positive(cached_positive) = &cached[&hosts[0]] else {
            unreachable!();
        };
        assert!(cached_positive.authoritative_validation);
        assert_eq!(cached_positive.resolver_count, 3);
        assert!(!cached.contains_key(&hosts[1]));
        assert_eq!(db.prune_cache().unwrap(), 1);

        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let finding = Finding {
            fqdn: hosts[0].clone(),
            records: answers[0].records.clone(),
            sources: BTreeSet::from(["test".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["test".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: answers[0].last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: false,
        };
        let expected_confidence = finding.confidence.score;
        db.persist_findings(scan_id, "example.com", &[finding], 86_400)
            .unwrap();
        let record_expiry = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT expires_at FROM dns_records WHERE fqdn=?1",
                [&hosts[0]],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(record_expiry, PERMANENT_EXPIRY);
        let confidence = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT confidence_score FROM scan_findings WHERE scan_id=?1 AND fqdn=?2",
                params![scan_id, hosts[0]],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(confidence, i64::from(expected_confidence));
    }

    #[test]
    fn dns_validation_journal_is_append_only() {
        let db = Database::in_memory().unwrap();
        let host = "api.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: host.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.10".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: true,
            resolver_count: 3,
        };
        db.update_cache(std::slice::from_ref(&host), &[answer], 60, 30)
            .unwrap();
        let connection = db.lock().unwrap();
        let id: i64 = connection
            .query_row("SELECT id FROM dns_verifications LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(
            connection
                .execute(
                    "UPDATE dns_verifications SET status='negative' WHERE id=?1",
                    [id]
                )
                .is_err()
        );
        assert!(
            connection
                .execute("DELETE FROM dns_verifications WHERE id=?1", [id])
                .is_err()
        );
    }

    #[test]
    fn scan_candidates_are_loaded_in_bounded_persistent_batches() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[("priority".to_owned(), "mutation".to_owned(), 10)],
        )
        .unwrap();
        db.persist_prior_candidates_to_scan(scan_id, "example.com", 5)
            .unwrap();
        assert_eq!(db.pending_scan_candidates(scan_id, 2).unwrap().len(), 2);
        let first = db.pending_scan_candidates(scan_id, 1).unwrap();
        assert_eq!(first[0].0, "priority");
        db.mark_scan_candidates_done(scan_id, &[format!("{}.example.com", first[0].0)])
            .unwrap();
        assert_eq!(
            db.pending_scan_candidate_count(scan_id).unwrap(),
            db.scan_candidate_count(scan_id).unwrap() - 1
        );
        db.clear_scan_candidates(scan_id).unwrap();
        assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 0);
    }

    #[test]
    fn wordlists_are_streamed_deduplicated_and_bounded_in_sqlite() {
        let directory = tempfile::tempdir().unwrap();
        let wordlist = directory.path().join("words.txt");
        std::fs::write(&wordlist, "www\napi\nwww\ninvalid name\nadmin\n").unwrap();
        let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        assert_eq!(
            db.persist_wordlist_candidates(scan_id, "example.com", &wordlist, 2)
                .unwrap(),
            2
        );
        let candidates = db.pending_scan_candidates(scan_id, 10).unwrap();
        assert_eq!(
            candidates
                .into_iter()
                .map(|(name, _, _)| name)
                .collect::<Vec<_>>(),
            vec!["www", "api"]
        );
    }

    #[test]
    fn imported_names_remain_unverified_after_reopening_v8() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        {
            let db = Database::open(temporary.path()).unwrap();
            db.import_inventory(
                "example.com",
                &BTreeSet::from(["api.example.com".to_owned()]),
                "import:test",
            )
            .unwrap();
        }
        let reopened = Database::open(temporary.path()).unwrap();
        let inventory = reopened.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state, ObservationState::Unverified);
        assert_eq!(inventory[0].last_verified_at, None);
    }

    #[test]
    fn legacy_empty_and_failed_axfr_rows_are_reclassified() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        {
            let db = Database::open(temporary.path()).unwrap();
            let scan_id = db.create_scan("example.com", &json!({})).unwrap();
            let connection = db.lock().unwrap();
            connection
                .execute(
                    r#"INSERT INTO axfr_attempts(
                       scan_id, nameserver, address, status, error, record_count, attempted_at
                       ) VALUES (?1, 'ns1.example.com', '192.0.2.53', 'success', NULL, 0, 1)"#,
                    [scan_id],
                )
                .unwrap();
            connection
                .execute(
                    r#"INSERT INTO axfr_attempts(
                       scan_id, nameserver, address, status, error, record_count, attempted_at
                       ) VALUES (?1, 'ns2.example.com', '192.0.2.54', 'failed', 'proto error', 0, 1)"#,
                    [scan_id],
                )
                .unwrap();
        }
        let reopened = Database::open(temporary.path()).unwrap();
        let statuses = reopened
            .lock()
            .unwrap()
            .prepare("SELECT status FROM axfr_attempts ORDER BY nameserver")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(statuses, vec!["empty", "protocol_error"]);
    }

    #[test]
    fn permanent_knowledge_keeps_words_patterns_and_passive_results() {
        let db = Database::in_memory().unwrap();
        let attempted = BTreeSet::from(["api".to_owned(), "dev".to_owned()]);
        let successful = BTreeSet::from(["api".to_owned()]);
        db.record_word_results("example.com", &attempted, &successful)
            .unwrap();
        db.record_patterns("example.com", &BTreeSet::from(["api.dev".to_owned()]))
            .unwrap();
        db.store_passive_cache("example.com", "crtsh", &["deep.api.example.com".to_owned()])
            .unwrap();
        db.store_passive_cache("example.com", "crtsh", &[]).unwrap();
        db.store_passive_cache("example.com", "crtsh", &["www.example.com".to_owned()])
            .unwrap();

        assert_eq!(db.ranked_words(1).unwrap(), vec!["api"]);
        assert_eq!(db.ranked_patterns(1).unwrap(), vec!["api.dev"]);
        assert_eq!(
            db.passive_cache("example.com", "crtsh")
                .unwrap()
                .unwrap()
                .names,
            vec!["deep.api.example.com", "www.example.com"]
        );
    }

    #[test]
    fn tls_cache_keeps_the_union_of_all_certificate_names() {
        let db = Database::in_memory().unwrap();
        db.store_tls_cache(
            "example.com",
            "www.example.com",
            443,
            "old-fingerprint",
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        db.store_tls_cache(
            "example.com",
            "www.example.com",
            443,
            "new-fingerprint",
            &BTreeSet::from(["admin.example.com".to_owned()]),
        )
        .unwrap();

        let cached = db
            .tls_cache("example.com", "www.example.com", 443)
            .unwrap()
            .unwrap();
        assert_eq!(cached.fingerprint_sha256, "new-fingerprint");
        assert_eq!(cached.names, vec!["admin.example.com", "api.example.com"]);
    }

    #[test]
    fn discovery_graph_is_persistent_and_counts_repeated_evidence() {
        let db = Database::in_memory().unwrap();
        let edges = BTreeSet::from([DiscoveryEdge {
            owner: "example.com".to_owned(),
            record_type: "MX".to_owned(),
            value: "10 mail.example.com".to_owned(),
            target: Some("mail.example.com".to_owned()),
        }]);
        let services = BTreeSet::from([ServiceEndpoint {
            hostname: "mail.example.com".to_owned(),
            port: 25,
            transport: "smtp-starttls".to_owned(),
            source: "dns-mx:example.com".to_owned(),
        }]);
        let zones = BTreeSet::from(["prod.example.com".to_owned()]);
        db.store_discovery_graph("example.com", &edges, &services, &zones)
            .unwrap();
        db.store_discovery_graph("example.com", &edges, &services, &zones)
            .unwrap();

        let connection = db.lock().unwrap();
        let times_seen = connection
            .query_row("SELECT times_seen FROM discovery_edges", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(times_seen, 2);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM service_endpoints", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM child_zones", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
    }

    #[test]
    fn web_and_dnssec_caches_keep_the_union_of_observed_names() {
        let db = Database::in_memory().unwrap();
        db.store_web_cache(
            "example.com",
            "https://www.example.com/",
            200,
            &BTreeSet::from(["api.example.com".to_owned()]),
            &WebCacheMetadata {
                etag: Some("etag-1".to_owned()),
                last_modified: None,
                content_hash: Some("hash-1".to_owned()),
            },
        )
        .unwrap();
        db.store_web_cache(
            "example.com",
            "https://www.example.com/",
            304,
            &BTreeSet::from(["static.example.com".to_owned()]),
            &WebCacheMetadata {
                etag: Some("etag-2".to_owned()),
                last_modified: None,
                content_hash: Some("hash-2".to_owned()),
            },
        )
        .unwrap();
        let web = db
            .web_cache("example.com", "https://www.example.com/")
            .unwrap()
            .unwrap();
        assert_eq!(web.status, 304);
        assert_eq!(web.names, vec!["api.example.com", "static.example.com"]);

        db.store_dnssec_cache(
            "example.com",
            "example.com",
            "ns1.example.com",
            "partial",
            &BTreeSet::from(["a.example.com".to_owned()]),
        )
        .unwrap();
        db.store_dnssec_cache(
            "example.com",
            "example.com",
            "ns2.example.com",
            "walked",
            &BTreeSet::from(["b.example.com".to_owned()]),
        )
        .unwrap();
        let dnssec = db
            .dnssec_cache("example.com", "example.com")
            .unwrap()
            .unwrap();
        assert_eq!(dnssec.status, "walked");
        assert_eq!(dnssec.names, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn generator_context_and_ct_cursor_are_persistent() {
        let db = Database::in_memory().unwrap();
        db.store_discovery_graph(
            "example.com",
            &BTreeSet::from([DiscoveryEdge {
                owner: "example.com".to_owned(),
                record_type: "NS".to_owned(),
                value: "alice.ns.cloudflare.com".to_owned(),
                target: None,
            }]),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
        let attempts = HashMap::from([("environment-swap".to_owned(), 5_usize)]);
        let successes = HashMap::from([("environment-swap".to_owned(), 2_usize)]);
        db.record_generator_results("example.com", &attempts, &successes)
            .unwrap();
        db.record_generator_results("another.com", &attempts, &successes)
            .unwrap();
        let score = db
            .generator_scores("third.com")
            .unwrap()
            .get("environment-swap")
            .copied()
            .unwrap_or_default();
        assert!(score > 0);
        let provider_bandit = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM generator_bandits WHERE context='provider:cloudflare'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(provider_bandit, 1);

        db.store_ct_global_batch(
            "https://ct.example/",
            42,
            &BTreeSet::from(["api.example.com".to_owned(), "www.example.net".to_owned()]),
        )
        .unwrap();
        assert_eq!(
            db.ct_global_cursor("https://ct.example/").unwrap(),
            Some(42)
        );
        assert_eq!(
            db.ct_names_for_domain("example.com", 10).unwrap(),
            vec!["api.example.com"]
        );
    }

    #[test]
    fn wildcard_and_normalized_observations_are_persistent() {
        let db = Database::in_memory().unwrap();
        db.store_wildcard_cache(
            "example.com",
            &BTreeSet::from(["A:*".to_owned()]),
            Some(42),
            std::time::Duration::from_secs(600),
            true,
        )
        .unwrap();
        let wildcard = db.wildcard_cache("example.com").unwrap().unwrap();
        assert_eq!(wildcard.soa_serial, Some(42));
        assert!(wildcard.signature.contains("A:*"));

        db.store_observations(
            "example.com",
            vec![ObservationInput {
                fqdn: "api.example.com".to_owned(),
                kind: "web".to_owned(),
                source: "web:https://www.example.com/".to_owned(),
                value: "hash".to_owned(),
            }],
        )
        .unwrap();
        assert_eq!(
            db.observation_names("example.com", "web:https://www.example.com/")
                .unwrap(),
            vec!["api.example.com"]
        );

        db.store_resolver_metrics(&[ResolverMetric {
            resolver: "1.1.1.1".to_owned(),
            requests: 10,
            successes: 9,
            failures: 1,
            average_ms: 12,
            consecutive_failures: 0,
        }])
        .unwrap();
        let resolver = db.resolver_history().unwrap().remove("1.1.1.1").unwrap();
        assert_eq!(resolver.requests, 10);
        assert_eq!(resolver.average_ms, 12);
    }

    #[test]
    fn failing_automatic_sources_enter_cooldown_and_recover() {
        let db = Database::in_memory().unwrap();
        for _ in 0..3 {
            db.record_source_result("slow", 0, 20_000, Some("timeout"))
                .unwrap();
        }
        assert!(
            db.source_cooldowns(std::time::Duration::from_secs(86_400))
                .unwrap()
                .contains("slow")
        );
        let diagnostic = db
            .source_diagnostics(std::time::Duration::from_secs(86_400))
            .unwrap()
            .remove("slow")
            .unwrap();
        assert_eq!(diagnostic.consecutive_failures, 3);
        assert!(diagnostic.next_retry.is_some());
        assert_eq!(diagnostic.last_error.as_deref(), Some("timeout"));

        db.store_source_metadata(
            "commoncrawl.latest_endpoint",
            "https://index.commoncrawl.org/x",
        )
        .unwrap();
        assert_eq!(
            db.source_metadata(
                "commoncrawl.latest_endpoint",
                std::time::Duration::from_secs(3_600)
            )
            .unwrap()
            .as_deref(),
            Some("https://index.commoncrawl.org/x")
        );
        db.store_source_metadata(
            "source.retry_until.slow",
            &now_epoch().saturating_add(7_200).to_string(),
        )
        .unwrap();
        assert!(
            db.source_diagnostics(std::time::Duration::from_secs(60))
                .unwrap()["slow"]
                .retry_in_seconds
                .is_some_and(|seconds| seconds > 7_000)
        );
        db.record_source_result("slow", 4, 100, None).unwrap();
        assert!(
            !db.source_cooldowns(std::time::Duration::from_secs(86_400))
                .unwrap()
                .contains("slow")
        );
        assert!(
            db.source_diagnostics(std::time::Duration::from_secs(86_400))
                .unwrap()["slow"]
                .next_retry
                .is_none()
        );
    }
}
