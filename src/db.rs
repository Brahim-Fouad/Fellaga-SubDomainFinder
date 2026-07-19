use crate::confidence::evidence_family;
use crate::model::{
    AxfrAttempt, DiscoveryEdge, EvidenceFamily, Finding, InventoryEntry, ObservationState,
    ResolvedHost, ResolverMetric, ServiceEndpoint, Stats, WildcardVerdict,
};
use crate::util::{
    domain_hash, learnable_label, learnable_relative_name, normalize_hostname,
    normalize_observed_name, now_epoch, public_suffix, registrable_domain, reverse_hostname,
    valid_relative_name,
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const PERMANENT_EXPIRY: i64 = i64::MAX;
const MAX_SCHEDULER_OUTCOMES: usize = 4_096;
const MAX_SCHEDULER_GENERATORS: usize = 1_024;
const MAX_SCHEDULER_COUNT_DELTA: u64 = 10_000_000;
const MAX_SCHEDULER_COST_DELTA: f64 = 1_000_000_000_000.0;
const MAX_SCHEDULER_TOTAL: f64 = 1_000_000_000_000_000.0;
const MAX_DISCOVERY_ACTIONS: usize = 4_096;
const MAX_DISCOVERY_ACTION_CLAIM: usize = 512;
const MAX_DISCOVERY_OUTCOME_JSON: usize = 64 * 1024;
const MAX_NAMED_SEED_CLAIM: usize = 4_096;
const MAX_IP_HOSTNAME_CACHE_NAMES: usize = 4_096;
const MAX_PASSIVE_PAGINATION_IDENTIFIER: usize = 128;
const PASSIVE_PAGINATION_HASH_LENGTH: usize = 64;
// Refresh generations are operational restart state, not observations. After
// three months an unfinished generation is closed and numeric progress is
// reset, while every discovered name and evidence row remains permanent.
const PASSIVE_REFRESH_ABANDONED_AFTER_SECS: i64 = 90 * 24 * 60 * 60;
const PASSIVE_REFRESH_GC_BATCH: usize = 256;
const PASSIVE_REFRESH_LEASE_GC_BATCH: usize = 256;
const CT_MATERIALIZATION_PAGE_SIZE: usize = 128;
const CT_MATERIALIZATION_LOCK_RETRY: Duration = Duration::from_millis(2);
const CT_COMMIT_HASH_CHUNK_SIZE: usize = 64 * 1024;
const CT_COMMIT_SQLITE_BUSY_MAX: Duration = Duration::from_millis(25);
const CURRENT_SCAN_WILDCARD_MATCH_DETAILS: &str =
    r#"{"network_positive":true,"reason":"current_scan_wildcard_match"}"#;
const CURRENT_SCAN_WILDCARD_AMBIGUITY_DETAILS: &str =
    r#"{"network_positive":true,"reason":"wildcard_profile_ambiguous"}"#;

fn usize_to_i64_saturating(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn validate_passive_pagination_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_PASSIVE_PAGINATION_IDENTIFIER
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
    {
        bail!("identifiant {field} invalide pour la pagination passive");
    }
    Ok(())
}

fn validate_ip_hostname_provider(provider: &str) -> Result<()> {
    if provider.is_empty()
        || provider.len() > 64
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("identifiant de fournisseur IP invalide");
    }
    Ok(())
}

fn validate_passive_pagination_hash(value: &str, field: &str) -> Result<()> {
    if value.len() != PASSIVE_PAGINATION_HASH_LENGTH
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("{field} invalide pour la pagination passive");
    }
    Ok(())
}

fn validate_passive_pagination_key(
    root_domain: &str,
    source: &str,
    lane: &str,
    contract_version: u32,
    query_hash: &str,
) -> Result<()> {
    if root_domain.is_empty()
        || root_domain.len() > 253
        || root_domain.starts_with('.')
        || root_domain.ends_with('.')
        || !root_domain.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
    {
        bail!("domaine invalide pour la pagination passive");
    }
    validate_passive_pagination_identifier(source, "source")?;
    validate_passive_pagination_identifier(lane, "lane")?;
    if contract_version == 0 {
        bail!("version de contrat nulle pour la pagination passive");
    }
    validate_passive_pagination_hash(query_hash, "hash de requête")
}

fn passive_pagination_counter(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value)
        .with_context(|| format!("compteur {field} trop grand pour la pagination passive"))
}

fn is_strict_subdomain(fqdn: &str, root_domain: &str) -> bool {
    fqdn.strip_suffix(root_domain)
        .is_some_and(|prefix| !prefix.is_empty() && prefix.ends_with('.'))
}

fn ensure_ct_materialization_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        bail!(
            "budget de matérialisation CT atteint; traitement reporté sans supprimer le cache permanent"
        );
    }
    Ok(())
}

fn ensure_ct_materialization_active(
    deadline: Option<Instant>,
    cancellation: &AtomicBool,
) -> Result<()> {
    if cancellation.load(Ordering::Acquire) {
        bail!("matérialisation CT annulée; traitement reporté sans supprimer le cache permanent");
    }
    ensure_ct_materialization_deadline(deadline)
}

fn ct_payload_sha256_until_cancelled(
    payload: &[u8],
    deadline: Option<Instant>,
    cancellation: &AtomicBool,
) -> Result<String> {
    ensure_ct_materialization_active(deadline, cancellation)?;
    let mut digest = Sha256::new();
    for chunk in payload.chunks(CT_COMMIT_HASH_CHUNK_SIZE) {
        ensure_ct_materialization_active(deadline, cancellation)?;
        digest.update(chunk);
    }
    ensure_ct_materialization_active(deadline, cancellation)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn with_ct_commit_busy_timeout<T, F>(
    connection: &mut Connection,
    deadline: Option<Instant>,
    operation: F,
) -> Result<T>
where
    F: FnOnce(&mut Connection) -> Result<T>,
{
    let busy_timeout = deadline
        .map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(CT_COMMIT_SQLITE_BUSY_MAX)
                .max(Duration::from_millis(1))
        })
        .unwrap_or(CT_COMMIT_SQLITE_BUSY_MAX);
    connection.busy_timeout(busy_timeout)?;
    let result = operation(connection);
    let restore = connection
        .busy_timeout(Duration::from_secs(5))
        .context("restauration du delai SQLite apres commit CT");
    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn has_current_scan_wildcard_match(
    transaction: &rusqlite::Transaction<'_>,
    scan_id: i64,
    fqdn: &str,
) -> Result<bool> {
    Ok(transaction
        .query_row(
            r#"SELECT 1
               FROM dns_verifications verification
               JOIN scans scan ON scan.id=verification.scan_id
               WHERE verification.scan_id=?1 AND verification.fqdn=?2
                  AND verification.outcome='unverified'
                  AND (verification.resolver_count>=2 OR verification.authoritative<>0)
                  AND verification.records_hash IS NOT NULL
                  AND verification.details_json=?3
                  AND verification.checked_at>=scan.started_at
                  AND scan.status='running'
               LIMIT 1"#,
            params![scan_id, fqdn, CURRENT_SCAN_WILDCARD_MATCH_DETAILS],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn canonical_dns_records_hash(records: &[crate::model::DnsRecord]) -> Result<String> {
    let mut canonical = records
        .iter()
        .map(|record| {
            (
                record.record_type.trim().to_ascii_uppercase(),
                record.value.trim().to_owned(),
            )
        })
        .collect::<Vec<_>>();
    canonical.sort();
    canonical.dedup();
    Ok(domain_hash(&serde_json::to_string(&canonical)?))
}

fn wildcard_cleanup_evidence_is_independent(kind: &str, source: &str) -> bool {
    matches!(
        evidence_family(source),
        Some(family) if family != EvidenceFamily::LiveDns
    ) || matches!(kind, "passive" | "web" | "tls" | "dnssec" | "import")
        || source == "import"
        || source.starts_with("import:")
}

type WildcardCleanupEvidence = (
    HashMap<String, BTreeSet<String>>,
    HashMap<String, BTreeSet<String>>,
);

fn wildcard_cleanup_evidence_for_hosts(
    transaction: &rusqlite::Transaction<'_>,
    root_domain: &str,
    hosts: &[String],
) -> Result<WildcardCleanupEvidence> {
    let mut stored_sources = HashMap::<String, BTreeSet<String>>::new();
    let mut independent_sources = HashMap::<String, BTreeSet<String>>::new();
    if hosts.is_empty() {
        return Ok((stored_sources, independent_sources));
    }

    let placeholders = std::iter::repeat_n("?", hosts.len())
        .collect::<Vec<_>>()
        .join(",");
    let mut inventory_values = Vec::<rusqlite::types::Value>::with_capacity(hosts.len() + 1);
    inventory_values.push(root_domain.to_owned().into());
    inventory_values.extend(hosts.iter().cloned().map(Into::into));

    {
        let sql = format!(
            "SELECT fqdn, sources FROM subdomains WHERE root_domain=? AND fqdn IN ({placeholders})"
        );
        let mut statement = transaction.prepare(&sql)?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(inventory_values.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
        for row in rows {
            let (fqdn, sources) = row?;
            let all = sources
                .split(',')
                .filter(|source| !source.is_empty())
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>();
            for source in &all {
                if wildcard_cleanup_evidence_is_independent("", source) {
                    independent_sources
                        .entry(fqdn.clone())
                        .or_default()
                        .insert(source.clone());
                }
            }
            stored_sources.insert(fqdn, all);
        }
    }

    {
        let sql = format!(
            r#"SELECT names.fqdn, evidence.kind, evidence.source
               FROM observation_evidence evidence
               JOIN observed_names names ON names.id=evidence.name_id
               WHERE names.fqdn IN ({placeholders})"#
        );
        let evidence_values = hosts
            .iter()
            .cloned()
            .map(rusqlite::types::Value::from)
            .collect::<Vec<_>>();
        let mut statement = transaction.prepare(&sql)?;
        let rows =
            statement.query_map(rusqlite::params_from_iter(evidence_values.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
        for row in rows {
            let (fqdn, kind, source) = row?;
            if wildcard_cleanup_evidence_is_independent(&kind, &source) {
                independent_sources.entry(fqdn).or_default().insert(source);
            }
        }
    }

    Ok((stored_sources, independent_sources))
}

fn quarantine_wildcard_host(
    transaction: &rusqlite::Transaction<'_>,
    root_domain: &str,
    fqdn: &str,
    scan_id: i64,
    reason: &str,
    quarantined_at: i64,
) -> Result<()> {
    transaction.execute(
        r#"INSERT INTO wildcard_quarantine(
               root_domain, fqdn, scan_id, reason, quarantined_at
           ) VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT(root_domain, fqdn) DO UPDATE SET
               scan_id=excluded.scan_id,
               reason=excluded.reason,
               quarantined_at=excluded.quarantined_at"#,
        params![root_domain, fqdn, scan_id, reason, quarantined_at],
    )?;
    transaction.execute("DELETE FROM dns_cache WHERE fqdn=?1", [fqdn])?;
    let inventory_changed = transaction.execute(
        r#"UPDATE subdomains
           SET active=0, verification_state='unverified', last_verified_at=NULL
           WHERE root_domain=?1 AND fqdn=?2"#,
        params![root_domain, fqdn],
    )?;
    if inventory_changed > 0 {
        transaction.execute("UPDATE dns_records SET active=0 WHERE fqdn=?1", [fqdn])?;
    }
    Ok(())
}

#[cfg(unix)]
fn sqlite_companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(unix)]
fn directory_is_dedicated_to_database(parent: &Path, path: &Path) -> bool {
    let Some(database_name) = path.file_name() else {
        return false;
    };
    if parent
        .file_name()
        .is_some_and(|name| name == "fellaga" || name == ".fellaga")
    {
        return true;
    }

    let mut allowed_names = vec![database_name.to_os_string()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = database_name.to_os_string();
        name.push(suffix);
        allowed_names.push(name);
    }
    let backup_prefix_v8 = database_name.to_str().map(|name| format!("{name}.pre-v8-"));
    let backup_prefix_v9 = database_name.to_str().map(|name| format!("{name}.pre-v9-"));

    let Ok(entries) = std::fs::read_dir(parent) else {
        return false;
    };
    entries.into_iter().all(|entry| {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        allowed_names.contains(&name)
            || [backup_prefix_v8.as_ref(), backup_prefix_v9.as_ref()]
                .into_iter()
                .flatten()
                .any(|prefix| {
                    name.to_str()
                        .is_some_and(|name| name.starts_with(prefix) && name.ends_with(".bak"))
                })
    })
}

fn prepare_private_database_storage(path: &Path) -> Result<()> {
    if path == Path::new(":memory:") {
        return Ok(());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        #[cfg(unix)]
        let parent_existed = parent.exists();
        #[cfg(unix)]
        let parent_was_symlink = parent_existed
            && std::fs::symlink_metadata(parent)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false);
        #[cfg(unix)]
        let secure_parent = !parent_existed
            || (!parent_was_symlink && directory_is_dedicated_to_database(parent, path));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("création du dossier {}", parent.display()))?;
        #[cfg(unix)]
        if secure_parent {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("protection du dossier SQLite {}", parent.display()))?;
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .with_context(|| format!("préparation de SQLite {}", path.display()))?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("protection de SQLite {}", path.display()))?;
    drop(file);
    secure_existing_sqlite_files(path)
}

fn secure_existing_sqlite_files(path: &Path) -> Result<()> {
    #[cfg(unix)]
    for candidate in [
        path.to_path_buf(),
        sqlite_companion_path(path, "-wal"),
        sqlite_companion_path(path, "-shm"),
        sqlite_companion_path(path, "-journal"),
    ] {
        match std::fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => {
                std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| {
                        format!("protection du fichier SQLite {}", candidate.display())
                    })?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspection de SQLite {}", candidate.display()));
            }
        }
    }
    Ok(())
}

fn next_schema_backup_path(path: &Path, version: u8) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fellaga.db");
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let timestamp = now_epoch();
    for suffix in 0_u32.. {
        let candidate_name = if suffix == 0 {
            format!("{file_name}.pre-v{version}-{timestamp}.bak")
        } else {
            format!("{file_name}.pre-v{version}-{timestamp}-{suffix}.bak")
        };
        let candidate = parent.join(candidate_name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&candidate) {
            Ok(file) => {
                #[cfg(unix)]
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .with_context(|| {
                        format!("protection de la sauvegarde SQLite {}", candidate.display())
                    })?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("création de la sauvegarde SQLite {}", candidate.display())
                });
            }
        }
    }
    unreachable!("la recherche d'un nom de sauvegarde libre est bornée par le système de fichiers")
}

fn next_v8_backup_path(path: &Path) -> Result<PathBuf> {
    next_schema_backup_path(path, 8)
}

fn next_v9_backup_path(path: &Path) -> Result<PathBuf> {
    next_schema_backup_path(path, 9)
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

/// Durable numeric progress for a passive connector lane. The state contains
/// only public query metadata and counters; opaque cursors, request URLs and
/// credentials are deliberately excluded from the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassivePaginationState {
    pub contract_version: u32,
    pub query_hash: String,
    pub next_position: u64,
    pub records_seen: u64,
    pub expected_records: Option<u64>,
    pub expected_pages: Option<u64>,
    pub last_page_hash: String,
    pub last_page_records: u64,
    pub done: bool,
    pub updated_at: i64,
}

/// A validated numeric page transition. `position` is the page just decoded;
/// `next_position` is persisted in the same transaction as its observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassivePaginationPage {
    pub position: u64,
    pub next_position: u64,
    pub records_seen: u64,
    pub expected_records: Option<u64>,
    pub expected_pages: Option<u64>,
    pub page_hash: String,
    pub page_records: u64,
}

#[derive(Debug, Clone)]
pub struct ScanCheckpoint {
    pub scan_id: i64,
    pub domain: String,
    pub stage: String,
    pub options_hash: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ScanCandidateLearning {
    pub generator_attempts: HashMap<String, usize>,
    pub generator_successes: HashMap<String, usize>,
    pub attempted_words: BTreeSet<String>,
    pub total_attempts: usize,
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
    pub assets: Vec<String>,
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
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[derive(Debug, Clone)]
pub struct DnssecCacheEntry {
    pub nameserver: String,
    pub status: String,
    pub names: Vec<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHostnameCacheEntry {
    pub hostnames: BTreeSet<String>,
    pub last_success_at: i64,
    pub last_attempt_at: i64,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct WildcardCacheEntry {
    pub signature: BTreeSet<String>,
    pub soa_serial: Option<u64>,
    pub expires_at: i64,
    pub algorithm_version: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WildcardCleanupResult {
    pub purged: usize,
    pub retained_unverified: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceDiagnostic {
    pub requests: i64,
    pub successes: i64,
    pub failures: i64,
    pub degraded: i64,
    pub deferred: i64,
    pub consecutive_failures: i64,
    pub names: i64,
    pub novel_names: i64,
    pub novel_requests: i64,
    pub average_ms: i64,
    pub last_error: Option<String>,
    pub last_status: String,
    pub last_used: i64,
    pub next_retry: Option<i64>,
    pub retry_in_seconds: Option<i64>,
}

/// One bounded learning update for the cost-aware candidate scheduler.
/// `exclusive_live` must only count names first discovered by this generator,
/// confirmed live and not synthesized by a wildcard.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulerOutcome {
    pub generator: String,
    pub attempts: u64,
    pub exclusive_live: u64,
    pub packets: u64,
    /// Normalized aggregate cost. Callers may combine logical DNS operations, elapsed
    /// work and other local resource costs, but the unit must remain stable
    /// between generators in the same installation.
    pub total_cost: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SchedulerArmRanking {
    pub generator: String,
    pub priority_milli: i64,
    pub posterior_mean: f64,
    pub posterior_upper: f64,
    pub average_cost: f64,
    pub exclusive_per_1000_cost: f64,
    pub packets: u64,
    pub exclusive_live: u64,
    pub contexts_matched: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryActionInput {
    pub fqdn: Option<String>,
    pub zone: String,
    pub kind: String,
    pub generator: String,
    pub context_key: String,
    pub priority_class: u8,
    pub predicted_unique_live: f64,
    pub predicted_cost: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DiscoveryActionRecord {
    pub id: i64,
    pub fqdn: Option<String>,
    pub zone: String,
    pub kind: String,
    pub generator: String,
    pub context_key: String,
    pub priority_class: u8,
    pub predicted_unique_live: f64,
    pub predicted_cost: f64,
}

#[derive(Debug, Default)]
struct SchedulerArmAggregate {
    weighted_successes: f64,
    weighted_failures: f64,
    weighted_attempts: f64,
    weighted_packets: f64,
    weighted_rewards: f64,
    weighted_cost: f64,
    max_packets: u64,
    max_rewards: u64,
    contexts_matched: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceResultStatus {
    Success,
    Failure,
    Degraded,
    Deferred,
}

impl SourceResultStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Degraded => "degraded",
            Self::Deferred => "deferred",
        }
    }
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
    passive_refresh_source: Option<String>,
    reply: mpsc::Sender<std::result::Result<ObservationWriteStats, String>>,
}

struct ObservationWriter {
    sender: mpsc::Sender<WriterMessage>,
}

impl ObservationWriter {
    fn start(path: PathBuf) -> Result<Self> {
        secure_existing_sqlite_files(&path)?;
        let (sender, receiver) = mpsc::channel::<WriterMessage>();
        std::thread::Builder::new()
            .name("fellaga-sqlite-writer".to_owned())
            .spawn(move || {
                let connection = Connection::open(&path);
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
                let _ = connection.busy_timeout(std::time::Duration::from_secs(5));
                if let Err(error) = secure_existing_sqlite_files(&path) {
                    for message in receiver {
                        let _ = message.reply.send(Err(format!(
                            "protection du writer SQLite impossible: {error:#}"
                        )));
                    }
                    return;
                }
                for message in receiver {
                    let result = match message.passive_refresh_source.as_deref() {
                        Some(source) => insert_passive_observations_with_stats(
                            &mut connection,
                            &message.root_domain,
                            source,
                            &message.observations,
                        ),
                        None => insert_observations_with_stats(
                            &mut connection,
                            &message.root_domain,
                            &message.observations,
                        ),
                    }
                    .map_err(|error| format!("{error:#}"));
                    let _ = message.reply.send(result);
                }
            })?;
        Ok(Self { sender })
    }

    fn submit_with_stats(
        &self,
        root_domain: &str,
        observations: Vec<ObservationInput>,
    ) -> Result<ObservationWriteStats> {
        if observations.is_empty() {
            return Ok(ObservationWriteStats::default());
        }
        let (reply, response) = mpsc::channel();
        self.sender
            .send(WriterMessage {
                root_domain: root_domain.to_owned(),
                observations,
                passive_refresh_source: None,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("writer SQLite arrêté"))?;
        response
            .recv()
            .map_err(|_| anyhow::anyhow!("réponse du writer SQLite absente"))?
            .map_err(anyhow::Error::msg)
    }

    fn submit_passive_page_with_stats(
        &self,
        root_domain: &str,
        source: &str,
        observations: Vec<ObservationInput>,
    ) -> Result<ObservationWriteStats> {
        // Even an empty provider page is durable progress: it starts or
        // refreshes the restart session and creates the incomplete cache
        // marker in one transaction, so it must still reach the writer.
        let (reply, response) = mpsc::channel();
        self.sender
            .send(WriterMessage {
                root_domain: root_domain.to_owned(),
                observations,
                passive_refresh_source: Some(source.to_owned()),
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
    Ok(insert_observations_with_stats(connection, root_domain, observations)?.written)
}

fn insert_observations_with_stats(
    connection: &mut Connection,
    root_domain: &str,
    observations: &[ObservationInput],
) -> Result<ObservationWriteStats> {
    if observations.is_empty() {
        return Ok(ObservationWriteStats::default());
    }
    let transaction = connection.transaction()?;
    let stats = insert_observation_rows_with_stats(&transaction, root_domain, observations)?;
    transaction.commit()?;
    Ok(stats)
}

fn insert_passive_observations_with_stats(
    connection: &mut Connection,
    root_domain: &str,
    source: &str,
    observations: &[ObservationInput],
) -> Result<ObservationWriteStats> {
    let transaction = connection.transaction()?;
    let stats = insert_passive_observation_rows_with_stats(
        &transaction,
        root_domain,
        source,
        observations,
    )?;
    transaction.execute(
        r#"INSERT OR IGNORE INTO passive_cache(
               root_domain, source, names_json, updated_at
           ) VALUES (?1, ?2, '[]', 0)"#,
        params![root_domain, source],
    )?;
    transaction.commit()?;
    Ok(stats)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ObservationWriteStats {
    written: usize,
    novel_names: usize,
}

fn insert_observation_rows(
    connection: &Connection,
    root_domain: &str,
    observations: &[ObservationInput],
) -> Result<usize> {
    Ok(insert_observation_rows_with_stats(connection, root_domain, observations)?.written)
}

fn insert_observation_rows_with_stats(
    connection: &Connection,
    root_domain: &str,
    observations: &[ObservationInput],
) -> Result<ObservationWriteStats> {
    insert_observation_rows_with_refresh_stats(connection, root_domain, None, observations)
}

fn cleanup_abandoned_passive_refresh_sessions(connection: &Connection, now: i64) -> Result<usize> {
    let cutoff = now.saturating_sub(PASSIVE_REFRESH_ABANDONED_AFTER_SECS);
    let limit = usize_to_i64_saturating(PASSIVE_REFRESH_GC_BATCH);
    connection.execute(
        r#"DELETE FROM passive_pagination_state
           WHERE (root_domain, source) IN (
               SELECT root_domain, source
               FROM passive_refresh_sessions
               WHERE active=1 AND updated_at < ?1
               ORDER BY updated_at, root_domain, source
               LIMIT ?2
           )"#,
        params![cutoff, limit],
    )?;
    let deactivated = connection.execute(
        r#"UPDATE passive_refresh_sessions
           SET active=0, updated_at=?1
           WHERE (root_domain, source) IN (
               SELECT root_domain, source
               FROM passive_refresh_sessions
               WHERE active=1 AND updated_at < ?2
               ORDER BY updated_at, root_domain, source
               LIMIT ?3
           )"#,
        params![now, cutoff, limit],
    )?;
    // Rows from the first replay-safe implementation are no longer used.
    // Remove them in a bounded batch so a million-name source never creates a
    // single blocking cascade transaction.
    connection.execute(
        r#"DELETE FROM passive_refresh_seen
           WHERE (root_domain, source, name_id) IN (
               SELECT seen.root_domain, seen.source, seen.name_id
               FROM passive_refresh_seen AS seen
               LEFT JOIN passive_refresh_sessions AS sessions
                 ON sessions.root_domain=seen.root_domain
                AND sessions.source=seen.source
               WHERE sessions.active=0 OR sessions.active IS NULL
               ORDER BY seen.root_domain, seen.source, seen.name_id
               LIMIT ?1
           )"#,
        [usize_to_i64_saturating(PASSIVE_REFRESH_GC_BATCH * 16)],
    )?;
    Ok(deactivated)
}

fn cleanup_expired_passive_refresh_leases(connection: &Connection, now: i64) -> Result<usize> {
    connection
        .execute(
            r#"DELETE FROM passive_refresh_leases
               WHERE (root_domain, source) IN (
                   SELECT root_domain, source
                   FROM passive_refresh_leases
                   WHERE expires_at<=?1
                   ORDER BY expires_at, root_domain, source
                   LIMIT ?2
               )"#,
            params![now, usize_to_i64_saturating(PASSIVE_REFRESH_LEASE_GC_BATCH)],
        )
        .map_err(Into::into)
}

fn begin_passive_refresh_session(
    connection: &Connection,
    root_domain: &str,
    source: &str,
    now: i64,
) -> Result<i64> {
    cleanup_abandoned_passive_refresh_sessions(connection, now)?;
    connection.execute(
        r#"INSERT INTO passive_refresh_sessions(
               root_domain, source, started_at, updated_at, generation, active
           ) VALUES (?1, ?2, ?3, ?3, 1, 1)
           ON CONFLICT(root_domain, source) DO UPDATE SET
               generation=CASE
                   WHEN passive_refresh_sessions.active=0
                   THEN passive_refresh_sessions.generation+1
                   ELSE passive_refresh_sessions.generation
               END,
               started_at=CASE
                   WHEN passive_refresh_sessions.active=0 THEN excluded.started_at
                   ELSE passive_refresh_sessions.started_at
               END,
               active=1,
               updated_at=excluded.updated_at"#,
        params![root_domain, source, now],
    )?;
    connection
        .query_row(
            r#"SELECT generation FROM passive_refresh_sessions
               WHERE root_domain=?1 AND source=?2 AND active=1"#,
            params![root_domain, source],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn clear_passive_refresh_session(
    connection: &Connection,
    root_domain: &str,
    source: &str,
) -> Result<()> {
    // Keep one tiny generation counter per source. Evidence records carry the
    // generation they last observed, so completion never cascades through a
    // million-name replay set.
    connection.execute(
        r#"UPDATE passive_refresh_sessions
           SET active=0, updated_at=?3
           WHERE root_domain=?1 AND source=?2"#,
        params![root_domain, source, now_epoch()],
    )?;
    Ok(())
}

fn insert_passive_observation_rows_with_stats(
    connection: &Connection,
    root_domain: &str,
    source: &str,
    observations: &[ObservationInput],
) -> Result<ObservationWriteStats> {
    insert_observation_rows_with_refresh_stats(connection, root_domain, Some(source), observations)
}

fn insert_observation_rows_with_refresh_stats(
    connection: &Connection,
    root_domain: &str,
    passive_refresh_source: Option<&str>,
    observations: &[ObservationInput],
) -> Result<ObservationWriteStats> {
    let now = now_epoch();
    let refresh_generation = passive_refresh_source
        .map(|source| begin_passive_refresh_session(connection, root_domain, source, now))
        .transpose()?;
    let mut stats = ObservationWriteStats::default();
    for observation in observations {
        let inserted = connection.execute(
            r#"INSERT OR IGNORE INTO observed_names(
                   fqdn, reversed_name, first_seen, last_seen
               ) VALUES (?1, ?2, ?3, ?3)"#,
            params![observation.fqdn, reverse_hostname(&observation.fqdn), now],
        )?;
        if inserted == 0 {
            connection.execute(
                "UPDATE observed_names SET last_seen=?2 WHERE fqdn=?1",
                params![observation.fqdn, now],
            )?;
        }
        stats.novel_names = stats.novel_names.saturating_add(inserted);
        let name_id: i64 = connection.query_row(
            "SELECT id FROM observed_names WHERE fqdn=?1",
            [&observation.fqdn],
            |row| row.get(0),
        )?;
        if let Some(refresh_generation) = refresh_generation {
            connection.execute(
                r#"INSERT INTO observation_evidence(
                   root_domain, name_id, kind, source, value,
                   first_seen, last_seen, times_seen, passive_refresh_generation
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1, ?7)
                   ON CONFLICT(root_domain, name_id, kind, source, value)
                   DO UPDATE SET last_seen=excluded.last_seen,
                                 times_seen=observation_evidence.times_seen+
                                   CASE WHEN observation_evidence.passive_refresh_generation=
                                                  excluded.passive_refresh_generation
                                        THEN 0 ELSE 1 END,
                                 passive_refresh_generation=
                                   excluded.passive_refresh_generation"#,
                params![
                    root_domain,
                    name_id,
                    observation.kind,
                    observation.source,
                    observation.value,
                    now,
                    refresh_generation
                ],
            )?;
        } else {
            connection.execute(
                r#"INSERT INTO observation_evidence(
                   root_domain, name_id, kind, source, value,
                   first_seen, last_seen, times_seen
                   ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
                   ON CONFLICT(root_domain, name_id, kind, source, value)
                   DO UPDATE SET last_seen=excluded.last_seen"#,
                params![
                    root_domain,
                    name_id,
                    observation.kind,
                    observation.source,
                    observation.value,
                    now
                ],
            )?;
        }
        stats.written = stats.written.saturating_add(1);
    }
    Ok(stats)
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

fn scheduler_context_weight(context: &str) -> f64 {
    match context.split(':').next().unwrap_or_default() {
        "suffix" | "registrable" | "provider" => 2.0,
        _ => 1.0,
    }
}

fn validate_scheduler_identifier(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("identifiant {field} invalide pour le scheduler");
    }
    Ok(())
}

fn validate_scheduler_outcome(outcome: &SchedulerOutcome) -> Result<()> {
    validate_scheduler_identifier(&outcome.generator, "generator")?;
    if outcome.attempts > MAX_SCHEDULER_COUNT_DELTA
        || outcome.packets > MAX_SCHEDULER_COUNT_DELTA
        || outcome.exclusive_live > outcome.attempts
    {
        bail!(
            "compteurs hors limites pour le générateur {}",
            outcome.generator
        );
    }
    if !outcome.total_cost.is_finite()
        || !(0.0..=MAX_SCHEDULER_COST_DELTA).contains(&outcome.total_cost)
    {
        bail!("coût hors limites pour le générateur {}", outcome.generator);
    }
    Ok(())
}

fn validate_discovery_action(action: &DiscoveryActionInput) -> Result<()> {
    validate_scheduler_identifier(&action.zone, "zone")?;
    validate_scheduler_identifier(&action.kind, "kind")?;
    validate_scheduler_identifier(&action.generator, "generator")?;
    validate_scheduler_identifier(&action.context_key, "context")?;
    if let Some(fqdn) = &action.fqdn {
        validate_scheduler_identifier(fqdn, "fqdn")?;
    }
    if action.priority_class > 3 {
        bail!("classe de priorité discovery_action hors limites");
    }
    if !action.predicted_unique_live.is_finite()
        || !(0.0..=1_000_000_000.0).contains(&action.predicted_unique_live)
        || !action.predicted_cost.is_finite()
        || !(0.000_001..=MAX_SCHEDULER_COST_DELTA).contains(&action.predicted_cost)
    {
        bail!("prédiction hors limites pour discovery_action");
    }
    Ok(())
}

fn upsert_scheduler_arm(
    transaction: &rusqlite::Transaction<'_>,
    context: &str,
    outcome: &SchedulerOutcome,
    now: i64,
) -> Result<()> {
    validate_scheduler_identifier(context, "context")?;
    validate_scheduler_outcome(outcome)?;
    let failures = outcome.attempts.saturating_sub(outcome.exclusive_live);
    transaction.execute(
        r#"INSERT INTO scheduler_arms(
               context, generator, alpha, beta, packets,
               exclusive_rewards, total_cost, last_seen
           ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
           ON CONFLICT(context, generator) DO UPDATE SET
               alpha=MIN(?9, MAX(scheduler_arms.alpha, 1.0)+excluded.alpha-1.0),
               beta=MIN(?9, MAX(scheduler_arms.beta, 1.0)+excluded.beta-1.0),
               packets=CASE
                   WHEN MAX(scheduler_arms.packets, 0) > 9223372036854775807-excluded.packets
                   THEN 9223372036854775807
                   ELSE MAX(scheduler_arms.packets, 0)+excluded.packets END,
               exclusive_rewards=CASE
                   WHEN MAX(scheduler_arms.exclusive_rewards, 0) > 9223372036854775807-excluded.exclusive_rewards
                   THEN 9223372036854775807
                   ELSE MAX(scheduler_arms.exclusive_rewards, 0)+excluded.exclusive_rewards END,
               total_cost=MIN(?9, MAX(scheduler_arms.total_cost, 0.0)+excluded.total_cost),
               last_seen=excluded.last_seen"#,
        params![
            context,
            outcome.generator,
            1.0 + outcome.exclusive_live as f64,
            1.0 + failures as f64,
            outcome.packets as i64,
            outcome.exclusive_live as i64,
            outcome.total_cost,
            now,
            MAX_SCHEDULER_TOTAL
        ],
    )?;
    Ok(())
}

#[derive(Clone)]
pub struct Database {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    writer: Option<Arc<ObservationWriter>>,
}

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

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("verrou SQLite empoisonné"))
    }

    fn lock_ct_materialization_until(
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
        if limit == 0 {
            return Ok(Vec::new());
        }
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            r#"SELECT DISTINCT n.fqdn FROM observation_evidence e
               JOIN observed_names n ON n.id=e.name_id
               WHERE e.root_domain=?1 AND e.source=?2
               ORDER BY n.fqdn LIMIT ?3"#,
        )?;
        statement
            .query_map(
                params![root_domain, source, limit.min(i64::MAX as usize) as i64],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
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

    fn apply_staged_refresh_wildcard_cleanup_with_cancel<F>(
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
        if ttl.is_zero() {
            bail!("durée de lease passive nulle");
        }
        validate_passive_pagination_key(root_domain, source, "lease", 1, owner)?;
        let now = now_epoch();
        let expires_at = now.saturating_add(u64_to_i64_saturating(ttl.as_secs().max(1)));
        let mut connection = self.lock()?;
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
        if ttl.is_zero() {
            bail!("durée de renouvellement passive nulle");
        }
        validate_passive_pagination_key(root_domain, source, "lease", 1, owner)?;
        let now = now_epoch();
        let expires_at = now.saturating_add(u64_to_i64_saturating(ttl.as_secs().max(1)));
        let connection = self.lock()?;
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
        validate_passive_pagination_key(root_domain, source, "lease", 1, owner)?;
        let connection = self.lock()?;
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

        let mut connection = self.lock()?;
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
        validate_passive_pagination_key(root_domain, source, lane, contract_version, query_hash)?;
        let mut connection = self.lock()?;
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
            transaction.commit()?;
            return Ok(None);
        };
        if stored_contract != i64::from(contract_version) || stored_query_hash != query_hash {
            transaction.execute(
                r#"DELETE FROM passive_pagination_state
                   WHERE root_domain=?1 AND source=?2 AND lane=?3"#,
                params![root_domain, source, lane],
            )?;
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

        let mut connection = self.lock()?;
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
        let stats = insert_passive_observation_rows_with_stats(
            &transaction,
            root_domain,
            source,
            &observations,
        )?;
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
        validate_passive_pagination_key(root_domain, source, lane, contract_version, query_hash)?;
        let mut connection = self.lock()?;
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

        let mut connection = self.lock()?;
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
            let mut names = self
                .observation_names_bounded(domain, &format!("passive:{source}"), limit)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            if names.len() < limit {
                for name in serde_json::from_str::<Vec<String>>(&names_json)? {
                    if names.len() >= limit {
                        break;
                    }
                    names.insert(name);
                }
            }
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
        let observations = names
            .iter()
            .map(|fqdn| ObservationInput {
                fqdn: fqdn.clone(),
                kind: "passive".to_owned(),
                source: format!("passive:{source}"),
                value: String::new(),
            })
            .collect::<Vec<_>>();
        let stats = if let Some(writer) = &self.writer {
            writer.submit_passive_page_with_stats(domain, source, observations)?
        } else {
            let mut connection = self.lock()?;
            insert_passive_observations_with_stats(&mut connection, domain, source, &observations)?
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
        let mut connection = self.lock()?;
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
        self.record_source_result_counts(source, None, novel_names, duration_ms, error)
    }

    pub fn record_source_result_with_counts(
        &self,
        source: &str,
        names: usize,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
    ) -> Result<()> {
        self.record_source_result_counts(source, Some(names), novel_names, duration_ms, error)
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
        )
    }

    fn record_source_result_counts(
        &self,
        source: &str,
        names: Option<usize>,
        novel_names: usize,
        duration_ms: u128,
        error: Option<&str>,
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
    ) -> Result<()> {
        let success = i64::from(status == SourceResultStatus::Success);
        let failure = i64::from(status == SourceResultStatus::Failure);
        let degraded = i64::from(status == SourceResultStatus::Degraded);
        let deferred = i64::from(status == SourceResultStatus::Deferred);
        let duration_ms = duration_ms.min(i64::MAX as u128) as i64;
        let novel_requests = i64::from(record_yield_sample);
        let novel_total_ms = if record_yield_sample { duration_ms } else { 0 };
        let mut connection = self.lock()?;
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
        transaction.commit()?;
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
        let now = now_epoch();
        let cooldown_seconds = cooldown.as_secs().min(i64::MAX as u64) as i64;
        let connection = self.lock()?;
        let mut diagnostics = {
            let mut statement = connection.prepare(
                r#"SELECT source, requests, successes, failures, degraded, deferred,
                   consecutive_failures, names, novel_names, novel_requests,
                   CASE WHEN requests=0 THEN 0 ELSE total_ms/requests END,
                   last_error, last_status, last_used FROM source_stats ORDER BY source"#,
            )?;
            statement
                .query_map([], |row| {
                    let source = row.get::<_, String>(0)?;
                    let consecutive_failures = row.get::<_, i64>(6)?;
                    let last_status = row.get::<_, String>(12)?;
                    let last_used = row.get::<_, i64>(13)?;
                    let retry_at = last_used.saturating_add(cooldown_seconds);
                    let next_retry =
                        (consecutive_failures >= 3 && last_status == "failure" && retry_at > now)
                            .then_some(retry_at);
                    Ok((
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
               WHERE consecutive_failures>=3
                 AND last_status='failure'
                 AND last_used>=?1"#,
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
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(Into::into)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DnsRecord;

    #[cfg(unix)]
    fn unix_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn unix_database_directory_file_and_sidecars_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("state");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        let path = directory.join("fellaga.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .unwrap();
        connection
            .execute("CREATE TABLE legacy_secret(value TEXT)", [])
            .unwrap();
        let wal = sqlite_companion_path(&path, "-wal");
        let shm = sqlite_companion_path(&path, "-shm");
        assert!(wal.exists());
        assert!(shm.exists());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&shm, std::fs::Permissions::from_mode(0o644)).unwrap();

        let database = Database::open(&path).unwrap();
        assert_eq!(unix_mode(&directory), 0o700);
        assert_eq!(unix_mode(&path), 0o600);
        assert!(
            wal.exists(),
            "le journal WAL doit être présent pendant l'ouverture"
        );
        assert!(
            shm.exists(),
            "le fichier SHM doit être présent pendant l'ouverture"
        );
        assert_eq!(unix_mode(&wal), 0o600);
        assert_eq!(unix_mode(&shm), 0o600);
        drop(database);
    }

    #[cfg(unix)]
    #[test]
    fn unix_shared_parent_is_not_repermissioned_but_database_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("unrelated.txt"), "keep").unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.path().join("fellaga.db");

        let database = Database::open(&path).unwrap();
        assert_eq!(unix_mode(root.path()), 0o755);
        assert_eq!(unix_mode(&path), 0o600);
        drop(database);
    }

    #[test]
    fn v7_to_v9_preserves_5239_names_and_creates_a_consistent_pre_v8_backup() {
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
            9
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
        assert_eq!(
            connection
                .query_row(
                    "SELECT verification_state FROM subdomains WHERE fqdn='host-1.example.com'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "unverified"
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
        #[cfg(unix)]
        assert_eq!(unix_mode(&backup), 0o600);
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
    fn v8_to_v9_is_transactional_preserves_observations_and_creates_a_pre_v9_backup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fellaga.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE scans (
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
                INSERT INTO scans(
                    id, domain, started_at, finished_at, status, options_json
                ) VALUES (41, 'example.com', 100, 200, 'complete', '{}');

                CREATE TABLE subdomains (
                    fqdn TEXT PRIMARY KEY,
                    root_domain TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    last_scan_id INTEGER REFERENCES scans(id),
                    times_seen INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    sources TEXT NOT NULL,
                    verification_state TEXT NOT NULL DEFAULT 'live',
                    last_verified_at INTEGER
                );
                INSERT INTO subdomains(
                    fqdn, root_domain, first_seen, last_seen, last_scan_id,
                    times_seen, active, sources, verification_state, last_verified_at
                ) VALUES (
                    'api.example.com', 'example.com', 101, 199, 41,
                    3, 1, 'passive:test,dns', 'live', 198
                );

                CREATE TABLE scan_findings (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fqdn TEXT NOT NULL REFERENCES subdomains(fqdn) ON DELETE CASCADE,
                    wildcard INTEGER NOT NULL DEFAULT 0,
                    from_cache INTEGER NOT NULL DEFAULT 0,
                    confidence_score INTEGER NOT NULL DEFAULT 0,
                    confidence_label TEXT NOT NULL DEFAULT 'faible',
                    confidence_reasons_json TEXT NOT NULL DEFAULT '[]',
                    state TEXT NOT NULL DEFAULT 'unverified',
                    last_verified_at INTEGER,
                    evidence_families_json TEXT NOT NULL DEFAULT '[]',
                    authoritative_validation INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(scan_id, fqdn)
                );
                INSERT INTO scan_findings(
                    scan_id, fqdn, wildcard, from_cache, confidence_score,
                    confidence_label, confidence_reasons_json, state,
                    last_verified_at, evidence_families_json, authoritative_validation
                ) VALUES (
                    41, 'api.example.com', 0, 0, 93,
                    'forte', '["dns"]', 'live', 198, '["live_dns"]', 1
                );

                CREATE TABLE observed_names (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fqdn TEXT NOT NULL UNIQUE,
                    reversed_name TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                CREATE TABLE observation_evidence (
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
                INSERT INTO observed_names(
                    id, fqdn, reversed_name, first_seen, last_seen
                ) VALUES (
                    7, 'api.example.com', 'com.example.api', 101, 199
                );
                INSERT INTO observation_evidence(
                    root_domain, name_id, kind, source, value,
                    first_seen, last_seen, times_seen
                ) VALUES (
                    'example.com', 7, 'passive', 'passive:test', 'fixture',
                    101, 199, 3
                );
                PRAGMA user_version=8;
                "#,
            )
            .unwrap();
        drop(connection);

        let database = Database::open(&path).unwrap();
        let connection = database.lock().unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            9
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT fqdn, reversed_name, first_seen, last_seen
                       FROM observed_names WHERE id=7"#,
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .unwrap(),
            (
                "api.example.com".to_owned(),
                "com.example.api".to_owned(),
                101,
                199
            )
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT kind, source, value, first_seen, last_seen, times_seen
                       FROM observation_evidence
                       WHERE root_domain='example.com' AND name_id=7"#,
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .unwrap(),
            (
                "passive".to_owned(),
                "passive:test".to_owned(),
                "fixture".to_owned(),
                101,
                199,
                3
            )
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT wildcard_verdict, owner_proofs_json,
                              generation_path_json, discovery_score
                       FROM scan_findings
                       WHERE scan_id=41 AND fqdn='api.example.com'"#,
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<f64>>(3)?,
                        ))
                    },
                )
                .unwrap(),
            (
                "not_profiled".to_owned(),
                "[]".to_owned(),
                "[]".to_owned(),
                None
            )
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT first_scan_id FROM subdomains WHERE fqdn='api.example.com'",
                    [],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .unwrap(),
            None
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM sqlite_master
                       WHERE type='table' AND name IN (
                           'discovery_actions', 'intelligence_edges', 'name_templates',
                           'dnssec_proofs', 'ct_tiles', 'scheduler_arms'
                       )"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            6
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM pragma_table_info('ct_tiles')
                       WHERE name='checkpoint_hash' AND type='TEXT'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM sqlite_master
                       WHERE type='table' AND name IN (
                           'passive_refresh_sessions', 'passive_refresh_seen',
                           'passive_refresh_leases'
                       )"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            3,
            "same-version additive repair must install replay-safe refresh state"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM migration_state WHERE name='intelligence-v9'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        drop(connection);
        drop(database);

        let backup = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("fellaga.db.pre-v9-"))
            })
            .expect("une sauvegarde pré-v9 doit exister");
        #[cfg(unix)]
        assert_eq!(unix_mode(&backup), 0o600);
        let backup_connection = Connection::open(backup).unwrap();
        assert_eq!(
            backup_connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            backup_connection
                .query_row(
                    "SELECT COUNT(*) FROM observation_evidence WHERE times_seen=3",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            backup_connection
                .query_row(
                    r#"SELECT COUNT(*) FROM pragma_table_info('scan_findings')
                       WHERE name='wildcard_verdict'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            backup_connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn a_future_database_version_is_rejected_without_downgrading_it() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        connection.pragma_update(None, "user_version", 10).unwrap();
        drop(connection);

        assert!(Database::open(temporary.path()).is_err());
        let connection = Connection::open(temporary.path()).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            10
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
        assert_eq!(version, 9);
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
            ..Finding::default()
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
    fn corrupt_or_empty_positive_cache_entries_are_cache_misses() {
        let db = Database::in_memory().unwrap();
        let now = now_epoch();
        let connection = db.lock().unwrap();
        for (fqdn, records) in [
            ("broken.example.com", "not-json"),
            ("empty.example.com", "[]"),
        ] {
            connection
                .execute(
                    r#"INSERT INTO dns_cache(
                       fqdn,status,records_json,expires_at,last_checked,resolver_count,authoritative
                       ) VALUES (?1,'positive',?2,?3,?4,1,0)"#,
                    params![fqdn, records, PERMANENT_EXPIRY, now],
                )
                .unwrap();
        }
        drop(connection);
        let hosts = vec![
            "broken.example.com".to_owned(),
            "empty.example.com".to_owned(),
        ];
        assert!(db.fresh_cache(&hosts).unwrap().is_empty());
    }

    #[test]
    fn indeterminate_dns_preserves_positive_cache_and_scan_provenance() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
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
            authoritative_validation: false,
            resolver_count: 2,
        };
        let untouched = "untouched.example.com".to_owned();
        let make_finding = |fqdn: String| Finding {
            fqdn,
            records: answer.records.clone(),
            sources: BTreeSet::from(["refresh".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["refresh".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: false,
            ..Finding::default()
        };
        db.persist_findings(
            scan_id,
            "example.com",
            &[make_finding(host.clone()), make_finding(untouched.clone())],
            86_400,
        )
        .unwrap();
        db.update_cache_outcomes(Some(scan_id), &[answer], &[], &[], 300)
            .unwrap();
        db.update_cache_outcomes(Some(scan_id), &[], &[], std::slice::from_ref(&host), 300)
            .unwrap();

        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&host)).unwrap()[&host],
            CachedAnswer::Positive(_)
        ));
        let states = db
            .inventory(Some("example.com"), false)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.fqdn, entry.state))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(states[&host], ObservationState::Live);
        assert_eq!(states[&untouched], ObservationState::Live);
        let connection = db.lock().unwrap();
        let rows = connection
            .prepare("SELECT scan_id, outcome FROM dns_verifications WHERE fqdn=?1 ORDER BY id")
            .unwrap()
            .query_map([&host], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(scan_id, "live".to_owned()), (scan_id, "error".to_owned())]
        );
    }

    #[test]
    fn unverified_findings_do_not_leave_active_dns_records() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let finding = Finding {
            fqdn: "wild.prod.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            sources: BTreeSet::from(["passive:crtsh".to_owned()]),
            wildcard: true,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["passive:crtsh".to_owned()]),
                true,
                false,
            ),
            state: ObservationState::Unverified,
            last_verified_at: Some(now_epoch()),
            evidence_families: BTreeSet::from([
                crate::model::EvidenceFamily::CertificateTransparency,
            ]),
            authoritative_validation: false,
            ..Finding::default()
        };
        db.persist_findings(scan_id, "example.com", &[finding], 86_400)
            .unwrap();
        let connection = db.lock().unwrap();
        let subdomain_active: i64 = connection
            .query_row(
                "SELECT active FROM subdomains WHERE fqdn='wild.prod.example.com'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let record_active: i64 = connection
            .query_row(
                "SELECT active FROM dns_records WHERE fqdn='wild.prod.example.com'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((subdomain_active, record_active), (0, 0));
    }

    #[test]
    fn wildcard_suspect_demotion_and_seed_requeue_are_atomic() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "api.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records.clone(),
                sources: BTreeSet::from(["dns:seed".to_owned()]),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
        db.update_cache_outcomes(Some(scan_id), &[answer], &[], &[], 300)
            .unwrap();
        let initial_sources = BTreeSet::from(["passive:first".to_owned()]);
        db.persist_scan_seed_candidates(scan_id, &[(fqdn.clone(), initial_sources, 10)], 10)
            .unwrap();
        let claimed = db.pending_scan_seed_candidates(scan_id, 1).unwrap();
        db.mark_scan_seed_candidates_started(scan_id, std::slice::from_ref(&fqdn))
            .unwrap();
        db.mark_scan_seed_candidates_done(scan_id, std::slice::from_ref(&fqdn))
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 0);

        db.demote_and_requeue_scan_findings(
            scan_id,
            &[(
                fqdn.clone(),
                BTreeSet::from(["dns:resume-wildcard".to_owned()]),
                50,
            )],
            "test revalidation",
        )
        .unwrap();

        let inventory = db.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state, ObservationState::Unverified);
        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&fqdn)).unwrap()[&fqdn],
            CachedAnswer::Positive(_)
        ));
        let queued = db.pending_scan_seed_candidates(scan_id, 1).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].0, fqdn);
        assert!(queued[0].1.contains("passive:first"));
        assert!(queued[0].1.contains("dns:resume-wildcard"));
        assert_eq!(queued[0].2, 50);
        let connection = db.lock().unwrap();
        let (finding_state, verdict, active_record, latest_outcome): (String, String, i64, String) =
            connection
                .query_row(
                    r#"SELECT finding.state, finding.wildcard_verdict, record.active,
                          verification.outcome
                   FROM scan_findings AS finding
                   JOIN dns_records AS record ON record.fqdn=finding.fqdn
                   JOIN dns_verifications AS verification ON verification.id=(
                       SELECT MAX(id) FROM dns_verifications WHERE fqdn=finding.fqdn
                   )
                   WHERE finding.scan_id=?1 AND finding.fqdn=?2"#,
                    params![scan_id, fqdn],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
        assert_eq!(finding_state, "unverified");
        assert_eq!(verdict, "ambiguous");
        assert_eq!(active_record, 0);
        assert_eq!(latest_outcome, "unverified");
    }

    #[test]
    fn provider_only_merge_preserves_verified_inventory_and_dns_record_state() {
        let db = Database::in_memory().unwrap();
        let live = "live.example.com";
        let historical = "historical.example.com";
        let new = "new.example.com";
        let first_scan = db.create_scan("example.com", &json!({})).unwrap();
        let verified = |fqdn: &str, address: &str, checked_at: i64| Finding {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: address.to_owned(),
                ttl: 60,
            }],
            sources: BTreeSet::from(["dns".to_owned()]),
            state: ObservationState::Live,
            last_verified_at: Some(checked_at),
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            ..Finding::default()
        };
        db.persist_findings(
            first_scan,
            "example.com",
            &[
                verified(live, "192.0.2.10", 101),
                verified(historical, "192.0.2.11", 102),
            ],
            60,
        )
        .unwrap();
        db.mark_inactive(&[historical.to_owned()]).unwrap();

        let second_scan = db.create_scan("example.com", &json!({})).unwrap();
        let provider_only = |fqdn: &str| Finding {
            fqdn: fqdn.to_owned(),
            sources: BTreeSet::from(["passive:crtsh:cache".to_owned()]),
            state: ObservationState::Unverified,
            ..Finding::default()
        };
        db.persist_unverified_findings_preserving_state(
            second_scan,
            "example.com",
            &[
                provider_only(live),
                provider_only(historical),
                provider_only(new),
            ],
        )
        .unwrap();

        let inventory = db
            .inventory(Some("example.com"), false)
            .unwrap()
            .into_iter()
            .map(|entry| (entry.fqdn.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(inventory[live].state, ObservationState::Live);
        assert_eq!(inventory[live].last_verified_at, Some(101));
        assert_eq!(inventory[historical].state, ObservationState::Historical);
        assert_eq!(inventory[historical].last_verified_at, Some(102));
        assert_eq!(inventory[new].state, ObservationState::Unverified);
        assert_eq!(inventory[new].last_verified_at, None);
        for fqdn in [live, historical] {
            assert!(inventory[fqdn].sources.contains("dns"));
            assert!(inventory[fqdn].sources.contains("passive:crtsh:cache"));
        }

        let connection = db.lock().unwrap();
        let active = |fqdn: &str| -> i64 {
            connection
                .query_row(
                    "SELECT active FROM dns_records WHERE fqdn=?1",
                    [fqdn],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(active(live), 1);
        assert_eq!(active(historical), 0);
        let new_record_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM dns_records WHERE fqdn=?1",
                [new],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_record_count, 0);
    }

    #[test]
    fn later_wildcard_findings_union_sources_and_clear_invalidated_live_verification_time() {
        let db = Database::in_memory().unwrap();
        let first_scan = db.create_scan("example.com", &json!({})).unwrap();
        let mut finding = Finding {
            fqdn: "api.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.10".to_owned(),
                ttl: 60,
            }],
            sources: BTreeSet::from(["passive:first".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["passive:first".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: Some(100),
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::PassiveDns]),
            authoritative_validation: false,
            ..Finding::default()
        };
        db.persist_findings(first_scan, "example.com", &[finding.clone()], 60)
            .unwrap();
        db.persist_findings(first_scan, "example.com", &[finding.clone()], 60)
            .unwrap();

        let second_scan = db.create_scan("example.com", &json!({})).unwrap();
        finding.sources = BTreeSet::from(["web:second".to_owned()]);
        finding.wildcard = true;
        finding.state = ObservationState::Unverified;
        finding.last_verified_at = Some(200);
        db.persist_findings(second_scan, "example.com", &[finding], 60)
            .unwrap();

        let connection = db.lock().unwrap();
        let (sources, last_verified_at, times_seen): (String, Option<i64>, i64) = connection
            .query_row(
                "SELECT sources,last_verified_at,times_seen FROM subdomains WHERE fqdn='api.example.com'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(sources, "passive:first,web:second");
        assert_eq!(last_verified_at, None);
        assert_eq!(times_seen, 2, "one scan must increment inventory only once");
    }

    #[test]
    fn candidate_indexes_cover_priority_relative_name_and_budget_counts() {
        let db = Database::in_memory().unwrap();
        let connection = db.lock().unwrap();
        let count: i64 = connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_master
                    WHERE type='index' AND name IN (
                       'idx_scan_candidates_relative', 'idx_candidate_priors_priority',
                       'idx_scan_candidates_unrecorded'
                    )"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn candidate_outcome_queries_force_the_fqdn_verification_index() {
        let db = Database::in_memory().unwrap();
        let connection = db.lock().unwrap();
        let plans = [
            r#"EXPLAIN QUERY PLAN
               UPDATE scan_seed_candidates SET status=CASE
                   WHEN COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.scan_id=1
                       AND verification.fqdn=scan_seed_candidates.fqdn
                     ORDER BY verification.checked_at DESC, verification.id DESC
                     LIMIT 1
                   ), '')='error' AND attempts<3 THEN 'queued'
                   ELSE 'done'
               END
               WHERE scan_id=1 AND fqdn IN ('plan.example.com')"#,
            r#"EXPLAIN QUERY PLAN
               UPDATE scan_candidates SET status=CASE
                   WHEN COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.scan_id=1
                       AND verification.fqdn=scan_candidates.fqdn
                     ORDER BY verification.checked_at DESC, verification.id DESC
                     LIMIT 1
                   ), '')='error' AND attempts<3 THEN 'queued'
                   ELSE 'done'
               END
               WHERE scan_id=1 AND fqdn IN ('plan.example.com')"#,
            r#"EXPLAIN QUERY PLAN
               UPDATE scan_candidates SET learning_recorded=1
               WHERE scan_id=1 AND fqdn='plan.example.com' AND learning_recorded=0
                 AND (
                   attempts>=3
                   OR COALESCE((
                     SELECT verification.outcome
                     FROM dns_verifications AS verification
                          INDEXED BY idx_dns_verifications_name
                     WHERE verification.scan_id=1
                       AND verification.fqdn=scan_candidates.fqdn
                     ORDER BY verification.checked_at DESC, verification.id DESC
                     LIMIT 1
                   ), '')<>'error'
                 )"#,
        ];
        for sql in plans {
            let mut statement = connection.prepare(sql).unwrap();
            let details = statement
                .query_map([], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                details
                    .iter()
                    .any(|detail| detail.contains("idx_dns_verifications_name (fqdn=?)")),
                "expected fqdn index in query plan: {details:?}"
            );
            assert!(
                details
                    .iter()
                    .all(|detail| !detail.contains("idx_dns_verifications_scan (scan_id=?)")),
                "scan-wide verification lookup leaked into query plan: {details:?}"
            );
        }
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
                    "UPDATE dns_verifications SET outcome='negative' WHERE id=?1",
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
    fn discovery_fast_path_excludes_all_durable_known_name_sources() {
        let db = Database::in_memory().unwrap();
        let inventory = "inventory.example.com".to_owned();
        let observed = "observed.example.com".to_owned();
        let cached = "cached.example.com".to_owned();
        let negative = "negative.example.com".to_owned();
        let unknown = "unknown.example.com".to_owned();

        db.lock()
            .unwrap()
            .execute(
                r#"INSERT INTO subdomains(
                       fqdn, root_domain, first_seen, last_seen, times_seen,
                       active, sources, verification_state
                   ) VALUES (?1, 'example.com', 1, 1, 1, 0, 'test', 'historical')"#,
                [&inventory],
            )
            .unwrap();
        db.store_observations(
            "example.com",
            vec![ObservationInput {
                fqdn: observed.clone(),
                kind: "passive".to_owned(),
                source: "passive:test".to_owned(),
                value: String::new(),
            }],
        )
        .unwrap();
        let answer = ResolvedHost {
            fqdn: cached.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.50".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        db.update_cache_outcomes(None, &[answer], std::slice::from_ref(&negative), &[], 30)
            .unwrap();

        let known = db
            .known_discovery_names(&[
                inventory.clone(),
                observed.clone(),
                cached.clone(),
                negative,
                unknown,
            ])
            .unwrap();
        assert_eq!(known, BTreeSet::from([cached, inventory, observed]));
    }

    #[test]
    fn discovery_negatives_only_append_journal_and_finalize_candidates() {
        let db = Database::in_memory().unwrap();
        let previous_scan = db.create_scan("example.com", &json!({})).unwrap();
        let live_host = "api.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: live_host.clone(),
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
        let sources = BTreeSet::from(["dns:trusted".to_owned()]);
        let finding = Finding {
            fqdn: live_host.clone(),
            records: answer.records.clone(),
            sources: sources.clone(),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(&sources, false, true),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: true,
            ..Finding::default()
        };
        db.persist_findings(previous_scan, "example.com", &[finding], 86_400)
            .unwrap();
        db.update_cache_outcomes(
            Some(previous_scan),
            std::slice::from_ref(&answer),
            &[],
            &[],
            300,
        )
        .unwrap();

        let (inventory_before, record_before, cache_before) = {
            let connection = db.lock().unwrap();
            let inventory = connection
                .query_row(
                    r#"SELECT active, verification_state, last_verified_at
                       FROM subdomains WHERE fqdn=?1"#,
                    [&live_host],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .unwrap();
            let record = connection
                .query_row(
                    r#"SELECT record_type, value, ttl, expires_at, active
                       FROM dns_records WHERE fqdn=?1"#,
                    [&live_host],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .unwrap();
            let cache = connection
                .query_row(
                    r#"SELECT status, records_json, expires_at, last_checked,
                              resolver_count, authoritative
                       FROM dns_cache WHERE fqdn=?1"#,
                    [&live_host],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .unwrap();
            (inventory, record, cache)
        };

        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let mut candidates = vec![("api".to_owned(), "test".to_owned(), 1)];
        candidates.extend((0..501).map(|index| (format!("absent-{index}"), "test".to_owned(), 1)));
        db.persist_scan_candidates(scan_id, "example.com", &candidates)
            .unwrap();
        assert_eq!(
            db.pending_scan_candidates(scan_id, 1_000).unwrap().len(),
            502
        );

        let mut hosts = candidates
            .iter()
            .map(|(relative_name, _, _)| format!("{relative_name}.example.com"))
            .collect::<Vec<_>>();
        hosts.push(live_host.clone());
        hosts.push("absent-0.example.com".to_owned());
        db.record_discovery_negatives(scan_id, &hosts).unwrap();
        hosts.truncate(502);
        db.mark_scan_candidates_done(scan_id, &hosts).unwrap();

        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 0);
        let connection = db.lock().unwrap();
        let terminal: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1 AND status='done'",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(terminal, 502);

        let journal: (i64, i64, i64, i64) = connection
            .query_row(
                r#"SELECT COUNT(*), COUNT(DISTINCT fqdn),
                          COUNT(DISTINCT details_json),
                          SUM(outcome='negative' AND resolver_count=1
                              AND authoritative=0 AND records_hash IS NULL)
                   FROM dns_verifications WHERE scan_id=?1"#,
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(journal, (502, 502, 1, 502));
        let details: Value = serde_json::from_str(
            &connection
                .query_row(
                    "SELECT details_json FROM dns_verifications WHERE scan_id=?1 LIMIT 1",
                    [scan_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            details,
            json!({
                "scope": "discovery-only",
                "cache_write": false,
                "inventory_write": false
            })
        );

        let inventory_after = connection
            .query_row(
                r#"SELECT active, verification_state, last_verified_at
                   FROM subdomains WHERE fqdn=?1"#,
                [&live_host],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .unwrap();
        let record_after = connection
            .query_row(
                r#"SELECT record_type, value, ttl, expires_at, active
                   FROM dns_records WHERE fqdn=?1"#,
                [&live_host],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .unwrap();
        let cache_after = connection
            .query_row(
                r#"SELECT status, records_json, expires_at, last_checked,
                          resolver_count, authoritative
                   FROM dns_cache WHERE fqdn=?1"#,
                [&live_host],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(inventory_after, inventory_before);
        assert_eq!(inventory_after.0, 1);
        assert_eq!(inventory_after.1, "live");
        assert_eq!(record_after, record_before);
        assert_eq!(record_after.4, 1);
        assert_eq!(cache_after, cache_before);
        assert_eq!(cache_after.0, "positive");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM subdomains WHERE fqdn LIKE 'absent-%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM dns_records WHERE fqdn LIKE 'absent-%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM dns_cache WHERE fqdn LIKE 'absent-%'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn negative_demotions_are_chunked_without_creating_absent_inventory() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let existing = ["first.example.com", "last.example.com"];
        let now = now_epoch();
        {
            let connection = db.lock().unwrap();
            for (offset, host) in existing.iter().enumerate() {
                connection
                    .execute(
                        r#"INSERT INTO subdomains(
                               fqdn, root_domain, first_seen, last_seen, last_scan_id,
                               times_seen, active, sources, verification_state, last_verified_at
                           ) VALUES (?1, 'example.com', ?2, ?2, ?3, 1, 1, 'dns:test', 'live', ?2)"#,
                        params![host, now, scan_id],
                    )
                    .unwrap();
                connection
                    .execute(
                        r#"INSERT INTO dns_records(
                               fqdn, record_type, value, ttl, expires_at,
                               first_seen, last_seen, active
                           ) VALUES (?1, 'A', ?2, 60, ?3, ?4, ?4, 1)"#,
                        params![
                            host,
                            format!("192.0.2.{}", offset + 10),
                            PERMANENT_EXPIRY,
                            now
                        ],
                    )
                    .unwrap();
            }
        }

        let mut negatives = Vec::with_capacity(502);
        negatives.push(existing[0].to_owned());
        negatives.extend((0..500).map(|index| format!("absent-{index}.example.com")));
        negatives.push(existing[1].to_owned());
        db.update_cache_outcomes(Some(scan_id), &[], &negatives, &[], 300)
            .unwrap();

        let connection = db.lock().unwrap();
        let scalar = |sql: &str| {
            connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .unwrap()
        };
        assert_eq!(scalar("SELECT COUNT(*) FROM subdomains"), 2);
        assert_eq!(
            scalar(
                "SELECT COUNT(*) FROM subdomains \
                 WHERE active=0 AND verification_state='historical'"
            ),
            2
        );
        assert_eq!(
            scalar("SELECT COUNT(*) FROM subdomains WHERE fqdn LIKE 'absent-%'"),
            0
        );
        assert_eq!(scalar("SELECT COUNT(*) FROM dns_records WHERE active=0"), 2);
        assert_eq!(scalar("SELECT COUNT(*) FROM dns_cache"), 502);
        assert_eq!(
            scalar("SELECT COUNT(*) FROM dns_verifications WHERE scan_id IS NOT NULL"),
            502
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
    fn exhausted_active_budget_leaves_every_active_source_queued() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[
                ("generated".to_owned(), "builtin".to_owned(), 100),
                ("resumed".to_owned(), "mutation".to_owned(), 90),
                ("explicit".to_owned(), "wordlist".to_owned(), 1),
            ],
        )
        .unwrap();

        let eligible = db
            .pending_scan_candidates_eligible(scan_id, 10, false)
            .unwrap();
        assert!(eligible.is_empty());
        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 3);
        assert_eq!(
            db.pending_scan_candidate_count_eligible(scan_id, false)
                .unwrap(),
            0
        );
        let untouched_active: i64 = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT COUNT(*) FROM scan_candidates
                   WHERE scan_id=?1 AND status='queued' AND attempts=0"#,
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(untouched_active, 3);

        let resumed = db
            .pending_scan_candidates_eligible(scan_id, 10, true)
            .unwrap();
        assert_eq!(
            resumed.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            vec!["generated", "resumed", "explicit"]
        );
    }

    #[test]
    fn unstarted_deadline_candidate_requeues_without_consuming_an_attempt() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "never-sent.example.com".to_owned();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[("never-sent".to_owned(), "builtin".to_owned(), 1)],
        )
        .unwrap();
        assert_eq!(db.pending_scan_candidates(scan_id, 1).unwrap().len(), 1);
        db.requeue_unstarted_scan_candidates(scan_id, std::slice::from_ref(&fqdn))
            .unwrap();
        let (status, attempts): (String, i64) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status,attempts FROM scan_candidates WHERE scan_id=?1 AND fqdn=?2",
                params![scan_id, fqdn],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((status.as_str(), attempts), ("queued", 0));
    }

    #[test]
    fn recursive_queue_pages_and_parent_cursors_survive_resume() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        let words = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        assert_eq!(
            db.ensure_scan_recursive_words(scan_id, &words).unwrap(),
            words
        );
        assert_eq!(
            db.ensure_scan_recursive_words(scan_id, &["changed".to_owned()])
                .unwrap(),
            words,
            "a resume must retain the original ordinal word list"
        );
        db.persist_scan_recursive_parents(scan_id, 2, &["api.example.com".to_owned()])
            .unwrap();
        assert_eq!(
            db.refill_scan_recursive_candidates(scan_id, 2, 2).unwrap(),
            2
        );
        let first = db.pending_scan_recursive_candidates(scan_id, 2, 2).unwrap();
        assert_eq!(
            first.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            vec!["a.api.example.com", "b.api.example.com"]
        );
        db.complete_scan_recursive_candidates(scan_id, &[first[0].0.clone()])
            .unwrap();
        db.requeue_unstarted_scan_recursive_candidates(scan_id, &[first[1].0.clone()])
            .unwrap();
        assert_eq!(
            db.refill_scan_recursive_candidates(scan_id, 2, 2).unwrap(),
            2
        );
        let second = db.pending_scan_recursive_candidates(scan_id, 2, 2).unwrap();
        assert_eq!(
            second.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            vec!["b.api.example.com", "c.api.example.com"]
        );

        db.pause_scan(scan_id, 0, 0, 0, 1, &[]).unwrap();
        db.reopen_scan(scan_id).unwrap();
        let resumed = db.pending_scan_recursive_candidates(scan_id, 2, 2).unwrap();
        assert_eq!(
            resumed.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            vec!["b.api.example.com", "c.api.example.com"]
        );
        db.complete_scan_recursive_candidates(
            scan_id,
            &resumed.into_iter().map(|row| row.0).collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(!db.scan_recursive_depth_has_more(scan_id, 2).unwrap());
        assert!(!db.scan_recursive_has_more(scan_id).unwrap());
    }

    #[test]
    fn live_results_from_the_same_scan_can_be_rehydrated_for_recursive_parents() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let answer = ResolvedHost {
            fqdn: "api.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(123),
            authoritative_validation: true,
            resolver_count: 2,
        };
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
            .unwrap();
        let sources = BTreeSet::from(["dns:test".to_owned()]);
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: answer.fqdn.clone(),
                records: answer.records.clone(),
                sources: sources.clone(),
                wildcard: false,
                from_cache: false,
                confidence: crate::confidence::assess(&sources, false, false),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                authoritative_validation: true,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();

        let hydrated = db.live_scan_answers(scan_id).unwrap();
        assert_eq!(hydrated.len(), 1);
        assert_eq!(hydrated[0].0.fqdn, answer.fqdn);
        assert_eq!(hydrated[0].0.records, answer.records);
        assert!(hydrated[0].0.from_cache);
        assert!(hydrated[0].0.authoritative_validation);
        assert_eq!(hydrated[0].1, sources);
    }

    #[test]
    fn passive_seed_queue_is_prioritized_durable_and_resumable() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        let axfr_sources = BTreeSet::from(["axfr:ns1.example.com".to_owned()]);
        let multi_sources =
            BTreeSet::from(["passive:crtsh".to_owned(), "passive:wayback".to_owned()]);
        let stale_sources = BTreeSet::from(["passive:otx:stale".to_owned()]);
        db.persist_scan_seed_candidates(
            scan_id,
            &[
                ("old.example.com".to_owned(), stale_sources.clone(), 10),
                ("api.example.com".to_owned(), multi_sources.clone(), 20),
                ("zone.example.com".to_owned(), axfr_sources.clone(), 30),
            ],
            3,
        )
        .unwrap();

        let first = db.pending_scan_seed_candidates(scan_id, 2).unwrap();
        assert_eq!(
            first.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            vec!["zone.example.com", "api.example.com"]
        );
        assert_eq!(first[0].1, axfr_sources);
        assert_eq!(first[1].1, multi_sources);
        db.mark_scan_seed_candidates_started(scan_id, &[first[0].0.clone()])
            .unwrap();
        db.mark_scan_seed_candidates_done(scan_id, &[first[0].0.clone()])
            .unwrap();

        db.lock()
            .unwrap()
            .execute(
                "UPDATE scans SET status='interrupted' WHERE id=?1",
                [scan_id],
            )
            .unwrap();
        db.reopen_scan(scan_id).unwrap();
        let resumed = db.pending_scan_seed_candidates(scan_id, 10).unwrap();
        assert_eq!(
            resumed.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
            vec!["api.example.com", "old.example.com"]
        );
        assert_eq!(resumed[1].1, stale_sources);
        assert_eq!(db.scan_seed_candidate_count(scan_id).unwrap(), 3);

        db.clear_scan_candidates(scan_id).unwrap();
        assert_eq!(db.scan_seed_candidate_count(scan_id).unwrap(), 0);
    }

    #[test]
    fn named_seed_claim_is_atomic_exact_and_bounded() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let sources = BTreeSet::from(["passive:ct-direct".to_owned()]);
        db.persist_scan_seed_candidates(
            scan_id,
            &[
                ("a.example.com".to_owned(), sources.clone(), 1),
                ("b.example.com".to_owned(), sources.clone(), 2),
                ("c.example.com".to_owned(), sources, 3),
            ],
            3,
        )
        .unwrap();
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap()[0].0,
            "c.example.com"
        );

        let claimed = db
            .claim_scan_seed_candidates_by_name(
                scan_id,
                &[
                    "c.example.com".to_owned(),
                    "b.example.com".to_owned(),
                    "missing.example.com".to_owned(),
                    "b.example.com".to_owned(),
                ],
            )
            .unwrap();
        assert_eq!(claimed, vec!["b.example.com"]);
        assert!(
            db.claim_scan_seed_candidates_by_name(scan_id, &["b.example.com".to_owned()],)
                .unwrap()
                .is_empty()
        );
        let connection = db.lock().unwrap();
        let mut statement = connection
            .prepare(
                "SELECT fqdn, status, attempts FROM scan_seed_candidates WHERE scan_id=?1 ORDER BY fqdn",
            )
            .unwrap();
        let states = statement
            .query_map([scan_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        drop(statement);
        drop(connection);
        assert_eq!(
            states,
            vec![
                ("a.example.com".to_owned(), "queued".to_owned(), 0),
                ("b.example.com".to_owned(), "processing".to_owned(), 0),
                ("c.example.com".to_owned(), "processing".to_owned(), 0),
            ]
        );

        let too_many = (0..=MAX_NAMED_SEED_CLAIM)
            .map(|index| format!("host-{index}.example.com"))
            .collect::<Vec<_>>();
        assert!(
            db.claim_scan_seed_candidates_by_name(scan_id, &too_many)
                .is_err()
        );
        assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 1);
    }

    #[test]
    fn passive_seed_errors_retry_three_times_then_remain_terminal_on_resume() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        let host = "api.example.com".to_owned();
        db.persist_scan_seed_candidates(
            scan_id,
            &[(
                host.clone(),
                BTreeSet::from(["passive:test".to_owned()]),
                10,
            )],
            1,
        )
        .unwrap();

        for attempt in 1..=3 {
            assert_eq!(
                db.pending_scan_seed_candidates(scan_id, 1).unwrap()[0].0,
                host
            );
            db.mark_scan_seed_candidates_started(scan_id, std::slice::from_ref(&host))
                .unwrap();
            db.update_cache_outcomes(Some(scan_id), &[], &[], std::slice::from_ref(&host), 300)
                .unwrap();
            db.mark_scan_seed_candidates_done(scan_id, std::slice::from_ref(&host))
                .unwrap();
            assert_eq!(
                db.pending_scan_seed_candidate_count(scan_id).unwrap(),
                i64::from(attempt < 3)
            );
        }

        db.finish_scan(scan_id, "interrupted", 1, 0, 0, 1, &[])
            .unwrap();
        db.reopen_scan(scan_id).unwrap();
        assert!(
            db.pending_scan_seed_candidates(scan_id, 1)
                .unwrap()
                .is_empty()
        );
        let (status, attempts): (String, i64) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status,attempts FROM scan_seed_candidates WHERE scan_id=?1 AND fqdn=?2",
                params![scan_id, host],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((status.as_str(), attempts), ("done", 3));
    }

    #[test]
    fn promoting_a_terminal_active_candidate_to_a_seed_does_not_reopen_word_budget() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let host = "api.example.com".to_owned();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[("api".to_owned(), "mutation".to_owned(), 10)],
        )
        .unwrap();
        db.pending_scan_candidates(scan_id, 1).unwrap();
        db.update_cache_outcomes(Some(scan_id), &[], std::slice::from_ref(&host), &[], 300)
            .unwrap();
        db.record_scan_candidate_results(
            scan_id,
            &[(host.clone(), "api".to_owned(), "mutation".to_owned(), false)],
        )
        .unwrap();
        db.mark_scan_candidates_done(scan_id, std::slice::from_ref(&host))
            .unwrap();
        assert_eq!(db.scan_candidate_budget_count(scan_id).unwrap(), 1);

        db.persist_scan_seed_candidates(
            scan_id,
            &[(host, BTreeSet::from(["passive:test".to_owned()]), 20)],
            1,
        )
        .unwrap();
        assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 0);
        assert_eq!(db.scan_candidate_budget_count(scan_id).unwrap(), 1);
    }

    #[test]
    fn a_full_seed_queue_merges_provenance_and_replaces_only_unattempted_low_priority_rows() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let original = BTreeSet::from(["passive:first".to_owned()]);
        db.persist_scan_seed_candidates(
            scan_id,
            &[
                ("attempted.example.com".to_owned(), original.clone(), 10),
                ("low.example.com".to_owned(), original.clone(), 5),
            ],
            2,
        )
        .unwrap();
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap()[0].0,
            "attempted.example.com"
        );
        db.persist_scan_seed_candidates(
            scan_id,
            &[
                (
                    "attempted.example.com".to_owned(),
                    BTreeSet::from(["passive:second".to_owned()]),
                    30,
                ),
                (
                    "high.example.com".to_owned(),
                    BTreeSet::from(["axfr:ns1.example.com".to_owned()]),
                    20,
                ),
            ],
            2,
        )
        .unwrap();

        let rows = db.scan_seed_candidates_for_output(scan_id).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|(fqdn, sources)| {
            fqdn == "attempted.example.com"
                && sources
                    == &BTreeSet::from(["passive:first".to_owned(), "passive:second".to_owned()])
        }));
        assert!(rows.iter().any(|(fqdn, _)| fqdn == "high.example.com"));
        assert!(!rows.iter().any(|(fqdn, _)| fqdn == "low.example.com"));
    }

    #[test]
    fn scan_finalization_applies_learning_exactly_once() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        let attempts = HashMap::from([("mutation".to_owned(), 2_usize)]);
        let successes = HashMap::from([("mutation".to_owned(), 1_usize)]);
        let attempted_words = BTreeSet::from(["api".to_owned(), "dev".to_owned()]);
        let successful_words = BTreeSet::from(["api".to_owned()]);
        let successful_patterns = BTreeSet::from(["api".to_owned()]);

        db.finalize_scan_with_learning(
            scan_id,
            "example.com",
            &attempts,
            &successes,
            &attempted_words,
            &successful_words,
            &successful_patterns,
            2,
            1,
            0,
            10,
            &[],
        )
        .unwrap();
        assert!(
            db.finalize_scan_with_learning(
                scan_id,
                "example.com",
                &attempts,
                &successes,
                &attempted_words,
                &successful_words,
                &successful_patterns,
                2,
                1,
                0,
                10,
                &[],
            )
            .is_err()
        );

        let connection = db.lock().unwrap();
        let scan: (String, i64) = connection
            .query_row(
                "SELECT status,learning_applied FROM scans WHERE id=?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(scan, ("completed".to_owned(), 1));
        let word: (i64, i64, i64) = connection
            .query_row(
                "SELECT attempts,successes,unique_domains FROM word_stats WHERE word='api'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(word, (1, 1, 1));
        let generator: (i64, i64) = connection
            .query_row(
                "SELECT attempts,successes FROM generator_stats WHERE generator='mutation'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(generator, (2, 1));
    }

    #[test]
    fn builtin_corpus_feed_resumes_from_its_durable_cursor() {
        let db = Database::in_memory().unwrap();
        let expected = db.prior_candidates(4).unwrap();
        assert_eq!(expected.len(), 4);
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();

        assert_eq!(
            db.refill_prior_candidates_to_scan(scan_id, "example.com", 2)
                .unwrap()
                .0,
            2
        );
        let first = db.pending_scan_candidates(scan_id, 2).unwrap();
        assert_eq!(
            first.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
            expected[..2]
        );
        db.mark_scan_candidates_done(
            scan_id,
            &first
                .iter()
                .map(|row| format!("{}.example.com", row.0))
                .collect::<Vec<_>>(),
        )
        .unwrap();

        assert_eq!(
            db.refill_prior_candidates_to_scan(scan_id, "example.com", 2)
                .unwrap()
                .0,
            2
        );
        let second = db.pending_scan_candidates(scan_id, 2).unwrap();
        assert_eq!(
            second.iter().map(|row| row.0.clone()).collect::<Vec<_>>(),
            expected[2..]
        );
        let cursor: i64 = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor FROM scan_candidate_feeds WHERE scan_id=?1 AND source='builtin'",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        let expected_cursor: i64 = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT priority FROM candidate_priors WHERE relative_name=?1",
                [&expected[3]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, expected_cursor);
        let cursor_text: String = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor_text FROM scan_candidate_feeds WHERE scan_id=?1 AND source='builtin'",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor_text, expected[3]);
    }

    #[test]
    fn stale_running_scans_are_reconciled_but_fresh_leases_are_preserved() {
        let db = Database::in_memory().unwrap();
        let stale = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(stale, "example.com", "running", "stale-hash")
            .unwrap();
        let fresh = db.create_scan("example.net", &json!({})).unwrap();
        db.upsert_checkpoint(fresh, "example.net", "running", "fresh-hash")
            .unwrap();
        db.stage_refresh_wildcard_candidates(stale, &["old.example.com".to_owned()])
            .unwrap();
        db.stage_refresh_wildcard_candidates(fresh, &["new.example.net".to_owned()])
            .unwrap();
        db.lock()
            .unwrap()
            .execute(
                "UPDATE scan_checkpoints SET updated_at=?1 WHERE scan_id=?2",
                params![now_epoch() - 600, stale],
            )
            .unwrap();

        assert_eq!(
            db.reconcile_stale_scans(std::time::Duration::from_secs(120))
                .unwrap(),
            1
        );
        let statuses = db
            .lock()
            .unwrap()
            .prepare("SELECT id, status FROM scans ORDER BY id")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            statuses,
            vec![
                (stale, "interrupted".to_owned()),
                (fresh, "running".to_owned())
            ]
        );
        assert!(db.reopen_scan(fresh).is_err());
        assert!(db.reopen_scan(stale).is_ok());
        assert_eq!(db.refresh_wildcard_candidate_count(stale).unwrap(), 0);
        assert_eq!(db.refresh_wildcard_candidate_count(fresh).unwrap(), 1);
    }

    #[test]
    fn indeterminate_scan_candidates_retry_three_times_then_become_terminal() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[
                ("deferred".to_owned(), "test".to_owned(), 10),
                ("negative".to_owned(), "test".to_owned(), 9),
            ],
        )
        .unwrap();
        let first_claim = db.pending_scan_candidates(scan_id, 10).unwrap();
        db.mark_scan_candidates_started(
            scan_id,
            &first_claim
                .iter()
                .map(|row| format!("{}.example.com", row.0))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        db.update_cache_outcomes(
            Some(scan_id),
            &[],
            &["negative.example.com".to_owned()],
            &["deferred.example.com".to_owned()],
            300,
        )
        .unwrap();
        db.mark_scan_candidates_done(
            scan_id,
            &[
                "deferred.example.com".to_owned(),
                "negative.example.com".to_owned(),
            ],
        )
        .unwrap();

        let second_claim = db.pending_scan_candidates(scan_id, 10).unwrap();
        assert_eq!(
            second_claim
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["deferred"]
        );
        db.mark_scan_candidates_started(scan_id, &["deferred.example.com".to_owned()])
            .unwrap();
        db.update_cache_outcomes(
            Some(scan_id),
            &[],
            &[],
            &["deferred.example.com".to_owned()],
            300,
        )
        .unwrap();
        db.mark_scan_candidates_done(scan_id, &["deferred.example.com".to_owned()])
            .unwrap();
        let third_claim = db.pending_scan_candidates(scan_id, 10).unwrap();
        assert_eq!(
            third_claim
                .iter()
                .map(|(name, _, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["deferred"]
        );
        db.mark_scan_candidates_started(scan_id, &["deferred.example.com".to_owned()])
            .unwrap();
        db.update_cache_outcomes(
            Some(scan_id),
            &[],
            &[],
            &["deferred.example.com".to_owned()],
            300,
        )
        .unwrap();
        db.mark_scan_candidates_done(scan_id, &["deferred.example.com".to_owned()])
            .unwrap();
        assert!(db.pending_scan_candidates(scan_id, 10).unwrap().is_empty());
        let negative_status: String = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status FROM scan_candidates WHERE scan_id=?1 AND relative_name='negative'",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(negative_status, "done");
        let (deferred_status, attempts): (String, i64) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status,attempts FROM scan_candidates WHERE scan_id=?1 AND relative_name='deferred'",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(deferred_status, "done");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn a_new_scan_supersedes_only_abandoned_queues_and_preserves_inventory() {
        let db = Database::in_memory().unwrap();
        db.import_inventory(
            "example.com",
            &BTreeSet::from(["api.example.com".to_owned()]),
            "import:test",
        )
        .unwrap();

        let abandoned = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(abandoned, "example.com", "running", "old")
            .unwrap();
        db.persist_scan_candidates(
            abandoned,
            "example.com",
            &[("old".to_owned(), "test".to_owned(), 1)],
        )
        .unwrap();
        db.mark_scan_candidate_feed_exhausted(abandoned, "high-value")
            .unwrap();
        db.finish_scan(abandoned, "interrupted", 1, 0, 0, 1, &[])
            .unwrap();

        let active = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(active, "example.com", "running", "active")
            .unwrap();
        db.persist_scan_candidates(
            active,
            "example.com",
            &[("active".to_owned(), "test".to_owned(), 1)],
        )
        .unwrap();

        let newest = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(newest, "example.com", "running", "new")
            .unwrap();
        assert_eq!(
            db.supersede_incomplete_candidate_queues(
                "example.com",
                newest,
                std::time::Duration::from_secs(120),
            )
            .unwrap(),
            1
        );

        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1",
                    [abandoned],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM scan_candidates WHERE scan_id=?1",
                    [active],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let abandoned_state: (String, String, i64) = connection
            .query_row(
                r#"SELECT scan.status, checkpoint.stage, checkpoint.completed
                   FROM scans AS scan
                   JOIN scan_checkpoints AS checkpoint ON checkpoint.scan_id=scan.id
                   WHERE scan.id=?1"#,
                [abandoned],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            abandoned_state,
            ("superseded".to_owned(), "superseded".to_owned(), 1)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT completed FROM scan_checkpoints WHERE scan_id=?1",
                    [newest],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM subdomains WHERE fqdn='api.example.com'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn superseded_queue_cleanup_is_bounded_and_resumable() {
        let db = Database::in_memory().unwrap();
        let abandoned = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(abandoned, "example.com", "running", "old")
            .unwrap();
        let candidates = (0..2_505)
            .map(|index| (format!("old-{index}"), "test".to_owned(), 1))
            .collect::<Vec<_>>();
        db.persist_scan_candidates(abandoned, "example.com", &candidates)
            .unwrap();
        db.finish_scan(abandoned, "interrupted", candidates.len(), 0, 0, 1, &[])
            .unwrap();

        let newest = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(newest, "example.com", "running", "new")
            .unwrap();
        assert_eq!(
            db.supersede_incomplete_candidate_queues(
                "example.com",
                newest,
                std::time::Duration::from_secs(120),
            )
            .unwrap(),
            2_000
        );
        assert_eq!(db.scan_candidate_count(abandoned).unwrap(), 505);
        assert_eq!(db.prune_superseded_candidate_queues(500).unwrap(), 500);
        assert_eq!(db.scan_candidate_count(abandoned).unwrap(), 5);
        assert_eq!(db.prune_superseded_candidate_queues(100).unwrap(), 5);
        assert_eq!(db.scan_candidate_count(abandoned).unwrap(), 0);
    }

    #[test]
    fn confirmed_wildcard_cleanup_quarantines_all_exact_matches_and_keeps_audit() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let answer = |fqdn: &str| ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "203.0.113.10".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let finding = |fqdn: &str, source: &str| Finding {
            fqdn: fqdn.to_owned(),
            records: answer(fqdn).records,
            sources: BTreeSet::from([source.to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from([source.to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: Some(now_epoch()),
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        };
        let generated = "generated.example.com";
        let cached_only = "cached-only.example.com";
        let observed = "observed.example.com";
        db.persist_findings(
            scan_id,
            "example.com",
            &[
                finding(generated, "dns-wave-2"),
                finding(observed, "passive:subdomainapp"),
            ],
            86_400,
        )
        .unwrap();
        db.update_cache_outcomes(
            Some(scan_id),
            &[answer(generated), answer(cached_only), answer(observed)],
            &[],
            &[],
            300,
        )
        .unwrap();
        db.store_observations(
            "example.com",
            vec![
                ObservationInput {
                    fqdn: generated.to_owned(),
                    kind: "dns-wave-2".to_owned(),
                    source: "dns-wave-2".to_owned(),
                    value: String::new(),
                },
                ObservationInput {
                    fqdn: observed.to_owned(),
                    kind: "passive".to_owned(),
                    source: "passive:subdomainapp".to_owned(),
                    value: String::new(),
                },
            ],
        )
        .unwrap();
        db.record_current_wildcard_matches(
            scan_id,
            &[answer(generated), answer(cached_only), answer(observed)],
        )
        .unwrap();
        let purged = db
            .purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                &[
                    generated.to_owned(),
                    cached_only.to_owned(),
                    observed.to_owned(),
                ],
            )
            .unwrap();
        assert_eq!(purged, vec![cached_only, generated, observed]);
        assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
        assert!(
            db.fresh_cache(&[
                generated.to_owned(),
                cached_only.to_owned(),
                observed.to_owned(),
            ])
            .unwrap()
            .is_empty()
        );
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM observed_names WHERE fqdn=?1",
                    [generated],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1",
                    [scan_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1 AND fqdn=?2",
                    params![scan_id, generated],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM dns_records WHERE fqdn=?1",
                    [generated],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT active FROM dns_records WHERE fqdn=?1",
                    [generated],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT found FROM scans WHERE id=?1", [scan_id], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM wildcard_quarantine WHERE root_domain='example.com'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            3
        );
    }

    #[test]
    fn wildcard_marker_is_cache_independent_and_hashes_records_without_ttl_or_order() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let mut answer = ResolvedHost {
            fqdn: "candidate.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 1,
        };
        assert_eq!(
            db.record_current_wildcard_matches(scan_id, &[answer.clone()])
                .unwrap(),
            0
        );
        answer.authoritative_validation = true;
        assert_eq!(
            db.record_current_wildcard_matches(scan_id, &[answer.clone()])
                .unwrap(),
            1,
            "an authoritative current answer is equivalent to resolver consensus"
        );
        answer.authoritative_validation = false;
        answer.resolver_count = 2;
        answer.records.clear();
        assert_eq!(
            db.record_current_wildcard_matches(scan_id, &[answer.clone()])
                .unwrap(),
            0
        );
        answer.records.push(DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        });
        answer.records.push(DnsRecord {
            record_type: "CNAME".to_owned(),
            value: "edge.example.net".to_owned(),
            ttl: 120,
        });
        answer.from_cache = true;
        assert_eq!(
            db.record_current_wildcard_matches(scan_id, &[answer.clone()])
                .unwrap(),
            0
        );
        answer.from_cache = false;
        assert_eq!(
            db.record_current_wildcard_matches(scan_id, &[answer.clone()])
                .unwrap(),
            1
        );
        let journal_hash = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT records_hash FROM dns_verifications \
                 WHERE scan_id=?1 AND fqdn=?2 ORDER BY id DESC LIMIT 1",
                params![scan_id, answer.fqdn],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let reordered_with_new_ttls = vec![
            DnsRecord {
                record_type: "cname".to_owned(),
                value: "edge.example.net".to_owned(),
                ttl: 1,
            },
            DnsRecord {
                record_type: "a".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 9_999,
            },
        ];
        assert_eq!(
            journal_hash,
            canonical_dns_records_hash(&reordered_with_new_ttls).unwrap()
        );
        assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                &[answer.fqdn.clone()],
            )
            .unwrap(),
            vec![answer.fqdn.clone()],
            "cleanup authorization must not require a positive dns_cache row"
        );
        let explanation = db.explain(&answer.fqdn).unwrap();
        assert_eq!(explanation["known"], true);
        assert_eq!(explanation["quarantine"].as_array().unwrap().len(), 1);
        assert!(
            db.purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                &["outside.example.net".to_owned()],
            )
            .is_err()
        );
    }

    #[test]
    fn wildcard_ambiguity_is_unverified_without_a_resolver_error() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "rotating.example.com";
        let answer = ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let sources = BTreeSet::from(["passive:test".to_owned()]);
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.to_owned(),
                records: answer.records.clone(),
                sources: sources.clone(),
                wildcard: false,
                from_cache: false,
                confidence: crate::confidence::assess(&sources, false, false),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                evidence_families: BTreeSet::new(),
                authoritative_validation: false,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
            .unwrap();

        assert_eq!(
            db.record_current_wildcard_ambiguities(
                scan_id,
                "example.com",
                std::slice::from_ref(&answer),
            )
            .unwrap(),
            1
        );
        assert!(
            !db.fresh_cache(&[fqdn.to_owned()])
                .unwrap()
                .contains_key(fqdn)
        );
        let inventory = db.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state, ObservationState::Unverified);
        let connection = db.lock().unwrap();
        let (outcome, details): (String, String) = connection
            .query_row(
                r#"SELECT outcome, details_json FROM dns_verifications
                   WHERE scan_id=?1 AND fqdn=?2 ORDER BY id DESC LIMIT 1"#,
                params![scan_id, fqdn],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(outcome, "unverified");
        assert_eq!(details, CURRENT_SCAN_WILDCARD_AMBIGUITY_DETAILS);
        assert_eq!(
            connection
                .query_row(
                    "SELECT active FROM dns_records WHERE fqdn=?1",
                    [fqdn],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn wildcard_quarantine_is_root_scoped_hidden_and_reversible() {
        let db = Database::in_memory().unwrap();
        let parent_scan = db.create_scan("example.com", &json!({})).unwrap();
        let child_scan = db.create_scan("sub.example.com", &json!({})).unwrap();
        let fqdn = "api.sub.example.com";
        let answer = ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.70".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let finding = Finding {
            fqdn: fqdn.to_owned(),
            records: answer.records.clone(),
            sources: BTreeSet::from(["dns-wave-2".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["dns-wave-2".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
            authoritative_validation: false,
            ..Finding::default()
        };
        db.persist_findings(
            parent_scan,
            "example.com",
            std::slice::from_ref(&finding),
            86_400,
        )
        .unwrap();
        db.record_current_wildcard_matches(parent_scan, std::slice::from_ref(&answer))
            .unwrap();
        db.record_current_wildcard_matches(child_scan, std::slice::from_ref(&answer))
            .unwrap();
        assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                parent_scan,
                "example.com",
                &[fqdn.to_owned()],
            )
            .unwrap(),
            vec![fqdn]
        );
        assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                child_scan,
                "sub.example.com",
                &[fqdn.to_owned()],
            )
            .unwrap(),
            vec![fqdn]
        );
        assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
        let explanation = db.explain(fqdn).unwrap();
        assert_eq!(explanation["quarantine"].as_array().unwrap().len(), 2);
        assert_eq!(explanation["scan_history"].as_array().unwrap().len(), 1);

        db.persist_findings(parent_scan, "example.com", &[finding], 86_400)
            .unwrap();
        assert_eq!(db.inventory(Some("example.com"), false).unwrap().len(), 1);
        let connection = db.lock().unwrap();
        let mut statement = connection
            .prepare(
                "SELECT root_domain FROM wildcard_quarantine WHERE fqdn=?1 ORDER BY root_domain",
            )
            .unwrap();
        let quarantined_roots = statement
            .query_map([fqdn], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(quarantined_roots, vec!["sub.example.com"]);
    }

    #[test]
    fn wildcard_consensus_quarantines_despite_independent_passive_evidence() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "api.example.com";
        let answer = ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.80".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let sources = BTreeSet::from(["dns-wave-2".to_owned()]);
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.to_owned(),
                records: answer.records.clone(),
                sources: sources.clone(),
                wildcard: false,
                from_cache: false,
                confidence: crate::confidence::assess(&sources, false, false),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                authoritative_validation: false,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
        db.record_current_wildcard_matches(scan_id, std::slice::from_ref(&answer))
            .unwrap();
        assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                &[fqdn.to_owned()],
            )
            .unwrap(),
            vec![fqdn]
        );
        assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
        db.store_observations(
            "archive.example.net",
            vec![ObservationInput {
                fqdn: fqdn.to_owned(),
                kind: "passive".to_owned(),
                source: "passive:cross-root".to_owned(),
                value: String::new(),
            }],
        )
        .unwrap();
        db.record_current_wildcard_matches(scan_id, &[answer])
            .unwrap();
        assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                &[fqdn.to_owned()],
            )
            .unwrap(),
            vec![fqdn]
        );
        assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM wildcard_quarantine WHERE fqdn=?1",
                    [fqdn],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM observation_evidence WHERE source='passive:cross-root'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "quarantine must preserve passive evidence for explain/audit"
        );
    }

    #[test]
    fn refresh_wildcard_staging_accepts_large_inventories_in_bounded_batches() {
        let db = Database::in_memory().unwrap();
        let scan_id = db
            .create_scan("example.com", &json!({"mode": "refresh"}))
            .unwrap();
        let names = (0..20_000)
            .map(|index| format!("candidate-{index:05}.example.com"))
            .collect::<Vec<_>>();
        for page in names.chunks(257) {
            db.stage_refresh_wildcard_candidates(scan_id, page).unwrap();
        }
        assert_eq!(
            db.refresh_wildcard_candidate_count(scan_id).unwrap(),
            20_000
        );
        assert_eq!(
            db.stage_refresh_wildcard_candidates(scan_id, &names[..500])
                .unwrap(),
            0,
            "staging is idempotent across overlapping refresh pages"
        );
        assert_eq!(
            db.discard_refresh_wildcard_candidates(scan_id).unwrap(),
            20_000
        );
        assert_eq!(db.refresh_wildcard_candidate_count(scan_id).unwrap(), 0);
    }

    #[test]
    fn cached_wildcard_match_without_current_network_marker_is_demoted_not_deleted() {
        let db = Database::in_memory().unwrap();
        let scan_id = db
            .create_scan("example.com", &json!({"mode": "refresh"}))
            .unwrap();
        let fqdn = "cached.example.com";
        let answer = ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let finding = Finding {
            fqdn: fqdn.to_owned(),
            records: answer.records.clone(),
            sources: BTreeSet::from(["dns-wave-2".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["dns-wave-2".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        };
        db.persist_findings(scan_id, "example.com", &[finding], 86_400)
            .unwrap();
        // An ordinary historical/live journal row and a positive cache entry
        // are intentionally insufficient: cleanup requires the dedicated
        // current-scan network wildcard marker.
        db.update_cache_outcomes(Some(scan_id), &[answer], &[], &[], 300)
            .unwrap();
        db.stage_refresh_wildcard_candidates(scan_id, &[fqdn.to_owned()])
            .unwrap();

        let result = db
            .apply_staged_refresh_wildcard_cleanup(
                scan_id,
                "example.com",
                1,
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            result,
            WildcardCleanupResult {
                purged: 0,
                retained_unverified: 1,
            }
        );
        let inventory = db.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].state, ObservationState::Unverified);
        assert!(matches!(
            db.fresh_cache(&[fqdn.to_owned()]).unwrap().get(fqdn),
            Some(CachedAnswer::Positive(_))
        ));
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM dns_records WHERE fqdn=?1",
                    [fqdn],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT active FROM dns_records WHERE fqdn=?1",
                    [fqdn],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn cancelled_staged_wildcard_cleanup_rolls_back_every_destructive_change() {
        let db = Database::in_memory().unwrap();
        let original_scan = db.create_scan("example.com", &json!({})).unwrap();
        let refresh_scan = db
            .create_scan("example.com", &json!({"mode": "refresh"}))
            .unwrap();
        let make = |fqdn: &str, source: &str| Finding {
            fqdn: fqdn.to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            sources: BTreeSet::from([source.to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from([source.to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Live,
            last_verified_at: Some(now_epoch()),
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        };
        let mut findings = vec![make("a-independent.example.com", "passive:crtsh")];
        findings.extend(
            (0..12).map(|index| make(&format!("weak-{index:02}.example.com"), "dns-wave-2")),
        );
        db.persist_findings(original_scan, "example.com", &findings, 86_400)
            .unwrap();
        db.finish_scan(
            original_scan,
            "completed",
            findings.len(),
            findings.len(),
            0,
            1,
            &[],
        )
        .unwrap();
        let names = findings
            .iter()
            .map(|finding| finding.fqdn.clone())
            .collect::<Vec<_>>();
        let wildcard_answers = names
            .iter()
            .map(|fqdn| ResolvedHost {
                fqdn: fqdn.clone(),
                records: vec![DnsRecord {
                    record_type: "A".to_owned(),
                    value: "192.0.2.44".to_owned(),
                    ttl: 60,
                }],
                from_cache: false,
                last_verified_at: Some(now_epoch()),
                authoritative_validation: false,
                resolver_count: 2,
            })
            .collect::<Vec<_>>();
        db.record_current_wildcard_matches(refresh_scan, &wildcard_answers)
            .unwrap();
        db.stage_refresh_wildcard_candidates(refresh_scan, &names)
            .unwrap();

        let result = db
            .apply_staged_refresh_wildcard_cleanup_with_cancel(
                refresh_scan,
                "example.com",
                2,
                |processed| processed >= 3,
            )
            .unwrap();
        assert!(result.is_none());
        assert_eq!(
            db.refresh_wildcard_candidate_count(refresh_scan).unwrap(),
            findings.len(),
            "a rolled-back transaction leaves staging available for explicit discard"
        );
        let inventory = db.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), findings.len());
        assert!(
            inventory
                .iter()
                .all(|entry| entry.state == ObservationState::Live)
        );
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1",
                    [original_scan],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            findings.len() as i64
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT found FROM scans WHERE id=?1",
                    [original_scan],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            findings.len() as i64
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM dns_verifications WHERE scan_id=?1",
                    [refresh_scan],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            findings.len() as i64
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM dns_records WHERE fqdn LIKE '%.example.com'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            findings.len() as i64,
            "record deactivation/deletion must roll back with inventory cleanup"
        );
        drop(connection);

        let applied = db
            .apply_staged_refresh_wildcard_cleanup(
                refresh_scan,
                "example.com",
                2,
                &AtomicBool::new(false),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            applied,
            WildcardCleanupResult {
                purged: 13,
                retained_unverified: 0,
            }
        );
        assert_eq!(
            db.refresh_wildcard_candidate_count(refresh_scan).unwrap(),
            0
        );
        assert!(db.inventory(Some("example.com"), false).unwrap().is_empty());
        let connection = db.lock().unwrap();
        let (finding_count, changed_findings, found): (i64, i64, i64) = connection
            .query_row(
                r#"SELECT COUNT(*),
                          SUM(CASE WHEN finding.wildcard<>0 OR finding.state<>'live'
                                   THEN 1 ELSE 0 END),
                          scans.found
                   FROM scan_findings finding
                   JOIN scans ON scans.id=finding.scan_id
                   WHERE finding.scan_id=?1"#,
                [original_scan],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((finding_count, changed_findings, found), (13, 0, 13));
        let (records, active_records): (i64, i64) = connection
            .query_row(
                r#"SELECT COUNT(*), COALESCE(SUM(active), 0) FROM dns_records
                   WHERE fqdn LIKE '%.example.com'"#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((records, active_records), (13, 0));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM wildcard_quarantine WHERE root_domain='example.com'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            13
        );
    }

    #[test]
    fn cancelled_staged_cleanup_never_waits_for_the_shared_database_lock() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.stage_refresh_wildcard_candidates(scan_id, &["weak.example.com".to_owned()])
            .unwrap();

        let held_lock = db.lock().unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_db = db.clone();
        let (result_tx, result_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = worker_db.apply_staged_refresh_wildcard_cleanup(
                scan_id,
                "example.com",
                1,
                &worker_cancelled,
            );
            let _ = result_tx.send(result);
        });

        std::thread::sleep(Duration::from_millis(25));
        cancelled.store(true, Ordering::Release);
        let result = result_rx.recv_timeout(Duration::from_millis(500));
        drop(held_lock);
        worker.join().unwrap();

        assert!(
            result
                .expect("cleanup ignored cancellation while waiting for SQLite")
                .unwrap()
                .is_none()
        );
        assert_eq!(db.refresh_wildcard_candidate_count(scan_id).unwrap(), 1);
    }

    #[test]
    fn candidate_attempt_counters_saturate_at_sqlite_integer_max() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let active = "active.example.com";
        let recursive = "recursive.example.com";
        db.lock()
            .unwrap()
            .execute(
                r#"INSERT INTO scan_candidates(
                       scan_id, fqdn, relative_name, priority, generator, attempts, status
                   ) VALUES (?1, ?2, 'active', 1, 'fixture', ?3, 'processing')"#,
                params![scan_id, active, i64::MAX],
            )
            .unwrap();
        db.lock()
            .unwrap()
            .execute(
                r#"INSERT INTO scan_recursive_candidates(
                       scan_id, fqdn, parent, depth, word, attempts, status
                   ) VALUES (?1, ?2, 'example.com', 2, 'recursive', ?3, 'processing')"#,
                params![scan_id, recursive, i64::MAX],
            )
            .unwrap();

        db.mark_scan_candidates_started(scan_id, &[active.to_owned()])
            .unwrap();
        db.mark_scan_recursive_candidates_started(scan_id, &[recursive.to_owned()])
            .unwrap();

        let connection = db.lock().unwrap();
        for (table, fqdn) in [
            ("scan_candidates", active),
            ("scan_recursive_candidates", recursive),
        ] {
            let query = format!(
                "SELECT attempts, typeof(attempts) FROM {table} WHERE scan_id=?1 AND fqdn=?2"
            );
            let (attempts, value_type): (i64, String) = connection
                .query_row(&query, params![scan_id, fqdn], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap();
            assert_eq!(attempts, i64::MAX);
            assert_eq!(value_type, "integer");
        }
    }

    #[test]
    fn scan_snapshot_replaces_rows_and_late_heartbeat_cannot_reopen_completion() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let make = |fqdn: &str| Finding {
            fqdn: fqdn.to_owned(),
            records: Vec::new(),
            sources: BTreeSet::from(["passive:test".to_owned()]),
            wildcard: false,
            from_cache: false,
            confidence: crate::confidence::assess(
                &BTreeSet::from(["passive:test".to_owned()]),
                false,
                false,
            ),
            state: ObservationState::Unverified,
            last_verified_at: None,
            evidence_families: BTreeSet::new(),
            authoritative_validation: false,
            ..Finding::default()
        };
        let first = make("one.example.com");
        let second = make("two.example.com");
        db.persist_findings(
            scan_id,
            "example.com",
            &[first.clone(), second.clone()],
            86_400,
        )
        .unwrap();
        db.persist_scan_snapshot(scan_id, std::slice::from_ref(&first))
            .unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        db.finalize_scan(scan_id, 2, 1, 0, 1, &[]).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM scan_findings WHERE scan_id=?1",
                    [scan_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT completed FROM scan_checkpoints WHERE scan_id=?1",
                    [scan_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn non_resumable_refresh_finalization_closes_its_checkpoint() {
        let db = Database::in_memory().unwrap();
        let scan_id = db
            .create_scan("example.com", &json!({"mode": "refresh"}))
            .unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "refresh-options")
            .unwrap();
        db.finalize_non_resumable_scan(
            scan_id,
            "interrupted",
            12,
            3,
            0,
            25,
            &["interrupted safely".to_owned()],
        )
        .unwrap();

        assert!(
            db.resumable_checkpoint("example.com", "latest")
                .unwrap()
                .is_none()
        );
        let connection = db.lock().unwrap();
        let (status, completed) = connection
            .query_row(
                r#"SELECT scans.status, checkpoint.completed
                   FROM scans JOIN scan_checkpoints checkpoint ON checkpoint.scan_id=scans.id
                   WHERE scans.id=?1"#,
                [scan_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap();
        assert_eq!(status, "interrupted");
        assert_eq!(completed, 1);
    }

    #[test]
    fn active_budget_pause_keeps_checkpoint_feeds_and_candidates_resumable() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[("pending".to_owned(), "builtin".to_owned(), 10)],
        )
        .unwrap();
        db.mark_scan_candidate_feed_exhausted(scan_id, "wordlist")
            .unwrap();

        db.pause_scan(scan_id, 1, 0, 0, 25, &["budget reached".to_owned()])
            .unwrap();

        let checkpoint = db
            .resumable_checkpoint("example.com", "latest")
            .unwrap()
            .expect("partial scan checkpoint was closed");
        assert_eq!(checkpoint.scan_id, scan_id);
        assert_eq!(checkpoint.stage, "paused");
        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 1);
        let (status, learning_applied): (String, i64) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT status,learning_applied FROM scans WHERE id=?1",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((status.as_str(), learning_applied), ("interrupted", 0));
        db.reopen_scan(scan_id).unwrap();
        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 1);
    }

    #[test]
    fn refresh_inventory_pages_are_stable_and_cache_only_pages_exclude_inventory() {
        let db = Database::in_memory().unwrap();
        let names = BTreeSet::from([
            "a.example.com".to_owned(),
            "b.example.com".to_owned(),
            "c.example.com".to_owned(),
            "d.example.com".to_owned(),
            "e.example.com".to_owned(),
        ]);
        db.import_inventory("example.com", &names, "import:test")
            .unwrap();
        assert_eq!(db.known_subdomain_count("example.com", true).unwrap(), 5);

        let first = db
            .known_subdomains_page("example.com", true, None, 2)
            .unwrap();
        let second = db
            .known_subdomains_page("example.com", true, first.last().map(String::as_str), 2)
            .unwrap();
        let third = db
            .known_subdomains_page("example.com", true, second.last().map(String::as_str), 2)
            .unwrap();
        assert_eq!(
            first
                .into_iter()
                .chain(second)
                .chain(third)
                .collect::<Vec<_>>(),
            names.iter().cloned().collect::<Vec<_>>()
        );
        let first_inventory = db.inventory_page("example.com", false, None, 3).unwrap();
        let second_inventory = db
            .inventory_page(
                "example.com",
                false,
                first_inventory.last().map(|entry| entry.fqdn.as_str()),
                3,
            )
            .unwrap();
        assert_eq!(
            first_inventory
                .into_iter()
                .chain(second_inventory)
                .map(|entry| entry.fqdn)
                .collect::<Vec<_>>(),
            names.iter().cloned().collect::<Vec<_>>()
        );

        let cached_only = ResolvedHost {
            fqdn: "cache-only.example.com".to_owned(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.55".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 1,
        };
        let inventory_answer = ResolvedHost {
            fqdn: names.iter().next().unwrap().clone(),
            ..cached_only.clone()
        };
        db.update_cache_outcomes(None, &[cached_only, inventory_answer], &[], &[], 300)
            .unwrap();
        assert_eq!(
            db.positive_cache_only_names_page("example.com", None, 10)
                .unwrap(),
            vec!["cache-only.example.com"]
        );
        assert_eq!(db.positive_cache_only_count("example.com").unwrap(), 1);
    }

    #[test]
    fn current_negative_inventory_is_hidden_but_preserved_and_can_return_live() {
        let db = Database::in_memory().unwrap();
        let fqdn = "retired.example.com".to_owned();
        db.import_inventory(
            "example.com",
            &BTreeSet::from([fqdn.clone()]),
            "passive:test",
        )
        .unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();

        db.record_discovery_negatives(scan_id, std::slice::from_ref(&fqdn))
            .unwrap();

        let retained = db.inventory(Some("example.com"), false).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].fqdn, fqdn);
        assert!(
            db.current_inventory_page("example.com", false, None, 10)
                .unwrap()
                .is_empty()
        );
        let explanation = db.explain(&fqdn).unwrap();
        assert_eq!(explanation["known"], true);
        assert_eq!(explanation["inventory"]["state"], "unverified");
        assert_eq!(
            explanation["dns_verifications"]
                .as_array()
                .and_then(|entries| entries.first())
                .and_then(|entry| entry["outcome"].as_str()),
            Some("negative")
        );

        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.90".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: true,
            resolver_count: 2,
        };
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
            .unwrap();
        let sources = BTreeSet::from(["live_dns".to_owned()]);
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records,
                sources: sources.clone(),
                wildcard: false,
                from_cache: false,
                confidence: crate::confidence::assess(&sources, false, true),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                authoritative_validation: true,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();

        let inventory = db.inventory(Some("example.com"), false).unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].fqdn, fqdn);
        assert_eq!(inventory[0].state, ObservationState::Live);
    }

    #[test]
    fn later_negative_overrides_old_positive_cache_and_live_inventory_for_current_output() {
        let db = Database::in_memory().unwrap();
        let fqdn = "stale-live.example.com".to_owned();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.91".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: true,
            resolver_count: 2,
        };
        let sources = BTreeSet::from(["live_dns".to_owned()]);
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records.clone(),
                sources: sources.clone(),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                authoritative_validation: true,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 300)
            .unwrap();
        db.record_discovery_negatives(scan_id, std::slice::from_ref(&fqdn))
            .unwrap();

        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .get(&fqdn),
            Some(CachedAnswer::Positive(_))
        ));
        assert_eq!(
            db.inventory(Some("example.com"), false).unwrap()[0].state,
            ObservationState::Live,
            "the append-only audit preserves the prior materialized state"
        );
        assert!(db.inventory(Some("example.com"), true).unwrap().is_empty());
        assert!(
            db.current_output_names(std::slice::from_ref(&fqdn))
                .unwrap()
                .is_empty()
        );
        assert!(
            db.current_inventory_page("example.com", false, None, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.explain(&fqdn).unwrap()["dns_verifications"][0]["outcome"],
            "negative"
        );
    }

    #[test]
    fn final_seed_filter_rejects_negative_and_quarantined_names_without_deleting_audit() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let allowed = "allowed.example.com".to_owned();
        let negative = "negative.example.com".to_owned();
        let quarantined = "quarantined.example.com".to_owned();
        let candidates = [
            (
                allowed.clone(),
                BTreeSet::from(["passive:test".to_owned()]),
                10,
            ),
            (
                negative.clone(),
                BTreeSet::from(["passive:test".to_owned()]),
                10,
            ),
            (
                quarantined.clone(),
                BTreeSet::from(["passive:test".to_owned()]),
                10,
            ),
        ];
        db.persist_scan_seed_candidates(scan_id, &candidates, candidates.len())
            .unwrap();
        db.record_discovery_negatives(scan_id, std::slice::from_ref(&negative))
            .unwrap();
        db.import_inventory(
            "example.com",
            &BTreeSet::from([quarantined.clone()]),
            "passive:test",
        )
        .unwrap();
        let wildcard_answer = ResolvedHost {
            fqdn: quarantined.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.92".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        db.record_current_wildcard_matches(scan_id, &[wildcard_answer])
            .unwrap();
        assert_eq!(
            db.purge_confirmed_wildcard_false_positives(
                scan_id,
                "example.com",
                std::slice::from_ref(&quarantined),
            )
            .unwrap(),
            vec![quarantined.as_str()]
        );

        let all_seeds = db.scan_seed_candidates_for_output(scan_id).unwrap();
        assert_eq!(all_seeds.len(), 3, "the durable audit queue is retained");
        let current = db
            .current_seed_output_names(
                "example.com",
                &all_seeds
                    .iter()
                    .map(|(fqdn, _)| fqdn.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        assert_eq!(current, BTreeSet::from([allowed]));
        assert!(
            db.inventory(Some("example.com"), false)
                .unwrap()
                .iter()
                .all(|entry| entry.fqdn != quarantined),
            "quarantined wildcard names stay out of every inventory listing"
        );
        assert!(db.inventory(Some("example.com"), true).unwrap().is_empty());
        assert_eq!(
            db.explain(&quarantined).unwrap()["quarantine"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn wordlists_are_streamed_deduplicated_and_bounded_in_sqlite() {
        let directory = tempfile::tempdir().unwrap();
        let wordlist = directory.path().join("words.txt");
        std::fs::write(&wordlist, "www\napi\nwww\ninvalid name\nadmin\n").unwrap();
        let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let (inserted, exhausted) = db
            .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 2)
            .unwrap();
        assert_eq!(inserted, 2);
        assert!(!exhausted);
        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 2);
        let candidates = db.pending_scan_candidates(scan_id, 2).unwrap();
        assert_eq!(
            candidates
                .into_iter()
                .map(|(name, _, _)| name)
                .collect::<Vec<_>>(),
            vec!["www", "api"]
        );
        db.mark_scan_candidates_done(
            scan_id,
            &["www.example.com".to_owned(), "api.example.com".to_owned()],
        )
        .unwrap();
        let (inserted, exhausted) = db
            .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 2)
            .unwrap();
        assert_eq!(inserted, 1);
        assert!(exhausted);
        assert_eq!(
            db.pending_scan_candidate_count(scan_id).unwrap(),
            1,
            "only the requested page may be queued"
        );
        assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 3);
    }

    #[test]
    fn wordlist_page_tracks_the_scheduler_batch_and_resumes_at_its_exact_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let wordlist = directory.path().join("batch-words.txt");
        let database_path = directory.path().join("fellaga.db");
        let words = (0..5_000)
            .map(|index| format!("batch-{index}"))
            .collect::<Vec<_>>();
        let expected_first_cursor = words[..4_096]
            .iter()
            .map(|word| word.len() + 1)
            .sum::<usize>() as i64;
        std::fs::write(&wordlist, format!("{}\n", words.join("\n"))).unwrap();

        let db = Database::open(&database_path).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        assert_eq!(
            db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 4_096)
                .unwrap(),
            (4_096, false)
        );
        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 4_096);
        let first_cursor: i64 = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor FROM scan_candidate_feeds WHERE scan_id=?1 AND source='wordlist'",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first_cursor, expected_first_cursor);
        drop(db);

        let reopened = Database::open(&database_path).unwrap();
        assert_eq!(
            reopened
                .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 4_096)
                .unwrap(),
            (904, true)
        );
        assert_eq!(reopened.scan_candidate_count(scan_id).unwrap(), 5_000);
        assert!(
            reopened
                .scan_candidate_feed_exhausted(scan_id, "wordlist")
                .unwrap()
        );
    }

    #[test]
    fn non_utf8_wordlist_lines_are_skipped_without_aborting_the_page() {
        let directory = tempfile::tempdir().unwrap();
        let wordlist = directory.path().join("binary-words.txt");
        std::fs::write(&wordlist, b"www\ninvalid-\xff-name\napi\r\n").unwrap();
        let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();

        assert_eq!(
            db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 10)
                .unwrap(),
            (2, true)
        );
        assert_eq!(
            db.pending_scan_candidates(scan_id, 10)
                .unwrap()
                .into_iter()
                .map(|(name, _, _)| name)
                .collect::<Vec<_>>(),
            vec!["www", "api"]
        );
    }

    #[test]
    fn invalid_heavy_wordlist_pages_have_a_hard_read_budget() {
        let directory = tempfile::tempdir().unwrap();
        let wordlist = directory.path().join("mostly-invalid.txt");
        let mut content = "invalid name\n".repeat(1_500);
        content.push_str("api\n");
        std::fs::write(&wordlist, content).unwrap();
        let file_size = std::fs::metadata(&wordlist).unwrap().len() as i64;
        let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();

        let first = db
            .refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
            .unwrap();
        assert_eq!(first, (0, false));
        let first_cursor: i64 = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor FROM scan_candidate_feeds WHERE scan_id=?1 AND source='wordlist'",
                [scan_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(first_cursor > 0);
        assert!(
            first_cursor < file_size,
            "one refill must not scan the whole file"
        );

        assert_eq!(
            db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
                .unwrap(),
            (1, true)
        );
        assert_eq!(
            db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
                .unwrap(),
            (0, true)
        );
    }

    #[test]
    fn a_single_oversized_wordlist_line_is_discarded_in_bounded_pages() {
        let directory = tempfile::tempdir().unwrap();
        let wordlist = directory.path().join("oversized-line.txt");
        let mut content = vec![b'a'; 4 * 1024 * 1024 + 128];
        content.extend_from_slice(b"\napi\n");
        std::fs::write(&wordlist, content).unwrap();
        let db = Database::open(&directory.path().join("fellaga.db")).unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();

        assert_eq!(
            db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
                .unwrap(),
            (0, false)
        );
        let (cursor, state): (i64, String) = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT cursor,cursor_text FROM scan_candidate_feeds WHERE scan_id=?1 AND source='wordlist'",
                [scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(cursor, 4 * 1024 * 1024);
        assert_eq!(state, "discard");
        assert_eq!(
            db.refill_wordlist_candidates(scan_id, "example.com", &wordlist, 1)
                .unwrap(),
            (1, true)
        );
        assert_eq!(db.scan_candidate_count(scan_id).unwrap(), 1);
        assert_eq!(db.pending_scan_candidates(scan_id, 1).unwrap()[0].0, "api");
    }

    #[test]
    fn opening_an_existing_v8_database_repairs_columns_before_dependent_indexes() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE scan_candidates (
                    scan_id INTEGER NOT NULL,
                    fqdn TEXT NOT NULL,
                    relative_name TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    generator TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    PRIMARY KEY(scan_id, fqdn)
                );
                PRAGMA user_version=8;
                "#,
            )
            .unwrap();
        drop(connection);

        let db = Database::open(temporary.path()).unwrap();
        let connection = db.lock().unwrap();
        let repaired_columns: i64 = connection
            .query_row(
                r#"SELECT COUNT(*) FROM pragma_table_info('scan_candidates')
                   WHERE name IN ('attempts', 'learning_recorded')"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repaired_columns, 2);
        let objects: i64 = connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_master WHERE
                   (type='table' AND name='scan_candidate_feeds') OR
                   (type='index' AND name='idx_scan_candidates_unrecorded')"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(objects, 2);
    }

    #[test]
    fn a_failed_v8_to_v9_migration_rolls_back_every_additive_change() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE scan_candidates (
                    scan_id INTEGER NOT NULL,
                    fqdn TEXT NOT NULL,
                    relative_name TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    generator TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    PRIMARY KEY(scan_id, fqdn)
                );
                CREATE TABLE migration_state(name TEXT PRIMARY KEY);
                PRAGMA user_version=8;
                "#,
            )
            .unwrap();
        drop(connection);

        assert!(Database::open(temporary.path()).is_err());
        let connection = Connection::open(temporary.path()).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            8
        );
        let repaired_columns: i64 = connection
            .query_row(
                r#"SELECT COUNT(*) FROM pragma_table_info('scan_candidates')
                   WHERE name IN ('attempts', 'learning_recorded')"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(repaired_columns, 0);
        let leaked_tables: i64 = connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_master
                   WHERE type='table' AND name IN (
                       'scan_candidate_feeds', 'scan_seed_candidates',
                       'scan_generator_stats', 'scan_attempted_words'
                   )"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked_tables, 0);
        let leaked_v9_tables: i64 = connection
            .query_row(
                r#"SELECT COUNT(*) FROM sqlite_master
                   WHERE type='table' AND name IN (
                       'discovery_actions', 'intelligence_edges', 'name_templates',
                       'dnssec_proofs', 'ct_tiles', 'scheduler_arms'
                   )"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked_v9_tables, 0);
    }

    #[test]
    fn imported_names_remain_unverified_after_reopening_v9() {
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
    fn numeric_passive_pagination_is_additive_atomic_and_resume_safe() {
        let db = Database::in_memory().unwrap();
        let query_hash = domain_hash("viewdns:pages:v1:example.com:output=json");
        let page_one_hash = domain_hash("api.example.com\0mail.example.com");
        let page_one = PassivePaginationPage {
            position: 1,
            next_position: 2,
            records_seen: 2,
            expected_records: Some(3),
            expected_pages: Some(2),
            page_hash: page_one_hash.clone(),
            page_records: 2,
        };
        let first_names =
            BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned()]);
        db.commit_passive_pagination_page(
            "example.com",
            "viewdns",
            "pages",
            1,
            &query_hash,
            &page_one,
            &first_names,
        )
        .unwrap();

        let state = db
            .passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
            .unwrap()
            .unwrap();
        assert_eq!(state.next_position, 2);
        assert_eq!(state.records_seen, 2);
        assert_eq!(state.last_page_records, 2);
        assert_eq!(state.last_page_hash, page_one_hash);

        // A resumed connector deliberately overlaps the last complete page.
        // The cumulative counter remains stable instead of double-counting it.
        db.commit_passive_pagination_page(
            "example.com",
            "viewdns",
            "pages",
            1,
            &query_hash,
            &page_one,
            &first_names,
        )
        .unwrap();
        assert_eq!(
            db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
                .unwrap()
                .unwrap()
                .records_seen,
            2
        );
        let overlap_times_seen: i64 = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT evidence.times_seen
                   FROM observation_evidence evidence
                   JOIN observed_names names ON names.id=evidence.name_id
                   WHERE evidence.root_domain='example.com'
                     AND evidence.source='passive:viewdns'
                     AND names.fqdn='api.example.com'"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(overlap_times_seen, 1, "overlap must be idempotent");
        assert!(
            db.finish_passive_pagination("example.com", "viewdns", "pages", 1, &query_hash)
                .is_err(),
            "a lane cannot finish before its advertised records and pages are complete"
        );

        db.lock()
            .unwrap()
            .execute_batch(
                r#"CREATE TRIGGER fail_passive_page_advance
                   BEFORE UPDATE ON passive_pagination_state
                   WHEN NEW.next_position=3
                   BEGIN SELECT RAISE(ABORT, 'forced pagination failure'); END;"#,
            )
            .unwrap();
        let page_two = PassivePaginationPage {
            position: 2,
            next_position: 3,
            records_seen: 3,
            expected_records: Some(3),
            expected_pages: Some(2),
            page_hash: domain_hash("www.example.com"),
            page_records: 1,
        };
        assert!(
            db.commit_passive_pagination_page(
                "example.com",
                "viewdns",
                "pages",
                1,
                &query_hash,
                &page_two,
                &BTreeSet::from(["www.example.com".to_owned()]),
            )
            .is_err()
        );
        assert_eq!(
            db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
                .unwrap()
                .unwrap()
                .next_position,
            2,
            "a failed SQLite transaction must not advance the page"
        );
        assert!(
            db.observation_names("example.com", "passive:viewdns")
                .unwrap()
                .iter()
                .all(|name| name != "www.example.com"),
            "the page evidence must roll back with its progress row"
        );

        db.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_passive_page_advance")
            .unwrap();
        db.commit_passive_pagination_page(
            "example.com",
            "viewdns",
            "pages",
            1,
            &query_hash,
            &page_two,
            &BTreeSet::from(["www.example.com".to_owned()]),
        )
        .unwrap();
        db.finish_passive_pagination("example.com", "viewdns", "pages", 1, &query_hash)
            .unwrap();
        assert!(
            db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
                .unwrap()
                .is_some_and(|state| state.done),
            "lane completion must remain durable until source publication"
        );
        assert!(
            db.passive_cache("example.com", "viewdns")
                .unwrap()
                .is_some_and(|cache| cache.updated_at == 0),
            "finishing one lane must not publish source freshness"
        );
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='viewdns'
                         AND active=1"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "lane completion must retain replay markers until source completion"
        );
        db.complete_passive_pagination_source(
            "example.com",
            "viewdns",
            &[("pages", 1, query_hash.as_str())],
        )
        .unwrap();
        assert!(
            db.passive_pagination_resume("example.com", "viewdns", "pages", 1, &query_hash)
                .unwrap()
                .is_none()
        );
        assert!(
            db.passive_cache("example.com", "viewdns")
                .unwrap()
                .is_some_and(|cache| cache.updated_at > 0),
            "source completion must publish cache freshness atomically"
        );
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='viewdns'
                         AND active=1"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "source completion must close the replay generation atomically"
        );
        assert_eq!(
            db.observation_names("example.com", "passive:viewdns")
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "api.example.com".to_owned(),
                "mail.example.com".to_owned(),
                "www.example.com".to_owned(),
            ])
        );
    }

    #[test]
    fn passive_source_completion_requires_every_expected_lane_atomically() {
        let db = Database::in_memory().unwrap();
        let lane_a_hash = domain_hash("fixture:lane-a:v1:example.com");
        let lane_b_hash = domain_hash("fixture:lane-b:v1:example.com");
        let expected = [
            ("lane_a", 1, lane_a_hash.as_str()),
            ("lane_b", 1, lane_b_hash.as_str()),
        ];
        db.prepare_passive_pagination_source("example.com", "fixture", &expected)
            .unwrap();
        let page = |name: &str| PassivePaginationPage {
            position: 1,
            next_position: 2,
            records_seen: 1,
            expected_records: Some(1),
            expected_pages: Some(1),
            page_hash: domain_hash(name),
            page_records: 1,
        };

        db.commit_passive_pagination_page(
            "example.com",
            "fixture",
            "lane_a",
            1,
            &lane_a_hash,
            &page("api.example.com"),
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        db.finish_passive_pagination("example.com", "fixture", "lane_a", 1, &lane_a_hash)
            .unwrap();

        assert!(
            db.complete_passive_pagination_source("example.com", "fixture", &expected)
                .is_err(),
            "a missing lane must fail closed"
        );
        assert!(
            db.passive_cache("example.com", "fixture")
                .unwrap()
                .is_some_and(|cache| cache.updated_at == 0),
            "an incomplete lane set must never publish freshness"
        );
        assert!(
            db.passive_pagination_resume("example.com", "fixture", "lane_a", 1, &lane_a_hash,)
                .unwrap()
                .is_some_and(|state| state.done),
            "a completed lane must survive the failed source completion"
        );

        db.commit_passive_pagination_page(
            "example.com",
            "fixture",
            "lane_b",
            1,
            &lane_b_hash,
            &page("www.example.com"),
            &BTreeSet::from(["www.example.com".to_owned()]),
        )
        .unwrap();
        db.finish_passive_pagination("example.com", "fixture", "lane_b", 1, &lane_b_hash)
            .unwrap();
        db.complete_passive_pagination_source("example.com", "fixture", &expected)
            .unwrap();

        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_pagination_state
                       WHERE root_domain='example.com' AND source='fixture'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='fixture'
                         AND active=1"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(connection);
        assert!(
            db.passive_cache("example.com", "fixture")
                .unwrap()
                .is_some_and(|cache| cache.updated_at > 0)
        );
        assert!(
            db.complete_passive_pagination_source("example.com", "fixture", &expected)
                .is_err(),
            "a concurrent duplicate completion must fail closed"
        );
    }

    #[test]
    fn passive_pagination_preparation_prunes_only_obsolete_lane_contracts() {
        let db = Database::in_memory().unwrap();
        let old_hash = domain_hash("fixture:retired:v1:example.com");
        let current_hash = domain_hash("fixture:current:v1:example.com");
        let page = PassivePaginationPage {
            position: 1,
            next_position: 2,
            records_seen: 1,
            expected_records: Some(2),
            expected_pages: Some(2),
            page_hash: domain_hash("api.example.com"),
            page_records: 1,
        };
        db.commit_passive_pagination_page(
            "example.com",
            "fixture",
            "retired",
            1,
            &old_hash,
            &page,
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        db.commit_passive_pagination_page(
            "example.com",
            "fixture",
            "current",
            1,
            &current_hash,
            &page,
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();

        db.prepare_passive_pagination_source(
            "example.com",
            "fixture",
            &[("current", 1, current_hash.as_str())],
        )
        .unwrap();
        assert!(
            db.passive_pagination_resume("example.com", "fixture", "retired", 1, &old_hash,)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.passive_pagination_resume("example.com", "fixture", "current", 1, &current_hash,)
                .unwrap()
                .unwrap()
                .next_position,
            2
        );
        assert_eq!(
            db.observation_names("example.com", "passive:fixture")
                .unwrap(),
            vec!["api.example.com"],
            "contract cleanup must not delete permanent observations"
        );
    }

    #[test]
    fn passive_pagination_contract_change_restarts_without_deleting_observations() {
        let db = Database::in_memory().unwrap();
        let old_hash = domain_hash("viewdns:pages:v1:example.com:output=json");
        db.commit_passive_pagination_page(
            "example.com",
            "viewdns",
            "pages",
            1,
            &old_hash,
            &PassivePaginationPage {
                position: 1,
                next_position: 2,
                records_seen: 1,
                expected_records: Some(2),
                expected_pages: Some(2),
                page_hash: domain_hash("api.example.com"),
                page_records: 1,
            },
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        let new_hash = domain_hash("viewdns:pages:v2:example.com:output=json");
        assert!(
            db.passive_pagination_resume("example.com", "viewdns", "pages", 2, &new_hash)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.observation_names("example.com", "passive:viewdns")
                .unwrap(),
            vec!["api.example.com"]
        );
        let (version, opaque_columns): (i64, i64) = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT (SELECT user_version FROM pragma_user_version),
                          (SELECT COUNT(*) FROM pragma_table_info('passive_pagination_state')
                           WHERE lower(name) LIKE '%cursor%'
                              OR lower(name) LIKE '%token%'
                              OR lower(name) LIKE '%url%')"#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, 9, "the additive table must not bump user_version");
        assert_eq!(opaque_columns, 0, "opaque pagination state is forbidden");
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
        db.lock()
            .unwrap()
            .execute(
                r#"UPDATE passive_cache SET updated_at=42
                   WHERE root_domain='example.com' AND source='crtsh'"#,
                [],
            )
            .unwrap();
        db.store_partial_passive_cache("example.com", "crtsh", &["partial.example.com".to_owned()])
            .unwrap();
        db.store_partial_passive_cache(
            "example.com",
            "page-only",
            &["first-page.example.com".to_owned()],
        )
        .unwrap();

        assert_eq!(db.ranked_words(1).unwrap(), vec!["api"]);
        assert_eq!(db.ranked_patterns(1).unwrap(), vec!["api.dev"]);
        assert_eq!(
            db.passive_cache("example.com", "crtsh")
                .unwrap()
                .unwrap()
                .names,
            vec![
                "deep.api.example.com",
                "partial.example.com",
                "www.example.com"
            ]
        );
        assert_eq!(
            db.passive_cache("example.com", "crtsh")
                .unwrap()
                .unwrap()
                .updated_at,
            42
        );
        let page_only = db
            .passive_cache("example.com", "page-only")
            .unwrap()
            .unwrap();
        assert_eq!(page_only.updated_at, 0);
        assert_eq!(page_only.names, vec!["first-page.example.com"]);
    }

    #[test]
    fn passive_cache_bounded_limits_reads_without_discarding_observations() {
        let db = Database::in_memory().unwrap();
        let full_page = BTreeSet::from([
            "a.example.com".to_owned(),
            "b.example.com".to_owned(),
            "c.example.com".to_owned(),
            "d.example.com".to_owned(),
        ]);
        db.store_passive_observation_page("example.com", "fixture", &full_page)
            .unwrap();

        let bounded = db
            .passive_cache_bounded("example.com", "fixture", 2)
            .unwrap()
            .unwrap();
        assert_eq!(bounded.names, vec!["a.example.com", "b.example.com"]);
        assert_eq!(bounded.updated_at, 0);
        assert!(
            db.passive_cache_bounded("example.com", "fixture", 0)
                .unwrap()
                .unwrap()
                .names
                .is_empty()
        );
        assert_eq!(
            db.passive_cache("example.com", "fixture")
                .unwrap()
                .unwrap()
                .names,
            full_page.into_iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn passive_page_novelty_counts_durable_names_outside_any_working_set() {
        let db = Database::in_memory().unwrap();
        let already_known = (0..100)
            .map(|index| format!("known-{index:03}.example.com"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            db.store_passive_observation_page("example.com", "prior", &already_known)
                .unwrap(),
            already_known.len()
        );
        let mut large_page = already_known;
        large_page.extend(
            (0..500)
                .map(|index| format!("zz-new-{index:03}.example.com"))
                .collect::<BTreeSet<_>>(),
        );
        // A scanner working set capped to the lexicographically first 100
        // names would retain only the old entries. The durable page commit
        // still reports every globally new name for source learning.
        assert_eq!(
            db.store_passive_observation_page("example.com", "large", &large_page)
                .unwrap(),
            500
        );
        assert_eq!(
            db.store_passive_observation_page("example.com", "large", &large_page)
                .unwrap(),
            0,
            "replaying a page must not manufacture novelty"
        );
        assert_eq!(
            db.passive_cache_bounded("example.com", "large", 100)
                .unwrap()
                .unwrap()
                .names
                .len(),
            100
        );
        assert_eq!(
            db.passive_cache("example.com", "large")
                .unwrap()
                .unwrap()
                .names
                .len(),
            600
        );
    }

    #[test]
    fn passive_refresh_replay_is_idempotent_across_database_reopen() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let page = BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned()]);
        {
            let db = Database::open(temporary.path()).unwrap();
            assert_eq!(
                db.store_passive_observation_page("example.com", "fixture", &page)
                    .unwrap(),
                2
            );
            db.mark_passive_cache_refresh("example.com", "fixture", false)
                .unwrap();
        }

        {
            let db = Database::open(temporary.path()).unwrap();
            assert_eq!(
                db.store_passive_observation_page("example.com", "fixture", &page)
                    .unwrap(),
                0
            );
            let connection = db.lock().unwrap();
            assert_eq!(
                connection
                    .query_row(
                        r#"SELECT MIN(evidence.times_seen)
                           FROM observation_evidence evidence
                           WHERE evidence.root_domain='example.com'
                             AND evidence.source='passive:fixture'"#,
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "an unfinished refresh replay must not inflate evidence"
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM passive_refresh_seen", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0,
                "generation ids replace per-name replay marker rows"
            );
            drop(connection);
            db.mark_passive_cache_refresh("example.com", "fixture", true)
                .unwrap();
            let connection = db.lock().unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM passive_refresh_sessions WHERE active=1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
            assert_eq!(
                connection
                    .query_row("SELECT COUNT(*) FROM passive_refresh_seen", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap(),
                0
            );
        }

        let db = Database::open(temporary.path()).unwrap();
        db.store_passive_observation_page("example.com", "fixture", &page)
            .unwrap();
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    r#"SELECT MIN(evidence.times_seen)
                       FROM observation_evidence evidence
                       WHERE evidence.root_domain='example.com'
                         AND evidence.source='passive:fixture'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2,
            "a new generation after successful completion is a new observation"
        );
    }

    #[test]
    fn passive_refresh_sessions_are_isolated_by_domain_and_source() {
        let db = Database::in_memory().unwrap();
        let page = BTreeSet::from(["shared.example.com".to_owned()]);
        db.store_passive_observation_page("example.com", "alpha", &page)
            .unwrap();
        db.store_passive_observation_page("example.com", "alpha", &page)
            .unwrap();
        db.store_passive_observation_page("example.com", "beta", &page)
            .unwrap();
        db.store_passive_observation_page("example.net", "alpha", &page)
            .unwrap();

        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM passive_refresh_sessions WHERE active=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            3
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT MAX(times_seen) FROM observation_evidence",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(connection);

        db.mark_passive_cache_refresh("example.com", "alpha", true)
            .unwrap();
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM passive_refresh_sessions WHERE active=1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE active=1 AND (
                           (root_domain='example.com' AND source='beta')
                           OR (root_domain='example.net' AND source='alpha')
                       )"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn passive_refresh_lease_is_exclusive_and_owner_safe() {
        let db = Database::in_memory().unwrap();
        let owner_a = domain_hash("lease-owner-a");
        let owner_b = domain_hash("lease-owner-b");
        let ttl = Duration::from_secs(30);

        assert!(
            db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_a, ttl)
                .unwrap()
        );
        assert!(
            !db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_b, ttl)
                .unwrap(),
            "a concurrent owner must be deferred"
        );
        assert!(
            db.renew_passive_refresh_lease("example.com", "fixture", &owner_a, ttl)
                .unwrap()
        );
        assert!(
            !db.renew_passive_refresh_lease("example.com", "fixture", &owner_b, ttl)
                .unwrap()
        );
        assert!(
            !db.release_passive_refresh_lease("example.com", "fixture", &owner_b)
                .unwrap(),
            "a stale guard cannot release another owner's lease"
        );
        assert!(
            db.release_passive_refresh_lease("example.com", "fixture", &owner_a)
                .unwrap()
        );
        assert!(
            db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_b, ttl)
                .unwrap()
        );

        db.lock()
            .unwrap()
            .execute(
                r#"UPDATE passive_refresh_leases SET expires_at=?1
                   WHERE root_domain='example.com' AND source='fixture'"#,
                [now_epoch().saturating_sub(1)],
            )
            .unwrap();
        assert!(
            db.try_acquire_passive_refresh_lease("example.com", "fixture", &owner_a, ttl)
                .unwrap(),
            "an expired owner must not block a bounded takeover"
        );
        assert!(
            !db.release_passive_refresh_lease("example.com", "fixture", &owner_b)
                .unwrap()
        );
        assert!(
            db.release_passive_refresh_lease("example.com", "fixture", &owner_a)
                .unwrap()
        );
    }

    #[test]
    fn passive_page_failure_rolls_back_observations_and_restart_markers() {
        let db = Database::in_memory().unwrap();
        db.lock()
            .unwrap()
            .execute_batch(
                r#"CREATE TRIGGER fail_passive_cache_marker
                   BEFORE INSERT ON passive_cache
                   BEGIN SELECT RAISE(ABORT, 'forced cache marker failure'); END;"#,
            )
            .unwrap();
        assert!(
            db.store_passive_observation_page(
                "example.com",
                "fixture",
                &BTreeSet::from(["api.example.com".to_owned()]),
            )
            .is_err()
        );
        let connection = db.lock().unwrap();
        for table in [
            "observed_names",
            "observation_evidence",
            "passive_refresh_sessions",
            "passive_refresh_seen",
        ] {
            let count: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} must roll back with the failed page");
        }
    }

    #[test]
    fn abandoned_refresh_cleanup_keeps_permanent_observations() {
        let db = Database::in_memory().unwrap();
        db.store_passive_observation_page(
            "example.com",
            "abandoned",
            &BTreeSet::from(["old.example.com".to_owned()]),
        )
        .unwrap();
        db.lock()
            .unwrap()
            .execute(
                r#"UPDATE passive_refresh_sessions
                   SET updated_at=?1
                   WHERE root_domain='example.com' AND source='abandoned'"#,
                [now_epoch()
                    .saturating_sub(PASSIVE_REFRESH_ABANDONED_AFTER_SECS)
                    .saturating_sub(1)],
            )
            .unwrap();

        db.store_passive_observation_page(
            "example.net",
            "current",
            &BTreeSet::from(["new.example.net".to_owned()]),
        )
        .unwrap();
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='abandoned'
                         AND active=1"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*)
                       FROM observation_evidence evidence
                       JOIN observed_names names ON names.id=evidence.name_id
                       WHERE evidence.root_domain='example.com'
                         AND evidence.source='passive:abandoned'
                         AND names.fqdn='old.example.com'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "cleanup may remove restart metadata but never observations"
        );
    }

    #[test]
    fn abandoned_numeric_refresh_restarts_without_deleting_observations() {
        let db = Database::in_memory().unwrap();
        let query_hash = domain_hash("fixture:pages:v1:example.com");
        db.commit_passive_pagination_page(
            "example.com",
            "fixture",
            "pages",
            1,
            &query_hash,
            &PassivePaginationPage {
                position: 1,
                next_position: 2,
                records_seen: 1,
                expected_records: Some(2),
                expected_pages: Some(2),
                page_hash: domain_hash("api.example.com"),
                page_records: 1,
            },
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        db.lock()
            .unwrap()
            .execute(
                r#"UPDATE passive_refresh_sessions
                   SET updated_at=?1
                   WHERE root_domain='example.com' AND source='fixture'"#,
                [now_epoch()
                    .saturating_sub(PASSIVE_REFRESH_ABANDONED_AFTER_SECS)
                    .saturating_sub(1)],
            )
            .unwrap();

        db.store_passive_observation_page(
            "example.net",
            "current",
            &BTreeSet::from(["new.example.net".to_owned()]),
        )
        .unwrap();
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_refresh_sessions
                       WHERE root_domain='example.com' AND source='fixture'
                         AND active=1"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "an abandoned generation must be closed"
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM passive_pagination_state
                       WHERE root_domain='example.com' AND source='fixture'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "an abandoned numeric lane must restart at page one"
        );
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT COUNT(*) FROM observation_evidence
                       WHERE root_domain='example.com'
                         AND source='passive:fixture'"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "cleanup must retain permanent observations"
        );
    }

    #[test]
    fn tls_cache_does_not_attribute_old_sans_to_a_rotated_certificate() {
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
        assert_eq!(cached.names, vec!["admin.example.com"]);
        assert_eq!(
            db.observation_names("example.com", "tls:www.example.com:443")
                .unwrap(),
            vec!["admin.example.com", "api.example.com"]
        );
    }

    #[test]
    fn tls_cache_replaces_even_repeated_observations_of_the_same_certificate() {
        let db = Database::in_memory().unwrap();
        db.store_tls_cache(
            "example.com",
            "www.example.com",
            443,
            "same-fingerprint",
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        db.store_tls_cache(
            "example.com",
            "www.example.com",
            443,
            "same-fingerprint",
            &BTreeSet::from(["admin.example.com".to_owned()]),
        )
        .unwrap();

        assert_eq!(
            db.tls_cache("example.com", "www.example.com", 443)
                .unwrap()
                .unwrap()
                .names,
            vec!["admin.example.com"]
        );
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
    fn web_cache_tracks_the_current_snapshot_while_history_is_permanent() {
        let db = Database::in_memory().unwrap();
        db.store_web_cache(
            "example.com",
            "https://www.example.com/",
            200,
            &BTreeSet::from(["api.example.com".to_owned()]),
            &["https://www.example.com/old.js".to_owned()],
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
            200,
            &BTreeSet::from(["static.example.com".to_owned()]),
            &["https://www.example.com/current.js".to_owned()],
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
        assert_eq!(web.status, 200);
        assert_eq!(web.names, vec!["static.example.com"]);
        assert_eq!(web.assets, vec!["https://www.example.com/current.js"]);
        assert_eq!(
            db.observation_names("example.com", "web:https://www.example.com/")
                .unwrap(),
            vec!["api.example.com", "static.example.com"]
        );

        // DNSSEC walk results remain an intentionally cumulative discovery corpus.
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
            &BTreeSet::from([
                "api.example.com".to_owned(),
                "deep.api.example.com".to_owned(),
                "api.notexample.com".to_owned(),
                "www.example.net".to_owned(),
            ]),
        )
        .unwrap();
        assert_eq!(
            db.ct_global_cursor("https://ct.example/").unwrap(),
            Some(42)
        );
        db.store_ct_global_batch("https://ct.example/", 12, &BTreeSet::new())
            .unwrap();
        assert_eq!(
            db.ct_global_cursor("https://ct.example/").unwrap(),
            Some(42)
        );
        assert_eq!(
            db.ct_global_states()
                .unwrap()
                .get("https://ct.example/")
                .map(|(cursor, _)| *cursor),
            Some(42)
        );
        db.reset_ct_global_cursor("https://ct.example/", 5).unwrap();
        assert_eq!(db.ct_global_cursor("https://ct.example/").unwrap(), Some(5));
        assert_eq!(
            db.ct_names_for_domain("example.com", 10).unwrap(),
            vec!["api.example.com", "deep.api.example.com"]
        );
        let connection = db.lock().unwrap();
        let mut statement = connection
            .prepare(
                r#"EXPLAIN QUERY PLAN SELECT fqdn FROM ct_names
                   WHERE reversed_name>=?1 AND reversed_name<?2
                   ORDER BY last_seen DESC, fqdn ASC LIMIT ?3"#,
            )
            .unwrap();
        let plan = statement
            .query_map(params!["com.example.", "com.example/", 10_i64], |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|detail| detail.contains("idx_ct_names_reversed"))
        );
    }

    #[test]
    fn scheduler_ranking_is_cost_aware_deterministic_and_bounded() {
        let db = Database::in_memory().unwrap();
        db.record_scheduler_outcomes(
            "example.com",
            &[
                SchedulerOutcome {
                    generator: "cheap".to_owned(),
                    attempts: 100,
                    exclusive_live: 20,
                    packets: 120,
                    total_cost: 50.0,
                },
                SchedulerOutcome {
                    generator: "expensive".to_owned(),
                    attempts: 100,
                    exclusive_live: 20,
                    packets: 120,
                    total_cost: 200.0,
                },
            ],
        )
        .unwrap();
        let rankings = db
            .scheduler_rankings(
                "example.com",
                &["cheap".to_owned(), "expensive".to_owned()],
                10,
            )
            .unwrap();
        assert_eq!(rankings.len(), 2);
        assert_eq!(rankings[0].generator, "cheap");
        assert!(rankings[0].priority_milli > rankings[1].priority_milli);
        assert!((rankings[0].average_cost - 0.5).abs() < f64::EPSILON);
        assert!((rankings[1].average_cost - 2.0).abs() < f64::EPSILON);
        assert_eq!(rankings[0].exclusive_live, 20);
        assert_eq!(rankings[0].packets, 120);

        let global = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT alpha, beta, packets, exclusive_rewards, total_cost
                   FROM scheduler_arms WHERE context='global' AND generator='cheap'"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, f64>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, f64>(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(global, (21.0, 81.0, 120, 20, 50.0));

        let invalid = SchedulerOutcome {
            generator: "invalid".to_owned(),
            attempts: 1,
            exclusive_live: 2,
            packets: 1,
            total_cost: 1.0,
        };
        assert!(
            db.record_scheduler_outcomes("example.com", &[invalid])
                .is_err()
        );
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM scheduler_arms WHERE generator='invalid'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let too_many_generators = (0..=MAX_SCHEDULER_GENERATORS)
            .map(|index| format!("generator-{index}"))
            .collect::<Vec<_>>();
        assert!(
            db.scheduler_rankings("example.com", &too_many_generators, usize::MAX)
                .is_err()
        );
        let too_many_outcomes = vec![
            SchedulerOutcome {
                generator: "bounded".to_owned(),
                attempts: 1,
                exclusive_live: 0,
                packets: 1,
                total_cost: 1.0,
            };
            MAX_SCHEDULER_OUTCOMES + 1
        ];
        assert!(
            db.record_scheduler_outcomes("example.com", &too_many_outcomes)
                .is_err()
        );
    }

    #[test]
    fn generator_scores_consume_cost_aware_scheduler_arms() {
        let db = Database::in_memory().unwrap();
        db.record_scheduler_outcomes(
            "example.com",
            &[
                SchedulerOutcome {
                    generator: "number-neighbor".to_owned(),
                    attempts: 50,
                    exclusive_live: 10,
                    packets: 50,
                    total_cost: 25.0,
                },
                SchedulerOutcome {
                    generator: "token-order".to_owned(),
                    attempts: 50,
                    exclusive_live: 10,
                    packets: 50,
                    total_cost: 200.0,
                },
            ],
        )
        .unwrap();

        let scores = db.generator_scores("example.com").unwrap();
        assert!(scores["number-neighbor"] > scores["token-order"]);
    }

    #[test]
    fn discovery_actions_claim_yield_per_cost_and_complete_exactly_once() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let actions = [
            DiscoveryActionInput {
                fqdn: Some("a.example.com".to_owned()),
                zone: "example.com".to_owned(),
                kind: "dns".to_owned(),
                generator: "generator-a".to_owned(),
                context_key: "suffix:com".to_owned(),
                priority_class: 0,
                predicted_unique_live: 0.8,
                predicted_cost: 2.0,
            },
            DiscoveryActionInput {
                fqdn: Some("b.example.com".to_owned()),
                zone: "example.com".to_owned(),
                kind: "dns".to_owned(),
                generator: "generator-b".to_owned(),
                context_key: "suffix:com".to_owned(),
                priority_class: 0,
                predicted_unique_live: 0.5,
                predicted_cost: 0.5,
            },
            DiscoveryActionInput {
                fqdn: Some("c.example.com".to_owned()),
                zone: "example.com".to_owned(),
                kind: "dns".to_owned(),
                generator: "generator-c".to_owned(),
                context_key: "suffix:com".to_owned(),
                priority_class: 1,
                predicted_unique_live: 10.0,
                predicted_cost: 0.01,
            },
        ];
        assert_eq!(db.enqueue_discovery_actions(scan_id, &actions).unwrap(), 3);
        let claimed = db.claim_discovery_actions(scan_id, 2).unwrap();
        assert_eq!(
            claimed
                .iter()
                .map(|action| action.generator.as_str())
                .collect::<Vec<_>>(),
            vec!["generator-b", "generator-a"]
        );
        let outcome = SchedulerOutcome {
            generator: "generator-b".to_owned(),
            attempts: 1,
            exclusive_live: 1,
            packets: 2,
            total_cost: 0.5,
        };
        assert!(
            db.complete_discovery_action(claimed[0].id, &outcome, &json!({"rcode": "NOERROR"}))
                .unwrap()
        );
        assert!(
            !db.complete_discovery_action(claimed[0].id, &outcome, &json!({}))
                .unwrap()
        );
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    r#"SELECT COUNT(*) FROM scheduler_arms
                       WHERE generator='generator-b' AND context IN ('global', 'suffix:com')
                         AND alpha=2.0 AND beta=1.0
                         AND exclusive_rewards=1 AND total_cost=0.5"#,
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn legacy_bandit_is_migrated_to_scheduler_once() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        {
            let db = Database::open(temporary.path()).unwrap();
            let connection = db.lock().unwrap();
            connection
                .execute("DELETE FROM scheduler_arms", [])
                .unwrap();
            connection
                .execute(
                    r#"INSERT INTO generator_bandits(
                           context, generator, alpha, beta, pulls, rewards, last_seen
                       ) VALUES ('global', 'legacy', 4.0, 7.0, 9, 3, 123)"#,
                    [],
                )
                .unwrap();
        }
        for _ in 0..2 {
            let db = Database::open(temporary.path()).unwrap();
            assert_eq!(
                db.lock()
                    .unwrap()
                    .query_row(
                        r#"SELECT alpha, beta, packets, exclusive_rewards, total_cost
                           FROM scheduler_arms
                           WHERE context='global' AND generator='legacy'"#,
                        [],
                        |row| {
                            Ok((
                                row.get::<_, f64>(0)?,
                                row.get::<_, f64>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, f64>(4)?,
                            ))
                        },
                    )
                    .unwrap(),
                (4.0, 7.0, 9, 0, 9.0)
            );
        }
    }

    #[test]
    fn static_ct_tiles_names_and_cursor_commit_atomically_and_are_reusable() {
        let db = Database::in_memory().unwrap();
        let log_url = "https://ct.example/2026h2/";
        db.store_ct_global_batch(log_url, 900, &BTreeSet::new())
            .unwrap();
        let payload = b"immutable-static-ct-tile".to_vec();
        let content_hash = format!("{:x}", Sha256::digest(&payload));
        let batch = crate::ct_static::StaticCtBatch {
            checkpoint_origin: "ct.example/2026h2".to_owned(),
            checkpoint_size: 512,
            checkpoint_hash: "checkpoint-a".to_owned(),
            reset_cursor: true,
            next_cursor: 257,
            entries_processed: 1,
            names: BTreeSet::from(["api.example.com".to_owned()]),
            tiles: vec![crate::ct_static::StaticTile {
                path: "tile/data/001".to_owned(),
                checkpoint_size: 512,
                checkpoint_hash: "checkpoint-a".to_owned(),
                content_hash: content_hash.clone(),
                payload: payload.clone(),
            }],
            ..crate::ct_static::StaticCtBatch::default()
        };

        db.store_ct_static_batch(log_url, &batch).unwrap();

        assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(257));
        assert_eq!(
            db.ct_names_for_domain("example.com", 10).unwrap(),
            vec!["api.example.com"]
        );
        assert_eq!(
            db.ct_static_tile(log_url, "tile/data/001", 512, "checkpoint-a")
                .unwrap(),
            Some((content_hash, payload))
        );
        assert!(
            db.ct_static_tile(log_url, "tile/data/001", 513, "checkpoint-a")
                .unwrap()
                .is_none()
        );
        assert!(
            db.ct_static_tile(log_url, "tile/data/001", 512, "checkpoint-b")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn existing_v9_ct_tile_table_is_repaired_without_losing_payloads() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        {
            let db = Database::open(temporary.path()).unwrap();
            let connection = db.lock().unwrap();
            connection.execute("DROP TABLE ct_tiles", []).unwrap();
            connection
                .execute_batch(
                    r#"CREATE TABLE ct_tiles (
                           log_url TEXT NOT NULL,
                           tile_path TEXT NOT NULL,
                           checkpoint_size INTEGER NOT NULL,
                           content_hash TEXT NOT NULL,
                           payload BLOB NOT NULL,
                           verified INTEGER NOT NULL DEFAULT 0,
                           updated_at INTEGER NOT NULL,
                           PRIMARY KEY(log_url, tile_path)
                       ) WITHOUT ROWID;
                       INSERT INTO ct_tiles(
                           log_url, tile_path, checkpoint_size, content_hash,
                           payload, verified, updated_at
                       ) VALUES (
                           'https://ct.example/2026h2/', 'tile/data/000', 256,
                           'legacy-hash', X'010203', 0, 1
                       );
                       PRAGMA user_version=9;"#,
                )
                .unwrap();
        }

        let reopened = Database::open(temporary.path()).unwrap();
        let connection = reopened.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    r#"SELECT checkpoint_hash, content_hash, payload
                       FROM ct_tiles WHERE tile_path='tile/data/000'"#,
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .unwrap(),
            ("".to_owned(), "legacy-hash".to_owned(), vec![1, 2, 3])
        );
    }

    #[test]
    fn conflicting_static_ct_tile_rolls_back_names_and_cursor() {
        let db = Database::in_memory().unwrap();
        let log_url = "https://ct.example/2026h2/";
        let first_payload = b"first immutable payload".to_vec();
        let first = crate::ct_static::StaticCtBatch {
            checkpoint_origin: "ct.example/2026h2".to_owned(),
            checkpoint_size: 512,
            checkpoint_hash: "checkpoint-a".to_owned(),
            next_cursor: 257,
            entries_processed: 1,
            names: BTreeSet::from(["api.example.com".to_owned()]),
            tiles: vec![crate::ct_static::StaticTile {
                path: "tile/data/001".to_owned(),
                checkpoint_size: 512,
                checkpoint_hash: "checkpoint-a".to_owned(),
                content_hash: format!("{:x}", Sha256::digest(&first_payload)),
                payload: first_payload,
            }],
            ..crate::ct_static::StaticCtBatch::default()
        };
        db.store_ct_static_batch(log_url, &first).unwrap();

        let conflicting_payload = b"rewritten payload".to_vec();
        let conflicting = crate::ct_static::StaticCtBatch {
            checkpoint_origin: "ct.example/2026h2".to_owned(),
            checkpoint_size: 768,
            checkpoint_hash: "checkpoint-b".to_owned(),
            next_cursor: 513,
            entries_processed: 256,
            names: BTreeSet::from(["must-not-commit.example.com".to_owned()]),
            tiles: vec![crate::ct_static::StaticTile {
                path: "tile/data/001".to_owned(),
                checkpoint_size: 768,
                checkpoint_hash: "checkpoint-b".to_owned(),
                content_hash: format!("{:x}", Sha256::digest(&conflicting_payload)),
                payload: conflicting_payload,
            }],
            ..crate::ct_static::StaticCtBatch::default()
        };

        assert!(db.store_ct_static_batch(log_url, &conflicting).is_err());
        assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(257));
        assert_eq!(
            db.ct_names_for_domain("example.com", 10).unwrap(),
            vec!["api.example.com"]
        );
    }

    #[test]
    fn expired_static_ct_commit_keeps_tiles_names_and_cursor_atomic() {
        let db = Database::in_memory().unwrap();
        let log_url = "https://ct.example/2026h2/";
        db.store_ct_global_batch(log_url, 100, &BTreeSet::new())
            .unwrap();
        let payload = b"must-not-be-visible".to_vec();
        let batch = crate::ct_static::StaticCtBatch {
            checkpoint_origin: "ct.example/2026h2".to_owned(),
            checkpoint_size: 512,
            checkpoint_hash: "checkpoint-deadline".to_owned(),
            next_cursor: 101,
            entries_processed: 1,
            names: BTreeSet::from(["deadline.example.com".to_owned()]),
            tiles: vec![crate::ct_static::StaticTile {
                path: "tile/data/deadline".to_owned(),
                checkpoint_size: 512,
                checkpoint_hash: "checkpoint-deadline".to_owned(),
                content_hash: format!("{:x}", Sha256::digest(&payload)),
                payload,
            }],
            ..crate::ct_static::StaticCtBatch::default()
        };
        let cancellation = AtomicBool::new(false);

        assert!(
            db.store_ct_static_batch_until_cancelled(
                log_url,
                &batch,
                Some(Instant::now()),
                &cancellation,
            )
            .is_err()
        );
        assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(100));
        assert!(
            db.ct_names_for_domain("example.com", 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            db.ct_static_tile(log_url, "tile/data/deadline", 512, "checkpoint-deadline",)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cancelled_global_ct_commit_stops_waiting_for_the_shared_mutex() {
        let db = Database::in_memory().unwrap();
        let log_url = "https://ct.example/log/";
        db.store_ct_global_batch(log_url, 100, &BTreeSet::new())
            .unwrap();
        let shared_lock = db.lock().unwrap();
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let worker_db = db.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = worker_db.store_ct_global_batch_until_cancelled(
                log_url,
                101,
                &BTreeSet::from(["cancelled.example.com".to_owned()]),
                None,
                worker_cancellation.as_ref(),
            );
            result_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        cancellation.store(true, Ordering::Release);
        let result = result_rx
            .recv_timeout(Duration::from_millis(500))
            .expect("le commit CT est reste bloque sur le mutex partage");
        assert!(result.unwrap_err().to_string().contains("annulée"));
        drop(shared_lock);
        worker.join().unwrap();
        assert_eq!(db.ct_global_cursor(log_url).unwrap(), Some(100));
        assert!(
            db.ct_names_for_domain("example.com", 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn wildcard_and_normalized_observations_are_persistent() {
        let db = Database::in_memory().unwrap();
        db.store_wildcard_cache(
            "example.com",
            &BTreeSet::from(["A:192.0.2.10".to_owned()]),
            Some(42),
            std::time::Duration::from_secs(600),
            true,
        )
        .unwrap();
        let wildcard = db.wildcard_cache("example.com").unwrap().unwrap();
        assert_eq!(wildcard.soa_serial, Some(42));
        assert!(wildcard.signature.contains("A:192.0.2.10"));
        assert_eq!(wildcard.algorithm_version, 4);

        db.lock()
            .unwrap()
            .execute(
                "UPDATE wildcard_cache SET signature_json='[\"A:*\"]', algorithm_version=1 WHERE zone='example.com'",
                [],
            )
            .unwrap();
        let legacy = db.wildcard_cache("example.com").unwrap().unwrap();
        assert!(legacy.signature.is_empty());
        assert_eq!(legacy.algorithm_version, 1);

        db.store_wildcard_cache_with_algorithm(
            "example.com",
            &BTreeSet::from(["A:192.0.2.20".to_owned()]),
            Some(43),
            std::time::Duration::from_secs(600),
            true,
            5,
        )
        .unwrap();
        let consensus = db.wildcard_cache("example.com").unwrap().unwrap();
        assert_eq!(consensus.algorithm_version, 5);
        assert!(consensus.signature.contains("A:192.0.2.20"));
        assert!(
            db.store_wildcard_cache_with_algorithm(
                "example.com",
                &BTreeSet::new(),
                None,
                std::time::Duration::from_secs(60),
                false,
                6,
            )
            .is_err()
        );

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

    #[test]
    fn degraded_and_deferred_sources_never_enter_failure_cooldown() {
        let db = Database::in_memory().unwrap();
        for _ in 0..3 {
            db.record_source_degraded_with_counts("partial", 10, 4, 100, "page suivante limitée")
                .unwrap();
            db.record_source_deferred("quota", 5, "Retry-After=60s")
                .unwrap();
        }

        let cooldowns = db
            .source_cooldowns(std::time::Duration::from_secs(86_400))
            .unwrap();
        assert!(!cooldowns.contains("partial"));
        assert!(!cooldowns.contains("quota"));

        let diagnostics = db
            .source_diagnostics(std::time::Duration::from_secs(86_400))
            .unwrap();
        let partial = &diagnostics["partial"];
        assert_eq!(partial.requests, 3);
        assert_eq!(partial.successes, 0);
        assert_eq!(partial.failures, 0);
        assert_eq!(partial.degraded, 3);
        assert_eq!(partial.deferred, 0);
        assert_eq!(partial.consecutive_failures, 0);
        assert_eq!(partial.names, 30);
        assert_eq!(partial.novel_names, 12);
        assert_eq!(partial.novel_requests, 3);
        assert_eq!(partial.last_status, "degraded");
        assert_eq!(partial.last_error.as_deref(), Some("page suivante limitée"));
        assert!(partial.next_retry.is_none());

        let quota = &diagnostics["quota"];
        assert_eq!(quota.requests, 3);
        assert_eq!(quota.successes, 0);
        assert_eq!(quota.failures, 0);
        assert_eq!(quota.degraded, 0);
        assert_eq!(quota.deferred, 3);
        assert_eq!(quota.consecutive_failures, 0);
        assert_eq!(quota.novel_requests, 0);
        assert_eq!(quota.last_status, "deferred");
        assert_eq!(quota.last_error.as_deref(), Some("Retry-After=60s"));
        assert!(quota.next_retry.is_none());
    }

    #[test]
    fn existing_source_stats_keep_raw_names_and_start_fresh_yield_metrics() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let connection = Connection::open(temporary.path()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE source_stats (
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
                INSERT INTO source_stats(
                    source, requests, successes, failures, consecutive_failures,
                    names, total_ms, last_error, last_used
                ) VALUES ('legacy', 4, 4, 0, 0, 250, 400, NULL, 1);
                PRAGMA user_version=8;
                "#,
            )
            .unwrap();
        drop(connection);

        let db = Database::open(temporary.path()).unwrap();
        let columns: i64 = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT COUNT(*) FROM pragma_table_info('source_stats')
                   WHERE name IN (
                       'novel_names', 'novel_requests', 'novel_total_ms',
                       'degraded', 'deferred', 'last_status'
                   )"#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(columns, 6);
        let score_before = db.source_scores().unwrap()["legacy"];

        db.record_source_result("legacy", 3, 100, None).unwrap();
        let diagnostic = db
            .source_diagnostics(std::time::Duration::ZERO)
            .unwrap()
            .remove("legacy")
            .unwrap();
        assert_eq!(diagnostic.names, 250);
        assert_eq!(diagnostic.novel_names, 3);
        assert_eq!(diagnostic.novel_requests, 1);
        assert_eq!(diagnostic.degraded, 0);
        assert_eq!(diagnostic.deferred, 0);
        assert_eq!(diagnostic.last_status, "success");
        assert!(db.source_scores().unwrap()["legacy"] > score_before);
        drop(db);

        let reopened = Database::open(temporary.path()).unwrap();
        reopened
            .record_source_result_with_counts("legacy", 11, 4, 200, None)
            .unwrap();
        let diagnostic = reopened
            .source_diagnostics(std::time::Duration::ZERO)
            .unwrap()
            .remove("legacy")
            .unwrap();
        assert_eq!(diagnostic.names, 261);
        assert_eq!(diagnostic.novel_names, 7);
        assert_eq!(diagnostic.novel_requests, 2);
        let yield_totals: (i64, i64, i64) = reopened
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT novel_names, novel_requests, novel_total_ms
                   FROM source_stats WHERE source='legacy'"#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(yield_totals, (7, 2, 300));
    }

    #[test]
    fn source_scores_reward_marginal_yield_and_penalize_zero_yield() {
        let db = Database::in_memory().unwrap();
        db.record_source_result("useful", 10, 1_000, None).unwrap();
        db.record_source_result("empty", 0, 100, None).unwrap();
        db.record_source_result_with_counts("clean-page", 10, 5, 100, None)
            .unwrap();
        db.record_source_degraded_with_counts(
            "partial-page",
            10,
            5,
            100,
            "page 2 returned invalid JSON",
        )
        .unwrap();
        for _ in 0..3 {
            db.record_source_result("failing", 0, 20_000, Some("timeout"))
                .unwrap();
        }

        let scores = db.source_scores().unwrap();
        assert!(scores["useful"] > scores["empty"]);
        assert!(scores["empty"] > scores["failing"]);
        assert!(scores["useful"] > 1_000);
        assert!(scores["failing"] < 0);
        assert!(scores["clean-page"] > scores["partial-page"]);
        let diagnostics = db.source_diagnostics(std::time::Duration::ZERO).unwrap();
        let partial = &diagnostics["partial-page"];
        assert_eq!(partial.names, 10);
        assert_eq!(partial.novel_names, 5);
        assert_eq!(partial.failures, 0);
        assert_eq!(partial.degraded, 1);
        assert_eq!(partial.deferred, 0);
        assert_eq!(partial.consecutive_failures, 0);
        assert_eq!(partial.last_status, "degraded");
        assert_eq!(
            partial.last_error.as_deref(),
            Some("page 2 returned invalid JSON")
        );
    }

    #[test]
    fn ct_materialization_is_bounded_permanent_and_idempotent() {
        let db = Database::in_memory().unwrap();
        let names = (0..500)
            .map(|index| format!("ct-{index:04}.example.com"))
            .collect::<BTreeSet<_>>();
        db.store_ct_global_batch("https://ct.example/log/", 500, &names)
            .unwrap();

        let first = db
            .materialize_ct_passive_cache_bounded("example.com", 17, true)
            .unwrap();
        assert_eq!(first.len(), 17);
        assert_eq!(
            db.ct_names_for_domain("example.com", 1_000).unwrap().len(),
            500
        );
        assert_eq!(
            db.observation_names("example.com", "passive:ct-direct")
                .unwrap()
                .len(),
            17
        );

        let tracked = first[0].clone();
        db.lock()
            .unwrap()
            .execute(
                r#"UPDATE observation_evidence
                      SET first_seen=11, last_seen=22, times_seen=9
                    WHERE root_domain='example.com'
                      AND source='passive:ct-direct'
                      AND name_id=(SELECT id FROM observed_names WHERE fqdn=?1)"#,
                [&tracked],
            )
            .unwrap();

        let second = db
            .materialize_ct_passive_cache_bounded("example.com", 17, true)
            .unwrap();
        assert_eq!(second, first);
        let evidence: (i64, i64, i64) = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT first_seen, last_seen, times_seen
                     FROM observation_evidence
                    WHERE root_domain='example.com'
                      AND source='passive:ct-direct'
                      AND name_id=(SELECT id FROM observed_names WHERE fqdn=?1)"#,
                [&tracked],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(evidence, (11, 22, 9));
    }

    #[test]
    fn expired_ct_materialization_never_writes_or_refreshes_cache() {
        let db = Database::in_memory().unwrap();
        db.store_ct_global_batch(
            "https://ct.example/log/",
            1,
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();

        assert!(
            db.materialize_ct_passive_cache_bounded_until(
                "example.com",
                10,
                true,
                Some(Instant::now()),
            )
            .is_err()
        );
        assert!(
            db.observation_names("example.com", "passive:ct-direct")
                .unwrap()
                .is_empty()
        );
        assert!(
            db.passive_cache_bounded("example.com", "ct-direct", 10)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ct_materialization_does_not_wait_past_its_deadline_for_a_locked_database() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let db = Database::open(temporary.path()).unwrap();
        db.store_ct_global_batch(
            "https://ct.example/log/",
            1,
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        let locker = Connection::open(temporary.path()).unwrap();
        locker.execute_batch("BEGIN IMMEDIATE").unwrap();

        let started = Instant::now();
        let result = db.materialize_ct_passive_cache_bounded_until(
            "example.com",
            10,
            true,
            Some(Instant::now() + Duration::from_millis(150)),
        );

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        locker.execute_batch("ROLLBACK").unwrap();
        assert!(
            db.observation_names("example.com", "passive:ct-direct")
                .unwrap()
                .is_empty()
        );
        assert!(
            db.passive_cache_bounded("example.com", "ct-direct", 10)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cancelled_ct_materialization_exits_while_the_shared_mutex_remains_locked() {
        let db = Database::in_memory().unwrap();
        db.store_ct_global_batch(
            "https://ct.example/log/",
            1,
            &BTreeSet::from(["api.example.com".to_owned()]),
        )
        .unwrap();
        let worker_db = db.clone();
        let cancellation = Arc::new(AtomicBool::new(false));
        let worker_cancellation = Arc::clone(&cancellation);
        let shared_lock = db.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = worker_db.materialize_ct_passive_cache_bounded_until_cancelled(
                "example.com",
                10,
                true,
                None,
                worker_cancellation,
            );
            result_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        cancellation.store(true, Ordering::Release);
        let result = result_rx
            .recv_timeout(Duration::from_millis(500))
            .expect("le worker CT est resté bloqué sur le mutex partagé");
        assert!(result.unwrap_err().to_string().contains("annulée"));
        drop(shared_lock);
        worker.join().unwrap();
        assert!(
            db.observation_names("example.com", "passive:ct-direct")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unversioned_legacy_database_is_backed_up_before_migration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fellaga.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("CREATE TABLE legacy_rows(value TEXT NOT NULL)", [])
            .unwrap();
        connection
            .execute("INSERT INTO legacy_rows(value) VALUES ('preserved')", [])
            .unwrap();
        drop(connection);

        let database = Database::open(&path).unwrap();
        drop(database);

        let backup = std::fs::read_dir(directory.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .find(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(".pre-v8-") && name.ends_with(".bak"))
            })
            .expect("unversioned legacy database had no safety backup");
        let backup = Connection::open(backup).unwrap();
        assert_eq!(
            backup
                .query_row("SELECT value FROM legacy_rows", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "preserved"
        );
        assert_eq!(
            backup
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn checkpoint_domain_is_immutable_and_resume_requeues_discovery_actions() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        assert!(
            db.upsert_checkpoint(scan_id, "other.example", "running", "bad")
                .is_err()
        );
        assert!(
            db.resumable_checkpoint("other.example", "latest")
                .unwrap()
                .is_none()
        );
        db.upsert_checkpoint(scan_id, "example.com", "running", "good")
            .unwrap();
        db.persist_scan_seed_candidates(
            scan_id,
            &[(
                "seed.example.com".to_owned(),
                BTreeSet::from(["passive:test".to_owned()]),
                1,
            )],
            1,
        )
        .unwrap();
        let seed = "seed.example.com".to_owned();
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
            1
        );
        db.requeue_unstarted_scan_seed_candidates(scan_id, std::slice::from_ref(&seed))
            .unwrap();
        assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 1);
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
            1
        );
        db.enqueue_discovery_actions(
            scan_id,
            &[DiscoveryActionInput {
                fqdn: Some("api.example.com".to_owned()),
                zone: "example.com".to_owned(),
                kind: "dns".to_owned(),
                generator: "resume-regression".to_owned(),
                context_key: "global".to_owned(),
                priority_class: 0,
                predicted_unique_live: 1.0,
                predicted_cost: 1.0,
            }],
        )
        .unwrap();
        let first = db.claim_discovery_actions(scan_id, 1).unwrap();
        assert_eq!(first.len(), 1);

        db.pause_scan(scan_id, 0, 0, 0, 1, &[]).unwrap();
        db.reopen_scan(scan_id).unwrap();
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
            1
        );
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    "SELECT attempts FROM scan_seed_candidates WHERE scan_id=?1",
                    [scan_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "unstarted claims must survive deadline requeue and resume without consuming a retry"
        );
        db.mark_scan_seed_candidates_started(scan_id, std::slice::from_ref(&seed))
            .unwrap();
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    "SELECT attempts FROM scan_seed_candidates WHERE scan_id=?1",
                    [scan_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        db.update_cache_outcomes(Some(scan_id), &[], &[], std::slice::from_ref(&seed), 60)
            .unwrap();
        db.mark_scan_seed_candidates_done(scan_id, std::slice::from_ref(&seed))
            .unwrap();
        assert_eq!(
            db.pending_scan_seed_candidates(scan_id, 1).unwrap().len(),
            1
        );
        db.requeue_unstarted_scan_seed_candidates(scan_id, std::slice::from_ref(&seed))
            .unwrap();
        assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 1);
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    "SELECT attempts FROM scan_seed_candidates WHERE scan_id=?1",
                    [scan_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "an unstarted retry must preserve attempts from earlier real DNS work"
        );
        let resumed = db.claim_discovery_actions(scan_id, 1).unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].id, first[0].id);
    }

    #[test]
    fn exhausted_rows_are_excluded_from_every_candidate_claim_and_loop_count() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let seed = "seed-exhausted.example.com".to_owned();
        db.persist_scan_seed_candidates(
            scan_id,
            &[(
                seed.clone(),
                BTreeSet::from(["passive:test".to_owned()]),
                10,
            )],
            10,
        )
        .unwrap();
        db.persist_scan_candidates(
            scan_id,
            "example.com",
            &[("active-exhausted".to_owned(), "builtin".to_owned(), 10)],
        )
        .unwrap();
        db.ensure_scan_recursive_words(scan_id, &["recursive-exhausted".to_owned()])
            .unwrap();
        db.persist_scan_recursive_parents(scan_id, 1, &["example.com".to_owned()])
            .unwrap();
        assert_eq!(
            db.refill_scan_recursive_candidates(scan_id, 1, 1).unwrap(),
            1
        );
        {
            let connection = db.lock().unwrap();
            for table in [
                "scan_seed_candidates",
                "scan_candidates",
                "scan_recursive_candidates",
            ] {
                connection
                    .execute(
                        &format!("UPDATE {table} SET attempts=3, status='queued' WHERE scan_id=?1"),
                        [scan_id],
                    )
                    .unwrap();
            }
        }

        assert!(
            db.pending_scan_seed_candidates(scan_id, 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            db.claim_scan_seed_candidates_by_name(scan_id, std::slice::from_ref(&seed))
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.pending_scan_seed_candidate_count(scan_id).unwrap(), 0);
        assert!(db.pending_scan_candidates(scan_id, 10).unwrap().is_empty());
        assert_eq!(db.pending_scan_candidate_count(scan_id).unwrap(), 0);
        assert_eq!(
            db.pending_scan_candidate_count_eligible(scan_id, true)
                .unwrap(),
            0
        );
        assert!(
            db.pending_scan_recursive_candidates(scan_id, 1, 10)
                .unwrap()
                .is_empty()
        );
        assert!(!db.scan_recursive_depth_has_more(scan_id, 1).unwrap());
        assert!(!db.scan_recursive_has_more(scan_id).unwrap());
    }

    #[test]
    fn reopen_scan_requeues_only_rows_with_retry_budget_in_all_three_queues() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.upsert_checkpoint(scan_id, "example.com", "running", "options")
            .unwrap();
        {
            let connection = db.lock().unwrap();
            connection
                .execute(
                    r#"INSERT INTO scan_seed_candidates(
                           scan_id, fqdn, priority, sources_json, attempts, status
                       ) VALUES
                           (?1, 'exhausted.example.com', 2, '[]', 3, 'queued'),
                           (?1, 'retry.example.com', 1, '[]', 2, 'processing')"#,
                    [scan_id],
                )
                .unwrap();
            connection
                .execute(
                    r#"INSERT INTO scan_candidates(
                           scan_id, fqdn, relative_name, priority, generator, attempts, status
                       ) VALUES
                           (?1, 'exhausted.example.com', 'exhausted', 2, 'test', 3, 'processing'),
                           (?1, 'retry.example.com', 'retry', 1, 'test', 2, 'processing')"#,
                    [scan_id],
                )
                .unwrap();
            connection
                .execute(
                    r#"INSERT INTO scan_recursive_candidates(
                           scan_id, fqdn, parent, depth, word, attempts, status
                       ) VALUES
                           (?1, 'exhausted.example.com', 'example.com', 1, 'exhausted', 3, 'queued'),
                           (?1, 'retry.example.com', 'example.com', 1, 'retry', 2, 'processing')"#,
                    [scan_id],
                )
                .unwrap();
        }
        db.pause_scan(scan_id, 0, 0, 0, 1, &[]).unwrap();
        db.reopen_scan(scan_id).unwrap();

        let connection = db.lock().unwrap();
        for table in [
            "scan_seed_candidates",
            "scan_candidates",
            "scan_recursive_candidates",
        ] {
            let rows = connection
                .prepare(&format!(
                    "SELECT fqdn, status FROM {table} WHERE scan_id=?1 ORDER BY fqdn"
                ))
                .unwrap()
                .query_map([scan_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![
                    ("exhausted.example.com".to_owned(), "done".to_owned()),
                    ("retry.example.com".to_owned(), "queued".to_owned()),
                ],
                "resume state mismatch for {table}"
            );
        }
    }

    #[test]
    fn live_outcome_wins_over_duplicate_negative_and_error_in_one_commit() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "api.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.10".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            resolver_count: 2,
            authoritative_validation: false,
        };
        let finding = Finding {
            fqdn: fqdn.clone(),
            records: answer.records.clone(),
            sources: BTreeSet::from(["dns:test".to_owned()]),
            wildcard: false,
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            ..Finding::default()
        };
        db.persist_findings(scan_id, "example.com", &[finding], 60)
            .unwrap();
        db.update_cache_outcomes(
            Some(scan_id),
            &[answer],
            std::slice::from_ref(&fqdn),
            std::slice::from_ref(&fqdn),
            60,
        )
        .unwrap();

        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .get(&fqdn),
            Some(CachedAnswer::Positive(_))
        ));
        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT active, verification_state FROM subdomains WHERE fqdn=?1",
                    [&fqdn],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (1, "live".to_owned())
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT group_concat(outcome, ',') FROM dns_verifications WHERE scan_id=?1 AND fqdn=?2",
                    params![scan_id, fqdn],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "live"
        );
    }

    #[test]
    fn off_zone_wildcard_ambiguity_cannot_delete_an_unrelated_cache_entry() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "api.other.example".to_owned();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.20".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            resolver_count: 2,
            authoritative_validation: false,
        };
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 60)
            .unwrap();
        assert!(
            db.record_current_wildcard_ambiguities(
                scan_id,
                "example.com",
                std::slice::from_ref(&answer),
            )
            .is_err()
        );
        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .get(&fqdn),
            Some(CachedAnswer::Positive(_))
        ));
    }

    #[test]
    fn live_wildcard_finding_is_audited_but_never_materialized_as_live() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "random.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.30".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            resolver_count: 2,
            authoritative_validation: false,
        };
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 60)
            .unwrap();
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records.clone(),
                sources: BTreeSet::from(["dns:initial-live".to_owned()]),
                wildcard: false,
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                ..Finding::default()
            }],
            60,
        )
        .unwrap();
        assert!(
            db.lock()
                .unwrap()
                .query_row(
                    "SELECT last_verified_at FROM subdomains WHERE fqdn=?1",
                    [&fqdn],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .get(&fqdn),
            Some(CachedAnswer::Positive(_))
        ));
        let finding = Finding {
            fqdn: fqdn.clone(),
            records: answer.records,
            sources: BTreeSet::from(["dns:wildcard".to_owned()]),
            wildcard: true,
            state: ObservationState::Live,
            last_verified_at: answer.last_verified_at,
            ..Finding::default()
        };
        db.persist_findings(scan_id, "example.com", &[finding], 60)
            .unwrap();

        assert!(
            !db.fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .contains_key(&fqdn),
            "a wildcard finding must purge the provisional positive cache"
        );

        let connection = db.lock().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT active, verification_state, last_verified_at FROM subdomains WHERE fqdn=?1",
                    [&fqdn],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    },
                )
                .unwrap(),
            (0, "unverified".to_owned(), None)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT active FROM dns_records WHERE fqdn=?1",
                    [&fqdn],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state, wildcard FROM scan_findings WHERE scan_id=?1 AND fqdn=?2",
                    params![scan_id, fqdn],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            ("live".to_owned(), 1)
        );
    }

    #[test]
    fn ordinary_historical_finding_keeps_its_positive_cache_history() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let fqdn = "old.example.com".to_owned();
        let answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.31".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(now_epoch()),
            resolver_count: 2,
            authoritative_validation: false,
        };
        db.update_cache_outcomes(Some(scan_id), std::slice::from_ref(&answer), &[], &[], 60)
            .unwrap();
        db.persist_findings(
            scan_id,
            "example.com",
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records,
                sources: BTreeSet::from(["history:test".to_owned()]),
                wildcard: false,
                state: ObservationState::Historical,
                last_verified_at: answer.last_verified_at,
                ..Finding::default()
            }],
            60,
        )
        .unwrap();

        assert!(matches!(
            db.fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .get(&fqdn),
            Some(CachedAnswer::Positive(_))
        ));
        assert_eq!(
            db.lock()
                .unwrap()
                .query_row(
                    "SELECT active, verification_state FROM subdomains WHERE fqdn=?1",
                    [&fqdn],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (0, "historical".to_owned())
        );
    }

    #[test]
    fn persistent_counters_and_legacy_bandits_tolerate_extreme_values() {
        let db = Database::in_memory().unwrap();
        let metric = ResolverMetric {
            resolver: "resolver.test:53".to_owned(),
            requests: u64::MAX,
            successes: u64::MAX,
            failures: u64::MAX,
            average_ms: u64::MAX,
            consecutive_failures: u64::MAX,
        };
        db.store_resolver_metrics(std::slice::from_ref(&metric))
            .unwrap();
        db.store_resolver_metrics(&[metric]).unwrap();
        let history = db.resolver_history().unwrap();
        let stored = &history["resolver.test:53"];
        assert_eq!(stored.requests, i64::MAX as u64);
        assert_eq!(stored.successes, i64::MAX as u64);
        assert_eq!(stored.failures, i64::MAX as u64);
        assert_eq!(stored.consecutive_failures, i64::MAX as u64);

        db.record_source_result_with_counts(
            "overflow-source",
            usize::MAX,
            usize::MAX,
            u128::MAX,
            None,
        )
        .unwrap();
        db.record_source_result_with_counts(
            "overflow-source",
            usize::MAX,
            usize::MAX,
            u128::MAX,
            None,
        )
        .unwrap();
        let source_counters = db
            .lock()
            .unwrap()
            .query_row(
                r#"SELECT requests, successes, names, novel_names,
                          novel_requests, novel_total_ms, total_ms
                   FROM source_stats WHERE source='overflow-source'"#,
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            source_counters,
            (2, 2, i64::MAX, i64::MAX, 2, i64::MAX, i64::MAX)
        );

        db.lock()
            .unwrap()
            .execute(
                r#"INSERT INTO generator_bandits(
                       context, generator, alpha, beta, pulls, rewards, last_seen
                   ) VALUES ('suffix:com', 'number-neighbor', -1.0e308, -1.0e308,
                             -9223372036854775808, -1, 1)"#,
                [],
            )
            .unwrap();
        let scores = db.generator_scores("example.com").unwrap();
        assert!((650..=2_650).contains(&scores["number-neighbor"]));
    }

    #[test]
    fn scan_summary_counts_saturate_instead_of_wrapping_negative() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        db.finish_scan(
            scan_id,
            "interrupted",
            usize::MAX,
            usize::MAX,
            usize::MAX,
            u128::MAX,
            &[],
        )
        .unwrap();
        let stored = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT candidates, found, cache_hits, duration_ms FROM scans WHERE id=?1",
                [scan_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap();
        let expected = usize_to_i64_saturating(usize::MAX);
        assert_eq!(stored, (expected, expected, expected, i64::MAX));
    }

    #[test]
    fn resumed_axfr_snapshot_replaces_attempts_without_duplicate_metrics() {
        let db = Database::in_memory().unwrap();
        let scan_id = db.create_scan("example.com", &json!({})).unwrap();
        let attempt = |nameserver: &str, status| AxfrAttempt {
            nameserver: nameserver.to_owned(),
            address: "192.0.2.53:53".to_owned(),
            status,
            error: None,
            records: Vec::new(),
            names: BTreeSet::new(),
        };
        db.save_axfr_attempts(
            scan_id,
            &[
                attempt("ns1.example.com", crate::model::AxfrStatus::Refused),
                attempt("ns2.example.com", crate::model::AxfrStatus::Timeout),
            ],
        )
        .unwrap();
        db.save_axfr_attempts(
            scan_id,
            &[attempt(
                "ns1.example.com",
                crate::model::AxfrStatus::Success,
            )],
        )
        .unwrap();

        let rows = db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*), SUM(status='success') FROM axfr_attempts WHERE scan_id=?1",
                [scan_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap();
        assert_eq!(rows, (1, 1));
    }

    #[test]
    fn ip_hostname_cache_is_permanent_and_failures_never_delete_names() {
        let db = Database::in_memory().unwrap();
        let address: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(
            db.ip_hostname_cache("shodan-internetdb", address, 256)
                .unwrap()
                .is_none()
        );

        db.store_ip_hostname_success(
            "shodan-internetdb",
            address,
            &BTreeSet::from([
                "a.example.com".to_owned(),
                "b.example.com".to_owned(),
                "invalid host".to_owned(),
            ]),
        )
        .unwrap();
        db.store_ip_hostname_success(
            "shodan-internetdb",
            address,
            &BTreeSet::from(["b.example.com".to_owned(), "c.example.com".to_owned()]),
        )
        .unwrap();
        let before_failure = db
            .ip_hostname_cache("shodan-internetdb", address, 256)
            .unwrap()
            .unwrap();
        assert_eq!(before_failure.status, "success");
        assert_eq!(
            before_failure.hostnames,
            BTreeSet::from([
                "a.example.com".to_owned(),
                "b.example.com".to_owned(),
                "c.example.com".to_owned(),
            ])
        );

        db.store_ip_hostname_failure("shodan-internetdb", address, "temporary failure")
            .unwrap();
        let after_failure = db
            .ip_hostname_cache("shodan-internetdb", address, 256)
            .unwrap()
            .unwrap();
        assert_eq!(after_failure.status, "error");
        assert_eq!(after_failure.hostnames, before_failure.hostnames);
        assert_eq!(
            after_failure.last_success_at,
            before_failure.last_success_at
        );
        assert!(db.ip_hostname_cache("INVALID", address, 1).is_err());
    }
}
