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

pub use crate::source_contract::{PassivePaginationPage, PassivePaginationState};

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
    deadline: Option<Instant>,
    reply: mpsc::Sender<Result<ObservationWriteStats>>,
}

struct ObservationWriter {
    sender: mpsc::Sender<WriterMessage>,
}

#[derive(Debug)]
struct PassivePersistenceDeadlineExceeded;

impl std::fmt::Display for PassivePersistenceDeadlineExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("délai de persistance SQLite passive dépassé")
    }
}

impl std::error::Error for PassivePersistenceDeadlineExceeded {}

pub(crate) fn is_passive_persistence_deadline_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<PassivePersistenceDeadlineExceeded>()
        .is_some()
}

fn is_sqlite_contention_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(inner, _))
                if matches!(
                    inner.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
        )
    })
}

pub(crate) fn is_passive_bookkeeping_deferred_error(error: &anyhow::Error) -> bool {
    is_passive_persistence_deadline_error(error) || is_sqlite_contention_error(error)
}

fn passive_persistence_deadline_error() -> anyhow::Error {
    anyhow::Error::new(PassivePersistenceDeadlineExceeded)
}

fn ensure_passive_persistence_deadline(deadline: Option<Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(passive_persistence_deadline_error());
    }
    Ok(())
}

fn receive_observation_writer_reply(
    response: mpsc::Receiver<Result<ObservationWriteStats>>,
    deadline: Option<Instant>,
) -> Result<ObservationWriteStats> {
    match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure_passive_persistence_deadline(Some(deadline))?;
            match response.recv_timeout(remaining) {
                Ok(reply) => reply,
                Err(mpsc::RecvTimeoutError::Timeout) => Err(passive_persistence_deadline_error()),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("réponse du writer SQLite absente");
                }
            }
        }
        None => response
            .recv()
            .map_err(|_| anyhow::anyhow!("réponse du writer SQLite absente"))?,
    }
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
                        let _ = message.reply.send(Err(anyhow::anyhow!(
                            "ouverture du writer SQLite impossible"
                        )));
                    }
                    return;
                };
                let _ = connection.pragma_update(None, "journal_mode", "WAL");
                let _ = connection.pragma_update(None, "synchronous", "NORMAL");
                let _ = connection.pragma_update(None, "foreign_keys", "ON");
                let _ = connection.busy_timeout(std::time::Duration::from_secs(5));
                if let Err(error) = secure_existing_sqlite_files(&path) {
                    for message in receiver {
                        let _ = message.reply.send(Err(anyhow::anyhow!(
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
                            message.deadline,
                        ),
                        None => insert_observations_with_stats(
                            &mut connection,
                            &message.root_domain,
                            &message.observations,
                        ),
                    };
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
                deadline: None,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("writer SQLite arrêté"))?;
        receive_observation_writer_reply(response, None)
    }

    fn submit_passive_page_with_stats(
        &self,
        root_domain: &str,
        source: &str,
        observations: Vec<ObservationInput>,
    ) -> Result<ObservationWriteStats> {
        self.submit_passive_page_with_stats_before(root_domain, source, observations, None)
    }

    fn submit_passive_page_with_stats_until(
        &self,
        root_domain: &str,
        source: &str,
        observations: Vec<ObservationInput>,
        deadline: Instant,
    ) -> Result<ObservationWriteStats> {
        self.submit_passive_page_with_stats_before(
            root_domain,
            source,
            observations,
            Some(deadline),
        )
    }

    fn submit_passive_page_with_stats_before(
        &self,
        root_domain: &str,
        source: &str,
        observations: Vec<ObservationInput>,
        deadline: Option<Instant>,
    ) -> Result<ObservationWriteStats> {
        // Even an empty provider page is durable progress: it starts or
        // refreshes the restart session and creates the incomplete cache
        // marker in one transaction, so it must still reach the writer.
        if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
            return Err(passive_persistence_deadline_error());
        }
        let (reply, response) = mpsc::channel();
        self.sender
            .send(WriterMessage {
                root_domain: root_domain.to_owned(),
                observations,
                passive_refresh_source: Some(source.to_owned()),
                deadline,
                reply,
            })
            .map_err(|_| anyhow::anyhow!("writer SQLite arrêté"))?;
        receive_observation_writer_reply(response, deadline)
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
    deadline: Option<Instant>,
) -> Result<ObservationWriteStats> {
    ensure_passive_persistence_deadline(deadline)?;
    let busy_timeout = deadline
        .map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250))
                .max(Duration::from_millis(1))
        })
        .unwrap_or(Duration::from_secs(5));
    connection.busy_timeout(busy_timeout)?;
    let result = (|| {
        ensure_passive_persistence_deadline(deadline)?;
        let transaction = connection.transaction()?;
        let stats = insert_passive_observation_rows_with_stats_before(
            &transaction,
            root_domain,
            source,
            observations,
            deadline,
        )?;
        ensure_passive_persistence_deadline(deadline)?;
        transaction.execute(
            r#"INSERT OR IGNORE INTO passive_cache(
                   root_domain, source, names_json, updated_at
               ) VALUES (?1, ?2, '[]', 0)"#,
            params![root_domain, source],
        )?;
        ensure_passive_persistence_deadline(deadline)?;
        transaction.commit()?;
        Ok(stats)
    })();
    let restore = connection
        .busy_timeout(Duration::from_secs(5))
        .context("restauration du délai SQLite après persistance passive");
    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(stats), Ok(())) => Ok(stats),
    }
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

fn insert_passive_observation_rows_with_stats_before(
    connection: &Connection,
    root_domain: &str,
    source: &str,
    observations: &[ObservationInput],
    deadline: Option<Instant>,
) -> Result<ObservationWriteStats> {
    insert_observation_rows_with_refresh_stats_before(
        connection,
        root_domain,
        Some(source),
        observations,
        deadline,
    )
}

fn insert_observation_rows_with_refresh_stats(
    connection: &Connection,
    root_domain: &str,
    passive_refresh_source: Option<&str>,
    observations: &[ObservationInput],
) -> Result<ObservationWriteStats> {
    insert_observation_rows_with_refresh_stats_before(
        connection,
        root_domain,
        passive_refresh_source,
        observations,
        None,
    )
}

fn insert_observation_rows_with_refresh_stats_before(
    connection: &Connection,
    root_domain: &str,
    passive_refresh_source: Option<&str>,
    observations: &[ObservationInput],
    deadline: Option<Instant>,
) -> Result<ObservationWriteStats> {
    ensure_passive_persistence_deadline(deadline)?;
    let now = now_epoch();
    let refresh_generation = passive_refresh_source
        .map(|source| begin_passive_refresh_session(connection, root_domain, source, now))
        .transpose()?;
    let mut stats = ObservationWriteStats::default();
    for (index, observation) in observations.iter().enumerate() {
        if index % 32 == 0 {
            ensure_passive_persistence_deadline(deadline)?;
        }
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
    ensure_passive_persistence_deadline(deadline)?;
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

mod connection;
mod enrichment;
mod intelligence;
mod observations;
mod passive;
mod read_model;
mod scan;

#[cfg(test)]
mod tests;
