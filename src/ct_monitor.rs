use crate::db::Database;
use crate::model::CtMonitorResult;
use crate::passive::{compact_external_error, external_user_agent, response_bytes_limited_to};
use crate::util::{is_subdomain, normalize_hostname};
use anyhow::{Context, Result, bail};
use base64::Engine;
use futures_util::{StreamExt, stream};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::Instant as TokioInstant;

const CHROME_LOG_LIST: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
const CT_GLOBAL_REFRESH: Duration = Duration::from_secs(10 * 60);
const DEFAULT_CT_MATERIALIZATION_LIMIT: usize = 100_000;
const CT_LOG_LIST_MAX_BYTES: usize = 4 * 1024 * 1024;
const CT_ENTRIES_MAX_BYTES: usize = 32 * 1024 * 1024;
static CT_GLOBAL_GATE: Semaphore = Semaphore::const_new(1);

/// Fine-grained progress emitted by the raw CT-log indexer.  The scanner can
/// bridge these events to its normal stderr/JSON progress channel without the
/// CT module depending on CLI types.  Events never contain credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtProgressEvent {
    ReusingFreshIndex,
    WaitingForGlobalIndexer {
        phase_remaining: Option<Duration>,
    },
    GlobalIndexerAcquired {
        waited: Duration,
    },
    LoadingLogList {
        request_budget: Duration,
        phase_remaining: Option<Duration>,
    },
    LogsSelected {
        total: usize,
        entries_per_log: usize,
    },
    LogStarted {
        position: usize,
        total: usize,
        log_url: String,
        request_budget: Duration,
        phase_remaining: Option<Duration>,
    },
    TreeHead {
        position: usize,
        total: usize,
        log_url: String,
        tree_size: u64,
        cursor: u64,
    },
    BatchStarted {
        position: usize,
        total: usize,
        log_url: String,
        batch: usize,
        start: u64,
        end: u64,
        request_budget: Duration,
        phase_remaining: Option<Duration>,
    },
    BatchCommitted {
        position: usize,
        total: usize,
        log_url: String,
        batch: usize,
        entries: usize,
        names: usize,
        next_cursor: u64,
    },
    LogFinished {
        completed: usize,
        total: usize,
        log_url: String,
        entries: usize,
        batches: usize,
        names: usize,
    },
    LogFailed {
        completed: usize,
        total: usize,
        log_url: String,
        error: String,
    },
    MaterializingTargetIndex,
    Finished {
        logs: usize,
        entries: usize,
        failures: usize,
        names: usize,
        duration: Duration,
    },
}

pub type CtProgressCallback = Arc<dyn Fn(CtProgressEvent) + Send + Sync>;

fn short_log_url(log_url: &str) -> &str {
    log_url
        .strip_prefix("https://")
        .or_else(|| log_url.strip_prefix("http://"))
        .unwrap_or(log_url)
        .trim_end_matches('/')
}

fn seconds(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

fn remaining_text(remaining: Option<Duration>) -> String {
    remaining.map_or_else(
        || "phase sans limite globale".to_owned(),
        |remaining| format!("reste phase {:.1}s", seconds(remaining)),
    )
}

impl fmt::Display for CtProgressEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReusingFreshIndex => {
                write!(
                    formatter,
                    "index CT global frais réutilisé; aucune lecture réseau"
                )
            }
            Self::WaitingForGlobalIndexer { phase_remaining } => write!(
                formatter,
                "attente du slot CT global; {}",
                remaining_text(*phase_remaining)
            ),
            Self::GlobalIndexerAcquired { waited } => write!(
                formatter,
                "slot CT global acquis après {:.1}s",
                seconds(*waited)
            ),
            Self::LoadingLogList {
                request_budget,
                phase_remaining,
            } => write!(
                formatter,
                "liste publique Chrome; requête bornée à {:.1}s, {}",
                seconds(*request_budget),
                remaining_text(*phase_remaining)
            ),
            Self::LogsSelected {
                total,
                entries_per_log,
            } => write!(
                formatter,
                "{total} journal(aux) sélectionné(s), plafond {entries_per_log} entrées/journal"
            ),
            Self::LogStarted {
                position,
                total,
                log_url,
                request_budget,
                phase_remaining,
            } => write!(
                formatter,
                "journal {position}/{total} {}: STH borné à {:.1}s, {}",
                short_log_url(log_url),
                seconds(*request_budget),
                remaining_text(*phase_remaining)
            ),
            Self::TreeHead {
                position,
                total,
                log_url,
                tree_size,
                cursor,
            } => write!(
                formatter,
                "journal {position}/{total} {}: taille {tree_size}, curseur SQLite {cursor}",
                short_log_url(log_url)
            ),
            Self::BatchStarted {
                position,
                total,
                log_url,
                batch,
                start,
                end,
                request_budget,
                phase_remaining,
            } => write!(
                formatter,
                "journal {position}/{total} {}, lot {batch}, index {start}..={end}: requête bornée à {:.1}s, {}",
                short_log_url(log_url),
                seconds(*request_budget),
                remaining_text(*phase_remaining)
            ),
            Self::BatchCommitted {
                position,
                total,
                log_url,
                batch,
                entries,
                names,
                next_cursor,
            } => write!(
                formatter,
                "journal {position}/{total} {}, lot {batch}: {entries} entrées, {names} nom(s), curseur {next_cursor} validé",
                short_log_url(log_url)
            ),
            Self::LogFinished {
                completed,
                total,
                log_url,
                entries,
                batches,
                names,
            } => write!(
                formatter,
                "journal terminé {completed}/{total} {}: {batches} lot(s), {entries} entrées, {names} nom(s)",
                short_log_url(log_url)
            ),
            Self::LogFailed {
                completed,
                total,
                log_url,
                error,
            } => write!(
                formatter,
                "journal en échec {completed}/{total} {}: {error}",
                short_log_url(log_url)
            ),
            Self::MaterializingTargetIndex => {
                write!(
                    formatter,
                    "lecture de l'index SQLite ciblé et fusion du cache"
                )
            }
            Self::Finished {
                logs,
                entries,
                failures,
                names,
                duration,
            } => write!(
                formatter,
                "terminé en {:.1}s: {logs} journal(aux), {entries} entrées, {failures} échec(s), {names} nom(s) ciblé(s)",
                seconds(*duration)
            ),
        }
    }
}

fn emit_progress(progress: &Option<CtProgressCallback>, event: CtProgressEvent) {
    if let Some(progress) = progress {
        progress(event);
    }
}

#[derive(Debug, Deserialize)]
struct LogList {
    #[serde(default)]
    operators: Vec<LogOperator>,
}

#[derive(Debug, Deserialize)]
struct LogOperator {
    #[serde(default)]
    logs: Vec<CtLog>,
}

#[derive(Debug, Deserialize)]
struct CtLog {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SignedTreeHead {
    tree_size: u64,
}

#[derive(Debug, Deserialize)]
struct EntriesResponse {
    #[serde(default)]
    entries: Vec<CtEntry>,
}

#[derive(Debug, Deserialize)]
struct CtEntry {
    leaf_input: String,
    extra_data: String,
}

fn next_batch_cursor(start: u64, end: u64, processed: usize) -> Result<u64> {
    if processed == 0 {
        bail!("le journal CT a retourné une page vide pour {start}..={end}");
    }
    let requested = end.saturating_sub(start).saturating_add(1);
    if processed as u64 > requested {
        bail!("le journal CT a retourné {processed} entrées pour une fenêtre de {requested}");
    }
    Ok(start.saturating_add(processed as u64))
}

fn completed_selected_log_pass(logs_checked: usize, failures: usize) -> bool {
    logs_checked > 0 && failures == 0
}

fn select_logs(
    logs: BTreeSet<String>,
    states: &HashMap<String, (u64, i64)>,
    max_logs: usize,
) -> Vec<String> {
    let mut logs = logs.into_iter().collect::<Vec<_>>();
    logs.sort_by_key(|log| {
        let state = states.get(log);
        (
            state.is_some(),
            state.map(|(_, updated)| *updated).unwrap_or(i64::MIN),
            log.clone(),
        )
    });
    logs.truncate(max_logs);
    logs
}

fn read_u24(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset + 3)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

fn certificate_der(entry: &CtEntry) -> Result<Vec<u8>> {
    let decoder = base64::engine::general_purpose::STANDARD;
    let leaf = decoder
        .decode(&entry.leaf_input)
        .context("leaf_input CT en base64 invalide")?;
    if leaf.len() < 15 {
        bail!("leaf_input CT tronqué");
    }
    let entry_type = u16::from_be_bytes([leaf[10], leaf[11]]);
    let source = if entry_type == 0 {
        leaf.get(12..).context("entrée X509 CT tronquée")?.to_vec()
    } else if entry_type == 1 {
        decoder
            .decode(&entry.extra_data)
            .context("extra_data CT en base64 invalide")?
    } else {
        bail!("type d'entrée CT inconnu: {entry_type}");
    };
    let length = read_u24(&source, 0).context("longueur de certificat CT absente")?;
    source
        .get(3..3 + length)
        .map(ToOwned::to_owned)
        .context("certificat CT tronqué")
}

fn names_from_entry(entry: &CtEntry) -> Result<BTreeSet<String>> {
    let der = certificate_der(entry)?;
    let certificate = X509::from_der(&der).context("certificat X509 CT invalide")?;
    let mut names = BTreeSet::new();
    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        for general_name in subject_alt_names {
            if let Some(name) = general_name.dnsname()
                && let Some(name) = normalize_hostname(name)
            {
                names.insert(name);
            }
        }
    }
    for entry in certificate.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(name) = entry.data().to_string()
            && let Some(name) = normalize_hostname(&name)
        {
            names.insert(name);
        }
    }
    Ok(names)
}

fn endpoint(log_url: &str, path: &str) -> String {
    format!("{}/{}", log_url.trim_end_matches('/'), path)
}

async fn before_ct_deadline<T, F>(deadline: Option<TokioInstant>, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match deadline {
        Some(deadline) if deadline <= TokioInstant::now() => {
            bail!("budget de temps cumulé CT atteint")
        }
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .context("budget de temps cumulé CT atteint")?,
        None => future.await,
    }
}

fn phase_remaining(deadline: Option<TokioInstant>) -> Option<Duration> {
    deadline.map(|deadline| deadline.saturating_duration_since(TokioInstant::now()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtRequestLimit {
    PerRequest,
    Phase,
}

#[derive(Debug, Clone, Copy)]
struct CtRequestBudget {
    deadline: TokioInstant,
    duration: Duration,
    limit: CtRequestLimit,
}

fn ct_request_budget(
    per_request_timeout: Duration,
    phase_deadline: Option<TokioInstant>,
    now: TokioInstant,
) -> Result<CtRequestBudget> {
    if per_request_timeout.is_zero() {
        bail!("le délai CT par requête doit être supérieur à zéro");
    }
    let request_deadline = now + per_request_timeout;
    match phase_deadline {
        Some(phase_deadline) if phase_deadline <= now => {
            bail!("budget de temps cumulé CT atteint avant la requête")
        }
        Some(phase_deadline) if phase_deadline <= request_deadline => Ok(CtRequestBudget {
            deadline: phase_deadline,
            duration: phase_deadline.saturating_duration_since(now),
            limit: CtRequestLimit::Phase,
        }),
        _ => Ok(CtRequestBudget {
            deadline: request_deadline,
            duration: per_request_timeout,
            limit: CtRequestLimit::PerRequest,
        }),
    }
}

async fn await_ct_request<T, F>(budget: CtRequestBudget, operation: &str, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout_at(budget.deadline, future).await {
        Ok(result) => result,
        Err(_) if budget.limit == CtRequestLimit::Phase => bail!(
            "budget de temps cumulé CT atteint pendant {operation}; requête annulée proprement"
        ),
        Err(_) => bail!(
            "délai CT par requête de {:.1}s atteint pendant {operation}; requête annulée proprement",
            seconds(budget.duration)
        ),
    }
}

async fn ct_response_json<T: DeserializeOwned>(
    response: reqwest::Response,
    operation: &str,
    max_bytes: usize,
) -> Result<T> {
    let (status, body) = response_bytes_limited_to(response, operation, max_bytes).await?;
    if !status.is_success() {
        bail!(
            "{operation}: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    serde_json::from_slice(&body).with_context(|| format!("JSON {operation} invalide"))
}

async fn store_ct_refresh_marker(
    database: &Database,
    key: &str,
    deadline: Option<TokioInstant>,
) -> Result<()> {
    let database = database.clone();
    let key = key.to_owned();
    let value = crate::util::now_epoch().to_string();
    before_ct_deadline(deadline, async move {
        tokio::task::spawn_blocking(move || database.store_source_metadata(&key, &value))
            .await
            .context("tâche d'écriture du marqueur CT interrompue")?
    })
    .await
}

async fn decode_batch_names(
    entries: &[CtEntry],
    deadline: Option<TokioInstant>,
) -> Result<BTreeSet<String>> {
    if deadline.is_some_and(|deadline| deadline <= TokioInstant::now()) {
        bail!(
            "budget de temps cumulé CT atteint avant le décodage du lot; curseur SQLite inchangé"
        );
    }
    let mut names = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        if index % 32 == 0 {
            tokio::task::yield_now().await;
            if deadline.is_some_and(|deadline| deadline <= TokioInstant::now()) {
                bail!(
                    "budget de temps cumulé CT atteint pendant le décodage du lot; curseur SQLite inchangé"
                );
            }
        }
        names.extend(
            names_from_entry(entry).with_context(|| format!("décodage de l'entrée CT {index}"))?,
        );
    }
    Ok(names)
}

#[derive(Debug)]
struct CommittedCtBatch {
    entries: usize,
    names: BTreeSet<String>,
    next_cursor: u64,
}

async fn process_and_store_batch(
    database: &Database,
    log_url: &str,
    start: u64,
    end: u64,
    entries: &[CtEntry],
    deadline: Option<TokioInstant>,
) -> Result<CommittedCtBatch> {
    // Decode the complete response before advancing the durable cursor.  If
    // cancellation or the phase deadline arrives mid-decode, this whole page
    // is replayed next time instead of silently losing unparsed certificates.
    let names = decode_batch_names(entries, deadline).await?;
    let next_cursor = next_batch_cursor(start, end, entries.len())?;
    database.store_ct_global_batch(log_url, next_cursor, &names)?;
    Ok(CommittedCtBatch {
        entries: entries.len(),
        names,
        next_cursor,
    })
}

async fn materialize_target_names(
    database: &Database,
    domain: &str,
    limit: usize,
    complete: bool,
    deadline: Option<TokioInstant>,
    progress: &Option<CtProgressCallback>,
) -> Result<BTreeSet<String>> {
    emit_progress(progress, CtProgressEvent::MaterializingTargetIndex);
    let database = database.clone();
    let target_domain = domain.to_owned();
    let materialization_domain = target_domain.clone();
    let storage_deadline = deadline.map(TokioInstant::into_std);
    let names = before_ct_deadline(deadline, async move {
        tokio::task::spawn_blocking(move || {
            database.materialize_ct_passive_cache_bounded_until(
                &materialization_domain,
                limit,
                complete,
                storage_deadline,
            )
        })
        .await
        .context("tâche de matérialisation CT interrompue")?
    })
    .await?;
    Ok(names
        .into_iter()
        .filter(|name| is_subdomain(name, &target_domain))
        .collect())
}

fn finish_progress(
    progress: &Option<CtProgressCallback>,
    result: &CtMonitorResult,
    started: Instant,
) {
    emit_progress(
        progress,
        CtProgressEvent::Finished {
            logs: result.logs_checked,
            entries: result.entries_processed,
            failures: result.failures,
            names: result.names.len(),
            duration: started.elapsed(),
        },
    );
}

pub async fn monitor_ct_logs(
    database: &Database,
    domain: &str,
    timeout: Duration,
    max_logs: usize,
    entries_per_log: usize,
    initial_backfill: usize,
) -> Result<CtMonitorResult> {
    monitor_ct_logs_until(
        database,
        domain,
        timeout,
        max_logs,
        entries_per_log,
        initial_backfill,
        None,
        DEFAULT_CT_MATERIALIZATION_LIMIT,
        None,
    )
    .await
}

pub async fn monitor_ct_logs_bounded(
    database: &Database,
    domain: &str,
    timeout: Duration,
    max_logs: usize,
    entries_per_log: usize,
    initial_backfill: usize,
    phase_timeout: Duration,
) -> Result<CtMonitorResult> {
    monitor_ct_logs_bounded_with_progress(
        database,
        domain,
        timeout,
        max_logs,
        entries_per_log,
        initial_backfill,
        phase_timeout,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn monitor_ct_logs_bounded_with_progress(
    database: &Database,
    domain: &str,
    timeout: Duration,
    max_logs: usize,
    entries_per_log: usize,
    initial_backfill: usize,
    phase_timeout: Duration,
    progress: Option<CtProgressCallback>,
) -> Result<CtMonitorResult> {
    monitor_ct_logs_bounded_with_progress_and_limit(
        database,
        domain,
        timeout,
        max_logs,
        entries_per_log,
        initial_backfill,
        phase_timeout,
        DEFAULT_CT_MATERIALIZATION_LIMIT,
        progress,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn monitor_ct_logs_bounded_with_progress_and_limit(
    database: &Database,
    domain: &str,
    timeout: Duration,
    max_logs: usize,
    entries_per_log: usize,
    initial_backfill: usize,
    phase_timeout: Duration,
    materialization_limit: usize,
    progress: Option<CtProgressCallback>,
) -> Result<CtMonitorResult> {
    let deadline = (!phase_timeout.is_zero()).then(|| TokioInstant::now() + phase_timeout);
    monitor_ct_logs_until(
        database,
        domain,
        timeout,
        max_logs,
        entries_per_log,
        initial_backfill,
        deadline,
        materialization_limit,
        progress,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn monitor_ct_logs_until(
    database: &Database,
    domain: &str,
    timeout: Duration,
    max_logs: usize,
    entries_per_log: usize,
    initial_backfill: usize,
    deadline: Option<TokioInstant>,
    materialization_limit: usize,
    progress: Option<CtProgressCallback>,
) -> Result<CtMonitorResult> {
    let started = Instant::now();
    if timeout.is_zero() {
        bail!("le délai CT par requête doit être supérieur à zéro");
    }
    let refresh_key =
        format!("ct.global.last_refresh.{max_logs}.{entries_per_log}.{initial_backfill}");
    if database
        .source_metadata(&refresh_key, CT_GLOBAL_REFRESH)?
        .is_some()
    {
        emit_progress(&progress, CtProgressEvent::ReusingFreshIndex);
        let result = CtMonitorResult {
            names: materialize_target_names(
                database,
                domain,
                materialization_limit,
                true,
                deadline,
                &progress,
            )
            .await?,
            duration_ms: started.elapsed().as_millis(),
            ..CtMonitorResult::default()
        };
        finish_progress(&progress, &result, started);
        return Ok(result);
    }

    if CT_GLOBAL_GATE.available_permits() == 0 {
        emit_progress(
            &progress,
            CtProgressEvent::WaitingForGlobalIndexer {
                phase_remaining: phase_remaining(deadline),
            },
        );
    }
    let gate_started = Instant::now();
    let global_permit = before_ct_deadline(deadline, async {
        CT_GLOBAL_GATE
            .acquire()
            .await
            .map_err(|error| anyhow::anyhow!("sémaphore CT fermé: {error}"))
    })
    .await?;
    emit_progress(
        &progress,
        CtProgressEvent::GlobalIndexerAcquired {
            waited: gate_started.elapsed(),
        },
    );

    // A different target may have completed the same global pass while this
    // task waited. Recheck under the single-flight permit before any request.
    if database
        .source_metadata(&refresh_key, CT_GLOBAL_REFRESH)?
        .is_some()
    {
        drop(global_permit);
        emit_progress(&progress, CtProgressEvent::ReusingFreshIndex);
        let result = CtMonitorResult {
            names: materialize_target_names(
                database,
                domain,
                materialization_limit,
                true,
                deadline,
                &progress,
            )
            .await?,
            duration_ms: started.elapsed().as_millis(),
            ..CtMonitorResult::default()
        };
        finish_progress(&progress, &result, started);
        return Ok(result);
    }

    let client = reqwest::Client::builder()
        .connect_timeout(timeout)
        .pool_idle_timeout(Duration::from_secs(30))
        .user_agent(external_user_agent())
        .build()?;
    let list_budget = ct_request_budget(timeout, deadline, TokioInstant::now())?;
    emit_progress(
        &progress,
        CtProgressEvent::LoadingLogList {
            request_budget: list_budget.duration,
            phase_remaining: phase_remaining(deadline),
        },
    );
    let list = await_ct_request(list_budget, "la lecture de la liste CT Chrome", async {
        let response = client
            .get(CHROME_LOG_LIST)
            .send()
            .await
            .context("connexion à la liste CT de Chrome")?;
        ct_response_json::<LogList>(response, "liste CT Chrome", CT_LOG_LIST_MAX_BYTES).await
    })
    .await?;
    let all_logs = list
        .operators
        .into_iter()
        .flat_map(|operator| operator.logs)
        .map(|log| log.url)
        .collect::<BTreeSet<_>>();
    if max_logs > 0 && all_logs.is_empty() {
        bail!("la liste CT de Chrome ne contient aucun journal");
    }
    let logs = select_logs(all_logs, &database.ct_global_states()?, max_logs);
    let log_count = logs.len();
    emit_progress(
        &progress,
        CtProgressEvent::LogsSelected {
            total: log_count,
            entries_per_log,
        },
    );
    let database = database.clone();
    let progress_for_logs = progress.clone();
    let mut pending = stream::iter(logs.into_iter().enumerate())
        .map(|(log_index, log_url)| {
            let client = client.clone();
            let database = database.clone();
            let progress = progress_for_logs.clone();
            async move {
                let position = log_index + 1;
                let outcome = async {
                    let sth_budget = ct_request_budget(timeout, deadline, TokioInstant::now())?;
                    emit_progress(
                        &progress,
                        CtProgressEvent::LogStarted {
                            position,
                            total: log_count,
                            log_url: log_url.clone(),
                            request_budget: sth_budget.duration,
                            phase_remaining: phase_remaining(deadline),
                        },
                    );
                    let operation = format!("la lecture STH de {}", short_log_url(&log_url));
                    let sth = await_ct_request(sth_budget, &operation, async {
                        let response = client
                            .get(endpoint(&log_url, "ct/v1/get-sth"))
                            .send()
                            .await
                            .with_context(|| format!("connexion STH au journal {log_url}"))?;
                        ct_response_json::<SignedTreeHead>(
                            response,
                            &format!("STH du journal {log_url}"),
                            CT_LOG_LIST_MAX_BYTES,
                        )
                        .await
                    })
                    .await?;
                    let stored = database.ct_global_cursor(&log_url)?;
                    if sth.tree_size == 0 {
                        let cursor = stored.unwrap_or_default();
                        emit_progress(
                            &progress,
                            CtProgressEvent::TreeHead {
                                position,
                                total: log_count,
                                log_url: log_url.clone(),
                                tree_size: 0,
                                cursor,
                            },
                        );
                        if cursor > 0 {
                            bail!(
                                "le journal CT {log_url} annonce une taille nulle après indexation"
                            );
                        }
                        database.store_ct_global_batch(&log_url, 0, &BTreeSet::new())?;
                        return Ok::<_, anyhow::Error>((0, 0, BTreeSet::new()));
                    }
                    let backfill_start = || {
                        sth.tree_size
                            .saturating_sub(initial_backfill.min(u64::MAX as usize) as u64)
                    };
                    let mut start = match stored {
                        Some(cursor) if cursor > sth.tree_size => {
                            let reset = backfill_start();
                            database.reset_ct_global_cursor(&log_url, reset)?;
                            reset
                        }
                        Some(cursor) => cursor,
                        None => backfill_start(),
                    };
                    emit_progress(
                        &progress,
                        CtProgressEvent::TreeHead {
                            position,
                            total: log_count,
                            log_url: log_url.clone(),
                            tree_size: sth.tree_size,
                            cursor: start,
                        },
                    );
                    if start >= sth.tree_size || entries_per_log == 0 {
                        database.store_ct_global_batch(&log_url, start, &BTreeSet::new())?;
                        return Ok((0, 0, BTreeSet::new()));
                    }

                    let mut total_processed = 0_usize;
                    let mut pages = 0_usize;
                    let mut names = BTreeSet::new();
                    while start < sth.tree_size && total_processed < entries_per_log && pages < 64 {
                        let remaining = entries_per_log.saturating_sub(total_processed);
                        let end = start
                            .saturating_add(remaining.saturating_sub(1) as u64)
                            .min(sth.tree_size - 1);
                        let batch = pages + 1;
                        let request_budget =
                            ct_request_budget(timeout, deadline, TokioInstant::now())?;
                        emit_progress(
                            &progress,
                            CtProgressEvent::BatchStarted {
                                position,
                                total: log_count,
                                log_url: log_url.clone(),
                                batch,
                                start,
                                end,
                                request_budget: request_budget.duration,
                                phase_remaining: phase_remaining(deadline),
                            },
                        );
                        let operation = format!(
                            "le lot {batch} ({start}..={end}) de {}",
                            short_log_url(&log_url)
                        );
                        let response = await_ct_request(request_budget, &operation, async {
                            let response = client
                                .get(endpoint(&log_url, "ct/v1/get-entries"))
                                .query(&[("start", start), ("end", end)])
                                .send()
                                .await
                                .with_context(|| {
                                    format!("connexion au lot {start}..={end} du journal {log_url}")
                                })?;
                            ct_response_json::<EntriesResponse>(
                                response,
                                &format!("lot {start}..={end} du journal {log_url}"),
                                CT_ENTRIES_MAX_BYTES,
                            )
                            .await
                        })
                        .await?;
                        let committed = process_and_store_batch(
                            &database,
                            &log_url,
                            start,
                            end,
                            &response.entries,
                            deadline,
                        )
                        .await?;
                        emit_progress(
                            &progress,
                            CtProgressEvent::BatchCommitted {
                                position,
                                total: log_count,
                                log_url: log_url.clone(),
                                batch,
                                entries: committed.entries,
                                names: committed.names.len(),
                                next_cursor: committed.next_cursor,
                            },
                        );
                        total_processed = total_processed.saturating_add(committed.entries);
                        names.extend(committed.names);
                        pages += 1;
                        start = committed.next_cursor;
                    }
                    Ok((total_processed, pages, names))
                }
                .await;
                (log_url, outcome)
            }
        })
        .buffer_unordered(4);
    let mut result = CtMonitorResult {
        logs_checked: log_count,
        ..CtMonitorResult::default()
    };
    let mut indexed_names = BTreeSet::new();
    let mut completed = 0_usize;
    while let Some((log_url, log_result)) = pending.next().await {
        completed += 1;
        match log_result {
            Ok((processed, batches, names)) => {
                result.entries_processed += processed;
                emit_progress(
                    &progress,
                    CtProgressEvent::LogFinished {
                        completed,
                        total: log_count,
                        log_url,
                        entries: processed,
                        batches,
                        names: names.len(),
                    },
                );
                indexed_names.extend(names);
            }
            Err(error) => {
                result.failures += 1;
                emit_progress(
                    &progress,
                    CtProgressEvent::LogFailed {
                        completed,
                        total: log_count,
                        log_url,
                        error: format!("{error:#}"),
                    },
                );
            }
        }
    }
    result.globally_indexed_names = indexed_names.len();
    let complete = completed_selected_log_pass(result.logs_checked, result.failures);
    if complete {
        store_ct_refresh_marker(&database, &refresh_key, deadline).await?;
    }
    // Per-target cache materialization does not need the global raw-log slot.
    // Releasing it here prevents a large local inventory query from blocking
    // every other target's CT progress.
    drop(global_permit);
    result.names = materialize_target_names(
        &database,
        domain,
        materialization_limit,
        complete,
        deadline,
        &progress,
    )
    .await?;
    result.duration_ms = started.elapsed().as_millis();
    finish_progress(&progress, &result, started);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};
    use std::sync::Mutex;

    fn valid_x509_entry(common_name: &str) -> CtEntry {
        let key = PKey::from_rsa(Rsa::generate(2_048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_serial_number(&serial).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate.set_not_before(&not_before).unwrap();
        certificate.set_not_after(&not_after).unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let der = certificate.build().to_der().unwrap();
        let length = der.len();
        let mut leaf = vec![0_u8; 12];
        leaf.extend_from_slice(&[
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ]);
        leaf.extend_from_slice(&der);
        leaf.extend_from_slice(&[0, 0]);
        CtEntry {
            leaf_input: base64::engine::general_purpose::STANDARD.encode(leaf),
            extra_data: String::new(),
        }
    }

    #[test]
    fn an_empty_ct_page_never_advances_the_cursor() {
        assert!(next_batch_cursor(100, 199, 0).is_err());
        assert_eq!(next_batch_cursor(100, 199, 25).unwrap(), 125);
        assert!(next_batch_cursor(100, 199, 101).is_err());
    }

    #[test]
    fn refresh_marker_requires_every_selected_log_to_succeed() {
        assert!(!completed_selected_log_pass(0, 0));
        assert!(completed_selected_log_pass(3, 0));
        assert!(!completed_selected_log_pass(3, 1));
        assert!(!completed_selected_log_pass(3, 3));
    }

    #[test]
    fn log_selection_prioritizes_unseen_then_oldest_logs() {
        let logs = BTreeSet::from([
            "https://a.example/".to_owned(),
            "https://b.example/".to_owned(),
            "https://c.example/".to_owned(),
        ]);
        let states = HashMap::from([
            ("https://a.example/".to_owned(), (10, 200)),
            ("https://b.example/".to_owned(), (20, 100)),
        ]);
        assert_eq!(
            select_logs(logs, &states, 2),
            vec![
                "https://c.example/".to_owned(),
                "https://b.example/".to_owned()
            ]
        );
    }

    #[test]
    fn parses_three_byte_lengths() {
        assert_eq!(read_u24(&[0x01, 0x02, 0x03], 0), Some(0x010203));
        assert_eq!(read_u24(&[0x01, 0x02], 0), None);
    }

    #[tokio::test]
    async fn expired_ct_deadline_cancels_without_network() {
        let error = before_ct_deadline(
            Some(TokioInstant::now()),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("budget de temps cumulé CT"));
    }

    #[test]
    fn each_request_uses_the_stricter_of_its_timeout_and_the_phase_budget() {
        let now = TokioInstant::now();
        let phase_limited = ct_request_budget(
            Duration::from_secs(8),
            Some(now + Duration::from_secs(2)),
            now,
        )
        .unwrap();
        assert_eq!(phase_limited.duration, Duration::from_secs(2));
        assert_eq!(phase_limited.limit, CtRequestLimit::Phase);

        let request_limited = ct_request_budget(
            Duration::from_secs(2),
            Some(now + Duration::from_secs(8)),
            now,
        )
        .unwrap();
        assert_eq!(request_limited.duration, Duration::from_secs(2));
        assert_eq!(request_limited.limit, CtRequestLimit::PerRequest);

        assert!(ct_request_budget(Duration::ZERO, None, now).is_err());
        assert!(ct_request_budget(Duration::from_secs(1), Some(now), now).is_err());
    }

    #[test]
    fn batch_progress_identifies_the_log_range_and_request_budget() {
        let message = CtProgressEvent::BatchStarted {
            position: 2,
            total: 5,
            log_url: "https://ct.example/log/".to_owned(),
            batch: 3,
            start: 12_000,
            end: 12_999,
            request_budget: Duration::from_secs(4),
            phase_remaining: Some(Duration::from_secs(21)),
        }
        .to_string();

        for expected in [
            "journal 2/5",
            "ct.example/log",
            "lot 3",
            "index 12000..=12999",
            "4.0s",
            "reste phase 21.0s",
        ] {
            assert!(
                message.contains(expected),
                "message absent: {expected}: {message}"
            );
        }
    }

    #[test]
    fn progress_callback_receives_structured_events() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_for_callback = Arc::clone(&received);
        let callback: CtProgressCallback = Arc::new(move |event| {
            received_for_callback.lock().unwrap().push(event);
        });

        emit_progress(
            &Some(callback),
            CtProgressEvent::LogsSelected {
                total: 4,
                entries_per_log: 2_000,
            },
        );

        assert_eq!(
            *received.lock().unwrap(),
            vec![CtProgressEvent::LogsSelected {
                total: 4,
                entries_per_log: 2_000,
            }]
        );
    }

    #[tokio::test]
    async fn cancellation_during_decode_preserves_the_durable_cursor() {
        let database = Database::in_memory().unwrap();
        let log_url = "https://ct.example/log/";
        database
            .store_ct_global_batch(log_url, 100, &BTreeSet::new())
            .unwrap();
        let entries = vec![CtEntry {
            leaf_input: String::new(),
            extra_data: String::new(),
        }];

        let error = process_and_store_batch(
            &database,
            log_url,
            100,
            100,
            &entries,
            Some(TokioInstant::now()),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("curseur SQLite inchangé"));
        assert_eq!(database.ct_global_cursor(log_url).unwrap(), Some(100));
    }

    #[tokio::test]
    async fn a_fully_decoded_batch_advances_the_durable_cursor_once() {
        let database = Database::in_memory().unwrap();
        let log_url = "https://ct.example/log/";
        database
            .store_ct_global_batch(log_url, 100, &BTreeSet::new())
            .unwrap();
        let entries = vec![valid_x509_entry("api.example.com")];

        let committed = process_and_store_batch(&database, log_url, 100, 100, &entries, None)
            .await
            .unwrap();

        assert_eq!(committed.entries, 1);
        assert_eq!(
            committed.names,
            BTreeSet::from(["api.example.com".to_owned()])
        );
        assert_eq!(committed.next_cursor, 101);
        assert_eq!(database.ct_global_cursor(log_url).unwrap(), Some(101));
    }

    #[tokio::test]
    async fn malformed_ct_entries_never_advance_the_durable_cursor() {
        let database = Database::in_memory().unwrap();
        let log_url = "https://ct.example/log/";
        database
            .store_ct_global_batch(log_url, 100, &BTreeSet::new())
            .unwrap();
        let entries = vec![CtEntry {
            leaf_input: "not-base64".to_owned(),
            extra_data: String::new(),
        }];

        let error = process_and_store_batch(&database, log_url, 100, 100, &entries, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("décodage de l'entrée CT 0"));
        assert_eq!(database.ct_global_cursor(log_url).unwrap(), Some(100));
    }

    #[tokio::test]
    async fn fresh_ct_index_materialization_obeys_the_caller_limit() {
        let database = Database::in_memory().unwrap();
        let names = (0..250)
            .map(|index| format!("ct-{index:04}.example.com"))
            .collect::<BTreeSet<_>>();
        database
            .store_ct_global_batch("https://ct.example/log/", 250, &names)
            .unwrap();
        database
            .store_source_metadata("ct.global.last_refresh.2.10.10", "fresh")
            .unwrap();

        let result = monitor_ct_logs_bounded_with_progress_and_limit(
            &database,
            "example.com",
            Duration::from_secs(1),
            2,
            10,
            10,
            Duration::from_secs(1),
            13,
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.names.len(), 13);
        assert_eq!(
            database
                .ct_names_for_domain("example.com", 1_000)
                .unwrap()
                .len(),
            250
        );
        assert_eq!(
            database
                .observation_names("example.com", "passive:ct-direct")
                .unwrap()
                .len(),
            13
        );
    }

    #[tokio::test]
    async fn ct_json_responses_are_rejected_past_their_byte_budget() {
        let response = reqwest::Response::from(
            http::Response::builder()
                .status(200)
                .body(reqwest::Body::from(vec![b' '; 65]))
                .unwrap(),
        );
        let error = ct_response_json::<LogList>(response, "fixture CT", 64)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("supérieure"));
    }

    #[tokio::test]
    async fn expired_ct_deadline_never_waits_for_or_writes_the_refresh_marker() {
        let database = Database::in_memory().unwrap();
        assert!(
            store_ct_refresh_marker(&database, "ct.fixture.refresh", Some(TokioInstant::now()))
                .await
                .is_err()
        );
        assert!(
            database
                .source_metadata("ct.fixture.refresh", Duration::from_secs(60))
                .unwrap()
                .is_none()
        );
    }
}
