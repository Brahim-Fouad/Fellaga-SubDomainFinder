use crate::db::Database;
use crate::dns::{DnsEngine, DnsResolutionOutcome, bind_buffered_udp};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

pub const MAX_PIPELINE_CANDIDATES: usize = 10_000_000;
pub const MAX_PIPELINE_BATCH_SIZE: usize = 50_000;
pub const MAX_PIPELINE_CONCURRENCY: usize = 60_000;
const BENCHMARK_DOMAIN: &str = "pipeline-benchmark.invalid";
const NEGATIVE_CACHE_TTL: u32 = 30;

#[derive(Debug, Clone)]
pub struct CandidatePipelineOptions {
    pub database: PathBuf,
    pub wordlist: PathBuf,
    pub output: PathBuf,
    pub candidates: usize,
    pub batch_size: usize,
    pub concurrency: usize,
    pub timeout: Duration,
    pub campaign_id: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CandidatePipelinePhaseDurations {
    pub fixture_generation: u128,
    pub database_initialization: u128,
    pub loading_and_sqlite: u128,
    pub scheduling: u128,
    pub dns: u128,
    pub wordlist_refill: u128,
    pub candidate_pending_count: u128,
    pub candidate_claim: u128,
    pub cache_journal: u128,
    pub candidate_finalize: u128,
    pub sqlite_total: u128,
}

impl CandidatePipelinePhaseDurations {
    fn add_sqlite_duration(total: &mut u128, component: &mut u128, elapsed_ms: u128) {
        *component = component.saturating_add(elapsed_ms);
        *total = total.saturating_add(elapsed_ms);
    }

    fn record_wordlist_refill(&mut self, elapsed_ms: u128) {
        Self::add_sqlite_duration(
            &mut self.loading_and_sqlite,
            &mut self.wordlist_refill,
            elapsed_ms,
        );
        self.sqlite_total = self.sqlite_total.saturating_add(elapsed_ms);
    }

    fn record_candidate_claim(&mut self, elapsed_ms: u128) {
        self.candidate_claim = self.candidate_claim.saturating_add(elapsed_ms);
        self.scheduling = self.scheduling.saturating_add(elapsed_ms);
        self.sqlite_total = self.sqlite_total.saturating_add(elapsed_ms);
    }

    fn record_pending_candidate_count(&mut self, elapsed_ms: u128) {
        Self::add_sqlite_duration(
            &mut self.loading_and_sqlite,
            &mut self.candidate_pending_count,
            elapsed_ms,
        );
        self.sqlite_total = self.sqlite_total.saturating_add(elapsed_ms);
    }

    fn record_cache_journal(&mut self, elapsed_ms: u128) {
        Self::add_sqlite_duration(
            &mut self.loading_and_sqlite,
            &mut self.cache_journal,
            elapsed_ms,
        );
        self.sqlite_total = self.sqlite_total.saturating_add(elapsed_ms);
    }

    fn record_candidate_finalize(&mut self, elapsed_ms: u128) {
        Self::add_sqlite_duration(
            &mut self.loading_and_sqlite,
            &mut self.candidate_finalize,
            elapsed_ms,
        );
        self.sqlite_total = self.sqlite_total.saturating_add(elapsed_ms);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CandidatePipelineResult {
    pub schema_version: u8,
    pub benchmark: &'static str,
    pub engine: &'static str,
    pub status: &'static str,
    pub campaign_id: String,
    pub fellaga_version: &'static str,
    pub binary_sha256: String,
    pub fellaga_sha256: String,
    pub fixture_sha256: String,
    pub wordlist_sha256: String,
    pub corpus_sha256: String,
    pub candidates: usize,
    pub requested_candidates: usize,
    pub loaded_candidates: usize,
    pub persisted_candidates: usize,
    pub scheduled_candidates: usize,
    pub dns_dispatched_candidates: usize,
    pub processed_candidates: usize,
    pub positive_candidates: usize,
    pub definitive_negative_candidates: usize,
    pub indeterminate_candidates: usize,
    pub dns_queries: u64,
    pub loopback_queries: u64,
    pub batch_size: usize,
    pub peak_queued_candidates: usize,
    pub concurrency: usize,
    pub dns_timeout_ms: u128,
    pub remaining_queued_candidates: usize,
    pub database_candidates: usize,
    pub database_dns_verifications: usize,
    pub database_cache_entries: usize,
    pub fixture_bytes: u64,
    pub sqlite_bytes: u64,
    pub duration_ms: u128,
    pub phase_duration_ms: CandidatePipelinePhaseDurations,
    pub loss_rate: f64,
}

struct PartialFile {
    path: PathBuf,
    armed: bool,
}

impl PartialFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct BenchmarkScanGuard {
    database: Database,
    scan_id: i64,
    started: Instant,
    armed: bool,
}

impl BenchmarkScanGuard {
    fn new(database: Database, scan_id: i64, started: Instant) -> Self {
        Self {
            database,
            scan_id,
            started,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BenchmarkScanGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.database.finish_scan(
                self.scan_id,
                "interrupted",
                0,
                0,
                0,
                self.started.elapsed().as_millis(),
                &["candidate pipeline benchmark interrupted".to_owned()],
            );
        }
    }
}

struct LoopbackNxDomainServer {
    address: SocketAddr,
    queries: Arc<AtomicU64>,
    tasks: Vec<JoinHandle<()>>,
}

impl LoopbackNxDomainServer {
    async fn start() -> Result<Self> {
        let socket = Arc::new(bind_buffered_udp("127.0.0.1:0".parse()?)?);
        let address = socket.local_addr()?;
        ensure!(
            address.ip().is_loopback(),
            "benchmark DNS server is not loopback"
        );
        let queries = Arc::new(AtomicU64::new(0));
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let socket = socket.clone();
            let queries = queries.clone();
            tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0_u8; 4_096];
                loop {
                    let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                        break;
                    };
                    if length < 12 {
                        continue;
                    }
                    // Preserve the transaction ID and question verbatim, set
                    // QR, and return a definitive NXDOMAIN response.
                    queries.fetch_add(1, Ordering::Relaxed);
                    buffer[2] |= 0x80;
                    buffer[3] = (buffer[3] & 0xF0) | 0x03;
                    let _ = socket.send_to(&buffer[..length], peer).await;
                }
            }));
        }
        Ok(Self {
            address,
            queries,
            tasks,
        })
    }

    fn query_count(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }
}

impl Drop for LoopbackNxDomainServer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn sha256_hex(digest: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(sha256_hex(hasher.finalize()))
}

fn partial_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("benchmark artifact path must include a file name")?;
    let mut partial_name = OsString::from(".");
    partial_name.push(name);
    partial_name.push(format!(".{}.partial", std::process::id()));
    Ok(path.with_file_name(partial_name))
}

fn normalize_new_file(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .context("benchmark artifact path must include a file name")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("creating benchmark directory {}", parent.display()))?;
    Ok(parent
        .canonicalize()
        .with_context(|| format!("resolving benchmark directory {}", parent.display()))?
        .join(name))
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn validate_options(options: &CandidatePipelineOptions) -> Result<CandidatePipelineOptions> {
    ensure!(
        (1..=MAX_PIPELINE_CANDIDATES).contains(&options.candidates),
        "--candidates must be between 1 and {MAX_PIPELINE_CANDIDATES}"
    );
    ensure!(
        (1..=MAX_PIPELINE_BATCH_SIZE).contains(&options.batch_size),
        "--batch-size must be between 1 and {MAX_PIPELINE_BATCH_SIZE}"
    );
    ensure!(
        (1..=MAX_PIPELINE_CONCURRENCY).contains(&options.concurrency),
        "--concurrency must be between 1 and {MAX_PIPELINE_CONCURRENCY}"
    );
    ensure!(
        !options.timeout.is_zero() && options.timeout <= Duration::from_secs(60),
        "--timeout must be greater than zero and at most 60 seconds"
    );
    ensure!(
        !options.campaign_id.is_empty()
            && options.campaign_id.len() <= 128
            && options
                .campaign_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "--campaign-id must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens"
    );

    let mut validated = options.clone();
    validated.database = normalize_new_file(&options.database)?;
    validated.wordlist = normalize_new_file(&options.wordlist)?;
    validated.output = normalize_new_file(&options.output)?;
    ensure!(
        validated.database != validated.wordlist
            && validated.database != validated.output
            && validated.wordlist != validated.output,
        "database, wordlist, and output paths must be distinct"
    );
    let fresh_paths = [
        validated.database.clone(),
        sqlite_sidecar(&validated.database, "-wal"),
        sqlite_sidecar(&validated.database, "-shm"),
        sqlite_sidecar(&validated.database, "-journal"),
        validated.wordlist.clone(),
        partial_path(&validated.wordlist)?,
        validated.output.clone(),
        partial_path(&validated.output)?,
    ];
    for path in &fresh_paths {
        ensure!(
            !path.exists(),
            "benchmark artifact already exists: {}",
            path.display()
        );
    }
    Ok(validated)
}

fn generate_fixture(path: &Path, candidates: usize) -> Result<(String, u64)> {
    let temporary = partial_path(path)?;
    ensure!(
        !temporary.exists(),
        "partial benchmark fixture already exists: {}",
        temporary.display()
    );
    let mut guard = PartialFile::new(temporary.clone());
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("creating benchmark fixture {}", temporary.display()))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    for index in 0..candidates {
        let line = format!("bench-{index:08}\n");
        writer.write_all(line.as_bytes())?;
        hasher.update(line.as_bytes());
        bytes = bytes.saturating_add(line.len() as u64);
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "publishing benchmark fixture {} as {}",
            temporary.display(),
            path.display()
        )
    })?;
    guard.disarm();
    Ok((sha256_hex(hasher.finalize()), bytes))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    ensure!(
        !path.exists(),
        "benchmark output already exists: {}",
        path.display()
    );
    let temporary = partial_path(path)?;
    ensure!(
        !temporary.exists(),
        "partial benchmark output already exists: {}",
        temporary.display()
    );
    let mut guard = PartialFile::new(temporary.clone());
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .with_context(|| format!("creating benchmark output {}", temporary.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    drop(writer);
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "publishing benchmark output {} as {}",
            temporary.display(),
            path.display()
        )
    })?;
    guard.disarm();
    Ok(())
}

fn sqlite_size(path: &Path) -> u64 {
    [
        path.to_path_buf(),
        sqlite_sidecar(path, "-wal"),
        sqlite_sidecar(path, "-shm"),
        sqlite_sidecar(path, "-journal"),
    ]
    .into_iter()
    .filter_map(|candidate| fs::metadata(candidate).ok())
    .map(|metadata| metadata.len())
    .sum()
}

pub async fn run_candidate_pipeline(
    options: CandidatePipelineOptions,
) -> Result<CandidatePipelineResult> {
    let options = validate_options(&options)?;
    let started = Instant::now();
    let mut phases = CandidatePipelinePhaseDurations::default();

    let fixture_started = Instant::now();
    let (fixture_sha256, fixture_bytes) = generate_fixture(&options.wordlist, options.candidates)?;
    phases.fixture_generation = fixture_started.elapsed().as_millis();
    ensure!(
        sha256_file(&options.wordlist)? == fixture_sha256,
        "generated fixture hash changed before loading"
    );

    let executable = std::env::current_exe().context("locating the Fellaga executable")?;
    let binary_sha256 = sha256_file(&executable)?;
    let server = LoopbackNxDomainServer::start().await?;
    ensure!(
        server.address.ip().is_loopback(),
        "candidate pipeline resolver must be loopback"
    );
    let dns = DnsEngine::new_with_socket_addresses(
        options.concurrency,
        options.timeout,
        &[server.address],
        0,
    )?;

    let database_started = Instant::now();
    let database = Database::open(&options.database)?;
    phases.database_initialization = database_started.elapsed().as_millis();
    let scan_id = database.create_scan(
        BENCHMARK_DOMAIN,
        &json!({
            "mode": "candidate_pipeline_benchmark",
            "campaign_id": options.campaign_id,
            "candidates": options.candidates,
            "batch_size": options.batch_size,
            "concurrency": options.concurrency,
        }),
    )?;
    let mut scan_guard = BenchmarkScanGuard::new(database.clone(), scan_id, started);

    let mut loaded = 0_usize;
    let mut persisted = 0_usize;
    let mut scheduled = 0_usize;
    let mut dispatched = 0_usize;
    let mut processed = 0_usize;
    let mut positive = 0_usize;
    let mut negative = 0_usize;
    let mut indeterminate = 0_usize;
    let mut peak_queued = 0_usize;

    while scheduled < options.candidates {
        let target = options
            .batch_size
            .min(options.candidates.saturating_sub(scheduled));
        let pending_count_started = Instant::now();
        let pending_count_result = database.pending_scan_candidate_count(scan_id);
        phases.record_pending_candidate_count(pending_count_started.elapsed().as_millis());
        let mut queued = pending_count_result?.max(0) as usize;
        while queued < target && persisted < options.candidates {
            let capacity = target
                .saturating_sub(queued)
                .min(options.candidates.saturating_sub(persisted));
            let refill_started = Instant::now();
            let refill_result = database.refill_wordlist_candidates(
                scan_id,
                BENCHMARK_DOMAIN,
                &options.wordlist,
                capacity,
            );
            phases.record_wordlist_refill(refill_started.elapsed().as_millis());
            let (inserted, exhausted) = refill_result?;
            loaded = loaded.saturating_add(inserted);
            persisted = persisted.saturating_add(inserted);
            queued = queued.saturating_add(inserted);
            peak_queued = peak_queued.max(queued);
            if inserted == 0 {
                if exhausted {
                    break;
                }
                bail!("candidate fixture page made no progress before end of file");
            }
        }

        let claim_started = Instant::now();
        let claim_result = database.pending_scan_candidates(scan_id, target);
        phases.record_candidate_claim(claim_started.elapsed().as_millis());
        let claimed = claim_result?;
        ensure!(
            !claimed.is_empty(),
            "candidate queue ended after {scheduled} of {} candidates",
            options.candidates
        );
        let hosts = claimed
            .iter()
            .map(|(relative_name, _, _)| format!("{relative_name}.{BENCHMARK_DOMAIN}"))
            .collect::<Vec<_>>();
        scheduled = scheduled.saturating_add(hosts.len());
        dispatched = dispatched.saturating_add(hosts.len());

        let dns_started = Instant::now();
        let outcomes = dns
            .resolve_many_classified_with_progress(hosts.clone(), |_| {})
            .await;
        phases.dns = phases.dns.saturating_add(dns_started.elapsed().as_millis());
        ensure!(
            outcomes.len() == hosts.len(),
            "DNS dispatcher returned {} outcomes for {} candidates",
            outcomes.len(),
            hosts.len()
        );

        let mut positive_answers = Vec::new();
        let mut negative_hosts = Vec::new();
        let mut indeterminate_hosts = Vec::new();
        for outcome in outcomes {
            match outcome {
                DnsResolutionOutcome::Positive(answer) => positive_answers.push(answer),
                DnsResolutionOutcome::Negative { fqdn } => negative_hosts.push(fqdn),
                DnsResolutionOutcome::Indeterminate { fqdn } => indeterminate_hosts.push(fqdn),
            }
        }
        positive = positive.saturating_add(positive_answers.len());
        negative = negative.saturating_add(negative_hosts.len());
        indeterminate = indeterminate.saturating_add(indeterminate_hosts.len());
        processed = processed
            .saturating_add(positive_answers.len())
            .saturating_add(negative_hosts.len());

        let cache_started = Instant::now();
        let cache_result = database.update_cache_outcomes(
            Some(scan_id),
            &positive_answers,
            &negative_hosts,
            &indeterminate_hosts,
            NEGATIVE_CACHE_TTL,
        );
        phases.record_cache_journal(cache_started.elapsed().as_millis());
        cache_result?;

        let finalize_started = Instant::now();
        let finalize_result = database.mark_scan_candidates_done(scan_id, &hosts);
        phases.record_candidate_finalize(finalize_started.elapsed().as_millis());
        finalize_result?;
        ensure!(
            indeterminate_hosts.is_empty(),
            "controlled loopback DNS produced {} indeterminate candidates",
            indeterminate_hosts.len()
        );
    }

    ensure!(
        database.scan_candidate_feed_exhausted(scan_id, "wordlist")?,
        "candidate fixture was not fully consumed"
    );
    let remaining_queued = database.pending_scan_candidate_count(scan_id)?.max(0) as usize;
    let database_candidates = database.scan_candidate_count(scan_id)?.max(0) as usize;
    let resolver_metrics = dns.take_metrics();
    let dns_queries = resolver_metrics
        .iter()
        .map(|metric| metric.requests)
        .sum::<u64>();
    let loopback_queries = server.query_count();
    let expected_queries = (options.candidates as u64).saturating_mul(2);
    ensure!(
        loaded == options.candidates,
        "fixture loading count mismatch"
    );
    ensure!(
        persisted == options.candidates,
        "SQLite persistence count mismatch"
    );
    ensure!(scheduled == options.candidates, "scheduler count mismatch");
    ensure!(
        dispatched == options.candidates,
        "DNS dispatch count mismatch"
    );
    ensure!(
        processed == options.candidates,
        "processed candidate count mismatch"
    );
    ensure!(
        positive == 0,
        "NXDOMAIN loopback returned positive candidates"
    );
    ensure!(negative == options.candidates, "NXDOMAIN count mismatch");
    ensure!(indeterminate == 0, "loopback DNS loss was not zero");
    ensure!(remaining_queued == 0, "candidate queue is not empty");
    ensure!(
        database_candidates == options.candidates,
        "persisted candidate table count mismatch"
    );
    ensure!(
        dns_queries == expected_queries,
        "DNS engine emitted {dns_queries} queries instead of {expected_queries}"
    );
    ensure!(
        loopback_queries == expected_queries,
        "loopback server received {loopback_queries} queries instead of {expected_queries}"
    );

    let stats = database.stats()?;
    ensure!(
        stats.dns_verifications.max(0) as usize == options.candidates,
        "DNS verification journal count mismatch"
    );
    ensure!(
        stats.cache_entries.max(0) as usize == options.candidates,
        "DNS cache persistence count mismatch"
    );
    database.finish_scan(
        scan_id,
        "completed",
        options.candidates,
        0,
        0,
        started.elapsed().as_millis(),
        &[],
    )?;
    scan_guard.disarm();

    let result = CandidatePipelineResult {
        schema_version: 1,
        benchmark: "candidate_pipeline",
        engine: "fellaga_core",
        status: "success",
        campaign_id: options.campaign_id.clone(),
        fellaga_version: env!("CARGO_PKG_VERSION"),
        binary_sha256: binary_sha256.clone(),
        fellaga_sha256: binary_sha256,
        fixture_sha256: fixture_sha256.clone(),
        wordlist_sha256: fixture_sha256.clone(),
        corpus_sha256: fixture_sha256,
        candidates: options.candidates,
        requested_candidates: options.candidates,
        loaded_candidates: loaded,
        persisted_candidates: persisted,
        scheduled_candidates: scheduled,
        dns_dispatched_candidates: dispatched,
        processed_candidates: processed,
        positive_candidates: positive,
        definitive_negative_candidates: negative,
        indeterminate_candidates: indeterminate,
        dns_queries,
        loopback_queries,
        batch_size: options.batch_size,
        peak_queued_candidates: peak_queued,
        concurrency: options.concurrency,
        dns_timeout_ms: options.timeout.as_millis(),
        remaining_queued_candidates: remaining_queued,
        database_candidates,
        database_dns_verifications: stats.dns_verifications.max(0) as usize,
        database_cache_entries: stats.cache_entries.max(0) as usize,
        fixture_bytes,
        sqlite_bytes: sqlite_size(&options.database),
        duration_ms: started.elapsed().as_millis(),
        phase_duration_ms: phases,
        loss_rate: indeterminate as f64 / options.candidates as f64,
    };
    write_json_atomic(&options.output, &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn candidate_pipeline_exercises_fixture_sqlite_scheduler_and_dns() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("candidate-pipeline.json");
        let result = run_candidate_pipeline(CandidatePipelineOptions {
            database: directory.path().join("candidate-pipeline.sqlite"),
            wordlist: directory.path().join("candidate-pipeline.txt"),
            output: output.clone(),
            candidates: 256,
            batch_size: 64,
            concurrency: 32,
            timeout: Duration::from_secs(1),
            campaign_id: "ci-candidate-pipeline".to_owned(),
        })
        .await
        .unwrap();

        assert_eq!(result.loaded_candidates, 256);
        assert_eq!(result.persisted_candidates, 256);
        assert_eq!(result.scheduled_candidates, 256);
        assert_eq!(result.dns_dispatched_candidates, 256);
        assert_eq!(result.processed_candidates, 256);
        assert_eq!(result.definitive_negative_candidates, 256);
        assert_eq!(result.indeterminate_candidates, 0);
        assert_eq!(result.dns_queries, 512);
        assert_eq!(result.loopback_queries, 512);
        assert_eq!(result.database_dns_verifications, 256);
        assert_eq!(result.database_cache_entries, 256);
        assert_eq!(result.remaining_queued_candidates, 0);
        assert_eq!(result.wordlist_sha256.len(), 64);
        assert_eq!(result.binary_sha256.len(), 64);
        assert_eq!(
            result.phase_duration_ms.loading_and_sqlite,
            result
                .phase_duration_ms
                .wordlist_refill
                .saturating_add(result.phase_duration_ms.candidate_pending_count)
                .saturating_add(result.phase_duration_ms.cache_journal)
                .saturating_add(result.phase_duration_ms.candidate_finalize)
        );
        assert_eq!(
            result.phase_duration_ms.scheduling,
            result.phase_duration_ms.candidate_claim
        );
        assert_eq!(
            result.phase_duration_ms.sqlite_total,
            result
                .phase_duration_ms
                .loading_and_sqlite
                .saturating_add(result.phase_duration_ms.scheduling)
        );
        assert!(output.is_file());

        let persisted: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(persisted["campaign_id"], "ci-candidate-pipeline");
        assert_eq!(persisted["processed_candidates"], 256);
        for phase in [
            "fixture_generation",
            "database_initialization",
            "loading_and_sqlite",
            "scheduling",
            "dns",
            "wordlist_refill",
            "candidate_pending_count",
            "candidate_claim",
            "cache_journal",
            "candidate_finalize",
            "sqlite_total",
        ] {
            assert!(
                persisted["phase_duration_ms"][phase].is_number(),
                "missing numeric phase duration: {phase}"
            );
        }
    }

    #[tokio::test]
    async fn failed_candidate_pipeline_never_publishes_the_final_json() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("candidate-pipeline.json");
        let result = run_candidate_pipeline(CandidatePipelineOptions {
            database: directory.path().join("candidate-pipeline.sqlite"),
            wordlist: directory.path().join("candidate-pipeline.txt"),
            output: output.clone(),
            candidates: 0,
            batch_size: 64,
            concurrency: 32,
            timeout: Duration::from_secs(1),
            campaign_id: "ci-candidate-pipeline".to_owned(),
        })
        .await;

        assert!(result.is_err());
        assert!(!output.exists());
        assert!(!partial_path(&output).unwrap().exists());
    }
}
