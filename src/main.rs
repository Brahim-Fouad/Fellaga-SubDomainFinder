use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use fellaga_core::benchmark::{CandidatePipelineOptions, run_candidate_pipeline};
use fellaga_core::candidate::{default_mutation_rules, load_mutation_rules};
use fellaga_core::db::Database;
use fellaga_core::dns::DnsEngine;
use fellaga_core::model::{AxfrStatus, Finding, ObservationState, ScanResult};
use fellaga_core::network_governor::NetworkControl;
use fellaga_core::passive::{
    ApiKeyStore, automatic_sources_for_profile, source_statuses, validate_sources,
};
use fellaga_core::scanner::{
    ProgressEvent, RefreshOptions, RefreshProgressCallback, ScanOptions, Scanner,
    refresh_inventory_bounded,
};
use fellaga_core::{passive, scanner, util};
use futures_util::{StreamExt, stream};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Read, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "fellaga",
    version,
    about = "Fast, adaptive Rust subdomain enumerator"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "SQLite database path (otherwise FELLAGA_DB or XDG_DATA_HOME)"
    )]
    db: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "API-key JSON configuration (otherwise FELLAGA_CONFIG or XDG_CONFIG_HOME)"
    )]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enumerate subdomains and attempt AXFR automatically.
    Scan(Box<ScanArgs>),
    /// List the permanent SQLite inventory.
    List(ListArgs),
    /// Revalidate known subdomains and refresh DNS state.
    Refresh(RefreshArgs),
    /// Show scan history.
    History(HistoryArgs),
    /// Show local learning and cache statistics.
    Stats,
    /// Maintain the SQLite cache.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Show the permanent local knowledge base.
    Knowledge(KnowledgeArgs),
    /// List passive sources and their automatic-activation status.
    Sources(SourcesArgs),
    /// Explain why a name is known and when it was last validated.
    Explain(ExplainArgs),
    /// Run controlled local performance benchmarks.
    Benchmark {
        #[command(subcommand)]
        action: BenchmarkAction,
    },
    /// Test DNS resolvers or benchmark the local DNS transport.
    Resolvers {
        #[command(subcommand)]
        action: ResolverAction,
    },
    /// Import names from other enumerators without marking them live.
    Import(ImportArgs),
    /// Export the permanent local inventory.
    Export(ExportArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum NetworkControlArg {
    Adaptive,
    Fixed,
}

impl From<NetworkControlArg> for NetworkControl {
    fn from(value: NetworkControlArg) -> Self {
        match value {
            NetworkControlArg::Adaptive => Self::Adaptive,
            NetworkControlArg::Fixed => Self::Fixed,
        }
    }
}

#[derive(Debug, Args)]
struct DnsArgs {
    #[arg(
        short = 'c',
        long,
        default_value_t = 128,
        help = "Maximum concurrent host-resolution tasks"
    )]
    concurrency: usize,
    #[arg(long, default_value_t = 2.0, help = "DNS query timeout in seconds")]
    timeout: f64,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "1.1.1.1,8.8.8.8,9.9.9.9",
        help = "DNS resolvers, for example 1.1.1.1,8.8.8.8"
    )]
    resolvers: Vec<IpAddr>,
    #[arg(
        long,
        default_value_t = 250,
        help = "Global DNS requests-per-second limit; 0 deliberately disables the safeguard"
    )]
    dns_rate_limit: u64,
    #[arg(
        long,
        value_enum,
        default_value_t = NetworkControlArg::Adaptive,
        help = "Network pressure control; adaptive treats rate and concurrency as ceilings"
    )]
    network_control: NetworkControlArg,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "1.1.1.1,8.8.8.8,9.9.9.9",
        help = "Independent resolvers used for final consensus validation"
    )]
    trusted_resolvers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum ScanProfile {
    Deep,
    Balanced,
    Passive,
    Turbo,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum MetadataDiscoveryArg {
    Auto,
    Off,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamJsonlMode {
    Disabled,
    Realtime,
    FinalOnly,
}

const fn stream_jsonl_mode(enabled: bool, only_live: bool) -> StreamJsonlMode {
    match (enabled, only_live) {
        (false, _) => StreamJsonlMode::Disabled,
        (true, false) => StreamJsonlMode::Realtime,
        (true, true) => StreamJsonlMode::FinalOnly,
    }
}

fn metadata_discovery_enabled(
    mode: MetadataDiscoveryArg,
    passive_profile: bool,
    web_disabled: bool,
) -> bool {
    mode != MetadataDiscoveryArg::Off && !passive_profile && !web_disabled
}

const fn is_strict_live(state: ObservationState, wildcard: bool) -> bool {
    matches!(state, ObservationState::Live) && !wildcard
}

const MAX_DOMAIN_CONCURRENCY: usize = 4;
const MAX_WEB_CONCURRENCY: usize = 16;
const MAX_TLS_CONCURRENCY: usize = 32;
const MAX_SOURCE_CHECK_CONCURRENCY: usize = 32;

fn validate_scan_concurrency(domain: usize, web: usize, tls: usize) -> Result<()> {
    if !(1..=MAX_DOMAIN_CONCURRENCY).contains(&domain) {
        bail!("--domain-concurrency doit être compris entre 1 et {MAX_DOMAIN_CONCURRENCY}");
    }
    if !(1..=MAX_WEB_CONCURRENCY).contains(&web) {
        bail!("--web-concurrency doit être compris entre 1 et {MAX_WEB_CONCURRENCY}");
    }
    if !(1..=MAX_TLS_CONCURRENCY).contains(&tls) {
        bail!("--tls-concurrency doit être compris entre 1 et {MAX_TLS_CONCURRENCY}");
    }
    Ok(())
}

fn validate_source_check_concurrency(value: usize) -> Result<()> {
    if !(1..=MAX_SOURCE_CHECK_CONCURRENCY).contains(&value) {
        bail!("--concurrency doit être compris entre 1 et {MAX_SOURCE_CHECK_CONCURRENCY}");
    }
    Ok(())
}

fn source_check_error_status(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if message.contains("budget total de") && message.contains("dépassé") {
        "deferred_budget"
    } else if [
        "http 500", "http 502", "http 503", "http 504", "http 520", "http 521", "http 522",
        "http 523", "http 524",
    ]
    .iter()
    .any(|status| message.contains(status))
    {
        "upstream_error"
    } else if message.contains("http 429")
        || message.contains("retry-after")
        || message.contains("rate limit")
        || message.contains("rate-limit")
        || message.contains("quota")
        || message.contains("limite l'accès anonyme")
    {
        "rate_limited"
    } else if message.contains("cloudflare")
        || message.contains("captcha")
        || message.contains("challenge")
        || message.contains("just a moment")
        || message.contains("réponse html inattendue")
    {
        "anti_bot"
    } else if message.contains("http 401")
        || message.contains("unauthorized")
        || message.contains("authentication")
        || message.contains("invalid api key")
        || message.contains("missing api key")
        || message.contains("http 403")
    {
        "auth_required"
    } else if message.contains("tls")
        || message.contains("certificate verify")
        || message.contains("certificate validation")
        || message.contains("unknown issuer")
    {
        "tls_error"
    } else if message.contains("connection refused")
        || message.contains("connexion refusée")
        || message.contains("error sending request")
        || message.contains("dns error")
        || message.contains("connect error")
    {
        "transport_error"
    } else if message.contains("json invalide")
        || (message.contains("json ") && message.contains(" invalide"))
        || message.contains("schéma json")
        || message.contains("schema json")
        || message.contains("schéma incompatible")
        || message.contains("schema incompatible")
        || message.contains("format ndjson incohérent")
    {
        "schema_error"
    } else if message.contains("timeout") || message.contains("timed out") {
        "timeout"
    } else {
        "error"
    }
}

fn source_check_result_status(names: usize, warning: Option<&str>) -> &'static str {
    match warning {
        Some(warning) if names == 0 => source_check_error_status(warning),
        Some(_) => "degraded",
        None if names == 0 => "empty",
        None => "success",
    }
}

#[derive(Debug, Clone, Copy)]
struct ProfileDefaults {
    max_runtime: u64,
    max_words: usize,
    active_max_runtime: u64,
    max_passive: usize,
    depth: usize,
    recursive_words: usize,
    recursive_hosts: usize,
    pipeline_rounds: usize,
    pipeline_budget: usize,
    tls_hosts: usize,
    graph_hosts: usize,
    ptr_ips: usize,
    nsec_max_names: usize,
    nsec_max_runtime: u64,
    ct_logs: usize,
    ct_entries: usize,
    ct_backfill: usize,
    ct_max_runtime: u64,
    web_hosts: usize,
    web_max_runtime: u64,
    web_assets: usize,
    passive_max_runtime: u64,
    passive_zone_concurrency: usize,
}

impl ScanProfile {
    const fn defaults(self) -> ProfileDefaults {
        match self {
            Self::Deep => ProfileDefaults {
                max_runtime: 600,
                max_words: 1_000_000,
                active_max_runtime: 120,
                max_passive: 25_000,
                depth: 5,
                recursive_words: 1_000,
                recursive_hosts: 1_000,
                pipeline_rounds: 10,
                pipeline_budget: 100_000,
                tls_hosts: 250,
                graph_hosts: 1_000,
                ptr_ips: 512,
                nsec_max_names: 10_000,
                nsec_max_runtime: 180,
                ct_logs: 8,
                ct_entries: 4_096,
                ct_backfill: 4_096,
                ct_max_runtime: 30,
                web_hosts: 100,
                web_max_runtime: 90,
                web_assets: 8,
                passive_max_runtime: 45,
                passive_zone_concurrency: 4,
            },
            Self::Balanced => ProfileDefaults {
                max_runtime: 300,
                max_words: 5_000,
                active_max_runtime: 45,
                max_passive: 10_000,
                depth: 3,
                recursive_words: 100,
                recursive_hosts: 50,
                pipeline_rounds: 2,
                pipeline_budget: 5_000,
                tls_hosts: 100,
                graph_hosts: 250,
                ptr_ips: 64,
                nsec_max_names: 10_000,
                nsec_max_runtime: 90,
                ct_logs: 2,
                ct_entries: 256,
                ct_backfill: 256,
                ct_max_runtime: 10,
                web_hosts: 30,
                web_max_runtime: 45,
                web_assets: 5,
                passive_max_runtime: 25,
                passive_zone_concurrency: 4,
            },
            Self::Passive => ProfileDefaults {
                max_runtime: 180,
                max_words: 0,
                active_max_runtime: 0,
                max_passive: 250_000,
                depth: 1,
                recursive_words: 1,
                recursive_hosts: 1,
                pipeline_rounds: 1,
                pipeline_budget: 250_000,
                tls_hosts: 1,
                graph_hosts: 1,
                ptr_ips: 1,
                nsec_max_names: 1,
                nsec_max_runtime: 1,
                ct_logs: 8,
                ct_entries: 4_096,
                ct_backfill: 4_096,
                ct_max_runtime: 30,
                web_hosts: 1,
                web_max_runtime: 0,
                web_assets: 1,
                passive_max_runtime: 60,
                passive_zone_concurrency: 6,
            },
            Self::Turbo => ProfileDefaults {
                max_runtime: 300,
                max_words: 1_000_000,
                active_max_runtime: 60,
                max_passive: 50_000,
                depth: 3,
                recursive_words: 1_000,
                recursive_hosts: 1_000,
                pipeline_rounds: 4,
                pipeline_budget: 250_000,
                tls_hosts: 100,
                graph_hosts: 500,
                ptr_ips: 128,
                nsec_max_names: 10_000,
                nsec_max_runtime: 60,
                ct_logs: 2,
                ct_entries: 512,
                ct_backfill: 512,
                ct_max_runtime: 5,
                web_hosts: 50,
                web_max_runtime: 45,
                web_assets: 5,
                passive_max_runtime: 15,
                passive_zone_concurrency: 8,
            },
        }
    }
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(value_name = "TARGET", help = "Authorized target domain")]
    targets: Vec<String>,
    #[arg(short = 'l', long, help = "Target file with one domain per line")]
    targets_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ScanProfile::Deep, help = "Scan coverage profile")]
    profile: ScanProfile,
    #[arg(
        long,
        default_value_t = 1,
        help = "Target domains processed in parallel (1-4)"
    )]
    domain_concurrency: usize,
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(short = 'w', long, help = "Additional candidate wordlist")]
    wordlist: Option<PathBuf>,
    #[arg(
        long,
        help = "Mutation DSL: score:name:pattern; variables word,parent,env,region,cloud,n"
    )]
    mutations: Option<PathBuf>,
    #[arg(
        long,
        help = "Maximum brute-force candidates from configured generators"
    )]
    max_words: Option<usize>,
    #[arg(
        long,
        help = "Cumulative runtime budget for adaptive generated candidates in seconds; 0 disables it"
    )]
    active_max_runtime: Option<u64>,
    #[arg(long, help = "Disable passive-provider discovery")]
    no_passive: bool,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated passive-source allowlist; empty selects automatically"
    )]
    passive_sources: Vec<String>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated passive sources to exclude"
    )]
    exclude_sources: Vec<String>,
    #[arg(
        long,
        help = "Select every connector; key-gated sources without credentials are skipped"
    )]
    all_sources: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Passive-source refresh interval in hours"
    )]
    passive_refresh_hours: u64,
    #[arg(
        long,
        help = "Cumulative passive-source budget per target in seconds; 0 disables the safeguard"
    )]
    passive_max_runtime: Option<u64>,
    #[arg(
        long,
        help = "Child zones queried concurrently during recursive passive discovery"
    )]
    passive_zone_concurrency: Option<usize>,
    #[arg(
        long,
        default_value_t = 8,
        help = "Global passive connector concurrency shared by root and child zones"
    )]
    passive_concurrency: usize,
    #[arg(long, help = "Maximum passive names accepted per target")]
    max_passive: Option<usize>,
    #[arg(
        long,
        help = "Skip brute-force generation; active enrichment may still run"
    )]
    passive_only: bool,
    #[arg(long, help = "Disable automatic AXFR attempts")]
    no_axfr: bool,
    #[arg(
        long,
        default_value_t = 4.0,
        help = "AXFR timeout per nameserver in seconds"
    )]
    axfr_timeout: f64,
    #[arg(long, help = "Bypass cached answers even when they are fresh")]
    refresh_cache: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Maximum cached-validation age in hours for a finding to remain live"
    )]
    verification_max_age: u64,
    #[arg(long, help = "Output only names whose final DNS state is live")]
    only_live: bool,
    #[arg(
        long,
        default_value_t = 86_400,
        help = "Compatibility option; positive answers are retained permanently"
    )]
    ttl_cap: u32,
    #[arg(
        long,
        default_value_t = 300,
        help = "Requested negative-cache lifetime in seconds"
    )]
    negative_ttl: u32,
    #[arg(long, help = "Include weak candidates that match a wildcard profile")]
    include_wildcard: bool,
    #[arg(
        long,
        default_value_t = 6,
        help = "Wildcard-profile refresh interval in hours; expired entries trigger SOA and new probes"
    )]
    wildcard_refresh_hours: u64,
    #[arg(long, help = "Maximum active DNS depth from 1 to 5")]
    depth: Option<usize>,
    #[arg(long, help = "Candidate words considered below validated parents")]
    recursive_words: Option<usize>,
    #[arg(
        long,
        help = "Validated parent hosts considered for recursive discovery"
    )]
    recursive_hosts: Option<usize>,
    #[arg(long, help = "Disable adaptive candidate waves and low-yield stopping")]
    no_adaptive: bool,
    #[arg(long, help = "Disable event-driven enrichment rounds")]
    no_pipeline: bool,
    #[arg(long, help = "Maximum event-pipeline rounds")]
    pipeline_rounds: Option<usize>,
    #[arg(long, help = "Global budget for new pipeline events")]
    pipeline_budget: Option<usize>,
    #[arg(
        long,
        help = "Disable hostname extraction from presented TLS certificates"
    )]
    no_tls: bool,
    #[arg(
        long,
        default_value_t = 443,
        help = "Default port used for TLS inspection"
    )]
    tls_port: u16,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "TLS timeout per endpoint in seconds"
    )]
    tls_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "TLS refresh interval in hours; old certificate names remain retained"
    )]
    tls_refresh_hours: u64,
    #[arg(long, help = "Maximum TLS endpoints inspected")]
    tls_hosts: Option<usize>,
    #[arg(long, default_value_t = 16, help = "Concurrent TLS handshakes (1-32)")]
    tls_concurrency: usize,
    #[arg(long, help = "Disable the MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB DNS graph")]
    no_dns_graph: bool,
    #[arg(long, help = "Maximum confirmed hosts enriched through the DNS graph")]
    graph_hosts: Option<usize>,
    #[arg(long, help = "Disable SRV service-discovery queries")]
    no_service_discovery: bool,
    #[arg(long, help = "Disable PTR pivots for already confirmed IP addresses")]
    no_ptr: bool,
    #[arg(long, help = "Maximum confirmed IP addresses queried with PTR")]
    ptr_ips: Option<usize>,
    #[arg(long, help = "Disable DNSSEC NSEC detection and bounded walking")]
    no_nsec: bool,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "Timeout per NSEC query in seconds"
    )]
    nsec_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "NSEC cache refresh interval in hours"
    )]
    nsec_refresh_hours: u64,
    #[arg(long, help = "Maximum NSEC names accepted per zone")]
    nsec_max_names: Option<usize>,
    #[arg(
        long,
        help = "Cumulative NSEC budget per target in seconds; 0 disables the safeguard"
    )]
    nsec_max_runtime: Option<u64>,
    #[arg(
        long,
        help = "Disable direct incremental Certificate Transparency monitoring"
    )]
    no_ct_monitor: bool,
    #[arg(long, default_value_t = 8.0, help = "CT API timeout in seconds")]
    ct_timeout: f64,
    #[arg(
        long,
        help = "Certificate Transparency phase budget per target in seconds; 0 disables the safeguard"
    )]
    ct_max_runtime: Option<u64>,
    #[arg(long, help = "Maximum CT logs inspected per scan")]
    ct_logs: Option<usize>,
    #[arg(long, help = "New entries read per CT log")]
    ct_entries: Option<usize>,
    #[arg(long, help = "Historical CT entries read on the first pass")]
    ct_backfill: Option<usize>,
    #[arg(
        long,
        value_enum,
        default_value_t = MetadataDiscoveryArg::Auto,
        help = "Standardized .well-known discovery: auto, off, or all validated Web hosts"
    )]
    metadata_discovery: MetadataDiscoveryArg,
    #[arg(
        long,
        help = "Disable HTTP, HTML, JavaScript, and source-map extraction"
    )]
    no_web: bool,
    #[arg(long, help = "Maximum Web hosts inspected")]
    web_hosts: Option<usize>,
    #[arg(
        long,
        default_value_t = 5.0,
        help = "HTTP timeout per request in seconds"
    )]
    web_timeout: f64,
    #[arg(
        long,
        help = "Cumulative Web and JavaScript budget per target in seconds; 0 disables the safeguard"
    )]
    web_max_runtime: Option<u64>,
    #[arg(
        long,
        default_value_t = 24,
        help = "Web cache refresh interval in hours"
    )]
    web_refresh_hours: u64,
    #[arg(
        long,
        default_value_t = 8,
        help = "Web hosts inspected concurrently (1-16)"
    )]
    web_concurrency: usize,
    #[arg(
        long,
        default_value_t = 262_144,
        help = "Maximum bytes read from each Web resource"
    )]
    web_max_bytes: usize,
    #[arg(
        long,
        help = "Maximum JS, JSON, or source-map assets followed per host"
    )]
    web_assets: Option<usize>,
    #[arg(
        long,
        help = "Maximum runtime per domain in seconds; profile default, 0 deliberately disables the limit"
    )]
    max_runtime: Option<u64>,
    #[arg(
        long,
        default_value_t = 30,
        help = "Persistent checkpoint interval in seconds"
    )]
    checkpoint_every: u64,
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "latest",
        help = "Resume a scan; without a value, use the latest checkpoint"
    )]
    resume: Option<String>,
    #[arg(long, help = "Disable final trusted-resolver consensus")]
    no_trusted_validation: bool,
    #[arg(long, help = "Write one final pretty JSON document")]
    json: bool,
    #[arg(long, help = "Write one compact final JSON object per domain")]
    jsonl: bool,
    #[arg(
        long,
        help = "Stream each finding as JSONL; --only-live defers until final classification"
    )]
    stream_jsonl: bool,
    #[arg(short = 'o', long, help = "Write final scan results to a file")]
    output: Option<PathBuf>,
    #[arg(long, help = "Write one final result file per domain")]
    output_dir: Option<PathBuf>,
    #[arg(
        short,
        long,
        visible_alias = "silent",
        help = "Suppress human progress and summary output"
    )]
    quiet: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    #[arg(long, help = "Restrict inventory to one domain")]
    domain: Option<String>,
    #[arg(
        long,
        hide = true,
        help = "Compatibility option; every state is already included"
    )]
    all: bool,
    #[arg(long, help = "Restrict inventory to live validations")]
    only_live: bool,
    #[arg(long, help = "Write pretty JSON")]
    json: bool,
}

#[derive(Debug, Args)]
struct RefreshArgs {
    #[arg(help = "Authorized target domain")]
    target: String,
    #[command(flatten)]
    dns: DnsArgs,
    #[arg(
        long,
        default_value_t = 86_400,
        help = "Compatibility option; positive answers are retained permanently"
    )]
    ttl_cap: u32,
    #[arg(
        long,
        default_value_t = 300,
        help = "Requested negative-cache lifetime in seconds"
    )]
    negative_ttl: u32,
    #[arg(
        long,
        default_value_t = 300,
        help = "Global refresh limit in seconds; 0 disables the safeguard"
    )]
    max_runtime: u64,
    #[arg(
        long,
        default_value_t = 256,
        help = "Inventory names resolved and persisted per batch (1-4096)"
    )]
    batch_size: usize,
    #[arg(
        short,
        long,
        visible_alias = "silent",
        help = "Suppress refresh progress on stderr"
    )]
    quiet: bool,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    #[arg(long, default_value_t = 20, help = "Maximum scan records to display")]
    limit: usize,
}

#[derive(Debug, Subcommand)]
enum CacheAction {
    /// Remove expired negatives and abandoned temporary candidate queues.
    Prune,
}

#[derive(Debug, Args)]
struct KnowledgeArgs {
    #[arg(
        long,
        default_value_t = 100,
        help = "Maximum learned entries to display"
    )]
    limit: usize,
}

#[derive(Debug, Args)]
struct SourcesArgs {
    #[arg(long, help = "Write pretty JSON")]
    json: bool,
    #[arg(long, help = "Perform live connector contract and reachability checks")]
    check: bool,
    #[arg(
        long,
        default_value = "your-domain.example",
        help = "Authorized domain used by --check"
    )]
    target: String,
    #[arg(
        long,
        default_value_t = 20.0,
        help = "Timeout per connector in seconds"
    )]
    timeout: f64,
    #[arg(
        long,
        default_value_t = 8,
        help = "Connectors checked concurrently (1-32)"
    )]
    concurrency: usize,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    #[arg(help = "Fully qualified domain name to explain")]
    fqdn: String,
    #[arg(long, help = "Write pretty JSON")]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum BenchmarkAction {
    /// Exercise candidate generation, SQLite, scheduling, and loopback DNS.
    CandidatePipeline(CandidatePipelineBenchmarkArgs),
}

#[derive(Debug, Args)]
struct CandidatePipelineBenchmarkArgs {
    #[arg(
        long,
        help = "Fresh path where Rust generates the deterministic candidate fixture"
    )]
    wordlist: PathBuf,
    #[arg(
        long,
        default_value_t = 10_000_000,
        help = "Number of unique candidates to generate and process (1-10000000)"
    )]
    candidates: usize,
    #[arg(
        long,
        default_value_t = 4_096,
        help = "Maximum candidates persisted and scheduled per wave (1-50000)"
    )]
    batch_size: usize,
    #[arg(
        long,
        default_value_t = 128,
        help = "Concurrent candidate DNS classifications (1-60000)"
    )]
    concurrency: usize,
    #[arg(
        long,
        default_value_t = 2.0,
        help = "Per-query loopback DNS timeout in seconds (maximum 60)"
    )]
    timeout: f64,
    #[arg(long, help = "Fresh campaign identifier recorded in the result")]
    campaign_id: String,
    #[arg(long, help = "Fresh path for the atomically published JSON result")]
    output: PathBuf,
}

#[derive(Debug, Subcommand)]
enum ResolverAction {
    /// Test resolver correctness and consistency.
    Test(ResolverTestArgs),
    /// Benchmark the native DNS transport against a controlled loopback server.
    Benchmark(ResolverBenchmarkArgs),
}

#[derive(Debug, Args)]
struct ResolverTestArgs {
    #[arg(
        value_delimiter = ',',
        help = "Comma-separated resolver IP addresses to test"
    )]
    resolvers: Vec<IpAddr>,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "Timeout per resolver test in seconds"
    )]
    timeout: f64,
    #[arg(long, help = "Write pretty JSON")]
    json: bool,
}

#[derive(Debug, Args)]
struct ResolverBenchmarkArgs {
    #[arg(
        long,
        default_value_t = 100_000,
        help = "Number of loopback DNS queries"
    )]
    queries: usize,
    #[arg(
        long,
        default_value_t = 2_000,
        help = "Concurrent loopback DNS queries"
    )]
    concurrency: usize,
    #[arg(long, default_value_t = 2.0, help = "Benchmark timeout in seconds")]
    timeout: f64,
    #[arg(long, help = "Write pretty JSON")]
    json: bool,
    #[arg(short = 'o', long, help = "Write the benchmark report to a file")]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImportFormat {
    Auto,
    Subfinder,
    Amass,
    Bbot,
    Massdns,
}

#[derive(Debug, Args)]
struct ImportArgs {
    #[arg(help = "Domain that owns the imported names")]
    domain: String,
    #[arg(help = "Input file, or - for standard input")]
    input: PathBuf,
    #[arg(long, value_enum, default_value_t = ImportFormat::Auto, help = "Input format")]
    format: ImportFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Args)]
struct ExportArgs {
    #[arg(long, help = "Restrict export to one domain")]
    domain: Option<String>,
    #[arg(long, help = "Export only live validations")]
    only_live: bool,
    #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl, help = "Export format")]
    format: ExportFormat,
    #[arg(
        short = 'o',
        long,
        help = "Write output to a file instead of standard output"
    )]
    output: Option<PathBuf>,
}

fn compact_error(error: &str, limit: usize) -> String {
    let compact = error.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut shortened = compact.chars().take(limit).collect::<String>();
    if compact.chars().count() > limit {
        shortened.push('…');
    }
    shortened
}

fn wait_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}")
    } else {
        format!("{minutes}m")
    }
}

fn positive_duration_seconds(value: f64, option: &str) -> Result<Duration> {
    if value <= 0.0 || !value.is_finite() {
        bail!("{option} doit être un nombre positif");
    }
    // Floating-point durations are per-operation network timeouts, not global
    // scan budgets. A one-day ceiling prevents accidental multi-year hangs
    // while remaining far above every practical DNS/HTTP/TLS timeout.
    if value > 86_400.0 {
        bail!("{option} ne peut pas dépasser 86400 secondes");
    }
    let duration = Duration::try_from_secs_f64(value)
        .map_err(|_| anyhow::anyhow!("{option} dépasse la durée maximale prise en charge"))?;
    if duration.is_zero() {
        bail!("{option} est trop petit pour être représenté");
    }
    if std::time::Instant::now().checked_add(duration).is_none()
        || tokio::time::Instant::now().checked_add(duration).is_none()
    {
        bail!("{option} dépasse la durée maximale prise en charge");
    }
    Ok(duration)
}

fn bounded_duration_seconds(value: u64, option: &str) -> Result<Duration> {
    let duration = Duration::from_secs(value);
    if value > 0
        && (std::time::Instant::now().checked_add(duration).is_none()
            || tokio::time::Instant::now().checked_add(duration).is_none())
    {
        bail!("{option} dépasse la durée maximale prise en charge");
    }
    Ok(duration)
}

fn bounded_duration_hours(value: u64, option: &str) -> Result<Duration> {
    let seconds = value
        .checked_mul(3_600)
        .ok_or_else(|| anyhow::anyhow!("{option} dépasse la durée maximale prise en charge"))?;
    bounded_duration_seconds(seconds, option)
}

fn default_database_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FELLAGA_DB") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("fellaga/fellaga.db");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/fellaga/fellaga.db")
}

fn collect_targets(args: &ScanArgs) -> Result<Vec<String>> {
    let mut raw = args.targets.clone();
    if let Some(path) = &args.targets_file {
        if !path.is_file() {
            bail!("fichier de cibles introuvable: {}", path.display());
        }
        raw.extend(
            std::fs::read_to_string(path)?
                .lines()
                .map(ToOwned::to_owned),
        );
    }
    let read_stdin = raw.iter().any(|target| target.trim() == "-")
        || (raw.is_empty() && !std::io::stdin().is_terminal());
    raw.retain(|target| target.trim() != "-");
    if read_stdin {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        raw.extend(input.lines().map(ToOwned::to_owned));
    }
    let mut targets = BTreeSet::new();
    for line in raw {
        let value = line.split('#').next().unwrap_or_default();
        for target in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            targets.insert(util::normalize_domain(target)?);
        }
    }
    if targets.is_empty() {
        bail!("aucune cible: fournissez TARGET, --targets-file ou des domaines sur stdin");
    }
    Ok(targets.into_iter().collect())
}

fn make_dns(args: &DnsArgs) -> Result<DnsEngine> {
    let timeout = positive_duration_seconds(args.timeout, "--timeout")?;
    if !(1..=4_096).contains(&args.concurrency) {
        bail!("--concurrency doit être compris entre 1 et 4096");
    }
    if args.dns_rate_limit > 100_000 {
        bail!("--dns-rate-limit ne peut pas dépasser 100000 requêtes/s");
    }
    DnsEngine::new_with_rate_and_control(
        args.concurrency,
        timeout,
        &args.resolvers,
        args.dns_rate_limit,
        args.network_control.into(),
    )
}

fn finding_line(finding: &Finding) -> String {
    let records = finding
        .records
        .iter()
        .map(|record| format!("{}={}", record.record_type, record.value))
        .collect::<Vec<_>>()
        .join(" ");
    let sources = finding
        .sources
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    let cache = if finding.from_cache { " cache" } else { "" };
    let wildcard = if finding.wildcard { " wildcard" } else { "" };
    format!(
        "[+] {:<45} {:<42} [{} {} | {}] ({sources}{cache}{wildcard})",
        finding.fqdn, records, finding.confidence.label, finding.confidence.score, finding.state
    )
}

fn stream_finding_line(finding: &Finding) -> String {
    serde_json::json!({"type": "finding", "finding": finding}).to_string()
}

struct ConsoleProgress {
    interactive: bool,
    json_output: bool,
    line_active: bool,
    last_log_bucket: Option<(String, usize)>,
}

impl ConsoleProgress {
    fn new(json_output: bool) -> Self {
        Self {
            interactive: std::io::stderr().is_terminal(),
            json_output,
            line_active: false,
            last_log_bucket: None,
        }
    }

    fn clear_progress_line(&mut self) {
        if self.interactive && self.line_active {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
        self.line_active = false;
    }

    fn write_streamed(&mut self, line: &str) {
        self.clear_progress_line();
        if self.json_output {
            eprintln!("{line}");
        } else {
            println!("{line}");
            let _ = std::io::stdout().flush();
        }
    }

    fn handle(&mut self, event: ProgressEvent) {
        match event {
            ProgressEvent::Started { scan_id, domain } => {
                self.clear_progress_line();
                eprintln!("[>] Scan #{scan_id} démarré pour {domain}");
            }
            ProgressEvent::Phase { name, detail } => {
                self.clear_progress_line();
                self.last_log_bucket = None;
                eprintln!("[>] {name}: {detail}");
            }
            ProgressEvent::PassiveSource {
                source,
                status,
                names,
            } => {
                self.clear_progress_line();
                eprintln!("[P] {source}: {names} nom(s) ({status})");
            }
            ProgressEvent::AxfrAttempt(attempt) => {
                let line = if attempt.status == AxfrStatus::Success {
                    format!(
                        "[AXFR] SUCCÈS {} ({}) : {} enregistrements, {} noms",
                        attempt.nameserver,
                        attempt.address,
                        attempt.records.len(),
                        attempt.names.len()
                    )
                } else {
                    format!(
                        "[AXFR] refus/échec {} ({}) : {}",
                        attempt.nameserver,
                        attempt.address,
                        attempt.error.as_deref().unwrap_or("réponse vide")
                    )
                };
                self.write_streamed(&line);
            }
            ProgressEvent::TlsCertificates {
                endpoints,
                network,
                successes,
                failures,
                cache_hits,
                names,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[TLS] {endpoints} endpoint(s), {network} réseau, {successes} succès, {failures} échec(s), {cache_hits} cache, {names} nom(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::DnsGraph {
                queries,
                edges,
                names,
                child_zones,
                services,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[DNS+] {queries} requête(s), {edges} relation(s), {names} nom(s), {child_zones} zone(s) enfant, {services} service(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::WebDiscovery {
                hosts,
                requests,
                cache_hits,
                failures,
                names,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[WEB] {hosts} hôte(s), {requests} requête(s), {cache_hits} cache, {failures} échec(s), {names} nom(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::Dnssec {
                zones,
                walked,
                protected,
                queries,
                names,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[NSEC] {zones} zone(s), {walked} parcourue(s), {protected} protégée(s), {queries} requête(s), {names} nom(s)"
                );
            }
            ProgressEvent::CtMonitor {
                logs,
                entries,
                failures,
                names,
                duration_ms,
            } => {
                self.clear_progress_line();
                eprintln!(
                    "[CT] {logs} journal(aux), {entries} entrée(s), {failures} échec(s), {names} nom(s) cumulé(s), {:.1}s",
                    duration_ms as f64 / 1_000.0
                );
            }
            ProgressEvent::DnsProgress {
                phase,
                processed,
                total,
                found,
                cache_hits,
                rate,
                elapsed_ms,
            } => {
                let percent = processed
                    .saturating_mul(100)
                    .checked_div(total)
                    .unwrap_or(100);
                if !self.interactive {
                    let bucket = percent / 10;
                    let already_logged = self.last_log_bucket.as_ref().is_some_and(
                        |(previous_phase, previous_bucket)| {
                            previous_phase == &phase && *previous_bucket == bucket
                        },
                    );
                    if already_logged && processed != total {
                        return;
                    }
                    self.last_log_bucket = Some((phase.clone(), bucket));
                }
                let filled = percent.min(100) * 20 / 100;
                let bar = format!("{}{}", "█".repeat(filled), "░".repeat(20 - filled));
                let line = format!(
                    "[~] {phase:<14} [{bar}] {percent:>3}% {processed}/{total} | +{found} | cache {cache_hits} | {rate:.0}/s | {:.1}s",
                    elapsed_ms as f64 / 1_000.0
                );
                if self.interactive {
                    eprint!("\r\x1b[2K{line}");
                    let _ = std::io::stderr().flush();
                    self.line_active = true;
                } else {
                    eprintln!("{line}");
                }
            }
            ProgressEvent::Finding(finding) => self.write_streamed(&finding_line(&finding)),
            ProgressEvent::Warning(warning) => {
                self.clear_progress_line();
                eprintln!("[!] {warning}");
            }
            ProgressEvent::Complete => self.clear_progress_line(),
        }
    }
}

fn print_scan_summary(result: &ScanResult) {
    println!(
        "\nScan #{} [{}]: {} trouvés / {} candidats, {} cache hits, {} ms",
        result.scan_id,
        result.status,
        result.findings.len(),
        result.candidates,
        result.cache_hits,
        result.duration_ms
    );
    if result.resumable {
        println!("[PAUSE] Travail actif restant conservé; reprenez avec --resume latest.");
    }
    if !result.phase_timings.is_empty() {
        let timings = result
            .phase_timings
            .iter()
            .map(|timing| {
                format!(
                    "{} {:.1}s",
                    timing.phase.replace('_', " "),
                    timing.duration_ms as f64 / 1_000.0
                )
            })
            .collect::<Vec<_>>()
            .join(" | ");
        println!("[TIME] {timings}");
    }
    if result.wildcard_detected {
        println!("[!] DNS wildcard détecté; faux positifs filtrés.");
    }
    if !result.tls_certificates.is_empty() {
        let names = result
            .tls_certificates
            .iter()
            .flat_map(|certificate| certificate.names.iter())
            .collect::<BTreeSet<_>>()
            .len();
        println!(
            "[TLS] {} certificat(s) observé(s), {} nom(s) SAN/CN en périmètre.",
            result.tls_certificates.len(),
            names
        );
    }
    if !result.dns_edges.is_empty() {
        println!(
            "[DNS+] {} relation(s), {} zone(s) enfant, {} endpoint(s) de service.",
            result.dns_edges.len(),
            result.child_zones.len(),
            result.service_endpoints.len()
        );
    }
    if !result.web_observations.is_empty() {
        let names = result
            .web_observations
            .iter()
            .flat_map(|observation| observation.names.iter())
            .collect::<BTreeSet<_>>()
            .len();
        println!(
            "[WEB] {} ressource(s) observée(s), {} nom(s) en périmètre.",
            result.web_observations.len(),
            names
        );
    }
    if !result.dnssec_walks.is_empty() {
        let names = result
            .dnssec_walks
            .iter()
            .flat_map(|walk| walk.names.iter())
            .collect::<BTreeSet<_>>()
            .len();
        println!(
            "[NSEC] {} zone(s) examinée(s), {} nom(s) conservé(s).",
            result.dnssec_walks.len(),
            names
        );
    }
    if result.ct_monitor.logs_checked > 0 || !result.ct_monitor.names.is_empty() {
        println!(
            "[CT] {} entrée(s) analysée(s), {} nom(s) indexé(s) globalement, {} nom(s) cumulé(s).",
            result.ct_monitor.entries_processed,
            result.ct_monitor.globally_indexed_names,
            result.ct_monitor.names.len()
        );
    }
    if result.pipeline.rounds > 0 || result.pipeline.events_enqueued > 0 {
        println!(
            "[PIPE] {} tour(s), {} événement(s), {} doublon(s) évité(s), {} nom(s) validé(s).",
            result.pipeline.rounds,
            result.pipeline.events_enqueued,
            result.pipeline.duplicates_suppressed,
            result.pipeline.names_validated
        );
    }
    if !result.resolver_metrics.is_empty() {
        let requests = result
            .resolver_metrics
            .iter()
            .map(|metric| metric.requests)
            .sum::<u64>();
        println!(
            "[DNS] {} résolveur(s) profilé(s), {} requête(s) mesurée(s).",
            result.resolver_metrics.len(),
            requests
        );
    }
    if let Some(reason) = result.scheduler_metrics.stop_reason {
        println!(
            "[SCHED] arrêt={}, {} découverte(s) exclusive(s), {} repli(s) réseau, rendement restant ≤ {:.3}/1000.",
            reason.as_str(),
            result.scheduler_metrics.exclusive_discoveries,
            result.scheduler_metrics.backoffs,
            result.scheduler_metrics.remaining_yield_upper_bound * 1_000.0,
        );
    }
}

fn write_scan(path: &PathBuf, result: &ScanResult, json_output: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if json_output
        || path
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        std::fs::write(path, serde_json::to_string_pretty(result)? + "\n")?;
    } else {
        let text = result
            .findings
            .iter()
            .map(|finding| finding.fqdn.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            path,
            text + if result.findings.is_empty() { "" } else { "\n" },
        )?;
    }
    Ok(())
}

fn write_scan_results(
    path: &PathBuf,
    results: &[ScanResult],
    json_output: bool,
    jsonl: bool,
) -> Result<()> {
    if results.len() == 1 && !jsonl {
        return write_scan(path, &results[0], json_output);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = if jsonl {
        results
            .iter()
            .map(serde_json::to_string)
            .collect::<serde_json::Result<Vec<_>>>()?
            .join("\n")
    } else if json_output
        || path
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        serde_json::to_string_pretty(results)?
    } else {
        results
            .iter()
            .flat_map(|result| result.findings.iter().map(|finding| finding.fqdn.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n")
    };
    let newline = if text.is_empty() { "" } else { "\n" };
    std::fs::write(path, text + newline)?;
    Ok(())
}

fn collect_names_from_json(value: &serde_json::Value, names: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                collect_names_from_json(value, names);
            }
        }
        serde_json::Value::Object(object) => {
            for key in ["name", "host", "fqdn", "hostname"] {
                if let Some(value) = object.get(key).and_then(serde_json::Value::as_str) {
                    names.push(value.to_owned());
                }
            }
            if let Some(data) = object.get("data") {
                match data {
                    serde_json::Value::String(value) => names.push(value.clone()),
                    _ => collect_names_from_json(data, names),
                }
            }
            for key in ["results", "hosts", "subdomains", "names", "events"] {
                if let Some(value) = object.get(key) {
                    collect_names_from_json(value, names);
                }
            }
        }
        serde_json::Value::String(value) => names.push(value.clone()),
        _ => {}
    }
}

fn parse_import_names(content: &str, format: ImportFormat, domain: &str) -> BTreeSet<String> {
    let mut raw_names = Vec::new();
    if matches!(
        format,
        ImportFormat::Amass | ImportFormat::Bbot | ImportFormat::Auto
    ) && let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
    {
        collect_names_from_json(&value, &mut raw_names);
    } else {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !matches!(format, ImportFormat::Massdns)
                && let Ok(value) = serde_json::from_str::<serde_json::Value>(line)
            {
                collect_names_from_json(&value, &mut raw_names);
                continue;
            }
            if let Some(name) = line.split_whitespace().next() {
                raw_names.push(name.to_owned());
            }
        }
    }
    raw_names
        .into_iter()
        .filter_map(|name| util::normalize_observed_name(&name, domain))
        .collect()
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let database_explicit = cli.db.is_some();
    let database_path = cli.db.unwrap_or_else(default_database_path);
    let config_path = cli.config.unwrap_or_else(passive::default_config_path);
    let api_keys = ApiKeyStore::load_or_create(&config_path)?;
    match cli.command {
        Command::Scan(args) => {
            if let Some(path) = &args.wordlist
                && !path.is_file()
            {
                bail!("wordlist introuvable: {}", path.display());
            }
            if let Some(path) = &args.mutations
                && !path.is_file()
            {
                bail!("DSL de mutations introuvable: {}", path.display());
            }
            let mutation_rules = if let Some(path) = &args.mutations {
                load_mutation_rules(path)?
            } else {
                default_mutation_rules()
            };
            let defaults = args.profile.defaults();
            let max_runtime_seconds = args.max_runtime.unwrap_or(defaults.max_runtime);
            let max_words = args.max_words.unwrap_or(defaults.max_words);
            let active_max_runtime = args
                .active_max_runtime
                .unwrap_or(defaults.active_max_runtime);
            let max_passive = args.max_passive.unwrap_or(defaults.max_passive);
            let depth = args.depth.unwrap_or(defaults.depth);
            let recursive_words = args.recursive_words.unwrap_or(defaults.recursive_words);
            let recursive_hosts = args.recursive_hosts.unwrap_or(defaults.recursive_hosts);
            let pipeline_rounds = args.pipeline_rounds.unwrap_or(defaults.pipeline_rounds);
            let pipeline_budget = args.pipeline_budget.unwrap_or(defaults.pipeline_budget);
            let tls_hosts = args.tls_hosts.unwrap_or(defaults.tls_hosts);
            let graph_hosts = args.graph_hosts.unwrap_or(defaults.graph_hosts);
            let ptr_ips = args.ptr_ips.unwrap_or(defaults.ptr_ips);
            let nsec_max_names = args.nsec_max_names.unwrap_or(defaults.nsec_max_names);
            let nsec_max_runtime = args.nsec_max_runtime.unwrap_or(defaults.nsec_max_runtime);
            let ct_logs = args.ct_logs.unwrap_or(defaults.ct_logs);
            let ct_entries = args.ct_entries.unwrap_or(defaults.ct_entries);
            let ct_backfill = args.ct_backfill.unwrap_or(defaults.ct_backfill);
            let ct_max_runtime = args.ct_max_runtime.unwrap_or(defaults.ct_max_runtime);
            let web_hosts = args.web_hosts.unwrap_or(defaults.web_hosts);
            let web_max_runtime = args.web_max_runtime.unwrap_or(defaults.web_max_runtime);
            let web_assets = args.web_assets.unwrap_or(defaults.web_assets);
            let passive_max_runtime = args
                .passive_max_runtime
                .unwrap_or(defaults.passive_max_runtime);
            let passive_zone_concurrency = args
                .passive_zone_concurrency
                .unwrap_or(defaults.passive_zone_concurrency);
            let profile_passive = args.profile == ScanProfile::Passive;
            let passive_only = args.passive_only || profile_passive;

            if !passive_only && max_words == 0 {
                bail!("--max-words doit être supérieur à zéro hors profil passif");
            }
            if !(1..=5).contains(&depth) {
                bail!("--depth doit être compris entre 1 et 5");
            }
            if recursive_words == 0 || recursive_hosts == 0 {
                bail!("--recursive-words et --recursive-hosts doivent être supérieurs à zéro");
            }
            if max_passive == 0 {
                bail!("--max-passive doit être supérieur à zéro");
            }
            if passive_zone_concurrency == 0 || passive_zone_concurrency > 32 {
                bail!("--passive-zone-concurrency doit être compris entre 1 et 32");
            }
            if args.passive_concurrency == 0 || args.passive_concurrency > 32 {
                bail!("--passive-concurrency doit être compris entre 1 et 32");
            }
            if max_words > 10_000_000 {
                bail!("--max-words ne peut pas dépasser 10000000");
            }
            if max_passive > 1_000_000 {
                bail!("--max-passive ne peut pas dépasser 1000000");
            }
            if args.checkpoint_every == 0 {
                bail!("--checkpoint-every doit être supérieur à zéro");
            }
            let effective_recursive_words = if args.no_adaptive {
                recursive_words
            } else {
                recursive_words.min(50)
            };
            let effective_recursive_hosts = if args.no_adaptive {
                recursive_hosts
            } else {
                recursive_hosts.min(20)
            };
            if effective_recursive_words.saturating_mul(effective_recursive_hosts) > 1_000_000 {
                bail!(
                    "--recursive-words × --recursive-hosts ne peut pas dépasser 1000000 par niveau"
                );
            }
            if pipeline_budget > 1_000_000 {
                bail!("--pipeline-budget ne peut pas dépasser 1000000");
            }
            validate_scan_concurrency(
                args.domain_concurrency,
                args.web_concurrency,
                args.tls_concurrency,
            )?;
            if args.axfr_timeout <= 0.0 || !args.axfr_timeout.is_finite() {
                bail!("--axfr-timeout doit être un nombre positif");
            }
            if args.tls_timeout <= 0.0 || !args.tls_timeout.is_finite() {
                bail!("--tls-timeout doit être un nombre positif");
            }
            if args.tls_port == 0 {
                bail!("--tls-port doit être supérieur à zéro");
            }
            if tls_hosts == 0 {
                bail!("--tls-hosts doit être supérieur à zéro");
            }
            if graph_hosts == 0 {
                bail!("--graph-hosts doit être supérieur à zéro");
            }
            if pipeline_rounds == 0 || pipeline_budget == 0 {
                bail!("--pipeline-rounds et --pipeline-budget doivent être supérieurs à zéro");
            }
            if ptr_ips == 0 {
                bail!("--ptr-ips doit être supérieur à zéro");
            }
            if nsec_max_names == 0 {
                bail!("--nsec-max-names doit être supérieur à zéro");
            }
            if args.nsec_timeout <= 0.0 || !args.nsec_timeout.is_finite() {
                bail!("--nsec-timeout doit être un nombre positif");
            }
            if ct_logs == 0 || ct_entries == 0 || ct_backfill == 0 {
                bail!("--ct-logs, --ct-entries et --ct-backfill doivent être supérieurs à zéro");
            }
            if args.ct_timeout <= 0.0 || !args.ct_timeout.is_finite() {
                bail!("--ct-timeout doit être un nombre positif");
            }
            if web_hosts == 0 || args.web_max_bytes == 0 {
                bail!("--web-hosts et --web-max-bytes doivent être supérieurs à zéro");
            }
            if args.web_timeout <= 0.0 || !args.web_timeout.is_finite() {
                bail!("--web-timeout doit être un nombre positif");
            }
            if [args.json, args.jsonl, args.stream_jsonl]
                .into_iter()
                .filter(|enabled| *enabled)
                .count()
                > 1
            {
                bail!("--json, --jsonl et --stream-jsonl sont mutuellement exclusifs");
            }
            if args.no_passive && passive_only {
                bail!("--no-passive et --passive-only sont incompatibles");
            }
            if args.checkpoint_every == 0 {
                bail!("--checkpoint-every doit être supérieur à zéro");
            }
            let targets = collect_targets(&args)?;
            validate_sources(&args.passive_sources)?;
            validate_sources(&args.exclude_sources)?;
            let mut passive_sources = if args.all_sources {
                source_statuses(&api_keys)
                    .into_iter()
                    .map(|source| source.name)
                    .collect::<Vec<_>>()
            } else if args.passive_sources.is_empty() {
                automatic_sources_for_profile(&api_keys, args.profile == ScanProfile::Deep)
            } else {
                args.passive_sources.clone()
            };
            let automatic_source_selection = args.passive_sources.is_empty() && !args.all_sources;
            let excluded = args
                .exclude_sources
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            passive_sources.retain(|source| !excluded.contains(source));
            passive_sources.sort();
            passive_sources.dedup();
            if !args.no_passive && passive_sources.is_empty() {
                bail!("aucune source passive sélectionnée");
            }
            let database = Database::open(&database_path)?;
            let dns = make_dns(&args.dns)?;
            dns.seed_metrics(&database.resolver_history()?);
            let trusted_dns = if args.no_trusted_validation {
                None
            } else {
                let trusted = DnsEngine::new_with_rate_and_control(
                    args.dns.concurrency.min(256),
                    positive_duration_seconds(args.dns.timeout, "--timeout")?,
                    &args.dns.trusted_resolvers,
                    args.dns.dns_rate_limit,
                    args.dns.network_control.into(),
                )?
                .share_rate_limit_with(&dns);
                trusted.seed_metrics(&database.resolver_history()?);
                Some(trusted)
            };
            let options = ScanOptions {
                wordlist: args.wordlist.clone(),
                mutation_rules,
                max_words,
                active_phase_timeout: bounded_duration_seconds(
                    active_max_runtime,
                    "--active-max-runtime",
                )?,
                passive: !args.no_passive,
                passive_sources,
                api_keys: api_keys.clone(),
                automatic_source_selection,
                passive_refresh: bounded_duration_hours(
                    args.passive_refresh_hours,
                    "--passive-refresh-hours",
                )?,
                passive_phase_timeout: bounded_duration_seconds(
                    passive_max_runtime,
                    "--passive-max-runtime",
                )?,
                passive_zone_concurrency,
                passive_concurrency: args.passive_concurrency,
                max_passive,
                passive_only,
                axfr: !args.no_axfr && !profile_passive,
                axfr_timeout: positive_duration_seconds(args.axfr_timeout, "--axfr-timeout")?,
                refresh_cache: args.refresh_cache,
                verification_max_age: bounded_duration_hours(
                    args.verification_max_age,
                    "--verification-max-age",
                )?,
                only_live: args.only_live,
                profile: format!("{:?}", args.profile).to_ascii_lowercase(),
                checkpoint_every: bounded_duration_seconds(
                    args.checkpoint_every,
                    "--checkpoint-every",
                )?,
                resume: args.resume.clone(),
                ttl_cap: args.ttl_cap,
                negative_ttl: args.negative_ttl,
                include_wildcard: args.include_wildcard,
                wildcard_refresh: bounded_duration_hours(
                    args.wildcard_refresh_hours,
                    "--wildcard-refresh-hours",
                )?,
                recursive_depth: depth,
                recursive_words,
                recursive_hosts,
                adaptive: !args.no_adaptive,
                pipeline: !args.no_pipeline && !profile_passive,
                pipeline_rounds,
                pipeline_budget,
                tls_certificates: !args.no_tls && !profile_passive,
                tls_port: args.tls_port,
                tls_timeout: positive_duration_seconds(args.tls_timeout, "--tls-timeout")?,
                tls_refresh: bounded_duration_hours(args.tls_refresh_hours, "--tls-refresh-hours")?,
                tls_max_hosts: tls_hosts,
                tls_concurrency: args.tls_concurrency,
                dns_graph: !args.no_dns_graph && !profile_passive,
                graph_max_hosts: graph_hosts,
                service_discovery: !args.no_service_discovery && !profile_passive,
                ptr_pivot: !args.no_ptr && !profile_passive,
                ptr_max_ips: ptr_ips,
                dnssec_nsec: !args.no_nsec && !profile_passive,
                nsec_timeout: positive_duration_seconds(args.nsec_timeout, "--nsec-timeout")?,
                nsec_refresh: bounded_duration_hours(
                    args.nsec_refresh_hours,
                    "--nsec-refresh-hours",
                )?,
                nsec_max_names,
                nsec_phase_timeout: bounded_duration_seconds(
                    nsec_max_runtime,
                    "--nsec-max-runtime",
                )?,
                ct_monitor: !args.no_ct_monitor,
                ct_timeout: positive_duration_seconds(args.ct_timeout, "--ct-timeout")?,
                ct_phase_timeout: bounded_duration_seconds(ct_max_runtime, "--ct-max-runtime")?,
                ct_max_logs: ct_logs,
                ct_entries_per_log: ct_entries,
                ct_initial_backfill: ct_backfill,
                metadata_discovery: metadata_discovery_enabled(
                    args.metadata_discovery,
                    profile_passive,
                    args.no_web,
                ),
                metadata_all_hosts: args.metadata_discovery == MetadataDiscoveryArg::All,
                metadata_max_requests: if args.profile == ScanProfile::Deep {
                    64
                } else {
                    24
                },
                web_discovery: !args.no_web && !profile_passive,
                web_max_hosts: web_hosts,
                web_timeout: positive_duration_seconds(args.web_timeout, "--web-timeout")?,
                web_phase_timeout: bounded_duration_seconds(web_max_runtime, "--web-max-runtime")?,
                web_refresh: bounded_duration_hours(args.web_refresh_hours, "--web-refresh-hours")?,
                web_concurrency: args.web_concurrency,
                web_max_bytes: args.web_max_bytes,
                web_assets_per_host: web_assets,
            };
            let stream_mode = stream_jsonl_mode(args.stream_jsonl, args.only_live);
            let callback: Option<scanner::ProgressCallback> = if !args.quiet || args.stream_jsonl {
                let printer = Arc::new(Mutex::new(ConsoleProgress::new(
                    args.json || args.jsonl || args.stream_jsonl,
                )));
                let quiet = args.quiet;
                Some(Arc::new(move |event| {
                    if stream_mode == StreamJsonlMode::Realtime
                        && let ProgressEvent::Finding(finding) = &event
                    {
                        println!("{}", stream_finding_line(finding));
                        let _ = std::io::stdout().flush();
                    }
                    if !quiet && let Ok(mut printer) = printer.lock() {
                        printer.handle(event);
                    }
                }))
            } else {
                None
            };
            let max_runtime = (max_runtime_seconds > 0)
                .then(|| bounded_duration_seconds(max_runtime_seconds, "--max-runtime"))
                .transpose()?;
            let domain_concurrency = args.domain_concurrency.min(targets.len()).max(1);
            let mut pending = stream::iter(targets)
                .map(|target| {
                    let database = database.clone();
                    let dns = dns.clone();
                    let options = options.clone();
                    let callback = callback.clone();
                    let trusted_dns = trusted_dns.clone();
                    async move {
                        let mut scanner = Scanner::new(database, dns, options);
                        if let Some(trusted_dns) = trusted_dns {
                            scanner = scanner.with_trusted_dns(trusted_dns);
                        }
                        if let Some(callback) = callback {
                            scanner = scanner.with_progress(callback);
                        }
                        if let Some(limit) = max_runtime {
                            tokio::time::timeout(limit, scanner.scan(&target))
                                .await
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "durée globale maximale atteinte pour {target}; utilisez --resume latest"
                                    )
                                })?
                        } else {
                            scanner.scan(&target).await
                        }
                    }
                })
                .buffer_unordered(domain_concurrency);
            let mut results = Vec::new();
            let mut first_error = None;
            let mut interrupted = Box::pin(tokio::signal::ctrl_c());
            loop {
                let next = tokio::select! {
                    signal = &mut interrupted => {
                        match signal {
                            Ok(()) => bail!(
                                "scan interrompu par l'utilisateur; checkpoint conservé pour --resume latest"
                            ),
                            Err(error) => bail!("écoute de Ctrl+C impossible: {error}"),
                        }
                    }
                    next = pending.next() => next,
                };
                let Some(result) = next else {
                    break;
                };
                match result {
                    Ok(result) => {
                        if stream_mode == StreamJsonlMode::FinalOnly {
                            for finding in result
                                .findings
                                .iter()
                                .filter(|finding| is_strict_live(finding.state, finding.wildcard))
                            {
                                println!("{}", stream_finding_line(finding));
                            }
                            std::io::stdout().flush()?;
                        }
                        results.push(result);
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
            }
            results.sort_by(|left, right| left.domain.cmp(&right.domain));
            if args.stream_jsonl {
                // Realtime events were emitted by the callback. With --only-live,
                // final findings were emitted after each domain completed wildcard
                // classification and final state filtering.
            } else if args.jsonl {
                for result in &results {
                    println!("{}", serde_json::to_string(result)?);
                }
            } else if args.json {
                if results.len() == 1 {
                    println!("{}", serde_json::to_string_pretty(&results[0])?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                }
            } else if !args.quiet {
                for result in &results {
                    print_scan_summary(result);
                }
            }
            if let Some(path) = &args.output {
                write_scan_results(path, &results, args.json, args.jsonl)?;
            }
            if let Some(directory) = &args.output_dir {
                std::fs::create_dir_all(directory)?;
                for result in &results {
                    let extension = if args.json {
                        "json"
                    } else if args.jsonl {
                        "jsonl"
                    } else {
                        "txt"
                    };
                    let path = directory.join(format!("{}.{}", result.domain, extension));
                    write_scan_results(&path, std::slice::from_ref(result), args.json, args.jsonl)?;
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        Command::List(args) => {
            let database = Database::open(&database_path)?;
            let normalized = args
                .domain
                .as_deref()
                .map(util::normalize_domain)
                .transpose()?;
            let _ = args.all;
            let hosts = database.inventory(normalized.as_deref(), args.only_live)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&hosts)?);
            } else {
                for host in hosts {
                    println!(
                        "{}\t{}\t{}",
                        host.fqdn,
                        host.state,
                        host.last_verified_at
                            .map(|timestamp| timestamp.to_string())
                            .unwrap_or_else(|| "-".to_owned())
                    );
                }
            }
        }
        Command::Refresh(args) => {
            if !(1..=4_096).contains(&args.batch_size) {
                bail!("--batch-size doit être compris entre 1 et 4096");
            }
            let database = Database::open(&database_path)?;
            let dns = make_dns(&args.dns)?;
            dns.seed_metrics(&database.resolver_history()?);
            let trusted_dns = DnsEngine::new_with_rate_and_control(
                args.dns.concurrency.min(256),
                positive_duration_seconds(args.dns.timeout, "--timeout")?,
                &args.dns.trusted_resolvers,
                args.dns.dns_rate_limit,
                args.dns.network_control.into(),
            )?
            .share_rate_limit_with(&dns);
            trusted_dns.seed_metrics(&database.resolver_history()?);
            let progress: Option<RefreshProgressCallback> = (!args.quiet).then(|| {
                Arc::new(|progress: fellaga_core::scanner::RefreshProgress| {
                    eprintln!(
                        "[refresh] {}/{} checked, {} live, {} historical, {} indeterminate",
                        progress.checked,
                        progress.total,
                        progress.active,
                        progress.inactive,
                        progress.indeterminate
                    );
                }) as RefreshProgressCallback
            });
            if !args.quiet {
                eprintln!(
                    "[refresh] starting {} with {}s limit and {}-name batches",
                    args.target, args.max_runtime, args.batch_size
                );
            }
            let refresh = refresh_inventory_bounded(
                &database,
                &dns,
                Some(&trusted_dns),
                &args.target,
                args.ttl_cap,
                args.negative_ttl,
                RefreshOptions {
                    max_runtime: bounded_duration_seconds(args.max_runtime, "--max-runtime")?,
                    wildcard_phase_timeout: Duration::from_secs(30),
                    batch_size: args.batch_size,
                },
                progress,
            );
            tokio::pin!(refresh);
            let result = tokio::select! {
                result = &mut refresh => result?,
                signal = tokio::signal::ctrl_c() => {
                    match signal {
                        Ok(()) => bail!("actualisation interrompue; résultats déjà persistés conservés sans purge wildcard"),
                        Err(error) => bail!("écoute de Ctrl+C impossible: {error}"),
                    }
                }
            };
            if !args.quiet {
                eprintln!(
                    "[refresh] {}: {}/{} checked in {} ms",
                    result.status, result.checked, result.total, result.duration_ms
                );
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::History(args) => {
            let database = Database::open(&database_path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&database.history(args.limit)?)?
            );
        }
        Command::Stats => {
            let database = Database::open(&database_path)?;
            println!("{}", serde_json::to_string_pretty(&database.stats()?)?);
        }
        Command::Cache { action } => {
            let database = Database::open(&database_path)?;
            match action {
                CacheAction::Prune => {
                    let expired = database.prune_cache()?;
                    let mut temporary = 0_usize;
                    const PRUNE_BATCH: usize = 25_000;
                    loop {
                        let removed = database.prune_superseded_candidate_queues(PRUNE_BATCH)?;
                        temporary = temporary.saturating_add(removed);
                        if removed > 0 {
                            eprintln!(
                                "cache prune: {temporary} candidat(s) temporaire(s) abandonné(s) supprimé(s)"
                            );
                        }
                        if removed < PRUNE_BATCH {
                            break;
                        }
                    }
                    println!(
                        "{expired} entrée(s) négative(s) expirée(s), {temporary} candidat(s) temporaire(s) abandonné(s) supprimé(s)"
                    );
                }
            }
        }
        Command::Knowledge(args) => {
            let database = Database::open(&database_path)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&database.knowledge(args.limit)?)?
            );
        }
        Command::Sources(args) => {
            let statuses = source_statuses(&api_keys);
            if args.check {
                if args.timeout <= 0.0 || !args.timeout.is_finite() {
                    bail!("--timeout must be a positive number");
                }
                validate_source_check_concurrency(args.concurrency)?;
                let target = util::normalize_domain(&args.target)?;
                let timeout = positive_duration_seconds(args.timeout, "--timeout")?;
                let mut pending_checks = stream::iter(statuses.iter().cloned())
                    .map(|source| {
                        let api_keys = api_keys.clone();
                        let target = target.clone();
                        async move {
                            if source.requires_key && !source.configured {
                                return serde_json::json!({
                                    "name": source.name,
                                    "status": "skipped_missing_key",
                                    "names": 0,
                                    "duration_ms": 0,
                                    "metadata": source.metadata
                                });
                            }
                            let started = std::time::Instant::now();
                            match passive::fetch_detailed_bounded(
                                &source.name,
                                &target,
                                timeout,
                                &api_keys,
                                timeout,
                            )
                            .await
                            {
                                Ok(result) => serde_json::json!({
                                    "name": source.name,
                                    "status": source_check_result_status(
                                        result.names.len(),
                                        result.partial_warning.as_deref()
                                    ),
                                    "names": result.names.len(),
                                    "duration_ms": started.elapsed().as_millis(),
                                    "warning": result.partial_warning,
                                    "metadata": source.metadata
                                }),
                                Err(error) => {
                                    let error = format!("{error:#}");
                                    serde_json::json!({
                                    "name": source.name,
                                    "status": source_check_error_status(&error),
                                    "names": 0,
                                    "duration_ms": started.elapsed().as_millis(),
                                    "error": error,
                                    "metadata": source.metadata
                                    })
                                }
                            }
                        }
                    })
                    .buffer_unordered(args.concurrency);
                let mut checks = Vec::with_capacity(statuses.len());
                while let Some(check) = pending_checks.next().await {
                    if !args.json {
                        println!(
                            "{:<22} {:<20} {:>6} name(s) {:>7} ms{}",
                            check["name"].as_str().unwrap_or("?"),
                            check["status"].as_str().unwrap_or("?"),
                            check["names"].as_u64().unwrap_or_default(),
                            check["duration_ms"].as_u64().unwrap_or_default(),
                            check["error"]
                                .as_str()
                                .or_else(|| check["warning"].as_str())
                                .map(|error| format!(" — {}", compact_error(error, 120)))
                                .unwrap_or_default()
                        );
                    }
                    checks.push(check);
                }
                checks.sort_by(|left, right| {
                    left["name"]
                        .as_str()
                        .unwrap_or_default()
                        .cmp(right["name"].as_str().unwrap_or_default())
                });
                let mut summary = BTreeMap::<String, usize>::new();
                for check in &checks {
                    *summary
                        .entry(check["status"].as_str().unwrap_or("error").to_owned())
                        .or_default() += 1;
                }
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "target": target,
                            "summary": summary,
                            "checks": checks
                        }))?
                    );
                } else {
                    println!(
                        "summary: {}",
                        summary
                            .iter()
                            .map(|(status, count)| format!("{status}={count}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                return Ok(());
            }
            let database = Database::open(&database_path)?;
            let diagnostics = database.source_diagnostics(Duration::from_secs(24 * 3_600))?;
            if args.json {
                let sources = statuses
                    .into_iter()
                    .map(|source| {
                        let health = diagnostics.get(&source.name);
                        serde_json::json!({
                            "name": source.name,
                            "requires_key": source.requires_key,
                            "key_environment": source.key_environment,
                            "configured": source.configured,
                            "automatic": source.automatic,
                            "metadata": source.metadata,
                            "health": health
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "config": config_path,
                        "sources": sources
                    }))?
                );
            } else {
                println!("Configuration: {}", config_path.display());
                for source in statuses {
                    let diagnostic = diagnostics.get(&source.name);
                    let state = if let Some(wait) =
                        diagnostic.and_then(|diagnostic| diagnostic.retry_in_seconds)
                    {
                        format!("paused {}", wait_label(wait))
                    } else if source.automatic {
                        "auto".to_owned()
                    } else if source.requires_key {
                        "missing key".to_owned()
                    } else {
                        "manual".to_owned()
                    };
                    let key = source
                        .key_environment
                        .map(|variable| format!(" [{variable}]"))
                        .unwrap_or_default();
                    let metrics = diagnostic
                        .map(|diagnostic| {
                            format!(
                                " {}/{} successes, {} ms",
                                diagnostic.successes, diagnostic.requests, diagnostic.average_ms
                            )
                        })
                        .unwrap_or_default();
                    println!(
                        "{:<20} {:<14} {:<26}{}{}",
                        source.name, source.metadata.evidence_family, state, key, metrics
                    );
                    if let Some(error) = diagnostic.and_then(|value| value.last_error.as_deref()) {
                        println!("  last error: {}", compact_error(error, 140));
                    }
                }
            }
        }
        Command::Explain(args) => {
            let database = Database::open(&database_path)?;
            let fqdn = util::normalize_domain(&args.fqdn)?;
            let explanation = database.explain(&fqdn)?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&explanation)?);
            } else if explanation["known"].as_bool() == Some(false) {
                println!("{fqdn}: inconnu de la base locale");
            } else {
                println!("{fqdn}");
                println!("  état: {}", explanation["inventory"]["state"]);
                println!(
                    "  dernière validation: {}",
                    explanation["inventory"]["last_verified_at"]
                );
                println!(
                    "  preuves: {} observation(s), {} validation(s) DNS, {} enregistrement(s)",
                    explanation["evidence"].as_array().map_or(0, Vec::len),
                    explanation["dns_verifications"]
                        .as_array()
                        .map_or(0, Vec::len),
                    explanation["dns_records"].as_array().map_or(0, Vec::len)
                );
                for evidence in explanation["evidence"].as_array().into_iter().flatten() {
                    println!(
                        "    - {} ({}, {} fois)",
                        evidence["source"], evidence["kind"], evidence["times_seen"]
                    );
                }
                if let Some(quarantine) = explanation["quarantine"]
                    .as_array()
                    .filter(|entries| !entries.is_empty())
                {
                    println!("  quarantaine wildcard: {} zone(s)", quarantine.len());
                    for entry in quarantine {
                        println!(
                            "    - zone {}, scan {}, raison {}, horodatage {}",
                            entry["root_domain"],
                            entry["scan_id"],
                            entry["reason"],
                            entry["quarantined_at"]
                        );
                    }
                }
            }
        }
        Command::Benchmark { action } => match action {
            BenchmarkAction::CandidatePipeline(args) => {
                if !database_explicit {
                    bail!("candidate-pipeline requires an explicit fresh --db path");
                }
                if args.timeout <= 0.0 || !args.timeout.is_finite() || args.timeout > 60.0 {
                    bail!("--timeout must be greater than zero and at most 60 seconds");
                }
                let result = run_candidate_pipeline(CandidatePipelineOptions {
                    database: database_path,
                    wordlist: args.wordlist,
                    output: args.output.clone(),
                    candidates: args.candidates,
                    batch_size: args.batch_size,
                    concurrency: args.concurrency,
                    timeout: positive_duration_seconds(args.timeout, "--timeout")?,
                    campaign_id: args.campaign_id,
                })
                .await?;
                println!(
                    "Candidate pipeline completed: {} candidates, {} DNS queries, {} ms; JSON: {}",
                    result.processed_candidates,
                    result.dns_queries,
                    result.duration_ms,
                    args.output.display()
                );
            }
        },
        Command::Resolvers { action } => match action {
            ResolverAction::Test(args) => {
                if args.timeout <= 0.0 || !args.timeout.is_finite() {
                    bail!("--timeout doit être un nombre positif");
                }
                let resolvers = if args.resolvers.is_empty() {
                    ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]
                        .into_iter()
                        .map(str::parse)
                        .collect::<std::result::Result<Vec<IpAddr>, _>>()?
                } else {
                    args.resolvers
                };
                let results = DnsEngine::test_resolvers(
                    &resolvers,
                    positive_duration_seconds(args.timeout, "--timeout")?,
                )
                .await;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&results)?);
                } else {
                    for result in results {
                        println!(
                            "{:<15} {:<8} NX-hijack={} DNSSEC={} AD={} cohérent={} {}ms{}",
                            result.resolver,
                            if result.usable { "OK" } else { "REJET" },
                            result.hijacks_nxdomain,
                            result.dnssec_records,
                            result.validates_dnssec,
                            result.consistent,
                            result.average_ms,
                            result
                                .error
                                .map(|error| format!(" — {}", compact_error(&error, 100)))
                                .unwrap_or_default()
                        );
                    }
                }
            }
            ResolverAction::Benchmark(args) => {
                if args.timeout <= 0.0 || !args.timeout.is_finite() {
                    bail!("--timeout doit être un nombre positif");
                }
                let result = DnsEngine::benchmark_loopback(
                    args.queries,
                    args.concurrency,
                    positive_duration_seconds(args.timeout, "--timeout")?,
                )
                .await?;
                let serialized = serde_json::to_string_pretty(&result)?;
                if let Some(path) = args.output {
                    std::fs::write(path, format!("{serialized}\n"))?;
                }
                if args.json {
                    println!("{serialized}");
                } else {
                    println!(
                        "{:.0} req/s | {} complétées | {} échecs | perte {:.3}% | {} ms",
                        result.queries_per_second,
                        result.completed,
                        result.failures,
                        result.loss_rate * 100.0,
                        result.duration_ms
                    );
                }
            }
        },
        Command::Import(args) => {
            let domain = util::normalize_domain(&args.domain)?;
            let content = if args.input == std::path::Path::new("-") {
                let mut content = String::new();
                std::io::stdin().read_to_string(&mut content)?;
                content
            } else {
                std::fs::read_to_string(&args.input)?
            };
            let names = parse_import_names(&content, args.format, &domain);
            let source = format!("import:{:?}", args.format).to_ascii_lowercase();
            let database = Database::open(&database_path)?;
            let written = database.import_inventory(&domain, &names, &source)?;
            println!(
                "{} nom(s) importé(s) pour {} avec l'état unverified ({} écriture(s))",
                names.len(),
                domain,
                written
            );
        }
        Command::Export(args) => {
            let domain = args
                .domain
                .as_deref()
                .map(util::normalize_domain)
                .transpose()?;
            let database = Database::open(&database_path)?;
            let inventory = database.inventory(domain.as_deref(), args.only_live)?;
            let output = match args.format {
                ExportFormat::Jsonl => inventory
                    .iter()
                    .map(serde_json::to_string)
                    .collect::<serde_json::Result<Vec<_>>>()?
                    .join("\n"),
                ExportFormat::Csv => {
                    let mut rows = vec![
                        "fqdn,state,last_verified_at,first_seen,last_seen,times_seen,sources"
                            .to_owned(),
                    ];
                    rows.extend(inventory.iter().map(|entry| {
                        [
                            csv_field(&entry.fqdn),
                            entry.state.to_string(),
                            entry
                                .last_verified_at
                                .map(|value| value.to_string())
                                .unwrap_or_default(),
                            entry.first_seen.to_string(),
                            entry.last_seen.to_string(),
                            entry.times_seen.to_string(),
                            csv_field(&entry.sources.iter().cloned().collect::<Vec<_>>().join(";")),
                        ]
                        .join(",")
                    }));
                    rows.join("\n")
                }
            };
            if let Some(path) = args.output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(path, output + if inventory.is_empty() { "" } else { "\n" })?;
            } else if !output.is_empty() {
                println!("{output}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floating_point_timeouts_are_converted_without_panicking() {
        assert_eq!(
            positive_duration_seconds(0.25, "--timeout").unwrap(),
            Duration::from_millis(250)
        );
        for invalid in [
            0.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::MIN_POSITIVE,
            1.0e18,
            f64::MAX,
        ] {
            assert!(
                positive_duration_seconds(invalid, "--timeout").is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
        assert_eq!(
            bounded_duration_hours(2, "--refresh-hours").unwrap(),
            Duration::from_secs(7_200)
        );
        assert_eq!(
            bounded_duration_seconds(0, "--max-runtime").unwrap(),
            Duration::ZERO
        );
        assert!(bounded_duration_seconds(u64::MAX, "--max-runtime").is_err());
        assert!(bounded_duration_hours(u64::MAX, "--refresh-hours").is_err());
    }

    #[test]
    fn stream_jsonl_mode_defers_only_live_findings_until_final_classification() {
        assert_eq!(stream_jsonl_mode(false, false), StreamJsonlMode::Disabled);
        assert_eq!(stream_jsonl_mode(false, true), StreamJsonlMode::Disabled);
        assert_eq!(stream_jsonl_mode(true, false), StreamJsonlMode::Realtime);
        assert_eq!(stream_jsonl_mode(true, true), StreamJsonlMode::FinalOnly);
    }

    #[test]
    fn intelligent_scan_controls_parse_with_safe_defaults_and_explicit_overrides() {
        let defaults = Cli::try_parse_from(["fellaga", "scan", "example.com"]).unwrap();
        let Command::Scan(defaults) = defaults.command else {
            panic!("scan command expected");
        };
        assert_eq!(defaults.dns.network_control, NetworkControlArg::Adaptive);
        assert_eq!(defaults.metadata_discovery, MetadataDiscoveryArg::Auto);
        assert!(metadata_discovery_enabled(
            defaults.metadata_discovery,
            false,
            defaults.no_web
        ));

        let overridden = Cli::try_parse_from([
            "fellaga",
            "scan",
            "example.com",
            "--network-control",
            "fixed",
            "--metadata-discovery",
            "all",
            "--no-web",
        ])
        .unwrap();
        let Command::Scan(overridden) = overridden.command else {
            panic!("scan command expected");
        };
        assert_eq!(overridden.dns.network_control, NetworkControlArg::Fixed);
        assert_eq!(overridden.metadata_discovery, MetadataDiscoveryArg::All);
        assert!(!metadata_discovery_enabled(
            overridden.metadata_discovery,
            false,
            overridden.no_web
        ));
        assert!(!metadata_discovery_enabled(
            MetadataDiscoveryArg::Auto,
            true,
            false
        ));
    }

    #[test]
    fn strict_live_stream_rejects_stale_unverified_and_wildcard_findings() {
        assert!(is_strict_live(ObservationState::Live, false));
        assert!(!is_strict_live(ObservationState::Historical, false));
        assert!(!is_strict_live(ObservationState::Unverified, false));
        assert!(!is_strict_live(ObservationState::Unverified, true));
        assert!(!is_strict_live(ObservationState::Live, true));
    }

    #[test]
    fn scan_concurrency_caps_bound_cross_target_network_fanout() {
        assert!(validate_scan_concurrency(1, 8, 16).is_ok());
        assert!(
            validate_scan_concurrency(
                MAX_DOMAIN_CONCURRENCY,
                MAX_WEB_CONCURRENCY,
                MAX_TLS_CONCURRENCY
            )
            .is_ok()
        );
        assert!(validate_scan_concurrency(0, 8, 16).is_err());
        assert!(validate_scan_concurrency(MAX_DOMAIN_CONCURRENCY + 1, 8, 16).is_err());
        assert!(validate_scan_concurrency(1, MAX_WEB_CONCURRENCY + 1, 16).is_err());
        assert!(validate_scan_concurrency(1, 8, MAX_TLS_CONCURRENCY + 1).is_err());
    }

    #[test]
    fn source_check_concurrency_is_bounded() {
        assert!(validate_source_check_concurrency(1).is_ok());
        assert!(validate_source_check_concurrency(8).is_ok());
        assert!(validate_source_check_concurrency(MAX_SOURCE_CHECK_CONCURRENCY).is_ok());
        assert!(validate_source_check_concurrency(0).is_err());
        assert!(validate_source_check_concurrency(MAX_SOURCE_CHECK_CONCURRENCY + 1).is_err());
    }

    #[test]
    fn source_check_distinguishes_connector_deadlines_from_errors() {
        assert_eq!(
            source_check_error_status(
                "commoncrawl: budget total de 20s dépassé; résultat en cache conservé"
            ),
            "deferred_budget"
        );
        assert_eq!(
            source_check_error_status("commoncrawl: HTTP 502"),
            "upstream_error"
        );
        assert_eq!(
            source_check_error_status("Cert Spotter: HTTP 429; Retry-After=60s"),
            "rate_limited"
        );
        assert_eq!(
            source_check_error_status("Common Crawl: HTTP 503; Retry-After=60s"),
            "upstream_error"
        );
        assert_eq!(
            source_check_error_status("Driftnet: HTTP 524 timeout CDN amont"),
            "upstream_error"
        );
        assert_eq!(
            source_check_error_status("Cloudflare challenge: Just a moment"),
            "anti_bot"
        );
        assert_eq!(
            source_check_error_status("error sending request: connection refused"),
            "transport_error"
        );
        assert_eq!(
            source_check_error_status(
                "error sending request for url (https://index.commoncrawl.org/collinfo.json)"
            ),
            "transport_error"
        );
        assert_eq!(
            source_check_error_status("JSON Common Crawl invalide"),
            "schema_error"
        );
        assert_eq!(source_check_result_status(0, None), "empty");
        assert_eq!(
            source_check_result_status(3, Some("page 2 failed")),
            "degraded"
        );
        assert_eq!(
            source_check_result_status(0, Some("budget total de 10s dépassé")),
            "deferred_budget"
        );
    }

    #[test]
    fn profiles_have_expected_finite_enrichment_budgets() {
        for profile in [ScanProfile::Deep, ScanProfile::Balanced, ScanProfile::Turbo] {
            let defaults = profile.defaults();
            assert!(defaults.max_runtime > 0);
            assert!(defaults.active_max_runtime > 0);
            assert!(defaults.nsec_max_runtime > 0);
            assert!(defaults.ct_max_runtime > 0);
            assert!(defaults.web_max_runtime > 0);
            assert!(
                defaults
                    .recursive_words
                    .saturating_mul(defaults.recursive_hosts)
                    <= 1_000_000
            );
        }
        assert_eq!(ScanProfile::Deep.defaults().max_runtime, 600);
        assert_eq!(ScanProfile::Balanced.defaults().max_runtime, 300);
        assert_eq!(ScanProfile::Passive.defaults().max_runtime, 180);
        assert_eq!(ScanProfile::Turbo.defaults().max_runtime, 300);
        assert_eq!(ScanProfile::Passive.defaults().active_max_runtime, 0);
        assert_eq!(ScanProfile::Deep.defaults().ct_max_runtime, 30);
        assert_eq!(ScanProfile::Balanced.defaults().ct_max_runtime, 10);
        assert_eq!(ScanProfile::Passive.defaults().ct_max_runtime, 30);
        assert_eq!(ScanProfile::Turbo.defaults().ct_max_runtime, 5);
        assert_eq!(ScanProfile::Deep.defaults().passive_max_runtime, 45);
        assert_eq!(ScanProfile::Balanced.defaults().passive_max_runtime, 25);
        assert_eq!(ScanProfile::Passive.defaults().passive_max_runtime, 60);
        assert_eq!(ScanProfile::Turbo.defaults().passive_max_runtime, 15);
        assert_eq!(ScanProfile::Deep.defaults().web_max_runtime, 90);
        assert_eq!(ScanProfile::Balanced.defaults().web_max_runtime, 45);
        assert_eq!(ScanProfile::Passive.defaults().web_max_runtime, 0);
        assert_eq!(ScanProfile::Turbo.defaults().web_max_runtime, 45);
    }
}
