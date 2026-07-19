use clap::{Args, Parser, Subcommand, ValueEnum};
use fellaga_core::network_governor::NetworkControl;
use std::net::IpAddr;
use std::path::PathBuf;

use super::profile::ScanProfile;
#[derive(Debug, Parser)]
#[command(
    name = "fellaga",
    version,
    about = "Fast, adaptive Rust subdomain enumerator"
)]
pub(crate) struct Cli {
    #[arg(
        long,
        global = true,
        help = "SQLite database path (otherwise FELLAGA_DB or XDG_DATA_HOME)"
    )]
    pub(crate) db: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        help = "API-key JSON configuration (otherwise FELLAGA_CONFIG or XDG_CONFIG_HOME)"
    )]
    pub(crate) config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
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
pub(crate) enum NetworkControlArg {
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
pub(crate) struct DnsArgs {
    #[arg(
        short = 'c',
        long,
        default_value_t = 128,
        help = "Maximum concurrent host-resolution tasks"
    )]
    pub(crate) concurrency: usize,
    #[arg(long, default_value_t = 2.0, help = "DNS query timeout in seconds")]
    pub(crate) timeout: f64,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "1.1.1.1,8.8.8.8,9.9.9.9",
        help = "DNS resolvers, for example 1.1.1.1,8.8.8.8"
    )]
    pub(crate) resolvers: Vec<IpAddr>,
    #[arg(
        long,
        default_value_t = 250,
        help = "Global DNS requests-per-second limit; 0 deliberately disables the safeguard"
    )]
    pub(crate) dns_rate_limit: u64,
    #[arg(
        long,
        value_enum,
        default_value_t = NetworkControlArg::Adaptive,
        help = "Network pressure control; adaptive treats rate and concurrency as ceilings"
    )]
    pub(crate) network_control: NetworkControlArg,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "1.1.1.1,8.8.8.8,9.9.9.9",
        help = "Independent resolvers used for final consensus validation"
    )]
    pub(crate) trusted_resolvers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub(crate) enum MetadataDiscoveryArg {
    Auto,
    Off,
    All,
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    #[arg(value_name = "TARGET", help = "Authorized target domain")]
    pub(crate) targets: Vec<String>,
    #[arg(short = 'l', long, help = "Target file with one domain per line")]
    pub(crate) targets_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ScanProfile::Deep, help = "Scan coverage profile")]
    pub(crate) profile: ScanProfile,
    #[arg(
        long,
        default_value_t = 1,
        help = "Target domains processed in parallel (1-4)"
    )]
    pub(crate) domain_concurrency: usize,
    #[command(flatten)]
    pub(crate) dns: DnsArgs,
    #[arg(short = 'w', long, help = "Additional candidate wordlist")]
    pub(crate) wordlist: Option<PathBuf>,
    #[arg(
        long,
        help = "Mutation DSL: score:name:pattern; variables word,parent,env,region,cloud,n"
    )]
    pub(crate) mutations: Option<PathBuf>,
    #[arg(
        long,
        help = "Maximum brute-force candidates from configured generators"
    )]
    pub(crate) max_words: Option<usize>,
    #[arg(
        long,
        help = "Optional cumulative deadline for generated candidates in seconds; 0 runs to convergence"
    )]
    pub(crate) active_max_runtime: Option<u64>,
    #[arg(long, help = "Disable passive-provider discovery")]
    pub(crate) no_passive: bool,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated passive-source allowlist; empty selects automatically"
    )]
    pub(crate) passive_sources: Vec<String>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Comma-separated passive sources to exclude"
    )]
    pub(crate) exclude_sources: Vec<String>,
    #[arg(
        long,
        help = "Select every unique available connector; compatibility aliases are not executed twice and key-gated sources without credentials are skipped"
    )]
    pub(crate) all_sources: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Passive-source refresh interval in hours"
    )]
    pub(crate) passive_refresh_hours: u64,
    #[arg(
        long,
        help = "Optional cumulative passive-source deadline per target in seconds; 0 waits for completion"
    )]
    pub(crate) passive_max_runtime: Option<u64>,
    #[arg(
        long,
        help = "Child zones queried concurrently during recursive passive discovery"
    )]
    pub(crate) passive_zone_concurrency: Option<usize>,
    #[arg(
        long,
        default_value_t = 8,
        help = "Global passive connector concurrency shared by root and child zones"
    )]
    pub(crate) passive_concurrency: usize,
    #[arg(long, help = "Maximum passive names accepted per target")]
    pub(crate) max_passive: Option<usize>,
    #[arg(
        long,
        help = "Skip brute-force generation; active enrichment may still run"
    )]
    pub(crate) passive_only: bool,
    #[arg(
        long,
        help = "Query passive providers only; disable target DNS and every direct target connection (requires --profile passive)"
    )]
    pub(crate) no_target_contact: bool,
    #[arg(long, help = "Disable automatic AXFR attempts")]
    pub(crate) no_axfr: bool,
    #[arg(
        long,
        default_value_t = 4.0,
        help = "AXFR timeout per nameserver in seconds"
    )]
    pub(crate) axfr_timeout: f64,
    #[arg(long, help = "Bypass cached answers even when they are fresh")]
    pub(crate) refresh_cache: bool,
    #[arg(
        long,
        default_value_t = 24,
        help = "Maximum cached-validation age in hours for a finding to remain live"
    )]
    pub(crate) verification_max_age: u64,
    #[arg(
        long,
        conflicts_with = "include_non_live",
        help = "Compatibility option; final live non-wildcard findings are already the default"
    )]
    pub(crate) only_live: bool,
    #[arg(
        long,
        conflicts_with = "only_live",
        help = "Include retained historical and unverified names in final output"
    )]
    pub(crate) include_non_live: bool,
    #[arg(
        long,
        default_value_t = 86_400,
        help = "Compatibility option; positive answers are retained permanently"
    )]
    pub(crate) ttl_cap: u32,
    #[arg(
        long,
        default_value_t = 300,
        help = "Requested negative-cache lifetime in seconds"
    )]
    pub(crate) negative_ttl: u32,
    #[arg(long, help = "Include weak candidates that match a wildcard profile")]
    pub(crate) include_wildcard: bool,
    #[arg(
        long,
        default_value_t = 6,
        help = "Wildcard-profile refresh interval in hours; expired entries trigger SOA and new probes"
    )]
    pub(crate) wildcard_refresh_hours: u64,
    #[arg(long, help = "Maximum active DNS depth from 1 to 5")]
    pub(crate) depth: Option<usize>,
    #[arg(long, help = "Candidate words considered below validated parents")]
    pub(crate) recursive_words: Option<usize>,
    #[arg(
        long,
        help = "Validated parent hosts considered for recursive discovery"
    )]
    pub(crate) recursive_hosts: Option<usize>,
    #[arg(long, help = "Disable adaptive candidate waves and low-yield stopping")]
    pub(crate) no_adaptive: bool,
    #[arg(long, help = "Disable event-driven enrichment rounds")]
    pub(crate) no_pipeline: bool,
    #[arg(long, help = "Maximum event-pipeline rounds")]
    pub(crate) pipeline_rounds: Option<usize>,
    #[arg(
        long = "pipeline-limit",
        alias = "pipeline-budget",
        help = "Optional maximum number of new pipeline events; 0 drains the finite event queue"
    )]
    pub(crate) pipeline_limit: Option<usize>,
    #[arg(
        long,
        help = "Disable hostname extraction from presented TLS certificates"
    )]
    pub(crate) no_tls: bool,
    #[arg(
        long,
        default_value_t = 443,
        help = "Default port used for TLS inspection"
    )]
    pub(crate) tls_port: u16,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "TLS timeout per endpoint in seconds"
    )]
    pub(crate) tls_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "TLS refresh interval in hours; old certificate names remain retained"
    )]
    pub(crate) tls_refresh_hours: u64,
    #[arg(long, help = "Maximum TLS endpoints inspected")]
    pub(crate) tls_hosts: Option<usize>,
    #[arg(long, default_value_t = 16, help = "Concurrent TLS handshakes (1-32)")]
    pub(crate) tls_concurrency: usize,
    #[arg(long, help = "Disable the MX/NS/SOA/TXT/CAA/SRV/HTTPS/SVCB DNS graph")]
    pub(crate) no_dns_graph: bool,
    #[arg(long, help = "Maximum confirmed hosts enriched through the DNS graph")]
    pub(crate) graph_hosts: Option<usize>,
    #[arg(long, help = "Disable SRV service-discovery queries")]
    pub(crate) no_service_discovery: bool,
    #[arg(long, help = "Disable PTR pivots for already confirmed IP addresses")]
    pub(crate) no_ptr: bool,
    #[arg(long, help = "Maximum confirmed IP addresses queried with PTR")]
    pub(crate) ptr_ips: Option<usize>,
    #[arg(
        long,
        help = "Disable the bounded Shodan InternetDB IP-to-hostname pivot"
    )]
    pub(crate) no_internetdb: bool,
    #[arg(
        long,
        help = "Maximum public IP addresses queried through Shodan InternetDB (1-64)"
    )]
    pub(crate) internetdb_ips: Option<usize>,
    #[arg(
        long,
        help = "Optional cumulative Shodan InternetDB deadline in seconds (0 waits for completion, maximum 60)"
    )]
    pub(crate) internetdb_max_runtime: Option<u64>,
    #[arg(
        long,
        default_value_t = 24,
        help = "Shodan InternetDB successful-cache refresh interval in hours"
    )]
    pub(crate) internetdb_refresh_hours: u64,
    #[arg(long, help = "Disable DNSSEC NSEC detection and bounded walking")]
    pub(crate) no_nsec: bool,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "Timeout per NSEC query in seconds"
    )]
    pub(crate) nsec_timeout: f64,
    #[arg(
        long,
        default_value_t = 24,
        help = "NSEC cache refresh interval in hours"
    )]
    pub(crate) nsec_refresh_hours: u64,
    #[arg(long, help = "Maximum NSEC names accepted per zone")]
    pub(crate) nsec_max_names: Option<usize>,
    #[arg(
        long,
        help = "Optional cumulative NSEC deadline per target in seconds; 0 waits for completion"
    )]
    pub(crate) nsec_max_runtime: Option<u64>,
    #[arg(
        long,
        help = "Disable direct incremental Certificate Transparency monitoring"
    )]
    pub(crate) no_ct_monitor: bool,
    #[arg(long, default_value_t = 8.0, help = "CT API timeout in seconds")]
    pub(crate) ct_timeout: f64,
    #[arg(
        long,
        help = "Optional Certificate Transparency deadline per target in seconds; 0 waits for completion"
    )]
    pub(crate) ct_max_runtime: Option<u64>,
    #[arg(long, help = "Maximum CT logs inspected per scan")]
    pub(crate) ct_logs: Option<usize>,
    #[arg(long, help = "New entries read per CT log")]
    pub(crate) ct_entries: Option<usize>,
    #[arg(long, help = "Historical CT entries read on the first pass")]
    pub(crate) ct_backfill: Option<usize>,
    #[arg(
        long,
        value_enum,
        default_value_t = MetadataDiscoveryArg::Auto,
        help = "Standardized .well-known discovery: auto, off, or all validated Web hosts"
    )]
    pub(crate) metadata_discovery: MetadataDiscoveryArg,
    #[arg(
        long,
        help = "Disable HTTP, HTML, JavaScript, and source-map extraction"
    )]
    pub(crate) no_web: bool,
    #[arg(long, help = "Maximum Web hosts inspected")]
    pub(crate) web_hosts: Option<usize>,
    #[arg(
        long,
        default_value_t = 5.0,
        help = "HTTP timeout per request in seconds"
    )]
    pub(crate) web_timeout: f64,
    #[arg(
        long,
        help = "Optional cumulative Web and JavaScript deadline per target in seconds; 0 waits for completion"
    )]
    pub(crate) web_max_runtime: Option<u64>,
    #[arg(
        long,
        default_value_t = 24,
        help = "Web cache refresh interval in hours"
    )]
    pub(crate) web_refresh_hours: u64,
    #[arg(
        long,
        default_value_t = 8,
        help = "Web hosts inspected concurrently (1-16)"
    )]
    pub(crate) web_concurrency: usize,
    #[arg(
        long,
        default_value_t = 262_144,
        help = "Maximum bytes read from each Web resource"
    )]
    pub(crate) web_max_bytes: usize,
    #[arg(
        long,
        help = "Maximum JS, JSON, or source-map assets followed per host"
    )]
    pub(crate) web_assets: Option<usize>,
    #[arg(
        long,
        help = "Optional maximum runtime per domain in seconds; 0 lets the scan finish"
    )]
    pub(crate) max_runtime: Option<u64>,
    #[arg(
        long,
        default_value_t = 30,
        help = "Persistent checkpoint interval in seconds"
    )]
    pub(crate) checkpoint_every: u64,
    #[arg(
        long,
        num_args = 0..=1,
        default_missing_value = "latest",
        help = "Resume a scan; without a value, use the latest checkpoint"
    )]
    pub(crate) resume: Option<String>,
    #[arg(long, help = "Disable final trusted-resolver consensus")]
    pub(crate) no_trusted_validation: bool,
    #[arg(long, help = "Write one final pretty JSON document")]
    pub(crate) json: bool,
    #[arg(long, help = "Write one compact final JSON object per domain")]
    pub(crate) jsonl: bool,
    #[arg(
        long,
        help = "Write finalized finding events as JSONL after each domain completes classification"
    )]
    pub(crate) stream_jsonl: bool,
    #[arg(
        long,
        conflicts_with_all = ["json", "jsonl", "stream_jsonl"],
        help = "Write only final discovered FQDNs, one sorted name per line"
    )]
    pub(crate) show: bool,
    #[arg(short = 'o', long, help = "Write final scan results to a file")]
    pub(crate) output: Option<PathBuf>,
    #[arg(long, help = "Write one final result file per domain")]
    pub(crate) output_dir: Option<PathBuf>,
    #[arg(
        short = 'v',
        long,
        action = clap::ArgAction::Count,
        conflicts_with = "quiet",
        help = "Show degraded source details; use -vv for every technical source status"
    )]
    pub(crate) verbose: u8,
    #[arg(
        short,
        long,
        visible_alias = "silent",
        conflicts_with = "verbose",
        help = "Suppress all human findings, progress, and summary output"
    )]
    pub(crate) quiet: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    #[arg(long, help = "Restrict inventory to one domain")]
    pub(crate) domain: Option<String>,
    #[arg(
        long,
        visible_alias = "all-states",
        conflicts_with = "only_live",
        help = "Include retained historical and unverified inventory rows"
    )]
    pub(crate) all: bool,
    #[arg(
        long,
        conflicts_with = "all",
        help = "Compatibility option; live validations are already the default"
    )]
    pub(crate) only_live: bool,
    #[arg(long, help = "Write pretty JSON")]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct RefreshArgs {
    #[arg(help = "Authorized target domain")]
    pub(crate) target: String,
    #[command(flatten)]
    pub(crate) dns: DnsArgs,
    #[arg(
        long,
        default_value_t = 86_400,
        help = "Compatibility option; positive answers are retained permanently"
    )]
    pub(crate) ttl_cap: u32,
    #[arg(
        long,
        default_value_t = 300,
        help = "Requested negative-cache lifetime in seconds"
    )]
    pub(crate) negative_ttl: u32,
    #[arg(
        long,
        default_value_t = 0,
        help = "Optional global refresh deadline in seconds; 0 waits for completion"
    )]
    pub(crate) max_runtime: u64,
    #[arg(
        long,
        default_value_t = 256,
        help = "Inventory names resolved and persisted per batch (1-4096)"
    )]
    pub(crate) batch_size: usize,
    #[arg(
        short,
        long,
        visible_alias = "silent",
        help = "Suppress refresh progress on stderr"
    )]
    pub(crate) quiet: bool,
}

#[derive(Debug, Args)]
pub(crate) struct HistoryArgs {
    #[arg(long, default_value_t = 20, help = "Maximum scan records to display")]
    pub(crate) limit: usize,
}

#[derive(Debug, Subcommand)]
pub(crate) enum CacheAction {
    /// Remove expired negatives and abandoned temporary candidate queues.
    Prune,
}

#[derive(Debug, Args)]
pub(crate) struct KnowledgeArgs {
    #[arg(
        long,
        default_value_t = 100,
        help = "Maximum learned entries to display"
    )]
    pub(crate) limit: usize,
}

#[derive(Debug, Args)]
pub(crate) struct SourcesArgs {
    #[arg(long, help = "Write pretty JSON")]
    pub(crate) json: bool,
    #[arg(long, help = "Perform live connector contract and reachability checks")]
    pub(crate) check: bool,
    #[arg(
        long,
        default_value = "your-domain.example",
        help = "Authorized domain used by --check"
    )]
    pub(crate) target: String,
    #[arg(
        long,
        default_value_t = 20.0,
        help = "Timeout per connector in seconds"
    )]
    pub(crate) timeout: f64,
    #[arg(
        long,
        default_value_t = 8,
        help = "Connectors checked concurrently (1-32)"
    )]
    pub(crate) concurrency: usize,
}

#[derive(Debug, Args)]
pub(crate) struct ExplainArgs {
    #[arg(help = "Fully qualified domain name to explain")]
    pub(crate) fqdn: String,
    #[arg(long, help = "Write pretty JSON")]
    pub(crate) json: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BenchmarkAction {
    /// Exercise candidate generation, SQLite, scheduling, and loopback DNS.
    CandidatePipeline(CandidatePipelineBenchmarkArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CandidatePipelineBenchmarkArgs {
    #[arg(
        long,
        help = "Fresh path where Rust generates the deterministic candidate fixture"
    )]
    pub(crate) wordlist: PathBuf,
    #[arg(
        long,
        default_value_t = 10_000_000,
        help = "Number of unique candidates to generate and process (1-10000000)"
    )]
    pub(crate) candidates: usize,
    #[arg(
        long,
        default_value_t = 4_096,
        help = "Maximum candidates persisted and scheduled per wave (1-50000)"
    )]
    pub(crate) batch_size: usize,
    #[arg(
        long,
        default_value_t = 128,
        help = "Concurrent candidate DNS classifications (1-60000)"
    )]
    pub(crate) concurrency: usize,
    #[arg(
        long,
        default_value_t = 2.0,
        help = "Per-query loopback DNS timeout in seconds (maximum 60)"
    )]
    pub(crate) timeout: f64,
    #[arg(long, help = "Fresh campaign identifier recorded in the result")]
    pub(crate) campaign_id: String,
    #[arg(long, help = "Fresh path for the atomically published JSON result")]
    pub(crate) output: PathBuf,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ResolverAction {
    /// Test resolver correctness and consistency.
    Test(ResolverTestArgs),
    /// Benchmark the native DNS transport against a controlled loopback server.
    Benchmark(ResolverBenchmarkArgs),
}

#[derive(Debug, Args)]
pub(crate) struct ResolverTestArgs {
    #[arg(
        value_delimiter = ',',
        help = "Comma-separated resolver IP addresses to test"
    )]
    pub(crate) resolvers: Vec<IpAddr>,
    #[arg(
        long,
        default_value_t = 3.0,
        help = "Timeout per resolver test in seconds"
    )]
    pub(crate) timeout: f64,
    #[arg(long, help = "Write pretty JSON")]
    pub(crate) json: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ResolverBenchmarkArgs {
    #[arg(
        long,
        default_value_t = 100_000,
        help = "Number of loopback DNS queries"
    )]
    pub(crate) queries: usize,
    #[arg(
        long,
        default_value_t = 2_000,
        help = "Concurrent loopback DNS queries"
    )]
    pub(crate) concurrency: usize,
    #[arg(long, default_value_t = 2.0, help = "Benchmark timeout in seconds")]
    pub(crate) timeout: f64,
    #[arg(long, help = "Write pretty JSON")]
    pub(crate) json: bool,
    #[arg(short = 'o', long, help = "Write the benchmark report to a file")]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ImportFormat {
    Auto,
    Json,
    Jsonl,
    Text,
    DnsText,
}

#[derive(Debug, Args)]
pub(crate) struct ImportArgs {
    #[arg(help = "Domain that owns the imported names")]
    pub(crate) domain: String,
    #[arg(help = "Input file, or - for standard input")]
    pub(crate) input: PathBuf,
    #[arg(long, value_enum, default_value_t = ImportFormat::Auto, help = "Input format")]
    pub(crate) format: ImportFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ExportFormat {
    Jsonl,
    Csv,
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[arg(long, help = "Restrict export to one domain")]
    pub(crate) domain: Option<String>,
    #[arg(long, help = "Export only live validations")]
    pub(crate) only_live: bool,
    #[arg(long, value_enum, default_value_t = ExportFormat::Jsonl, help = "Export format")]
    pub(crate) format: ExportFormat,
    #[arg(
        short = 'o',
        long,
        help = "Write output to a file instead of standard output"
    )]
    pub(crate) output: Option<PathBuf>,
}
