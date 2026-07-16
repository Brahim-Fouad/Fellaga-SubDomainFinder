use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    Live,
    Historical,
    #[default]
    Unverified,
}

impl ObservationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Historical => "historical",
            Self::Unverified => "unverified",
        }
    }
}

impl fmt::Display for ObservationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFamily {
    Authoritative,
    LiveDns,
    CertificateTransparency,
    PassiveDns,
    WebArchive,
    WebCrawl,
    CodeSearch,
    Aggregator,
}

impl EvidenceFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::LiveDns => "live_dns",
            Self::CertificateTransparency => "certificate_transparency",
            Self::PassiveDns => "passive_dns",
            Self::WebArchive => "web_archive",
            Self::WebCrawl => "web_crawl",
            Self::CodeSearch => "code_search",
            Self::Aggregator => "aggregator",
        }
    }
}

impl fmt::Display for EvidenceFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedHost {
    pub fqdn: String,
    pub records: Vec<DnsRecord>,
    pub from_cache: bool,
    #[serde(default)]
    pub last_verified_at: Option<i64>,
    #[serde(default)]
    pub authoritative_validation: bool,
    #[serde(default = "default_resolver_count")]
    pub resolver_count: u16,
}

const fn default_resolver_count() -> u16 {
    1
}

impl ResolvedHost {
    pub fn signature(&self) -> BTreeSet<String> {
        self.records
            .iter()
            .map(|record| format!("{}:{}", record.record_type, record.value))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub fqdn: String,
    pub records: Vec<DnsRecord>,
    pub sources: BTreeSet<String>,
    pub wildcard: bool,
    pub from_cache: bool,
    pub confidence: ConfidenceAssessment,
    #[serde(default)]
    pub state: ObservationState,
    #[serde(default)]
    pub last_verified_at: Option<i64>,
    #[serde(default)]
    pub evidence_families: BTreeSet<EvidenceFamily>,
    #[serde(default)]
    pub authoritative_validation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryEntry {
    pub fqdn: String,
    pub state: ObservationState,
    pub last_verified_at: Option<i64>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub times_seen: i64,
    pub sources: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidenceAssessment {
    pub score: u8,
    pub label: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PipelineMetrics {
    pub rounds: usize,
    pub events_enqueued: usize,
    pub duplicates_suppressed: usize,
    pub names_validated: usize,
    pub budget_exhausted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolverMetric {
    pub resolver: String,
    pub requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub average_ms: u64,
    pub consecutive_failures: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverTestResult {
    pub resolver: String,
    pub usable: bool,
    pub hijacks_nxdomain: bool,
    pub dnssec_records: bool,
    pub validates_dnssec: bool,
    pub consistent: bool,
    pub average_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBenchmarkResult {
    pub queries: usize,
    pub completed: usize,
    pub failures: usize,
    pub concurrency: usize,
    pub duration_ms: u128,
    pub queries_per_second: f64,
    pub loss_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxfrAttempt {
    pub nameserver: String,
    pub address: String,
    pub status: AxfrStatus,
    pub error: Option<String>,
    pub records: Vec<DnsRecord>,
    pub names: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AxfrStatus {
    Success,
    Refused,
    Empty,
    Timeout,
    ProtocolError,
}

impl AxfrStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Refused => "refused",
            Self::Empty => "empty",
            Self::Timeout => "timeout",
            Self::ProtocolError => "protocol_error",
        }
    }
}

impl fmt::Display for AxfrStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertificateObservation {
    pub endpoint: String,
    pub port: u16,
    pub fingerprint_sha256: String,
    pub names: BTreeSet<String>,
    pub from_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoveryEdge {
    pub owner: String,
    pub record_type: String,
    pub value: String,
    pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceEndpoint {
    pub hostname: String,
    pub port: u16,
    pub transport: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebObservation {
    pub url: String,
    pub status: u16,
    pub names: BTreeSet<String>,
    pub from_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecWalkResult {
    pub zone: String,
    pub nameserver: String,
    pub status: String,
    pub queries: usize,
    pub names: BTreeSet<String>,
    pub from_cache: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CtMonitorResult {
    pub logs_checked: usize,
    pub entries_processed: usize,
    pub names: BTreeSet<String>,
    pub globally_indexed_names: usize,
    pub failures: usize,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PhaseTiming {
    pub phase: String,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: i64,
    pub domain: String,
    #[serde(default = "default_completed_status")]
    pub status: String,
    #[serde(default)]
    pub resumable: bool,
    pub candidates: usize,
    pub resolved_from_network: usize,
    pub cache_hits: usize,
    pub duration_ms: u128,
    #[serde(default)]
    pub phase_timings: Vec<PhaseTiming>,
    pub wildcard_detected: bool,
    pub findings: Vec<Finding>,
    pub axfr_attempts: Vec<AxfrAttempt>,
    pub tls_certificates: Vec<TlsCertificateObservation>,
    pub dns_edges: Vec<DiscoveryEdge>,
    pub child_zones: BTreeSet<String>,
    pub service_endpoints: Vec<ServiceEndpoint>,
    pub web_observations: Vec<WebObservation>,
    pub dnssec_walks: Vec<DnssecWalkResult>,
    pub ct_monitor: CtMonitorResult,
    pub pipeline: PipelineMetrics,
    pub resolver_metrics: Vec<ResolverMetric>,
    pub warnings: Vec<String>,
}

fn default_completed_status() -> String {
    "completed".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub database: String,
    pub scans: i64,
    pub known_subdomains: i64,
    pub active_subdomains: i64,
    pub live_subdomains: i64,
    pub historical_subdomains: i64,
    pub unverified_subdomains: i64,
    pub dns_verifications: i64,
    pub learned_words: i64,
    pub learned_patterns: i64,
    pub passive_cache_entries: i64,
    pub builtin_candidates: i64,
    pub cache_entries: i64,
    pub fresh_cache_entries: i64,
    pub axfr_attempts: i64,
    pub successful_axfr: i64,
    pub tls_certificate_entries: i64,
    pub discovery_edges: i64,
    pub service_endpoints: i64,
    pub child_zones: i64,
    pub candidate_generators: i64,
    pub web_cache_entries: i64,
    pub dnssec_zone_entries: i64,
    pub ct_log_cursors: i64,
    pub wildcard_cache_entries: i64,
    pub normalized_names: i64,
    pub normalized_observations: i64,
    pub global_ct_names: i64,
    pub resolver_profiles: i64,
    pub generator_bandits: i64,
    pub top_words: Vec<BTreeMap<String, serde_json::Value>>,
}
