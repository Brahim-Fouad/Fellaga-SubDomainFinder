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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    #[serde(default)]
    pub wildcard_verdict: WildcardVerdict,
    #[serde(default)]
    pub owner_proofs: BTreeSet<OwnerProof>,
    #[serde(default)]
    pub generation_path: Vec<String>,
    #[serde(default)]
    pub discovery_score: Option<f64>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum WildcardVerdict {
    ExactOwner,
    Synthesized,
    Ambiguous,
    #[default]
    NotProfiled,
}

impl WildcardVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactOwner => "exact_owner",
            Self::Synthesized => "synthesized",
            Self::Ambiguous => "ambiguous",
            Self::NotProfiled => "not_profiled",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum OwnerProof {
    Nxname,
    Nsec,
    Nsec3,
    AuthoritativeDistinct,
    ControlDistribution,
    None,
}

impl OwnerProof {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nxname => "nxname",
            Self::Nsec => "nsec",
            Self::Nsec3 => "nsec3",
            Self::AuthoritativeDistinct => "authoritative_distinct",
            Self::ControlDistribution => "control_distribution",
            Self::None => "none",
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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
    #[serde(default)]
    pub scheduler_metrics: SchedulerMetrics,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    QueueDrained,
    PosteriorLowYield,
    BudgetExhausted,
    NetworkDegraded,
    Interrupted,
}

impl StopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueDrained => "queue_drained",
            Self::PosteriorLowYield => "posterior_low_yield",
            Self::BudgetExhausted => "budget_exhausted",
            Self::NetworkDegraded => "network_degraded",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SchedulerMetrics {
    /// DNS resolver operations observed during the scan. One logical lookup
    /// can still produce a UDP retry or TCP fallback at the transport layer.
    #[serde(alias = "dns_packets")]
    pub dns_queries: u64,
    /// TCP connection attempts directly measured by active enrichment phases.
    /// DNS-library fallbacks and passive-provider transports are not included.
    pub tcp_connections: u64,
    /// HTTP requests directly measured by metadata and Web/JavaScript phases.
    pub http_requests: u64,
    /// TLS/STARTTLS connection attempts, including bounded no-SNI probes.
    pub tls_connections: u64,
    /// Response body bytes retained by measured HTTP enrichment phases. This
    /// intentionally excludes headers, TLS framing and provider-side caches.
    pub bytes_transferred: u64,
    pub exclusive_discoveries: usize,
    pub exploration_actions: usize,
    pub backoffs: usize,
    pub effective_qps_min: f64,
    pub effective_qps_max: f64,
    pub remaining_yield_upper_bound: f64,
    pub stop_reason: Option<StopReason>,
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

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finding_deserializes_without_v8_or_v9_fields() {
        let value = json!({
            "fqdn": "api.example.com",
            "records": [{"record_type": "A", "value": "192.0.2.10", "ttl": 60}],
            "sources": ["dns"],
            "wildcard": false,
            "from_cache": false,
            "confidence": {"score": 90, "label": "high", "reasons": ["live DNS"]}
        });

        let finding: Finding = serde_json::from_value(value).expect("legacy Finding JSON");
        assert_eq!(finding.fqdn, "api.example.com");
        assert_eq!(finding.state, ObservationState::Unverified);
        assert!(finding.last_verified_at.is_none());
        assert!(finding.evidence_families.is_empty());
        assert!(!finding.authoritative_validation);
        assert_eq!(finding.wildcard_verdict, WildcardVerdict::NotProfiled);
        assert!(finding.owner_proofs.is_empty());
        assert!(finding.generation_path.is_empty());
        assert!(finding.discovery_score.is_none());
    }

    #[test]
    fn scan_result_deserializes_without_optional_or_scheduler_fields() {
        let value = json!({
            "scan_id": 7,
            "domain": "example.com",
            "candidates": 1,
            "resolved_from_network": 1,
            "cache_hits": 0,
            "duration_ms": 12,
            "wildcard_detected": false,
            "findings": [],
            "axfr_attempts": [],
            "tls_certificates": [],
            "dns_edges": [],
            "child_zones": [],
            "service_endpoints": [],
            "web_observations": [],
            "dnssec_walks": [],
            "ct_monitor": {
                "logs_checked": 0,
                "entries_processed": 0,
                "names": [],
                "globally_indexed_names": 0,
                "failures": 0,
                "duration_ms": 0
            },
            "pipeline": {
                "rounds": 0,
                "events_enqueued": 0,
                "duplicates_suppressed": 0,
                "names_validated": 0,
                "budget_exhausted": false
            },
            "resolver_metrics": [],
            "warnings": []
        });

        let scan: ScanResult = serde_json::from_value(value).expect("legacy ScanResult JSON");
        assert_eq!(scan.status, "completed");
        assert!(!scan.resumable);
        assert!(scan.phase_timings.is_empty());
        assert_eq!(scan.scheduler_metrics.dns_queries, 0);
        assert!(scan.scheduler_metrics.stop_reason.is_none());
    }

    #[test]
    fn scheduler_metrics_accepts_the_v09_preview_packet_field() {
        let metrics: SchedulerMetrics = serde_json::from_value(json!({"dns_packets": 9})).unwrap();
        assert_eq!(metrics.dns_queries, 9);
        assert_eq!(metrics.http_requests, 0);
    }
}
