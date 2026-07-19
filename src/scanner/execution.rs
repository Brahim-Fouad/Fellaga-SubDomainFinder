use super::*;

/// Immutable identity shared by every phase of one scan.
///
/// Keeping this separate from the mutable phase outputs makes the phase
/// boundaries explicit without cloning the scanner, target, or timer.
pub(super) struct ScanExecution<'scan> {
    pub(super) scanner: &'scan Scanner,
    pub(super) scan_id: i64,
    pub(super) domain: &'scan str,
    pub(super) started: Instant,
}

impl<'scan> ScanExecution<'scan> {
    pub(super) fn new(
        scanner: &'scan Scanner,
        scan_id: i64,
        domain: &'scan str,
        started: Instant,
    ) -> Self {
        Self {
            scanner,
            scan_id,
            domain,
            started,
        }
    }
}

/// Output of passive, CT, and AXFR discovery.
pub(super) struct InitialDiscoveryState<'scan> {
    pub(super) execution: ScanExecution<'scan>,
    pub(super) warnings: Vec<String>,
    pub(super) pipeline_metrics: PipelineMetrics,
    pub(super) phase_timings: Vec<PhaseTiming>,
    pub(super) sources: BTreeMap<String, BTreeSet<String>>,
    pub(super) passive_budget_remaining: Option<Duration>,
    pub(super) nsec_budget_remaining: Option<Duration>,
    pub(super) nsec_budget_warning_emitted: bool,
    pub(super) web_budget_remaining: Option<Duration>,
    pub(super) web_budget_exhausted: bool,
    pub(super) passive_zones_queried: BTreeSet<String>,
    pub(super) ct_task_started: Instant,
    pub(super) ct_tasks: tokio::task::JoinSet<Result<(CtMonitorResult, Vec<String>)>>,
    pub(super) ct_task_pending: bool,
    pub(super) ct_monitor: CtMonitorResult,
    pub(super) axfr_attempts: Vec<crate::model::AxfrAttempt>,
}

/// Output of candidate generation, wildcard profiling, and DNS validation.
pub(super) struct ActiveValidationState<'scan> {
    pub(super) execution: ScanExecution<'scan>,
    pub(super) warnings: Vec<String>,
    pub(super) pipeline_metrics: PipelineMetrics,
    pub(super) phase_timings: Vec<PhaseTiming>,
    pub(super) sources: BTreeMap<String, BTreeSet<String>>,
    pub(super) passive_budget_remaining: Option<Duration>,
    pub(super) nsec_budget_remaining: Option<Duration>,
    pub(super) nsec_budget_warning_emitted: bool,
    pub(super) web_budget_remaining: Option<Duration>,
    pub(super) web_budget_exhausted: bool,
    pub(super) passive_zones_queried: BTreeSet<String>,
    pub(super) ct_monitor: CtMonitorResult,
    pub(super) axfr_attempts: Vec<crate::model::AxfrAttempt>,
    pub(super) active_budget_remaining: Option<Duration>,
    pub(super) recursive_budget_exhausted: bool,
    pub(super) candidate_expansion_stopped_naturally: bool,
    pub(super) root_wildcard: BTreeSet<String>,
    pub(super) wildcard_by_parent: BTreeMap<String, BTreeSet<String>>,
    pub(super) reliable_wildcard_zones: BTreeSet<String>,
    pub(super) parent_by_host: HashMap<String, String>,
    pub(super) answers: BTreeMap<String, ResolvedHost>,
    pub(super) pipeline: DiscoveryPipeline,
    pub(super) validation_rounds: usize,
    pub(super) pipeline_names_validated: usize,
    pub(super) graph_processed: BTreeSet<String>,
    pub(super) web_processed: BTreeSet<String>,
    pub(super) tls_processed: BTreeSet<String>,
    pub(super) remaining_yield_upper_bound: f64,
    pub(super) cache_hits: usize,
    pub(super) network_resolved: usize,
}

/// Output of graph, DNSSEC, Web, metadata, TLS, and recursive enrichment.
pub(super) struct EnrichmentState<'scan> {
    pub(super) execution: ScanExecution<'scan>,
    pub(super) warnings: Vec<String>,
    pub(super) pipeline_metrics: PipelineMetrics,
    pub(super) phase_timings: Vec<PhaseTiming>,
    pub(super) sources: BTreeMap<String, BTreeSet<String>>,
    pub(super) ct_monitor: CtMonitorResult,
    pub(super) axfr_attempts: Vec<crate::model::AxfrAttempt>,
    pub(super) active_budget_remaining: Option<Duration>,
    pub(super) candidate_expansion_stopped_naturally: bool,
    pub(super) root_wildcard: BTreeSet<String>,
    pub(super) wildcard_by_parent: BTreeMap<String, BTreeSet<String>>,
    pub(super) parent_by_host: HashMap<String, String>,
    pub(super) answers: BTreeMap<String, ResolvedHost>,
    pub(super) pipeline: DiscoveryPipeline,
    pub(super) validation_rounds: usize,
    pub(super) pipeline_names_validated: usize,
    pub(super) remaining_yield_upper_bound: f64,
    pub(super) cache_hits: usize,
    pub(super) network_resolved: usize,
    pub(super) dns_edges: Vec<DiscoveryEdge>,
    pub(super) child_zones: BTreeSet<String>,
    pub(super) service_endpoints: Vec<ServiceEndpoint>,
    pub(super) dnssec_walks: Vec<DnssecWalkResult>,
    pub(super) web_observations: Vec<WebObservation>,
    pub(super) measured_http_requests: u64,
    pub(super) measured_http_bytes: u64,
    pub(super) measured_tls_connections: u64,
    pub(super) tls_certificates: Vec<crate::model::TlsCertificateObservation>,
}
