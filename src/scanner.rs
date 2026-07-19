use crate::axfr::attempt_axfr;
use crate::candidate::{CandidateProposal, MutationRule, generate_contextual_with_rules};
use crate::confidence::{assess_with_context as assess_confidence, evidence_families};
use crate::ct_monitor::{
    CtProgressCallback, CtProgressEvent, monitor_ct_logs_bounded_with_progress_and_limit,
};
use crate::db::{CachedAnswer, Database, IpHostnameCacheEntry};
use crate::discovery::discover_dns_graph;
use crate::dns::{DnsEngine, DnsResolutionOutcome, WildcardProbeOutcome};
use crate::dnssec::discover_nsec_bounded;
use crate::dnssec_proof::{DnssecOwnerState, DnssecProofAssessment, DnssecProofKind};
use crate::intelligence::{IntelligenceConfig, NameObservation, learn_and_generate};
use crate::metadata_discovery::{MetadataDiscoveryConfig, discover_metadata};
use crate::model::{
    CtMonitorResult, DiscoveryEdge, DnssecWalkResult, Finding, OwnerProof, PhaseTiming,
    PipelineMetrics, ResolvedHost, ResolverMetric, ScanResult, SchedulerMetrics, ServiceEndpoint,
    StopReason, WebObservation, WildcardVerdict,
};
use crate::passive::{
    ApiKeyStore, PassiveFetchResult, PassivePageSink, PassivePaginationContext,
    PassivePaginationFinishSink, PassivePaginationPageSink, current_commoncrawl_endpoint,
    fetch_detailed_bounded_with_pagination as fetch_passive_paginated,
    fetch_detailed_bounded_with_sink as fetch_passive_bounded, numeric_pagination_contracts,
    sanitize_external_error, seed_commoncrawl_endpoint, source_metadata, source_policy,
    with_external_target_guard,
};
use crate::pipeline::DiscoveryPipeline;
use crate::tls::discover as discover_tls_certificates;
use crate::util::{
    domain_hash, labels_from_name, learnable_label, learnable_relative_name, normalize_domain,
    normalize_observed_name, now_epoch,
};
use crate::web_discovery::discover_web_bounded;
use anyhow::{Context, Result, bail};
use futures_util::{FutureExt, StreamExt, stream, stream::FuturesUnordered};
use hickory_net::proto::rr::RecordType;
use serde_json::json;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

const DNSSEC_WILDCARD_SUSPECT_CAP: usize = 4;
const METADATA_PHASE_BUDGET_CAP: Duration = Duration::from_secs(30);
const METADATA_DNS_CONCURRENCY: usize = 4;
const ENRICHMENT_VALIDATION_BATCH_SIZE: usize = 4_000;
const PASSIVE_REFRESH_LEASE_GRACE: Duration = Duration::from_secs(60);
const INTERNETDB_PROVIDER: &str = "shodan-internetdb";
const INTERNETDB_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const INTERNETDB_MAX_AGGREGATE_NAMES: usize = 2_000;
const INTERNETDB_MAX_HOSTNAMES_PER_IP: usize = 256;
const INTERNETDB_ERROR_RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
static PASSIVE_REFRESH_LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

mod active_validation;
mod api;
mod candidates;
mod enrichment;
mod execution;
mod finalization;
mod findings;
mod initial_discovery;
mod lifecycle;
mod passive_phase;
mod plan;
mod policy;
mod refresh;
mod resolution;
mod run;
mod support;
mod validation;
mod wildcard;

pub use api::{PassiveSourceOutcome, ProgressCallback, ProgressEvent, ScanOptions};
pub use refresh::{
    RefreshOptions, RefreshProgress, RefreshProgressCallback, RefreshResult, refresh_inventory,
    refresh_inventory_bounded, refresh_inventory_with_trusted,
};

use execution::*;
use lifecycle::*;
use plan::*;
use policy::*;
use resolution::*;
use support::*;

#[derive(Clone)]
pub struct Scanner {
    database: Database,
    dns: DnsEngine,
    trusted_dns: Option<DnsEngine>,
    options: ScanPlan,
    progress: Option<ProgressCallback>,
    passive_request_slots: Arc<tokio::sync::Semaphore>,
}
#[cfg(test)]
#[path = "scanner/tests.rs"]
mod tests;
