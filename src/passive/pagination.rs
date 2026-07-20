//! Connector result checkpointing and durable numeric pagination contracts.

use crate::source_contract::{PassivePaginationPage, PassivePaginationState};
use crate::util::domain_hash;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;
#[derive(Debug)]
pub struct PassiveFetchResult {
    pub names: BTreeSet<String>,
    pub partial_warning: Option<String>,
    /// Names decoded by the provider before applying the working-set cap.
    /// Paginated connectors sum the distinct count of each decoded page, so a
    /// provider that repeats a name across pages may count it more than once.
    pub decoded_names: usize,
    /// The connector decoded more distinct names than it retained in its
    /// in-memory working set. A configured page sink still receives the full
    /// decoded pages before this cap is applied.
    pub working_set_truncated: bool,
}

pub type PassivePageSink = Arc<dyn Fn(&BTreeSet<String>) -> Result<()> + Send + Sync>;

/// Deadline-aware durable page callback. Implementations must call
/// `control.ensure_active()` before expensive work and stop promptly once
/// `control.is_cancelled()` is true.
pub type ControlledPassivePageSink =
    Arc<dyn Fn(&BTreeSet<String>, &PassiveSinkControl) -> Result<()> + Send + Sync>;

#[derive(Clone)]
pub struct PassiveSinkControl {
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
}

impl PassiveSinkControl {
    pub(super) fn new(deadline: Option<Instant>) -> Self {
        Self {
            deadline,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub fn ensure_active(&self) -> Result<()> {
        if self.is_cancelled() {
            bail!("persistance passive annulée à son échéance");
        }
        Ok(())
    }

    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassivePaginationContract {
    pub lane: &'static str,
    pub contract_version: u32,
    pub query_hash: String,
}

pub type PassivePaginationPageSink =
    Arc<dyn Fn(&PassivePaginationPage, &BTreeSet<String>) -> Result<()> + Send + Sync>;
pub type PassivePaginationFinishSink = Arc<dyn Fn() -> Result<()> + Send + Sync>;

/// Scanner-owned durable callbacks and the state loaded before the connector
/// starts. The value is scoped to exactly one async connector task, preventing
/// concurrent passive sources from observing each other's resume point.
#[derive(Clone)]
pub struct PassivePaginationContext {
    lanes: BTreeMap<&'static str, PassivePaginationLaneContext>,
}

#[derive(Clone)]
struct PassivePaginationLaneContext {
    contract: PassivePaginationContract,
    resume: Option<PassivePaginationState>,
    page_sink: PassivePaginationPageSink,
    finish_sink: PassivePaginationFinishSink,
}

impl PassivePaginationContext {
    pub fn new(
        contract: PassivePaginationContract,
        resume: Option<PassivePaginationState>,
        page_sink: PassivePaginationPageSink,
        finish_sink: PassivePaginationFinishSink,
    ) -> Self {
        let lane = contract.lane;
        Self {
            lanes: BTreeMap::from([(
                lane,
                PassivePaginationLaneContext {
                    contract,
                    resume,
                    page_sink,
                    finish_sink,
                },
            )]),
        }
    }

    pub fn empty() -> Self {
        Self {
            lanes: BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        contract: PassivePaginationContract,
        resume: Option<PassivePaginationState>,
        page_sink: PassivePaginationPageSink,
        finish_sink: PassivePaginationFinishSink,
    ) -> Result<()> {
        let lane = contract.lane;
        if self.lanes.contains_key(lane) {
            bail!("voie de pagination passive dupliquée: {lane}");
        }
        self.lanes.insert(
            lane,
            PassivePaginationLaneContext {
                contract,
                resume,
                page_sink,
                finish_sink,
            },
        );
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.lanes.is_empty()
    }
}

/// Returns a durable contract only for connectors whose continuation is a
/// stable numeric position. Opaque-cursor connectors intentionally return
/// an empty list and restart from their first request after interruption.
pub fn numeric_pagination_contracts(source: &str, domain: &str) -> Vec<PassivePaginationContract> {
    match source {
        "viewdns" => vec![PassivePaginationContract {
            lane: "pages",
            contract_version: 1,
            query_hash: domain_hash(&format!(
                "viewdns:pages:v1:{}:output=json",
                domain.trim_end_matches('.').to_ascii_lowercase()
            )),
        }],
        _ => Vec::new(),
    }
}

/// Compatibility helper for single-lane connectors. New scanner integration
/// uses `numeric_pagination_contracts` so multiple independent lanes can be
/// resumed and finalized as one source refresh.
pub fn numeric_pagination_contract(
    source: &str,
    domain: &str,
) -> Option<PassivePaginationContract> {
    numeric_pagination_contracts(source, domain)
        .into_iter()
        .next()
}

#[derive(Default)]
pub(super) struct PartialResultState {
    pub(super) names: BTreeSet<String>,
    pub(super) committed_pages: usize,
    pub(super) decoded_names: usize,
    pub(super) working_set_truncated: bool,
    pub(super) persistence_error: Option<String>,
}

#[derive(Clone)]
pub(super) struct PartialResultCheckpoint {
    state: Arc<StdMutex<PartialResultState>>,
    working_set_limit: usize,
    page_sink: Option<ControlledPassivePageSink>,
    sink_control: PassiveSinkControl,
}

impl PartialResultCheckpoint {
    pub(super) fn new(
        working_set_limit: usize,
        page_sink: Option<ControlledPassivePageSink>,
        sink_control: PassiveSinkControl,
    ) -> Self {
        Self {
            state: Arc::new(StdMutex::new(PartialResultState::default())),
            working_set_limit,
            page_sink,
            sink_control,
        }
    }

    fn record_page(&self, names: &BTreeSet<String>, persistence_error: Option<String>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.committed_pages = state.committed_pages.saturating_add(1);
        state.decoded_names = state.decoded_names.saturating_add(names.len());
        state.working_set_truncated |= extend_btree_set_bounded(
            &mut state.names,
            names.iter().cloned(),
            self.working_set_limit,
        );
        if state.persistence_error.is_none() {
            state.persistence_error = persistence_error;
        }
    }

    fn commit_page(&self, names: &BTreeSet<String>) {
        let persistence_error = self
            .page_sink
            .as_ref()
            .and_then(|sink| sink(names, &self.sink_control).err())
            .map(|error| format!("persistance SQLite de page passive: {error:#}"));
        self.record_page(names, persistence_error);
    }

    pub(super) fn persist_non_paginated_result(&self, names: &BTreeSet<String>) {
        if !self.should_persist_non_paginated_result(names) {
            return;
        }
        let persistence_error = self
            .page_sink
            .as_ref()
            .and_then(|sink| sink(names, &self.sink_control).err())
            .map(|error| format!("persistance SQLite du résultat passif: {error:#}"));
        if let Some(persistence_error) = persistence_error {
            self.record_persistence_error(persistence_error);
        }
    }

    pub(super) fn should_persist_non_paginated_result(&self, names: &BTreeSet<String>) -> bool {
        self.page_sink.is_some()
            && !names.is_empty()
            && self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .committed_pages
                == 0
    }

    pub(super) fn record_persistence_error(&self, persistence_error: String) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.persistence_error.is_none() {
            state.persistence_error = Some(persistence_error);
        }
    }

    pub(super) fn cancel_persistence(&self) {
        self.sink_control.cancel();
    }

    pub(super) fn snapshot(&self) -> PartialResultState {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        PartialResultState {
            names: state.names.clone(),
            committed_pages: state.committed_pages,
            decoded_names: state.decoded_names,
            working_set_truncated: state.working_set_truncated,
            persistence_error: state.persistence_error.clone(),
        }
    }
}

fn extend_btree_set_bounded(
    target: &mut BTreeSet<String>,
    names: impl IntoIterator<Item = String>,
    limit: usize,
) -> bool {
    let mut truncated = false;
    for name in names {
        if target.contains(&name) {
            continue;
        }
        if target.len() < limit {
            target.insert(name);
        } else {
            truncated = true;
        }
    }
    truncated
}

tokio::task_local! {
    pub(super) static PARTIAL_RESULT_CHECKPOINT: PartialResultCheckpoint;
    pub(super) static PASSIVE_PAGINATION_CONTEXT: Option<PassivePaginationContext>;
}

pub(super) fn numeric_pagination_resume(
    contract: &PassivePaginationContract,
) -> Option<PassivePaginationState> {
    PASSIVE_PAGINATION_CONTEXT
        .try_with(|context| {
            context.as_ref().and_then(|context| {
                context
                    .lanes
                    .get(contract.lane)
                    .filter(|lane| lane.contract == *contract)
                    .and_then(|lane| lane.resume.clone())
            })
        })
        .ok()
        .flatten()
}

/// Reports a durable lane completion left between the connector's last page
/// and the scanner's atomic source-level publication. Numeric connectors use
/// this generic guard to avoid replaying an already completed lane.
pub(super) fn numeric_pagination_is_complete(contract: &PassivePaginationContract) -> bool {
    PASSIVE_PAGINATION_CONTEXT
        .try_with(|context| {
            context
                .as_ref()
                .and_then(|context| context.lanes.get(contract.lane))
                .is_some_and(|lane| {
                    lane.contract == *contract
                        && lane.resume.as_ref().is_some_and(|state| state.done)
                })
        })
        .unwrap_or(false)
}

/// Commits a validated numeric page through the scanner-owned SQLite
/// transaction before exposing it to the in-memory partial result. Without a
/// scan context (for example `sources --check`) it behaves like a normal page.
pub(super) fn commit_numeric_result_page(
    accumulated: &mut BTreeSet<String>,
    page_names: BTreeSet<String>,
    contract: &PassivePaginationContract,
    progress: &PassivePaginationPage,
) -> Result<()> {
    let durable_context = PASSIVE_PAGINATION_CONTEXT
        .try_with(|context| context.clone())
        .ok()
        .flatten();
    let Some(context) = durable_context else {
        commit_result_page(accumulated, page_names);
        return Ok(());
    };
    let lane = context
        .lanes
        .get(contract.lane)
        .filter(|lane| lane.contract == *contract)
        .context("contexte de pagination passive incompatible avec le connecteur")?;
    (lane.page_sink)(progress, &page_names).context("commit atomique de pagination passive")?;
    if PARTIAL_RESULT_CHECKPOINT
        .try_with(|checkpoint| {
            checkpoint.record_page(&page_names, None);
            extend_btree_set_bounded(
                accumulated,
                page_names.iter().cloned(),
                checkpoint.working_set_limit,
            )
        })
        .is_err()
    {
        accumulated.extend(page_names);
    }
    Ok(())
}

pub(super) fn finish_numeric_pagination(contract: &PassivePaginationContract) -> Result<()> {
    let context = PASSIVE_PAGINATION_CONTEXT
        .try_with(|context| context.clone())
        .ok()
        .flatten();
    let Some(context) = context else {
        return Ok(());
    };
    let lane = context
        .lanes
        .get(contract.lane)
        .filter(|lane| lane.contract == *contract)
        .context("contexte de fin de pagination passive incompatible")?;
    (lane.finish_sink)().context("finalisation de pagination passive")
}

/// Commits one fully decoded provider page both to the connector accumulator
/// and to a task-local checkpoint. If the total connector budget expires while
/// the next page is in flight, `fetch` can still return every committed page.
pub(super) fn commit_result_page(accumulated: &mut BTreeSet<String>, page: BTreeSet<String>) {
    if page.is_empty() {
        return;
    }
    if PARTIAL_RESULT_CHECKPOINT
        .try_with(|checkpoint| {
            checkpoint.commit_page(&page);
            extend_btree_set_bounded(
                accumulated,
                page.iter().cloned(),
                checkpoint.working_set_limit,
            )
        })
        .is_err()
    {
        accumulated.extend(page);
    }
}
