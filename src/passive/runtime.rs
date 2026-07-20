//! Passive connector dispatch and bounded result execution.

use super::catalog::source_policy;
use super::config::{ApiKeyStore, sanitize_external_error};
use super::dispatch;
use super::pagination::{
    ControlledPassivePageSink, PARTIAL_RESULT_CHECKPOINT, PASSIVE_PAGINATION_CONTEXT,
    PartialResultCheckpoint, PassiveFetchResult, PassivePageSink, PassivePaginationContext,
    PassiveSinkControl,
};
use anyhow::Result;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
#[derive(Debug)]
struct SourceDeadlineExceeded {
    source: String,
    deadline: Duration,
}

impl fmt::Display for SourceDeadlineExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deadline = if self.deadline < Duration::from_secs(1) {
            format!("{}ms", self.deadline.as_millis().max(1))
        } else {
            format!("{:.0}s", self.deadline.as_secs_f64().round())
        };
        write!(
            formatter,
            "{}: délai de sécurité du connecteur atteint après {deadline}; pages terminées conservées dans le résultat courant",
            self.source
        )
    }
}

impl std::error::Error for SourceDeadlineExceeded {}

pub(super) async fn enforce_source_budget<T, F>(
    source: &str,
    budget: Duration,
    request: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    if budget.is_zero() {
        return request.await;
    }
    tokio::time::timeout(budget, request).await.map_err(|_| {
        anyhow::Error::new(SourceDeadlineExceeded {
            source: source.to_owned(),
            deadline: budget,
        })
    })?
}

#[cfg(test)]
pub(super) async fn enforce_source_budget_preserving_partial<F>(
    source: &str,
    budget: Duration,
    request: F,
) -> Result<PassiveFetchResult>
where
    F: std::future::Future<Output = Result<BTreeSet<String>>>,
{
    enforce_source_budget_preserving_partial_with_sink(
        source,
        budget,
        request,
        usize::MAX,
        None,
        None,
    )
    .await
}

#[cfg(test)]
pub(super) async fn enforce_source_budget_preserving_partial_with_sink<F>(
    source: &str,
    budget: Duration,
    request: F,
    working_set_limit: usize,
    page_sink: Option<PassivePageSink>,
    pagination_context: Option<PassivePaginationContext>,
) -> Result<PassiveFetchResult>
where
    F: std::future::Future<Output = Result<BTreeSet<String>>>,
{
    enforce_source_budget_preserving_partial_with_controlled_sink(
        source,
        budget,
        request,
        working_set_limit,
        page_sink.map(adapt_passive_page_sink),
        pagination_context,
    )
    .await
}

fn adapt_passive_page_sink(page_sink: PassivePageSink) -> ControlledPassivePageSink {
    Arc::new(move |names, control| {
        control.ensure_active()?;
        page_sink(names)
    })
}

/// Propagates cancellation when the connector future is dropped externally.
///
/// `tokio::task::JoinHandle` detaches its task when dropped, and blocking tasks
/// cannot be force-aborted once they have started. Keeping this guard alive for
/// the whole connector call makes a cooperative sink observe cancellation even
/// when its caller aborts the async future before the normal timeout branch can
/// cancel the checkpoint.
struct CancelPersistenceOnDrop(PartialResultCheckpoint);

impl Drop for CancelPersistenceOnDrop {
    fn drop(&mut self) {
        self.0.cancel_persistence();
    }
}

pub(super) async fn enforce_source_budget_preserving_partial_with_controlled_sink<F>(
    source: &str,
    budget: Duration,
    request: F,
    working_set_limit: usize,
    page_sink: Option<ControlledPassivePageSink>,
    pagination_context: Option<PassivePaginationContext>,
) -> Result<PassiveFetchResult>
where
    F: std::future::Future<Output = Result<BTreeSet<String>>>,
{
    let started = tokio::time::Instant::now();
    let sink_control =
        PassiveSinkControl::new((!budget.is_zero()).then(|| StdInstant::now() + budget));
    let checkpoint = PartialResultCheckpoint::new(working_set_limit, page_sink, sink_control);
    let _cancel_persistence_on_drop = CancelPersistenceOnDrop(checkpoint.clone());
    let result = PASSIVE_PAGINATION_CONTEXT
        .scope(
            pagination_context,
            PARTIAL_RESULT_CHECKPOINT.scope(
                checkpoint.clone(),
                enforce_source_budget(source, budget, request),
            ),
        )
        .await;
    match result {
        Err(error) => {
            if error.downcast_ref::<SourceDeadlineExceeded>().is_some() {
                checkpoint.cancel_persistence();
            }
            let partial = checkpoint.snapshot();
            if error.downcast_ref::<SourceDeadlineExceeded>().is_some() || !partial.names.is_empty()
            {
                let mut warning = format!("{error:#}");
                if let Some(persistence_error) = partial.persistence_error {
                    warning.push_str(&format!("; {persistence_error}"));
                }
                Ok(PassiveFetchResult {
                    names: partial.names,
                    partial_warning: Some(warning),
                    decoded_names: partial.decoded_names,
                    working_set_truncated: partial.working_set_truncated,
                })
            } else {
                Err(error)
            }
        }
        Ok(mut names) => {
            let network_names = names.len();
            let mut persistence_recovery_truncated = false;
            if checkpoint.should_persist_non_paginated_result(&names) {
                let remaining =
                    (!budget.is_zero()).then(|| budget.saturating_sub(started.elapsed()));
                if remaining.is_some_and(|remaining| remaining.is_zero()) {
                    checkpoint.cancel_persistence();
                    checkpoint.record_persistence_error(
                        SourceDeadlineExceeded {
                            source: source.to_owned(),
                            deadline: budget,
                        }
                        .to_string(),
                    );
                } else {
                    let shared_names = Arc::new(names);
                    let persistence_names = Arc::clone(&shared_names);
                    let persistence_checkpoint = checkpoint.clone();
                    let mut task = tokio::task::spawn_blocking(move || {
                        persistence_checkpoint
                            .persist_non_paginated_result(persistence_names.as_ref());
                    });
                    let persistence_error = if let Some(remaining) = remaining {
                        match tokio::time::timeout(remaining, &mut task).await {
                            Ok(Ok(())) => None,
                            Ok(Err(error)) => {
                                Some(format!("persistance SQLite passive interrompue: {error}"))
                            }
                            Err(_) => {
                                checkpoint.cancel_persistence();
                                let deadline_error = SourceDeadlineExceeded {
                                    source: source.to_owned(),
                                    deadline: budget,
                                }
                                .to_string();
                                let _ = task.await;
                                Some(deadline_error)
                            }
                        }
                    } else {
                        task.await
                            .err()
                            .map(|error| format!("persistance SQLite passive interrompue: {error}"))
                    };
                    if let Some(error) = persistence_error {
                        checkpoint.record_persistence_error(error);
                    }
                    names = match Arc::try_unwrap(shared_names) {
                        Ok(names) => names,
                        Err(shared_names) => {
                            persistence_recovery_truncated = shared_names.len() > working_set_limit;
                            shared_names
                                .iter()
                                .take(working_set_limit)
                                .cloned()
                                .collect()
                        }
                    };
                }
            }
            let snapshot = checkpoint.snapshot();
            let decoded_names = if snapshot.committed_pages == 0 {
                network_names
            } else {
                snapshot.decoded_names
            };
            let result_truncated = if names.len() > working_set_limit {
                let retained = names.into_iter().take(working_set_limit).collect();
                names = retained;
                true
            } else {
                false
            };
            Ok(PassiveFetchResult {
                names,
                partial_warning: snapshot.persistence_error,
                decoded_names,
                working_set_truncated: snapshot.working_set_truncated
                    || persistence_recovery_truncated
                    || result_truncated,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_detailed_with_total_budget(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: Option<ControlledPassivePageSink>,
    pagination_context: Option<PassivePaginationContext>,
) -> Result<PassiveFetchResult> {
    let request = dispatch::fetch(source, domain, timeout, keys);
    let result = enforce_source_budget_preserving_partial_with_controlled_sink(
        source,
        total_budget,
        request,
        working_set_limit,
        page_sink,
        pagination_context,
    )
    .await;
    match result {
        Ok(mut fetch) => {
            if let Some(warning) = fetch.partial_warning.as_mut() {
                *warning = sanitize_external_error(warning, keys);
            }
            Ok(fetch)
        }
        Err(error) => Err(anyhow::Error::msg(sanitize_external_error(
            &format!("{error:#}"),
            keys,
        ))),
    }
}

pub async fn fetch_detailed(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        source_policy(source).total_timeout,
        usize::MAX,
        None,
        None,
    )
    .await
}

/// Runs the complete connector under a caller-supplied wall deadline while
/// retaining pages committed before the deadline. A zero duration deliberately
/// disables the cumulative wall deadline; per-request timeouts and structural
/// pagination/response limits remain active.
pub async fn fetch_detailed_bounded(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        if total_budget.is_zero() {
            Duration::ZERO
        } else {
            total_budget.min(source_policy(source).total_timeout)
        },
        usize::MAX,
        None,
        None,
    )
    .await
}

/// Runs a connector check with a caller-defined retained-name ceiling.  The
/// decoder may process more records, reported through `decoded_names`, while
/// preventing diagnostics from building a multi-million-name in-memory set.
pub async fn fetch_detailed_bounded_with_limit(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        if total_budget.is_zero() {
            Duration::ZERO
        } else {
            total_budget.min(source_policy(source).total_timeout)
        },
        working_set_limit.max(1),
        None,
        None,
    )
    .await
}

/// Runs a connector with a bounded in-memory working set. Fully decoded pages
/// are delivered to `page_sink` before the cap is applied so callers can keep
/// permanent observations without retaining the entire provider response.
pub async fn fetch_detailed_bounded_with_sink(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: PassivePageSink,
) -> Result<PassiveFetchResult> {
    fetch_detailed_bounded_with_controlled_sink(
        source,
        domain,
        timeout,
        keys,
        total_budget,
        working_set_limit,
        adapt_passive_page_sink(page_sink),
    )
    .await
}

pub async fn fetch_detailed_bounded_with_controlled_sink(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: ControlledPassivePageSink,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        if total_budget.is_zero() {
            Duration::ZERO
        } else {
            total_budget.min(source_policy(source).total_timeout)
        },
        working_set_limit,
        Some(page_sink),
        None,
    )
    .await
}

/// Scanner integration for a connector with durable numeric pagination. The
/// ordinary page sink remains available to non-numeric page commits within the
/// same connector, while numeric commits use the atomic pagination callback.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_detailed_bounded_with_pagination(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: PassivePageSink,
    pagination_context: PassivePaginationContext,
) -> Result<PassiveFetchResult> {
    fetch_detailed_bounded_with_controlled_pagination(
        source,
        domain,
        timeout,
        keys,
        total_budget,
        working_set_limit,
        adapt_passive_page_sink(page_sink),
        pagination_context,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_detailed_bounded_with_controlled_pagination(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: ControlledPassivePageSink,
    pagination_context: PassivePaginationContext,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        if total_budget.is_zero() {
            Duration::ZERO
        } else {
            total_budget.min(source_policy(source).total_timeout)
        },
        working_set_limit,
        Some(page_sink),
        Some(pagination_context),
    )
    .await
}

pub async fn fetch(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    Ok(fetch_detailed(source, domain, timeout, keys).await?.names)
}
