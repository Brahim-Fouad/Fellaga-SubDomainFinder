//! Passive connector dispatch and bounded result execution.

use super::catalog::source_policy;
use super::config::{ApiKeyStore, sanitize_external_error};
use super::dispatch;
use super::pagination::{
    PARTIAL_RESULT_CHECKPOINT, PASSIVE_PAGINATION_CONTEXT, PartialResultCheckpoint,
    PassiveFetchResult, PassivePageSink, PassivePaginationContext,
};
use anyhow::Result;
use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;
#[derive(Debug)]
struct SourceDeadlineExceeded {
    source: String,
    deadline: Duration,
}

impl fmt::Display for SourceDeadlineExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: limite cumulative configurée de {}s atteinte; pages terminées conservées dans le résultat courant",
            self.source,
            self.deadline.as_secs_f64()
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
    let checkpoint = PartialResultCheckpoint::new(working_set_limit, page_sink);
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
            checkpoint.persist_non_paginated_result(&names);
            let snapshot = checkpoint.snapshot();
            let decoded_names = if snapshot.committed_pages == 0 {
                names.len()
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
                working_set_truncated: snapshot.working_set_truncated || result_truncated,
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
    page_sink: Option<PassivePageSink>,
    pagination_context: Option<PassivePaginationContext>,
) -> Result<PassiveFetchResult> {
    let request = dispatch::fetch(source, domain, timeout, keys);
    let result = enforce_source_budget_preserving_partial_with_sink(
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
