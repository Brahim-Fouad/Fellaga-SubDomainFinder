use anyhow::{Result, bail};
use fellaga_core::db::Database;
use fellaga_core::passive::source_statuses;
use fellaga_core::{passive, util};
use futures_util::{StreamExt, stream};
use std::collections::BTreeMap;
use std::time::Duration;

use super::super::args::SourcesArgs;
use super::super::runtime::{compact_error, positive_duration_seconds, wait_label};
use super::AppContext;

const MAX_SOURCE_CHECK_CONCURRENCY: usize = 32;

pub(crate) fn validate_source_check_concurrency(value: usize) -> Result<()> {
    if !(1..=MAX_SOURCE_CHECK_CONCURRENCY).contains(&value) {
        bail!("--concurrency doit être compris entre 1 et {MAX_SOURCE_CHECK_CONCURRENCY}");
    }
    Ok(())
}

pub(crate) fn source_check_error_status(message: &str) -> &'static str {
    let message = message.to_ascii_lowercase();
    if (message.contains("budget total de") && message.contains("dépassé"))
        || (message.contains("limite cumulative configurée") && message.contains("atteinte"))
    {
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

pub(crate) fn source_check_result_status(names: usize, warning: Option<&str>) -> &'static str {
    match warning {
        Some(warning) if names == 0 => source_check_error_status(warning),
        Some(_) => "degraded",
        None if names == 0 => "empty",
        None => "success",
    }
}

pub(crate) async fn run(args: SourcesArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();
    let config_path = context.config_path.clone();
    let api_keys = context.api_keys.clone();

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
                    if !source.metadata.available {
                        return serde_json::json!({
                            "name": source.name,
                            "status": "skipped_unavailable",
                            "names": 0,
                            "duration_ms": 0,
                            "error": source.metadata.unavailable_reason,
                            "metadata": source.metadata
                        });
                    }
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
                    match passive::fetch_detailed_bounded_with_limit(
                        &source.name,
                        &target,
                        timeout,
                        &api_keys,
                        timeout,
                        100_000,
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
                            "decoded_names": result.decoded_names,
                            "working_set_truncated": result.working_set_truncated,
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
                    "{:<22} {:<20} {:>6} name(s) {:>7} ms{}{}",
                    check["name"].as_str().unwrap_or("?"),
                    check["status"].as_str().unwrap_or("?"),
                    check["names"].as_u64().unwrap_or_default(),
                    check["duration_ms"].as_u64().unwrap_or_default(),
                    check["error"]
                        .as_str()
                        .or_else(|| check["warning"].as_str())
                        .map(|error| format!(" — {}", compact_error(error)))
                        .unwrap_or_default(),
                    if check["working_set_truncated"].as_bool() == Some(true) {
                        " — diagnostic set capped at 100000 names"
                    } else {
                        ""
                    }
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
            let state = if !source.metadata.available {
                format!(
                    "unavailable ({})",
                    source
                        .metadata
                        .unavailable_reason
                        .unwrap_or("provider unavailable")
                )
            } else if let Some(wait) = diagnostic.and_then(|diagnostic| diagnostic.retry_in_seconds)
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
                println!("  last error: {}", compact_error(error));
            }
        }
    }

    Ok(())
}
