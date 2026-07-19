use anyhow::{Result, bail};
use fellaga_core::db::Database;
use fellaga_core::dns::DnsEngine;
use fellaga_core::scanner::{RefreshOptions, RefreshProgressCallback, refresh_inventory_bounded};
use std::sync::Arc;
use std::time::Duration;

use super::super::args::RefreshArgs;
use super::super::runtime::{bounded_duration_seconds, make_dns, positive_duration_seconds};
use super::AppContext;

pub(crate) async fn run(args: RefreshArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

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
        let deadline = if args.max_runtime == 0 {
            "no cumulative deadline".to_owned()
        } else {
            format!("{}s cumulative deadline", args.max_runtime)
        };
        eprintln!(
            "[refresh] starting {} with {deadline} and {}-name batches",
            args.target, args.batch_size
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
            wildcard_phase_timeout: Duration::ZERO,
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

    Ok(())
}
