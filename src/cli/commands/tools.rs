use anyhow::{Result, bail};
use fellaga_core::benchmark::{CandidatePipelineOptions, run_candidate_pipeline};
use fellaga_core::dns::DnsEngine;
use std::net::IpAddr;

use super::super::args::{BenchmarkAction, ResolverAction};
use super::super::runtime::{compact_error, positive_duration_seconds};
use super::AppContext;

pub(crate) async fn benchmark(action: BenchmarkAction, context: &AppContext) -> Result<()> {
    let database_explicit = context.database_explicit;
    let database_path = context.database_path.clone();
    match action {
        BenchmarkAction::CandidatePipeline(args) => {
            if !database_explicit {
                bail!("candidate-pipeline requires an explicit fresh --db path");
            }
            if args.timeout <= 0.0 || !args.timeout.is_finite() || args.timeout > 60.0 {
                bail!("--timeout must be greater than zero and at most 60 seconds");
            }
            let result = run_candidate_pipeline(CandidatePipelineOptions {
                database: database_path,
                wordlist: args.wordlist,
                output: args.output.clone(),
                candidates: args.candidates,
                batch_size: args.batch_size,
                concurrency: args.concurrency,
                timeout: positive_duration_seconds(args.timeout, "--timeout")?,
                campaign_id: args.campaign_id,
            })
            .await?;
            println!(
                "Candidate pipeline completed: {} candidates, {} DNS queries, {} ms; JSON: {}",
                result.processed_candidates,
                result.dns_queries,
                result.duration_ms,
                args.output.display()
            );
        }
    }
    Ok(())
}

pub(crate) async fn resolvers(action: ResolverAction) -> Result<()> {
    match action {
        ResolverAction::Test(args) => {
            if args.timeout <= 0.0 || !args.timeout.is_finite() {
                bail!("--timeout doit être un nombre positif");
            }
            let resolvers = if args.resolvers.is_empty() {
                ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]
                    .into_iter()
                    .map(str::parse)
                    .collect::<std::result::Result<Vec<IpAddr>, _>>()?
            } else {
                args.resolvers
            };
            let results = DnsEngine::test_resolvers(
                &resolvers,
                positive_duration_seconds(args.timeout, "--timeout")?,
            )
            .await;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            } else {
                for result in results {
                    println!(
                        "{:<15} {:<8} NX-hijack={} DNSSEC={} AD={} cohérent={} {}ms{}",
                        result.resolver,
                        if result.usable { "OK" } else { "REJET" },
                        result.hijacks_nxdomain,
                        result.dnssec_records,
                        result.validates_dnssec,
                        result.consistent,
                        result.average_ms,
                        result
                            .error
                            .map(|error| format!(" — {}", compact_error(&error)))
                            .unwrap_or_default()
                    );
                }
            }
        }
        ResolverAction::Benchmark(args) => {
            if args.timeout <= 0.0 || !args.timeout.is_finite() {
                bail!("--timeout doit être un nombre positif");
            }
            let result = DnsEngine::benchmark_loopback(
                args.queries,
                args.concurrency,
                positive_duration_seconds(args.timeout, "--timeout")?,
            )
            .await?;
            let serialized = serde_json::to_string_pretty(&result)?;
            if let Some(path) = args.output {
                std::fs::write(path, format!("{serialized}\n"))?;
            }
            if args.json {
                println!("{serialized}");
            } else {
                println!(
                    "{:.0} req/s | {} complétées | {} échecs | perte {:.3}% | {} ms",
                    result.queries_per_second,
                    result.completed,
                    result.failures,
                    result.loss_rate * 100.0,
                    result.duration_ms
                );
            }
        }
    }
    Ok(())
}
