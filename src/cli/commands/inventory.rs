use anyhow::Result;
use fellaga_core::db::Database;
use fellaga_core::util;

use super::super::args::{CacheAction, ExplainArgs, HistoryArgs, KnowledgeArgs, ListArgs};
use super::AppContext;

pub(crate) fn list(args: ListArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let database = Database::open(&database_path)?;
    let normalized = args
        .domain
        .as_deref()
        .map(util::normalize_domain)
        .transpose()?;
    let only_live = !args.all || args.only_live;
    let hosts = database.inventory(normalized.as_deref(), only_live)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&hosts)?);
    } else {
        for host in hosts {
            println!(
                "{}\t{}\t{}",
                host.fqdn,
                host.state,
                host.last_verified_at
                    .map(|timestamp| timestamp.to_string())
                    .unwrap_or_else(|| "-".to_owned())
            );
        }
    }
    Ok(())
}

pub(crate) fn history(args: HistoryArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let database = Database::open(&database_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&database.history(args.limit)?)?
    );
    Ok(())
}

pub(crate) fn stats(context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let database = Database::open(&database_path)?;
    println!("{}", serde_json::to_string_pretty(&database.stats()?)?);
    Ok(())
}

pub(crate) fn cache(action: CacheAction, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let database = Database::open(&database_path)?;
    match action {
        CacheAction::Prune => {
            let expired = database.prune_cache()?;
            let mut temporary = 0_usize;
            const PRUNE_BATCH: usize = 25_000;
            loop {
                let removed = database.prune_superseded_candidate_queues(PRUNE_BATCH)?;
                temporary = temporary.saturating_add(removed);
                if removed > 0 {
                    eprintln!(
                        "cache prune: {temporary} candidat(s) temporaire(s) abandonné(s) supprimé(s)"
                    );
                }
                if removed < PRUNE_BATCH {
                    break;
                }
            }
            println!(
                "{expired} entrée(s) négative(s) expirée(s), {temporary} candidat(s) temporaire(s) abandonné(s) supprimé(s)"
            );
        }
    }
    Ok(())
}

pub(crate) fn knowledge(args: KnowledgeArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let database = Database::open(&database_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&database.knowledge(args.limit)?)?
    );
    Ok(())
}

pub(crate) fn explain(args: ExplainArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let database = Database::open(&database_path)?;
    let fqdn = util::normalize_domain(&args.fqdn)?;
    let explanation = database.explain(&fqdn)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&explanation)?);
    } else if explanation["known"].as_bool() == Some(false) {
        println!("{fqdn}: inconnu de la base locale");
    } else {
        println!("{fqdn}");
        println!("  état: {}", explanation["inventory"]["state"]);
        println!(
            "  dernière validation: {}",
            explanation["inventory"]["last_verified_at"]
        );
        println!(
            "  preuves: {} observation(s), {} validation(s) DNS, {} enregistrement(s)",
            explanation["evidence"].as_array().map_or(0, Vec::len),
            explanation["dns_verifications"]
                .as_array()
                .map_or(0, Vec::len),
            explanation["dns_records"].as_array().map_or(0, Vec::len)
        );
        for evidence in explanation["evidence"].as_array().into_iter().flatten() {
            println!(
                "    - {} ({}, {} fois)",
                evidence["source"], evidence["kind"], evidence["times_seen"]
            );
        }
        if let Some(quarantine) = explanation["quarantine"]
            .as_array()
            .filter(|entries| !entries.is_empty())
        {
            println!("  quarantaine wildcard: {} zone(s)", quarantine.len());
            for entry in quarantine {
                println!(
                    "    - zone {}, scan {}, raison {}, horodatage {}",
                    entry["root_domain"],
                    entry["scan_id"],
                    entry["reason"],
                    entry["quarantined_at"]
                );
            }
        }
    }
    Ok(())
}
