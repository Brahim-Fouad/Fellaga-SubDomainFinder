use anyhow::{Result, bail};
use fellaga_core::candidate::{default_mutation_rules, load_mutation_rules};
use fellaga_core::db::Database;
use fellaga_core::dns::DnsEngine;
use fellaga_core::passive;
use fellaga_core::passive::{all_unique_sources, automatic_sources_for_profile, validate_sources};
use fellaga_core::scanner::{self, ScanOptions, Scanner};
use futures_util::{StreamExt, stream};
use std::collections::BTreeSet;
use std::io::Write;
use std::sync::{Arc, Mutex};

use super::super::args::{MetadataDiscoveryArg, ScanArgs};
use super::super::console::{ConsoleProgress, print_scan_findings, print_scan_summary};
use super::super::output::{
    StreamJsonlMode, finding_selected_for_output, raw_output_diagnostic_event,
    scan_progress_enabled, scan_result_for_output, stream_finding_line, stream_jsonl_mode,
    write_raw_scan_list, write_scan_results,
};
use super::super::profile::ScanProfile;
use super::super::runtime::{
    bounded_duration_hours, bounded_duration_seconds, collect_targets, make_dns,
    positive_duration_seconds,
};
use super::AppContext;

pub(crate) const MAX_DOMAIN_CONCURRENCY: usize = 4;
pub(crate) const MAX_WEB_CONCURRENCY: usize = 16;
pub(crate) const MAX_TLS_CONCURRENCY: usize = 32;

pub(crate) fn validate_scan_concurrency(domain: usize, web: usize, tls: usize) -> Result<()> {
    if !(1..=MAX_DOMAIN_CONCURRENCY).contains(&domain) {
        bail!("--domain-concurrency doit être compris entre 1 et {MAX_DOMAIN_CONCURRENCY}");
    }
    if !(1..=MAX_WEB_CONCURRENCY).contains(&web) {
        bail!("--web-concurrency doit être compris entre 1 et {MAX_WEB_CONCURRENCY}");
    }
    if !(1..=MAX_TLS_CONCURRENCY).contains(&tls) {
        bail!("--tls-concurrency doit être compris entre 1 et {MAX_TLS_CONCURRENCY}");
    }
    Ok(())
}

pub(crate) fn validate_no_target_contact(profile: ScanProfile, enabled: bool) -> Result<()> {
    if enabled && profile != ScanProfile::Passive {
        bail!("--no-target-contact requires --profile passive");
    }
    Ok(())
}

pub(crate) fn metadata_discovery_enabled(
    mode: MetadataDiscoveryArg,
    passive_profile: bool,
    web_disabled: bool,
) -> bool {
    mode != MetadataDiscoveryArg::Off && !passive_profile && !web_disabled
}

pub(crate) async fn run(args: Box<ScanArgs>, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();
    let api_keys = context.api_keys.clone();

    if let Some(path) = &args.wordlist
        && !path.is_file()
    {
        bail!("wordlist introuvable: {}", path.display());
    }
    if let Some(path) = &args.mutations
        && !path.is_file()
    {
        bail!("DSL de mutations introuvable: {}", path.display());
    }
    let mutation_rules = if let Some(path) = &args.mutations {
        load_mutation_rules(path)?
    } else {
        default_mutation_rules()
    };
    let defaults = args.profile.defaults();
    let max_runtime_seconds = args.max_runtime.unwrap_or(defaults.max_runtime);
    let max_words = args.max_words.unwrap_or(defaults.max_words);
    let active_max_runtime = args
        .active_max_runtime
        .unwrap_or(defaults.active_max_runtime);
    let max_passive = args.max_passive.unwrap_or(defaults.max_passive);
    let depth = args.depth.unwrap_or(defaults.depth);
    let recursive_words = args.recursive_words.unwrap_or(defaults.recursive_words);
    let recursive_hosts = args.recursive_hosts.unwrap_or(defaults.recursive_hosts);
    let pipeline_rounds = args.pipeline_rounds.unwrap_or(defaults.pipeline_rounds);
    let pipeline_limit = args.pipeline_limit.unwrap_or(defaults.pipeline_budget);
    let tls_hosts = args.tls_hosts.unwrap_or(defaults.tls_hosts);
    let graph_hosts = args.graph_hosts.unwrap_or(defaults.graph_hosts);
    let ptr_ips = args.ptr_ips.unwrap_or(defaults.ptr_ips);
    let internetdb_ips = args.internetdb_ips.unwrap_or(defaults.internetdb_ips);
    let internetdb_max_runtime = args
        .internetdb_max_runtime
        .unwrap_or(defaults.internetdb_max_runtime);
    let nsec_max_names = args.nsec_max_names.unwrap_or(defaults.nsec_max_names);
    let nsec_max_runtime = args.nsec_max_runtime.unwrap_or(defaults.nsec_max_runtime);
    let ct_logs = args.ct_logs.unwrap_or(defaults.ct_logs);
    let ct_entries = args.ct_entries.unwrap_or(defaults.ct_entries);
    let ct_backfill = args.ct_backfill.unwrap_or(defaults.ct_backfill);
    let ct_max_runtime = args.ct_max_runtime.unwrap_or(defaults.ct_max_runtime);
    let web_hosts = args.web_hosts.unwrap_or(defaults.web_hosts);
    let web_max_runtime = args.web_max_runtime.unwrap_or(defaults.web_max_runtime);
    let web_assets = args.web_assets.unwrap_or(defaults.web_assets);
    let passive_max_runtime = args
        .passive_max_runtime
        .unwrap_or(defaults.passive_max_runtime);
    let passive_zone_concurrency = args
        .passive_zone_concurrency
        .unwrap_or(defaults.passive_zone_concurrency);
    let profile_passive = args.profile == ScanProfile::Passive;
    let passive_only = args.passive_only || profile_passive;

    validate_no_target_contact(args.profile, args.no_target_contact)?;

    if !passive_only && max_words == 0 {
        bail!("--max-words doit être supérieur à zéro hors profil passif");
    }
    if !(1..=5).contains(&depth) {
        bail!("--depth doit être compris entre 1 et 5");
    }
    if recursive_words == 0 || recursive_hosts == 0 {
        bail!("--recursive-words et --recursive-hosts doivent être supérieurs à zéro");
    }
    if max_passive == 0 {
        bail!("--max-passive doit être supérieur à zéro");
    }
    if passive_zone_concurrency == 0 || passive_zone_concurrency > 32 {
        bail!("--passive-zone-concurrency doit être compris entre 1 et 32");
    }
    if args.passive_concurrency == 0 || args.passive_concurrency > 32 {
        bail!("--passive-concurrency doit être compris entre 1 et 32");
    }
    if max_words > 10_000_000 {
        bail!("--max-words ne peut pas dépasser 10000000");
    }
    if max_passive > 1_000_000 {
        bail!("--max-passive ne peut pas dépasser 1000000");
    }
    if args.checkpoint_every == 0 {
        bail!("--checkpoint-every doit être supérieur à zéro");
    }
    let effective_recursive_words = if args.no_adaptive {
        recursive_words
    } else {
        recursive_words.min(50)
    };
    let effective_recursive_hosts = if args.no_adaptive {
        recursive_hosts
    } else {
        recursive_hosts.min(20)
    };
    if effective_recursive_words.saturating_mul(effective_recursive_hosts) > 1_000_000 {
        bail!("--recursive-words × --recursive-hosts ne peut pas dépasser 1000000 par niveau");
    }
    if pipeline_limit > 1_000_000 {
        bail!("--pipeline-limit ne peut pas dépasser 1000000");
    }
    validate_scan_concurrency(
        args.domain_concurrency,
        args.web_concurrency,
        args.tls_concurrency,
    )?;
    if args.axfr_timeout <= 0.0 || !args.axfr_timeout.is_finite() {
        bail!("--axfr-timeout doit être un nombre positif");
    }
    if args.tls_timeout <= 0.0 || !args.tls_timeout.is_finite() {
        bail!("--tls-timeout doit être un nombre positif");
    }
    if args.tls_port == 0 {
        bail!("--tls-port doit être supérieur à zéro");
    }
    if tls_hosts == 0 {
        bail!("--tls-hosts doit être supérieur à zéro");
    }
    if graph_hosts == 0 {
        bail!("--graph-hosts doit être supérieur à zéro");
    }
    if pipeline_rounds == 0 {
        bail!("--pipeline-rounds doit être supérieur à zéro");
    }
    if ptr_ips == 0 {
        bail!("--ptr-ips doit être supérieur à zéro");
    }
    if !(1..=64).contains(&internetdb_ips) {
        bail!("--internetdb-ips doit être compris entre 1 et 64");
    }
    if internetdb_max_runtime > 60 {
        bail!("--internetdb-max-runtime doit être compris entre 0 et 60");
    }
    if args.internetdb_refresh_hours == 0 {
        bail!("--internetdb-refresh-hours doit être supérieur à zéro");
    }
    if nsec_max_names == 0 {
        bail!("--nsec-max-names doit être supérieur à zéro");
    }
    if args.nsec_timeout <= 0.0 || !args.nsec_timeout.is_finite() {
        bail!("--nsec-timeout doit être un nombre positif");
    }
    if ct_logs == 0 || ct_entries == 0 || ct_backfill == 0 {
        bail!("--ct-logs, --ct-entries et --ct-backfill doivent être supérieurs à zéro");
    }
    if args.ct_timeout <= 0.0 || !args.ct_timeout.is_finite() {
        bail!("--ct-timeout doit être un nombre positif");
    }
    if web_hosts == 0 || args.web_max_bytes == 0 {
        bail!("--web-hosts et --web-max-bytes doivent être supérieurs à zéro");
    }
    if args.web_timeout <= 0.0 || !args.web_timeout.is_finite() {
        bail!("--web-timeout doit être un nombre positif");
    }
    if [args.json, args.jsonl, args.stream_jsonl, args.show]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
        > 1
    {
        bail!("--show, --json, --jsonl et --stream-jsonl sont mutuellement exclusifs");
    }
    if args.no_passive && passive_only {
        bail!("--no-passive et --passive-only sont incompatibles");
    }
    if args.checkpoint_every == 0 {
        bail!("--checkpoint-every doit être supérieur à zéro");
    }
    let targets = collect_targets(&args)?;
    validate_sources(&args.passive_sources)?;
    validate_sources(&args.exclude_sources)?;
    let mut passive_sources = if args.all_sources {
        all_unique_sources()
    } else if args.passive_sources.is_empty() {
        automatic_sources_for_profile(&api_keys, args.profile == ScanProfile::Deep)
    } else {
        args.passive_sources.clone()
    };
    let automatic_source_selection = args.passive_sources.is_empty() && !args.all_sources;
    let excluded = args
        .exclude_sources
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    passive_sources.retain(|source| !excluded.contains(source));
    if let Some(source) = passive_sources
        .iter()
        .find(|source| !passive::source_metadata(source).available)
    {
        let metadata = passive::source_metadata(source);
        bail!(
            "passive source {source} is unavailable: {}",
            metadata
                .unavailable_reason
                .unwrap_or("provider unavailable")
        );
    }
    passive_sources.sort();
    passive_sources.dedup();
    if !args.no_passive && passive_sources.is_empty() {
        bail!("aucune source passive sélectionnée");
    }
    let database = Database::open(&database_path)?;
    let dns = make_dns(&args.dns)?;
    dns.seed_metrics(&database.resolver_history()?);
    let trusted_dns = if args.no_trusted_validation || args.no_target_contact {
        None
    } else {
        let trusted = DnsEngine::new_with_rate_and_control(
            args.dns.concurrency.min(256),
            positive_duration_seconds(args.dns.timeout, "--timeout")?,
            &args.dns.trusted_resolvers,
            args.dns.dns_rate_limit,
            args.dns.network_control.into(),
        )?
        .share_rate_limit_with(&dns);
        trusted.seed_metrics(&database.resolver_history()?);
        Some(trusted)
    };
    let options = ScanOptions {
        wordlist: args.wordlist.clone(),
        mutation_rules,
        max_words,
        active_phase_timeout: bounded_duration_seconds(active_max_runtime, "--active-max-runtime")?,
        passive: !args.no_passive,
        passive_sources,
        api_keys: api_keys.clone(),
        automatic_source_selection,
        passive_refresh: bounded_duration_hours(
            args.passive_refresh_hours,
            "--passive-refresh-hours",
        )?,
        passive_phase_timeout: bounded_duration_seconds(
            passive_max_runtime,
            "--passive-max-runtime",
        )?,
        passive_zone_concurrency,
        passive_concurrency: args.passive_concurrency,
        max_passive,
        passive_only,
        no_target_contact: args.no_target_contact,
        axfr: !args.no_axfr && !profile_passive,
        axfr_timeout: positive_duration_seconds(args.axfr_timeout, "--axfr-timeout")?,
        refresh_cache: args.refresh_cache,
        verification_max_age: bounded_duration_hours(
            args.verification_max_age,
            "--verification-max-age",
        )?,
        only_live: args.only_live,
        profile: format!("{:?}", args.profile).to_ascii_lowercase(),
        checkpoint_every: bounded_duration_seconds(args.checkpoint_every, "--checkpoint-every")?,
        resume: args.resume.clone(),
        ttl_cap: args.ttl_cap,
        negative_ttl: args.negative_ttl,
        include_wildcard: args.include_wildcard,
        wildcard_refresh: bounded_duration_hours(
            args.wildcard_refresh_hours,
            "--wildcard-refresh-hours",
        )?,
        recursive_depth: depth,
        recursive_words,
        recursive_hosts,
        adaptive: !args.no_adaptive,
        pipeline: !args.no_pipeline && !profile_passive,
        pipeline_rounds,
        pipeline_budget: pipeline_limit,
        tls_certificates: !args.no_tls && !profile_passive,
        tls_port: args.tls_port,
        tls_timeout: positive_duration_seconds(args.tls_timeout, "--tls-timeout")?,
        tls_refresh: bounded_duration_hours(args.tls_refresh_hours, "--tls-refresh-hours")?,
        tls_max_hosts: tls_hosts,
        tls_concurrency: args.tls_concurrency,
        dns_graph: !args.no_dns_graph && !profile_passive,
        graph_max_hosts: graph_hosts,
        service_discovery: !args.no_service_discovery && !profile_passive,
        ptr_pivot: !args.no_ptr && !profile_passive,
        ptr_max_ips: ptr_ips,
        internetdb_pivot: !args.no_internetdb && !profile_passive,
        internetdb_max_ips: internetdb_ips,
        internetdb_phase_timeout: bounded_duration_seconds(
            internetdb_max_runtime,
            "--internetdb-max-runtime",
        )?,
        internetdb_refresh: bounded_duration_hours(
            args.internetdb_refresh_hours,
            "--internetdb-refresh-hours",
        )?,
        dnssec_nsec: !args.no_nsec && !profile_passive,
        nsec_timeout: positive_duration_seconds(args.nsec_timeout, "--nsec-timeout")?,
        nsec_refresh: bounded_duration_hours(args.nsec_refresh_hours, "--nsec-refresh-hours")?,
        nsec_max_names,
        nsec_phase_timeout: bounded_duration_seconds(nsec_max_runtime, "--nsec-max-runtime")?,
        ct_monitor: !args.no_ct_monitor,
        ct_timeout: positive_duration_seconds(args.ct_timeout, "--ct-timeout")?,
        ct_phase_timeout: bounded_duration_seconds(ct_max_runtime, "--ct-max-runtime")?,
        ct_max_logs: ct_logs,
        ct_entries_per_log: ct_entries,
        ct_initial_backfill: ct_backfill,
        metadata_discovery: metadata_discovery_enabled(
            args.metadata_discovery,
            profile_passive,
            args.no_web,
        ),
        metadata_all_hosts: args.metadata_discovery == MetadataDiscoveryArg::All,
        metadata_max_requests: if args.profile == ScanProfile::Deep {
            64
        } else {
            24
        },
        web_discovery: !args.no_web && !profile_passive,
        web_max_hosts: web_hosts,
        web_timeout: positive_duration_seconds(args.web_timeout, "--web-timeout")?,
        web_phase_timeout: bounded_duration_seconds(web_max_runtime, "--web-max-runtime")?,
        web_refresh: bounded_duration_hours(args.web_refresh_hours, "--web-refresh-hours")?,
        web_concurrency: args.web_concurrency,
        web_max_bytes: args.web_max_bytes,
        web_assets_per_host: web_assets,
    };
    let stream_mode = stream_jsonl_mode(args.stream_jsonl, args.only_live);
    let progress_enabled = scan_progress_enabled(args.quiet, args.show, args.stream_jsonl);
    let multiple_targets = targets.len() > 1;
    let printer = (!args.quiet).then(|| {
        Arc::new(Mutex::new(ConsoleProgress::new(
            args.json || args.jsonl || args.stream_jsonl,
            args.show,
            multiple_targets,
            args.verbose,
        )))
    });
    let quiet = args.quiet;
    let show = args.show;
    let max_runtime = (max_runtime_seconds > 0)
        .then(|| bounded_duration_seconds(max_runtime_seconds, "--max-runtime"))
        .transpose()?;
    let domain_concurrency = args.domain_concurrency.min(targets.len()).max(1);
    let mut pending = stream::iter(targets)
        .map(|target| {
            let database = database.clone();
            let dns = dns.clone();
            let options = options.clone();
            let callback: Option<scanner::ProgressCallback> = progress_enabled.then(|| {
                let printer = printer.clone();
                let target_context = target.clone();
                Arc::new(move |event| {
                    if !quiet
                        && (!show || raw_output_diagnostic_event(&event))
                        && let Some(printer) = &printer
                        && let Ok(mut printer) = printer.lock()
                    {
                        printer.handle(&target_context, event);
                    }
                }) as scanner::ProgressCallback
            });
            let target_printer = printer.clone();
            let trusted_dns = trusted_dns.clone();
            async move {
                let mut scanner = Scanner::new(database, dns, options);
                if let Some(trusted_dns) = trusted_dns {
                    scanner = scanner.with_trusted_dns(trusted_dns);
                }
                if let Some(callback) = callback {
                    scanner = scanner.with_progress(callback);
                }
                let result = if let Some(limit) = max_runtime {
                    tokio::time::timeout(limit, scanner.scan(&target))
                        .await
                        .map_err(|_| {
                            anyhow::anyhow!(
                                "durée globale maximale atteinte pour {target}; utilisez --resume latest"
                            )
                        })?
                } else {
                    scanner.scan(&target).await
                };
                if let Some(printer) = &target_printer
                    && let Ok(mut printer) = printer.lock()
                {
                    printer.finish_target(&target);
                }
                result
            }
        })
        .buffer_unordered(domain_concurrency);
    let mut results = Vec::new();
    let mut first_error = None;
    let mut interrupted = Box::pin(tokio::signal::ctrl_c());
    loop {
        let next = tokio::select! {
            signal = &mut interrupted => {
                if let Some(printer) = &printer
                    && let Ok(mut printer) = printer.lock()
                {
                    printer.finish();
                }
                match signal {
                    Ok(()) => bail!(
                        "scan interrompu par l'utilisateur; checkpoint conservé pour --resume latest"
                    ),
                    Err(error) => bail!("écoute de Ctrl+C impossible: {error}"),
                }
            }
            next = pending.next() => next,
        };
        let Some(result) = next else {
            break;
        };
        match result {
            Ok(result) => {
                if stream_mode == StreamJsonlMode::FinalOnly {
                    for finding in result.findings.iter().filter(|finding| {
                        finding_selected_for_output(
                            finding,
                            args.include_non_live,
                            args.include_wildcard,
                        )
                    }) {
                        println!("{}", stream_finding_line(finding));
                    }
                    std::io::stdout().flush()?;
                }
                results.push(result);
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    if let Some(printer) = &printer
        && let Ok(mut printer) = printer.lock()
    {
        printer.finish();
    }
    results.sort_by(|left, right| left.domain.cmp(&right.domain));
    if args.stream_jsonl {
        // Findings were emitted only after final DNS, wildcard and state
        // classification for each completed domain.
    } else if args.jsonl {
        for result in &results {
            let output =
                scan_result_for_output(result, args.include_non_live, args.include_wildcard);
            println!("{}", serde_json::to_string(&output)?);
        }
    } else if args.json {
        if results.len() == 1 {
            let output =
                scan_result_for_output(&results[0], args.include_non_live, args.include_wildcard);
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            let output = results
                .iter()
                .map(|result| {
                    scan_result_for_output(result, args.include_non_live, args.include_wildcard)
                })
                .collect::<Vec<_>>();
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    } else if args.show {
        write_raw_scan_list(&results, args.include_non_live, args.include_wildcard)?;
    } else if !args.quiet {
        for result in &results {
            print_scan_findings(result, args.include_non_live, args.include_wildcard);
            print_scan_summary(result, args.verbose);
        }
    }
    if let Some(path) = &args.output {
        write_scan_results(
            path,
            &results,
            args.json,
            args.jsonl,
            args.include_non_live,
            args.include_wildcard,
        )?;
    }
    if let Some(directory) = &args.output_dir {
        std::fs::create_dir_all(directory)?;
        for result in &results {
            let extension = if args.json {
                "json"
            } else if args.jsonl {
                "jsonl"
            } else {
                "txt"
            };
            let path = directory.join(format!("{}.{}", result.domain, extension));
            write_scan_results(
                &path,
                std::slice::from_ref(result),
                args.json,
                args.jsonl,
                args.include_non_live,
                args.include_wildcard,
            )?;
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }

    Ok(())
}
