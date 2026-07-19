use anyhow::{Result, bail};
use fellaga_core::dns::DnsEngine;
use fellaga_core::util;
use std::collections::BTreeSet;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Duration;

use super::args::{DnsArgs, ScanArgs};
use super::console::sanitize_terminal_text;
pub(crate) fn compact_error(error: &str) -> String {
    sanitize_terminal_text(error)
}

pub(crate) fn wait_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}")
    } else {
        format!("{minutes}m")
    }
}

pub(crate) fn positive_duration_seconds(value: f64, option: &str) -> Result<Duration> {
    if value <= 0.0 || !value.is_finite() {
        bail!("{option} doit être un nombre positif");
    }
    // Floating-point durations are per-operation network timeouts, not global
    // scan budgets. A one-day ceiling prevents accidental multi-year hangs
    // while remaining far above every practical DNS/HTTP/TLS timeout.
    if value > 86_400.0 {
        bail!("{option} ne peut pas dépasser 86400 secondes");
    }
    let duration = Duration::try_from_secs_f64(value)
        .map_err(|_| anyhow::anyhow!("{option} dépasse la durée maximale prise en charge"))?;
    if duration.is_zero() {
        bail!("{option} est trop petit pour être représenté");
    }
    if std::time::Instant::now().checked_add(duration).is_none()
        || tokio::time::Instant::now().checked_add(duration).is_none()
    {
        bail!("{option} dépasse la durée maximale prise en charge");
    }
    Ok(duration)
}

pub(crate) fn bounded_duration_seconds(value: u64, option: &str) -> Result<Duration> {
    let duration = Duration::from_secs(value);
    if value > 0
        && (std::time::Instant::now().checked_add(duration).is_none()
            || tokio::time::Instant::now().checked_add(duration).is_none())
    {
        bail!("{option} dépasse la durée maximale prise en charge");
    }
    Ok(duration)
}

pub(crate) fn bounded_duration_hours(value: u64, option: &str) -> Result<Duration> {
    let seconds = value
        .checked_mul(3_600)
        .ok_or_else(|| anyhow::anyhow!("{option} dépasse la durée maximale prise en charge"))?;
    bounded_duration_seconds(seconds, option)
}

pub(crate) fn default_database_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FELLAGA_DB") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("fellaga/fellaga.db");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/fellaga/fellaga.db")
}

pub(crate) fn collect_targets(args: &ScanArgs) -> Result<Vec<String>> {
    let mut raw = args.targets.clone();
    if let Some(path) = &args.targets_file {
        if !path.is_file() {
            bail!("fichier de cibles introuvable: {}", path.display());
        }
        raw.extend(
            std::fs::read_to_string(path)?
                .lines()
                .map(ToOwned::to_owned),
        );
    }
    let read_stdin = raw.iter().any(|target| target.trim() == "-")
        || (raw.is_empty() && !std::io::stdin().is_terminal());
    raw.retain(|target| target.trim() != "-");
    if read_stdin {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input)?;
        raw.extend(input.lines().map(ToOwned::to_owned));
    }
    let mut targets = BTreeSet::new();
    for line in raw {
        let value = line.split('#').next().unwrap_or_default();
        for target in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            targets.insert(util::normalize_domain(target)?);
        }
    }
    if targets.is_empty() {
        bail!("aucune cible: fournissez TARGET, --targets-file ou des domaines sur stdin");
    }
    Ok(targets.into_iter().collect())
}

pub(crate) fn make_dns(args: &DnsArgs) -> Result<DnsEngine> {
    let timeout = positive_duration_seconds(args.timeout, "--timeout")?;
    if !(1..=4_096).contains(&args.concurrency) {
        bail!("--concurrency doit être compris entre 1 et 4096");
    }
    if args.dns_rate_limit > 100_000 {
        bail!("--dns-rate-limit ne peut pas dépasser 100000 requêtes/s");
    }
    DnsEngine::new_with_rate_and_control(
        args.concurrency,
        timeout,
        &args.resolvers,
        args.dns_rate_limit,
        args.network_control.into(),
    )
}
