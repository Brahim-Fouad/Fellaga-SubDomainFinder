use crate::db::Database;
use crate::model::CtMonitorResult;
use crate::util::{is_subdomain, normalize_hostname};
use anyhow::{Context, Result};
use base64::Engine;
use futures_util::{StreamExt, stream};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

const CHROME_LOG_LIST: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

#[derive(Debug, Deserialize)]
struct LogList {
    #[serde(default)]
    operators: Vec<LogOperator>,
}

#[derive(Debug, Deserialize)]
struct LogOperator {
    #[serde(default)]
    logs: Vec<CtLog>,
}

#[derive(Debug, Deserialize)]
struct CtLog {
    url: String,
}

#[derive(Debug, Deserialize)]
struct SignedTreeHead {
    tree_size: u64,
}

#[derive(Debug, Deserialize)]
struct EntriesResponse {
    #[serde(default)]
    entries: Vec<CtEntry>,
}

#[derive(Debug, Deserialize)]
struct CtEntry {
    leaf_input: String,
    extra_data: String,
}

fn read_u24(data: &[u8], offset: usize) -> Option<usize> {
    let bytes = data.get(offset..offset + 3)?;
    Some(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

fn certificate_der(entry: &CtEntry) -> Option<Vec<u8>> {
    let decoder = base64::engine::general_purpose::STANDARD;
    let leaf = decoder.decode(&entry.leaf_input).ok()?;
    if leaf.len() < 15 {
        return None;
    }
    let entry_type = u16::from_be_bytes([leaf[10], leaf[11]]);
    let source = if entry_type == 0 {
        leaf.get(12..)?.to_vec()
    } else if entry_type == 1 {
        decoder.decode(&entry.extra_data).ok()?
    } else {
        return None;
    };
    let length = read_u24(&source, 0)?;
    source.get(3..3 + length).map(ToOwned::to_owned)
}

fn names_from_entry(entry: &CtEntry) -> BTreeSet<String> {
    let Some(der) = certificate_der(entry) else {
        return BTreeSet::new();
    };
    let Ok(certificate) = X509::from_der(&der) else {
        return BTreeSet::new();
    };
    let mut names = BTreeSet::new();
    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        for general_name in subject_alt_names {
            if let Some(name) = general_name.dnsname()
                && let Some(name) = normalize_hostname(name)
            {
                names.insert(name);
            }
        }
    }
    for entry in certificate.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(name) = entry.data().to_string()
            && let Some(name) = normalize_hostname(&name)
        {
            names.insert(name);
        }
    }
    names
}

fn endpoint(log_url: &str, path: &str) -> String {
    format!("{}/{}", log_url.trim_end_matches('/'), path)
}

pub async fn monitor_ct_logs(
    database: &Database,
    domain: &str,
    timeout: Duration,
    max_logs: usize,
    entries_per_log: usize,
    initial_backfill: usize,
) -> Result<CtMonitorResult> {
    let started = Instant::now();
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!(
            "Fellaga-SubDomainFinder/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let list = client
        .get(CHROME_LOG_LIST)
        .send()
        .await
        .context("connexion à la liste CT de Chrome")?
        .error_for_status()
        .context("réponse de la liste CT de Chrome")?
        .json::<LogList>()
        .await
        .context("liste CT Chrome invalide")?;
    let logs = list
        .operators
        .into_iter()
        .flat_map(|operator| operator.logs)
        .map(|log| log.url)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(max_logs)
        .collect::<Vec<_>>();
    let log_count = logs.len();
    let database = database.clone();
    let mut pending = stream::iter(logs)
        .map(|log_url| {
            let client = client.clone();
            let database = database.clone();
            async move {
                let sth = client
                    .get(endpoint(&log_url, "ct/v1/get-sth"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<SignedTreeHead>()
                    .await?;
                if sth.tree_size == 0 {
                    return Ok::<_, anyhow::Error>((0, BTreeSet::new()));
                }
                let start = database
                    .ct_global_cursor(&log_url)?
                    .unwrap_or_else(|| {
                        sth.tree_size
                            .saturating_sub(initial_backfill.min(u64::MAX as usize) as u64)
                    })
                    .min(sth.tree_size);
                if start >= sth.tree_size {
                    return Ok((0, BTreeSet::new()));
                }
                let end = start
                    .saturating_add(entries_per_log.saturating_sub(1) as u64)
                    .min(sth.tree_size - 1);
                let response = client
                    .get(endpoint(&log_url, "ct/v1/get-entries"))
                    .query(&[("start", start), ("end", end)])
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<EntriesResponse>()
                    .await?;
                let processed = response.entries.len();
                let mut names = BTreeSet::new();
                for entry in &response.entries {
                    names.extend(names_from_entry(entry));
                }
                let next = if processed == 0 {
                    end.saturating_add(1)
                } else {
                    start.saturating_add(processed as u64)
                };
                database.store_ct_global_batch(&log_url, next, &names)?;
                Ok((processed, names))
            }
        })
        .buffer_unordered(4);
    let mut result = CtMonitorResult {
        logs_checked: log_count,
        ..CtMonitorResult::default()
    };
    let mut indexed_names = BTreeSet::new();
    while let Some(log_result) = pending.next().await {
        match log_result {
            Ok((processed, names)) => {
                result.entries_processed += processed;
                indexed_names.extend(names);
            }
            Err(_) => result.failures += 1,
        }
    }
    result.globally_indexed_names = indexed_names.len();
    result.names = database
        .ct_names_for_domain(domain, 100_000)?
        .into_iter()
        .filter(|name| is_subdomain(name, domain))
        .collect();
    database.store_passive_cache(
        domain,
        "ct-direct",
        &result.names.iter().cloned().collect::<Vec<_>>(),
    )?;
    if let Some(cache) = database.passive_cache(domain, "ct-direct")? {
        result.names = cache.names.into_iter().collect();
    }
    result.duration_ms = started.elapsed().as_millis();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_byte_lengths() {
        assert_eq!(read_u24(&[0x01, 0x02, 0x03], 0), Some(0x010203));
        assert_eq!(read_u24(&[0x01, 0x02], 0), None);
    }
}
