use crate::db::Database;
use crate::model::CtMonitorResult;
use crate::util::{is_subdomain, normalize_hostname};
use anyhow::{Context, Result, bail};
use base64::Engine;
use futures_util::{StreamExt, stream};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
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

fn next_batch_cursor(start: u64, end: u64, processed: usize) -> Result<u64> {
    if processed == 0 {
        bail!("le journal CT a retourné une page vide pour {start}..={end}");
    }
    let requested = end.saturating_sub(start).saturating_add(1);
    if processed as u64 > requested {
        bail!("le journal CT a retourné {processed} entrées pour une fenêtre de {requested}");
    }
    Ok(start.saturating_add(processed as u64))
}

fn select_logs(
    logs: BTreeSet<String>,
    states: &HashMap<String, (u64, i64)>,
    max_logs: usize,
) -> Vec<String> {
    let mut logs = logs.into_iter().collect::<Vec<_>>();
    logs.sort_by_key(|log| {
        let state = states.get(log);
        (
            state.is_some(),
            state.map(|(_, updated)| *updated).unwrap_or(i64::MIN),
            log.clone(),
        )
    });
    logs.truncate(max_logs);
    logs
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
    let all_logs = list
        .operators
        .into_iter()
        .flat_map(|operator| operator.logs)
        .map(|log| log.url)
        .collect::<BTreeSet<_>>();
    if max_logs > 0 && all_logs.is_empty() {
        bail!("la liste CT de Chrome ne contient aucun journal");
    }
    let logs = select_logs(all_logs, &database.ct_global_states()?, max_logs);
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
                    if database.ct_global_cursor(&log_url)?.unwrap_or_default() > 0 {
                        bail!("le journal CT {log_url} annonce une taille nulle après indexation");
                    }
                    database.store_ct_global_batch(&log_url, 0, &BTreeSet::new())?;
                    return Ok::<_, anyhow::Error>((0, BTreeSet::new()));
                }
                let stored = database.ct_global_cursor(&log_url)?;
                let backfill_start = || {
                    sth.tree_size
                        .saturating_sub(initial_backfill.min(u64::MAX as usize) as u64)
                };
                let mut start = match stored {
                    Some(cursor) if cursor > sth.tree_size => {
                        let reset = backfill_start();
                        database.reset_ct_global_cursor(&log_url, reset)?;
                        reset
                    }
                    Some(cursor) => cursor,
                    None => backfill_start(),
                };
                if start >= sth.tree_size || entries_per_log == 0 {
                    database.store_ct_global_batch(&log_url, start, &BTreeSet::new())?;
                    return Ok((0, BTreeSet::new()));
                }
                let mut total_processed = 0_usize;
                let mut pages = 0_usize;
                let mut names = BTreeSet::new();
                while start < sth.tree_size && total_processed < entries_per_log && pages < 64 {
                    let remaining = entries_per_log.saturating_sub(total_processed);
                    let end = start
                        .saturating_add(remaining.saturating_sub(1) as u64)
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
                    let mut batch_names = BTreeSet::new();
                    for entry in &response.entries {
                        batch_names.extend(names_from_entry(entry));
                    }
                    let next = next_batch_cursor(start, end, processed)?;
                    database.store_ct_global_batch(&log_url, next, &batch_names)?;
                    names.extend(batch_names);
                    total_processed = total_processed.saturating_add(processed);
                    pages += 1;
                    start = next;
                }
                Ok((total_processed, names))
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
    fn an_empty_ct_page_never_advances_the_cursor() {
        assert!(next_batch_cursor(100, 199, 0).is_err());
        assert_eq!(next_batch_cursor(100, 199, 25).unwrap(), 125);
        assert!(next_batch_cursor(100, 199, 101).is_err());
    }

    #[test]
    fn log_selection_prioritizes_unseen_then_oldest_logs() {
        let logs = BTreeSet::from([
            "https://a.example/".to_owned(),
            "https://b.example/".to_owned(),
            "https://c.example/".to_owned(),
        ]);
        let states = HashMap::from([
            ("https://a.example/".to_owned(), (10, 200)),
            ("https://b.example/".to_owned(), (20, 100)),
        ]);
        assert_eq!(
            select_logs(logs, &states, 2),
            vec![
                "https://c.example/".to_owned(),
                "https://b.example/".to_owned()
            ]
        );
    }

    #[test]
    fn parses_three_byte_lengths() {
        assert_eq!(read_u24(&[0x01, 0x02, 0x03], 0), Some(0x010203));
        assert_eq!(read_u24(&[0x01, 0x02], 0), None);
    }
}
