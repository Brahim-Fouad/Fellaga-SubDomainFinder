use crate::db::{Database, DnssecCacheEntry};
use crate::dns::DnsEngine;
use crate::model::DnssecWalkResult;
use crate::util::{normalize_observed_name, now_epoch};
use futures_util::{StreamExt, stream};
use hickory_client::client::Client;
use hickory_client::proto::op::Query;
use hickory_client::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::xfer::{DnsHandle, DnsRequestOptions};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;

fn cached_result(zone: String, cache: DnssecCacheEntry) -> DnssecWalkResult {
    DnssecWalkResult {
        zone,
        nameserver: cache.nameserver,
        status: cache.status,
        queries: 0,
        names: cache.names.into_iter().collect(),
        from_cache: true,
        error: None,
    }
}

async fn walk_one(
    root_domain: &str,
    zone: &str,
    nameserver: &str,
    address: IpAddr,
    operation_timeout: Duration,
    max_names: usize,
) -> DnssecWalkResult {
    let mut result = DnssecWalkResult {
        zone: zone.to_owned(),
        nameserver: nameserver.to_owned(),
        status: "unsupported".to_owned(),
        queries: 0,
        names: BTreeSet::new(),
        from_cache: false,
        error: None,
    };
    let zone_name = match Name::from_str(&format!("{zone}.")) {
        Ok(name) => name,
        Err(error) => {
            result.error = Some(error.to_string());
            return result;
        }
    };
    let socket = SocketAddr::new(address, 53);
    let (stream, sender) = TcpClientStream::new(socket, None, None, TokioRuntimeProvider::new());
    let client_future = Client::new(stream, sender, None);
    let (client, background) = match timeout(operation_timeout, client_future).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => {
            result.error = Some(error.to_string());
            return result;
        }
        Err(_) => {
            result.error = Some("timeout de connexion DNSSEC".to_owned());
            return result;
        }
    };
    tokio::spawn(background);

    let probe_name = match Name::from_str(&format!("fellaga-nsec-probe-7f4b9d.{zone}.")) {
        Ok(name) => name,
        Err(error) => {
            result.error = Some(error.to_string());
            return result;
        }
    };
    result.queries += 1;
    let mut probe_query = Query::query(probe_name, RecordType::A);
    probe_query.set_query_class(DNSClass::IN);
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    options.edns_set_dnssec_ok = true;
    options.recursion_desired = false;
    let mut probe_responses = client.lookup(probe_query, options);
    let probe = match timeout(operation_timeout, probe_responses.next()).await {
        Ok(Some(Ok(response))) => response,
        Ok(Some(Err(error))) => {
            result.error = Some(error.to_string());
            return result;
        }
        Ok(None) => {
            result.error = Some("réponse DNSSEC vide".to_owned());
            return result;
        }
        Err(_) => {
            result.error = Some("timeout de détection NSEC".to_owned());
            return result;
        }
    };
    let mut current = None;
    let mut nsec3 = false;
    for record in probe.answers().iter().chain(probe.name_servers()) {
        let RData::DNSSEC(data) = record.data() else {
            continue;
        };
        if data.as_nsec3().is_some() {
            nsec3 = true;
        }
        let Some(nsec) = data.as_nsec() else {
            continue;
        };
        let owner = record
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let next_name = nsec
            .next_domain_name()
            .to_utf8()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if next_name.starts_with("\\000.") {
            result.status = "nsec-minimal-protected".to_owned();
            return result;
        }
        if let Some(owner) = normalize_observed_name(&owner, root_domain) {
            result.names.insert(owner);
        }
        if let Some(name) = normalize_observed_name(&next_name, root_domain) {
            result.names.insert(name);
        }
        current = Some(nsec.next_domain_name().clone());
        break;
    }
    let Some(mut current) = current else {
        if nsec3 {
            result.status = "nsec3-protected".to_owned();
        }
        return result;
    };
    if current == zone_name {
        result.status = "walked".to_owned();
        return result;
    }
    let mut seen = BTreeSet::new();
    loop {
        if result.names.len() >= max_names || result.queries >= max_names.saturating_add(2) {
            result.status = "partial".to_owned();
            break;
        }
        let current_text = current.to_utf8().to_ascii_lowercase();
        if !seen.insert(current_text) {
            result.status = "walked".to_owned();
            break;
        }
        result.queries += 1;
        let mut nsec_query = Query::query(current.clone(), RecordType::NSEC);
        nsec_query.set_query_class(DNSClass::IN);
        let mut nsec_responses = client.lookup(nsec_query, options);
        let response = match timeout(operation_timeout, nsec_responses.next()).await {
            Ok(Some(Ok(response))) => response,
            Ok(Some(Err(error))) => {
                result.error = Some(error.to_string());
                break;
            }
            Ok(None) => {
                result.error = Some("réponse NSEC vide".to_owned());
                break;
            }
            Err(_) => {
                result.error = Some("timeout pendant NSEC walking".to_owned());
                break;
            }
        };
        let mut next = None;
        let mut nsec3 = false;
        for record in response.answers().iter().chain(response.name_servers()) {
            let RData::DNSSEC(data) = record.data() else {
                continue;
            };
            if data.as_nsec3().is_some() {
                nsec3 = true;
            }
            let Some(nsec) = data.as_nsec() else {
                continue;
            };
            let owner = record
                .name()
                .to_utf8()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let next_name = nsec
                .next_domain_name()
                .to_utf8()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if let Some(owner) = normalize_observed_name(&owner, root_domain) {
                result.names.insert(owner);
            }
            if let Some(name) = normalize_observed_name(&next_name, root_domain) {
                result.names.insert(name);
            }
            next = Some(nsec.next_domain_name().clone());
            break;
        }
        if nsec3 && next.is_none() {
            result.status = "nsec3-protected".to_owned();
            break;
        }
        let Some(next_name) = next else {
            break;
        };
        if next_name == zone_name {
            result.status = "walked".to_owned();
            break;
        }
        current = next_name;
    }
    result
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_nsec(
    database: &Database,
    dns: &DnsEngine,
    root_domain: &str,
    zones: BTreeSet<String>,
    operation_timeout: Duration,
    refresh: Duration,
    max_names: usize,
) -> Vec<DnssecWalkResult> {
    let now = now_epoch();
    let freshness = refresh.as_secs().min(i64::MAX as u64) as i64;
    let database = database.clone();
    let dns = dns.clone();
    let root = root_domain.to_owned();
    let mut pending = stream::iter(zones)
        .map(move |zone| {
            let database = database.clone();
            let dns = dns.clone();
            let root = root.clone();
            async move {
                let cached = database.dnssec_cache(&root, &zone).ok().flatten();
                if let Some(cache) = &cached
                    && now.saturating_sub(cache.updated_at) < freshness
                {
                    return cached_result(zone, cache.clone());
                }
                let mut best = DnssecWalkResult {
                    zone: zone.clone(),
                    nameserver: String::new(),
                    status: "unsupported".to_owned(),
                    queries: 0,
                    names: BTreeSet::new(),
                    from_cache: false,
                    error: Some("aucun serveur DNS autoritaire joignable".to_owned()),
                };
                if let Ok(servers) = dns.authoritative_servers(&zone).await {
                    'servers: for (nameserver, addresses) in servers {
                        for address in addresses {
                            let attempt = walk_one(
                                &root,
                                &zone,
                                &nameserver,
                                address,
                                operation_timeout,
                                max_names,
                            )
                            .await;
                            let terminal = matches!(
                                attempt.status.as_str(),
                                "walked" | "partial" | "nsec3-protected" | "nsec-minimal-protected"
                            );
                            best = attempt;
                            if terminal {
                                break 'servers;
                            }
                        }
                    }
                }
                if best.names.is_empty()
                    && best.status == "unsupported"
                    && let Some(cache) = cached
                {
                    return cached_result(zone, cache);
                }
                if matches!(
                    best.status.as_str(),
                    "walked" | "partial" | "nsec3-protected" | "nsec-minimal-protected"
                ) && let Ok(cache) = database.store_dnssec_cache(
                    &root,
                    &zone,
                    &best.nameserver,
                    &best.status,
                    &best.names,
                ) {
                    best.names = cache.names.into_iter().collect();
                }
                best
            }
        })
        .buffer_unordered(4);
    let mut results = Vec::new();
    while let Some(result) = pending.next().await {
        results.push(result);
    }
    results.sort_by(|left, right| left.zone.cmp(&right.zone));
    results
}
