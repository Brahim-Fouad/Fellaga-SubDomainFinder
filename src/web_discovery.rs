use crate::archive_intelligence::{ArchiveLimits, analyze_archived_document};
use crate::db::{Database, WebCacheEntry, WebCacheMetadata};
use crate::dns::{DnsEngine, DnsResolutionOutcome};
use crate::model::{ResolvedHost, WebObservation};
use crate::util::{extract_observed_names, is_subdomain};
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream};
use reqwest::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_LOCATION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, ETAG,
    HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LINK, LOCATION, RANGE, REFRESH,
};
use reqwest::{Client, Url};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const EXTRA_HEADERS: &[&str] = &["report-to", "nel", "alt-svc", "x-frame-options"];

#[derive(Debug, Default)]
pub struct WebDiscovery {
    pub observations: Vec<WebObservation>,
    pub unique_names: BTreeSet<String>,
    pub network_requests: usize,
    /// Response body bytes retained for analysis. Cached observations and
    /// protocol overhead are deliberately excluded.
    pub bytes_transferred: u64,
    pub cache_hits: usize,
    pub failures: usize,
    pub duration_ms: u128,
    pub budget_exhausted: bool,
}

struct FetchResult {
    observation: WebObservation,
    assets: Vec<String>,
    network: bool,
}

#[derive(Default)]
struct WebIoCounters {
    requests: AtomicUsize,
    bytes: AtomicU64,
}

struct BoundedFetch {
    result: Option<FetchResult>,
    budget_exhausted: bool,
}

struct HostFetchBatch {
    results: Vec<FetchResult>,
    budget_exhausted: bool,
}

fn operation_deadline(
    timeout: Duration,
    phase_deadline: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    let request_deadline = tokio::time::Instant::now() + timeout;
    phase_deadline
        .map(|deadline| deadline.min(request_deadline))
        .unwrap_or(request_deadline)
}

async fn before_web_deadline<T, F>(deadline: Option<tokio::time::Instant>, future: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    match deadline {
        Some(deadline) if deadline <= tokio::time::Instant::now() => None,
        Some(deadline) => tokio::time::timeout_at(deadline, future).await.ok(),
        None => Some(future.await),
    }
}

fn web_deadline_expired(deadline: Option<tokio::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now())
}

fn merge_host_fetch_batch(discovery: &mut WebDiscovery, batch: HostFetchBatch) {
    discovery.budget_exhausted |= batch.budget_exhausted;
    for result in batch.results {
        if result.network {
            // Keep the partial object meaningful for callers/tests that merge
            // completed batches directly. discover_web replaces this with the
            // exact attempt counter (which also includes failed requests).
            discovery.network_requests += 1;
        } else {
            discovery.cache_hits += 1;
        }
        discovery
            .unique_names
            .extend(result.observation.names.clone());
        discovery.observations.push(result.observation);
    }
}

fn finish_web_discovery(mut discovery: WebDiscovery, started: Instant) -> WebDiscovery {
    discovery
        .observations
        .sort_by(|left, right| left.url.cmp(&right.url));
    discovery
        .observations
        .dedup_by(|left, right| left.url == right.url);
    discovery.duration_ms = started.elapsed().as_millis();
    discovery
}

fn cached_observation(url: String, cache: WebCacheEntry) -> WebObservation {
    WebObservation {
        url,
        status: cache.status,
        names: cache.names.into_iter().collect(),
        from_cache: true,
    }
}

fn cached_root_fetch(database: &Database, domain: &str, host: &str) -> Result<Option<FetchResult>> {
    for scheme in ["https", "http"] {
        let url = format!("{scheme}://{host}/");
        if let Some(cache) = database.web_cache(domain, &url)? {
            return Ok(Some(FetchResult {
                observation: cached_observation(url, cache),
                // A cache-only fallback must not turn cached asset URLs into
                // new network work after the Web phase deadline.
                assets: Vec::new(),
                network: false,
            }));
        }
    }
    Ok(None)
}

fn header_text(headers: &HeaderMap) -> String {
    let mut values = Vec::new();
    for name in [
        LOCATION,
        CONTENT_LOCATION,
        CONTENT_SECURITY_POLICY,
        LINK,
        REFRESH,
        ACCESS_CONTROL_ALLOW_ORIGIN,
    ] {
        values.extend(
            headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
        );
    }
    for name in EXTRA_HEADERS {
        values.extend(
            headers
                .get_all(*name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
        );
    }
    values.join("\n")
}

fn in_scope_url(url: &Url, domain: &str) -> bool {
    let allowed_port = match url.scheme() {
        "http" => url.port_or_known_default() == Some(80),
        "https" => url.port_or_known_default() == Some(443),
        _ => false,
    };
    url.host_str()
        .is_some_and(|host| host == domain || is_subdomain(host, domain))
        && allowed_port
        && url.username().is_empty()
        && url.password().is_none()
}

fn canonical_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    url.set_fragment(None);
    if url.path().is_empty() {
        url.set_path("/");
    }
    Some(url.to_string())
}

fn is_public_web_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
                || address == Ipv4Addr::BROADCAST)
        }
        IpAddr::V6(address) => {
            if let Some(embedded) = address.to_ipv4() {
                return is_public_web_ip(IpAddr::V4(embedded));
            }
            let segments = address.segments();
            !(address == Ipv6Addr::UNSPECIFIED
                || address == Ipv6Addr::LOCALHOST
                || address.is_multicast()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || segments[0] & 0xffc0 == 0xfec0
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && matches!(segments[2], 0 | 1))
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

async fn resolve_public_web_hosts(
    dns: &DnsEngine,
    hosts: BTreeSet<String>,
    timeout: Duration,
    phase_deadline: Option<tokio::time::Instant>,
) -> Result<(BTreeMap<String, Vec<SocketAddr>>, bool)> {
    if hosts.is_empty() {
        return Ok((BTreeMap::new(), false));
    }
    let dns = dns.clone();
    let results = stream::iter(hosts)
        .map(|host| {
            let dns = dns.clone();
            async move {
                let deadline = operation_deadline(timeout, phase_deadline);
                let outcome =
                    tokio::time::timeout_at(deadline, dns.resolve_host_classified(host.as_str()))
                        .await;
                let budget_exhausted =
                    outcome.is_err() && phase_deadline.is_some_and(|phase| deadline == phase);
                let addresses = outcome
                    .ok()
                    .and_then(|outcome| match outcome {
                        DnsResolutionOutcome::Positive(answer) => Some(answer),
                        DnsResolutionOutcome::Negative { .. }
                        | DnsResolutionOutcome::Indeterminate { .. } => None,
                    })
                    .map(|answer| public_socket_addresses(&answer))
                    .unwrap_or_default();
                (host, addresses, budget_exhausted)
            }
        })
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await;
    let budget_exhausted = results.iter().any(|(_, _, exhausted)| *exhausted);
    let pinned = results
        .into_iter()
        .filter_map(|(host, addresses, _)| (!addresses.is_empty()).then_some((host, addresses)))
        .collect();
    Ok((pinned, budget_exhausted))
}

fn public_socket_addresses(answer: &ResolvedHost) -> Vec<SocketAddr> {
    answer
        .records
        .iter()
        .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
        .filter_map(|record| record.value.parse().ok())
        .filter(|address| is_public_web_ip(*address))
        .map(|address| SocketAddr::new(address, 0))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn approved_asset_url(value: &str, domain: &str, approved_hosts: &BTreeSet<String>) -> bool {
    Url::parse(value)
        .ok()
        .filter(|url| in_scope_url(url, domain))
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .is_some_and(|host| approved_hosts.contains(&host))
}

fn textual_response(headers: &HeaderMap, url: &Url) -> bool {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.is_empty()
        || content_type.starts_with("text/")
        || ["javascript", "json", "xml", "x-www-form-urlencoded"]
            .iter()
            .any(|marker| content_type.contains(marker))
    {
        return true;
    }
    matches!(
        url.path()
            .rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .as_deref(),
        Some("js" | "mjs" | "map" | "json" | "html" | "htm" | "xml" | "webmanifest")
    )
}

async fn claim_url(visited: &Mutex<BTreeSet<String>>, url: &str) -> Option<String> {
    let canonical = canonical_url(url)?;
    visited
        .lock()
        .await
        .insert(canonical.clone())
        .then_some(canonical)
}

fn extract_asset_urls(text: &str, base: &Url, domain: &str, limit: usize) -> Vec<String> {
    let mut urls = BTreeSet::new();
    for token in text.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
            )
    }) {
        let value = token
            .rsplit_once('=')
            .map(|(_, value)| value)
            .unwrap_or(token)
            .trim_matches(|character: char| {
                matches!(character, '"' | '\'' | ':' | ')' | '(' | '>')
            });
        if value.is_empty() || value.starts_with("data:") {
            continue;
        }
        let Ok(url) = base.join(value) else {
            continue;
        };
        if !in_scope_url(&url, domain) || url == *base {
            continue;
        }
        let path = url.path().to_ascii_lowercase();
        if path.ends_with(".js")
            || path.ends_with(".mjs")
            || path.ends_with(".map")
            || path.ends_with(".json")
            || path.ends_with(".webmanifest")
            || path.contains("manifest")
        {
            urls.insert(url.to_string());
            if urls.len() >= limit {
                break;
            }
        }
    }
    urls.into_iter().collect()
}

fn response_body_limit(headers: &HeaderMap, configured_limit: usize) -> usize {
    headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .map_or(configured_limit, |declared| declared.min(configured_limit))
}

fn static_asset_url(value: &str, domain: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if !in_scope_url(&url, domain) {
        return false;
    }
    let path = url.path().to_ascii_lowercase();
    path.ends_with(".js")
        || path.ends_with(".mjs")
        || path.ends_with(".map")
        || path.ends_with(".json")
        || path.ends_with(".webmanifest")
        || path.contains("manifest")
}

fn archive_limits(max_bytes: usize, asset_limit: usize) -> ArchiveLimits {
    ArchiveLimits {
        max_archive_bytes: max_bytes,
        max_record_bytes: max_bytes,
        max_header_bytes: max_bytes.min(64 * 1024),
        max_records: 1,
        max_document_bytes: max_bytes,
        max_analysis_bytes: max_bytes.saturating_mul(4).min(16 * 1024 * 1024),
        max_names: 4_096,
        max_evidence: 8_192,
        max_urls: asset_limit.saturating_mul(4).min(512),
        max_js_literals: 4_096,
        max_string_bytes: max_bytes.min(4_096),
        max_json_values: 32_768,
    }
}

#[allow(clippy::too_many_arguments)]
fn enrich_with_archive_intelligence(
    domain: &str,
    source_url: &str,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
    asset_limit: usize,
    names: &mut BTreeSet<String>,
    assets: &mut Vec<String>,
) {
    let Ok(intelligence) = analyze_archived_document(
        domain,
        source_url,
        content_type,
        body,
        archive_limits(max_bytes, asset_limit),
    ) else {
        return;
    };
    names.extend(intelligence.names);
    for asset in intelligence.in_scope_urls {
        if assets.len() >= asset_limit {
            break;
        }
        if static_asset_url(&asset, domain) && !assets.contains(&asset) {
            assets.push(asset);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_url(
    database: &Database,
    client: &Client,
    domain: &str,
    url: String,
    refresh: Duration,
    max_bytes: usize,
    asset_limit: usize,
    phase_deadline: Option<tokio::time::Instant>,
    io: &WebIoCounters,
) -> Result<BoundedFetch> {
    let now = crate::util::now_epoch();
    let freshness = refresh.as_secs().min(i64::MAX as u64) as i64;
    let stale = database.web_cache(domain, &url)?;
    if let Some(cache) = &stale
        && now.saturating_sub(cache.updated_at) < freshness
    {
        return Ok(BoundedFetch {
            result: Some(FetchResult {
                observation: cached_observation(url, cache.clone()),
                assets: cache.assets.clone(),
                network: false,
            }),
            budget_exhausted: web_deadline_expired(phase_deadline),
        });
    }

    let fetched = before_web_deadline(phase_deadline, async {
        let mut request = client
            .get(&url)
            .header(RANGE, format!("bytes=0-{}", max_bytes.saturating_sub(1)));
        if let Some(cache) = &stale {
            if let Some(etag) = &cache.etag {
                request = request.header(IF_NONE_MATCH, etag);
            }
            if let Some(last_modified) = &cache.last_modified {
                request = request.header(IF_MODIFIED_SINCE, last_modified);
            }
        }
        io.requests.fetch_add(1, Ordering::Relaxed);
        let mut response = request.send().await.with_context(|| format!("GET {url}"))?;
        let status = response.status();
        let headers = response.headers().clone();
        if status == reqwest::StatusCode::NOT_MODIFIED
            && let Some(cache) = &stale
        {
            let refreshed = database.store_web_cache(
                domain,
                &url,
                cache.status,
                &cache.names.iter().cloned().collect(),
                &cache.assets,
                &WebCacheMetadata {
                    etag: cache.etag.clone(),
                    last_modified: cache.last_modified.clone(),
                    content_hash: cache.content_hash.clone(),
                },
            )?;
            return Ok::<_, anyhow::Error>(FetchResult {
                observation: cached_observation(url.clone(), refreshed),
                assets: cache.assets.clone(),
                network: true,
            });
        }
        if !status.is_success() && !status.is_redirection() {
            bail!("GET {url}: HTTP {status}");
        }
        let base = Url::parse(&url)?;
        let read_body = textual_response(&headers, &base);
        let body_limit = response_body_limit(&headers, max_bytes);
        let mut body = Vec::with_capacity(body_limit.min(64 * 1024));
        if read_body {
            while body.len() < body_limit {
                let Some(chunk) = response.chunk().await? else {
                    break;
                };
                let remaining = body_limit.saturating_sub(body.len());
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            }
        }
        io.bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
        let content_hash = format!("{:x}", Sha256::digest(&body));
        let body_text = String::from_utf8_lossy(&body);
        let metadata = format!("{}\n{}", header_text(&headers), body_text);
        let mut names = extract_observed_names(&metadata, domain);
        let mut assets = extract_asset_urls(&body_text, &base, domain, asset_limit);
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        enrich_with_archive_intelligence(
            domain,
            &url,
            content_type,
            &body,
            max_bytes,
            asset_limit,
            &mut names,
            &mut assets,
        );
        if status.is_redirection()
            && let Some(location) = headers.get(LOCATION).and_then(|value| value.to_str().ok())
            && let Ok(redirect) = base.join(location)
            && in_scope_url(&redirect, domain)
        {
            assets.insert(0, redirect.to_string());
            assets.truncate(asset_limit);
        }
        let etag = headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let last_modified = headers
            .get(LAST_MODIFIED)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let cache = database.store_web_cache(
            domain,
            &url,
            status.as_u16(),
            &names,
            &assets,
            &WebCacheMetadata {
                etag,
                last_modified,
                content_hash: Some(content_hash),
            },
        )?;
        Ok::<_, anyhow::Error>(FetchResult {
            observation: WebObservation {
                url: url.clone(),
                status: cache.status,
                names: cache.names.into_iter().collect(),
                from_cache: false,
            },
            assets,
            network: true,
        })
    })
    .await;
    match fetched {
        Some(Ok(result)) => Ok(BoundedFetch {
            result: Some(result),
            budget_exhausted: false,
        }),
        Some(Err(error)) => stale
            .map(|cache| {
                let assets = cache.assets.clone();
                BoundedFetch {
                    result: Some(FetchResult {
                        observation: cached_observation(url, cache),
                        assets,
                        network: false,
                    }),
                    budget_exhausted: false,
                }
            })
            .ok_or(error),
        None => Ok(BoundedFetch {
            result: stale.map(|cache| {
                let assets = cache.assets.clone();
                FetchResult {
                    observation: cached_observation(url, cache),
                    assets,
                    network: false,
                }
            }),
            budget_exhausted: true,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_web(
    database: &Database,
    dns: &DnsEngine,
    domain: &str,
    hosts: Vec<String>,
    timeout: Duration,
    refresh: Duration,
    concurrency: usize,
    max_bytes: usize,
    assets_per_host: usize,
) -> Result<WebDiscovery> {
    discover_web_bounded(
        database,
        dns,
        domain,
        hosts,
        timeout,
        refresh,
        concurrency,
        max_bytes,
        assets_per_host,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_web_bounded(
    database: &Database,
    dns: &DnsEngine,
    domain: &str,
    hosts: Vec<String>,
    timeout: Duration,
    refresh: Duration,
    concurrency: usize,
    max_bytes: usize,
    assets_per_host: usize,
    phase_deadline: Option<tokio::time::Instant>,
) -> Result<WebDiscovery> {
    let started = Instant::now();
    let requested_hosts = hosts.into_iter().collect::<BTreeSet<_>>();
    let (pinned_hosts, resolution_budget_exhausted) =
        resolve_public_web_hosts(dns, requested_hosts.clone(), timeout, phase_deadline).await?;
    let mut discovery = WebDiscovery {
        budget_exhausted: resolution_budget_exhausted,
        ..WebDiscovery::default()
    };
    let io = Arc::new(WebIoCounters::default());
    for host in requested_hosts
        .iter()
        .filter(|host| !pinned_hosts.contains_key(*host))
    {
        if let Some(result) = cached_root_fetch(database, domain, host)? {
            merge_host_fetch_batch(
                &mut discovery,
                HostFetchBatch {
                    results: vec![result],
                    budget_exhausted: resolution_budget_exhausted,
                },
            );
        }
    }
    if pinned_hosts.is_empty() {
        discovery.network_requests = io.requests.load(Ordering::Relaxed);
        discovery.bytes_transferred = io.bytes.load(Ordering::Relaxed);
        return Ok(finish_web_discovery(discovery, started));
    }
    let approved_hosts = Arc::new(pinned_hosts.keys().cloned().collect::<BTreeSet<_>>());
    let mut client_builder = Client::builder()
        .timeout(timeout)
        // Les IP ont été résolues et épinglées ci-dessus; un proxy système
        // contournerait cette protection et pourrait réintroduire du SSRF.
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .user_agent(concat!(
            "Fellaga-SubDomainFinder/",
            env!("CARGO_PKG_VERSION")
        ));
    for (host, addresses) in &pinned_hosts {
        client_builder = client_builder.resolve_to_addrs(host, addresses);
    }
    let client = client_builder.build()?;
    let database = database.clone();
    let domain_owned = domain.to_owned();
    let visited = Arc::new(Mutex::new(BTreeSet::new()));
    let mut pending = stream::iter(approved_hosts.iter().cloned())
        .map(|host| {
            let database = database.clone();
            let client = client.clone();
            let domain = domain_owned.clone();
            let visited = visited.clone();
            let approved_hosts = approved_hosts.clone();
            let io = io.clone();
            async move {
                let Some(https) = claim_url(&visited, &format!("https://{host}/")).await else {
                    return Ok::<_, anyhow::Error>(HostFetchBatch {
                        results: Vec::new(),
                        budget_exhausted: false,
                    });
                };
                let https_result = fetch_url(
                    &database,
                    &client,
                    &domain,
                    https,
                    refresh,
                    max_bytes,
                    assets_per_host,
                    phase_deadline,
                    &io,
                )
                .await;
                let root = match https_result {
                    Ok(BoundedFetch {
                        result: Some(result),
                        budget_exhausted: false,
                    }) => result,
                    Ok(BoundedFetch {
                        result: Some(result),
                        budget_exhausted: true,
                    }) => {
                        return Ok(HostFetchBatch {
                            results: vec![result],
                            budget_exhausted: true,
                        });
                    }
                    Ok(BoundedFetch { result: None, .. }) | Err(_) => {
                        let Some(http) = claim_url(&visited, &format!("http://{host}/")).await
                        else {
                            return Ok(HostFetchBatch {
                                results: Vec::new(),
                                budget_exhausted: web_deadline_expired(phase_deadline),
                            });
                        };
                        let http_result = fetch_url(
                            &database,
                            &client,
                            &domain,
                            http,
                            refresh,
                            max_bytes,
                            assets_per_host,
                            phase_deadline,
                            &io,
                        )
                        .await?;
                        if http_result.budget_exhausted {
                            return Ok(HostFetchBatch {
                                results: http_result.result.into_iter().collect(),
                                budget_exhausted: true,
                            });
                        }
                        let Some(result) = http_result.result else {
                            return Ok(HostFetchBatch {
                                results: Vec::new(),
                                budget_exhausted: false,
                            });
                        };
                        result
                    }
                };
                let mut results = vec![root];
                let mut assets = results[0].assets.iter().cloned().collect::<VecDeque<_>>();
                let mut attempted_assets = 0_usize;
                let mut budget_exhausted = false;
                while attempted_assets < assets_per_host {
                    let Some(asset) = assets.pop_front() else {
                        break;
                    };
                    if !approved_asset_url(&asset, &domain, &approved_hosts) {
                        continue;
                    }
                    let Some(asset) = claim_url(&visited, &asset).await else {
                        continue;
                    };
                    attempted_assets += 1;
                    if let Ok(asset_result) = fetch_url(
                        &database,
                        &client,
                        &domain,
                        asset,
                        refresh,
                        max_bytes,
                        assets_per_host.saturating_sub(attempted_assets),
                        phase_deadline,
                        &io,
                    )
                    .await
                    {
                        if let Some(result) = asset_result.result {
                            assets.extend(result.assets.iter().cloned());
                            results.push(result);
                        }
                        if asset_result.budget_exhausted {
                            budget_exhausted = true;
                            break;
                        }
                    }
                }
                Ok::<_, anyhow::Error>(HostFetchBatch {
                    results,
                    budget_exhausted,
                })
            }
        })
        .buffer_unordered(concurrency.max(1));

    while let Some(result) = pending.next().await {
        match result {
            Ok(batch) => merge_host_fetch_batch(&mut discovery, batch),
            Err(_) => discovery.failures += 1,
        }
    }
    discovery.network_requests = io.requests.load(Ordering::Relaxed);
    discovery.bytes_transferred = io.bytes.load(Ordering::Relaxed);
    Ok(finish_web_discovery(discovery, started))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DnsRecord;

    #[test]
    fn extracts_only_useful_in_scope_assets() {
        let base = Url::parse("https://www.example.com/").unwrap();
        let assets = extract_asset_urls(
            r#"<script src="/assets/app.js"></script><a href="https://cdn.example.com/manifest.json">x</a><script src="https://evil.test/x.js"></script>"#,
            &base,
            "example.com",
            5,
        );
        assert_eq!(assets.len(), 2);
        assert!(assets.iter().all(|url| url.contains("example.com")));
    }

    #[test]
    fn recognizes_success_and_redirect_statuses() {
        assert!(reqwest::StatusCode::OK.is_success());
        assert!(reqwest::StatusCode::FOUND.is_redirection());
    }

    #[test]
    fn canonical_urls_drop_fragments_and_keep_a_root_path() {
        assert_eq!(
            canonical_url("https://www.example.com#section").as_deref(),
            Some("https://www.example.com/")
        );
    }

    #[test]
    fn scope_rejects_non_web_ports_and_embedded_credentials() {
        assert!(in_scope_url(
            &Url::parse("https://cdn.example.com/app.js").unwrap(),
            "example.com"
        ));
        assert!(in_scope_url(
            &Url::parse("http://cdn.example.com:80/app.js").unwrap(),
            "example.com"
        ));
        assert!(!in_scope_url(
            &Url::parse("https://cdn.example.com:8443/app.js").unwrap(),
            "example.com"
        ));
        assert!(!in_scope_url(
            &Url::parse("https://user:secret@cdn.example.com/app.js").unwrap(),
            "example.com"
        ));
    }

    #[test]
    fn private_addresses_and_unvalidated_asset_hosts_are_rejected() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:192.168.1.1",
            "64:ff9b::c0a8:101",
        ] {
            assert!(!is_public_web_ip(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_web_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_web_ip("2606:4700:4700::1111".parse().unwrap()));

        let resolved = ResolvedHost {
            fqdn: "www.example.com".to_owned(),
            records: vec![
                DnsRecord {
                    record_type: "A".to_owned(),
                    value: "10.0.0.1".to_owned(),
                    ttl: 60,
                },
                DnsRecord {
                    record_type: "A".to_owned(),
                    value: "1.1.1.1".to_owned(),
                    ttl: 60,
                },
            ],
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 1,
        };
        assert_eq!(
            public_socket_addresses(&resolved),
            vec!["1.1.1.1:0".parse().unwrap()]
        );

        let approved = BTreeSet::from(["www.example.com".to_owned()]);
        assert!(approved_asset_url(
            "https://www.example.com/app.js",
            "example.com",
            &approved
        ));
        assert!(!approved_asset_url(
            "https://internal.example.com/app.js",
            "example.com",
            &approved
        ));
        assert!(!approved_asset_url(
            "https://www.example.com:8443/app.js",
            "example.com",
            &approved
        ));
    }

    #[test]
    fn web_resolution_uses_only_the_shared_dns_engine() {
        let source = include_str!("web_discovery.rs");
        for forbidden in [
            ["Tokio", "Resolver"].concat(),
            ["lookup", "_host"].concat(),
            ["ToSocket", "Addrs"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden resolver: {forbidden}"
            );
        }
        assert!(source.contains("dns: &DnsEngine"));
    }

    #[test]
    fn only_textual_or_explicit_script_representations_are_parsed() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "image/png".parse().unwrap());
        assert!(!textual_response(
            &headers,
            &Url::parse("https://www.example.com/logo.png").unwrap()
        ));
        assert!(textual_response(
            &headers,
            &Url::parse("https://www.example.com/app.js").unwrap()
        ));
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(textual_response(
            &headers,
            &Url::parse("https://www.example.com/api").unwrap()
        ));
    }

    #[test]
    fn content_length_and_configured_cap_bound_each_response_body() {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::CONTENT_LENGTH, "12".parse().unwrap());
        assert_eq!(response_body_limit(&headers, 1_024), 12);
        headers.insert(
            reqwest::header::CONTENT_LENGTH,
            "999999999".parse().unwrap(),
        );
        assert_eq!(response_body_limit(&headers, 1_024), 1_024);
        headers.insert(reqwest::header::CONTENT_LENGTH, "invalid".parse().unwrap());
        assert_eq!(response_body_limit(&headers, 1_024), 1_024);
    }

    #[test]
    fn static_javascript_intelligence_enriches_names_but_only_queues_safe_assets() {
        let body = include_bytes!("../tests/fixtures/archive/bundle.js");
        let mut names = BTreeSet::new();
        let mut assets = Vec::new();
        enrich_with_archive_intelligence(
            "example.com",
            "https://static.example.com/assets/bundle.js",
            "application/javascript",
            body,
            body.len(),
            16,
            &mut names,
            &mut assets,
        );

        for expected in [
            "api-v2.example.com",
            "fetch.example.com",
            "axios.example.com",
            "events.example.com",
            "webpack.example.com",
            "vite.example.com",
            "next.example.com",
            "maps.example.com",
        ] {
            assert!(names.contains(expected), "missing {expected}");
        }
        assert_eq!(
            assets,
            vec!["https://maps.example.com/assets/bundle.js.map"]
        );
        assert!(
            assets
                .iter()
                .all(|asset| static_asset_url(asset, "example.com"))
        );
        assert!(!assets.iter().any(|asset| asset.contains("graphql")));
    }

    #[tokio::test]
    async fn url_claims_are_global_and_canonical() {
        let visited = Mutex::new(BTreeSet::new());
        assert_eq!(
            claim_url(&visited, "https://www.example.com#first").await,
            Some("https://www.example.com/".to_owned())
        );
        assert_eq!(
            claim_url(&visited, "https://www.example.com/#second").await,
            None
        );
    }

    #[tokio::test]
    async fn expired_web_deadline_cancels_pending_work() {
        let result = before_web_deadline(
            Some(tokio::time::Instant::now() - Duration::from_millis(1)),
            std::future::pending::<()>(),
        )
        .await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn expired_network_budget_still_returns_fresh_and_stale_cache() {
        let database = Database::in_memory().unwrap();
        let url = "https://www.example.com/";
        database
            .store_web_cache(
                "example.com",
                url,
                200,
                &BTreeSet::from(["api.example.com".to_owned()]),
                &["https://www.example.com/app.js".to_owned()],
                &WebCacheMetadata::default(),
            )
            .unwrap();
        let client = Client::builder().build().unwrap();
        let expired = Some(tokio::time::Instant::now() - Duration::from_millis(1));
        let io = WebIoCounters::default();

        for refresh in [Duration::from_secs(3_600), Duration::ZERO] {
            let fetched = fetch_url(
                &database,
                &client,
                "example.com",
                url.to_owned(),
                refresh,
                1_024,
                4,
                expired,
                &io,
            )
            .await
            .unwrap();
            assert!(fetched.budget_exhausted);
            let cached = fetched.result.expect("cached result must survive deadline");
            assert!(!cached.network);
            assert!(cached.observation.from_cache);
            assert!(cached.observation.names.contains("api.example.com"));
        }
    }

    #[tokio::test]
    async fn expired_public_web_budget_returns_cached_root_without_network() {
        let database = Database::in_memory().unwrap();
        database
            .store_web_cache(
                "example.com",
                "https://www.example.com/",
                200,
                &BTreeSet::from(["api.example.com".to_owned()]),
                &["https://www.example.com/app.js".to_owned()],
                &WebCacheMetadata::default(),
            )
            .unwrap();
        let dns = DnsEngine::new_with_socket_addresses(
            1,
            Duration::from_secs(1),
            &["127.0.0.1:9".parse().unwrap()],
            0,
        )
        .unwrap();

        let discovery = discover_web_bounded(
            &database,
            &dns,
            "example.com",
            vec!["www.example.com".to_owned()],
            Duration::from_secs(1),
            Duration::ZERO,
            1,
            1_024,
            4,
            Some(tokio::time::Instant::now() - Duration::from_millis(1)),
        )
        .await
        .unwrap();

        assert!(discovery.budget_exhausted);
        assert_eq!(discovery.cache_hits, 1);
        assert_eq!(discovery.network_requests, 0);
        assert_eq!(discovery.observations.len(), 1);
        assert_eq!(discovery.observations[0].url, "https://www.example.com/");
        assert!(discovery.observations[0].from_cache);
        assert!(discovery.observations[0].names.contains("api.example.com"));
        assert!(discovery.unique_names.contains("api.example.com"));
    }

    #[test]
    fn phase_deadline_caps_each_web_operation() {
        let phase = tokio::time::Instant::now() + Duration::from_secs(1);
        assert_eq!(
            operation_deadline(Duration::from_secs(30), Some(phase)),
            phase
        );
        let per_request = operation_deadline(Duration::from_secs(1), None);
        assert!(per_request > tokio::time::Instant::now());
        assert!(per_request <= tokio::time::Instant::now() + Duration::from_secs(2));
    }

    #[test]
    fn completed_results_survive_a_later_web_budget_expiration() {
        let observation = WebObservation {
            url: "https://www.example.com/app.js".to_owned(),
            status: 200,
            names: BTreeSet::from(["api.example.com".to_owned()]),
            from_cache: false,
        };
        let mut discovery = WebDiscovery::default();
        merge_host_fetch_batch(
            &mut discovery,
            HostFetchBatch {
                results: vec![FetchResult {
                    observation: observation.clone(),
                    assets: Vec::new(),
                    network: true,
                }],
                budget_exhausted: true,
            },
        );
        assert!(discovery.budget_exhausted);
        assert_eq!(discovery.network_requests, 1);
        assert_eq!(discovery.observations.len(), 1);
        assert_eq!(discovery.observations[0].url, observation.url);
        assert_eq!(discovery.observations[0].names, observation.names);
        assert!(discovery.unique_names.contains("api.example.com"));
    }
}
