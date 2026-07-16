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
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const EXTRA_HEADERS: &[&str] = &["report-to", "nel", "alt-svc", "x-frame-options"];

#[derive(Debug, Default)]
pub struct WebDiscovery {
    pub observations: Vec<WebObservation>,
    pub unique_names: BTreeSet<String>,
    pub network_requests: usize,
    pub cache_hits: usize,
    pub failures: usize,
    pub duration_ms: u128,
}

struct FetchResult {
    observation: WebObservation,
    assets: Vec<String>,
    network: bool,
}

fn cached_observation(url: String, cache: WebCacheEntry) -> WebObservation {
    WebObservation {
        url,
        status: cache.status,
        names: cache.names.into_iter().collect(),
        from_cache: true,
    }
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
) -> Result<BTreeMap<String, Vec<SocketAddr>>> {
    if hosts.is_empty() {
        return Ok(BTreeMap::new());
    }
    let dns = dns.clone();
    Ok(stream::iter(hosts)
        .map(|host| {
            let dns = dns.clone();
            async move {
                let deadline = tokio::time::Instant::now() + timeout;
                let addresses =
                    tokio::time::timeout_at(deadline, dns.resolve_host_classified(host.as_str()))
                        .await
                        .ok()
                        .and_then(|outcome| match outcome {
                            DnsResolutionOutcome::Positive(answer) => Some(answer),
                            DnsResolutionOutcome::Negative { .. }
                            | DnsResolutionOutcome::Indeterminate { .. } => None,
                        })
                        .map(|answer| public_socket_addresses(&answer))
                        .unwrap_or_default();
                (host, addresses)
            }
        })
        .buffer_unordered(32)
        .filter_map(|(host, addresses)| async move {
            (!addresses.is_empty()).then_some((host, addresses))
        })
        .collect()
        .await)
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

#[allow(clippy::too_many_arguments)]
async fn fetch_url(
    database: &Database,
    client: &Client,
    domain: &str,
    url: String,
    refresh: Duration,
    max_bytes: usize,
    asset_limit: usize,
) -> Result<FetchResult> {
    let now = crate::util::now_epoch();
    let freshness = refresh.as_secs().min(i64::MAX as u64) as i64;
    let stale = database.web_cache(domain, &url)?;
    if let Some(cache) = &stale
        && now.saturating_sub(cache.updated_at) < freshness
    {
        return Ok(FetchResult {
            observation: cached_observation(url, cache.clone()),
            assets: cache.assets.clone(),
            network: false,
        });
    }

    let fetched = async {
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
        let mut body = Vec::new();
        if read_body {
            while body.len() < max_bytes {
                let Some(chunk) = response.chunk().await? else {
                    break;
                };
                let remaining = max_bytes.saturating_sub(body.len());
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            }
        }
        let content_hash = format!("{:x}", Sha256::digest(&body));
        let body = String::from_utf8_lossy(&body);
        let metadata = format!("{}\n{}", header_text(&headers), body);
        let names = extract_observed_names(&metadata, domain);
        let mut assets = extract_asset_urls(&body, &base, domain, asset_limit);
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
    }
    .await;
    match fetched {
        Ok(result) => Ok(result),
        Err(error) => stale
            .map(|cache| {
                let assets = cache.assets.clone();
                FetchResult {
                    observation: cached_observation(url, cache),
                    assets,
                    network: false,
                }
            })
            .ok_or(error),
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
    let started = Instant::now();
    let pinned_hosts = resolve_public_web_hosts(dns, hosts.into_iter().collect(), timeout).await?;
    if pinned_hosts.is_empty() {
        return Ok(WebDiscovery {
            duration_ms: started.elapsed().as_millis(),
            ..WebDiscovery::default()
        });
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
            async move {
                let Some(https) = claim_url(&visited, &format!("https://{host}/")).await else {
                    return Ok::<_, anyhow::Error>(Vec::new());
                };
                let root = match fetch_url(
                    &database,
                    &client,
                    &domain,
                    https,
                    refresh,
                    max_bytes,
                    assets_per_host,
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        let Some(http) = claim_url(&visited, &format!("http://{host}/")).await
                        else {
                            return Ok(Vec::new());
                        };
                        fetch_url(
                            &database,
                            &client,
                            &domain,
                            http,
                            refresh,
                            max_bytes,
                            assets_per_host,
                        )
                        .await?
                    }
                };
                let mut results = vec![root];
                let mut assets = results[0].assets.iter().cloned().collect::<VecDeque<_>>();
                let mut attempted_assets = 0_usize;
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
                    if let Ok(result) = fetch_url(
                        &database,
                        &client,
                        &domain,
                        asset,
                        refresh,
                        max_bytes,
                        assets_per_host.saturating_sub(attempted_assets),
                    )
                    .await
                    {
                        assets.extend(result.assets.iter().cloned());
                        results.push(result);
                    }
                }
                Ok::<_, anyhow::Error>(results)
            }
        })
        .buffer_unordered(concurrency.max(1));

    let mut discovery = WebDiscovery::default();
    while let Some(result) = pending.next().await {
        match result {
            Ok(results) => {
                for result in results {
                    if result.network {
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
            Err(_) => discovery.failures += 1,
        }
    }
    discovery
        .observations
        .sort_by(|left, right| left.url.cmp(&right.url));
    discovery
        .observations
        .dedup_by(|left, right| left.url == right.url);
    discovery.duration_ms = started.elapsed().as_millis();
    Ok(discovery)
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
}
