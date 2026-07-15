use crate::db::{Database, WebCacheEntry, WebCacheMetadata};
use crate::model::WebObservation;
use crate::util::{extract_observed_names, is_subdomain};
use anyhow::{Context, Result};
use futures_util::{StreamExt, stream};
use reqwest::header::{
    ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_LOCATION, CONTENT_SECURITY_POLICY, ETAG, HeaderMap,
    IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LINK, LOCATION, RANGE, REFRESH,
};
use reqwest::{Client, Url};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
    url.host_str()
        .is_some_and(|host| host == domain || is_subdomain(host, domain))
        && matches!(url.scheme(), "http" | "https")
}

fn canonical_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    url.set_fragment(None);
    if url.path().is_empty() {
        url.set_path("/");
    }
    Some(url.to_string())
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
            assets: Vec::new(),
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
                &BTreeSet::new(),
                &WebCacheMetadata {
                    etag: cache.etag.clone(),
                    last_modified: cache.last_modified.clone(),
                    content_hash: cache.content_hash.clone(),
                },
            )?;
            return Ok::<_, anyhow::Error>(FetchResult {
                observation: cached_observation(url.clone(), refreshed),
                assets: Vec::new(),
                network: true,
            });
        }
        let mut body = Vec::new();
        while body.len() < max_bytes {
            let Some(chunk) = response.chunk().await? else {
                break;
            };
            let remaining = max_bytes.saturating_sub(body.len());
            body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
        let body = String::from_utf8_lossy(&body);
        let content_hash = format!("{:x}", Sha256::digest(body.as_bytes()));
        let metadata = format!("{}\n{}", header_text(&headers), body);
        let names = extract_observed_names(&metadata, domain);
        let base = Url::parse(&url)?;
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
            .map(|cache| FetchResult {
                observation: cached_observation(url, cache),
                assets: Vec::new(),
                network: false,
            })
            .ok_or(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn discover_web(
    database: &Database,
    domain: &str,
    hosts: Vec<String>,
    timeout: Duration,
    refresh: Duration,
    concurrency: usize,
    max_bytes: usize,
    assets_per_host: usize,
) -> Result<WebDiscovery> {
    let started = Instant::now();
    let client = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .user_agent(concat!(
            "Fellaga-SubDomainFinder/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let database = database.clone();
    let domain_owned = domain.to_owned();
    let visited = Arc::new(Mutex::new(BTreeSet::new()));
    let mut pending = stream::iter(hosts.into_iter().collect::<BTreeSet<_>>())
        .map(|host| {
            let database = database.clone();
            let client = client.clone();
            let domain = domain_owned.clone();
            let visited = visited.clone();
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
                let assets = results[0].assets.clone();
                for asset in assets.into_iter().take(assets_per_host) {
                    let Some(asset) = claim_url(&visited, &asset).await else {
                        continue;
                    };
                    if let Ok(result) =
                        fetch_url(&database, &client, &domain, asset, refresh, max_bytes, 0).await
                    {
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
