use super::{
    ApiKeyStore, client, commit_result_page, hostname_from_url, response_bytes_limited,
    response_json, response_text, send_external, send_with_retry, source_policy,
};
use crate::util::normalize_observed_name;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;

fn normalize_many<I, S>(values: I, domain: &str) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    values
        .into_iter()
        .filter_map(|value| normalize_observed_name(value.as_ref(), domain))
        .collect()
}

fn extract_from_text(text: &str, domain: &str) -> BTreeSet<String> {
    text.split(|character: char| {
        !character.is_ascii_alphanumeric()
            && character != '.'
            && character != '-'
            && character != '*'
    })
    .filter_map(|token| normalize_observed_name(token, domain))
    .collect()
}

fn extract_from_json(value: &Value, domain: &str, names: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => {
            names.extend(extract_from_text(value, domain));
        }
        Value::Array(values) => {
            for value in values {
                extract_from_json(value, domain, names);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                names.extend(extract_from_text(key, domain));
                extract_from_json(value, domain, names);
            }
        }
        _ => {}
    }
}

#[derive(Deserialize)]
struct HostsResponse {
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    subdomains: Vec<String>,
}

#[derive(Deserialize)]
struct ShodanDomainResponse {
    #[serde(default)]
    subdomains: Vec<String>,
    #[serde(default)]
    more: bool,
}

#[derive(Deserialize)]
struct BinaryEdgeSubdomainPage {
    #[serde(default)]
    total: usize,
    #[serde(default)]
    page: usize,
    #[serde(default)]
    pagesize: usize,
    #[serde(default)]
    events: Vec<String>,
}

#[derive(Deserialize)]
struct MerkleMapSearchPage {
    #[serde(default)]
    count: usize,
    #[serde(default)]
    results: Vec<MerkleMapSearchResult>,
}

#[derive(Deserialize)]
struct MerkleMapSearchResult {
    hostname: Option<String>,
    subject_common_name: Option<String>,
}

#[derive(Deserialize, Default)]
struct BraveSearchPage {
    #[serde(default)]
    query: BraveSearchQuery,
    web: Option<BraveWebResults>,
}

#[derive(Deserialize, Default)]
struct BraveSearchQuery {
    #[serde(default)]
    more_results_available: bool,
}

#[derive(Deserialize)]
struct BraveWebResults {
    #[serde(default)]
    results: Vec<BraveWebResult>,
}

#[derive(Deserialize)]
struct BraveWebResult {
    url: String,
    title: Option<String>,
    description: Option<String>,
    #[serde(default)]
    extra_snippets: Vec<String>,
}

const BINARYEDGE_MAX_PAGES: usize = 2;
const MERKLEMAP_MAX_PAGES: usize = 2;
const BRAVE_MAX_PAGES: usize = 2;

fn binaryedge_request(
    client: &reqwest::Client,
    domain: &str,
    page: usize,
    token: &str,
) -> reqwest::RequestBuilder {
    client
        .get(format!(
            "https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        ))
        .header("X-Key", token)
        .query(&[("page", page.to_string())])
}

fn brave_request(
    client: &reqwest::Client,
    domain: &str,
    offset: usize,
    token: &str,
) -> reqwest::RequestBuilder {
    client
        .get("https://api.search.brave.com/res/v1/web/search")
        .header("X-Subscription-Token", token)
        .query(&[
            ("q", format!("site:{domain}")),
            ("count", "20".to_owned()),
            ("offset", offset.to_string()),
            ("extra_snippets", "true".to_owned()),
            ("spellcheck", "false".to_owned()),
        ])
}

fn merklemap_request(
    client: &reqwest::Client,
    domain: &str,
    page: usize,
    token: &str,
) -> reqwest::RequestBuilder {
    client
        .get("https://api.merklemap.com/v1/search")
        .bearer_auth(token)
        .query(&[
            ("query", format!("*.{domain}")),
            ("type", "wildcard".to_owned()),
            ("page", page.to_string()),
        ])
}

fn binaryedge_page_names(page: &BinaryEdgeSubdomainPage, domain: &str) -> BTreeSet<String> {
    normalize_many(&page.events, domain)
}

fn merklemap_page_names(page: &MerkleMapSearchPage, domain: &str) -> BTreeSet<String> {
    page.results
        .iter()
        .flat_map(|result| {
            [
                result.hostname.as_deref(),
                result.subject_common_name.as_deref(),
            ]
        })
        .flatten()
        .filter_map(|name| normalize_observed_name(name, domain))
        .collect()
}

fn brave_page_names(page: &BraveSearchPage, domain: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(web) = &page.web else {
        return names;
    };
    for result in &web.results {
        if let Some(name) = hostname_from_url(&result.url, domain) {
            names.insert(name);
        }
        for text in result
            .title
            .iter()
            .chain(result.description.iter())
            .chain(result.extra_snippets.iter())
        {
            names.extend(extract_from_text(text, domain));
        }
    }
    names
}

fn binaryedge_has_more(page: &BinaryEdgeSubdomainPage, requested_page: usize) -> bool {
    let event_count = page.events.len();
    let page_number = page.page.max(requested_page);
    let page_size = page.pagesize.max(event_count).max(1);
    event_count > 0 && page_number.saturating_mul(page_size) < page.total
}

fn brave_has_more(page: &BraveSearchPage) -> bool {
    page.web.as_ref().is_some_and(|web| !web.results.is_empty())
        && page.query.more_results_available
}

fn merklemap_has_more(page: &MerkleMapSearchPage, page_number: usize) -> bool {
    let result_count = page.results.len();
    result_count > 0 && page.count > (page_number + 1).saturating_mul(result_count)
}

pub(super) async fn bevigil(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("bevigil")?;
    let response = send_external(
        "bevigil",
        client(timeout)?
            .get(format!(
                "https://osint.bevigil.com/api/{domain}/subdomains/"
            ))
            .header("X-Access-Token", token),
        domain,
    )
    .await
    .context("connexion à BeVigil")?;
    let response = response_json::<HostsResponse>(response, "BeVigil").await?;
    Ok(normalize_many(response.subdomains, domain))
}

pub(super) async fn binaryedge(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for requested_page in 1..=BINARYEDGE_MAX_PAGES {
        let token = keys.pick("binaryedge")?;
        let request = binaryedge_request(&http, domain, requested_page, &token);
        let response = match send_external("binaryedge", request, domain).await {
            Ok(response) => {
                match response_json::<BinaryEdgeSubdomainPage>(response, "BinaryEdge").await {
                    Ok(response) => response,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error).context("connexion à BinaryEdge"),
        };
        let page_names = binaryedge_page_names(&response, domain);
        commit_result_page(&mut names, page_names);
        if !binaryedge_has_more(&response, requested_page) {
            break;
        }
    }
    Ok(names)
}

pub(super) async fn brave(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("brave")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for offset in 0..BRAVE_MAX_PAGES {
        let request = brave_request(&http, domain, offset, &token);
        let response = match send_external("brave", request, domain).await {
            Ok(response) => {
                match response_json::<BraveSearchPage>(response, "Brave Search").await {
                    Ok(response) => response,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error).context("connexion à Brave Search"),
        };
        let page_names = brave_page_names(&response, domain);
        commit_result_page(&mut names, page_names);
        if !brave_has_more(&response) {
            break;
        }
    }
    Ok(names)
}

pub(super) async fn builtwith(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("builtwith")?;
    let response = send_external(
        "builtwith",
        client(timeout)?
            .get("https://api.builtwith.com/v21/api.json")
            .query(&[
                ("KEY", token.as_str()),
                ("LOOKUP", domain),
                ("HIDETEXT", "yes"),
                ("HIDEDL", "yes"),
                ("NOLIVE", "yes"),
                ("NOMETA", "yes"),
                ("NOPII", "yes"),
                ("NOATTR", "yes"),
            ]),
        domain,
    )
    .await
    .context("connexion à BuiltWith")?;
    let response = response_json::<Value>(response, "BuiltWith").await?;
    let mut names = BTreeSet::new();
    if let Some(results) = response.get("Results").and_then(Value::as_array) {
        for result in results {
            let paths = result
                .pointer("/Result/Paths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            for path in paths {
                let base = path.get("Domain").and_then(Value::as_str).unwrap_or(domain);
                let label = path
                    .get("SubDomain")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(name) = normalize_observed_name(&format!("{label}.{base}"), domain) {
                    names.insert(name);
                }
            }
        }
    }
    Ok(names)
}

pub(super) async fn censys(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("censys")?;
    let (identifier, secret) = token
        .split_once(':')
        .context("CENSYS_API_KEY doit être au format API_ID:API_SECRET")?;
    let http = client(timeout)?;
    let mut cursor: Option<String> = None;
    let mut names = BTreeSet::new();
    for _ in 0..10 {
        let mut request = http
            .get("https://search.censys.io/api/v2/certificates/search")
            .basic_auth(identifier, Some(secret))
            .query(&[("q", domain), ("per_page", "100")]);
        if let Some(value) = &cursor {
            request = request.query(&[("cursor", value)]);
        }
        let response = match send_external("censys", request, domain).await {
            Ok(response) => match response_json::<Value>(response, "Censys").await {
                Ok(response) => response,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error).context("connexion à Censys"),
        };
        let mut page_names = BTreeSet::new();
        if let Some(hits) = response.pointer("/result/hits").and_then(Value::as_array) {
            for hit in hits {
                if let Some(values) = hit.get("names").and_then(Value::as_array) {
                    page_names.extend(
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .filter_map(|name| normalize_observed_name(name, domain)),
                    );
                }
            }
        }
        commit_result_page(&mut names, page_names);
        cursor = response
            .pointer("/result/links/next")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    Ok(names)
}

pub(super) async fn circl(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credentials = keys.pick("circl")?;
    let (username, password) = credentials
        .split_once(':')
        .context("CIRCL_PDNS_CREDENTIALS doit être au format utilisateur:mot-de-passe")?;
    let response = send_external(
        "circl",
        client(timeout)?
            .get(format!("https://www.circl.lu/pdns/query/{domain}"))
            .basic_auth(username, Some(password))
            .header("dribble-disable-active-query", "1"),
        domain,
    )
    .await
    .context("connexion à CIRCL Passive DNS")?;
    let response = response_text(response, "CIRCL Passive DNS").await?;
    let mut names = BTreeSet::new();
    for line in response.lines().take(100_000) {
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            extract_from_json(&value, domain, &mut names);
        } else {
            names.extend(extract_from_text(line, domain));
        }
    }
    Ok(names)
}

pub(super) async fn certificate_details(
    domain: &str,
    timeout: Duration,
) -> Result<BTreeSet<String>> {
    let response = send_external(
        "certificatedetails",
        client(timeout)?.get(format!("https://certificatedetails.com/{domain}")),
        domain,
    )
    .await
    .context("connexion à CertificateDetails")?;
    let text = response_text(response, "CertificateDetails").await?;
    Ok(extract_from_text(&text, domain))
}

pub(super) async fn chaos(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("chaos")?;
    let response = send_external(
        "chaos",
        client(timeout)?
            .get(format!(
                "https://dns.projectdiscovery.io/dns/{domain}/subdomains"
            ))
            .header("Authorization", token),
        domain,
    )
    .await
    .context("connexion à Chaos")?;
    let response = response_json::<HostsResponse>(response, "Chaos").await?;
    Ok(response
        .subdomains
        .into_iter()
        .filter_map(|label| normalize_observed_name(&format!("{label}.{domain}"), domain))
        .collect())
}

pub(super) async fn driftnet(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let response = send_external(
        "driftnet",
        client(timeout)?
            .get("https://api.driftnet.io/v1/multi/summary")
            .bearer_auth("anon")
            .query(&[
                ("summary_limit", "1000"),
                ("timeout", "30"),
                ("field", &format!("host:{domain}")),
            ]),
        domain,
    )
    .await
    .context("connexion à Driftnet")?;
    let response = response_json::<Value>(response, "Driftnet").await?;
    let mut names = BTreeSet::new();
    extract_from_json(&response, domain, &mut names);
    Ok(names)
}

pub(super) async fn fullhunt(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("fullhunt")?;
    let response = send_external(
        "fullhunt",
        client(timeout)?
            .get(format!(
                "https://fullhunt.io/api/v1/domain/{domain}/subdomains"
            ))
            .header("X-API-KEY", token),
        domain,
    )
    .await
    .context("connexion à FullHunt")?;
    let response = response_json::<HostsResponse>(response, "FullHunt").await?;
    Ok(normalize_many(response.hosts, domain))
}

pub(super) async fn github(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for page in 1..=3 {
        let token = keys.pick("github")?;
        let request = http
            .get("https://api.github.com/search/code")
            .bearer_auth(token)
            .header("Accept", "application/vnd.github.text-match+json")
            .query(&[
                ("q", format!("\"{domain}\"")),
                ("per_page", "100".to_owned()),
                ("page", page.to_string()),
            ]);
        let response = match send_external("github", request, domain).await {
            Ok(response) => match response_json::<Value>(response, "GitHub Code Search").await {
                Ok(response) => response,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error).context("connexion à GitHub Code Search"),
        };
        let items = response.get("items").and_then(Value::as_array);
        let Some(items) = items else { break };
        if items.is_empty() {
            break;
        }
        let mut page_names = BTreeSet::new();
        for item in items {
            if let Some(matches) = item.get("text_matches").and_then(Value::as_array) {
                for text_match in matches {
                    if let Some(fragment) = text_match.get("fragment").and_then(Value::as_str) {
                        page_names.extend(extract_from_text(fragment, domain));
                    }
                }
            }
        }
        commit_result_page(&mut names, page_names);
        if items.len() < 100 {
            break;
        }
    }
    Ok(names)
}

pub(super) async fn gitlab(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("gitlab")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for page in 1..=3 {
        let request = http
            .get("https://gitlab.com/api/v4/search")
            .header("PRIVATE-TOKEN", &token)
            .query(&[
                ("scope", "blobs".to_owned()),
                ("search", domain.to_owned()),
                ("per_page", "100".to_owned()),
                ("page", page.to_string()),
            ]);
        let response = match send_external("gitlab", request, domain).await {
            Ok(response) => response,
            Err(error) => return Err(error).context("connexion à GitLab Code Search"),
        };
        let next_page = response
            .headers()
            .get("x-next-page")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let values = match response_json::<Vec<Value>>(response, "GitLab Code Search").await {
            Ok(values) => values,
            Err(error) => return Err(error),
        };
        let mut page_names = BTreeSet::new();
        for value in &values {
            extract_from_json(value, domain, &mut page_names);
        }
        commit_result_page(&mut names, page_names);
        if values.is_empty() || next_page.is_none() {
            break;
        }
    }
    Ok(names)
}

pub(super) async fn intelx(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("intelx")?;
    let (host, key) = token
        .split_once(':')
        .context("INTELX_API_KEY doit être au format api-host:clé")?;
    let http = client(timeout)?;
    let search = send_external(
        "intelx",
        http.post(format!("https://{host}/phonebook/search"))
            .query(&[("k", key)])
            .json(&json!({
            "term": domain,
            "maxresults": 100_000,
            "media": 0,
            "target": 1,
            "timeout": 20
            })),
        domain,
    )
    .await
    .context("connexion à Intelligence X")?;
    let search = response_json::<Value>(search, "recherche Intelligence X").await?;
    let id = search
        .get("id")
        .and_then(Value::as_str)
        .context("ID Intelligence X absent")?;
    let mut names = BTreeSet::new();
    for _ in 0..10 {
        let request = http
            .get(format!("https://{host}/phonebook/search/result"))
            .query(&[("k", key), ("id", id), ("limit", "10000")]);
        let response = match send_external("intelx", request, domain).await {
            Ok(response) => match response_json::<Value>(response, "Intelligence X").await {
                Ok(response) => response,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error).context("lecture des résultats Intelligence X"),
        };
        let mut page_names = BTreeSet::new();
        if let Some(selectors) = response.get("selectors").and_then(Value::as_array) {
            for selector in selectors {
                if let Some(name) = selector.get("selectorvalue").and_then(Value::as_str)
                    && let Some(name) = normalize_observed_name(name, domain)
                {
                    page_names.insert(name);
                }
            }
        }
        commit_result_page(&mut names, page_names);
        let status = response.get("status").and_then(Value::as_i64).unwrap_or(2);
        if status != 0 && status != 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(names)
}

pub(super) async fn leakix(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("leakix")?;
    let response = send_external(
        "leakix",
        client(timeout)?
            .get(format!("https://leakix.net/api/subdomains/{domain}"))
            .header("api-key", token)
            .header("Accept", "application/json"),
        domain,
    )
    .await
    .context("connexion à LeakIX")?;
    let response = response_json::<Value>(response, "LeakIX").await?;
    let mut names = BTreeSet::new();
    extract_from_json(&response, domain, &mut names);
    Ok(names)
}

pub(super) async fn merklemap(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("merklemap")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for page in 0..MERKLEMAP_MAX_PAGES {
        let request = merklemap_request(&http, domain, page, &token);
        let response = match send_external("merklemap", request, domain).await {
            Ok(response) => {
                match response_json::<MerkleMapSearchPage>(response, "MerkleMap").await {
                    Ok(response) => response,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error).context("connexion à MerkleMap"),
        };
        let page_names = merklemap_page_names(&response, domain);
        commit_result_page(&mut names, page_names);
        if !merklemap_has_more(&response, page) {
            break;
        }
    }
    Ok(names)
}

#[derive(Deserialize)]
struct OtxResponse {
    #[serde(default)]
    passive_dns: Vec<OtxRecord>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct OtxRecord {
    hostname: String,
}

fn otx_request(
    client: &reqwest::Client,
    endpoint: &str,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let request = client.get(endpoint);
    match token {
        Some(token) => request.header("X-OTX-API-KEY", token),
        None => request,
    }
}

pub(super) async fn otx(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.optional("otx");
    let policy = source_policy("otx");
    let endpoint =
        format!("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns");
    let response = send_with_retry(
        otx_request(&client(timeout)?, &endpoint, token.as_deref()),
        if token.is_some() { policy.attempts } else { 1 },
        policy.base_backoff,
        domain,
    )
    .await
    .context("connexion à AlienVault OTX")?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let (_, body) = response_bytes_limited(response, "OTX").await?;
        let detail = String::from_utf8_lossy(&body);
        if token.is_none() {
            bail!(
                "OTX limite l'accès anonyme (HTTP 429); configurez OTX_API_KEY ou X_OTX_API_KEY: {}",
                detail.trim()
            );
        }
        bail!("OTX limite la clé fournie (HTTP 429): {}", detail.trim());
    }
    let response = response_json::<OtxResponse>(response, "OTX").await?;
    if let Some(error) = response.error {
        bail!("OTX: {error}");
    }
    Ok(normalize_many(
        response
            .passive_dns
            .into_iter()
            .map(|record| record.hostname),
        domain,
    ))
}

pub(super) async fn shodan(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("shodan")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for page in 1..=10 {
        let request = http
            .get(format!("https://api.shodan.io/dns/domain/{domain}"))
            .query(&[
                ("key", token.as_str()),
                ("history", "true"),
                ("page", &page.to_string()),
            ]);
        let response = match send_external("shodan", request, domain).await {
            Ok(response) => match response_json::<ShodanDomainResponse>(response, "Shodan").await {
                Ok(response) => response,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error).context("connexion à Shodan"),
        };
        let page_names = response
            .subdomains
            .into_iter()
            .filter_map(|label| normalize_observed_name(&format!("{label}.{domain}"), domain))
            .collect();
        commit_result_page(&mut names, page_names);
        if !response.more {
            break;
        }
    }
    Ok(names)
}

pub(super) async fn subdomain_center(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let response = send_external(
        "subdomaincenter",
        client(timeout)?
            .get("https://api.subdomain.center")
            .query(&[("domain", domain)]),
        domain,
    )
    .await
    .context("connexion à Subdomain Center")?;
    let response = response_json::<Vec<String>>(response, "Subdomain Center").await?;
    Ok(normalize_many(response, domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passive::sanitize_external_error;

    #[test]
    fn extracts_only_target_subdomains_from_unstructured_text() {
        let names = extract_from_text(
            "https://api.example.com/a mail.dev.example.com, example.net and example.com",
            "example.com",
        );
        assert_eq!(
            names,
            BTreeSet::from([
                "api.example.com".to_owned(),
                "mail.dev.example.com".to_owned()
            ])
        );
    }

    #[test]
    fn otx_authentication_uses_the_documented_header() {
        let request = otx_request(
            &client(Duration::from_secs(1)).unwrap(),
            "https://otx.example.test/api",
            Some("secret-test"),
        )
        .build()
        .unwrap();
        assert_eq!(
            request
                .headers()
                .get("X-OTX-API-KEY")
                .and_then(|value| value.to_str().ok()),
            Some("secret-test")
        );
    }

    #[test]
    fn shodan_pagination_shape_accepts_the_more_flag() {
        let response: ShodanDomainResponse = serde_json::from_value(serde_json::json!({
            "subdomains": ["www", "*.api.dev"],
            "more": true
        }))
        .unwrap();
        assert!(response.more);
        assert_eq!(
            normalize_many(
                response
                    .subdomains
                    .into_iter()
                    .map(|label| format!("{label}.example.com")),
                "example.com"
            ),
            BTreeSet::from([
                "api.dev.example.com".to_owned(),
                "www.example.com".to_owned()
            ])
        );
    }

    #[test]
    fn binaryedge_contract_fixture_preserves_pagination_and_scope() {
        let page: BinaryEdgeSubdomainPage =
            serde_json::from_str(include_str!("../../tests/fixtures/binaryedge-page.json"))
                .unwrap();
        assert_eq!(page.page, 1);
        assert_eq!(page.pagesize, 100);
        assert_eq!(page.total, 250);
        assert_eq!(
            binaryedge_page_names(&page, "example.com"),
            BTreeSet::from(["api.example.com".to_owned(), "edge.example.com".to_owned()])
        );
    }

    #[test]
    fn merklemap_contract_fixture_handles_wildcards_and_scope() {
        let page: MerkleMapSearchPage =
            serde_json::from_str(include_str!("../../tests/fixtures/merklemap-page.json")).unwrap();
        assert_eq!(page.count, 125);
        assert_eq!(
            merklemap_page_names(&page, "example.com"),
            BTreeSet::from(["api.example.com".to_owned(), "dev.example.com".to_owned()])
        );
    }

    #[test]
    fn brave_contract_fixture_extracts_urls_and_snippets_in_scope() {
        let page: BraveSearchPage =
            serde_json::from_str(include_str!("../../tests/fixtures/brave-page.json")).unwrap();
        assert!(page.query.more_results_available);
        assert_eq!(
            brave_page_names(&page, "example.com"),
            BTreeSet::from([
                "api.example.com".to_owned(),
                "cdn.assets.example.com".to_owned(),
                "portal.example.com".to_owned(),
                "status.example.com".to_owned()
            ])
        );
    }

    #[test]
    fn targeted_connector_requests_follow_provider_contracts() {
        assert_eq!(BINARYEDGE_MAX_PAGES, 2);
        assert_eq!(BRAVE_MAX_PAGES, 2);
        assert_eq!(MERKLEMAP_MAX_PAGES, 2);
        let http = client(Duration::from_secs(1)).unwrap();

        let binaryedge = binaryedge_request(&http, "example.com", 2, "binaryedge-key")
            .build()
            .unwrap();
        assert_eq!(binaryedge.url().host_str(), Some("api.binaryedge.io"));
        assert_eq!(
            binaryedge.url().path(),
            "/v2/query/domains/subdomain/example.com"
        );
        assert_eq!(
            binaryedge
                .headers()
                .get("X-Key")
                .and_then(|value| value.to_str().ok()),
            Some("binaryedge-key")
        );
        assert!(
            binaryedge
                .url()
                .query_pairs()
                .any(|pair| pair.0 == "page" && pair.1 == "2")
        );

        let brave = brave_request(&http, "example.com", 1, "brave-key")
            .build()
            .unwrap();
        assert_eq!(brave.url().host_str(), Some("api.search.brave.com"));
        assert_eq!(brave.url().path(), "/res/v1/web/search");
        assert_eq!(
            brave
                .headers()
                .get("X-Subscription-Token")
                .and_then(|value| value.to_str().ok()),
            Some("brave-key")
        );
        let brave_query = brave.url().query_pairs().collect::<Vec<_>>();
        assert!(brave_query.contains(&("q".into(), "site:example.com".into())));
        assert!(brave_query.contains(&("count".into(), "20".into())));
        assert!(brave_query.contains(&("offset".into(), "1".into())));
        assert!(brave_query.contains(&("extra_snippets".into(), "true".into())));
        assert!(brave_query.contains(&("spellcheck".into(), "false".into())));

        let merklemap = merklemap_request(&http, "example.com", 0, "merkle-token")
            .build()
            .unwrap();
        assert_eq!(merklemap.url().host_str(), Some("api.merklemap.com"));
        assert_eq!(merklemap.url().path(), "/v1/search");
        assert_eq!(
            merklemap
                .headers()
                .get("Authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer merkle-token")
        );
        let merklemap_query = merklemap.url().query_pairs().collect::<Vec<_>>();
        assert!(merklemap_query.contains(&("query".into(), "*.example.com".into())));
        assert!(merklemap_query.contains(&("type".into(), "wildcard".into())));
        assert!(merklemap_query.contains(&("page".into(), "0".into())));
    }

    #[test]
    fn pagination_uses_raw_provider_progress_not_normalized_name_yield() {
        let binaryedge: BinaryEdgeSubdomainPage = serde_json::from_value(serde_json::json!({
            "page": 1,
            "pagesize": 1,
            "total": 2,
            "events": ["outside.test"]
        }))
        .unwrap();
        assert!(binaryedge_page_names(&binaryedge, "example.com").is_empty());
        assert!(binaryedge_has_more(&binaryedge, 1));

        let brave: BraveSearchPage = serde_json::from_value(serde_json::json!({
            "query": {"more_results_available": true},
            "web": {"results": [{"url": "https://outside.test/"}]}
        }))
        .unwrap();
        assert!(brave_page_names(&brave, "example.com").is_empty());
        assert!(brave_has_more(&brave));

        let merklemap: MerkleMapSearchPage = serde_json::from_value(serde_json::json!({
            "count": 2,
            "results": [{"hostname": "outside.test"}]
        }))
        .unwrap();
        assert!(merklemap_page_names(&merklemap, "example.com").is_empty());
        assert!(merklemap_has_more(&merklemap, 0));
    }

    #[test]
    fn query_credentials_used_by_extra_connectors_are_redacted() {
        let error = "request https://api.example.test/search?KEY=builtwith-secret&k=intelx-secret&key=shodan-secret&page=2 failed";
        let sanitized = sanitize_external_error(error, &ApiKeyStore::default());

        for secret in ["builtwith-secret", "intelx-secret", "shodan-secret"] {
            assert!(!sanitized.contains(secret));
        }
        assert!(sanitized.contains("page=2"));
        assert!(sanitized.contains("REDACTED"));
    }
}
