use super::{
    ApiKeyStore, client, commit_result_page, compact_external_error, hostname_from_url,
    response_bytes_limited, response_json, response_text, send_external,
    send_with_retry_for_source, source_policy,
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
    hosts: Option<Vec<String>>,
    subdomains: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ShodanDomainResponse {
    subdomains: Vec<String>,
    more: bool,
}

#[derive(Deserialize)]
struct BinaryEdgeSubdomainPage {
    total: usize,
    page: usize,
    pagesize: usize,
    events: Vec<String>,
}

#[derive(Deserialize)]
struct MerkleMapSearchPage {
    count: usize,
    results: Vec<MerkleMapSearchResult>,
}

#[derive(Deserialize)]
struct MerkleMapSearchResult {
    hostname: Option<String>,
    subject_common_name: Option<String>,
}

#[derive(Deserialize, Default)]
struct BraveSearchPage {
    query: BraveSearchQuery,
    web: Option<BraveWebResults>,
}

#[derive(Deserialize, Default)]
struct BraveSearchQuery {
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

#[derive(Deserialize)]
struct DriftnetPage {
    #[serde(default)]
    page: Option<Value>,
    #[serde(default)]
    pages: Option<Value>,
    results: Vec<DriftnetReport>,
    #[serde(default)]
    timed_out: bool,
}

#[derive(Deserialize)]
struct DriftnetReport {
    #[serde(default)]
    items: Vec<DriftnetItem>,
}

#[derive(Deserialize)]
struct DriftnetItem {
    #[serde(default)]
    value: Value,
}

const BINARYEDGE_MAX_PAGES: usize = 2;
const MERKLEMAP_MAX_PAGES: usize = 2;
const BRAVE_MAX_PAGES: usize = 2;
const DRIFTNET_MAX_PAGES: usize = 10;

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

fn driftnet_request(
    client: &reqwest::Client,
    domain: &str,
    page: usize,
    token: &str,
) -> reqwest::RequestBuilder {
    client
        .get("https://api.driftnet.io/v1/ct/log")
        .bearer_auth(token)
        .query(&[
            ("field", format!("host:{domain}")),
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

fn binaryedge_has_more(page: &BinaryEdgeSubdomainPage, requested_page: usize) -> Result<bool> {
    if requested_page == 0 || page.page != requested_page {
        bail!(
            "BinaryEdge: page inattendue {}, page {requested_page} demandée",
            page.page
        );
    }
    if page.pagesize == 0 || page.events.len() > page.pagesize {
        bail!("BinaryEdge: taille de page incohérente");
    }
    let page_start = requested_page
        .saturating_sub(1)
        .checked_mul(page.pagesize)
        .context("BinaryEdge: pagination trop grande")?;
    if page.events.is_empty() && page_start < page.total {
        bail!("BinaryEdge: page vide avant la fin annoncée");
    }
    if !page.events.is_empty() && page_start >= page.total {
        bail!("BinaryEdge: résultats au-delà du total annoncé");
    }
    Ok(requested_page
        .checked_mul(page.pagesize)
        .context("BinaryEdge: pagination trop grande")?
        < page.total)
}

fn brave_has_more(page: &BraveSearchPage) -> Result<bool> {
    let result_count = page.web.as_ref().map_or(0, |web| web.results.len());
    if page.query.more_results_available && result_count == 0 {
        bail!("Brave Search: pagination annoncée sans aucun résultat");
    }
    Ok(page.query.more_results_available)
}

fn merklemap_has_more(page: &MerkleMapSearchPage, seen_results: usize) -> Result<bool> {
    if seen_results > page.count {
        bail!("MerkleMap: nombre de résultats supérieur au total annoncé");
    }
    if page.results.is_empty() && seen_results < page.count {
        bail!("MerkleMap: page vide avant la fin annoncée");
    }
    Ok(seen_results < page.count)
}

fn driftnet_page_number(value: Option<&Value>, field: &str) -> Result<Option<usize>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = match value {
        Value::Number(value) => value.as_u64().and_then(|value| usize::try_from(value).ok()),
        Value::String(value) => value.trim().parse::<usize>().ok(),
        Value::Null => return Ok(None),
        _ => None,
    };
    parsed
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("Driftnet: champ de pagination {field} invalide"))
}

fn driftnet_pagination(page: &DriftnetPage, requested_page: usize) -> Result<(usize, usize)> {
    let returned_page = driftnet_page_number(page.page.as_ref(), "page")?
        .context("Driftnet: champ de pagination page absent")?;
    if returned_page != requested_page {
        bail!("Driftnet: page inattendue {returned_page}, page {requested_page} demandée");
    }
    let pages = driftnet_page_number(page.pages.as_ref(), "pages")?
        .context("Driftnet: champ de pagination pages absent")?;
    if !page.results.is_empty() && pages <= returned_page {
        bail!("Driftnet: pagination incohérente (page {returned_page}, pages {pages})");
    }
    Ok((returned_page, pages))
}

fn driftnet_page_names(page: &DriftnetPage, domain: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for item in page.results.iter().flat_map(|report| &report.items) {
        extract_from_json(&item.value, domain, &mut names);
    }
    names
}

fn driftnet_http_error(status: reqwest::StatusCode, body: &[u8]) -> Option<String> {
    let reason = match status.as_u16() {
        401 => "jeton API invalide",
        403 => "quota API dépassé",
        524 => "timeout CDN amont",
        _ => return None,
    };
    let detail = compact_external_error(&String::from_utf8_lossy(body));
    Some(if detail.is_empty() {
        format!("Driftnet: {reason} (HTTP {})", status.as_u16())
    } else {
        format!("Driftnet: {reason} (HTTP {}): {detail}", status.as_u16())
    })
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
    Ok(normalize_many(
        response
            .subdomains
            .context("BeVigil: champ subdomains absent")?,
        domain,
    ))
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
        let has_more = binaryedge_has_more(&response, requested_page)?;
        if !has_more {
            break;
        }
        if requested_page == BINARYEDGE_MAX_PAGES {
            bail!("BinaryEdge: limite de pagination atteinte avec des résultats supplémentaires");
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
        let has_more = brave_has_more(&response)?;
        if !has_more {
            break;
        }
        if offset + 1 == BRAVE_MAX_PAGES {
            bail!("Brave Search: limite de pagination atteinte avec des résultats supplémentaires");
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
    let results = response
        .get("Results")
        .and_then(Value::as_array)
        .context("BuiltWith: tableau Results absent")?;
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
    for iteration in 0..10 {
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
        let hits = response
            .pointer("/result/hits")
            .and_then(Value::as_array)
            .context("Censys: tableau result.hits absent")?;
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
        commit_result_page(&mut names, page_names);
        let next_cursor = response
            .pointer("/result/links/next")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let Some(next_cursor) = next_cursor else {
            break;
        };
        if cursor.as_deref() == Some(next_cursor.as_str()) {
            bail!("Censys: curseur de pagination répété");
        }
        if iteration + 1 == 10 {
            bail!("Censys: limite de pagination atteinte avec un curseur suivant");
        }
        cursor = Some(next_cursor);
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
        .context("Chaos: champ subdomains absent")?
        .into_iter()
        .filter_map(|label| normalize_observed_name(&format!("{label}.{domain}"), domain))
        .collect())
}

pub(super) async fn driftnet(
    domain: &str,
    timeout: Duration,
    token: &str,
) -> Result<BTreeSet<String>> {
    let token = token.trim();
    if token.is_empty() {
        bail!("Driftnet: jeton API manquant");
    }
    let http = client(timeout)?;
    let policy = source_policy("driftnet");
    let mut names = BTreeSet::new();
    for requested_page in 0..DRIFTNET_MAX_PAGES {
        let response = send_with_retry_for_source(
            "driftnet",
            driftnet_request(&http, domain, requested_page, token),
            policy.attempts,
            policy.base_backoff,
            domain,
        )
        .await
        .context("connexion à Driftnet Certificate Transparency")?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            break;
        }
        if matches!(response.status().as_u16(), 401 | 403 | 524) {
            let (status, body) = response_bytes_limited(response, "Driftnet").await?;
            bail!(
                "{}",
                driftnet_http_error(status, &body)
                    .unwrap_or_else(|| format!("Driftnet: HTTP {status}"))
            );
        }
        let page = response_json::<DriftnetPage>(response, "Driftnet").await?;
        let (returned_page, pages) = driftnet_pagination(&page, requested_page)?;
        let has_results = !page.results.is_empty();
        commit_result_page(&mut names, driftnet_page_names(&page, domain));
        if page.timed_out {
            bail!("Driftnet: délai interne du fournisseur atteint à la page {returned_page}");
        }
        if !has_results || returned_page.saturating_add(1) >= pages {
            break;
        }
        if requested_page + 1 == DRIFTNET_MAX_PAGES {
            bail!("Driftnet: limite de pagination atteinte avant la dernière page");
        }
    }
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
    Ok(normalize_many(
        response.hosts.context("FullHunt: champ hosts absent")?,
        domain,
    ))
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
        let items = response
            .get("items")
            .and_then(Value::as_array)
            .context("GitHub Code Search: tableau items absent")?;
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
        if page == 3 {
            bail!("GitHub Code Search: limite de pagination atteinte avec une page complète");
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
    let mut page = "1".to_owned();
    for iteration in 0..3 {
        let request = http
            .get("https://gitlab.com/api/v4/search")
            .header("PRIVATE-TOKEN", &token)
            .query(&[
                ("scope", "blobs".to_owned()),
                ("search", domain.to_owned()),
                ("per_page", "100".to_owned()),
                ("page", page.clone()),
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
        if values.is_empty() {
            break;
        }
        let Some(next_page) = next_page else {
            break;
        };
        if next_page == page {
            bail!("GitLab Code Search: page suivante répétée ({page})");
        }
        if iteration + 1 == 3 {
            bail!("GitLab Code Search: limite de pagination atteinte avant la dernière page");
        }
        page = next_page;
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
    for iteration in 0..10 {
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
        let selectors = response
            .get("selectors")
            .and_then(Value::as_array)
            .context("Intelligence X: tableau selectors absent")?;
        for selector in selectors {
            if let Some(name) = selector.get("selectorvalue").and_then(Value::as_str)
                && let Some(name) = normalize_observed_name(name, domain)
            {
                page_names.insert(name);
            }
        }
        commit_result_page(&mut names, page_names);
        let status = response
            .get("status")
            .and_then(Value::as_i64)
            .context("Intelligence X: statut absent")?;
        if status != 0 && status != 3 {
            break;
        }
        if iteration + 1 == 10 {
            bail!("Intelligence X: recherche encore active après la limite de scrutation");
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
    let mut seen_results = 0_usize;
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
        seen_results = seen_results
            .checked_add(response.results.len())
            .context("MerkleMap: compteur de pagination trop grand")?;
        let page_names = merklemap_page_names(&response, domain);
        commit_result_page(&mut names, page_names);
        let has_more = merklemap_has_more(&response, seen_results)?;
        if !has_more {
            break;
        }
        if page + 1 == MERKLEMAP_MAX_PAGES {
            bail!("MerkleMap: limite de pagination atteinte avec des résultats supplémentaires");
        }
    }
    Ok(names)
}

#[derive(Deserialize)]
struct OtxResponse {
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
    let token = keys.pick("otx")?;
    let policy = source_policy("otx");
    let endpoint =
        format!("https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns");
    let response = send_with_retry_for_source(
        "otx",
        otx_request(&client(timeout)?, &endpoint, Some(&token)),
        policy.attempts,
        policy.base_backoff,
        domain,
    )
    .await
    .context("connexion à AlienVault OTX")?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let (_, body) = response_bytes_limited(response, "OTX").await?;
        let detail = String::from_utf8_lossy(&body);
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
        if page == 10 {
            bail!("Shodan: limite de pagination atteinte avec des résultats supplémentaires");
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
    fn driftnet_request_uses_the_documented_ct_contract() {
        assert_eq!(DRIFTNET_MAX_PAGES, 10);
        let request = driftnet_request(
            &client(Duration::from_secs(1)).unwrap(),
            "example.com",
            3,
            "driftnet-token",
        )
        .build()
        .unwrap();
        assert_eq!(request.url().host_str(), Some("api.driftnet.io"));
        assert_eq!(request.url().path(), "/v1/ct/log");
        assert_eq!(
            request
                .headers()
                .get("Authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer driftnet-token")
        );
        let query = request.url().query_pairs().collect::<Vec<_>>();
        assert!(query.contains(&("field".into(), "host:example.com".into())));
        assert!(query.contains(&("page".into(), "3".into())));
        assert!(!query.iter().any(|(name, _)| name == "summary_limit"));
    }

    #[test]
    fn driftnet_pages_accept_numeric_strings_and_extract_only_in_scope_names() {
        let page: DriftnetPage = serde_json::from_value(serde_json::json!({
            "page": "0",
            "pages": "2",
            "result_count": 101,
            "results": [{
                "date": "2026-07-16",
                "id": "fixture-report",
                "items": [
                    {"context": "cert-dns-name", "type": "host", "value": "api.example.com"},
                    {"context": "cert-dns-name", "type": "host", "value": "*.wild.example.com"},
                    {"context": "ct-log", "type": "url", "value": "https://cdn.example.com/log/"},
                    {"context": "cert-dns-name", "type": "host", "value": "outside.test"},
                    {"context": "ct-log", "type": "index", "value": 42}
                ]
            }]
        }))
        .unwrap();
        assert_eq!(driftnet_pagination(&page, 0).unwrap(), (0, 2));
        assert!(!page.timed_out);
        assert_eq!(
            driftnet_page_names(&page, "example.com"),
            BTreeSet::from([
                "api.example.com".to_owned(),
                "cdn.example.com".to_owned(),
                "wild.example.com".to_owned()
            ])
        );
    }

    #[test]
    fn driftnet_schema_and_pagination_fail_explicitly() {
        assert!(
            serde_json::from_value::<DriftnetPage>(serde_json::json!({
                "page": 0,
                "pages": 1,
                "error": "quota exceeded"
            }))
            .is_err()
        );

        let invalid_page: DriftnetPage = serde_json::from_value(serde_json::json!({
            "page": [],
            "pages": 1,
            "results": []
        }))
        .unwrap();
        assert!(
            format!("{:#}", driftnet_pagination(&invalid_page, 0).unwrap_err())
                .contains("champ de pagination page invalide")
        );

        let repeated_page: DriftnetPage = serde_json::from_value(serde_json::json!({
            "page": 1,
            "pages": 2,
            "results": []
        }))
        .unwrap();
        assert!(
            format!("{:#}", driftnet_pagination(&repeated_page, 0).unwrap_err())
                .contains("page inattendue 1")
        );

        let timed_out: DriftnetPage = serde_json::from_value(serde_json::json!({
            "page": 0,
            "pages": 2,
            "timed_out": true,
            "results": []
        }))
        .unwrap();
        assert!(timed_out.timed_out);

        assert!(
            driftnet_http_error(
                reqwest::StatusCode::UNAUTHORIZED,
                br#"{"message":"bad token"}"#
            )
            .unwrap()
            .contains("jeton API invalide (HTTP 401)")
        );
        assert!(
            driftnet_http_error(reqwest::StatusCode::FORBIDDEN, br#"{"message":"quota"}"#)
                .unwrap()
                .contains("quota API dépassé (HTTP 403)")
        );
        assert!(
            driftnet_http_error(reqwest::StatusCode::from_u16(524).unwrap(), b"")
                .unwrap()
                .contains("timeout CDN amont (HTTP 524)")
        );
        let oversized = format!("bad\nrequest \u{1b}[31m{}\u{202e}", "x".repeat(1_000));
        let diagnostic =
            driftnet_http_error(reqwest::StatusCode::UNAUTHORIZED, oversized.as_bytes()).unwrap();
        assert!(diagnostic.contains("bad request"));
        assert!(diagnostic.ends_with('…'));
        assert!(!diagnostic.contains('\u{1b}'));
        assert!(!diagnostic.contains('\u{202e}'));
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
        assert!(binaryedge_has_more(&binaryedge, 1).unwrap());

        let brave: BraveSearchPage = serde_json::from_value(serde_json::json!({
            "query": {"more_results_available": true},
            "web": {"results": [{"url": "https://outside.test/"}]}
        }))
        .unwrap();
        assert!(brave_page_names(&brave, "example.com").is_empty());
        assert!(brave_has_more(&brave).unwrap());

        let merklemap: MerkleMapSearchPage = serde_json::from_value(serde_json::json!({
            "count": 2,
            "results": [{"hostname": "outside.test"}]
        }))
        .unwrap();
        assert!(merklemap_page_names(&merklemap, "example.com").is_empty());
        assert!(merklemap_has_more(&merklemap, 1).unwrap());
    }

    #[test]
    fn pagination_schema_drift_and_inconsistent_progress_are_rejected() {
        assert!(
            serde_json::from_value::<BinaryEdgeSubdomainPage>(serde_json::json!({
                "events": ["api.example.com"]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<MerkleMapSearchPage>(serde_json::json!({
                "results": []
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<BraveSearchPage>(serde_json::json!({
                "query": {},
                "web": {"results": []}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ShodanDomainResponse>(serde_json::json!({
                "subdomains": []
            }))
            .is_err()
        );

        let missing_driftnet_pagination: DriftnetPage =
            serde_json::from_value(serde_json::json!({"results": []})).unwrap();
        assert!(driftnet_pagination(&missing_driftnet_pagination, 0).is_err());

        let wrong_binaryedge_page: BinaryEdgeSubdomainPage =
            serde_json::from_value(serde_json::json!({
                "page": 2,
                "pagesize": 100,
                "total": 250,
                "events": ["api.example.com"]
            }))
            .unwrap();
        assert!(binaryedge_has_more(&wrong_binaryedge_page, 1).is_err());

        let empty_brave_page: BraveSearchPage = serde_json::from_value(serde_json::json!({
            "query": {"more_results_available": true},
            "web": {"results": []}
        }))
        .unwrap();
        assert!(brave_has_more(&empty_brave_page).is_err());
    }

    #[test]
    fn merklemap_uses_cumulative_raw_results_for_a_short_final_page() {
        let final_page = MerkleMapSearchPage {
            count: 125,
            results: (0..25)
                .map(|index| MerkleMapSearchResult {
                    hostname: Some(format!("host-{index}.example.com")),
                    subject_common_name: None,
                })
                .collect(),
        };
        assert!(!merklemap_has_more(&final_page, 125).unwrap());
        assert!(merklemap_has_more(&final_page, 100).unwrap());
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
