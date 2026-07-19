use super::{
    ApiKeyStore, client, commit_result_page, compact_external_error, hostname_from_url,
    response_bytes_limited, response_json, send_external, send_external_idempotent,
    send_external_streaming, send_with_retry_for_source, source_policy,
};
use crate::util::normalize_observed_name;
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use url::Url;

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

const CODE_SEARCH_TEXT_MAX_BYTES: usize = 16 * 1024 * 1024;

fn bounded_text_prefix(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_hostname_sequences(text: &str, max_bytes: usize) -> String {
    let text = bounded_text_prefix(text, max_bytes);
    let input = text.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%'
            && index + 2 < input.len()
            && let (Some(high), Some(low)) =
                (hex_value(input[index + 1]), hex_value(input[index + 2]))
        {
            let value = (high << 4) | low;
            if value.is_ascii_alphanumeric() || matches!(value, b'.' | b'-' | b'*') {
                decoded.push(value);
                index += 3;
                continue;
            }
        }
        decoded.push(input[index]);
        index += 1;
    }
    String::from_utf8(decoded).expect("le décodage prudent conserve un UTF-8 valide")
}

fn extract_from_code_text(text: &str, domain: &str) -> BTreeSet<String> {
    let text = bounded_text_prefix(text, CODE_SEARCH_TEXT_MAX_BYTES);
    let mut names = extract_from_text(text, domain);
    let decoded = percent_decode_hostname_sequences(text, CODE_SEARCH_TEXT_MAX_BYTES);
    if decoded != text {
        names.extend(extract_from_text(&decoded, domain));
    }
    names
}

const PARTIAL_FAILURE_EXAMPLE_LIMIT: usize = 8;

#[derive(Debug, Default)]
struct PartialFailureSummary {
    count: usize,
    examples: Vec<String>,
}

impl PartialFailureSummary {
    fn record(&mut self, message: impl AsRef<str>) {
        self.count = self.count.saturating_add(1);
        let message = compact_external_error(message.as_ref());
        if !message.is_empty()
            && self.examples.len() < PARTIAL_FAILURE_EXAMPLE_LIMIT
            && !self.examples.contains(&message)
        {
            self.examples.push(message);
        }
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn detail(&self) -> String {
        if self.examples.is_empty() {
            return format!("{} échec(s)", self.count);
        }
        let mut detail = format!("{} échec(s); premier: {}", self.count, self.examples[0]);
        let mut others = self.examples.iter().skip(1).cloned().collect::<Vec<_>>();
        others.sort();
        if !others.is_empty() {
            detail.push_str(" | autres exemples: ");
            detail.push_str(&others.join(" | "));
        }
        detail
    }
}

fn finish_code_search(
    provider: &str,
    names: BTreeSet<String>,
    raw_failures: &PartialFailureSummary,
) -> Result<BTreeSet<String>> {
    if raw_failures.is_empty() {
        Ok(names)
    } else {
        bail!(
            "{provider}: résultats partiels; téléchargements de contenu brut: {}",
            raw_failures.detail()
        )
    }
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

fn next_link(headers: &reqwest::header::HeaderMap) -> Result<Option<String>> {
    let Some(header) = headers.get(reqwest::header::LINK) else {
        return Ok(None);
    };
    let header = header.to_str().context("pagination Link non ASCII")?;
    for entry in header.split(',') {
        let mut parts = entry.trim().split(';');
        let Some(target) = parts.next() else {
            continue;
        };
        let is_next = parts.any(|parameter| {
            let parameter = parameter.trim();
            parameter == "rel=\"next\"" || parameter == "rel=next"
        });
        if is_next {
            let target = target
                .trim()
                .strip_prefix('<')
                .and_then(|value| value.strip_suffix('>'))
                .context("lien de pagination next mal formé")?;
            return Ok(Some(target.to_owned()));
        }
    }
    Ok(None)
}

fn github_content_url(api_url: &str) -> Result<Url> {
    let parsed = Url::parse(api_url).context("GitHub: URL de contenu invalide")?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("api.github.com")
        || parsed.port_or_known_default() != Some(443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || !parsed.path().starts_with("/repositories/")
        || !parsed.path().contains("/contents/")
    {
        bail!("GitHub: URL de contenu non fiable");
    }
    if parsed.query_pairs().any(|(name, _)| name != "ref") {
        bail!("GitHub: paramètre de contenu non fiable");
    }
    Ok(parsed)
}

fn gitlab_raw_url(item: &GitlabSearchItem) -> Result<Url> {
    if item.project_id == 0 || item.path.is_empty() || item.reference.is_empty() {
        bail!("GitLab: résultat de blob incomplet");
    }
    let encoded_path =
        url::form_urlencoded::byte_serialize(item.path.as_bytes()).collect::<String>();
    let mut url = Url::parse(&format!(
        "https://gitlab.com/api/v4/projects/{}/repository/files/{encoded_path}/raw",
        item.project_id
    ))
    .context("GitLab: URL raw invalide")?;
    url.query_pairs_mut().append_pair("ref", &item.reference);
    Ok(url)
}

fn validate_intelx_host(host: &str) -> Result<&str> {
    let host = host.trim();
    if matches!(host, "public.intelx.io" | "free.intelx.io" | "2.intelx.io") {
        Ok(host)
    } else {
        bail!("Intelligence X: API host must be public.intelx.io, free.intelx.io, or 2.intelx.io")
    }
}

const INTELX_MAX_POLLS: usize = 25;
const INTELX_POLL_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Deserialize)]
struct IntelxSearchResponse {
    #[serde(default)]
    id: Option<String>,
    status: i64,
}

#[derive(Debug, Deserialize)]
struct IntelxSearchResult {
    #[serde(default)]
    selectors: Vec<IntelxSelector>,
    status: i64,
}

#[derive(Debug, Deserialize)]
struct IntelxSelector {
    selectorvalue: String,
}

fn intelx_search_id(response: &IntelxSearchResponse) -> Result<&str> {
    match response.status {
        0 => response
            .id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
            .context("Intelligence X: successful search omitted its ID"),
        1 => bail!("Intelligence X: invalid search term"),
        2 => bail!("Intelligence X: maximum concurrent searches reached"),
        status => bail!("Intelligence X: unknown initial search status {status}"),
    }
}

fn intelx_result_complete(status: i64) -> Result<bool> {
    match status {
        0 | 3 => Ok(false),
        1 => Ok(true),
        2 => bail!("Intelligence X: search ID was not found"),
        4 => bail!("Intelligence X: provider reported a search error"),
        status => bail!("Intelligence X: unknown result status {status}"),
    }
}

fn intelx_search_request(
    http: &reqwest::Client,
    host: &str,
    key: &str,
    domain: &str,
) -> reqwest::RequestBuilder {
    http.post(format!("https://{host}/phonebook/search"))
        .header("X-Key", key)
        .json(&json!({
            "term": domain,
            "maxresults": 100_000,
            "media": 0,
            "target": 1,
            "timeout": 20
        }))
}

fn intelx_result_request(
    http: &reqwest::Client,
    host: &str,
    key: &str,
    id: &str,
) -> reqwest::RequestBuilder {
    http.get(format!("https://{host}/phonebook/search/result"))
        .header("X-Key", key)
        .query(&[("id", id), ("limit", "10000")])
}

async fn code_content_names(
    source: &'static str,
    request: reqwest::RequestBuilder,
    domain: &str,
) -> Result<BTreeSet<String>> {
    let response = send_external(source, request, domain).await?;
    let (status, body) = response_bytes_limited(response, source).await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(BTreeSet::new());
    }
    if !status.is_success() {
        bail!(
            "{source}: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    Ok(extract_from_code_text(
        &String::from_utf8_lossy(&body),
        domain,
    ))
}

#[derive(Deserialize)]
struct HostsResponse {
    subdomains: Option<Vec<String>>,
    #[serde(default)]
    count: Option<usize>,
}

#[derive(Deserialize)]
struct FullHuntDomainResponse {
    #[serde(default)]
    hosts: Vec<String>,
    status: u16,
    #[serde(default)]
    message: String,
    metadata: FullHuntMetadata,
}

#[derive(Deserialize)]
struct FullHuntMetadata {
    all_results_count: usize,
    available_results_for_user: usize,
}

#[derive(Deserialize)]
struct FullHuntPassiveDnsResponse {
    count: usize,
    #[serde(default)]
    data: Vec<String>,
    #[serde(default)]
    error: String,
    status: u16,
}

#[derive(Deserialize)]
struct ShodanDomainResponse {
    subdomains: Vec<String>,
    more: bool,
}

#[derive(Deserialize)]
struct GithubSearchPage {
    #[serde(default)]
    total_count: usize,
    #[serde(default)]
    incomplete_results: bool,
    #[serde(default)]
    items: Vec<GithubSearchItem>,
}

#[derive(Deserialize)]
struct GithubSearchItem {
    url: String,
    #[serde(default)]
    text_matches: Vec<GithubTextMatch>,
}

#[derive(Deserialize)]
struct GithubTextMatch {
    fragment: String,
}

fn rotate_tokens_to_preferred(mut tokens: Vec<String>, preferred: &str) -> Vec<String> {
    if let Some(index) = tokens.iter().position(|token| token == preferred) {
        tokens.rotate_left(index);
    }
    tokens
}

fn github_tokens_for_page(keys: &ApiKeyStore) -> Result<Vec<String>> {
    let preferred = keys.pick("github")?;
    Ok(rotate_tokens_to_preferred(
        keys.values("github"),
        &preferred,
    ))
}

fn github_limit_message(body: &[u8]) -> bool {
    const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
    let prefix = &body[..body.len().min(MAX_DIAGNOSTIC_BYTES)];
    let message = String::from_utf8_lossy(prefix).to_ascii_lowercase();
    [
        "rate limit",
        "secondary limit",
        "abuse detection",
        "quota exceeded",
        "quota exhausted",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn github_token_rejected(
    status: reqwest::StatusCode,
    exhausted_rate_limit: bool,
    body: &[u8],
) -> bool {
    matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || exhausted_rate_limit
        || github_limit_message(body)
}

fn github_quota_observed(
    status: reqwest::StatusCode,
    exhausted_rate_limit: bool,
    body: &[u8],
) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || exhausted_rate_limit
        || github_limit_message(body)
}

fn github_tokens_exhausted_message(
    attempts: usize,
    last_status: Option<reqwest::StatusCode>,
    quota_observed: bool,
) -> String {
    let last_status = last_status
        .map(|status| status.to_string())
        .unwrap_or_else(|| "inconnu".to_owned());
    if quota_observed {
        format!(
            "GitHub Code Search: quota observé après {attempts} jeton(s) configuré(s); dernier HTTP {last_status}"
        )
    } else {
        format!(
            "GitHub Code Search: authentification refusée pour {attempts} jeton(s) configuré(s); dernier HTTP {last_status}"
        )
    }
}

async fn github_search_page(
    http: &reqwest::Client,
    url: &str,
    keys: &ApiKeyStore,
) -> Result<(GithubSearchPage, Option<String>)> {
    let tokens = github_tokens_for_page(keys)?;
    let attempts = tokens.len();
    let mut last_status = None;
    let mut quota_observed = false;
    for token in tokens {
        let request = http
            .get(url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github.v3.text-match+json");
        super::ensure_external_request_allowed(&request)?;
        super::throttle_external_source("github").await;
        super::throttle_external_host(&request).await;
        let response = request
            .send()
            .await
            .context("connexion à GitHub Code Search")?;
        let status = response.status();
        let exhausted_rate_limit = super::exhausted_rate_limit(&response);
        let next = status
            .is_success()
            .then(|| next_link(response.headers()))
            .transpose()?
            .flatten();
        let quota_from_headers = github_quota_observed(status, exhausted_rate_limit, b"");
        if !status.is_success()
            && (status == reqwest::StatusCode::UNAUTHORIZED || quota_from_headers)
        {
            quota_observed |= quota_from_headers;
            last_status = Some(status);
            continue;
        }
        let body = match response_bytes_limited(response, "GitHub Code Search").await {
            Ok((_, body)) => body,
            Err(_) if status == reqwest::StatusCode::FORBIDDEN => {
                last_status = Some(status);
                continue;
            }
            Err(error) => return Err(error),
        };
        if status.is_success() {
            let page = serde_json::from_slice::<GithubSearchPage>(&body)
                .context("JSON GitHub Code Search invalide")?;
            return Ok((page, next));
        }
        quota_observed |= github_quota_observed(status, exhausted_rate_limit, &body);
        if github_token_rejected(status, false, &body) {
            last_status = Some(status);
            continue;
        }
        let detail = super::sanitize_external_error(
            &compact_external_error(&String::from_utf8_lossy(&body)),
            keys,
        );
        bail!("GitHub Code Search: HTTP {status}: {detail}");
    }
    bail!(github_tokens_exhausted_message(
        attempts,
        last_status,
        quota_observed
    ))
}

#[derive(Deserialize)]
struct GitlabSearchItem {
    #[serde(default)]
    data: String,
    project_id: u64,
    path: String,
    #[serde(rename = "ref")]
    reference: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum CensysCredential {
    Platform {
        pat: String,
        organization_id: Option<String>,
        legacy_fallback: Option<(String, String)>,
    },
    Legacy {
        identifier: String,
        secret: String,
    },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CensysPlatformRequest {
    query: String,
    fields: Vec<&'static str>,
    page_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysPlatformResponse {
    result: CensysPlatformResult,
}

#[derive(Debug, Deserialize)]
struct CensysPlatformResult {
    hits: Vec<CensysPlatformHit>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysPlatformHit {
    certificate_v1: CensysCertificateV1,
}

#[derive(Debug, Deserialize)]
struct CensysCertificateV1 {
    resource: CensysCertificateResource,
}

#[derive(Debug, Deserialize)]
struct CensysCertificateResource {
    names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysLegacyResponse {
    result: CensysLegacyResult,
}

#[derive(Debug, Deserialize)]
struct CensysLegacyResult {
    hits: Vec<CensysLegacyHit>,
    #[serde(default)]
    links: CensysLegacyLinks,
}

#[derive(Debug, Deserialize)]
struct CensysLegacyHit {
    names: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CensysLegacyLinks {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DriftnetEndpoint {
    path: &'static str,
    query_name: &'static str,
    query_prefix: &'static str,
    summary_context: &'static str,
}

#[derive(Debug, Deserialize)]
struct DriftnetSummaryResponse {
    summary: DriftnetSummary,
}

#[derive(Debug, Deserialize)]
struct DriftnetSummary {
    #[serde(default)]
    other: usize,
    #[serde(default)]
    values: BTreeMap<String, usize>,
}

const MERKLEMAP_MAX_PAGES: usize = 1_000;
const BRAVE_MAX_PAGES: usize = 10;
const CENSYS_MAX_PAGES: usize = 10;
const CENSYS_PAGE_SIZE: usize = 100;
const CENSYS_MAX_CURSOR_BYTES: usize = 8 * 1024;
const CIRCL_MAX_STREAM_BYTES: usize = 128 * 1024 * 1024;
const CIRCL_MAX_LINE_BYTES: usize = 64 * 1024;
const CIRCL_MAX_LINES: usize = 100_000;
const CIRCL_CHECKPOINT_EVERY_LINES: usize = 1_000;
const DRIFTNET_SUMMARY_LIMIT: usize = 10_000;
const DRIFTNET_CONCURRENCY: usize = 4;
const DRIFTNET_ENDPOINTS: [DriftnetEndpoint; 4] = [
    DriftnetEndpoint {
        path: "ct/log",
        query_name: "field",
        query_prefix: "host:",
        summary_context: "cert-dns-name",
    },
    DriftnetEndpoint {
        path: "scan/protocols",
        query_name: "field",
        query_prefix: "host:",
        summary_context: "cert-dns-name",
    },
    DriftnetEndpoint {
        path: "scan/domains",
        query_name: "field",
        query_prefix: "host:",
        summary_context: "cert-dns-name",
    },
    DriftnetEndpoint {
        path: "domain/rdns",
        query_name: "host",
        query_prefix: "",
        summary_context: "dns-ptr",
    },
];

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

fn builtwith_request(
    client: &reqwest::Client,
    domain: &str,
    token: &str,
) -> reqwest::RequestBuilder {
    client
        .get("https://api.builtwith.com/v23/api.json")
        .query(&[
            ("KEY", token),
            ("LOOKUP", domain),
            ("HIDETEXT", "yes"),
            ("HIDEDL", "yes"),
            ("NOMETA", "yes"),
            ("NOPII", "yes"),
            ("NOATTR", "yes"),
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

fn parse_censys_credential(raw: &str) -> Result<CensysCredential> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("Censys: identifiant vide");
    }

    if let Some(value) = raw.strip_prefix("legacy:") {
        let (identifier, secret) = value
            .split_once(':')
            .context("CENSYS_API_KEY legacy doit être au format legacy:API_ID:API_SECRET")?;
        if identifier.trim().is_empty() || secret.trim().is_empty() {
            bail!("CENSYS_API_KEY legacy contient un identifiant ou un secret vide");
        }
        return Ok(CensysCredential::Legacy {
            identifier: identifier.trim().to_owned(),
            secret: secret.trim().to_owned(),
        });
    }

    let (raw, explicit_platform) = raw
        .strip_prefix("platform:")
        .map_or((raw, false), |value| (value, true));
    let (pat, organization_id) = raw
        .split_once(':')
        .map_or((raw, None), |(pat, organization_id)| {
            (pat, Some(organization_id))
        });
    let pat = pat.trim();
    if pat.is_empty() {
        bail!("CENSYS_API_KEY contient un PAT vide");
    }
    let organization_id = organization_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if raw.contains(':') && organization_id.is_none() {
        bail!("CENSYS_API_KEY contient un identifiant d'organisation vide");
    }
    let legacy_fallback = (!explicit_platform)
        .then(|| organization_id.clone().map(|value| (pat.to_owned(), value)))
        .flatten();
    Ok(CensysCredential::Platform {
        pat: pat.to_owned(),
        organization_id,
        legacy_fallback,
    })
}

fn censys_platform_request(
    client: &reqwest::Client,
    domain: &str,
    credential: &CensysCredential,
    cursor: Option<&str>,
) -> Result<reqwest::RequestBuilder> {
    let CensysCredential::Platform {
        pat,
        organization_id,
        ..
    } = credential
    else {
        bail!("Censys: identifiant Platform requis");
    };
    let mut request = client
        .post("https://api.platform.censys.io/v3/global/search/query")
        .bearer_auth(pat)
        .json(&CensysPlatformRequest {
            query: format!("cert.names: {domain}"),
            fields: vec!["cert.names"],
            page_size: CENSYS_PAGE_SIZE,
            page_token: cursor.map(ToOwned::to_owned),
        });
    if let Some(organization_id) = organization_id {
        request = request.header("X-Organization-ID", organization_id);
    }
    Ok(request)
}

fn censys_legacy_request(
    client: &reqwest::Client,
    domain: &str,
    identifier: &str,
    secret: &str,
    cursor: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut request = client
        .get("https://search.censys.io/api/v2/certificates/search")
        .basic_auth(identifier, Some(secret))
        .query(&[("q", domain), ("per_page", "100")]);
    if let Some(cursor) = cursor {
        request = request.query(&[("cursor", cursor)]);
    }
    request
}

fn censys_platform_page_names(page: &CensysPlatformResponse, domain: &str) -> BTreeSet<String> {
    page.result
        .hits
        .iter()
        .flat_map(|hit| &hit.certificate_v1.resource.names)
        .filter_map(|name| normalize_observed_name(name, domain))
        .collect()
}

fn censys_legacy_page_names(page: &CensysLegacyResponse, domain: &str) -> BTreeSet<String> {
    page.result
        .hits
        .iter()
        .flat_map(|hit| &hit.names)
        .filter_map(|name| normalize_observed_name(name, domain))
        .collect()
}

fn checked_censys_cursor(
    next: Option<&str>,
    seen: &mut BTreeSet<String>,
) -> Result<Option<String>> {
    let Some(next) = next.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if next.len() > CENSYS_MAX_CURSOR_BYTES {
        bail!("Censys: curseur de pagination trop long");
    }
    if !seen.insert(next.to_owned()) {
        bail!("Censys: curseur de pagination répété");
    }
    Ok(Some(next.to_owned()))
}

fn driftnet_request(
    client: &reqwest::Client,
    domain: &str,
    endpoint: DriftnetEndpoint,
    token: &str,
) -> reqwest::RequestBuilder {
    let filter = format!("{}{}", endpoint.query_prefix, domain);
    client
        .get(format!("https://api.driftnet.io/v1/{}", endpoint.path))
        .bearer_auth(token)
        .query(&[
            (endpoint.query_name, filter),
            ("summarize", "host".to_owned()),
            ("summary_context", endpoint.summary_context.to_owned()),
            ("summary_limit", DRIFTNET_SUMMARY_LIMIT.to_string()),
        ])
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

fn driftnet_summary_names(response: &DriftnetSummaryResponse, domain: &str) -> BTreeSet<String> {
    response
        .summary
        .values
        .keys()
        .filter_map(|name| normalize_observed_name(name, domain))
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct CirclStreamLimits {
    max_bytes: usize,
    max_line_bytes: usize,
    max_nonempty_lines: usize,
    checkpoint_every: usize,
}

const CIRCL_STREAM_LIMITS: CirclStreamLimits = CirclStreamLimits {
    max_bytes: CIRCL_MAX_STREAM_BYTES,
    max_line_bytes: CIRCL_MAX_LINE_BYTES,
    max_nonempty_lines: CIRCL_MAX_LINES,
    checkpoint_every: CIRCL_CHECKPOINT_EVERY_LINES,
};

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Debug)]
struct CirclStreamDecoder<'a> {
    domain: &'a str,
    limits: CirclStreamLimits,
    names: BTreeSet<String>,
    batch: BTreeSet<String>,
    carry: Vec<u8>,
    bytes_seen: usize,
    nonempty_lines: usize,
}

impl<'a> CirclStreamDecoder<'a> {
    fn new(domain: &'a str, mut limits: CirclStreamLimits) -> Self {
        limits.checkpoint_every = limits.checkpoint_every.max(1);
        Self {
            domain,
            limits,
            names: BTreeSet::new(),
            batch: BTreeSet::new(),
            carry: Vec::new(),
            bytes_seen: 0,
            nonempty_lines: 0,
        }
    }

    fn checkpoint(&mut self) {
        commit_result_page(&mut self.names, std::mem::take(&mut self.batch));
    }

    fn process_line(&mut self, line: &[u8], at_eof: bool) -> Result<()> {
        let line = trim_ascii_whitespace(line);
        if line.is_empty() {
            return Ok(());
        }
        if self.nonempty_lines >= self.limits.max_nonempty_lines {
            bail!(
                "CIRCL Passive DNS: plus de {} lignes non vides; résultats partiels enregistrés",
                self.limits.max_nonempty_lines
            );
        }
        self.nonempty_lines = self.nonempty_lines.saturating_add(1);
        match serde_json::from_slice::<Value>(line) {
            Ok(value) => extract_from_json(&value, self.domain, &mut self.batch),
            Err(error) if matches!(line.first().copied(), Some(b'{') | Some(b'[')) => {
                if at_eof {
                    bail!("CIRCL Passive DNS: enregistrement NDJSON final tronqué: {error}");
                }
                bail!("CIRCL Passive DNS: enregistrement NDJSON invalide: {error}");
            }
            Err(_) => {
                let line = std::str::from_utf8(line)
                    .context("CIRCL Passive DNS: enregistrement texte non UTF-8")?;
                self.batch.extend(extract_from_text(line, self.domain));
            }
        }
        if self
            .nonempty_lines
            .is_multiple_of(self.limits.checkpoint_every)
        {
            self.checkpoint();
        }
        Ok(())
    }

    fn process_carried_line(&mut self, at_eof: bool) -> Result<()> {
        let mut complete = std::mem::take(&mut self.carry);
        let line = complete.strip_suffix(b"\r").unwrap_or(&complete);
        let result = self.process_line(line, at_eof);
        complete.clear();
        self.carry = complete;
        result
    }

    fn push_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        self.bytes_seen = self
            .bytes_seen
            .checked_add(chunk.len())
            .context("CIRCL Passive DNS: compteur de taille dépassé")?;
        if self.bytes_seen > self.limits.max_bytes {
            self.checkpoint();
            bail!(
                "CIRCL Passive DNS: flux supérieur à la limite de {} Mio; résultats partiels enregistrés",
                self.limits.max_bytes / 1024 / 1024
            );
        }

        let mut offset = 0_usize;
        while offset < chunk.len() {
            let remaining = &chunk[offset..];
            let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') else {
                let pending = self
                    .carry
                    .len()
                    .checked_add(remaining.len())
                    .context("CIRCL Passive DNS: longueur de ligne dépassée")?;
                if pending > self.limits.max_line_bytes {
                    self.checkpoint();
                    bail!(
                        "CIRCL Passive DNS: ligne supérieure à {} octets; résultats partiels enregistrés",
                        self.limits.max_line_bytes
                    );
                }
                self.carry.extend_from_slice(remaining);
                break;
            };
            let segment = &remaining[..newline];
            let line_length = self
                .carry
                .len()
                .checked_add(segment.len())
                .context("CIRCL Passive DNS: longueur de ligne dépassée")?;
            if line_length > self.limits.max_line_bytes {
                self.checkpoint();
                bail!(
                    "CIRCL Passive DNS: ligne supérieure à {} octets; résultats partiels enregistrés",
                    self.limits.max_line_bytes
                );
            }
            self.carry.extend_from_slice(segment);
            if let Err(error) = self.process_carried_line(false) {
                self.checkpoint();
                return Err(error);
            }
            offset = offset.saturating_add(newline).saturating_add(1);
        }
        // This checkpoint is synchronous and happens before the caller awaits
        // the next transport chunk, preserving every complete record.
        self.checkpoint();
        Ok(())
    }

    fn finish(mut self) -> Result<BTreeSet<String>> {
        if !self.carry.is_empty()
            && let Err(error) = self.process_carried_line(true)
        {
            self.checkpoint();
            return Err(error);
        }
        self.checkpoint();
        Ok(self.names)
    }
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

#[derive(Debug)]
struct DriftnetEndpointResult {
    names: BTreeSet<String>,
    truncated: usize,
}

async fn query_driftnet_endpoint(
    http: &reqwest::Client,
    domain: &str,
    token: &str,
    endpoint: DriftnetEndpoint,
    attempts: usize,
    base_backoff: Duration,
) -> Result<DriftnetEndpointResult> {
    let response = send_with_retry_for_source(
        "driftnet",
        driftnet_request(http, domain, endpoint, token),
        attempts,
        base_backoff,
        domain,
    )
    .await
    .with_context(|| format!("connexion à Driftnet {}", endpoint.path))?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(DriftnetEndpointResult {
            names: BTreeSet::new(),
            truncated: 0,
        });
    }
    if matches!(response.status().as_u16(), 401 | 403 | 524) {
        let (status, body) = response_bytes_limited(response, "Driftnet").await?;
        bail!(
            "{}",
            driftnet_http_error(status, &body)
                .unwrap_or_else(|| format!("Driftnet: HTTP {status}"))
        );
    }
    let page = response_json::<DriftnetSummaryResponse>(response, "Driftnet").await?;
    if page.summary.values.len() > DRIFTNET_SUMMARY_LIMIT {
        bail!(
            "Driftnet {}: résumé supérieur à la limite demandée de {} valeurs",
            endpoint.path,
            DRIFTNET_SUMMARY_LIMIT
        );
    }
    Ok(DriftnetEndpointResult {
        names: driftnet_summary_names(&page, domain),
        truncated: page.summary.other,
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
        builtwith_request(&client(timeout)?, domain, &token),
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

async fn censys_platform(
    domain: &str,
    timeout: Duration,
    credential: &CensysCredential,
) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut names = BTreeSet::new();
    for iteration in 0..CENSYS_MAX_PAGES {
        let request = censys_platform_request(&http, domain, credential, cursor.as_deref())?;
        // This POST is a read-only search query. Opt it into the same bounded
        // retry policy as GET requests; the job-creating IntelX POST remains
        // deliberately one-shot.
        let response = match send_external_idempotent("censys", request, domain).await {
            Ok(response) => response,
            Err(error) => return Err(error).context("connexion à Censys Platform v3"),
        };
        if iteration == 0
            && response.status() == reqwest::StatusCode::UNAUTHORIZED
            && let CensysCredential::Platform {
                legacy_fallback: Some((identifier, secret)),
                ..
            } = credential
        {
            return censys_legacy(domain, timeout, identifier, secret)
                .await
                .context("Censys Platform v3 a rejeté l'identifiant; repli legacy v2");
        }
        let page = response_json::<CensysPlatformResponse>(response, "Censys Platform v3").await?;
        commit_result_page(&mut names, censys_platform_page_names(&page, domain));
        let next_cursor =
            checked_censys_cursor(page.result.next_page_token.as_deref(), &mut seen_cursors)?;
        let Some(next_cursor) = next_cursor else {
            break;
        };
        if iteration + 1 == CENSYS_MAX_PAGES {
            bail!("Censys Platform v3: limite de pagination atteinte avec un curseur suivant");
        }
        cursor = Some(next_cursor);
    }
    Ok(names)
}

async fn censys_legacy(
    domain: &str,
    timeout: Duration,
    identifier: &str,
    secret: &str,
) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = BTreeSet::new();
    let mut names = BTreeSet::new();
    for iteration in 0..CENSYS_MAX_PAGES {
        let response = send_external(
            "censys",
            censys_legacy_request(&http, domain, identifier, secret, cursor.as_deref()),
            domain,
        )
        .await
        .context("connexion à Censys legacy v2")?;
        let page = response_json::<CensysLegacyResponse>(response, "Censys legacy v2").await?;
        commit_result_page(&mut names, censys_legacy_page_names(&page, domain));
        let next_cursor =
            checked_censys_cursor(page.result.links.next.as_deref(), &mut seen_cursors)?;
        let Some(next_cursor) = next_cursor else {
            break;
        };
        if iteration + 1 == CENSYS_MAX_PAGES {
            bail!("Censys legacy v2: limite de pagination atteinte avec un curseur suivant");
        }
        cursor = Some(next_cursor);
    }
    Ok(names)
}

pub(super) async fn censys(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credential = parse_censys_credential(&keys.pick("censys")?)?;
    match &credential {
        CensysCredential::Platform { .. } => censys_platform(domain, timeout, &credential).await,
        CensysCredential::Legacy { identifier, secret } => {
            censys_legacy(domain, timeout, identifier, secret).await
        }
    }
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
    let mut response = send_external_streaming(
        "circl",
        client(timeout)?
            .get(format!("https://www.circl.lu/pdns/query/{domain}"))
            .basic_auth(username, Some(password))
            .header("dribble-disable-active-query", "1"),
        domain,
    )
    .await
    .context("connexion à CIRCL Passive DNS")?;
    if !response.status().is_success() {
        let status = response.status();
        let (_, body) = response_bytes_limited(response, "CIRCL Passive DNS").await?;
        bail!(
            "CIRCL Passive DNS: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > CIRCL_MAX_STREAM_BYTES as u64)
    {
        bail!(
            "CIRCL Passive DNS: réponse supérieure à la limite de {} Mio",
            CIRCL_MAX_STREAM_BYTES / 1024 / 1024
        );
    }

    let mut decoder = CirclStreamDecoder::new(domain, CIRCL_STREAM_LIMITS);
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => decoder.push_chunk(&chunk)?,
            Ok(None) => return decoder.finish(),
            Err(error) => {
                let incomplete = !decoder.carry.is_empty();
                decoder.checkpoint();
                let context = if incomplete {
                    "CIRCL Passive DNS: flux interrompu avec une ligne inachevée; résultats partiels enregistrés"
                } else {
                    "CIRCL Passive DNS: flux interrompu; résultats partiels enregistrés"
                };
                return Err(error).context(context);
            }
        }
    }
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
    let (status, body) = response_bytes_limited(response, "CertificateDetails").await?;
    if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
        bail!(
            "CertificateDetails: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    // The provider intentionally embeds its certificate inventory in the
    // branded 404 page when a direct per-domain route is not available.
    let text = String::from_utf8(body).context("CertificateDetails: réponse non UTF-8")?;
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
    let values = response
        .subdomains
        .context("Chaos: champ subdomains absent")?;
    let returned = values.len();
    let total = response.count.context("Chaos: champ count absent")?;
    if total < returned {
        bail!("Chaos: result count exceeds reported total");
    }
    let mut names = BTreeSet::new();
    let page = values
        .into_iter()
        .filter_map(|label| normalize_observed_name(&format!("{label}.{domain}"), domain))
        .collect();
    commit_result_page(&mut names, page);
    if total > returned {
        bail!("Chaos: résultats partiels, {returned}/{total} entrées reçues");
    }
    Ok(names)
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
    let mut failures = PartialFailureSummary::default();
    let mut truncated_endpoints = Vec::new();
    let mut requests = stream::iter(DRIFTNET_ENDPOINTS.into_iter().map(|endpoint| {
        let http = http.clone();
        async move {
            (
                endpoint,
                query_driftnet_endpoint(
                    &http,
                    domain,
                    token,
                    endpoint,
                    policy.attempts,
                    policy.base_backoff,
                )
                .await,
            )
        }
    }))
    .buffer_unordered(DRIFTNET_CONCURRENCY);
    while let Some((endpoint, result)) = requests.next().await {
        match result {
            Ok(result) => {
                commit_result_page(&mut names, result.names);
                if result.truncated > 0 {
                    truncated_endpoints.push(format!("{} (+{})", endpoint.path, result.truncated));
                }
            }
            Err(error) => {
                let error =
                    super::sanitize_external_message(&format!("{error:#}"), &[token.to_owned()]);
                failures.record(format!("{}: {error}", endpoint.path));
            }
        }
    }
    if failures.is_empty() && truncated_endpoints.is_empty() {
        return Ok(names);
    }
    truncated_endpoints.sort();
    let mut problems = Vec::new();
    if !failures.is_empty() {
        problems.push(failures.detail());
    }
    if !truncated_endpoints.is_empty() {
        problems.push(format!(
            "résumés tronqués: {}",
            truncated_endpoints.join(", ")
        ));
    }
    bail!("Driftnet: résultats partiels; {}", problems.join("; "))
}

async fn fullhunt_domain(
    http: &reqwest::Client,
    domain: &str,
    token: &str,
) -> Result<BTreeSet<String>> {
    let response = send_external(
        "fullhunt",
        http.get(format!(
            "https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        ))
        .header("X-API-KEY", token),
        domain,
    )
    .await
    .context("connexion à FullHunt")?;
    let response = response_json::<FullHuntDomainResponse>(response, "FullHunt").await?;
    if response.status != 200 {
        bail!(
            "FullHunt: {} (status {})",
            compact_external_error(&response.message),
            response.status
        );
    }
    let returned = response.hosts.len();
    if response.metadata.all_results_count < returned
        || response.metadata.available_results_for_user < returned
    {
        bail!("FullHunt: result count exceeds provider metadata");
    }
    let mut names = BTreeSet::new();
    commit_result_page(&mut names, normalize_many(response.hosts, domain));
    if response.metadata.all_results_count > returned
        || response.metadata.available_results_for_user < response.metadata.all_results_count
    {
        bail!(
            "FullHunt: résultats partiels, {returned}/{} entrées disponibles pour ce plan sur {} connues",
            response.metadata.available_results_for_user,
            response.metadata.all_results_count
        );
    }
    Ok(names)
}

async fn fullhunt_passive_dns(
    http: &reqwest::Client,
    domain: &str,
    token: &str,
) -> Result<BTreeSet<String>> {
    let response = send_external(
        "fullhunt",
        http.get("https://fullhunt.io/api/v1/nexus/passive-dns/lookup")
            .query(&[("domain", domain)])
            .header("X-API-KEY", token),
        domain,
    )
    .await
    .context("connexion à FullHunt Passive DNS")?;
    let response =
        response_json::<FullHuntPassiveDnsResponse>(response, "FullHunt Passive DNS").await?;
    if response.status != 200 || !response.error.is_empty() {
        bail!(
            "FullHunt Passive DNS: {} (status {})",
            compact_external_error(&response.error),
            response.status
        );
    }
    let returned = response.data.len();
    if response.count < returned {
        bail!("FullHunt Passive DNS: result count exceeds reported total");
    }
    let mut names = BTreeSet::new();
    commit_result_page(&mut names, normalize_many(response.data, domain));
    if response.count > returned {
        bail!(
            "FullHunt Passive DNS: résultats partiels, {returned}/{} entrées reçues",
            response.count
        );
    }
    Ok(names)
}

pub(super) async fn fullhunt(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("fullhunt")?;
    let http = client(timeout)?;
    let (domain_result, passive_dns_result) = tokio::join!(
        fullhunt_domain(&http, domain, &token),
        fullhunt_passive_dns(&http, domain, &token)
    );
    let mut names = BTreeSet::new();
    let mut failures = PartialFailureSummary::default();
    for result in [domain_result, passive_dns_result] {
        match result {
            Ok(found) => commit_result_page(&mut names, found),
            Err(error) => failures.record(format!("{error:#}")),
        }
    }
    if failures.is_empty() {
        Ok(names)
    } else {
        bail!("FullHunt: résultats partiels; {}", failures.detail())
    }
}

pub(super) async fn github(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut initial = Url::parse("https://api.github.com/search/code")?;
    initial
        .query_pairs_mut()
        .append_pair("per_page", "100")
        .append_pair("q", domain);
    let mut next = Some(initial.to_string());
    let mut visited = BTreeSet::new();
    let mut raw_failures = PartialFailureSummary::default();
    let mut upstream_partial = false;
    for _ in 0..10 {
        let Some(url) = next.take() else {
            if upstream_partial {
                let raw = if raw_failures.is_empty() {
                    String::new()
                } else {
                    format!("; contenu brut: {}", raw_failures.detail())
                };
                bail!(
                    "GitHub Code Search: résultats partiels signalés par l'API ou plafond de 1000 résultats atteint{raw}"
                );
            }
            return finish_code_search("GitHub Code Search", names, &raw_failures);
        };
        if !super::trusted_pagination_url(&url, "api.github.com", "/search/code") {
            bail!("GitHub Code Search: URL de pagination non fiable");
        }
        if !visited.insert(url.clone()) {
            bail!("GitHub Code Search: URL de pagination répétée");
        }
        let (page, page_next) = github_search_page(&http, &url, keys).await?;
        upstream_partial |= page.incomplete_results || page.total_count > 1_000;
        next = page_next;
        let mut page_names = BTreeSet::new();
        let mut content_requests = BTreeSet::new();
        for item in page.items {
            for text_match in item.text_matches {
                page_names.extend(extract_from_code_text(&text_match.fragment, domain));
            }
            content_requests.insert((github_content_url(&item.url)?, keys.pick("github")?));
        }
        commit_result_page(&mut names, page_names);

        let mut content = stream::iter(content_requests.into_iter().map(|(url, token)| {
            let http = http.clone();
            async move {
                code_content_names(
                    "github-content",
                    http.get(url)
                        .bearer_auth(token)
                        .header("Accept", "application/vnd.github.raw+json"),
                    domain,
                )
                .await
            }
        }))
        .buffer_unordered(8);
        while let Some(result) = content.next().await {
            match result {
                Ok(page_names) => commit_result_page(&mut names, page_names),
                Err(error) => {
                    let error = super::sanitize_external_error(&format!("{error:#}"), keys);
                    raw_failures.record(error);
                }
            }
        }
    }
    if !raw_failures.is_empty() || upstream_partial {
        let upstream = if upstream_partial {
            "API incomplète ou plafond de 1000 résultats atteint"
        } else {
            ""
        };
        let raw = if raw_failures.is_empty() {
            String::new()
        } else {
            raw_failures.detail()
        };
        bail!(
            "GitHub Code Search: résultats partiels; {upstream} {raw}; limite de pagination atteinte avec une page suivante"
        );
    }
    bail!("GitHub Code Search: limite de pagination atteinte avec une page suivante")
}

pub(super) async fn gitlab(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("gitlab")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut initial = Url::parse("https://gitlab.com/api/v4/search")?;
    initial
        .query_pairs_mut()
        .append_pair("scope", "blobs")
        .append_pair("search", domain)
        .append_pair("per_page", "100");
    let mut next = Some(initial.to_string());
    let mut visited = BTreeSet::new();
    let mut raw_failures = PartialFailureSummary::default();
    for _ in 0..1_000 {
        let Some(url) = next.take() else {
            return finish_code_search("GitLab Code Search", names, &raw_failures);
        };
        if !super::trusted_pagination_url(&url, "gitlab.com", "/api/v4/search") {
            bail!("GitLab Code Search: URL de pagination non fiable");
        }
        if !visited.insert(url.clone()) {
            bail!("GitLab Code Search: URL de pagination répétée");
        }
        let request = http
            .get(url)
            .header("PRIVATE-TOKEN", &token)
            .header("Accept", "application/json");
        let response = match send_external("gitlab", request, domain).await {
            Ok(response) => response,
            Err(error) => return Err(error).context("connexion à GitLab Code Search"),
        };
        next = next_link(response.headers())?;
        let items =
            match response_json::<Vec<GitlabSearchItem>>(response, "GitLab Code Search").await {
                Ok(values) => values,
                Err(error) => return Err(error),
            };
        let mut page_names = BTreeSet::new();
        let mut raw_urls = BTreeSet::new();
        for item in &items {
            page_names.extend(extract_from_code_text(&item.data, domain));
            raw_urls.insert(gitlab_raw_url(item)?);
        }
        commit_result_page(&mut names, page_names);

        let mut content = stream::iter(raw_urls.into_iter().map(|url| {
            let http = http.clone();
            let token = token.clone();
            async move {
                code_content_names(
                    "gitlab-content",
                    http.get(url).header("PRIVATE-TOKEN", token),
                    domain,
                )
                .await
            }
        }))
        .buffer_unordered(8);
        while let Some(result) = content.next().await {
            match result {
                Ok(page_names) => commit_result_page(&mut names, page_names),
                Err(error) => {
                    let error = super::sanitize_external_error(&format!("{error:#}"), keys);
                    raw_failures.record(error);
                }
            }
        }
    }
    if !raw_failures.is_empty() {
        bail!(
            "GitLab Code Search: résultats partiels; {}; limite de pagination atteinte avec une page suivante",
            raw_failures.detail()
        );
    }
    bail!("GitLab Code Search: limite de pagination atteinte avec une page suivante")
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
    let host = validate_intelx_host(host)?;
    let key = key.trim();
    if key.is_empty() {
        bail!("Intelligence X: clé API vide");
    }
    let http = client(timeout)?;
    let search = send_external(
        "intelx",
        intelx_search_request(&http, host, key, domain),
        domain,
    )
    .await
    .context("connexion à Intelligence X")?;
    let search = response_json::<IntelxSearchResponse>(search, "recherche Intelligence X").await?;
    let id = intelx_search_id(&search)?;
    let mut names = BTreeSet::new();
    for iteration in 0..INTELX_MAX_POLLS {
        tokio::time::sleep(INTELX_POLL_DELAY).await;
        let request = intelx_result_request(&http, host, key, id);
        let response = match send_external("intelx", request, domain).await {
            Ok(response) => {
                match response_json::<IntelxSearchResult>(response, "Intelligence X").await {
                    Ok(response) => response,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error).context("lecture des résultats Intelligence X"),
        };
        let page_names = response
            .selectors
            .into_iter()
            .filter_map(|selector| normalize_observed_name(&selector.selectorvalue, domain))
            .collect();
        commit_result_page(&mut names, page_names);
        if intelx_result_complete(response.status)? {
            return Ok(names);
        }
        if iteration + 1 == INTELX_MAX_POLLS {
            bail!("Intelligence X: search remained active after {INTELX_MAX_POLLS} bounded polls");
        }
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
    #[serde(default)]
    passive_dns: Vec<OtxRecord>,
    #[serde(default)]
    has_next: bool,
    #[serde(default)]
    page_num: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    actual_size: Option<usize>,
    #[serde(default)]
    full_size: Option<usize>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Deserialize)]
struct OtxRecord {
    hostname: String,
}

const OTX_PAGE_SIZE: usize = 50;
const OTX_MAX_PAGES: usize = 1_000;
const POSTMAN_PAGE_SIZE: usize = 25;
const POSTMAN_MAX_PAGES: usize = 100;
const POSTMAN_CURSOR_MAX_BYTES: usize = 8 * 1024;

fn otx_request(
    client: &reqwest::Client,
    endpoint: &str,
    token: Option<&str>,
    page: usize,
) -> reqwest::RequestBuilder {
    let request = client
        .get(endpoint)
        .query(&[("limit", OTX_PAGE_SIZE), ("page", page)]);
    match token {
        Some(token) => request.header("X-OTX-API-KEY", token),
        None => request,
    }
}

#[derive(Deserialize)]
struct PostmanSearchResponse {
    meta: PostmanSearchMeta,
    data: Vec<Value>,
}

#[derive(Deserialize)]
struct PostmanSearchMeta {
    #[serde(rename = "nextCursor", default)]
    next_cursor: Option<String>,
    #[serde(default)]
    total: Option<usize>,
}

fn postman_search_request(
    http: &reqwest::Client,
    domain: &str,
    cursor: Option<&str>,
    token: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut request = http
        .post("https://api.postman.com/search")
        .query(&[("limit", POSTMAN_PAGE_SIZE)])
        .json(&json!({
            "elementType": "requests",
            "q": domain,
            "ownership": "all",
            "filters": {
                "$and": [
                    {"visibility": {"$eq": "public"}}
                ]
            }
        }));
    if let Some(cursor) = cursor {
        request = request.query(&[("cursor", cursor)]);
    }
    if let Some(token) = token {
        request = request.header("x-api-key", token);
    }
    request
}

fn postman_page_names(data: &[Value], domain: &str) -> BTreeSet<String> {
    fn extract(value: &Value, domain: &str, names: &mut BTreeSet<String>) {
        match value {
            Value::String(value) => names.extend(extract_from_code_text(value, domain)),
            Value::Array(values) => {
                for value in values {
                    extract(value, domain, names);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    names.extend(extract_from_code_text(key, domain));
                    extract(value, domain, names);
                }
            }
            _ => {}
        }
    }

    let mut names = BTreeSet::new();
    for item in data {
        extract(item, domain, &mut names);
    }
    names
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut canonical = serde_json::Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonical_json_value(&values[key]));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

fn postman_page_fingerprint(data: &[Value]) -> Result<Vec<Vec<u8>>> {
    let mut records = data
        .iter()
        .map(|record| {
            serde_json::to_vec(&canonical_json_value(record))
                .context("Postman: page fingerprint failed")
        })
        .collect::<Result<Vec<_>>>()?;
    // Search ordering is not part of the provider contract. Sorting complete
    // canonical records detects a cursor loop even when the same page is
    // returned in a different order.
    records.sort_unstable();
    Ok(records)
}

fn postman_next_cursor(cursor: Option<String>) -> Result<Option<String>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let cursor = cursor.trim().to_owned();
    if cursor.is_empty() {
        return Ok(None);
    }
    if cursor.len() > POSTMAN_CURSOR_MAX_BYTES
        || cursor.chars().any(|character| character.is_control())
    {
        bail!("Postman returned an invalid pagination cursor");
    }
    Ok(Some(cursor))
}

fn postman_reported_total(known: Option<usize>, received: Option<usize>) -> Result<Option<usize>> {
    match (known, received) {
        (Some(known), Some(received)) if known != received => {
            bail!("Postman changed the reported total during pagination: {known} -> {received}")
        }
        (None, Some(received)) => Ok(Some(received)),
        (known, _) => Ok(known),
    }
}

pub(super) async fn postman(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.optional("postman");
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    let mut seen_pages = BTreeSet::new();
    let mut raw_records_seen = 0_usize;
    let mut reported_total = None;

    for page in 1..=POSTMAN_MAX_PAGES {
        let response = send_external_idempotent(
            "postman",
            postman_search_request(&http, domain, cursor.as_deref(), token.as_deref()),
            &format!("{domain}:{page}"),
        )
        .await
        .with_context(|| format!("connection to Postman search page {page}"))?;
        let response = response_json::<PostmanSearchResponse>(response, "Postman").await?;
        let raw_count = response.data.len();
        let next_reported_total = postman_reported_total(reported_total, response.meta.total)?;
        let next_raw_records_seen = raw_records_seen.saturating_add(raw_count);
        if next_reported_total.is_some_and(|total| next_raw_records_seen > total) {
            bail!(
                "Postman returned more records than reported: {next_raw_records_seen}/{}",
                next_reported_total.unwrap_or(next_raw_records_seen)
            );
        }
        let fingerprint = postman_page_fingerprint(&response.data)?;
        if !fingerprint.is_empty() && seen_pages.contains(&fingerprint) {
            bail!("Postman returned a repeated pagination page");
        }
        let next_cursor = postman_next_cursor(response.meta.next_cursor)?;
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| seen_cursors.contains(cursor))
        {
            bail!("Postman returned a repeated pagination cursor");
        }
        if next_cursor.is_some() && raw_count == 0 {
            bail!("Postman returned an empty page with a continuation cursor");
        }

        // Commit only after every structural invariant for this page has
        // passed. A valid terminal page is retained even when its metadata
        // proves the overall result was partial.
        reported_total = next_reported_total;
        raw_records_seen = next_raw_records_seen;
        if !fingerprint.is_empty() {
            seen_pages.insert(fingerprint);
        }
        if let Some(cursor) = &next_cursor {
            seen_cursors.insert(cursor.clone());
        }
        commit_result_page(&mut names, postman_page_names(&response.data, domain));
        let Some(next_cursor) = next_cursor else {
            if reported_total.is_some_and(|total| total > raw_records_seen) {
                bail!(
                    "Postman returned a partial result: {raw_records_seen}/{} records",
                    reported_total.unwrap_or(raw_records_seen)
                );
            }
            return Ok(names);
        };
        if page == POSTMAN_MAX_PAGES {
            bail!("Postman pagination limit reached while more results remained");
        }
        cursor = Some(next_cursor);
    }

    Ok(names)
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
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut seen_pages = BTreeSet::new();
    let mut raw_records_seen = 0_usize;

    for requested_page in 1..=OTX_MAX_PAGES {
        let response = send_with_retry_for_source(
            "otx",
            otx_request(&http, &endpoint, Some(&token), requested_page),
            policy.attempts,
            policy.base_backoff,
            &format!("{domain}:{requested_page}"),
        )
        .await
        .with_context(|| format!("connexion à AlienVault OTX page {requested_page}"))?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let (_, body) = response_bytes_limited(response, "OTX").await?;
            let detail = compact_external_error(&String::from_utf8_lossy(&body));
            bail!("OTX rate limited the configured key (HTTP 429): {detail}");
        }
        let response = response_json::<OtxResponse>(response, "OTX").await?;
        if let Some(error) = response
            .error
            .as_deref()
            .or(response.detail.as_deref())
            .filter(|error| !error.trim().is_empty())
        {
            bail!("OTX: {}", compact_external_error(error));
        }
        if let Some(returned_page) = response.page_num
            && returned_page != requested_page
        {
            bail!("OTX returned page {returned_page} for request {requested_page}");
        }
        if let Some(limit) = response.limit
            && limit == 0
        {
            bail!("OTX returned an invalid zero page limit");
        }

        let raw_count = response.passive_dns.len();
        let fingerprint = response
            .passive_dns
            .iter()
            .map(|record| record.hostname.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if response.has_next && raw_count == 0 {
            bail!("OTX returned an empty page while has_next was true");
        }
        if !fingerprint.is_empty() && !seen_pages.insert(fingerprint) {
            bail!("OTX returned a repeated pagination page");
        }
        raw_records_seen = raw_records_seen.saturating_add(raw_count);
        commit_result_page(
            &mut names,
            normalize_many(
                response
                    .passive_dns
                    .iter()
                    .map(|record| record.hostname.as_str()),
                domain,
            ),
        );

        let reported_total = response.full_size.or(response.actual_size);
        if !response.has_next {
            if reported_total.is_some_and(|total| total > raw_records_seen) {
                bail!(
                    "OTX returned a partial result: {raw_records_seen}/{} records",
                    reported_total.unwrap_or(raw_records_seen)
                );
            }
            return Ok(names);
        }
        if requested_page == OTX_MAX_PAGES {
            bail!("OTX pagination limit reached while has_next remained true");
        }
    }

    Ok(names)
}

pub(super) async fn shodan(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("shodan")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for page in 1..=1_000 {
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
        if page == 1_000 {
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
    fn code_search_decodes_only_hostname_safe_percent_sequences_with_a_bound() {
        let encoded = "api%2Edev%2Dblue%2Eexample%2Ecom+mail%2eexample%2ecom/path%2Fignored";
        let decoded = percent_decode_hostname_sequences(encoded, encoded.len());
        assert_eq!(
            decoded,
            "api.dev-blue.example.com+mail.example.com/path%2Fignored"
        );
        assert!(decoded.contains('+'));
        assert_eq!(
            extract_from_code_text(encoded, "example.com"),
            BTreeSet::from([
                "api.dev-blue.example.com".to_owned(),
                "mail.example.com".to_owned()
            ])
        );

        let bounded = percent_decode_hostname_sequences("ééapi%2Eexample%2Ecom", 5);
        assert_eq!(bounded, "ééa");
        assert!(bounded.len() <= 5);
    }

    #[test]
    fn github_token_rotation_is_finite_and_classifies_quota_responses() {
        assert_eq!(
            rotate_tokens_to_preferred(
                vec![
                    "token-a".to_owned(),
                    "token-b".to_owned(),
                    "token-c".to_owned()
                ],
                "token-b"
            ),
            vec!["token-b", "token-c", "token-a"]
        );
        assert!(github_token_rejected(
            reqwest::StatusCode::UNAUTHORIZED,
            false,
            b""
        ));
        assert!(github_token_rejected(
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            false,
            br#"{"message":"API rate limit exceeded"}"#
        ));
        assert!(github_token_rejected(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            true,
            b""
        ));
        assert!(!github_token_rejected(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            false,
            b"temporary outage"
        ));

        let quota =
            github_tokens_exhausted_message(3, Some(reqwest::StatusCode::TOO_MANY_REQUESTS), true);
        assert!(quota.contains("quota"));
        assert!(quota.contains("3 jeton(s)"));
        let authentication =
            github_tokens_exhausted_message(2, Some(reqwest::StatusCode::UNAUTHORIZED), false);
        assert!(authentication.contains("authentification refusée"));
        assert!(!authentication.contains("quota"));
    }

    #[test]
    fn partial_content_failures_are_bounded_and_reported_only_after_successes() {
        let mut failures = PartialFailureSummary::default();
        failures.record("first raw failure");
        for index in 0..20 {
            failures.record(format!("raw failure {index}"));
        }
        assert_eq!(failures.count, 21);
        assert_eq!(failures.examples.len(), PARTIAL_FAILURE_EXAMPLE_LIMIT);
        assert!(failures.detail().contains("premier: first raw failure"));

        let names = BTreeSet::from(["api.example.com".to_owned()]);
        let error = finish_code_search("Code Search", names, &failures)
            .unwrap_err()
            .to_string();
        assert!(error.contains("résultats partiels"));
        assert!(error.contains("21 échec(s)"));

        let names = BTreeSet::from(["api.example.com".to_owned()]);
        assert_eq!(
            finish_code_search(
                "Code Search",
                names.clone(),
                &PartialFailureSummary::default()
            )
            .unwrap(),
            names
        );
    }

    #[test]
    fn circl_stream_reassembles_fragmented_lines_and_checkpoints_each_chunk() {
        let limits = CirclStreamLimits {
            max_bytes: 1_024,
            max_line_bytes: 128,
            max_nonempty_lines: 10,
            checkpoint_every: 10,
        };
        let mut decoder = CirclStreamDecoder::new("example.com", limits);
        decoder.push_chunk(br#"{"rrname":"api.ex"#).unwrap();
        assert!(decoder.names.is_empty());
        decoder
            .push_chunk(b"ample.com\"}\r\nmail.example.")
            .unwrap();
        assert!(decoder.names.contains("api.example.com"));
        decoder.push_chunk(b"com\n\n   \n").unwrap();
        assert!(decoder.names.contains("mail.example.com"));
        let names = decoder.finish().unwrap();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn circl_stream_detects_truncated_structured_records_after_checkpointing() {
        let limits = CirclStreamLimits {
            max_bytes: 1_024,
            max_line_bytes: 256,
            max_nonempty_lines: 10,
            checkpoint_every: 1_000,
        };
        let mut decoder = CirclStreamDecoder::new("example.com", limits);
        decoder
            .push_chunk(b"{\"rrname\":\"api.example.com\"}\n{\"rrname\":\"broken.example.com\"")
            .unwrap();
        assert!(decoder.names.contains("api.example.com"));
        let error = decoder.finish().unwrap_err().to_string();
        assert!(error.contains("final tronqué"));
    }

    #[test]
    fn circl_stream_limits_preserve_previously_committed_results() {
        let line_limits = CirclStreamLimits {
            max_bytes: 1_024,
            max_line_bytes: 16,
            max_nonempty_lines: 10,
            checkpoint_every: 1_000,
        };
        let mut decoder = CirclStreamDecoder::new("example.com", line_limits);
        decoder.push_chunk(b"a.example.com\n").unwrap();
        let error = decoder.push_chunk(&[b'x'; 17]).unwrap_err().to_string();
        assert!(error.contains("ligne supérieure"));
        assert!(decoder.names.contains("a.example.com"));

        let count_limits = CirclStreamLimits {
            max_bytes: 1_024,
            max_line_bytes: 64,
            max_nonempty_lines: 2,
            checkpoint_every: 1_000,
        };
        let mut decoder = CirclStreamDecoder::new("example.com", count_limits);
        let error = decoder
            .push_chunk(b"a.example.com\n\n b.example.com\n   \nc.example.com\n")
            .unwrap_err()
            .to_string();
        assert!(error.contains("plus de 2 lignes non vides"));
        assert_eq!(decoder.names.len(), 2);

        let byte_limits = CirclStreamLimits {
            max_bytes: 16,
            max_line_bytes: 64,
            max_nonempty_lines: 10,
            checkpoint_every: 1_000,
        };
        let mut decoder = CirclStreamDecoder::new("example.com", byte_limits);
        decoder.push_chunk(b"a.example.com\n").unwrap();
        let error = decoder.push_chunk(b"overflow").unwrap_err().to_string();
        assert!(error.contains("flux supérieur"));
        assert!(decoder.names.contains("a.example.com"));

        assert_eq!(CIRCL_MAX_STREAM_BYTES, 128 * 1024 * 1024);
        assert_eq!(CIRCL_MAX_LINE_BYTES, 64 * 1024);
        assert_eq!(CIRCL_MAX_LINES, 100_000);
    }

    #[test]
    fn otx_authentication_uses_the_documented_header() {
        let request = otx_request(
            &client(Duration::from_secs(1)).unwrap(),
            "https://otx.example.test/api",
            Some("secret-test"),
            3,
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
        assert_eq!(
            request.url().query_pairs().collect::<Vec<_>>(),
            vec![("limit".into(), "50".into()), ("page".into(), "3".into())]
        );

        let empty: OtxResponse = serde_json::from_str(r#"{"error":""}"#).unwrap();
        assert!(empty.passive_dns.is_empty());
        assert_eq!(empty.error.as_deref(), Some(""));
        assert!(empty.detail.is_none());

        let detailed: OtxResponse =
            serde_json::from_str(r#"{"detail":"authentication failed"}"#).unwrap();
        assert_eq!(detailed.detail.as_deref(), Some("authentication failed"));

        let paged: OtxResponse = serde_json::from_str(
            r#"{"has_next":true,"page_num":2,"limit":50,"actual_size":50,"full_size":125,"passive_dns":[{"hostname":"api.example.com"}]}"#,
        )
        .unwrap();
        assert!(paged.has_next);
        assert_eq!(paged.page_num, Some(2));
        assert_eq!(paged.full_size, Some(125));
    }

    #[test]
    fn postman_contract_supports_public_and_authenticated_searches() {
        let response: PostmanSearchResponse = serde_json::from_str(include_str!(
            "../../tests/fixtures/postman-search-page.json"
        ))
        .unwrap();
        assert_eq!(
            response.meta.next_cursor.as_deref(),
            Some("next-page-token")
        );
        assert_eq!(response.meta.total, Some(2));
        assert_eq!(
            postman_page_names(&response.data, "example.com"),
            BTreeSet::from([
                "api.example.com".to_owned(),
                "cdn.example.com".to_owned(),
                "mail.dev.example.com".to_owned(),
            ])
        );

        let http = client(Duration::from_secs(1)).unwrap();
        let public = postman_search_request(&http, "example.com", None, None)
            .build()
            .unwrap();
        assert_eq!(public.method(), reqwest::Method::POST);
        assert_eq!(public.url().host_str(), Some("api.postman.com"));
        assert_eq!(public.url().path(), "/search");
        assert_eq!(public.url().query(), Some("limit=25"));
        assert!(!public.headers().contains_key("x-api-key"));
        assert_eq!(
            public
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let body: Value =
            serde_json::from_slice(public.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body["elementType"], "requests");
        assert_eq!(body["q"], "example.com");
        assert_eq!(body["ownership"], "all");
        assert_eq!(body["filters"]["$and"][0]["visibility"]["$eq"], "public");

        let authenticated = postman_search_request(
            &http,
            "example.com",
            Some("next-page-token"),
            Some("secret"),
        )
        .build()
        .unwrap();
        let query = authenticated
            .url()
            .query_pairs()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("limit").map(|value| value.as_ref()), Some("25"));
        assert_eq!(
            query.get("cursor").map(|value| value.as_ref()),
            Some("next-page-token")
        );
        assert_eq!(authenticated.headers().get("x-api-key").unwrap(), "secret");
        assert!(!authenticated.url().as_str().contains("secret"));
        assert!(
            !authenticated
                .body()
                .unwrap()
                .as_bytes()
                .unwrap()
                .windows(b"secret".len())
                .any(|window| window == b"secret")
        );
    }

    #[test]
    fn postman_cursor_and_total_validation_are_bounded_and_stable() {
        assert_eq!(
            postman_next_cursor(Some(" cursor-1 ".to_owned())).unwrap(),
            Some("cursor-1".to_owned())
        );
        assert_eq!(postman_next_cursor(Some(String::new())).unwrap(), None);
        assert!(postman_next_cursor(Some("x".repeat(POSTMAN_CURSOR_MAX_BYTES + 1))).is_err());
        assert!(postman_next_cursor(Some("bad\ncursor".to_owned())).is_err());
        assert_eq!(postman_reported_total(None, Some(10)).unwrap(), Some(10));
        assert_eq!(postman_reported_total(Some(10), None).unwrap(), Some(10));
        assert!(postman_reported_total(Some(10), Some(11)).is_err());
        assert!(postman_reported_total(Some(10), Some(9)).is_err());
        assert_eq!(POSTMAN_PAGE_SIZE, 25);
        assert_eq!(POSTMAN_MAX_PAGES, 100);
    }

    #[test]
    fn postman_page_fingerprint_ignores_result_and_object_key_order() {
        let first = vec![
            json!({"id": "one", "request": {"url": "https://api.example.com", "method": "GET"}}),
            json!({"id": "two", "request": {"url": "https://cdn.example.com", "method": "HEAD"}}),
        ];
        let second: Vec<Value> = serde_json::from_str(
            r#"[
                {"request":{"method":"HEAD","url":"https://cdn.example.com"},"id":"two"},
                {"request":{"method":"GET","url":"https://api.example.com"},"id":"one"}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            postman_page_fingerprint(&first).unwrap(),
            postman_page_fingerprint(&second).unwrap()
        );
    }

    #[test]
    fn intelx_contract_uses_header_auth_and_rejects_error_statuses() {
        let http = client(Duration::from_secs(1)).unwrap();
        let request = intelx_search_request(&http, "2.intelx.io", "secret-test", "example.com")
            .build()
            .unwrap();
        assert_eq!(request.url().path(), "/phonebook/search");
        assert!(request.url().query().is_none());
        assert_eq!(request.headers().get("X-Key").unwrap(), "secret-test");

        let result = intelx_result_request(
            &http,
            "2.intelx.io",
            "secret-test",
            "61202067-543e-4e6a-8c23-11f9b8f008cf",
        )
        .build()
        .unwrap();
        assert_eq!(result.headers().get("X-Key").unwrap(), "secret-test");
        assert!(
            !result
                .url()
                .query()
                .unwrap_or_default()
                .contains("secret-test")
        );
        assert!(
            result
                .url()
                .query()
                .unwrap_or_default()
                .contains("limit=10000")
        );

        let success = IntelxSearchResponse {
            id: Some("search-id".to_owned()),
            status: 0,
        };
        assert_eq!(intelx_search_id(&success).unwrap(), "search-id");
        assert!(
            intelx_search_id(&IntelxSearchResponse {
                id: None,
                status: 0
            })
            .is_err()
        );
        assert!(
            intelx_search_id(&IntelxSearchResponse {
                id: None,
                status: 1
            })
            .is_err()
        );
        assert!(
            intelx_search_id(&IntelxSearchResponse {
                id: None,
                status: 2
            })
            .is_err()
        );
        assert!(!intelx_result_complete(0).unwrap());
        assert!(intelx_result_complete(1).unwrap());
        assert!(intelx_result_complete(2).is_err());
        assert!(intelx_result_complete(4).is_err());
    }

    #[test]
    fn censys_platform_credentials_and_request_follow_the_v3_contract() {
        let credential = parse_censys_credential("pat-token:organization-id").unwrap();
        assert_eq!(
            credential,
            CensysCredential::Platform {
                pat: "pat-token".to_owned(),
                organization_id: Some("organization-id".to_owned()),
                legacy_fallback: Some(("pat-token".to_owned(), "organization-id".to_owned())),
            }
        );
        let request = censys_platform_request(
            &client(Duration::from_secs(1)).unwrap(),
            "example.com",
            &credential,
            Some("cursor-1"),
        )
        .unwrap()
        .build()
        .unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().host_str(), Some("api.platform.censys.io"));
        assert_eq!(request.url().path(), "/v3/global/search/query");
        assert_eq!(
            request
                .headers()
                .get("Authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer pat-token")
        );
        assert_eq!(
            request
                .headers()
                .get("X-Organization-ID")
                .and_then(|value| value.to_str().ok()),
            Some("organization-id")
        );
        let body: Value =
            serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body["query"], "cert.names: example.com");
        assert_eq!(body["fields"], serde_json::json!(["cert.names"]));
        assert_eq!(body["page_size"], 100);
        assert_eq!(body["page_token"], "cursor-1");
        assert!(body.get("cursor").is_none());
    }

    #[test]
    fn builtwith_request_uses_the_current_domain_api_contract() {
        let request = builtwith_request(
            &client(Duration::from_secs(1)).unwrap(),
            "example.com",
            "secret",
        )
        .build()
        .unwrap();
        assert_eq!(request.url().path(), "/v23/api.json");
        let query = request.url().query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(
            query.get("LOOKUP").map(|value| value.as_ref()),
            Some("example.com")
        );
        assert!(!query.contains_key("NOLIVE"));
    }

    #[test]
    fn censys_supports_pat_only_explicit_platform_and_legacy_credentials() {
        let pat_only = parse_censys_credential("pat-only").unwrap();
        assert_eq!(
            pat_only,
            CensysCredential::Platform {
                pat: "pat-only".to_owned(),
                organization_id: None,
                legacy_fallback: None,
            }
        );
        assert_eq!(
            parse_censys_credential("platform:pat-token:org-id").unwrap(),
            CensysCredential::Platform {
                pat: "pat-token".to_owned(),
                organization_id: Some("org-id".to_owned()),
                legacy_fallback: None,
            }
        );
        assert_eq!(
            parse_censys_credential("legacy:api-id:api-secret").unwrap(),
            CensysCredential::Legacy {
                identifier: "api-id".to_owned(),
                secret: "api-secret".to_owned(),
            }
        );
        assert!(parse_censys_credential("platform:pat-token:").is_err());

        let http = client(Duration::from_secs(1)).unwrap();
        let platform_request = censys_platform_request(&http, "example.com", &pat_only, None)
            .unwrap()
            .build()
            .unwrap();
        assert!(!platform_request.headers().contains_key("X-Organization-ID"));
        let legacy_request = censys_legacy_request(
            &http,
            "example.com",
            "api-id",
            "api-secret",
            Some("legacy-cursor"),
        )
        .build()
        .unwrap();
        assert_eq!(legacy_request.method(), reqwest::Method::GET);
        assert_eq!(legacy_request.url().host_str(), Some("search.censys.io"));
        assert_eq!(legacy_request.url().path(), "/api/v2/certificates/search");
        assert!(
            legacy_request
                .headers()
                .get("Authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Basic "))
        );
        let legacy_query = legacy_request
            .url()
            .query_pairs()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            legacy_query.get("cursor").map(|value| value.as_ref()),
            Some("legacy-cursor")
        );
    }

    #[test]
    fn censys_platform_fixture_is_scoped_and_cursor_progress_is_bounded() {
        let page: CensysPlatformResponse = serde_json::from_str(include_str!(
            "../../tests/fixtures/censys-platform-v3-page.json"
        ))
        .unwrap();
        assert_eq!(
            censys_platform_page_names(&page, "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
        );
        let mut seen = BTreeSet::new();
        assert_eq!(
            checked_censys_cursor(page.result.next_page_token.as_deref(), &mut seen).unwrap(),
            Some("cursor-2".to_owned())
        );
        assert!(checked_censys_cursor(Some("cursor-3"), &mut seen).is_ok());
        assert!(checked_censys_cursor(Some("cursor-2"), &mut seen).is_err());
        assert!(
            checked_censys_cursor(
                Some(&"x".repeat(CENSYS_MAX_CURSOR_BYTES + 1)),
                &mut BTreeSet::new()
            )
            .is_err()
        );
    }

    #[test]
    fn driftnet_requests_all_four_upstream_summary_families() {
        assert_eq!(DRIFTNET_ENDPOINTS.len(), 4);
        assert_eq!(DRIFTNET_CONCURRENCY, DRIFTNET_ENDPOINTS.len());
        let http = client(Duration::from_secs(1)).unwrap();
        let expected = [
            ("/v1/ct/log", "field", "host:example.com", "cert-dns-name"),
            (
                "/v1/scan/protocols",
                "field",
                "host:example.com",
                "cert-dns-name",
            ),
            (
                "/v1/scan/domains",
                "field",
                "host:example.com",
                "cert-dns-name",
            ),
            ("/v1/domain/rdns", "host", "example.com", "dns-ptr"),
        ];
        for (endpoint, expected) in DRIFTNET_ENDPOINTS.into_iter().zip(expected) {
            let request = driftnet_request(&http, "example.com", endpoint, "driftnet-token")
                .build()
                .unwrap();
            assert_eq!(request.url().host_str(), Some("api.driftnet.io"));
            assert_eq!(request.url().path(), expected.0);
            assert_eq!(
                request
                    .headers()
                    .get("Authorization")
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer driftnet-token")
            );
            let query = request.url().query_pairs().collect::<BTreeMap<_, _>>();
            assert_eq!(
                query.get(expected.1).map(|value| value.as_ref()),
                Some(expected.2)
            );
            assert_eq!(
                query.get("summarize").map(|value| value.as_ref()),
                Some("host")
            );
            assert_eq!(
                query.get("summary_context").map(|value| value.as_ref()),
                Some(expected.3)
            );
            assert_eq!(
                query.get("summary_limit").map(|value| value.as_ref()),
                Some("10000")
            );
        }
    }

    #[test]
    fn driftnet_summary_fixture_extracts_only_normalized_in_scope_names() {
        let response: DriftnetSummaryResponse =
            serde_json::from_str(include_str!("../../tests/fixtures/driftnet-summary.json"))
                .unwrap();
        assert_eq!(response.summary.other, 0);
        assert_eq!(
            driftnet_summary_names(&response, "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
        );
        assert!(serde_json::from_value::<DriftnetSummaryResponse>(serde_json::json!({})).is_err());
    }

    #[test]
    fn driftnet_errors_remain_bounded_and_specific() {
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
            BTreeSet::from(["www.example.com".to_owned()])
        );
    }

    #[test]
    fn merklemap_contract_fixture_handles_wildcards_and_scope() {
        let page: MerkleMapSearchPage =
            serde_json::from_str(include_str!("../../tests/fixtures/merklemap-page.json")).unwrap();
        assert_eq!(page.count, 125);
        assert_eq!(
            merklemap_page_names(&page, "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
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
    fn code_search_pagination_and_content_urls_are_vendor_pinned() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            reqwest::header::HeaderValue::from_static(
                "<https://api.github.com/search/code?q=example.com&page=2>; rel=\"next\", <https://api.github.com/search/code?q=example.com&page=10>; rel=\"last\"",
            ),
        );
        assert_eq!(
            next_link(&headers).unwrap().as_deref(),
            Some("https://api.github.com/search/code?q=example.com&page=2")
        );
        assert_eq!(
            github_content_url(
                "https://api.github.com/repositories/42/contents/config/app.txt?ref=main"
            )
            .unwrap()
            .as_str(),
            "https://api.github.com/repositories/42/contents/config/app.txt?ref=main"
        );
        assert!(github_content_url("https://attacker.test/repositories/42/contents/x").is_err());
        assert!(
            github_content_url("https://api.github.com/repositories/42/contents/x?token=bad")
                .is_err()
        );

        let item = GitlabSearchItem {
            data: String::new(),
            project_id: 42,
            path: "config/app file.txt".to_owned(),
            reference: "main".to_owned(),
        };
        let raw = gitlab_raw_url(&item).unwrap();
        assert_eq!(raw.host_str(), Some("gitlab.com"));
        assert!(
            raw.path()
                .starts_with("/api/v4/projects/42/repository/files/")
        );
        assert!(
            raw.query_pairs()
                .any(|pair| pair.0 == "ref" && pair.1 == "main")
        );
    }

    #[test]
    fn targeted_connector_requests_follow_provider_contracts() {
        assert_eq!(BRAVE_MAX_PAGES, 10);
        assert_eq!(MERKLEMAP_MAX_PAGES, 1_000);
        let http = client(Duration::from_secs(1)).unwrap();

        let brave = brave_request(&http, "example.com", 9, "brave-key")
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
        assert!(brave_query.contains(&("offset".into(), "9".into())));
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

        let empty_driftnet_summary: DriftnetSummaryResponse =
            serde_json::from_value(serde_json::json!({"summary": {}})).unwrap();
        assert!(empty_driftnet_summary.summary.values.is_empty());
        assert_eq!(empty_driftnet_summary.summary.other, 0);

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
