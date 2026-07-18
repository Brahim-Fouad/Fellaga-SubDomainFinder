use super::{
    ApiKeyStore, client, commit_result_page, compact_external_error, hostname_from_url,
    response_bytes_limited, response_json, send_external, send_external_streaming,
};
use crate::util::{extract_observed_names, normalize_observed_name, valid_fqdn};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;
use url::Url;

const MAX_PAGES: usize = 1_000;
const MAX_ROBTEX_REVERSE_IPS: usize = 1_000;
const MAX_STREAM_BYTES: usize = 128 * 1024 * 1024;
const MAX_STREAM_LINE_BYTES: usize = 64 * 1024;
const STREAM_COMMIT_BATCH: usize = 1_000;

fn names_from_text(text: &str, domain: &str) -> BTreeSet<String> {
    extract_observed_names(text, domain)
}

fn names_from_values<I, S>(values: I, domain: &str) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    values
        .into_iter()
        .flat_map(|value| names_from_text(value.as_ref(), domain))
        .collect()
}

async fn for_each_stream_line<F>(
    mut response: reqwest::Response,
    source: &str,
    mut visit: F,
) -> Result<()>
where
    // `None` marks a completed transport chunk. Callers use it to commit
    // decoded records before the next await point, making timeout cancellation
    // preserve every complete line received so far.
    F: FnMut(Option<&[u8]>) -> Result<()>,
{
    if !response.status().is_success() {
        let status = response.status();
        let (_, body) = response_bytes_limited(response, source).await?;
        bail!(
            "{source}: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }

    let mut bytes_seen = 0_usize;
    let mut carry = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("{source}: interrupted stream"))?
    {
        bytes_seen = bytes_seen
            .checked_add(chunk.len())
            .with_context(|| format!("{source}: response byte counter overflow"))?;
        if bytes_seen > MAX_STREAM_BYTES {
            visit(None)?;
            bail!(
                "{source}: stream exceeded the {} MiB budget after committed batches",
                MAX_STREAM_BYTES / 1024 / 1024
            );
        }
        let mut offset = 0_usize;
        while offset < chunk.len() {
            let remaining = &chunk[offset..];
            let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') else {
                let pending = carry
                    .len()
                    .checked_add(remaining.len())
                    .with_context(|| format!("{source}: record length overflow"))?;
                if pending > MAX_STREAM_LINE_BYTES {
                    visit(None)?;
                    bail!("{source}: record exceeds {MAX_STREAM_LINE_BYTES} bytes");
                }
                carry.extend_from_slice(remaining);
                break;
            };
            let segment = &remaining[..newline];
            let line_length = carry
                .len()
                .checked_add(segment.len())
                .with_context(|| format!("{source}: record length overflow"))?;
            if line_length > MAX_STREAM_LINE_BYTES {
                visit(None)?;
                bail!("{source}: record exceeds {MAX_STREAM_LINE_BYTES} bytes");
            }
            carry.extend_from_slice(segment);
            let line = carry.strip_suffix(b"\r").unwrap_or(&carry);
            if let Err(error) = visit(Some(line)) {
                let _ = visit(None);
                return Err(error);
            }
            carry.clear();
            offset = offset.saturating_add(newline).saturating_add(1);
        }
        visit(None)?;
    }
    if !carry.is_empty()
        && let Err(error) = visit(Some(&carry))
    {
        let _ = visit(None);
        return Err(error);
    }
    visit(None)?;
    Ok(())
}

fn normalize_host_or_url(value: &str, domain: &str) -> Option<String> {
    normalize_observed_name(value, domain)
        .or_else(|| hostname_from_url(value, domain))
        .or_else(|| {
            Url::parse(&format!("http://{}", value.trim()))
                .ok()
                .and_then(|url| url.host_str().map(ToOwned::to_owned))
                .and_then(|host| normalize_observed_name(&host, domain))
        })
}

fn split_key<'a>(source: &str, value: &'a str) -> Result<(&'a str, &'a str)> {
    let (left, right) = value
        .split_once(':')
        .with_context(|| format!("{source}: credential must contain two colon-separated fields"))?;
    let left = left.trim();
    let right = right.trim();
    if left.is_empty() || right.is_empty() || right.contains(':') {
        bail!("{source}: credential contains an empty or unexpected field");
    }
    Ok((left, right))
}

fn split_endpoint_key(value: &str) -> Result<(Url, &str)> {
    let (endpoint, token) = value
        .rsplit_once(':')
        .context("redhuntlabs: credential must be HTTPS_ENDPOINT:API_KEY")?;
    let endpoint = Url::parse(endpoint.trim()).context("redhuntlabs: invalid endpoint URL")?;
    let token = token.trim();
    let host = endpoint
        .host_str()
        .context("redhuntlabs: endpoint has no host")?;
    let trusted_host = host.eq_ignore_ascii_case("redhuntlabs.com")
        || host.to_ascii_lowercase().ends_with(".redhuntlabs.com");
    if endpoint.scheme() != "https"
        || endpoint.port_or_known_default() != Some(443)
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok()
        || !trusted_host
        || token.is_empty()
    {
        bail!(
            "redhuntlabs: endpoint must be a public HTTPS hostname and API key must be non-empty"
        );
    }
    Ok((endpoint, token))
}

fn validate_api_suffix(source: &str, value: &str) -> Result<String> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if !valid_fqdn(&host)
        || host.parse::<IpAddr>().is_ok()
        || host.eq_ignore_ascii_case("localhost")
        || host.starts_with("api.")
        || !matches!(host.as_str(), "zoomeye.org" | "zoomeye.hk")
    {
        bail!("{source}: API host suffix is invalid");
    }
    Ok(host)
}

fn flexible_usize(value: Option<&Value>, source: &str, field: &str) -> Result<usize> {
    let value = value.with_context(|| format!("{source}: missing {field}"))?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .with_context(|| format!("{source}: invalid {field}")),
        Value::String(number) => number
            .parse::<usize>()
            .with_context(|| format!("{source}: invalid {field}")),
        _ => bail!("{source}: invalid {field}"),
    }
}

fn page_count(total: usize, size: usize) -> Result<usize> {
    if size == 0 {
        bail!("provider returned a zero page size");
    }
    Ok(total.saturating_add(size - 1) / size)
}

#[derive(Deserialize)]
struct BufferOverResponse {
    #[serde(rename = "Meta")]
    meta: BufferOverMeta,
    #[serde(rename = "FDNS_A", default)]
    fdns_a: Vec<String>,
    #[serde(rename = "RDNS", default)]
    rdns: Vec<String>,
    #[serde(rename = "Results", default)]
    results: Vec<String>,
}

#[derive(Deserialize)]
struct BufferOverMeta {
    #[serde(rename = "Errors", default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct C99Response {
    success: bool,
    subdomains: Vec<C99Entry>,
    #[serde(default)]
    error: String,
}

#[derive(Deserialize)]
struct C99Entry {
    subdomain: String,
}

#[derive(Deserialize)]
struct DigitalYamaResponse {
    subdomains: Vec<String>,
}

#[derive(Deserialize)]
struct DnsDumpsterResponse {
    a: Vec<DnsDumpsterRecord>,
    ns: Vec<DnsDumpsterRecord>,
}

#[derive(Deserialize)]
struct DnsDumpsterRecord {
    host: String,
}

#[derive(Deserialize)]
struct DomainsProjectResponse {
    domains: Vec<String>,
    #[serde(default)]
    error: String,
}

#[derive(Deserialize)]
struct FofaResponse {
    error: bool,
    #[serde(default)]
    errmsg: String,
    results: Vec<String>,
}

#[derive(Deserialize)]
struct DnsDbRateResponse {
    rate: DnsDbRate,
}

#[derive(Deserialize)]
struct DnsDbRate {
    offset_max: Value,
}

#[derive(Deserialize)]
struct DnsDbSafRecord {
    #[serde(rename = "cond", default)]
    condition: String,
    #[serde(default)]
    obj: Option<DnsDbObject>,
    #[serde(default)]
    msg: String,
}

#[derive(Deserialize)]
struct DnsDbObject {
    #[serde(default)]
    rrname: String,
}

#[derive(Deserialize)]
struct OnypheResponse {
    results: Vec<Value>,
    page: Value,
    max_page: Value,
}

#[derive(Deserialize)]
struct PugReconResponse {
    results: Vec<PugReconResult>,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct PugReconResult {
    name: String,
}

#[derive(Deserialize)]
struct QuakeResponse {
    code: i64,
    #[serde(default)]
    message: String,
    data: Vec<QuakeEntry>,
    meta: QuakeMeta,
}

#[derive(Deserialize)]
struct QuakeEntry {
    service: QuakeService,
}

#[derive(Deserialize)]
struct QuakeService {
    http: QuakeHttp,
}

#[derive(Deserialize)]
struct QuakeHttp {
    #[serde(default)]
    host: String,
}

#[derive(Deserialize)]
struct QuakeMeta {
    pagination: QuakePagination,
}

#[derive(Deserialize)]
struct QuakePagination {
    total: usize,
}

#[derive(Deserialize)]
struct RedHuntResponse {
    subdomains: Vec<String>,
    metadata: RedHuntMetadata,
}

#[derive(Deserialize)]
struct RedHuntMetadata {
    result_count: usize,
    page_size: usize,
    page_number: usize,
}

#[derive(Deserialize)]
struct RseCloudResponse {
    data: Vec<String>,
    page: usize,
    #[serde(rename = "pagesize")]
    page_size: usize,
    total_pages: usize,
}

#[derive(Deserialize)]
struct ThreatBookResponse {
    response_code: i64,
    #[serde(default)]
    verbose_msg: String,
    data: ThreatBookData,
}

#[derive(Deserialize)]
struct ThreatBookData {
    sub_domains: ThreatBookSubdomains,
}

#[derive(Deserialize)]
struct ThreatBookSubdomains {
    total: String,
    data: Vec<String>,
}

#[derive(Deserialize)]
struct WindvaneResponse {
    code: i64,
    #[serde(default)]
    msg: String,
    data: WindvaneData,
}

#[derive(Deserialize)]
struct WindvaneData {
    list: Vec<WindvaneEntry>,
    page_response: WindvanePage,
}

#[derive(Deserialize)]
struct WindvaneEntry {
    domain: String,
}

#[derive(Deserialize)]
struct WindvanePage {
    total: String,
    count: String,
    total_page: String,
}

#[derive(Deserialize)]
struct ZoomEyeResponse {
    status: i64,
    total: usize,
    list: Vec<ZoomEyeEntry>,
}

#[derive(Deserialize)]
struct ZoomEyeEntry {
    name: String,
}

#[derive(Deserialize)]
struct RobtexRecord {
    #[serde(default)]
    rrname: String,
    #[serde(default)]
    rrdata: String,
    #[serde(default)]
    rrtype: String,
}

async fn visit_robtex_records<F>(
    http: &reqwest::Client,
    endpoint: String,
    token: &str,
    domain: &str,
    mut visit: F,
) -> Result<()>
where
    F: FnMut(Option<RobtexRecord>) -> Result<()>,
{
    let response = send_external_streaming("robtex", robtex_request(http, endpoint, token), domain)
        .await
        .context("connection to Robtex")?;
    for_each_stream_line(response, "Robtex", |line| {
        let Some(line) = line else {
            return visit(None);
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let record = serde_json::from_slice(line).context("Robtex: invalid NDJSON record")?;
        visit(Some(record))
    })
    .await
}

fn robtex_request(
    http: &reqwest::Client,
    endpoint: String,
    token: &str,
) -> reqwest::RequestBuilder {
    http.get(endpoint)
        .query(&[("key", token)])
        .header("Accept", "application/x-ndjson")
}

#[cfg(test)]
fn parse_robtex_records(body: &str) -> Result<Vec<RobtexRecord>> {
    let mut records = Vec::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        records.push(serde_json::from_str(line).context("Robtex: invalid NDJSON record")?);
    }
    Ok(records)
}

pub(super) async fn bufferover(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("bufferover")?;
    let response = send_external(
        "bufferover",
        client(timeout)?
            .get("https://tls.bufferover.run/dns")
            .query(&[("q", format!(".{domain}"))])
            .header("x-api-key", token),
        domain,
    )
    .await
    .context("connection to BufferOver")?;
    let response = response_json::<BufferOverResponse>(response, "BufferOver").await?;
    if !response.meta.errors.is_empty() {
        bail!("BufferOver: {}", response.meta.errors.join(", "));
    }
    let values = if response.fdns_a.is_empty() {
        response.results
    } else {
        response.fdns_a.into_iter().chain(response.rdns).collect()
    };
    Ok(names_from_values(values, domain))
}

pub(super) async fn c99(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("c99")?;
    let response = send_external(
        "c99",
        client(timeout)?
            .get("https://api.c99.nl/subdomainfinder")
            .query(&[("key", token.as_str()), ("domain", domain), ("json", "")]),
        domain,
    )
    .await
    .context("connection to C99")?;
    let response = response_json::<C99Response>(response, "C99").await?;
    if !response.error.is_empty() {
        bail!("C99: {}", response.error);
    }
    if !response.success && response.subdomains.is_empty() {
        bail!("C99 reported an unsuccessful lookup");
    }
    Ok(response
        .subdomains
        .into_iter()
        .filter_map(|entry| normalize_observed_name(&entry.subdomain, domain))
        .collect())
}

pub(super) async fn chinaz(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("chinaz")?;
    let response = send_external(
        "chinaz",
        client(timeout)?
            .get("https://apidatav2.chinaz.com/single/alexa")
            .query(&[("key", token.as_str()), ("domain", domain)]),
        domain,
    )
    .await
    .context("connection to Chinaz")?;
    let response = response_json::<Value>(response, "Chinaz").await?;
    let entries = response
        .pointer("/Result/ContributingSubdomainList")
        .and_then(Value::as_array)
        .context("Chinaz: missing Result.ContributingSubdomainList array")?;
    Ok(entries
        .iter()
        .map(|entry| {
            entry
                .get("DataUrl")
                .and_then(Value::as_str)
                .context("Chinaz: ContributingSubdomainList item has no DataUrl")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|value| normalize_host_or_url(value, domain))
        .collect())
}

pub(super) async fn digitalyama(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("digitalyama")?;
    let response = send_external(
        "digitalyama",
        client(timeout)?
            .get("https://api.digitalyama.com/subdomain_finder")
            .query(&[("domain", domain)])
            .header("x-api-key", token),
        domain,
    )
    .await
    .context("connection to DigitalYama")?;
    let response = response_json::<DigitalYamaResponse>(response, "DigitalYama").await?;
    Ok(names_from_values(response.subdomains, domain))
}

pub(super) async fn dnsdb(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("dnsdb")?;
    let http = client(timeout)?;
    let rate_response = send_external(
        "dnsdb",
        http.get("https://api.dnsdb.info/dnsdb/v2/rate_limit")
            .header("X-API-KEY", &token)
            .header("Accept", "application/json"),
        domain,
    )
    .await
    .context("connection to DNSDB rate-limit endpoint")?;
    let rate = response_json::<DnsDbRateResponse>(rate_response, "DNSDB rate limit").await?;
    let offset_max = match &rate.rate.offset_max {
        Value::String(value) if value.eq_ignore_ascii_case("n/a") => None,
        Value::String(value) => Some(
            value
                .parse::<usize>()
                .context("DNSDB: invalid rate.offset_max")?,
        ),
        Value::Number(value) => Some(
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .context("DNSDB: invalid rate.offset_max")?,
        ),
        _ => bail!("DNSDB: invalid rate.offset_max"),
    };

    let mut names = BTreeSet::new();
    let mut offset = 0_usize;
    for page_index in 0..MAX_PAGES {
        let mut query = vec![
            ("limit", "0".to_owned()),
            ("swclient", "fellaga".to_owned()),
        ];
        if offset > 0 {
            query.push(("offset", offset.to_string()));
        }
        let response = send_external_streaming(
            "dnsdb",
            http.get(format!(
                "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.{domain}"
            ))
            .query(&query)
            .header("X-API-KEY", &token)
            .header("Accept", "application/x-ndjson"),
            domain,
        )
        .await
        .context("connection to DNSDB")?;
        let mut terminal = None;
        let mut seen_begin = false;
        let mut raw_records = 0_usize;
        let mut page_names = BTreeSet::new();
        for_each_stream_line(response, "DNSDB", |line| {
            let Some(line) = line else {
                commit_result_page(&mut names, std::mem::take(&mut page_names));
                return Ok(());
            };
            if line.iter().all(u8::is_ascii_whitespace) {
                return Ok(());
            }
            if terminal.is_some() {
                bail!("DNSDB: record received after terminal SAF condition");
            }
            let record: DnsDbSafRecord =
                serde_json::from_slice(line).context("DNSDB: invalid SAF NDJSON record")?;
            match record.condition.as_str() {
                "" | "ongoing" => {
                    if let Some(object) = record.obj {
                        raw_records = raw_records.saturating_add(1);
                        if let Some(name) = normalize_observed_name(&object.rrname, domain) {
                            page_names.insert(name);
                        }
                        if page_names.len() >= STREAM_COMMIT_BATCH {
                            commit_result_page(&mut names, std::mem::take(&mut page_names));
                        }
                    }
                }
                "begin" => {
                    if seen_begin {
                        bail!("DNSDB: duplicate SAF begin condition");
                    }
                    seen_begin = true;
                }
                "limited" | "succeeded" => terminal = Some(record.condition),
                other => {
                    let detail = (!record.msg.is_empty())
                        .then_some(format!(": {}", record.msg))
                        .unwrap_or_default();
                    bail!("DNSDB terminated with condition {other}{detail}");
                }
            }
            Ok(())
        })
        .await?;
        commit_result_page(&mut names, page_names);
        match terminal.as_deref() {
            Some("succeeded") => return Ok(names),
            Some("limited") => {
                if raw_records == 0 {
                    bail!("DNSDB returned a limited page without records");
                }
                let next_offset = offset
                    .checked_add(raw_records)
                    .context("DNSDB offset overflow")?;
                let Some(maximum) = offset_max else {
                    bail!("DNSDB limited the response but this account does not permit offsets");
                };
                if next_offset > maximum {
                    bail!("DNSDB offset limit reached at {next_offset}/{maximum}");
                }
                if page_index + 1 == MAX_PAGES {
                    bail!("DNSDB pagination limit reached with more results available");
                }
                offset = next_offset;
            }
            _ => bail!("DNSDB response has no terminal SAF condition"),
        }
    }
    Ok(names)
}

pub(super) async fn dnsdumpster(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("dnsdumpster")?;
    let response = send_external(
        "dnsdumpster",
        client(timeout)?
            .get(format!("https://api.dnsdumpster.com/domain/{domain}"))
            .header("X-API-Key", token),
        domain,
    )
    .await
    .context("connection to DNSDumpster")?;
    let response = response_json::<DnsDumpsterResponse>(response, "DNSDumpster").await?;
    Ok(response
        .a
        .into_iter()
        .chain(response.ns)
        .filter_map(|record| normalize_observed_name(&record.host, domain))
        .collect())
}

pub(super) async fn dnsrepo(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credential = keys.pick("dnsrepo")?;
    let (access_token, api_key) = split_key("dnsrepo", &credential)?;
    let response = send_external(
        "dnsrepo",
        client(timeout)?
            .get("https://dnsarchive.net/api/")
            .query(&[("apikey", api_key), ("search", domain)])
            .header("X-API-Access", access_token),
        domain,
    )
    .await
    .context("connection to DNSRepo")?;
    let response = response_json::<Vec<Value>>(response, "DNSRepo").await?;
    Ok(response
        .into_iter()
        .map(|entry| {
            entry
                .get("domain")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .context("DNSRepo: result has no domain string")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|name| normalize_observed_name(&name, domain))
        .collect())
}

pub(super) async fn domainsproject(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credential = keys.pick("domainsproject")?;
    let (username, password) = split_key("domainsproject", &credential)?;
    let response = send_external(
        "domainsproject",
        client(timeout)?
            .get("https://api.domainsproject.org/api/tld/search")
            .query(&[("domain", domain)])
            .basic_auth(username, Some(password)),
        domain,
    )
    .await
    .context("connection to DomainsProject")?;
    let response = response_json::<DomainsProjectResponse>(response, "DomainsProject").await?;
    if !response.error.is_empty() {
        bail!("DomainsProject: {}", response.error);
    }
    Ok(names_from_values(response.domains, domain))
}

pub(super) async fn fofa(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credential = keys.pick("fofa")?;
    let (email, secret) = split_key("fofa", &credential)?;
    if !email.contains('@') {
        bail!("fofa: credential username must be an email address");
    }
    let query = base64::engine::general_purpose::STANDARD.encode(format!("domain=\"{domain}\""));
    let response = send_external(
        "fofa",
        client(timeout)?
            .get("https://fofa.info/api/v1/search/all")
            .query(&[
                ("full", "true"),
                ("fields", "host"),
                ("page", "1"),
                ("size", "10000"),
                ("email", email),
                ("key", secret),
                ("qbase64", query.as_str()),
            ]),
        domain,
    )
    .await
    .context("connection to FOFA")?;
    let response = response_json::<FofaResponse>(response, "FOFA").await?;
    if response.error {
        bail!("FOFA: {}", response.errmsg);
    }
    Ok(response
        .results
        .into_iter()
        .filter_map(|value| normalize_host_or_url(&value, domain))
        .collect())
}

pub(super) async fn onyphe(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("onyphe")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for requested_page in 1..=MAX_PAGES {
        let response = send_external(
            "onyphe",
            http.get("https://www.onyphe.io/api/v2/search/")
                .query(&[
                    ("q", format!("category:resolver domain:{domain}")),
                    ("page", requested_page.to_string()),
                    ("size", "1000".to_owned()),
                ])
                .bearer_auth(&token),
            domain,
        )
        .await
        .context("connection to ONYPHE")?;
        let response = response_json::<OnypheResponse>(response, "ONYPHE").await?;
        let returned_page = flexible_usize(Some(&response.page), "ONYPHE", "page")?;
        let max_page = flexible_usize(Some(&response.max_page), "ONYPHE", "max_page")?;
        if returned_page != requested_page {
            bail!("ONYPHE returned page {returned_page} for request {requested_page}");
        }
        let raw_count = response.results.len();
        let mut page_names = BTreeSet::new();
        for entry in response.results {
            let object = entry
                .as_object()
                .context("ONYPHE: result is not an object")?;
            for field in [
                "subdomains",
                "hostname",
                "forward",
                "reverse",
                "host",
                "domain",
            ] {
                if let Some(value) = object.get(field) {
                    match value {
                        Value::String(value) => page_names.extend(names_from_text(value, domain)),
                        Value::Array(values) => {
                            for value in values {
                                let value = value.as_str().with_context(|| {
                                    format!("ONYPHE: {field} contains a non-string")
                                })?;
                                page_names.extend(names_from_text(value, domain));
                            }
                        }
                        Value::Null => {}
                        _ => bail!("ONYPHE: {field} is neither a string nor an array"),
                    }
                }
            }
        }
        commit_result_page(&mut names, page_names);
        if raw_count == 0 || requested_page >= max_page {
            return Ok(names);
        }
        if requested_page == MAX_PAGES {
            bail!("ONYPHE pagination limit reached with more results available");
        }
    }
    Ok(names)
}

pub(super) async fn profundis(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("profundis")?;
    let response = send_external_streaming(
        "profundis",
        client(timeout)?
            .post("https://api.profundis.io/api/v2/common/data/subdomains")
            .header("X-API-KEY", token)
            .header("Accept", "text/event-stream")
            .json(&json!({"domain": domain})),
        domain,
    )
    .await
    .context("connection to Profundis")?;
    let mut names = BTreeSet::new();
    let mut page_names = BTreeSet::new();
    for_each_stream_line(response, "Profundis", |line| {
        let Some(line) = line else {
            commit_result_page(&mut names, std::mem::take(&mut page_names));
            return Ok(());
        };
        if line.iter().all(u8::is_ascii_whitespace) {
            return Ok(());
        }
        let line = std::str::from_utf8(line).context("Profundis: invalid UTF-8 event")?;
        page_names.extend(names_from_text(line.trim(), domain));
        if page_names.len() >= STREAM_COMMIT_BATCH {
            commit_result_page(&mut names, std::mem::take(&mut page_names));
        }
        Ok(())
    })
    .await?;
    commit_result_page(&mut names, page_names);
    Ok(names)
}

pub(super) async fn pugrecon(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("pugrecon")?;
    let response = send_external(
        "pugrecon",
        client(timeout)?
            .post("https://pugrecon.com/api/v1/domains")
            .bearer_auth(token)
            .json(&json!({"domain_name": domain})),
        domain,
    )
    .await
    .context("connection to PugRecon")?;
    let response = response_json::<PugReconResponse>(response, "PugRecon").await?;
    if response.results.is_empty() && !response.message.is_empty() {
        bail!("PugRecon: {}", response.message);
    }
    Ok(response
        .results
        .into_iter()
        .filter_map(|result| normalize_observed_name(&result.name, domain))
        .collect())
}

pub(super) async fn quake(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("quake")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let page_size = 500_usize;
    for page_index in 0..MAX_PAGES {
        let start = page_index.saturating_mul(page_size);
        let response = send_external(
            "quake",
            http.post("https://quake.360.net/api/v3/search/quake_service")
                .header("X-QuakeToken", &token)
                .json(&json!({
                    "query": format!("domain: {domain}"),
                    "include": ["service.http.host"],
                    "latest": true,
                    "size": page_size,
                    "start": start,
                })),
            domain,
        )
        .await
        .context("connection to Quake")?;
        let response = response_json::<QuakeResponse>(response, "Quake").await?;
        if response.code != 0 {
            bail!("Quake: {} (code {})", response.message, response.code);
        }
        let total = response.meta.pagination.total;
        let raw_count = response.data.len();
        let page_names = response
            .data
            .into_iter()
            .filter_map(|entry| normalize_observed_name(&entry.service.http.host, domain))
            .collect();
        commit_result_page(&mut names, page_names);
        if raw_count == 0 || start.saturating_add(page_size) >= total {
            return Ok(names);
        }
        if page_index + 1 == MAX_PAGES {
            bail!("Quake pagination limit reached with more results available");
        }
    }
    Ok(names)
}

pub(super) async fn redhuntlabs(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credential = keys.pick("redhuntlabs")?;
    let (endpoint, token) = split_endpoint_key(&credential)?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for requested_page in 1..=MAX_PAGES {
        let mut url = endpoint.clone();
        url.query_pairs_mut()
            .append_pair("domain", domain)
            .append_pair("page", &requested_page.to_string())
            .append_pair("page_size", "1000");
        let response = send_external(
            "redhuntlabs",
            http.get(url).header("X-BLOBR-KEY", token),
            domain,
        )
        .await
        .context("connection to RedHunt Labs")?;
        let response = response_json::<RedHuntResponse>(response, "RedHunt Labs").await?;
        if response.metadata.page_number != requested_page {
            bail!(
                "RedHunt Labs returned page {} for request {requested_page}",
                response.metadata.page_number
            );
        }
        let total_pages = page_count(response.metadata.result_count, response.metadata.page_size)?;
        let raw_count = response.subdomains.len();
        commit_result_page(&mut names, names_from_values(response.subdomains, domain));
        if requested_page >= total_pages || response.metadata.result_count == 0 {
            return Ok(names);
        }
        if raw_count == 0 {
            bail!("RedHunt Labs returned an empty page before the reported end");
        }
        if requested_page == MAX_PAGES {
            bail!("RedHunt Labs pagination limit reached with more results available");
        }
    }
    Ok(names)
}

pub(super) async fn robtex(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("robtex")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut forward_names = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut ip_limit_reached = false;
    visit_robtex_records(
        &http,
        format!("https://proapi.robtex.com/pdns/forward/{domain}"),
        &token,
        domain,
        |record| {
            let Some(record) = record else {
                commit_result_page(&mut names, std::mem::take(&mut forward_names));
                return Ok(());
            };
            forward_names.extend(names_from_text(&record.rrname, domain));
            forward_names.extend(names_from_text(&record.rrdata, domain));
            if let Ok(ip) = record.rrdata.trim().parse::<IpAddr>() {
                let type_matches = matches!(
                    (record.rrtype.as_str(), ip),
                    ("A", IpAddr::V4(_)) | ("AAAA", IpAddr::V6(_))
                );
                if type_matches && !ips.contains(&ip) {
                    if ips.len() < MAX_ROBTEX_REVERSE_IPS {
                        ips.insert(ip);
                    } else {
                        ip_limit_reached = true;
                    }
                }
            }
            if forward_names.len() >= STREAM_COMMIT_BATCH {
                commit_result_page(&mut names, std::mem::take(&mut forward_names));
            }
            Ok(())
        },
    )
    .await?;
    commit_result_page(&mut names, forward_names);

    for ip in ips {
        let mut reverse_names = BTreeSet::new();
        visit_robtex_records(
            &http,
            format!("https://proapi.robtex.com/pdns/reverse/{ip}"),
            &token,
            domain,
            |record| {
                let Some(record) = record else {
                    commit_result_page(&mut names, std::mem::take(&mut reverse_names));
                    return Ok(());
                };
                reverse_names.extend(names_from_text(&record.rrname, domain));
                reverse_names.extend(names_from_text(&record.rrdata, domain));
                if reverse_names.len() >= STREAM_COMMIT_BATCH {
                    commit_result_page(&mut names, std::mem::take(&mut reverse_names));
                }
                Ok(())
            },
        )
        .await
        .with_context(|| format!("Robtex reverse lookup for {ip}"))?;
        commit_result_page(&mut names, reverse_names);
    }
    if ip_limit_reached {
        bail!(
            "Robtex reverse pivot limit reached (first {MAX_ROBTEX_REVERSE_IPS} unique IPs queried; more were advertised)"
        );
    }
    Ok(names)
}

pub(super) async fn rsecloud(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("rsecloud")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for endpoint in ["active", "passive"] {
        for requested_page in 1..=MAX_PAGES {
            let response = send_external(
                "rsecloud",
                http.get(format!(
                    "https://api.rsecloud.com/api/v2/subdomains/{endpoint}/{domain}"
                ))
                .query(&[("page", requested_page)])
                .header("X-API-Key", &token),
                domain,
            )
            .await
            .with_context(|| format!("connection to RSE Cloud {endpoint}"))?;
            let response = response_json::<RseCloudResponse>(response, "RSE Cloud").await?;
            if response.page != requested_page {
                bail!(
                    "RSE Cloud {endpoint} returned page {} for request {requested_page}",
                    response.page
                );
            }
            if response.page_size == 0 && response.total_pages > 0 {
                bail!("RSE Cloud {endpoint} returned a zero page size");
            }
            let raw_count = response.data.len();
            let total_pages = response.total_pages;
            commit_result_page(&mut names, names_from_values(response.data, domain));
            if total_pages == 0 || requested_page >= total_pages {
                break;
            }
            if raw_count == 0 {
                bail!("RSE Cloud {endpoint} returned an empty page before the reported end");
            }
            if requested_page == MAX_PAGES {
                bail!("RSE Cloud {endpoint} pagination limit reached with more results available");
            }
        }
    }
    Ok(names)
}

pub(super) async fn threatbook(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("threatbook")?;
    let response = send_external(
        "threatbook",
        client(timeout)?
            .get("https://api.threatbook.cn/v3/domain/sub_domains")
            .query(&[("apikey", token.as_str()), ("resource", domain)]),
        domain,
    )
    .await
    .context("connection to ThreatBook")?;
    let response = response_json::<ThreatBookResponse>(response, "ThreatBook").await?;
    if response.response_code != 0 {
        bail!(
            "ThreatBook: {} (code {})",
            response.verbose_msg,
            response.response_code
        );
    }
    let total = response
        .data
        .sub_domains
        .total
        .parse::<usize>()
        .context("ThreatBook: invalid subdomain total")?;
    if total < response.data.sub_domains.data.len() {
        bail!("ThreatBook: result count exceeds reported total");
    }
    Ok(names_from_values(response.data.sub_domains.data, domain))
}

pub(super) async fn windvane(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("windvane")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for requested_page in 1..=MAX_PAGES {
        let response = send_external(
            "windvane",
            http.post(
                "https://windvane.lichoin.com/trpc.backendhub.public.WindvaneService/ListSubDomain",
            )
            .header("X-Api-Key", &token)
            .json(&json!({
                "domain": domain,
                "page_request": {"page": requested_page, "count": 1000},
            })),
            domain,
        )
        .await
        .context("connection to Windvane")?;
        let response = response_json::<WindvaneResponse>(response, "Windvane").await?;
        if response.code != 0 {
            bail!("Windvane: {} (code {})", response.msg, response.code);
        }
        let total = response
            .data
            .page_response
            .total
            .parse::<usize>()
            .context("Windvane: invalid total")?;
        let count = response
            .data
            .page_response
            .count
            .parse::<usize>()
            .context("Windvane: invalid count")?;
        let declared_pages = response
            .data
            .page_response
            .total_page
            .parse::<usize>()
            .context("Windvane: invalid total_page")?;
        let computed_pages = page_count(total, count)?;
        if declared_pages != computed_pages && total > 0 {
            bail!(
                "Windvane: inconsistent pagination ({declared_pages} declared, {computed_pages} computed)"
            );
        }
        let raw_count = response.data.list.len();
        commit_result_page(
            &mut names,
            response
                .data
                .list
                .into_iter()
                .filter_map(|entry| normalize_observed_name(&entry.domain, domain))
                .collect(),
        );
        if total == 0 || requested_page >= declared_pages {
            return Ok(names);
        }
        if raw_count == 0 {
            bail!("Windvane returned an empty page before the reported end");
        }
        if requested_page == MAX_PAGES {
            bail!("Windvane pagination limit reached with more results available");
        }
    }
    Ok(names)
}

pub(super) async fn zoomeyeapi(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let credential = keys.pick("zoomeyeapi")?;
    let (host_suffix, token) = split_key("zoomeyeapi", &credential)?;
    let host_suffix = validate_api_suffix("zoomeyeapi", host_suffix)?;
    let endpoint = format!("https://api.{host_suffix}/domain/search");
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for requested_page in 1..=MAX_PAGES {
        let response = send_external(
            "zoomeyeapi",
            http.get(&endpoint)
                .query(&[
                    ("q", domain.to_owned()),
                    ("type", "1".to_owned()),
                    ("s", "1000".to_owned()),
                    ("page", requested_page.to_string()),
                ])
                .header("API-KEY", token),
            domain,
        )
        .await
        .context("connection to ZoomEye")?;
        // ZoomEye uses numeric status 60000 for a successful response, which
        // must not be interpreted as a generic HTTP-like provider error code.
        let (status, body) = response_bytes_limited(response, "ZoomEye").await?;
        if !status.is_success() {
            bail!(
                "ZoomEye: HTTP {status}: {}",
                compact_external_error(&String::from_utf8_lossy(&body))
            );
        }
        let response: ZoomEyeResponse =
            serde_json::from_slice(&body).context("ZoomEye: incompatible JSON schema")?;
        if !matches!(response.status, 0 | 200 | 60_000) {
            bail!("ZoomEye returned status {}", response.status);
        }
        let total_pages = page_count(response.total, 1_000)?;
        let raw_count = response.list.len();
        commit_result_page(
            &mut names,
            response
                .list
                .into_iter()
                .filter_map(|entry| normalize_observed_name(&entry.name, domain))
                .collect(),
        );
        if response.total == 0 || requested_page >= total_pages {
            return Ok(names);
        }
        if raw_count == 0 {
            bail!("ZoomEye returned an empty page before the reported end");
        }
        if requested_page == MAX_PAGES {
            bail!("ZoomEye pagination limit reached with more results available");
        }
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_credentials_and_dynamic_hosts_are_strictly_validated() {
        assert_eq!(
            split_key("fofa", "analyst@example.test:secret").unwrap(),
            ("analyst@example.test", "secret")
        );
        assert!(split_key("fofa", "missing_separator").is_err());
        assert!(split_key("fofa", ":secret").is_err());
        assert!(split_key("fofa", "user:secret:extra").is_err());

        let (endpoint, token) = split_endpoint_key("https://api.redhuntlabs.com:token").unwrap();
        assert_eq!(endpoint.as_str(), "https://api.redhuntlabs.com/");
        assert_eq!(token, "token");
        assert!(split_endpoint_key("http://api.redhuntlabs.com:token").is_err());
        assert!(split_endpoint_key("https://127.0.0.1:token").is_err());
        assert!(split_endpoint_key("https://user@api.redhuntlabs.com:token").is_err());
        assert!(split_endpoint_key("https://api.attacker.test:token").is_err());

        assert_eq!(
            validate_api_suffix("zoomeyeapi", "zoomeye.org.").unwrap(),
            "zoomeye.org"
        );
        assert!(validate_api_suffix("zoomeyeapi", "api.zoomeye.org").is_err());
        assert!(validate_api_suffix("zoomeyeapi", "localhost").is_err());
        assert!(validate_api_suffix("zoomeyeapi", "attacker.test").is_err());
    }

    #[test]
    fn normalization_keeps_only_strict_in_scope_subdomains() {
        let names = names_from_text(
            "*.API.Example.COM. https://cdn.example.com:8443/path example.com evil-example.com",
            "example.com",
        );
        assert_eq!(
            names,
            BTreeSet::from(["api.example.com".to_owned(), "cdn.example.com".to_owned()])
        );
        assert_eq!(
            normalize_host_or_url("HTTPS://WWW.EXAMPLE.COM:443/path", "example.com"),
            Some("www.example.com".to_owned())
        );
        assert_eq!(normalize_host_or_url("example.com", "example.com"), None);
    }

    #[test]
    fn flexible_pagination_accepts_numbers_and_numeric_strings() {
        assert_eq!(
            flexible_usize(Some(&json!(7)), "source", "page").unwrap(),
            7
        );
        assert_eq!(
            flexible_usize(Some(&json!("8")), "source", "page").unwrap(),
            8
        );
        assert!(flexible_usize(Some(&json!(-1)), "source", "page").is_err());
        assert!(flexible_usize(Some(&json!("NaN")), "source", "page").is_err());
        assert_eq!(page_count(2_001, 1_000).unwrap(), 3);
        assert_eq!(page_count(0, 1_000).unwrap(), 0);
        assert!(page_count(1, 0).is_err());
    }

    #[test]
    fn provider_contract_fixtures_decode_expected_shapes() {
        let onyphe: OnypheResponse = serde_json::from_value(json!({
            "results": ["api.example.com", ["cdn.example.com"]],
            "page": "1",
            "max_page": 2
        }))
        .unwrap();
        assert_eq!(onyphe.results.len(), 2);
        assert_eq!(
            flexible_usize(Some(&onyphe.page), "Onyphe", "page").unwrap(),
            1
        );

        let windvane: WindvaneResponse = serde_json::from_value(json!({
            "code": 0,
            "msg": "ok",
            "data": {
                "list": [{"domain": "api.example.com"}],
                "page_response": {"total": "1", "count": "1000", "total_page": "1"}
            }
        }))
        .unwrap();
        assert_eq!(windvane.data.list[0].domain, "api.example.com");

        let zoomeye: ZoomEyeResponse = serde_json::from_value(json!({
            "status": 60000,
            "total": 1,
            "list": [{"name": "api.example.com", "ip": ["192.0.2.1"]}]
        }))
        .unwrap();
        assert_eq!(zoomeye.status, 60_000);
        assert_eq!(zoomeye.list[0].name, "api.example.com");

        let records = parse_robtex_records(
            "{\"rrname\":\"example.com\",\"rrdata\":\"192.0.2.1\",\"rrtype\":\"A\"}\n\
             {\"rrname\":\"1.2.0.192.in-addr.arpa\",\"rrdata\":\"api.example.com\",\"rrtype\":\"PTR\"}\n",
        )
        .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].rrdata, "api.example.com");
        assert!(parse_robtex_records("{not-json}\n").is_err());
    }

    #[test]
    fn robtex_request_uses_structured_query_and_ndjson_accept_header() {
        let http = reqwest::Client::new();
        let request = robtex_request(
            &http,
            "https://proapi.robtex.com/pdns/forward/example.com".to_owned(),
            "a key/+",
        )
        .build()
        .unwrap();
        assert_eq!(request.url().path(), "/pdns/forward/example.com");
        assert_eq!(
            request.url().query_pairs().collect::<Vec<_>>(),
            vec![("key".into(), "a key/+".into())]
        );
        assert_eq!(
            request.headers().get("accept").unwrap(),
            "application/x-ndjson"
        );
    }
}
