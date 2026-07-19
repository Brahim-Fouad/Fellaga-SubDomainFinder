use super::{
    ApiKeyStore, client, commit_numeric_result_page, commit_result_page, compact_external_error,
    finish_numeric_pagination, hostname_from_url, numeric_pagination_contract,
    numeric_pagination_is_complete, numeric_pagination_resume, response_bytes_limited,
    response_json, send_external, send_external_idempotent, send_external_streaming,
    send_external_streaming_idempotent,
};
use crate::db::PassivePaginationPage;
use crate::util::{domain_hash, extract_observed_names, normalize_observed_name, valid_fqdn};
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
const DNSDUMPSTER_PAGE_SIZE: usize = 200;
const DNSDUMPSTER_MAX_PAGES: usize = 50;
const DNSDUMPSTER_PAGE_DELAY: Duration = Duration::from_secs(2);
const VIEWDNS_MAX_PAGES: usize = 1_000;

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
    #[serde(default)]
    a: Vec<DnsDumpsterRecord>,
    #[serde(default)]
    cname: Vec<DnsDumpsterRecord>,
    #[serde(default)]
    mx: Vec<DnsDumpsterRecord>,
    #[serde(default)]
    ns: Vec<DnsDumpsterRecord>,
    #[serde(default)]
    total_a_recs: Option<usize>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct DnsDumpsterRecord {
    host: String,
}

fn dnsdumpster_request(
    http: &reqwest::Client,
    domain: &str,
    page: usize,
    token: &str,
) -> reqwest::RequestBuilder {
    let request = http
        .get(format!("https://api.dnsdumpster.com/domain/{domain}"))
        .header("X-API-Key", token);
    if page == 1 {
        request
    } else {
        request.query(&[("page", page)])
    }
}

fn dnsdumpster_page_fingerprint(response: &DnsDumpsterResponse) -> Vec<String> {
    let mut fingerprint = response
        .a
        .iter()
        .map(|record| format!("a:{}", record.host.to_ascii_lowercase()))
        .chain(
            response
                .cname
                .iter()
                .map(|record| format!("cname:{}", record.host.to_ascii_lowercase())),
        )
        .chain(
            response
                .mx
                .iter()
                .map(|record| format!("mx:{}", record.host.to_ascii_lowercase())),
        )
        .chain(
            response
                .ns
                .iter()
                .map(|record| format!("ns:{}", record.host.to_ascii_lowercase())),
        )
        .collect::<Vec<_>>();
    fingerprint.sort_unstable();
    fingerprint
}

fn dnsdumpster_page_names(response: &DnsDumpsterResponse, domain: &str) -> BTreeSet<String> {
    response
        .a
        .iter()
        .chain(&response.cname)
        .chain(&response.mx)
        .chain(&response.ns)
        .filter_map(|record| normalize_observed_name(&record.host, domain))
        .collect()
}

#[derive(Deserialize)]
struct ViewDnsEnvelope {
    #[serde(default)]
    query: Option<ViewDnsQuery>,
    #[serde(default)]
    response: Option<ViewDnsResponse>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ViewDnsQuery {
    domain: String,
}

#[derive(Deserialize)]
struct ViewDnsResponse {
    #[serde(default)]
    subdomain_count: Value,
    #[serde(default)]
    total_pages: Value,
    #[serde(default)]
    current_page: Value,
    subdomains: Vec<ViewDnsRecord>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ViewDnsRecord {
    name: String,
}

fn viewdns_request(
    http: &reqwest::Client,
    domain: &str,
    page: usize,
    token: &str,
) -> reqwest::RequestBuilder {
    http.get("https://api.viewdns.info/subdomains/")
        .query(&[("domain", domain), ("apikey", token), ("output", "json")])
        .query(&[("page", page)])
}

fn viewdns_page_names(response: &ViewDnsResponse, domain: &str) -> BTreeSet<String> {
    response
        .subdomains
        .iter()
        .filter_map(|record| normalize_observed_name(&record.name, domain))
        .collect()
}

fn viewdns_page_hash(response: &ViewDnsResponse) -> String {
    let mut records = response
        .subdomains
        .iter()
        .map(|record| record.name.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    records.sort_unstable();
    domain_hash(&records.join("\0"))
}

fn viewdns_page_state(response: &ViewDnsResponse, requested_page: usize) -> Result<(usize, usize)> {
    let current_page = flexible_usize(Some(&response.current_page), "ViewDNS", "current_page")?;
    let total_pages = flexible_usize(Some(&response.total_pages), "ViewDNS", "total_pages")?;
    let total = flexible_usize(
        Some(&response.subdomain_count),
        "ViewDNS",
        "subdomain_count",
    )?;
    if current_page != requested_page {
        bail!("ViewDNS returned page {current_page} for request {requested_page}");
    }
    if total_pages == 0 {
        if requested_page == 1 && current_page == 1 && total == 0 && response.subdomains.is_empty()
        {
            return Ok((0, 0));
        }
        bail!("ViewDNS returned zero total_pages outside an empty first page");
    }
    if current_page > total_pages {
        bail!("ViewDNS returned current_page greater than total_pages");
    }
    Ok((total, total_pages))
}

fn viewdns_stable_count(known: Option<usize>, received: usize, field: &str) -> Result<usize> {
    if let Some(known) = known
        && known != received
    {
        bail!("ViewDNS changed {field} during pagination: {known} -> {received}");
    }
    Ok(known.unwrap_or(received))
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
    #[serde(default)]
    results: Vec<String>,
    #[serde(default)]
    size: Option<usize>,
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
    #[serde(default)]
    results: Vec<Value>,
    #[serde(default)]
    page: Value,
    #[serde(default)]
    max_page: Value,
    #[serde(default)]
    error: Value,
    #[serde(default)]
    status: Value,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct PugReconResponse {
    results: Vec<PugReconResult>,
    #[serde(default)]
    message: String,
    #[serde(default)]
    limited: bool,
    #[serde(default)]
    total_results: Option<usize>,
    #[serde(default)]
    quota_remaining: Option<usize>,
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
    #[serde(default)]
    data: Option<ThreatBookData>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportedTotal {
    Exact(usize),
    AtLeast(usize),
}

fn parse_reported_total(source: &str, value: &str) -> Result<ReportedTotal> {
    let value = value.trim();
    if let Some(minimum) = value.strip_suffix('+') {
        let minimum = minimum
            .parse::<usize>()
            .with_context(|| format!("{source}: invalid reported total"))?;
        return Ok(ReportedTotal::AtLeast(minimum));
    }
    value
        .parse::<usize>()
        .map(ReportedTotal::Exact)
        .with_context(|| format!("{source}: invalid reported total"))
}

const ONYPHE_MAX_PAGES: usize = 10;

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
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut seen_pages = BTreeSet::new();
    let mut a_records_seen = 0_usize;

    for requested_page in 1..=DNSDUMPSTER_MAX_PAGES {
        if requested_page > 1 {
            tokio::time::sleep(DNSDUMPSTER_PAGE_DELAY).await;
        }
        let response = send_external(
            "dnsdumpster",
            dnsdumpster_request(&http, domain, requested_page, &token),
            &format!("{domain}:{requested_page}"),
        )
        .await
        .with_context(|| format!("connection to DNSDumpster page {requested_page}"))?;
        let response = response_json::<DnsDumpsterResponse>(response, "DNSDumpster").await?;
        if let Some(error) = response
            .error
            .as_deref()
            .filter(|error| !error.trim().is_empty())
        {
            bail!("DNSDumpster: {}", compact_external_error(error));
        }

        let raw_count = response
            .a
            .len()
            .saturating_add(response.cname.len())
            .saturating_add(response.mx.len())
            .saturating_add(response.ns.len());
        if raw_count == 0 {
            if response
                .total_a_recs
                .is_some_and(|total| a_records_seen < total)
            {
                bail!(
                    "DNSDumpster: empty page {requested_page} before the reported A-record total"
                );
            }
            return Ok(names);
        }

        let fingerprint = dnsdumpster_page_fingerprint(&response);
        if !seen_pages.insert(fingerprint) {
            bail!("DNSDumpster: repeated page {requested_page}");
        }
        a_records_seen = a_records_seen.saturating_add(response.a.len());
        let reported_a_total = response.total_a_recs;
        commit_result_page(&mut names, dnsdumpster_page_names(&response, domain));

        let has_more_a_records = reported_a_total.is_some_and(|total| a_records_seen < total);
        let page_is_full = raw_count >= DNSDUMPSTER_PAGE_SIZE;
        if !has_more_a_records && !page_is_full {
            return Ok(names);
        }
        if requested_page == DNSDUMPSTER_MAX_PAGES {
            bail!("DNSDumpster: pagination limit reached while more records may be available");
        }
    }

    Ok(names)
}

async fn collect_viewdns_pages<F, Fut>(domain: &str, mut fetch_page: F) -> Result<BTreeSet<String>>
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = Result<ViewDnsEnvelope>>,
{
    let contract = numeric_pagination_contract("viewdns", domain)
        .context("ViewDNS: numeric pagination contract is missing")?;
    if numeric_pagination_is_complete(&contract) {
        // The lane completed before a previous process could atomically
        // publish source freshness. The scanner will now complete the source
        // from the durable done row without replaying provider pages.
        return Ok(BTreeSet::new());
    }
    let resume = numeric_pagination_resume(&contract);
    let mut names = BTreeSet::new();
    let mut seen_pages = BTreeSet::new();
    if let Some(state) = &resume
        && state.last_page_records > 0
    {
        seen_pages.insert(state.last_page_hash.clone());
    }
    let mut raw_records_seen = resume
        .as_ref()
        .map(|state| state.records_seen)
        .map(usize::try_from)
        .transpose()
        .context("ViewDNS: saved record count is too large")?
        .unwrap_or_default();
    let mut reported_total = resume
        .as_ref()
        .and_then(|state| state.expected_records)
        .map(usize::try_from)
        .transpose()
        .context("ViewDNS: saved total is too large")?;
    let mut reported_pages = resume
        .as_ref()
        .and_then(|state| state.expected_pages)
        .map(usize::try_from)
        .transpose()
        .context("ViewDNS: saved page total is too large")?;
    let first_requested_page = resume
        .as_ref()
        .map(|state| state.next_position)
        .map(usize::try_from)
        .transpose()
        .context("ViewDNS: saved page position is too large")?
        .unwrap_or(1);
    if first_requested_page > VIEWDNS_MAX_PAGES {
        bail!("ViewDNS: saved page position exceeds the connector limit");
    }

    for requested_page in first_requested_page..=VIEWDNS_MAX_PAGES {
        let envelope = fetch_page(requested_page).await?;
        if let Some(error) = envelope
            .error
            .as_deref()
            .filter(|error| !error.trim().is_empty())
        {
            bail!("ViewDNS: {}", compact_external_error(error));
        }
        let response = envelope
            .response
            .context("ViewDNS: successful response omitted the response object")?;
        if let Some(error) = response
            .error
            .as_deref()
            .filter(|error| !error.trim().is_empty())
        {
            bail!("ViewDNS: {}", compact_external_error(error));
        }
        let returned_domain = envelope
            .query
            .as_ref()
            .context("ViewDNS: successful response omitted the query object")?
            .domain
            .trim()
            .trim_end_matches('.');
        if !returned_domain.eq_ignore_ascii_case(domain.trim_end_matches('.')) {
            bail!("ViewDNS returned data for a different domain");
        }

        let (total, total_pages) = viewdns_page_state(&response, requested_page)?;
        let next_reported_total = viewdns_stable_count(reported_total, total, "subdomain_count")?;
        let next_reported_pages = viewdns_stable_count(reported_pages, total_pages, "total_pages")?;

        let raw_count = response.subdomains.len();
        let page_hash = viewdns_page_hash(&response);
        if raw_count > 0 && seen_pages.contains(&page_hash) {
            bail!("ViewDNS returned a repeated pagination page");
        }
        let next_raw_records_seen = raw_records_seen.saturating_add(raw_count);
        if next_raw_records_seen > next_reported_total {
            bail!(
                "ViewDNS returned more records than reported: {next_raw_records_seen}/{next_reported_total}"
            );
        }

        // Validation precedes the atomic page commit. Empty pages still move
        // the numeric resume point forward, avoiding an endless retry loop on
        // a provider-side sparse page.
        let page_names = viewdns_page_names(&response, domain);
        commit_numeric_result_page(
            &mut names,
            page_names,
            &contract,
            &PassivePaginationPage {
                position: requested_page as u64,
                next_position: requested_page.saturating_add(1) as u64,
                records_seen: next_raw_records_seen as u64,
                expected_records: Some(next_reported_total as u64),
                expected_pages: Some(next_reported_pages as u64),
                page_hash: page_hash.clone(),
                page_records: raw_count as u64,
            },
        )?;
        reported_total = Some(next_reported_total);
        reported_pages = Some(next_reported_pages);
        raw_records_seen = next_raw_records_seen;
        if raw_count > 0 {
            seen_pages.insert(page_hash);
        }

        if next_reported_pages == 0 {
            finish_numeric_pagination(&contract)?;
            return Ok(names);
        }

        if requested_page >= next_reported_pages {
            if raw_records_seen != next_reported_total {
                bail!(
                    "ViewDNS returned a partial result: {raw_records_seen}/{next_reported_total} records"
                );
            }
            finish_numeric_pagination(&contract)?;
            return Ok(names);
        }
        if requested_page == VIEWDNS_MAX_PAGES {
            bail!("ViewDNS pagination limit reached while more results remained");
        }
    }

    Ok(names)
}

pub(super) async fn viewdns(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("viewdns")?;
    let http = client(timeout)?;
    let request_domain = domain.to_owned();
    collect_viewdns_pages(domain, move |requested_page| {
        let http = http.clone();
        let token = token.clone();
        let domain = request_domain.clone();
        async move {
            let response = send_external(
                "viewdns",
                viewdns_request(&http, &domain, requested_page, &token),
                &format!("{domain}:{requested_page}"),
            )
            .await
            .with_context(|| format!("connection to ViewDNS page {requested_page}"))?;
            response_json::<ViewDnsEnvelope>(response, "ViewDNS").await
        }
    })
    .await
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
        bail!("FOFA: {}", compact_external_error(&response.errmsg));
    }
    let returned = response.results.len();
    let total = response
        .size
        .context("FOFA: successful response omitted result size")?;
    if total < returned {
        bail!("FOFA: result count exceeds reported total");
    }
    let mut names = BTreeSet::new();
    let page = response
        .results
        .into_iter()
        .filter_map(|value| normalize_host_or_url(&value, domain))
        .collect();
    commit_result_page(&mut names, page);
    if total > returned {
        bail!(
            "FOFA: résultat partiel, {returned}/{total} entrées reçues; le plafond Search est atteint"
        );
    }
    Ok(names)
}

fn onyphe_error(response: &OnypheResponse) -> Result<Option<String>> {
    let failed = match &response.error {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64() != Some(0),
        Value::String(value) => !matches!(value.trim(), "" | "0" | "false"),
        _ => bail!("ONYPHE: invalid error field"),
    };
    if !failed {
        return Ok(None);
    }
    let status = match &response.status {
        Value::Null => String::new(),
        Value::String(value) => compact_external_error(value),
        value => compact_external_error(&value.to_string()),
    };
    let text = compact_external_error(&response.text);
    let detail = [status, text]
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(": ");
    Ok(Some(if detail.is_empty() {
        "ONYPHE: provider returned an error".to_owned()
    } else {
        format!("ONYPHE: {detail}")
    }))
}

async fn onyphe_category(
    http: &reqwest::Client,
    domain: &str,
    token: &str,
    category: &str,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for requested_page in 1..=ONYPHE_MAX_PAGES {
        let response = send_external(
            "onyphe",
            http.get("https://www.onyphe.io/api/v2/search/")
                .query(&[
                    ("q", format!("category:{category} domain:{domain}")),
                    ("page", requested_page.to_string()),
                    ("size", "1000".to_owned()),
                ])
                .bearer_auth(token),
            &format!("{domain}:{category}:{requested_page}"),
        )
        .await
        .with_context(|| format!("connection to ONYPHE category {category}"))?;
        let response = response_json::<OnypheResponse>(response, "ONYPHE").await?;
        if let Some(error) = onyphe_error(&response)? {
            bail!("{error}");
        }
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
        if requested_page == ONYPHE_MAX_PAGES {
            bail!(
                "ONYPHE category {category}: résultat partiel au plafond de {} pages",
                ONYPHE_MAX_PAGES
            );
        }
    }
    Ok(names)
}

pub(super) async fn onyphe(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("onyphe")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    for category in ["resolver", "hostname"] {
        let category_names = onyphe_category(&http, domain, &token, category).await?;
        commit_result_page(&mut names, category_names);
    }
    Ok(names)
}

pub(super) async fn profundis(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("profundis")?;
    let response = send_external_streaming_idempotent(
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
    let response = send_external_idempotent(
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
        bail!("PugRecon: {}", compact_external_error(&response.message));
    }
    let returned = response.results.len();
    let total = response.total_results.unwrap_or(returned);
    let mut names = BTreeSet::new();
    let page = response
        .results
        .into_iter()
        .filter_map(|result| normalize_observed_name(&result.name, domain))
        .collect();
    commit_result_page(&mut names, page);
    if response.limited && total > returned {
        let message = compact_external_error(&response.message);
        let detail = if message.is_empty() {
            String::new()
        } else {
            format!(": {message}")
        };
        let quota = response
            .quota_remaining
            .map(|value| format!(", quota restante {value}"))
            .unwrap_or_default();
        bail!("PugRecon: résultat partiel, {returned}/{total} entrées reçues{quota}{detail}");
    }
    Ok(names)
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
        let response = send_external_idempotent(
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
            compact_external_error(&response.verbose_msg),
            response.response_code
        );
    }
    let subdomains = response
        .data
        .context("ThreatBook: successful response omitted data")?
        .sub_domains;
    let total = parse_reported_total("ThreatBook", &subdomains.total)?;
    let returned = subdomains.data.len();
    if matches!(total, ReportedTotal::Exact(value) if value < returned) {
        bail!("ThreatBook: result count exceeds reported total");
    }
    let mut names = BTreeSet::new();
    commit_result_page(&mut names, names_from_values(subdomains.data, domain));
    let incomplete = match total {
        ReportedTotal::Exact(value) => value > returned,
        ReportedTotal::AtLeast(_) => true,
    };
    if incomplete {
        let total = match total {
            ReportedTotal::Exact(value) => value.to_string(),
            ReportedTotal::AtLeast(value) => format!("{value}+"),
        };
        bail!(
            "ThreatBook: résultat partiel, {returned}/{total} entrées reçues; l'API ne fournit pas de pagination"
        );
    }
    Ok(names)
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
        let response = send_external_idempotent(
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
    use crate::db::Database;
    use crate::passive::{
        PassivePaginationContext, PassivePaginationFinishSink, PassivePaginationPageSink,
    };
    use std::sync::{Arc, Mutex};

    fn viewdns_fixture_page(
        page: usize,
        total_pages: usize,
        total: usize,
        names: &[&str],
    ) -> ViewDnsEnvelope {
        ViewDnsEnvelope {
            query: Some(ViewDnsQuery {
                domain: "example.com".to_owned(),
            }),
            response: Some(ViewDnsResponse {
                subdomain_count: json!(total),
                total_pages: json!(total_pages),
                current_page: json!(page),
                subdomains: names
                    .iter()
                    .map(|name| ViewDnsRecord {
                        name: (*name).to_owned(),
                    })
                    .collect(),
                error: None,
            }),
            error: None,
        }
    }

    fn viewdns_pagination_context(db: &Database) -> PassivePaginationContext {
        let contract = numeric_pagination_contract("viewdns", "example.com").unwrap();
        let resume = db
            .passive_pagination_resume(
                "example.com",
                "viewdns",
                contract.lane,
                contract.contract_version,
                &contract.query_hash,
            )
            .unwrap();
        let page_db = db.clone();
        let page_contract = contract.clone();
        let page_sink: PassivePaginationPageSink = Arc::new(move |page, names| {
            page_db
                .commit_passive_pagination_page(
                    "example.com",
                    "viewdns",
                    page_contract.lane,
                    page_contract.contract_version,
                    &page_contract.query_hash,
                    page,
                    names,
                )
                .map(|_| ())
        });
        let finish_db = db.clone();
        let finish_contract = contract.clone();
        let finish_sink: PassivePaginationFinishSink = Arc::new(move || {
            finish_db.finish_passive_pagination(
                "example.com",
                "viewdns",
                finish_contract.lane,
                finish_contract.contract_version,
                &finish_contract.query_hash,
            )
        });
        PassivePaginationContext::new(contract, resume, page_sink, finish_sink)
    }

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
        assert_eq!(names, BTreeSet::from(["cdn.example.com".to_owned()]));
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

        let pugrecon: PugReconResponse = serde_json::from_value(json!({
            "results": [{"name": "api.example.com"}],
            "message": "free-tier result limit",
            "limited": true,
            "total_results": 75,
            "quota_remaining": 9
        }))
        .unwrap();
        assert!(pugrecon.limited);
        assert_eq!(pugrecon.total_results, Some(75));
        assert_eq!(pugrecon.quota_remaining, Some(9));

        assert_eq!(
            parse_reported_total("ThreatBook", "500").unwrap(),
            ReportedTotal::Exact(500)
        );
        assert_eq!(
            parse_reported_total("ThreatBook", "1000+").unwrap(),
            ReportedTotal::AtLeast(1000)
        );
        assert!(parse_reported_total("ThreatBook", "many").is_err());

        let onyphe: OnypheResponse = serde_json::from_value(json!({
            "error": 3,
            "status": "rate_limit",
            "text": "quota exhausted"
        }))
        .unwrap();
        assert!(
            onyphe_error(&onyphe)
                .unwrap()
                .is_some_and(|error| error.contains("quota exhausted"))
        );

        let fofa: FofaResponse = serde_json::from_value(json!({
            "error": false,
            "errmsg": "",
            "size": 12_000,
            "results": ["https://api.example.com"]
        }))
        .unwrap();
        assert_eq!(fofa.size, Some(12_000));
    }

    #[test]
    fn dnsdumpster_contract_paginates_and_reads_every_host_category() {
        let response: DnsDumpsterResponse = serde_json::from_value(json!({
            "a": [{"host": "api.example.com"}],
            "cname": [{"host": "cdn.example.com"}],
            "mx": [{"host": "mail.example.com"}],
            "ns": [{"host": "ns.example.com"}],
            "total_a_recs": 201
        }))
        .unwrap();
        assert_eq!(
            dnsdumpster_page_names(&response, "example.com"),
            BTreeSet::from([
                "api.example.com".to_owned(),
                "cdn.example.com".to_owned(),
                "mail.example.com".to_owned(),
                "ns.example.com".to_owned(),
            ])
        );
        assert_eq!(response.total_a_recs, Some(201));

        let http = reqwest::Client::new();
        let first = dnsdumpster_request(&http, "example.com", 1, "secret")
            .build()
            .unwrap();
        assert!(first.url().query().is_none());
        let second = dnsdumpster_request(&http, "example.com", 2, "secret")
            .build()
            .unwrap();
        assert_eq!(second.url().query(), Some("page=2"));
        assert_eq!(second.headers().get("X-API-Key").unwrap(), "secret");
    }

    #[test]
    fn viewdns_contract_uses_documented_pagination_and_scopes_names() {
        let envelope: ViewDnsEnvelope =
            serde_json::from_str(include_str!("../../tests/fixtures/viewdns-page.json")).unwrap();
        let response = envelope.response.unwrap();
        assert_eq!(
            flexible_usize(
                Some(&response.subdomain_count),
                "ViewDNS",
                "subdomain_count"
            )
            .unwrap(),
            3
        );
        assert_eq!(
            flexible_usize(Some(&response.total_pages), "ViewDNS", "total_pages").unwrap(),
            1
        );
        assert_eq!(
            viewdns_page_names(&response, "example.com"),
            BTreeSet::from([
                "api.example.com".to_owned(),
                "mail.dev.example.com".to_owned(),
            ])
        );

        let request = viewdns_request(&reqwest::Client::new(), "example.com", 2, "secret key/+")
            .build()
            .unwrap();
        assert_eq!(request.method(), reqwest::Method::GET);
        assert_eq!(request.url().host_str(), Some("api.viewdns.info"));
        assert_eq!(request.url().path(), "/subdomains/");
        let query = request
            .url()
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            query.get("domain").map(|value| value.as_ref()),
            Some("example.com")
        );
        assert_eq!(
            query.get("apikey").map(|value| value.as_ref()),
            Some("secret key/+")
        );
        assert_eq!(
            query.get("output").map(|value| value.as_ref()),
            Some("json")
        );
        assert_eq!(query.get("page").map(|value| value.as_ref()), Some("2"));
        assert_eq!(VIEWDNS_MAX_PAGES, 1_000);
    }

    #[test]
    fn viewdns_pagination_rejects_drift_and_accepts_empty_terminal_shapes() {
        let page = |current: Value, pages: Value, total: Value, subdomains: Vec<ViewDnsRecord>| {
            ViewDnsResponse {
                subdomain_count: total,
                total_pages: pages,
                current_page: current,
                subdomains,
                error: None,
            }
        };

        assert_eq!(
            viewdns_page_state(&page(json!(2), json!("3"), json!(2001), Vec::new()), 2).unwrap(),
            (2001, 3)
        );
        assert!(viewdns_page_state(&page(json!(1), json!(2), json!(10), Vec::new()), 2).is_err());
        assert!(viewdns_page_state(&page(json!(2), json!(1), json!(10), Vec::new()), 2).is_err());
        assert_eq!(
            viewdns_page_state(&page(json!(1), json!(0), json!(0), Vec::new()), 1).unwrap(),
            (0, 0)
        );
        assert!(viewdns_page_state(&page(json!(2), json!(0), json!(0), Vec::new()), 2).is_err());
        assert!(
            viewdns_page_state(
                &page(
                    json!(1),
                    json!(0),
                    json!(1),
                    vec![ViewDnsRecord {
                        name: "api.example.com".to_owned()
                    }]
                ),
                1
            )
            .is_err()
        );
        assert_eq!(
            viewdns_stable_count(None, 2_001, "subdomain_count").unwrap(),
            2_001
        );
        assert_eq!(
            viewdns_stable_count(Some(2_001), 2_001, "subdomain_count").unwrap(),
            2_001
        );
        assert!(viewdns_stable_count(Some(2_001), 2_002, "subdomain_count").is_err());
        assert!(viewdns_stable_count(Some(3), 2, "total_pages").is_err());
    }

    #[tokio::test]
    async fn viewdns_interruption_resumes_at_the_next_durable_page() {
        let db = Database::in_memory().unwrap();
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let first_requests_for_fetch = first_requests.clone();
        let first = super::super::enforce_source_budget_preserving_partial_with_sink(
            "viewdns",
            Duration::from_millis(20),
            collect_viewdns_pages("example.com", move |page| {
                first_requests_for_fetch.lock().unwrap().push(page);
                async move {
                    if page == 1 {
                        Ok(viewdns_fixture_page(1, 2, 2, &["api.example.com"]))
                    } else {
                        std::future::pending::<Result<ViewDnsEnvelope>>().await
                    }
                }
            }),
            usize::MAX,
            None,
            Some(viewdns_pagination_context(&db)),
        )
        .await
        .unwrap();
        assert!(first.partial_warning.is_some());
        assert_eq!(*first_requests.lock().unwrap(), vec![1, 2]);
        let contract = numeric_pagination_contract("viewdns", "example.com").unwrap();
        let interrupted = db
            .passive_pagination_resume(
                "example.com",
                "viewdns",
                contract.lane,
                contract.contract_version,
                &contract.query_hash,
            )
            .unwrap()
            .unwrap();
        assert_eq!(interrupted.next_position, 2);
        assert_eq!(interrupted.records_seen, 1);

        let repeated_requests = Arc::new(Mutex::new(Vec::new()));
        let repeated_requests_for_fetch = repeated_requests.clone();
        let repeated = super::super::enforce_source_budget_preserving_partial_with_sink(
            "viewdns",
            Duration::from_secs(1),
            collect_viewdns_pages("example.com", move |page| {
                repeated_requests_for_fetch.lock().unwrap().push(page);
                async move {
                    // The provider echoes page 2 but repeats the exact records
                    // already committed for page 1.
                    Ok(viewdns_fixture_page(page, 2, 2, &["api.example.com"]))
                }
            }),
            usize::MAX,
            None,
            Some(viewdns_pagination_context(&db)),
        )
        .await;
        assert!(repeated.is_err());
        assert_eq!(*repeated_requests.lock().unwrap(), vec![2]);

        let resumed_requests = Arc::new(Mutex::new(Vec::new()));
        let resumed_requests_for_fetch = resumed_requests.clone();
        let resumed = super::super::enforce_source_budget_preserving_partial_with_sink(
            "viewdns",
            Duration::from_secs(1),
            collect_viewdns_pages("example.com", move |page| {
                resumed_requests_for_fetch.lock().unwrap().push(page);
                async move {
                    match page {
                        2 => Ok(viewdns_fixture_page(2, 2, 2, &["www.example.com"])),
                        _ => bail!("unexpected ViewDNS page {page}"),
                    }
                }
            }),
            usize::MAX,
            None,
            Some(viewdns_pagination_context(&db)),
        )
        .await
        .unwrap();
        assert!(resumed.partial_warning.is_none());
        assert_eq!(*resumed_requests.lock().unwrap(), vec![2]);
        let completed = db
            .passive_pagination_resume(
                "example.com",
                "viewdns",
                contract.lane,
                contract.contract_version,
                &contract.query_hash,
            )
            .unwrap()
            .unwrap();
        assert!(completed.done);
        let after_crash = super::super::enforce_source_budget_preserving_partial_with_sink(
            "viewdns",
            Duration::from_secs(1),
            collect_viewdns_pages("example.com", |_| async {
                bail!("a completed lane must not contact the provider again")
            }),
            usize::MAX,
            None,
            Some(viewdns_pagination_context(&db)),
        )
        .await
        .unwrap();
        assert!(after_crash.names.is_empty());
        assert!(after_crash.partial_warning.is_none());
        db.complete_passive_pagination_source(
            "example.com",
            "viewdns",
            &[(
                contract.lane,
                contract.contract_version,
                contract.query_hash.as_str(),
            )],
        )
        .unwrap();
        assert!(
            db.passive_pagination_resume(
                "example.com",
                "viewdns",
                contract.lane,
                contract.contract_version,
                &contract.query_hash,
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            db.observation_names("example.com", "passive:viewdns")
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["api.example.com".to_owned(), "www.example.com".to_owned(),])
        );
    }

    #[tokio::test]
    async fn viewdns_valid_empty_page_advances_to_the_next_numeric_position() {
        let db = Database::in_memory().unwrap();
        let requested = Arc::new(Mutex::new(Vec::new()));
        let requested_for_fetch = requested.clone();
        let result = super::super::enforce_source_budget_preserving_partial_with_sink(
            "viewdns",
            Duration::from_secs(1),
            collect_viewdns_pages("example.com", move |page| {
                requested_for_fetch.lock().unwrap().push(page);
                async move {
                    match page {
                        1 => Ok(viewdns_fixture_page(1, 2, 1, &[])),
                        2 => Ok(viewdns_fixture_page(2, 2, 1, &["api.example.com"])),
                        _ => bail!("unexpected ViewDNS page {page}"),
                    }
                }
            }),
            usize::MAX,
            None,
            Some(viewdns_pagination_context(&db)),
        )
        .await
        .unwrap();
        assert_eq!(*requested.lock().unwrap(), vec![1, 2]);
        assert_eq!(result.names, BTreeSet::from(["api.example.com".to_owned()]));
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
