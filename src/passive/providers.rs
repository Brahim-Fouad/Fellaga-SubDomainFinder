//! Built-in unaffiliated passive providers and provider-specific parsers.

use super::catalog::{SourcePolicy, source_policy};
use super::config::ApiKeyStore;
use super::pagination::commit_result_page;
use super::transport::{
    MAX_EXTERNAL_BODY_BYTES, client, compact_external_error, ensure_external_host_allowed,
    ensure_external_request_allowed, response_bytes_limited_to, response_json, response_text,
    response_text_limited, same_http_origin, send_external, send_external_streaming,
    send_with_retry_for_source,
};
use crate::archive_intelligence::{ArchiveLimits, analyze_common_crawl_warc};
use crate::util::normalize_observed_name;
use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use futures_util::{StreamExt, TryStreamExt, stream};
use reqwest::header::{CONTENT_RANGE, RANGE};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as TokioMutex, Semaphore};
use url::Url;

static COMMONCRAWL_API: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static COMMONCRAWL_GATE: OnceLock<Semaphore> = OnceLock::new();
static COMMONCRAWL_LAST_REQUEST: OnceLock<TokioMutex<Option<Instant>>> = OnceLock::new();
pub(super) const COMMONCRAWL_INDEX_COUNT: usize = 5;
pub(super) const COMMONCRAWL_BLOCKS_PER_REQUEST: usize = 15;
pub(super) const COMMONCRAWL_MAX_PAGES: usize = 1_000;
pub(super) const COMMONCRAWL_MAX_RESULT_LINES: usize = 150_000;
pub(super) const COMMONCRAWL_MAX_BODY_BYTES: usize = 3 * MAX_EXTERNAL_BODY_BYTES;
pub(super) const COMMONCRAWL_WARC_SAMPLE_LIMIT: usize = 2;
pub(super) const COMMONCRAWL_MAX_WARC_MEMBER_BYTES: usize = 2 * 1024 * 1024;
pub(super) const COMMONCRAWL_MAX_WARC_DECOMPRESSED_BYTES: usize = 4 * 1024 * 1024;
pub(super) struct AbortOnDrop<T>(pub(super) tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn commoncrawl_endpoint_cache() -> &'static RwLock<Option<String>> {
    COMMONCRAWL_API.get_or_init(|| RwLock::new(None))
}

pub(super) fn validate_commoncrawl_endpoint(endpoint: &str) -> Result<Url> {
    let url = Url::parse(endpoint).context("URL d'index Common Crawl invalide")?;
    let authority = endpoint
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    if url.scheme() != "https"
        || url.host_str() != Some("index.commoncrawl.org")
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || authority.contains('@')
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("URL d'index Common Crawl non fiable");
    }
    Ok(url)
}

pub fn seed_commoncrawl_endpoint(endpoint: String) {
    let Ok(endpoint) = validate_commoncrawl_endpoint(&endpoint).map(|url| url.to_string()) else {
        return;
    };
    if let Ok(mut cached) = commoncrawl_endpoint_cache().write()
        && cached.is_none()
    {
        *cached = Some(endpoint);
    }
}

pub fn current_commoncrawl_endpoint() -> Option<String> {
    commoncrawl_endpoint_cache()
        .read()
        .ok()
        .and_then(|endpoint| endpoint.clone())
}

async fn throttle_commoncrawl() {
    let mut last_request = COMMONCRAWL_LAST_REQUEST
        .get_or_init(|| TokioMutex::new(None))
        .lock()
        .await;
    if let Some(last) = *last_request {
        let minimum_gap = Duration::from_secs(2);
        if last.elapsed() < minimum_gap {
            tokio::time::sleep(minimum_gap.saturating_sub(last.elapsed())).await;
        }
    }
    *last_request = Some(Instant::now());
}

#[derive(Debug, Deserialize)]
struct CrtRow {
    name_value: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CertSpotterIssuance {
    pub(super) id: String,
    #[serde(default)]
    pub(super) dns_names: Vec<String>,
}

pub(super) fn certspotter_next_after(
    page: &[CertSpotterIssuance],
    current_after: Option<&str>,
) -> Result<Option<String>> {
    let Some(last) = page.last() else {
        return Ok(None);
    };
    if last.id.trim().is_empty() {
        bail!("Cert Spotter: identifiant de pagination vide");
    }
    if current_after == Some(last.id.as_str()) {
        bail!("Cert Spotter: curseur de pagination répété");
    }
    Ok(Some(last.id.clone()))
}

#[derive(Debug, Deserialize)]
pub(super) struct CommonCrawlCollection {
    #[serde(default)]
    pub(super) id: String,
    #[serde(rename = "cdx-api")]
    pub(super) cdx_api: String,
}

fn commoncrawl_collection_year(id: &str) -> Option<&str> {
    id.split(|character: char| !character.is_ascii_digit())
        .find(|part| {
            part.len() == 4
                && part
                    .parse::<u16>()
                    .is_ok_and(|year| (2000..=2100).contains(&year))
        })
}

pub(super) fn select_commoncrawl_endpoints(collections: Vec<CommonCrawlCollection>) -> Vec<String> {
    let mut years = BTreeSet::new();
    let mut endpoints = Vec::new();
    let mut fallback = Vec::new();
    for collection in collections {
        let Ok(endpoint) = validate_commoncrawl_endpoint(&collection.cdx_api) else {
            continue;
        };
        let endpoint = endpoint.to_string();
        if let Some(year) = commoncrawl_collection_year(&collection.id)
            && years.insert(year.to_owned())
        {
            endpoints.push(endpoint.clone());
        }
        fallback.push(endpoint);
        if endpoints.len() == COMMONCRAWL_INDEX_COUNT {
            break;
        }
    }
    if endpoints.len() < COMMONCRAWL_INDEX_COUNT {
        for endpoint in fallback {
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
            if endpoints.len() == COMMONCRAWL_INDEX_COUNT {
                break;
            }
        }
    }
    endpoints
}

#[derive(Debug, Deserialize)]
struct CommonCrawlRow {
    url: String,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    offset: Option<CommonCrawlInteger>,
    #[serde(default)]
    length: Option<CommonCrawlInteger>,
    #[serde(default)]
    mime: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CommonCrawlInteger {
    Text(String),
    Number(u64),
}

impl CommonCrawlInteger {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Text(value) => value.parse().ok(),
            Self::Number(value) => Some(*value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CommonCrawlRecordRef {
    pub(super) url: String,
    pub(super) filename: String,
    pub(super) offset: u64,
    pub(super) length: usize,
}

#[derive(Debug, Default)]
pub(super) struct CommonCrawlPage {
    pub(super) names: BTreeSet<String>,
    pub(super) records: BTreeSet<CommonCrawlRecordRef>,
    pub(super) truncated: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct UrlscanResponse {
    results: Vec<UrlscanResult>,
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct UrlscanResult {
    pub(super) page: Option<UrlscanHost>,
    pub(super) task: Option<UrlscanHost>,
    #[serde(default)]
    pub(super) sort: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UrlscanHost {
    domain: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SubdomainAppResponse {
    subdomains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: Vec<VirusTotalDomain>,
    links: Option<VirusTotalLinks>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalDomain {
    id: String,
}

#[derive(Debug, Deserialize)]
struct VirusTotalLinks {
    next: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SecurityTrailsMeta {
    #[serde(default)]
    scroll_id: String,
}

#[derive(Debug, Deserialize)]
struct SecurityTrailsRecord {
    hostname: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SecurityTrailsResponse {
    #[serde(default)]
    meta: SecurityTrailsMeta,
    #[serde(default)]
    records: Vec<SecurityTrailsRecord>,
    #[serde(default)]
    subdomains: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WhoisXmlResponse {
    pub(super) result: Option<WhoisXmlResult>,
}

#[derive(Debug, Deserialize)]
pub(super) struct WhoisXmlResult {
    #[serde(default)]
    pub(super) records: Vec<WhoisXmlRecord>,
    #[serde(rename = "nextPageSearchAfter", default)]
    pub(super) next_page_search_after: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct WhoisXmlRecord {
    pub(super) domain: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct NetlasItem {
    pub(super) data: NetlasDomain,
}

#[derive(Debug, Deserialize)]
pub(super) struct NetlasDomain {
    pub(super) domain: String,
}

#[derive(Debug, Deserialize)]
struct NetlasCountResponse {
    count: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct NetlasDownloadRequest<'a> {
    pub(super) q: &'a str,
    pub(super) fields: [&'static str; 1],
    pub(super) source_type: &'static str,
    pub(super) size: usize,
}

pub(super) fn netlas_count_request(
    client: &reqwest::Client,
    query: &str,
    key: &str,
) -> reqwest::RequestBuilder {
    client
        .get("https://app.netlas.io/api/domains_count/")
        .query(&[("q", query)])
        .bearer_auth(key)
}

pub(super) fn netlas_download_request(
    client: &reqwest::Client,
    request: &NetlasDownloadRequest<'_>,
    key: &str,
) -> reqwest::RequestBuilder {
    client
        .post("https://app.netlas.io/api/domains/download/")
        .bearer_auth(key)
        .json(request)
}

pub(super) const NETLAS_DEFAULT_DOWNLOAD_LIMIT: usize = 200;
const NETLAS_MAX_DOWNLOAD_LIMIT: usize = 1_000_000;
pub(super) const NETLAS_DOWNLOAD_MAX_BYTES: usize = 16 * 1024 * 1024;
const NETLAS_DOWNLOAD_MAX_ITEM_BYTES: usize = 1024 * 1024;
pub(super) const NETLAS_CHECKPOINT_RECORDS: usize = 50;
pub(super) const SECURITYTRAILS_MAX_SCROLL_PAGES: usize = 1000;

pub(super) fn parse_netlas_download_limit(value: Option<&str>) -> Result<usize> {
    let Some(value) = value else {
        return Ok(NETLAS_DEFAULT_DOWNLOAD_LIMIT);
    };
    let limit = value
        .trim()
        .parse::<usize>()
        .context("FELLAGA_NETLAS_DOWNLOAD_LIMIT must be a positive integer")?;
    if !(1..=NETLAS_MAX_DOWNLOAD_LIMIT).contains(&limit) {
        bail!("FELLAGA_NETLAS_DOWNLOAD_LIMIT must be between 1 and {NETLAS_MAX_DOWNLOAD_LIMIT}");
    }
    Ok(limit)
}

fn netlas_download_limit() -> Result<usize> {
    match std::env::var("FELLAGA_NETLAS_DOWNLOAD_LIMIT") {
        Ok(value) => parse_netlas_download_limit(Some(&value)),
        Err(std::env::VarError::NotPresent) => parse_netlas_download_limit(None),
        Err(error) => Err(error).context("FELLAGA_NETLAS_DOWNLOAD_LIMIT is not valid Unicode"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetlasArrayState {
    Start,
    FirstItemOrEnd,
    NextItem,
    Item,
    CommaOrEnd,
    Done,
}

/// Incrementally decodes Netlas' top-level JSON array without retaining the
/// complete download in memory. Each record is still decoded strictly by
/// serde_json before it reaches the connector.
pub(super) struct NetlasArrayDecoder {
    state: NetlasArrayState,
    item: Vec<u8>,
    depth: usize,
    in_string: bool,
    escaped: bool,
    decoded: usize,
    max_items: usize,
    max_item_bytes: usize,
}

impl NetlasArrayDecoder {
    pub(super) fn new(max_items: usize, max_item_bytes: usize) -> Self {
        Self {
            state: NetlasArrayState::Start,
            item: Vec::new(),
            depth: 0,
            in_string: false,
            escaped: false,
            decoded: 0,
            max_items,
            max_item_bytes,
        }
    }

    pub(super) fn push<F>(&mut self, bytes: &[u8], visit: &mut F) -> Result<()>
    where
        F: FnMut(NetlasItem) -> Result<()>,
    {
        for &byte in bytes {
            match self.state {
                NetlasArrayState::Start => {
                    if byte.is_ascii_whitespace() {
                        continue;
                    }
                    if byte != b'[' {
                        bail!("Netlas: download is not a JSON array");
                    }
                    self.state = NetlasArrayState::FirstItemOrEnd;
                }
                NetlasArrayState::FirstItemOrEnd => {
                    if byte.is_ascii_whitespace() {
                        continue;
                    }
                    if byte == b']' {
                        self.state = NetlasArrayState::Done;
                    } else {
                        self.start_item(byte)?;
                    }
                }
                NetlasArrayState::NextItem => {
                    if byte.is_ascii_whitespace() {
                        continue;
                    }
                    self.start_item(byte)?;
                }
                NetlasArrayState::Item => self.push_item_byte(byte, visit)?,
                NetlasArrayState::CommaOrEnd => {
                    if byte.is_ascii_whitespace() {
                        continue;
                    }
                    match byte {
                        b',' => self.state = NetlasArrayState::NextItem,
                        b']' => self.state = NetlasArrayState::Done,
                        _ => bail!("Netlas: invalid delimiter in download array"),
                    }
                }
                NetlasArrayState::Done => {
                    if !byte.is_ascii_whitespace() {
                        bail!("Netlas: trailing data after download array");
                    }
                }
            }
        }
        Ok(())
    }

    fn start_item(&mut self, byte: u8) -> Result<()> {
        if byte != b'{' {
            bail!("Netlas: download array contains a non-object item");
        }
        self.item.clear();
        self.item.push(byte);
        self.depth = 1;
        self.in_string = false;
        self.escaped = false;
        self.state = NetlasArrayState::Item;
        Ok(())
    }

    fn push_item_byte<F>(&mut self, byte: u8, visit: &mut F) -> Result<()>
    where
        F: FnMut(NetlasItem) -> Result<()>,
    {
        if self.item.len() >= self.max_item_bytes {
            bail!("Netlas: one download record exceeds the size limit");
        }
        self.item.push(byte);
        if self.in_string {
            if self.escaped {
                self.escaped = false;
            } else if byte == b'\\' {
                self.escaped = true;
            } else if byte == b'"' {
                self.in_string = false;
            }
            return Ok(());
        }
        match byte {
            b'"' => self.in_string = true,
            b'{' | b'[' => self.depth = self.depth.saturating_add(1),
            b'}' | b']' => {
                self.depth = self
                    .depth
                    .checked_sub(1)
                    .context("Netlas: unbalanced JSON download record")?;
                if self.depth == 0 {
                    self.decoded = self.decoded.saturating_add(1);
                    if self.decoded > self.max_items {
                        bail!("Netlas: download returned more records than requested");
                    }
                    let item = serde_json::from_slice(&self.item)
                        .context("Netlas: invalid JSON download record")?;
                    visit(item)?;
                    self.item.clear();
                    self.state = NetlasArrayState::CommaOrEnd;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<()> {
        if self.state != NetlasArrayState::Done {
            bail!("Netlas: truncated JSON download array");
        }
        Ok(())
    }
}

pub(super) fn ordered_crtsh_postgres_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> Vec<IpAddr> {
    let mut addresses = addresses.into_iter().collect::<Vec<_>>();
    addresses.sort_by_key(|address| (address.is_ipv6(), address.ip()));
    addresses.dedup_by_key(|address| address.ip());
    addresses
        .into_iter()
        .map(|address| address.ip())
        .take(8)
        .collect()
}

async fn crtsh_postgres(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    ensure_external_host_allowed("crt.sh")?;
    let addresses = ordered_crtsh_postgres_addresses(
        tokio::net::lookup_host(("crt.sh", 5_432))
            .await
            .context("résolution du service PostgreSQL crt.sh")?,
    );
    if addresses.is_empty() {
        bail!("résolution du service PostgreSQL crt.sh sans adresse");
    }
    let mut config = tokio_postgres::Config::new();
    for address in addresses {
        config.host("crt.sh").hostaddr(address);
    }
    config
        .user("guest")
        .dbname("certwatch")
        .connect_timeout(timeout.min(Duration::from_secs(10)));
    let statement_timeout_ms = timeout.as_millis().clamp(1, 30_000);
    config.options(format!("-c statement_timeout={statement_timeout_ms}"));
    let (database, connection) = config
        .connect(tokio_postgres::NoTls)
        .await
        .context("connexion PostgreSQL publique crt.sh")?;
    let _connection_task = AbortOnDrop(tokio::spawn(connection));
    let query = r#"SELECT DISTINCT cai.NAME_VALUE
        FROM certificate_and_identities cai
        WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
          AND cai.NAME_VALUE ILIKE ('%' || $1 || '%')"#;
    let search = domain.to_owned();
    let parameter: &(dyn tokio_postgres::types::ToSql + Sync) = &search;
    let rows = database
        .query_raw(query, std::iter::once(parameter))
        .await
        .context("requête PostgreSQL crt.sh")?;
    futures_util::pin_mut!(rows);
    let mut names = BTreeSet::new();
    let mut batch = BTreeSet::new();
    while let Some(row) = rows.try_next().await.context("flux PostgreSQL crt.sh")? {
        let values: String = row.try_get(0).context("ligne PostgreSQL crt.sh")?;
        for value in values.lines() {
            if let Some(name) = normalize_observed_name(value, domain) {
                batch.insert(name);
            }
        }
        if batch.len() >= 1_000 {
            commit_result_page(&mut names, std::mem::take(&mut batch));
        }
    }
    commit_result_page(&mut names, batch);
    drop(database);
    Ok(names)
}

async fn crtsh_http(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let policy = source_policy("crtsh");
    let response = send_with_retry_for_source(
        "crtsh",
        client
            .get("https://crt.sh/")
            .query(&[("q", format!("%.{domain}")), ("output", "json".to_owned())]),
        policy.attempts,
        policy.base_backoff,
        domain,
    )
    .await
    .context("connexion à crt.sh après backoff")?;
    let rows = response_json::<Vec<CrtRow>>(response, "crt.sh").await?;
    Ok(rows
        .into_iter()
        .flat_map(|row| {
            row.name_value
                .lines()
                .filter_map(|name| normalize_observed_name(name, domain))
                .collect::<Vec<_>>()
        })
        .collect())
}

pub(super) fn crtsh_http_head_start(timeout: Duration) -> Duration {
    timeout.min(Duration::from_secs(8))
}

pub(super) async fn crtsh(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let http_budget = crtsh_http_head_start(timeout);
    let http_error = match tokio::time::timeout(http_budget, crtsh_http(domain, http_budget)).await
    {
        Ok(Ok(names)) => return Ok(names),
        Ok(Err(error)) => compact_external_error(&format!("{error:#}")),
        Err(_) => format!(
            "HTTP crt.sh exceeded its {:.1}s head start",
            http_budget.as_secs_f64()
        ),
    };
    let postgres_budget = timeout.saturating_sub(http_budget);
    if postgres_budget.is_zero() {
        bail!("crt.sh HTTP failed without PostgreSQL fallback budget: {http_error}");
    }
    match tokio::time::timeout(postgres_budget, crtsh_postgres(domain, postgres_budget)).await {
        Ok(result) => result
            .with_context(|| format!("fallback PostgreSQL crt.sh après échec HTTP: {http_error}")),
        Err(_) => bail!(
            "fallback PostgreSQL crt.sh exceeded its remaining {:.1}s budget after HTTP failure: {http_error}",
            postgres_budget.as_secs_f64()
        ),
    }
}

pub(super) async fn certspotter(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let token = keys.optional("certspotter");
    let mut after: Option<String> = None;
    let mut names = BTreeSet::new();
    for page_index in 0..1_000 {
        let mut request = client
            .get("https://api.certspotter.com/v1/issuances")
            .query(&[
                ("domain", domain),
                ("include_subdomains", "true"),
                ("expand", "dns_names"),
            ]);
        if let Some(after) = &after {
            request = request.query(&[("after", after)]);
        }
        if let Some(token) = &token {
            request = request.bearer_auth(token);
        }
        let page = match send_external("certspotter", request, domain).await {
            Ok(response) => {
                match response_json::<Vec<CertSpotterIssuance>>(response, "Cert Spotter").await {
                    Ok(page) => page,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error).context("connexion à Cert Spotter"),
        };
        if page.is_empty() {
            break;
        }
        let next_after = certspotter_next_after(&page, after.as_deref())?;
        after = next_after;
        let mut page_names = BTreeSet::new();
        for issuance in page {
            for dns_name in issuance.dns_names {
                if let Some(name) = normalize_observed_name(&dns_name, domain) {
                    page_names.insert(name);
                }
            }
        }
        commit_result_page(&mut names, page_names);
        if page_index + 1 == 1_000 {
            bail!("Cert Spotter: limite de pagination atteinte avec une page supplémentaire");
        }
    }
    Ok(names)
}

pub(super) async fn hackertarget(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let mut request = client
        .get("https://api.hackertarget.com/hostsearch/")
        .query(&[("q", domain)]);
    if let Some(token) = keys.optional("hackertarget") {
        request = request.query(&[("apikey", token)]);
    }
    let response = send_external("hackertarget", request, domain)
        .await
        .context("connexion à HackerTarget")?;
    let response = response_text(response, "HackerTarget").await?;
    let lowered = response.to_ascii_lowercase();
    if lowered.starts_with("error") || lowered.contains("api count exceeded") {
        bail!("HackerTarget: {}", response.trim());
    }
    Ok(response
        .lines()
        .filter_map(|line| line.split(',').next())
        .filter_map(|name| normalize_observed_name(name, domain))
        .collect())
}

pub(super) fn hostname_from_url(value: &str, domain: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .and_then(|hostname| normalize_observed_name(&hostname, domain))
}

fn commoncrawl_filename_is_safe(filename: &str) -> bool {
    filename.starts_with("crawl-data/")
        && !filename.contains('\\')
        && filename
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."))
}

fn commoncrawl_row_is_textual(row: &CommonCrawlRow) -> bool {
    let mime = row.mime.as_deref().unwrap_or_default().to_ascii_lowercase();
    if mime.starts_with("text/")
        || mime.contains("javascript")
        || mime.contains("json")
        || mime.contains("xml")
    {
        return true;
    }
    Url::parse(&row.url).ok().is_some_and(|url| {
        let path = url.path().to_ascii_lowercase();
        [".html", ".htm", ".js", ".mjs", ".json", ".map", ".xml"]
            .iter()
            .any(|suffix| path.ends_with(suffix))
    })
}

pub(super) fn commoncrawl_content_range_matches(
    value: &str,
    expected_start: u64,
    expected_end: u64,
) -> bool {
    let mut fields = value.split_ascii_whitespace();
    let Some(unit) = fields.next() else {
        return false;
    };
    let Some(range_and_size) = fields.next() else {
        return false;
    };
    if !unit.eq_ignore_ascii_case("bytes") || fields.next().is_some() {
        return false;
    }
    let Some((range, total)) = range_and_size.split_once('/') else {
        return false;
    };
    let Some((start, end)) = range.split_once('-') else {
        return false;
    };
    let Ok(start) = start.parse::<u64>() else {
        return false;
    };
    let Ok(end) = end.parse::<u64>() else {
        return false;
    };
    let valid_total = total == "*" || total.parse::<u64>().is_ok_and(|total| total > expected_end);
    start == expected_start && end == expected_end && expected_start <= expected_end && valid_total
}

pub(super) fn parse_commoncrawl_page(body: &str, domain: &str) -> Result<CommonCrawlPage> {
    parse_commoncrawl_page_bounded(body, domain, COMMONCRAWL_MAX_RESULT_LINES)
}

pub(super) fn parse_commoncrawl_page_bounded(
    body: &str,
    domain: &str,
    max_result_lines: usize,
) -> Result<CommonCrawlPage> {
    let mut page = CommonCrawlPage::default();
    let mut valid = 0_usize;
    let mut invalid = 0_usize;
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if valid.saturating_add(invalid) >= max_result_lines {
            page.truncated = true;
            break;
        }
        match serde_json::from_str::<CommonCrawlRow>(line) {
            Ok(row) => {
                valid = valid.saturating_add(1);
                if let Some(name) = hostname_from_url(&row.url, domain) {
                    page.names.insert(name);
                    let record = row
                        .filename
                        .as_deref()
                        .filter(|filename| commoncrawl_filename_is_safe(filename))
                        .zip(row.offset.as_ref().and_then(CommonCrawlInteger::value))
                        .zip(row.length.as_ref().and_then(CommonCrawlInteger::value))
                        .and_then(|((filename, offset), length)| {
                            let length = usize::try_from(length).ok()?;
                            (length > 0
                                && length <= COMMONCRAWL_MAX_WARC_MEMBER_BYTES
                                && offset.checked_add(length as u64).is_some()
                                && commoncrawl_row_is_textual(&row))
                            .then(|| CommonCrawlRecordRef {
                                url: row.url.clone(),
                                filename: filename.to_owned(),
                                offset,
                                length,
                            })
                        });
                    if let Some(record) = record {
                        page.records.insert(record);
                    }
                }
            }
            Err(_) => invalid = invalid.saturating_add(1),
        }
    }
    let total = valid.saturating_add(invalid);
    if invalid > 0 && (valid == 0 || invalid > 10 && invalid.saturating_mul(20) > total) {
        bail!(
            "index Common Crawl: format NDJSON incohérent ({invalid}/{total} ligne(s) invalides)"
        );
    }
    Ok(page)
}

#[cfg(test)]
pub(super) fn parse_commoncrawl_rows(body: &str, domain: &str) -> Result<BTreeSet<String>> {
    Ok(parse_commoncrawl_page(body, domain)?.names)
}

async fn load_commoncrawl_endpoints(
    client: &reqwest::Client,
    policy: SourcePolicy,
    seed: &str,
) -> Result<Vec<String>> {
    throttle_commoncrawl().await;
    let response = send_with_retry_for_source(
        "commoncrawl",
        client.get("https://index.commoncrawl.org/collinfo.json"),
        policy.attempts,
        policy.base_backoff,
        seed,
    )
    .await
    .context("connexion à Common Crawl")?;
    let collections = response_json::<Vec<CommonCrawlCollection>>(response, "Common Crawl").await?;
    let endpoints = select_commoncrawl_endpoints(collections);
    let endpoint = endpoints
        .first()
        .context("aucune collection Common Crawl")?;
    if let Ok(mut cached) = commoncrawl_endpoint_cache().write() {
        *cached = Some(endpoint.clone());
    }
    Ok(endpoints)
}

async fn query_commoncrawl(
    client: &reqwest::Client,
    endpoint: &str,
    domain: &str,
    policy: SourcePolicy,
    page: usize,
    page_size: usize,
) -> Result<reqwest::Response> {
    let endpoint = validate_commoncrawl_endpoint(endpoint)?;
    throttle_commoncrawl().await;
    send_with_retry_for_source(
        "commoncrawl",
        client.get(endpoint).query(&[
            ("url", domain),
            ("matchType", "domain"),
            ("output", "json"),
            ("fl", "url,filename,offset,length,mime"),
            ("filter", "status:200"),
            ("collapse", "urlkey"),
            ("pageSize", &page_size.to_string()),
            ("page", &page.to_string()),
        ]),
        policy.attempts,
        policy.base_backoff,
        domain,
    )
    .await
}

async fn fetch_commoncrawl_warc_names(
    client: &reqwest::Client,
    record: &CommonCrawlRecordRef,
    domain: &str,
) -> Result<BTreeSet<String>> {
    let base = Url::parse("https://data.commoncrawl.org/")?;
    let url = base.join(&record.filename)?;
    if url.scheme() != "https"
        || url.host_str() != Some("data.commoncrawl.org")
        || !url.path().starts_with("/crawl-data/")
    {
        bail!("Common Crawl WARC: chemin d'archive non fiable");
    }
    let end = record
        .offset
        .checked_add(record.length.saturating_sub(1) as u64)
        .context("Common Crawl WARC: plage d'octets invalide")?;
    throttle_commoncrawl().await;
    let request = client
        .get(url.clone())
        .header(RANGE, format!("bytes={}-{}", record.offset, end));
    ensure_external_request_allowed(&request)?;
    let response = request
        .send()
        .await
        .with_context(|| format!("connexion à l'archive Common Crawl {url}"))?;
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        bail!(
            "Common Crawl WARC: HTTP {} au lieu d'une réponse partielle",
            response.status()
        );
    }
    let range_matches = response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| commoncrawl_content_range_matches(value, record.offset, end));
    if !range_matches {
        bail!("Common Crawl WARC: Content-Range absent ou différent de la plage demandée");
    }
    let (_, compressed) = response_bytes_limited_to(
        response,
        "archive Common Crawl",
        COMMONCRAWL_MAX_WARC_MEMBER_BYTES,
    )
    .await?;
    if compressed.len() != record.length {
        bail!(
            "Common Crawl WARC: membre tronqué ({} octets reçus, {} attendus)",
            compressed.len(),
            record.length
        );
    }
    let limits = ArchiveLimits {
        max_archive_bytes: COMMONCRAWL_MAX_WARC_DECOMPRESSED_BYTES,
        max_record_bytes: COMMONCRAWL_MAX_WARC_DECOMPRESSED_BYTES,
        max_header_bytes: 64 * 1024,
        max_records: 1,
        max_document_bytes: 1024 * 1024,
        max_analysis_bytes: 8 * 1024 * 1024,
        max_names: 4_096,
        max_evidence: 8_192,
        max_urls: 512,
        max_js_literals: 4_096,
        max_string_bytes: 4_096,
        max_json_values: 32_768,
    };
    let archive_source = format!("commoncrawl:{}@{}", record.filename, record.offset);
    let discovery = analyze_common_crawl_warc(
        GzDecoder::new(compressed.as_slice()),
        domain,
        &archive_source,
        limits,
    )
    .with_context(|| format!("analyse WARC de {}", record.url))?;
    Ok(discovery.names)
}

pub(super) async fn commoncrawl(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let policy = source_policy("commoncrawl");
    let client = client(timeout)?;
    let _permit = COMMONCRAWL_GATE
        .get_or_init(|| Semaphore::new(1))
        .acquire()
        .await
        .context("limiteur Common Crawl fermé")?;
    let endpoints = match load_commoncrawl_endpoints(&client, policy, domain).await {
        Ok(endpoints) => endpoints,
        Err(error) => match current_commoncrawl_endpoint() {
            Some(endpoint) => vec![endpoint],
            None => return Err(error),
        },
    };
    let mut names = BTreeSet::new();
    let mut warc_records = BTreeSet::new();
    let mut successful_requests = 0_usize;
    let mut errors = Vec::new();
    // Walk the selected yearly indexes breadth-first. This gives every year a
    // useful first page before the source wall-clock budget is spent on deeper
    // blocks from a single collection.
    let mut endpoints = endpoints
        .into_iter()
        .map(|endpoint| (endpoint, true))
        .collect::<Vec<_>>();
    for page in 0..COMMONCRAWL_MAX_PAGES {
        let mut queried = false;
        for (endpoint, active) in &mut endpoints {
            if !*active {
                continue;
            }
            queried = true;
            let response = match query_commoncrawl(
                &client,
                endpoint,
                domain,
                policy,
                page,
                COMMONCRAWL_BLOCKS_PER_REQUEST,
            )
            .await
            {
                Ok(response) => response,
                Err(error) => {
                    errors.push(format!("{endpoint} page {page}: {error:#}"));
                    *active = false;
                    continue;
                }
            };
            if matches!(
                response.status(),
                reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
            ) {
                *active = false;
                continue;
            }
            match response_text_limited(response, "index Common Crawl", COMMONCRAWL_MAX_BODY_BYTES)
                .await
            {
                Ok(body) => {
                    if body.trim().is_empty() {
                        successful_requests += 1;
                        *active = false;
                        continue;
                    }
                    match parse_commoncrawl_page(&body, domain) {
                        Ok(parsed_page) => {
                            successful_requests += 1;
                            let truncated = parsed_page.truncated;
                            commit_result_page(&mut names, parsed_page.names);
                            let remaining = COMMONCRAWL_WARC_SAMPLE_LIMIT
                                .saturating_mul(4)
                                .saturating_sub(warc_records.len());
                            warc_records.extend(parsed_page.records.into_iter().take(remaining));
                            if truncated {
                                errors.push(format!(
                                    "{endpoint} page {page}: plus de {COMMONCRAWL_MAX_RESULT_LINES} lignes de résultats"
                                ));
                                *active = false;
                            }
                        }
                        Err(error) => {
                            errors.push(format!("{endpoint} page {page}: {error:#}"));
                            *active = false;
                        }
                    }
                }
                Err(error) => {
                    errors.push(format!("{endpoint} page {page}: {error:#}"));
                    *active = false;
                }
            }
        }
        if !queried || endpoints.iter().all(|(_, active)| !*active) {
            break;
        }
        if page + 1 == COMMONCRAWL_MAX_PAGES {
            errors.push(
                "Common Crawl: limite de pagination atteinte avec des index encore actifs"
                    .to_owned(),
            );
        }
    }
    let mut sampled_urls = BTreeSet::new();
    let mut sampled = 0_usize;
    for record in warc_records {
        if sampled >= COMMONCRAWL_WARC_SAMPLE_LIMIT || !sampled_urls.insert(record.url.clone()) {
            continue;
        }
        sampled += 1;
        if let Ok(archive_names) = fetch_commoncrawl_warc_names(&client, &record, domain).await {
            commit_result_page(&mut names, archive_names);
        }
    }
    if successful_requests == 0 {
        bail!("Common Crawl: {}", errors.join(" | "));
    }
    if !errors.is_empty() {
        bail!("Common Crawl partiel: {}", errors.join(" | "));
    }
    Ok(names)
}

#[cfg(test)]
pub(super) fn parse_wayback_rows(rows: Vec<Vec<String>>, domain: &str) -> BTreeSet<String> {
    parse_wayback_page(rows, domain).names
}

#[derive(Debug, Default)]
pub(super) struct WaybackPage {
    pub(super) names: BTreeSet<String>,
    pub(super) resume_key: Option<String>,
}

pub(super) fn parse_wayback_page(rows: Vec<Vec<String>>, domain: &str) -> WaybackPage {
    let mut page = WaybackPage::default();
    let mut resume_follows = false;
    for row in rows.into_iter().skip(1) {
        if row.is_empty() {
            resume_follows = true;
            continue;
        }
        if resume_follows {
            if let Some(encoded) = row.first() {
                let parameter = format!("resume={encoded}");
                page.resume_key = url::form_urlencoded::parse(parameter.as_bytes())
                    .next()
                    .map(|(_, value)| value.into_owned());
            }
            break;
        }
        if let Some(url) = row.first()
            && let Some(host) = hostname_from_url(url, domain)
        {
            page.names.insert(host);
        }
    }
    page
}

async fn query_wayback_page(
    client: &reqwest::Client,
    domain: &str,
    from: Option<&str>,
    to: Option<&str>,
    resume_key: Option<&str>,
    limit: usize,
) -> Result<WaybackPage> {
    let mut query = vec![
        ("url", domain.to_owned()),
        ("matchType", "domain".to_owned()),
        ("output", "json".to_owned()),
        ("fl", "original".to_owned()),
        ("collapse", "urlkey".to_owned()),
        ("filter", "statuscode:200".to_owned()),
        ("limit", limit.to_string()),
        ("showResumeKey", "true".to_owned()),
        ("gzip", "false".to_owned()),
    ];
    if let Some(from) = from {
        query.push(("from", from.to_owned()));
    }
    if let Some(to) = to {
        query.push(("to", to.to_owned()));
    }
    if let Some(resume_key) = resume_key {
        query.push(("resumeKey", resume_key.to_owned()));
    }
    let response = send_with_retry_for_source(
        "wayback",
        client
            .get("https://web.archive.org/cdx/search/cdx")
            .query(&query),
        1,
        Duration::from_secs(1),
        domain,
    )
    .await
    .context("connexion à Wayback CDX")?;
    let rows = response_json::<Vec<Vec<String>>>(response, "Wayback CDX").await?;
    Ok(parse_wayback_page(rows, domain))
}

async fn query_wayback_window(
    client: &reqwest::Client,
    domain: &str,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut resume_key = None;
    let mut seen = BTreeSet::new();
    for page_index in 0..1_000 {
        let page =
            query_wayback_page(client, domain, from, to, resume_key.as_deref(), 10_000).await?;
        commit_result_page(&mut names, page.names);
        let Some(next) = page.resume_key else {
            return Ok(names);
        };
        if next.len() > 4_096 || !seen.insert(next.clone()) {
            bail!("Wayback CDX: clé de reprise invalide ou répétée");
        }
        if page_index + 1 == 1_000 {
            bail!("Wayback CDX: limite de pagination atteinte avec une clé de reprise");
        }
        resume_key = Some(next);
    }
    Ok(names)
}

pub(super) async fn wayback(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let primary = query_wayback_window(&client(timeout)?, domain, None, None).await;
    let primary_error = match primary {
        Ok(names) => return Ok(names),
        Err(error) => format!("{error:#}"),
    };

    let fallback_timeout = timeout.min(Duration::from_secs(20));
    let fallback_client = client(fallback_timeout)?;
    let domain_owned = domain.to_owned();
    let windows = [
        (Some("20240101"), None),
        (Some("20180101"), Some("20231231")),
        (Some("20100101"), Some("20171231")),
        (Some("19960101"), Some("20091231")),
    ];
    let mut pending = stream::iter(windows)
        .map(|(from, to)| {
            let client = fallback_client.clone();
            let domain = domain_owned.clone();
            async move { query_wayback_window(&client, &domain, from, to).await }
        })
        .buffer_unordered(4);
    let mut names = BTreeSet::new();
    let mut completed = 0_usize;
    let mut errors = Vec::new();
    while let Some(result) = pending.next().await {
        match result {
            Ok(window_names) => {
                completed += 1;
                commit_result_page(&mut names, window_names);
            }
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    if completed > 0 {
        if errors.is_empty() {
            return Ok(names);
        }
        bail!(
            "Wayback partiel après échec de la requête complète ({primary_error}): {} fenêtre(s) terminée(s), {}",
            completed,
            errors.join(" | ")
        );
    }
    bail!(
        "Wayback complet puis fenêtres temporelles indisponibles: {primary_error}; {}",
        errors.join(" | ")
    )
}

pub(super) async fn urlscan(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let token = keys.optional("urlscan");
    let mut names = BTreeSet::new();
    let mut search_after: Option<String> = None;
    for page_index in 0..1_000 {
        let mut query = vec![
            (
                "q",
                format!("(page.domain:{domain} OR task.domain:{domain})"),
            ),
            ("size", "1000".to_owned()),
        ];
        if let Some(value) = &search_after {
            query.push(("search_after", value.clone()));
        }
        let mut request = client
            .get("https://urlscan.io/api/v1/search/")
            .query(&query);
        if let Some(token) = &token {
            request = request.header("api-key", token);
        }
        let response = match send_external("urlscan", request, domain).await {
            Ok(response) => match response_json::<UrlscanResponse>(response, "urlscan").await {
                Ok(response) => response,
                Err(error) => return Err(error),
            },
            Err(error) => return Err(error).context("connexion à urlscan"),
        };
        let has_more = response.has_more;
        let next = response.results.last().and_then(urlscan_search_after);
        let mut page_names = BTreeSet::new();
        for result in response.results {
            for host in [result.page, result.task].into_iter().flatten() {
                if let Some(name) = host
                    .domain
                    .as_deref()
                    .and_then(|name| normalize_observed_name(name, domain))
                    .or_else(|| {
                        host.url
                            .as_deref()
                            .and_then(|url| hostname_from_url(url, domain))
                    })
                {
                    page_names.insert(name);
                }
            }
        }
        commit_result_page(&mut names, page_names);
        if !has_more {
            return Ok(names);
        }
        if next.is_none() {
            bail!("urlscan: has_more=true sans curseur search_after");
        }
        if next == search_after {
            bail!("urlscan: curseur de pagination répété");
        }
        if page_index + 1 == 1_000 {
            bail!("urlscan: limite de pagination atteinte avec un curseur suivant");
        }
        search_after = next;
    }
    Ok(names)
}

pub(super) fn urlscan_search_after(result: &UrlscanResult) -> Option<String> {
    let values = result
        .sort
        .iter()
        .filter_map(|value| match value {
            serde_json::Value::String(value) => Some(value.clone()),
            serde_json::Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(","))
}

pub(super) async fn anubisdb(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let response = send_external(
        "anubisdb",
        client(timeout)?.get(format!("https://anubisdb.com/subdomains/{domain}")),
        domain,
    )
    .await
    .context("connexion à Anubis DB")?;
    let names = response_json::<Vec<String>>(response, "Anubis DB").await?;
    Ok(names
        .into_iter()
        .filter_map(|name| normalize_observed_name(&name, domain))
        .collect())
}

pub(super) async fn subdomainapp(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let response = send_external(
        "subdomainapp",
        client(timeout)?
            .get("https://api.subdomain.app/v1/query")
            .query(&[("domain", domain)]),
        domain,
    )
    .await
    .context("connexion à subdomain.app")?;
    let response = response_json::<SubdomainAppResponse>(response, "subdomain.app").await?;
    Ok(response
        .subdomains
        .into_iter()
        .filter_map(|name| normalize_observed_name(&name, domain))
        .collect())
}

pub(super) async fn virustotal(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("virustotal")?;
    let client = client(timeout)?;
    let mut next = Some(format!(
        "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    ));
    let mut visited = BTreeSet::new();
    let mut names = BTreeSet::new();
    for _ in 0..1_000 {
        let Some(url) = next.take() else {
            break;
        };
        if !trusted_pagination_url(&url, "www.virustotal.com", "/api/v3/domains/") {
            bail!("VirusTotal a renvoyé une URL de pagination non fiable");
        }
        if !visited.insert(url.clone()) {
            bail!("VirusTotal a renvoyé une URL de pagination répétée");
        }
        let response = match send_external(
            "virustotal",
            client.get(url).header("x-apikey", &token),
            domain,
        )
        .await
        {
            Ok(response) => {
                match response_json::<VirusTotalResponse>(response, "VirusTotal").await {
                    Ok(response) => response,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error).context("connexion à VirusTotal"),
        };
        let page_names = response
            .data
            .into_iter()
            .filter_map(|item| normalize_observed_name(&item.id, domain))
            .collect();
        commit_result_page(&mut names, page_names);
        next = response.links.and_then(|links| links.next);
    }
    if next.is_some() {
        bail!("VirusTotal: limite de pagination atteinte avec une page suivante");
    }
    Ok(names)
}

pub(super) fn trusted_pagination_url(url: &str, expected_host: &str, expected_path: &str) -> bool {
    Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some(expected_host)
            && url.port_or_known_default() == Some(443)
            && url.path().starts_with(expected_path)
            && url.username().is_empty()
            && url.password().is_none()
    })
}

pub(super) async fn whoisxml(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let key = keys.pick("whoisxml")?;
    let mut search_after = String::new();
    let mut names = BTreeSet::new();
    for page_index in 0..1_000 {
        let mut query = vec![
            ("apiKey", key.clone()),
            ("domainName", domain.to_owned()),
            ("outputFormat", "JSON".to_owned()),
        ];
        if !search_after.is_empty() {
            query.push(("searchAfter", search_after.clone()));
        }
        let response = send_external(
            "whoisxml",
            client
                .get("https://subdomains.whoisxmlapi.com/api/v2")
                .query(&query),
            domain,
        )
        .await
        .context("connexion à WhoisXML Subdomains Lookup")?;
        let page = response_json::<WhoisXmlResponse>(response, "WhoisXML").await?;
        let Some(result) = page.result else {
            break;
        };
        let page_names = result
            .records
            .into_iter()
            .filter_map(|record| normalize_observed_name(&record.domain, domain))
            .collect();
        commit_result_page(&mut names, page_names);
        if result.next_page_search_after.is_empty() {
            break;
        }
        if result.next_page_search_after == search_after {
            bail!("WhoisXML: curseur de pagination répété");
        }
        if page_index + 1 == 1_000 {
            bail!("WhoisXML: limite de pagination atteinte avec un curseur suivant");
        }
        search_after = result.next_page_search_after;
    }
    Ok(names)
}

pub(super) async fn netlas(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let key = keys.pick("netlas")?;
    let query = format!("domain:*.{domain} AND NOT domain:{domain}");

    let count_response = send_external("netlas", netlas_count_request(&http, &query, &key), domain)
        .await
        .context("connexion au compteur de domaines Netlas")?;
    let count = response_json::<NetlasCountResponse>(count_response, "Netlas count")
        .await?
        .count;
    let configured_limit = netlas_download_limit()?;
    let requested = count.min(configured_limit);
    if requested == 0 {
        return Ok(BTreeSet::new());
    }

    let request = NetlasDownloadRequest {
        q: &query,
        fields: ["domain"],
        source_type: "include",
        size: requested,
    };
    let mut response = send_external_streaming(
        "netlas",
        netlas_download_request(&http, &request, &key),
        domain,
    )
    .await
    .context("connexion au téléchargement de domaines Netlas")?;
    if !response.status().is_success() {
        let (status, body) =
            response_bytes_limited_to(response, "Netlas download", 64 * 1024).await?;
        bail!(
            "Netlas download: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > NETLAS_DOWNLOAD_MAX_BYTES as u64)
    {
        bail!("Netlas: download response exceeds the size limit");
    }

    let mut names = BTreeSet::new();
    let mut page_names = BTreeSet::new();
    let mut records_since_checkpoint = 0_usize;
    let mut decoder = NetlasArrayDecoder::new(requested, NETLAS_DOWNLOAD_MAX_ITEM_BYTES);
    let mut total_bytes = 0_usize;
    let finish_result;
    {
        let mut visit = |item: NetlasItem| -> Result<()> {
            records_since_checkpoint = records_since_checkpoint.saturating_add(1);
            if let Some(name) = normalize_observed_name(&item.data.domain, domain) {
                page_names.insert(name);
            }
            if records_since_checkpoint >= NETLAS_CHECKPOINT_RECORDS {
                commit_result_page(&mut names, std::mem::take(&mut page_names));
                records_since_checkpoint = 0;
            }
            Ok(())
        };
        while let Some(chunk) = response
            .chunk()
            .await
            .context("lecture du téléchargement Netlas")?
        {
            total_bytes = total_bytes.saturating_add(chunk.len());
            if total_bytes > NETLAS_DOWNLOAD_MAX_BYTES {
                bail!("Netlas: download response exceeds the size limit");
            }
            decoder.push(&chunk, &mut visit)?;
        }
        finish_result = decoder.finish();
    }
    commit_result_page(&mut names, page_names);
    finish_result?;
    let decoded = decoder.decoded;
    if decoded < requested {
        bail!("Netlas returned a partial download: {decoded}/{requested} requested records");
    }
    if count > requested {
        bail!(
            "Netlas result is partial: downloaded {requested}/{count} records; raise FELLAGA_NETLAS_DOWNLOAD_LIMIT only when the configured account plan permits it"
        );
    }
    Ok(names)
}

pub(super) fn securitytrails_page_names(
    page: &SecurityTrailsResponse,
    domain: &str,
) -> BTreeSet<String> {
    let records = page
        .records
        .iter()
        .filter_map(|record| normalize_observed_name(&record.hostname, domain));
    let labels = page.subdomains.iter().filter_map(|label| {
        let label = label.trim();
        if label.is_empty() {
            return None;
        }
        let candidate = if label.ends_with('.') {
            format!("{label}{domain}")
        } else {
            format!("{label}.{domain}")
        };
        normalize_observed_name(&candidate, domain)
    });
    records.chain(labels).collect()
}

pub(super) fn securitytrails_scroll_url(scroll_id: &str) -> Result<Url> {
    const MAX_SCROLL_ID_BYTES: usize = 4096;
    if scroll_id.is_empty()
        || scroll_id.len() > MAX_SCROLL_ID_BYTES
        || scroll_id.chars().any(char::is_control)
    {
        bail!("SecurityTrails: invalid scroll identifier");
    }
    let origin = Url::parse("https://api.securitytrails.com/")?;
    let mut next = origin.join("v1/scroll/")?;
    next.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("SecurityTrails: invalid scroll endpoint"))?
        .pop_if_empty()
        .push(scroll_id);
    let strict_scroll_path = next
        .path()
        .strip_prefix("/v1/scroll/")
        .is_some_and(|encoded_id| !encoded_id.is_empty() && !encoded_id.contains('/'));
    if !same_http_origin(&origin, &next)
        || !strict_scroll_path
        || !next.username().is_empty()
        || next.password().is_some()
        || next.query().is_some()
        || next.fragment().is_some()
    {
        bail!("SecurityTrails: rejected cross-origin scroll endpoint");
    }
    Ok(next)
}

pub(super) fn securitytrails_use_legacy_fallback(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::FORBIDDEN
}

pub(super) fn securitytrails_next_scroll(
    scroll_id: String,
    seen_scroll_ids: &mut BTreeSet<String>,
) -> Result<Option<String>> {
    if scroll_id.is_empty() {
        return Ok(None);
    }
    securitytrails_scroll_url(&scroll_id)?;
    if !seen_scroll_ids.insert(scroll_id.clone()) {
        bail!("SecurityTrails: repeated scroll identifier");
    }
    Ok(Some(scroll_id))
}

pub(super) async fn securitytrails(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("securitytrails")?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut scroll_id: Option<String> = None;
    let mut seen_scroll_ids = BTreeSet::new();

    for page_index in 0..SECURITYTRAILS_MAX_SCROLL_PAGES {
        let request = if let Some(scroll_id) = scroll_id.as_deref() {
            http.get(securitytrails_scroll_url(scroll_id)?)
                .header("APIKEY", &token)
        } else {
            http.post(
                "https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true",
            )
            .header("APIKEY", &token)
            .json(&serde_json::json!({
                "query": format!("apex_domain='{domain}'")
            }))
        };
        let response =
            send_external_streaming("securitytrails", request, &format!("{domain}:{page_index}"))
                .await
                .context("connexion à SecurityTrails domains/list")?;

        // The domains/list endpoint is not available on every subscription.
        // SecurityTrails documents the legacy endpoint through an exact 403;
        // no other status is treated as permission to change workflows.
        let (response, used_legacy_fallback) =
            if securitytrails_use_legacy_fallback(response.status()) {
                let fallback = send_external_streaming(
                    "securitytrails",
                    http.get(format!(
                        "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                    ))
                    .header("APIKEY", &token),
                    domain,
                )
                .await
                .context("connexion au repli SecurityTrails subdomains")?;
                (fallback, true)
            } else {
                (response, false)
            };

        let page = response_json::<SecurityTrailsResponse>(response, "SecurityTrails").await?;
        commit_result_page(&mut names, securitytrails_page_names(&page, domain));
        if used_legacy_fallback {
            return Ok(names);
        }
        let Some(next_scroll_id) =
            securitytrails_next_scroll(page.meta.scroll_id, &mut seen_scroll_ids)?
        else {
            return Ok(names);
        };
        scroll_id = Some(next_scroll_id);
    }
    bail!("SecurityTrails: pagination exceeded {SECURITYTRAILS_MAX_SCROLL_PAGES} pages")
}
