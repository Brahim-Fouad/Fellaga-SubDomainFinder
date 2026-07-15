use crate::model::EvidenceFamily;
use crate::util::normalize_observed_name;
use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, stream};
use reqwest::header::RETRY_AFTER;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{Mutex as TokioMutex, Semaphore};
use url::Url;

mod extra;

#[derive(Debug, Clone, Default)]
pub struct ApiKeyStore {
    keys: BTreeMap<String, Vec<String>>,
    cursor: Arc<AtomicUsize>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct ConfigFile {
    #[serde(default)]
    api_keys: BTreeMap<String, KeyList>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum KeyList {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub requires_key: bool,
    pub key_environment: Option<String>,
    pub configured: bool,
    pub automatic: bool,
    pub metadata: SourceMetadata,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceMetadata {
    pub name: String,
    pub evidence_family: EvidenceFamily,
    pub recursive_children: bool,
    pub recursive_parents: bool,
    pub cost: &'static str,
    pub authentication: &'static str,
    pub rate_limit_per_minute: u32,
    pub experimental: bool,
    pub documented: bool,
}

#[derive(Clone, Copy)]
struct SourceDefinition {
    name: &'static str,
    requires_key: bool,
    key_environment: Option<&'static str>,
    automatic: bool,
}

const SOURCE_DEFINITIONS: &[SourceDefinition] = &[
    SourceDefinition {
        name: "anubisdb",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "bevigil",
        requires_key: true,
        key_environment: Some("BEVIGIL_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "builtwith",
        requires_key: true,
        key_environment: Some("BUILTWITH_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "censys",
        requires_key: true,
        key_environment: Some("CENSYS_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "certificatedetails",
        requires_key: false,
        key_environment: None,
        automatic: false,
    },
    SourceDefinition {
        name: "certspotter",
        requires_key: false,
        key_environment: Some("CERTSPOTTER_API_TOKEN"),
        automatic: true,
    },
    SourceDefinition {
        name: "chaos",
        requires_key: true,
        key_environment: Some("CHAOS_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "commoncrawl",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "circl",
        requires_key: true,
        key_environment: Some("CIRCL_PDNS_CREDENTIALS"),
        automatic: true,
    },
    SourceDefinition {
        name: "crtsh",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "driftnet",
        requires_key: false,
        key_environment: None,
        automatic: false,
    },
    SourceDefinition {
        name: "fullhunt",
        requires_key: true,
        key_environment: Some("FULLHUNT_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "github",
        requires_key: true,
        key_environment: Some("GITHUB_TOKEN"),
        automatic: true,
    },
    SourceDefinition {
        name: "gitlab",
        requires_key: true,
        key_environment: Some("GITLAB_TOKEN"),
        automatic: true,
    },
    SourceDefinition {
        name: "hackertarget",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "intelx",
        requires_key: true,
        key_environment: Some("INTELX_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "leakix",
        requires_key: true,
        key_environment: Some("LEAKIX_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "netlas",
        requires_key: true,
        key_environment: Some("NETLAS_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "otx",
        requires_key: false,
        key_environment: Some("OTX_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "securitytrails",
        requires_key: true,
        key_environment: Some("SECURITYTRAILS_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "shodan",
        requires_key: true,
        key_environment: Some("SHODAN_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "subdomaincenter",
        requires_key: false,
        key_environment: None,
        automatic: false,
    },
    SourceDefinition {
        name: "subdomainapp",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "urlscan",
        requires_key: false,
        key_environment: Some("URLSCAN_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "virustotal",
        requires_key: true,
        key_environment: Some("VIRUSTOTAL_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "whoisxml",
        requires_key: true,
        key_environment: Some("WHOISXML_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "wayback",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
];

pub fn default_config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("FELLAGA_CONFIG") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(path).join("fellaga/config.json");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/fellaga/config.json")
}

impl ApiKeyStore {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(
                path,
                serde_json::to_string_pretty(&ConfigFile::default())? + "\n",
            )?;
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("lecture de la configuration {}", path.display()))?;
        let config: ConfigFile = serde_json::from_str(&content)
            .with_context(|| format!("JSON de configuration invalide: {}", path.display()))?;
        let mut keys = BTreeMap::new();
        for (source, value) in config.api_keys {
            let values = match value {
                KeyList::One(value) => split_keys(&value),
                KeyList::Many(values) => values,
            }
            .into_iter()
            .map(|key| key.trim().to_owned())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
            if !values.is_empty() {
                keys.insert(source.to_ascii_lowercase(), values);
            }
        }
        Ok(Self {
            keys,
            cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn has(&self, source: &str) -> bool {
        !self.values(source).is_empty()
    }

    pub(super) fn pick(&self, source: &str) -> Result<String> {
        let values = self.values(source);
        if values.is_empty() {
            let variable = definition(source)
                .and_then(|entry| entry.key_environment)
                .unwrap_or("clé API");
            bail!("{variable} absent pour la source {source}");
        }
        let index = self.cursor.fetch_add(1, Ordering::Relaxed) % values.len();
        Ok(values[index].clone())
    }

    pub(super) fn optional(&self, source: &str) -> Option<String> {
        let values = self.values(source);
        (!values.is_empty()).then(|| {
            let index = self.cursor.fetch_add(1, Ordering::Relaxed) % values.len();
            values[index].clone()
        })
    }

    fn values(&self, source: &str) -> Vec<String> {
        let mut values = self
            .keys
            .get(&source.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default();
        for variable in environment_names(source) {
            if let Ok(value) = std::env::var(variable) {
                values.extend(split_keys(&value));
            }
        }
        values.sort();
        values.dedup();
        values
    }
}

fn split_keys(value: &str) -> Vec<String> {
    value
        .split([',', ';', '\n', '\r'])
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn definition(source: &str) -> Option<SourceDefinition> {
    SOURCE_DEFINITIONS
        .iter()
        .copied()
        .find(|entry| entry.name == source)
}

fn environment_names(source: &str) -> &'static [&'static str] {
    match source {
        "bevigil" => &["BEVIGIL_API_KEY"],
        "builtwith" => &["BUILTWITH_API_KEY"],
        "censys" => &["CENSYS_API_KEY"],
        "circl" => &["CIRCL_PDNS_CREDENTIALS"],
        "certspotter" => &["CERTSPOTTER_API_TOKEN"],
        "chaos" => &["CHAOS_API_KEY"],
        "fullhunt" => &["FULLHUNT_API_KEY"],
        "github" => &["GITHUB_TOKEN", "GITHUB_TOKENS"],
        "gitlab" => &["GITLAB_TOKEN"],
        "intelx" => &["INTELX_API_KEY"],
        "leakix" => &["LEAKIX_API_KEY"],
        "netlas" => &["NETLAS_API_KEY"],
        "otx" => &["OTX_API_KEY", "X_OTX_API_KEY"],
        "securitytrails" => &["SECURITYTRAILS_API_KEY"],
        "shodan" => &["SHODAN_API_KEY"],
        "urlscan" => &["URLSCAN_API_KEY"],
        "virustotal" => &["VIRUSTOTAL_API_KEY"],
        "whoisxml" => &["WHOISXML_API_KEY"],
        _ => &[],
    }
}

pub fn source_statuses(keys: &ApiKeyStore) -> Vec<SourceStatus> {
    SOURCE_DEFINITIONS
        .iter()
        .map(|entry| SourceStatus {
            name: entry.name.to_owned(),
            requires_key: entry.requires_key,
            key_environment: entry.key_environment.map(ToOwned::to_owned),
            configured: keys.has(entry.name),
            automatic: entry.automatic && (!entry.requires_key || keys.has(entry.name)),
            metadata: source_metadata(entry.name),
        })
        .collect()
}

pub fn source_metadata(name: &str) -> SourceMetadata {
    let evidence_family = crate::confidence::evidence_family(&format!("passive:{name}"))
        .unwrap_or(EvidenceFamily::Aggregator);
    let experimental = matches!(
        name,
        "anubisdb" | "certificatedetails" | "driftnet" | "subdomainapp" | "subdomaincenter"
    );
    let requires_key = definition(name).is_some_and(|definition| definition.requires_key);
    let authentication = if requires_key {
        "required"
    } else if definition(name).is_some_and(|definition| definition.key_environment.is_some()) {
        "optional"
    } else {
        "none"
    };
    let cost = match name {
        "commoncrawl" | "wayback" | "github" | "gitlab" | "urlscan" | "netlas" => "high",
        "crtsh" | "certspotter" | "virustotal" | "shodan" | "censys" | "whoisxml" => "medium",
        _ => "low",
    };
    let rate_limit_per_minute = match name {
        "crtsh" => 6,
        "certspotter" => 12,
        "hackertarget" => 5,
        "commoncrawl" | "wayback" => 10,
        "urlscan" => 12,
        _ if requires_key => 30,
        _ => 20,
    };
    SourceMetadata {
        name: name.to_owned(),
        evidence_family,
        recursive_children: !matches!(name, "builtwith" | "certificatedetails"),
        recursive_parents: matches!(
            evidence_family,
            EvidenceFamily::CertificateTransparency
                | EvidenceFamily::PassiveDns
                | EvidenceFamily::WebArchive
        ),
        cost,
        authentication,
        rate_limit_per_minute,
        experimental,
        documented: !experimental,
    }
}

pub fn automatic_sources(keys: &ApiKeyStore) -> Vec<String> {
    automatic_sources_for_profile(keys, false)
}

pub fn automatic_sources_for_profile(
    keys: &ApiKeyStore,
    include_experimental: bool,
) -> Vec<String> {
    source_statuses(keys)
        .into_iter()
        .filter(|source| {
            source.automatic
                || (include_experimental
                    && source.metadata.experimental
                    && (!source.requires_key || source.configured))
        })
        .map(|source| source.name)
        .collect()
}

pub fn validate_sources(sources: &[String]) -> Result<()> {
    for source in sources {
        if definition(source).is_none() {
            bail!("source passive inconnue: {source}");
        }
    }
    Ok(())
}

static COMMONCRAWL_API: OnceLock<RwLock<Option<String>>> = OnceLock::new();
static COMMONCRAWL_GATE: OnceLock<Semaphore> = OnceLock::new();
static COMMONCRAWL_LAST_REQUEST: OnceLock<TokioMutex<Option<Instant>>> = OnceLock::new();
type ExternalHostLimiters = StdMutex<BTreeMap<String, Arc<TokioMutex<Option<Instant>>>>>;
static EXTERNAL_HOST_LIMITERS: OnceLock<ExternalHostLimiters> = OnceLock::new();

const MAX_EXTERNAL_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePolicy {
    pub timeout: Duration,
    pub attempts: usize,
    pub base_backoff: Duration,
}

pub fn source_policy(source: &str) -> SourcePolicy {
    match source {
        "crtsh" => SourcePolicy {
            timeout: Duration::from_secs(25),
            attempts: 3,
            base_backoff: Duration::from_millis(750),
        },
        "commoncrawl" => SourcePolicy {
            timeout: Duration::from_secs(30),
            attempts: 3,
            base_backoff: Duration::from_secs(1),
        },
        "wayback" => SourcePolicy {
            timeout: Duration::from_secs(45),
            attempts: 1,
            base_backoff: Duration::from_secs(1),
        },
        "otx" => SourcePolicy {
            timeout: Duration::from_secs(20),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        "certspotter" | "urlscan" | "virustotal" | "shodan" | "censys" | "github" | "gitlab" => {
            SourcePolicy {
                timeout: Duration::from_secs(30),
                attempts: 2,
                base_backoff: Duration::from_secs(1),
            }
        }
        _ => SourcePolicy {
            timeout: Duration::from_secs(20),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
    }
}

fn commoncrawl_endpoint_cache() -> &'static RwLock<Option<String>> {
    COMMONCRAWL_API.get_or_init(|| RwLock::new(None))
}

pub fn seed_commoncrawl_endpoint(endpoint: String) {
    if !endpoint.starts_with("https://index.commoncrawl.org/") {
        return;
    }
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
    #[serde(default)]
    name_value: String,
}

#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CommonCrawlCollection {
    #[serde(rename = "cdx-api")]
    cdx_api: String,
}

#[derive(Debug, Deserialize)]
struct CommonCrawlRow {
    url: String,
}

#[derive(Debug, Deserialize)]
struct UrlscanResponse {
    #[serde(default)]
    results: Vec<UrlscanResult>,
}

#[derive(Debug, Deserialize)]
struct UrlscanResult {
    page: Option<UrlscanHost>,
    task: Option<UrlscanHost>,
    #[serde(default)]
    sort: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UrlscanHost {
    domain: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubdomainAppResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    #[serde(default)]
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

#[derive(Debug, Deserialize)]
struct SecurityTrailsResponse {
    #[serde(default)]
    subdomains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WhoisXmlResponse {
    result: Option<WhoisXmlResult>,
}

#[derive(Debug, Deserialize)]
struct WhoisXmlResult {
    #[serde(default)]
    records: Vec<WhoisXmlRecord>,
    #[serde(rename = "nextPageSearchAfter", default)]
    next_page_search_after: String,
}

#[derive(Debug, Deserialize)]
struct WhoisXmlRecord {
    domain: String,
}

#[derive(Debug, Deserialize)]
struct NetlasResponse {
    #[serde(default)]
    items: Vec<NetlasItem>,
}

#[derive(Debug, Deserialize)]
struct NetlasItem {
    data: NetlasDomain,
}

#[derive(Debug, Deserialize)]
struct NetlasDomain {
    domain: String,
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(30))
        .user_agent(concat!(
            "Fellaga-SubDomainFinder/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?)
}

fn retry_after_delay(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    httpdate::parse_http_date(value)
        .ok()?
        .duration_since(SystemTime::now())
        .ok()
}

fn backoff_delay(seed: &str, attempt: usize, base: Duration) -> Duration {
    let multiplier = 1_u32.checked_shl(attempt.min(8) as u32).unwrap_or(256);
    let base = base.saturating_mul(multiplier);
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let jitter = Duration::from_millis(hasher.finish() % 500);
    base.saturating_add(jitter)
}

fn retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
            | reqwest::StatusCode::INTERNAL_SERVER_ERROR
            | reqwest::StatusCode::BAD_GATEWAY
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT
    )
}

fn host_minimum_gap(host: &str) -> Duration {
    match host {
        "api.github.com" => Duration::from_secs(6),
        "index.commoncrawl.org" => Duration::from_secs(2),
        "crt.sh" | "web.archive.org" => Duration::from_secs(1),
        "urlscan.io" | "api.urlscan.io" => Duration::from_millis(500),
        "api.certspotter.com" => Duration::from_millis(250),
        _ => Duration::from_millis(100),
    }
}

fn request_host(request: &reqwest::RequestBuilder) -> Option<String> {
    request
        .try_clone()?
        .build()
        .ok()?
        .url()
        .host_str()
        .map(str::to_ascii_lowercase)
}

async fn throttle_external_host(request: &reqwest::RequestBuilder) {
    let Some(host) = request_host(request) else {
        return;
    };
    let limiter = {
        let mut limiters = EXTERNAL_HOST_LIMITERS
            .get_or_init(|| StdMutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limiters
            .entry(host.clone())
            .or_insert_with(|| Arc::new(TokioMutex::new(None)))
            .clone()
    };
    let mut last_request = limiter.lock().await;
    if let Some(last) = *last_request {
        let gap = host_minimum_gap(&host);
        if last.elapsed() < gap {
            tokio::time::sleep(gap.saturating_sub(last.elapsed())).await;
        }
    }
    *last_request = Some(Instant::now());
}

fn server_retry_delay(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(retry_after_delay)
        .or_else(|| {
            response
                .headers()
                .get("x-rate-limit-reset-after")
                .and_then(|value| value.to_str().ok())
                .and_then(retry_after_delay)
        })
}

fn compact_external_error(body: &str) -> String {
    let compact = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut characters = compact.chars();
    let shortened = characters.by_ref().take(500).collect::<String>();
    if characters.next().is_some() {
        format!("{shortened}…")
    } else {
        shortened
    }
}

pub(super) async fn response_bytes_limited(
    mut response: reqwest::Response,
    source: &str,
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_EXTERNAL_BODY_BYTES as u64)
    {
        bail!(
            "{source}: réponse supérieure à {} Mio",
            MAX_EXTERNAL_BODY_BYTES / 1024 / 1024
        );
    }
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("lecture de la réponse {source}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_EXTERNAL_BODY_BYTES {
            bail!(
                "{source}: réponse décompressée supérieure à {} Mio",
                MAX_EXTERNAL_BODY_BYTES / 1024 / 1024
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

pub(super) async fn response_json<T: DeserializeOwned>(
    response: reqwest::Response,
    source: &str,
) -> Result<T> {
    let (status, body) = response_bytes_limited(response, source).await?;
    if !status.is_success() {
        bail!(
            "{source}: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    serde_json::from_slice(&body).with_context(|| format!("JSON {source} invalide"))
}

pub(super) async fn response_text(response: reqwest::Response, source: &str) -> Result<String> {
    let (status, body) = response_bytes_limited(response, source).await?;
    if !status.is_success() {
        bail!(
            "{source}: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    String::from_utf8(body).with_context(|| format!("texte {source} non UTF-8"))
}

pub(super) async fn send_external(
    source: &str,
    request: reqwest::RequestBuilder,
    seed: &str,
) -> Result<reqwest::Response> {
    let policy = source_policy(source);
    send_with_retry(request, policy.attempts, policy.base_backoff, seed).await
}

pub(super) async fn send_with_retry(
    request: reqwest::RequestBuilder,
    attempts: usize,
    base_backoff: Duration,
    seed: &str,
) -> Result<reqwest::Response> {
    let attempts = attempts.max(1);
    for attempt in 0..attempts {
        throttle_external_host(&request).await;
        let response = request
            .try_clone()
            .context("requête HTTP non clonable")?
            .send()
            .await;
        match response {
            Ok(response) if !retryable_status(response.status()) => return Ok(response),
            Ok(response) => {
                let retry_after = server_retry_delay(&response);
                if let Some(delay) = retry_after
                    && delay > Duration::from_secs(30)
                {
                    bail!(
                        "HTTP {} avec Retry-After={}s; nouvelle tentative différée",
                        response.status(),
                        delay.as_secs()
                    );
                }
                if attempt + 1 >= attempts {
                    return Ok(response);
                }
                let delay =
                    retry_after.unwrap_or_else(|| backoff_delay(seed, attempt, base_backoff));
                tokio::time::sleep(delay).await;
            }
            Err(error) => {
                if attempt + 1 >= attempts {
                    return Err(error.into());
                }
                tokio::time::sleep(backoff_delay(seed, attempt, base_backoff)).await;
            }
        }
    }
    unreachable!("au moins une tentative HTTP est toujours exécutée")
}

pub async fn fetch(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    match source {
        "crtsh" => crtsh(domain, timeout).await,
        "certspotter" => certspotter(domain, timeout, keys).await,
        "hackertarget" => hackertarget(domain, timeout).await,
        "commoncrawl" => commoncrawl(domain, timeout).await,
        "wayback" => wayback(domain, timeout).await,
        "urlscan" => urlscan(domain, timeout, keys).await,
        "anubisdb" => anubisdb(domain, timeout).await,
        "subdomainapp" => subdomainapp(domain, timeout).await,
        "virustotal" => virustotal(domain, timeout, keys).await,
        "whoisxml" => whoisxml(domain, timeout, keys).await,
        "securitytrails" => securitytrails(domain, timeout, keys).await,
        "bevigil" => extra::bevigil(domain, timeout, keys).await,
        "builtwith" => extra::builtwith(domain, timeout, keys).await,
        "censys" => extra::censys(domain, timeout, keys).await,
        "circl" => extra::circl(domain, timeout, keys).await,
        "certificatedetails" => extra::certificate_details(domain, timeout).await,
        "chaos" => extra::chaos(domain, timeout, keys).await,
        "driftnet" => extra::driftnet(domain, timeout).await,
        "fullhunt" => extra::fullhunt(domain, timeout, keys).await,
        "github" => extra::github(domain, timeout, keys).await,
        "gitlab" => extra::gitlab(domain, timeout, keys).await,
        "intelx" => extra::intelx(domain, timeout, keys).await,
        "leakix" => extra::leakix(domain, timeout, keys).await,
        "netlas" => netlas(domain, timeout, keys).await,
        "otx" => extra::otx(domain, timeout, keys).await,
        "shodan" => extra::shodan(domain, timeout, keys).await,
        "subdomaincenter" => extra::subdomain_center(domain, timeout).await,
        _ => bail!("source passive inconnue: {source}"),
    }
}

async fn crtsh(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let policy = source_policy("crtsh");
    let response = send_with_retry(
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

async fn certspotter(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let token = keys.optional("certspotter");
    let mut after: Option<String> = None;
    let mut names = BTreeSet::new();
    for _page in 0..25 {
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
                    Err(_) if !names.is_empty() => break,
                    Err(error) => return Err(error),
                }
            }
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("connexion à Cert Spotter"),
        };
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|issuance| issuance.id.clone());
        if next_after == after {
            break;
        }
        after = next_after;
        for issuance in page {
            for dns_name in issuance.dns_names {
                if let Some(name) = normalize_observed_name(&dns_name, domain) {
                    names.insert(name);
                }
            }
        }
    }
    Ok(names)
}

async fn hackertarget(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let response = send_external(
        "hackertarget",
        client(timeout)?
            .get("https://api.hackertarget.com/hostsearch/")
            .query(&[("q", domain)]),
        domain,
    )
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

fn hostname_from_url(value: &str, domain: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .and_then(|hostname| normalize_observed_name(&hostname, domain))
}

async fn load_commoncrawl_endpoints(
    client: &reqwest::Client,
    policy: SourcePolicy,
    seed: &str,
) -> Result<Vec<String>> {
    throttle_commoncrawl().await;
    let response = send_with_retry(
        client.get("https://index.commoncrawl.org/collinfo.json"),
        policy.attempts,
        policy.base_backoff,
        seed,
    )
    .await
    .context("connexion à Common Crawl")?;
    let collections = response_json::<Vec<CommonCrawlCollection>>(response, "Common Crawl").await?;
    let endpoints = collections
        .into_iter()
        .take(5)
        .map(|collection| collection.cdx_api)
        .collect::<Vec<_>>();
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
) -> Result<reqwest::Response> {
    throttle_commoncrawl().await;
    send_with_retry(
        client.get(endpoint).query(&[
            ("url", domain),
            ("matchType", "domain"),
            ("output", "json"),
            ("filter", "status:200"),
            ("collapse", "urlkey"),
            ("pageSize", "5"),
            ("page", &page.to_string()),
        ]),
        policy.attempts,
        policy.base_backoff,
        domain,
    )
    .await
}

async fn commoncrawl(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
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
    let mut successful_requests = 0_usize;
    let mut errors = Vec::new();
    for endpoint in endpoints {
        for page in 0..3 {
            let response = match query_commoncrawl(&client, &endpoint, domain, policy, page).await {
                Ok(response) => response,
                Err(error) => {
                    errors.push(format!("{endpoint} page {page}: {error:#}"));
                    break;
                }
            };
            if matches!(
                response.status(),
                reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
            ) {
                break;
            }
            match response_text(response, "index Common Crawl").await {
                Ok(body) => {
                    if body.trim().is_empty() {
                        break;
                    }
                    successful_requests += 1;
                    names.extend(
                        body.lines()
                            .take(50_000)
                            .filter_map(|line| serde_json::from_str::<CommonCrawlRow>(line).ok())
                            .filter_map(|row| hostname_from_url(&row.url, domain)),
                    );
                }
                Err(error) => {
                    errors.push(format!("{endpoint} page {page}: {error:#}"));
                    break;
                }
            }
        }
    }
    if successful_requests == 0 {
        bail!("Common Crawl: {}", errors.join(" | "));
    }
    Ok(names)
}

fn parse_wayback_rows(rows: Vec<Vec<String>>, domain: &str) -> BTreeSet<String> {
    rows.into_iter()
        .skip(1)
        .filter_map(|row| row.into_iter().next())
        .filter_map(|url| hostname_from_url(&url, domain))
        .collect()
}

async fn query_wayback(
    client: &reqwest::Client,
    domain: &str,
    from: Option<&str>,
    to: Option<&str>,
    limit: usize,
) -> Result<BTreeSet<String>> {
    let mut query = vec![
        ("url", domain.to_owned()),
        ("matchType", "domain".to_owned()),
        ("output", "json".to_owned()),
        ("fl", "original".to_owned()),
        ("collapse", "urlkey".to_owned()),
        ("filter", "statuscode:200".to_owned()),
        ("limit", limit.to_string()),
    ];
    if let Some(from) = from {
        query.push(("from", from.to_owned()));
    }
    if let Some(to) = to {
        query.push(("to", to.to_owned()));
    }
    let response = send_with_retry(
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
    Ok(parse_wayback_rows(rows, domain))
}

async fn wayback(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let primary = query_wayback(&client(timeout)?, domain, None, None, 2_000).await;
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
            async move { query_wayback(&client, &domain, from, to, 1_000).await }
        })
        .buffer_unordered(4);
    let mut names = BTreeSet::new();
    let mut completed = 0_usize;
    let mut errors = Vec::new();
    while let Some(result) = pending.next().await {
        match result {
            Ok(window_names) => {
                completed += 1;
                names.extend(window_names);
            }
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    if completed > 0 {
        return Ok(names);
    }
    bail!(
        "Wayback complet puis fenêtres temporelles indisponibles: {primary_error}; {}",
        errors.join(" | ")
    )
}

async fn urlscan(domain: &str, timeout: Duration, keys: &ApiKeyStore) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let token = keys.optional("urlscan");
    let mut names = BTreeSet::new();
    let mut search_after: Option<String> = None;
    for _page in 0..5 {
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
                Err(_) if !names.is_empty() => break,
                Err(error) => return Err(error),
            },
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("connexion à urlscan"),
        };
        let page_len = response.results.len();
        let next = response.results.last().and_then(urlscan_search_after);
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
                    names.insert(name);
                }
            }
        }
        if page_len < 1_000 || next.is_none() || next == search_after {
            break;
        }
        search_after = next;
    }
    Ok(names)
}

fn urlscan_search_after(result: &UrlscanResult) -> Option<String> {
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

async fn anubisdb(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
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

async fn subdomainapp(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
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

async fn virustotal(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("virustotal")?;
    let client = client(timeout)?;
    let mut next = Some(format!(
        "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    ));
    let mut names = BTreeSet::new();
    for _ in 0..5 {
        let Some(url) = next.take() else {
            break;
        };
        if !trusted_pagination_url(&url, "www.virustotal.com", "/api/v3/domains/") {
            bail!("VirusTotal a renvoyé une URL de pagination non fiable");
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
                    Err(_) if !names.is_empty() => break,
                    Err(error) => return Err(error),
                }
            }
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("connexion à VirusTotal"),
        };
        for item in response.data {
            if let Some(name) = normalize_observed_name(&item.id, domain) {
                names.insert(name);
            }
        }
        next = response.links.and_then(|links| links.next);
    }
    Ok(names)
}

fn trusted_pagination_url(url: &str, expected_host: &str, expected_path: &str) -> bool {
    Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some(expected_host)
            && url.path().starts_with(expected_path)
            && url.username().is_empty()
            && url.password().is_none()
    })
}

async fn whoisxml(domain: &str, timeout: Duration, keys: &ApiKeyStore) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let key = keys.pick("whoisxml")?;
    let mut search_after = String::new();
    let mut names = BTreeSet::new();
    for _ in 0..100 {
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
        for record in result.records {
            if let Some(name) = normalize_observed_name(&record.domain, domain) {
                names.insert(name);
            }
        }
        if result.next_page_search_after.is_empty() || result.next_page_search_after == search_after
        {
            break;
        }
        search_after = result.next_page_search_after;
    }
    Ok(names)
}

async fn netlas(domain: &str, timeout: Duration, keys: &ApiKeyStore) -> Result<BTreeSet<String>> {
    let client = client(timeout)?;
    let key = keys.pick("netlas")?;
    let mut names = BTreeSet::new();
    for start in (0..10_000).step_by(20).take(50) {
        let response = send_external(
            "netlas",
            client
                .get("https://app.netlas.io/api/domains/")
                .bearer_auth(&key)
                .query(&[
                    ("q", format!("domain:*.{domain}")),
                    ("fields", "domain".to_owned()),
                    ("start", start.to_string()),
                ]),
            domain,
        )
        .await
        .context("connexion à Netlas Domains Search")?;
        let page = response_json::<NetlasResponse>(response, "Netlas").await?;
        if page.items.is_empty() {
            break;
        }
        for item in page.items {
            if let Some(name) = normalize_observed_name(&item.data.domain, domain) {
                names.insert(name);
            }
        }
    }
    Ok(names)
}

async fn securitytrails(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let token = keys.pick("securitytrails")?;
    let response = send_external(
        "securitytrails",
        client(timeout)?
            .get(format!(
                "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            ))
            .header("APIKEY", token),
        domain,
    )
    .await
    .context("connexion à SecurityTrails")?;
    let response = response_json::<SecurityTrailsResponse>(response, "SecurityTrails").await?;
    Ok(response
        .subdomains
        .into_iter()
        .filter_map(|label| normalize_observed_name(&format!("{label}.{domain}"), domain))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn whoisxml_contract_fixture_preserves_pagination_and_scope() {
        let page: WhoisXmlResponse =
            serde_json::from_str(include_str!("../tests/fixtures/whoisxml-page.json")).unwrap();
        let result = page.result.unwrap();
        assert_eq!(result.next_page_search_after, "cursor-2");
        let names = result
            .records
            .into_iter()
            .filter_map(|record| normalize_observed_name(&record.domain, "example.com"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([
                "api.example.com".to_owned(),
                "deep.api.example.com".to_owned()
            ])
        );
    }

    #[test]
    fn netlas_contract_fixture_ignores_out_of_scope_names() {
        let page: NetlasResponse =
            serde_json::from_str(include_str!("../tests/fixtures/netlas-page.json")).unwrap();
        let names = page
            .items
            .into_iter()
            .filter_map(|item| normalize_observed_name(&item.data.domain, "example.com"))
            .collect::<BTreeSet<_>>();
        assert_eq!(names, BTreeSet::from(["edge.example.com".to_owned()]));
    }

    #[test]
    fn deep_profile_enables_accessible_experimental_connectors() {
        let keys = ApiKeyStore::default();
        let balanced = automatic_sources_for_profile(&keys, false);
        let deep = automatic_sources_for_profile(&keys, true);
        assert!(!balanced.contains(&"driftnet".to_owned()));
        assert!(deep.contains(&"driftnet".to_owned()));
        assert!(deep.contains(&"subdomaincenter".to_owned()));
        assert!(!deep.contains(&"bevigil".to_owned()));
    }

    #[test]
    fn archived_urls_are_reduced_to_in_scope_hosts() {
        assert_eq!(
            hostname_from_url("https://deep.api.example.com/path", "example.com").as_deref(),
            Some("deep.api.example.com")
        );
        assert!(hostname_from_url("https://example.net/", "example.com").is_none());
        assert!(hostname_from_url("not a url", "example.com").is_none());
    }

    #[test]
    fn unstable_sources_have_bounded_individual_policies() {
        assert_eq!(source_policy("wayback").timeout, Duration::from_secs(45));
        assert_eq!(source_policy("crtsh").attempts, 3);
        assert_eq!(source_policy("commoncrawl").attempts, 3);
        assert!(retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(retryable_status(reqwest::StatusCode::TOO_EARLY));
        assert!(retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(retry_after_delay("12"), Some(Duration::from_secs(12)));
        let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(60));
        let date_delay = retry_after_delay(&date).unwrap();
        assert!(date_delay > Duration::from_secs(55));
        assert!(date_delay <= Duration::from_secs(60));
        assert!(
            backoff_delay("example.com", 1, Duration::from_millis(750))
                > backoff_delay("example.com", 0, Duration::from_millis(750))
        );
    }

    #[test]
    fn external_pagination_cannot_redirect_credentials_to_another_host() {
        assert!(trusted_pagination_url(
            "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=x",
            "www.virustotal.com",
            "/api/v3/domains/"
        ));
        assert!(!trusted_pagination_url(
            "https://evil.test/api/v3/domains/example.com/subdomains",
            "www.virustotal.com",
            "/api/v3/domains/"
        ));
        assert!(!trusted_pagination_url(
            "https://www.virustotal.com@evil.test/api/v3/domains/example.com/subdomains",
            "www.virustotal.com",
            "/api/v3/domains/"
        ));
    }

    #[test]
    fn urlscan_sort_values_become_a_search_after_cursor() {
        let result = UrlscanResult {
            page: None,
            task: None,
            sort: vec![
                serde_json::json!(1_784_000_000_000_i64),
                serde_json::json!("uuid"),
            ],
        };
        assert_eq!(
            urlscan_search_after(&result).as_deref(),
            Some("1784000000000,uuid")
        );
    }

    #[test]
    fn wayback_windows_keep_only_in_scope_hosts() {
        let names = parse_wayback_rows(
            vec![
                vec!["original".to_owned()],
                vec!["https://api.example.com/path".to_owned()],
                vec!["https://evil.test/".to_owned()],
            ],
            "example.com",
        );
        assert_eq!(names, BTreeSet::from(["api.example.com".to_owned()]));
    }

    #[tokio::test]
    async fn retry_after_is_honored_before_a_successful_retry() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0_u8; 1_024];
                let _ = socket.read(&mut request);
                let response = if attempt == 0 {
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"
                };
                socket.write_all(response.as_bytes()).unwrap();
            }
        });
        let response = send_with_retry(
            client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            2,
            Duration::from_millis(1),
            "retry-test",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn external_error_bodies_are_preserved_for_diagnostics() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            let body = r#"{"error":"invalid api key"}"#;
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).unwrap();
        });
        let response = client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let error = response_json::<serde_json::Value>(response, "source-test")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("401 Unauthorized"));
        assert!(error.contains("invalid api key"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn oversized_external_responses_are_rejected_from_headers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_EXTERNAL_BODY_BYTES + 1
            );
            socket.write_all(response.as_bytes()).unwrap();
        });
        let response = client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let error = response_text(response, "source-test")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("supérieure à 16 Mio"));
        server.join().unwrap();
    }
}
