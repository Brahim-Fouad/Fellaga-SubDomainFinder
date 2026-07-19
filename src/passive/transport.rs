//! Bounded HTTP transport, throttling, retries, and safe error handling.

use super::catalog::{source_policy, try_source_metadata};
use super::config::sanitize_external_message;
use anyhow::{Context, Result, bail};
use reqwest::ResponseBuilderExt;
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_LENGTH, HeaderMap, HeaderValue, RETRY_AFTER, TRANSFER_ENCODING,
};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;
use url::Url;

type ExternalHostLimiters = StdMutex<BTreeMap<String, Arc<TokioMutex<Option<Instant>>>>>;
static EXTERNAL_HOST_LIMITERS: OnceLock<ExternalHostLimiters> = OnceLock::new();
type ExternalSourceLimiters = StdMutex<BTreeMap<String, Arc<TokioMutex<Option<Instant>>>>>;
static EXTERNAL_SOURCE_LIMITERS: OnceLock<ExternalSourceLimiters> = OnceLock::new();
type ExternalClients = StdMutex<BTreeMap<u64, reqwest::Client>>;
static EXTERNAL_CLIENTS: OnceLock<ExternalClients> = OnceLock::new();

tokio::task_local! {
    static BLOCKED_EXTERNAL_TARGET: Option<String>;
}

pub(super) const MAX_EXTERNAL_BODY_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_INLINE_RETRY_AFTER: Duration = Duration::from_secs(15 * 60);
const COMMONCRAWL_MAX_BODY_BYTES: usize = 3 * MAX_EXTERNAL_BODY_BYTES;

pub(super) fn defer_retry_after(delay: Duration) -> bool {
    delay > MAX_INLINE_RETRY_AFTER
}
pub(super) fn valid_user_agent_override(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && !value.chars().any(char::is_control)
        && HeaderValue::from_str(value).is_ok()
}

pub(crate) fn external_user_agent() -> String {
    std::env::var("FELLAGA_USER_AGENT")
        .ok()
        .filter(|value| valid_user_agent_override(value))
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| {
            format!(
                "Fellaga/{} (+https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder)",
                env!("CARGO_PKG_VERSION")
            )
        })
}

pub(super) fn build_client(timeout: Duration) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(
            "application/json, application/x-ndjson, text/plain;q=0.9, text/html;q=0.7, */*;q=0.5",
        ),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.8"));
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .tcp_keepalive(Duration::from_secs(30))
        .tcp_nodelay(true)
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let Some(previous) = attempt.previous().last() else {
                return attempt.error("redirect without an origin request");
            };
            if scoped_external_url_is_blocked(attempt.url()) {
                attempt.error("no-target-contact: external redirect to the target was rejected")
            } else if attempt.previous().len() >= 5 {
                attempt.error("too many external redirects")
            } else if same_http_origin(previous, attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("cross-origin external redirect rejected")
            }
        }))
        .user_agent(external_user_agent())
        .build()?)
}

pub(super) fn client(timeout: Duration) -> Result<reqwest::Client> {
    let timeout_key = timeout.as_millis().clamp(1, u64::MAX as u128) as u64;
    if let Some(client) = EXTERNAL_CLIENTS
        .get_or_init(|| StdMutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&timeout_key)
        .cloned()
    {
        return Ok(client);
    }

    let built = build_client(timeout)?;
    let mut clients = EXTERNAL_CLIENTS
        .get_or_init(|| StdMutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok(clients.entry(timeout_key).or_insert(built).clone())
}

pub(super) fn same_http_origin(previous: &Url, next: &Url) -> bool {
    previous.scheme() == next.scheme()
        && previous.host_str() == next.host_str()
        && previous.port_or_known_default() == next.port_or_known_default()
}

fn normalized_contact_host(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

pub(super) fn external_host_contacts_target(host: &str, root_domain: &str) -> bool {
    let Some(host) = normalized_contact_host(host) else {
        return false;
    };
    let Some(root_domain) = normalized_contact_host(root_domain) else {
        return false;
    };
    host == root_domain
        || host
            .strip_suffix(&root_domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn scoped_external_target_for_host(host: &str) -> Option<String> {
    BLOCKED_EXTERNAL_TARGET
        .try_with(|target| {
            target
                .as_deref()
                .filter(|target| external_host_contacts_target(host, target))
                .map(str::to_owned)
        })
        .ok()
        .flatten()
}

fn scoped_external_url_is_blocked(url: &Url) -> bool {
    url.host_str()
        .is_some_and(|host| scoped_external_target_for_host(host).is_some())
}

pub(super) fn ensure_external_host_allowed(host: &str) -> Result<()> {
    if let Some(target) = scoped_external_target_for_host(host) {
        bail!("no-target-contact: external request to {host} blocked because it targets {target}");
    }
    Ok(())
}

fn ensure_external_url_allowed(url: &Url) -> Result<()> {
    if let Some(host) = url.host_str() {
        ensure_external_host_allowed(host)?;
    }
    Ok(())
}

pub(super) fn ensure_external_request_allowed(request: &reqwest::RequestBuilder) -> Result<()> {
    let request = request
        .try_clone()
        .context("requête HTTP non clonable")?
        .build()
        .context("construction de la requête HTTP")?;
    ensure_external_url_allowed(request.url())
}

/// Applies the scanner's no-direct-contact policy to one passive provider
/// future. An absent target preserves the ordinary provider behavior.
pub(crate) async fn with_external_target_guard<T>(
    root_domain: Option<String>,
    future: impl std::future::Future<Output = T>,
) -> T {
    BLOCKED_EXTERNAL_TARGET.scope(root_domain, future).await
}

pub(super) fn retry_after_delay(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    httpdate::parse_http_date(value)
        .ok()?
        .duration_since(SystemTime::now())
        .ok()
}

fn unix_reset_delay(value: &str) -> Option<Duration> {
    let reset_at = value.trim().parse::<u64>().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset_at.saturating_sub(now)))
}

pub(super) fn backoff_delay(seed: &str, attempt: usize, base: Duration) -> Duration {
    let multiplier = 1_u32.checked_shl(attempt.min(8) as u32).unwrap_or(256);
    let base = base.saturating_mul(multiplier);
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    attempt.hash(&mut hasher);
    let jitter = Duration::from_millis(hasher.finish() % 500);
    base.saturating_add(jitter)
}

pub(super) fn retryable_status(status: reqwest::StatusCode) -> bool {
    status.as_u16() == 524
        || matches!(
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

pub(super) fn retry_safe_method(method: &reqwest::Method) -> bool {
    method == reqwest::Method::GET
        || method == reqwest::Method::HEAD
        || method == reqwest::Method::OPTIONS
        || method == reqwest::Method::TRACE
}

fn retryable_transport_error(error: &reqwest::Error) -> bool {
    if error.is_timeout() || error.is_body() {
        return true;
    }
    if !error.is_connect() {
        return false;
    }
    let mut message = String::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        if !message.is_empty() {
            message.push_str(": ");
        }
        message.push_str(&error.to_string());
        current = error.source();
    }
    let message = message.to_ascii_lowercase();
    !message.contains("connection refused")
        && !message.contains("connexion refusée")
        && !message.contains("certificate")
        && !message.contains("unknown issuer")
        && !message.contains("invalid peer certificate")
}

pub(super) fn host_minimum_gap(host: &str) -> Duration {
    match host {
        "api.github.com" => Duration::from_secs(6),
        "index.commoncrawl.org" => Duration::from_secs(2),
        "crt.sh" | "web.archive.org" => Duration::from_secs(1),
        "urlscan.io" | "api.urlscan.io" => Duration::from_millis(500),
        "api.certspotter.com" => Duration::from_millis(250),
        "api.search.brave.com" | "api.merklemap.com" => Duration::from_secs(3),
        "internetdb.shodan.io" => Duration::from_secs(1),
        _ => Duration::from_millis(100),
    }
}

pub(super) fn request_host(request: &reqwest::RequestBuilder) -> Option<(String, String)> {
    let request = request.try_clone()?.build().ok()?;
    let url = request.url();
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((format!("{host}|{port}"), host))
}

pub(super) async fn throttle_external_host(request: &reqwest::RequestBuilder) {
    let Some((limiter_key, host)) = request_host(request) else {
        return;
    };
    let limiter = {
        let mut limiters = EXTERNAL_HOST_LIMITERS
            .get_or_init(|| StdMutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limiters
            .entry(limiter_key)
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

pub(super) async fn throttle_external_source(source: &str) {
    let limiter = {
        let mut limiters = EXTERNAL_SOURCE_LIMITERS
            .get_or_init(|| StdMutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        limiters
            .entry(source.to_owned())
            .or_insert_with(|| Arc::new(TokioMutex::new(None)))
            .clone()
    };
    let requests_per_minute = transport_rate_limit_per_minute(source);
    let minimum_gap = Duration::from_millis(60_000_u64.div_ceil(u64::from(requests_per_minute)));
    let mut last_request = limiter.lock().await;
    if let Some(last) = *last_request
        && last.elapsed() < minimum_gap
    {
        tokio::time::sleep(minimum_gap.saturating_sub(last.elapsed())).await;
    }
    *last_request = Some(Instant::now());
}

/// Returns the rate limit for transport-only lanes which are deliberately not
/// exposed as passive connectors. Keeping these entries separate prevents an
/// internal content fetch from inheriting the conservative unknown-source
/// fallback while avoiding fake public source metadata.
pub(super) fn internal_transport_rate_limit_per_minute(source: &str) -> Option<u32> {
    const INTERNAL_TRANSPORT_RATES: &[(&str, u32)] = &[
        ("github-content", 600),
        ("gitlab-content", 600),
        ("shodan-internetdb", 60),
    ];
    INTERNAL_TRANSPORT_RATES
        .iter()
        .find_map(|(name, limit)| (*name == source).then_some(*limit))
}

pub(super) fn transport_rate_limit_per_minute(source: &str) -> u32 {
    internal_transport_rate_limit_per_minute(source)
        .or_else(|| try_source_metadata(source).map(|metadata| metadata.rate_limit_per_minute))
        .unwrap_or(1)
        .max(1)
}

pub(super) fn retry_delay_from_headers(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(retry_after_delay)
        .or_else(|| {
            headers
                .get("ratelimit-reset")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs)
        })
        .or_else(|| {
            headers
                .get("x-rate-limit-reset-after")
                .and_then(|value| value.to_str().ok())
                .and_then(retry_after_delay)
        })
        .or_else(|| {
            headers
                .get("x-ratelimit-reset-after")
                .and_then(|value| value.to_str().ok())
                .and_then(retry_after_delay)
        })
        .or_else(|| {
            headers
                .get("x-rate-limit-reset")
                .or_else(|| headers.get("x-ratelimit-reset"))
                .and_then(|value| value.to_str().ok())
                .and_then(unix_reset_delay)
        })
}

fn server_retry_delay(response: &reqwest::Response) -> Option<Duration> {
    retry_delay_from_headers(response.headers())
}

pub(super) fn exhausted_rate_limit(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get("ratelimit-remaining")
        .or_else(|| response.headers().get("x-rate-limit-remaining"))
        .or_else(|| response.headers().get("x-ratelimit-remaining"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == "0")
}

fn unsafe_log_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

pub(crate) fn compact_external_error(body: &str) -> String {
    const MAX_CHARACTERS: usize = 500;

    let prefix = body
        .trim_start()
        .chars()
        .take(4_096)
        .collect::<String>()
        .to_ascii_lowercase();
    let html = prefix.starts_with("<!doctype html")
        || prefix.starts_with("<html")
        || prefix.contains("<html ")
        || prefix.contains("<head>")
        || prefix.contains("<body>");
    if html {
        let anti_bot = [
            "cloudflare",
            "cf-chl-",
            "just a moment",
            "captcha",
            "challenge-platform",
            "checking your browser",
        ]
        .iter()
        .any(|marker| prefix.contains(marker));
        return if anti_bot {
            "HTML anti-bot challenge".to_owned()
        } else {
            "HTML error page".to_owned()
        };
    }

    let mut compact = String::with_capacity(body.len().min(MAX_CHARACTERS));
    let mut characters = 0_usize;
    let mut pending_space = false;
    let mut truncated = false;

    let mut input = body.chars().peekable();
    while let Some(character) = input.next() {
        if character == '\u{1b}' {
            match input.peek().copied() {
                Some('[') => {
                    input.next();
                    for sequence_character in input.by_ref() {
                        if ('@'..='~').contains(&sequence_character) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    input.next();
                    let mut escape = false;
                    for sequence_character in input.by_ref() {
                        if sequence_character == '\u{7}' || (escape && sequence_character == '\\') {
                            break;
                        }
                        escape = sequence_character == '\u{1b}';
                    }
                }
                Some(_) => {
                    input.next();
                }
                None => {}
            }
            continue;
        }
        if character.is_whitespace() {
            pending_space |= !compact.is_empty();
            continue;
        }
        if unsafe_log_character(character) {
            continue;
        }
        if pending_space {
            if characters >= MAX_CHARACTERS {
                truncated = true;
                break;
            }
            compact.push(' ');
            characters += 1;
            pending_space = false;
        }
        if characters >= MAX_CHARACTERS {
            truncated = true;
            break;
        }
        compact.push(character);
        characters += 1;
    }
    if truncated {
        compact.push('…');
    }
    compact
}

#[derive(Debug)]
pub(super) struct ResponseBufferError {
    message: String,
    retryable: bool,
}

impl fmt::Display for ResponseBufferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ResponseBufferError {}

/// Marks a response whose decoded body was already read completely and
/// bounded by `buffer_external_response`. Downstream parsers can consume that
/// single body allocation directly instead of copying it through another
/// chunk accumulator.
#[derive(Clone, Debug)]
pub(super) struct BufferedExternalBody;

pub(super) async fn buffer_external_response(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> std::result::Result<reqwest::Response, ResponseBufferError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(ResponseBufferError {
            message: format!(
                "réponse externe supérieure à {} Mio",
                max_bytes / 1024 / 1024
            ),
            retryable: false,
        });
    }
    let status = response.status();
    let retryable_body = status.is_success();
    let version = response.version();
    let url = response.url().clone();
    let mut headers = response.headers().clone();
    let extensions = std::mem::take(response.extensions_mut());
    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|error| ResponseBufferError {
                message: format!("HTTP {status}: lecture interrompue du corps: {error}"),
                retryable: retryable_body,
            })?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ResponseBufferError {
                message: format!(
                    "réponse externe décompressée supérieure à {} Mio",
                    max_bytes / 1024 / 1024
                ),
                retryable: false,
            });
        }
        body.extend_from_slice(&chunk);
    }
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    let mut rebuilt = http::Response::builder().status(status).version(version);
    *rebuilt
        .headers_mut()
        .expect("un constructeur de réponse HTTP valide expose toujours ses en-têtes") = headers;
    *rebuilt
        .extensions_mut()
        .expect("un constructeur de réponse HTTP valide expose toujours ses extensions") =
        extensions;
    let rebuilt = rebuilt.url(url);
    let mut response = rebuilt
        .body(reqwest::Body::from(body))
        .map(reqwest::Response::from)
        .map_err(|error| ResponseBufferError {
            message: format!("reconstruction de la réponse HTTP: {error}"),
            retryable: false,
        })?;
    response.extensions_mut().insert(BufferedExternalBody);
    Ok(response)
}

fn external_response_buffer_limit(source: Option<&str>) -> usize {
    if source == Some("commoncrawl") {
        COMMONCRAWL_MAX_BODY_BYTES
    } else if source == Some("shodan-internetdb") {
        256 * 1024
    } else {
        MAX_EXTERNAL_BODY_BYTES
    }
}

pub(crate) async fn response_bytes_limited_to(
    mut response: reqwest::Response,
    source: &str,
    max_bytes: usize,
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!(
            "{source}: réponse supérieure à {} Mio",
            max_bytes / 1024 / 1024
        );
    }
    let status = response.status();
    if response
        .extensions()
        .get::<BufferedExternalBody>()
        .is_some()
    {
        let body = response
            .bytes()
            .await
            .with_context(|| format!("lecture de la réponse {source}"))?;
        if body.len() > max_bytes {
            bail!(
                "{source}: réponse décompressée supérieure à {} Mio",
                max_bytes / 1024 / 1024
            );
        }
        // `Bytes -> Vec<u8>` reuses the owned Vec allocation when possible.
        // Responses rebuilt above contain exactly one owned body frame, so
        // this avoids the previous second full-body copy.
        return Ok((status, Vec::from(body)));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("lecture de la réponse {source}"))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            bail!(
                "{source}: réponse décompressée supérieure à {} Mio",
                max_bytes / 1024 / 1024
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, body))
}

pub(super) async fn response_bytes_limited(
    response: reqwest::Response,
    source: &str,
) -> Result<(reqwest::StatusCode, Vec<u8>)> {
    response_bytes_limited_to(response, source, MAX_EXTERNAL_BODY_BYTES).await
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
    if body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'<')
    {
        bail!("{source}: réponse HTML inattendue à la place de JSON");
    }
    let value = serde_json::from_slice::<serde_json::Value>(&body)
        .with_context(|| format!("JSON {source} invalide"))?;
    if let Some(message) = provider_error_message(&value) {
        bail!("{source}: erreur fournisseur: {message}");
    }
    if value.as_object().is_some_and(|object| object.is_empty()) {
        bail!("schéma JSON {source} incompatible: objet vide");
    }
    serde_json::from_value(value).with_context(|| format!("schéma JSON {source} incompatible"))
}

pub(super) fn provider_error_message(value: &serde_json::Value) -> Option<String> {
    let object = value.as_object()?;
    let status_error = object
        .get("status")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|status| status >= 400)
        || object
            .get("status")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|status| {
                matches!(
                    status.to_ascii_lowercase().as_str(),
                    "error" | "failed" | "unauthorized" | "forbidden"
                )
            });
    let code_error = object
        .get("code")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|code| code >= 400)
        || object
            .get("code")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|code| {
                let code = code.to_ascii_lowercase();
                code.contains("error")
                    || code.contains("unauthorized")
                    || code.contains("forbidden")
                    || code.contains("quota")
            });
    let failed = object.get("success").and_then(serde_json::Value::as_bool) == Some(false)
        || object
            .get("status")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|status| {
                matches!(status.to_ascii_lowercase().as_str(), "error" | "failed")
            })
        || status_error
        || code_error;
    for key in ["error", "errors"] {
        let Some(error) = object.get(key) else {
            continue;
        };
        let non_empty = match error {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::Number(value) => value.as_f64() != Some(0.0),
            serde_json::Value::String(value) => !value.trim().is_empty(),
            serde_json::Value::Array(values) => !values.is_empty(),
            serde_json::Value::Object(values) => !values.is_empty(),
        };
        if non_empty {
            return Some(compact_external_error(&error.to_string()));
        }
    }
    if failed {
        return object
            .get("message")
            .map(|message| compact_external_error(&message.to_string()))
            .or_else(|| Some("réponse marquée en échec".to_owned()));
    }
    let payload_keys = [
        "data",
        "domains",
        "events",
        "hosts",
        "items",
        "passive_dns",
        "records",
        "result",
        "results",
        "subdomains",
        "web",
    ];
    if !payload_keys.iter().any(|key| object.contains_key(*key))
        && let Some(message) = object
            .get("message")
            .or_else(|| object.get("detail"))
            .and_then(serde_json::Value::as_str)
            .filter(|message| !message.trim().is_empty())
    {
        return Some(compact_external_error(message));
    }
    None
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

pub(super) async fn response_text_limited(
    response: reqwest::Response,
    source: &str,
    max_bytes: usize,
) -> Result<String> {
    let (status, body) = response_bytes_limited_to(response, source, max_bytes).await?;
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
    send_with_retry_for_source(source, request, policy.attempts, policy.base_backoff, seed).await
}

/// Retry a provider request whose connector contract is explicitly read-only
/// and idempotent even though the HTTP method is POST. Generic POST requests
/// remain one-shot so this opt-in cannot replay mutations accidentally.
pub(super) async fn send_external_idempotent(
    source: &str,
    request: reqwest::RequestBuilder,
    seed: &str,
) -> Result<reqwest::Response> {
    let policy = source_policy(source);
    send_with_retry_scoped(
        Some(source),
        request,
        policy.attempts,
        policy.base_backoff,
        seed,
        true,
        true,
    )
    .await
}

/// Sends a provider request without first buffering its complete body.  This
/// is reserved for newline-delimited high-volume feeds whose decoded records
/// are checkpointed to SQLite in bounded batches while the response arrives.
pub(super) async fn send_external_streaming(
    source: &str,
    request: reqwest::RequestBuilder,
    seed: &str,
) -> Result<reqwest::Response> {
    let policy = source_policy(source);
    send_with_retry_scoped(
        Some(source),
        request,
        policy.attempts,
        policy.base_backoff,
        seed,
        false,
        false,
    )
    .await
}

/// Streams a read-only provider search whose POST contract is explicitly
/// idempotent. Only failures observed before a successful response is handed
/// to the decoder are retried; generic streaming POST requests remain
/// one-shot.
pub(super) async fn send_external_streaming_idempotent(
    source: &str,
    request: reqwest::RequestBuilder,
    seed: &str,
) -> Result<reqwest::Response> {
    let policy = source_policy(source);
    send_with_retry_scoped(
        Some(source),
        request,
        policy.attempts,
        policy.base_backoff,
        seed,
        false,
        true,
    )
    .await
}

pub(super) async fn send_with_retry_for_source(
    source: &str,
    request: reqwest::RequestBuilder,
    attempts: usize,
    base_backoff: Duration,
    seed: &str,
) -> Result<reqwest::Response> {
    send_with_retry_scoped(
        Some(source),
        request,
        attempts,
        base_backoff,
        seed,
        true,
        false,
    )
    .await
}

#[cfg(test)]
pub(super) async fn send_with_retry(
    request: reqwest::RequestBuilder,
    attempts: usize,
    base_backoff: Duration,
    seed: &str,
) -> Result<reqwest::Response> {
    send_with_retry_scoped(None, request, attempts, base_backoff, seed, true, false).await
}

pub(super) async fn send_with_retry_scoped(
    source: Option<&str>,
    request: reqwest::RequestBuilder,
    attempts: usize,
    base_backoff: Duration,
    seed: &str,
    buffer_response_body: bool,
    allow_idempotent_post_retry: bool,
) -> Result<reqwest::Response> {
    let request_snapshot = request
        .try_clone()
        .context("requête HTTP non clonable")?
        .build()
        .context("construction de la requête HTTP")?;
    ensure_external_url_allowed(request_snapshot.url())?;
    let method = request_snapshot.method().clone();
    let retry_safe = retry_safe_method(&method)
        || (allow_idempotent_post_retry && method == reqwest::Method::POST);
    let attempts = if retry_safe { attempts.max(1) } else { 1 };
    for attempt in 0..attempts {
        if let Some(source) = source {
            throttle_external_source(source).await;
        }
        throttle_external_host(&request).await;
        let response = request
            .try_clone()
            .context("requête HTTP non clonable")?
            .send()
            .await;
        match response {
            Ok(response) => {
                let retry_after = server_retry_delay(&response);
                // SecurityTrails uses an exact 403 from its scroll-capable
                // endpoint to select the documented legacy API. Return that
                // response to the connector even when quota headers exist.
                let rate_limited_forbidden = source != Some("securitytrails")
                    && response.status() == reqwest::StatusCode::FORBIDDEN
                    && exhausted_rate_limit(&response);
                let retryable = retryable_status(response.status()) || rate_limited_forbidden;
                if retryable {
                    if let Some(delay) = retry_after
                        && defer_retry_after(delay)
                    {
                        bail!(
                            "HTTP {} avec Retry-After={}s; nouvelle tentative différée",
                            response.status(),
                            delay.as_secs()
                        );
                    }
                    if attempt + 1 < attempts {
                        let delay = retry_after
                            .unwrap_or_else(|| backoff_delay(seed, attempt, base_backoff));
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || rate_limited_forbidden
                    {
                        let delay = retry_after.unwrap_or(Duration::from_secs(15 * 60));
                        bail!(
                            "HTTP {} avec Retry-After={}s; quota externe différé",
                            response.status(),
                            delay.as_secs()
                        );
                    }
                    if let Some(delay) = retry_after {
                        bail!(
                            "HTTP {} avec Retry-After={}s; service amont temporairement différé",
                            response.status(),
                            delay.as_secs()
                        );
                    }
                }
                if !buffer_response_body {
                    return Ok(response);
                }
                let response = match buffer_external_response(
                    response,
                    external_response_buffer_limit(source),
                )
                .await
                {
                    Ok(response) => response,
                    Err(error) if error.retryable && attempt + 1 < attempts => {
                        tokio::time::sleep(backoff_delay(seed, attempt, base_backoff)).await;
                        continue;
                    }
                    Err(error) => {
                        return Err(anyhow::Error::msg(sanitize_external_message(
                            &format!("{error:#}"),
                            &[],
                        )));
                    }
                };
                return Ok(response);
            }
            Err(error) => {
                if attempt + 1 >= attempts || !retryable_transport_error(&error) {
                    return Err(anyhow::Error::msg(sanitize_external_message(
                        &format!("{error:#}"),
                        &[],
                    )));
                }
                tokio::time::sleep(backoff_delay(seed, attempt, base_backoff)).await;
            }
        }
    }
    unreachable!("au moins une tentative HTTP est toujours exécutée")
}
