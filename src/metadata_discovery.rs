use crate::dns::{DnsEngine, DnsResolutionOutcome};
use crate::util::{extract_observed_names, is_subdomain, normalize_domain, normalize_hostname};
use anyhow::Result;
use futures_util::{Stream, StreamExt, stream};
use reqwest::header::{ACCEPT, CONTENT_LOCATION, CONTENT_TYPE, HeaderMap, LINK, LOCATION, RANGE};
use reqwest::{Client, Url};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const ENDPOINTS: [MetadataEndpoint; 6] = [
    MetadataEndpoint::ApiCatalog,
    MetadataEndpoint::OpenIdConfiguration,
    MetadataEndpoint::OauthAuthorizationServer,
    MetadataEndpoint::SshKnownHosts,
    MetadataEndpoint::Terraform,
    MetadataEndpoint::HostMeta,
];
const MAX_DNS_CONCURRENCY: usize = 8;

/// A deliberately small list of standardized metadata documents. Fellaga
/// probes only these paths; this module is not a generic crawler.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetadataEndpoint {
    ApiCatalog,
    OpenIdConfiguration,
    OauthAuthorizationServer,
    SshKnownHosts,
    Terraform,
    HostMeta,
}

impl MetadataEndpoint {
    pub const fn path(self) -> &'static str {
        match self {
            Self::ApiCatalog => "/.well-known/api-catalog",
            Self::OpenIdConfiguration => "/.well-known/openid-configuration",
            Self::OauthAuthorizationServer => "/.well-known/oauth-authorization-server",
            Self::SshKnownHosts => "/.well-known/ssh-known-hosts",
            Self::Terraform => "/.well-known/terraform.json",
            Self::HostMeta => "/.well-known/host-meta",
        }
    }

    pub const fn source_name(self) -> &'static str {
        match self {
            Self::ApiCatalog => "metadata:api-catalog",
            Self::OpenIdConfiguration => "metadata:openid-configuration",
            Self::OauthAuthorizationServer => "metadata:oauth-authorization-server",
            Self::SshKnownHosts => "metadata:ssh-known-hosts",
            Self::Terraform => "metadata:terraform",
            Self::HostMeta => "metadata:host-meta",
        }
    }
}

#[derive(Clone, Debug)]
pub struct MetadataDiscoveryConfig {
    /// Maximum bytes retained from one response body. One additional byte is
    /// read only to report truncation accurately.
    pub max_body_bytes: usize,
    /// Maximum number of manually followed redirects for one seed URL.
    pub max_redirects: usize,
    /// Global HTTP request budget, including redirects and nested catalogs.
    pub max_requests: usize,
    pub request_timeout: Duration,
    /// One absolute wall-clock deadline shared by hostname resolution, HTTPS
    /// requests, redirects, nested catalogs, and response-body reads.
    pub phase_deadline: Option<tokio::time::Instant>,
    /// Small bounded fan-out used only while pinning approved hostnames.
    pub dns_concurrency: usize,
}

impl Default for MetadataDiscoveryConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 512 * 1024,
            max_redirects: 2,
            max_requests: 64,
            request_timeout: Duration::from_secs(8),
            phase_deadline: None,
            dns_concurrency: 4,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataObservation {
    pub url: String,
    pub endpoint: MetadataEndpoint,
    pub status: u16,
    pub names: BTreeSet<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
    pub redirect_hops: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataFailure {
    pub url: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct MetadataDiscovery {
    pub observations: Vec<MetadataObservation>,
    pub unique_names: BTreeSet<String>,
    pub failures: Vec<MetadataFailure>,
    pub skipped_unsafe_hosts: Vec<String>,
    pub network_requests: usize,
    /// Successful response body bytes retained for parsing. HTTP framing and
    /// bodies rejected before parsing are not included.
    pub bytes_transferred: u64,
    pub budget_exhausted: bool,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ParsedMetadata {
    pub names: BTreeSet<String>,
    /// Only in-scope API catalog URLs are returned. The caller still checks
    /// that their hosts were approved and DNS-pinned before following them.
    pub nested_catalogs: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct PendingUrl {
    url: Url,
    endpoint: MetadataEndpoint,
    redirect_hops: usize,
}

fn endpoint_urls(host: &str) -> impl Iterator<Item = PendingUrl> + '_ {
    ENDPOINTS.into_iter().filter_map(move |endpoint| {
        Url::parse(&format!("https://{host}{}", endpoint.path()))
            .ok()
            .map(|url| PendingUrl {
                url,
                endpoint,
                redirect_hops: 0,
            })
    })
}

fn canonical_url(mut url: Url) -> Url {
    url.set_fragment(None);
    url
}

fn url_is_in_scope(url: &Url, domain: &str) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url
            .host_str()
            .is_some_and(|host| host == domain || is_subdomain(host, domain))
}

fn url_uses_approved_host(url: &Url, approved_hosts: &BTreeSet<String>) -> bool {
    url.host_str()
        .is_some_and(|host| approved_hosts.contains(host))
}

fn public_web_ip(address: IpAddr) -> bool {
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
                return public_web_ip(IpAddr::V4(embedded));
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

fn operation_deadline(
    timeout: Duration,
    phase_deadline: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    let request_deadline = tokio::time::Instant::now() + timeout;
    phase_deadline.map_or(request_deadline, |deadline| deadline.min(request_deadline))
}

fn phase_expired(deadline: Option<tokio::time::Instant>) -> bool {
    deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now())
}

async fn collect_stream_until_deadline<S, T>(
    pending: &mut S,
    deadline: Option<tokio::time::Instant>,
) -> (Vec<T>, bool)
where
    S: Stream<Item = T> + Unpin,
{
    let mut completed = Vec::new();
    loop {
        let next = if let Some(deadline) = deadline {
            match tokio::time::timeout_at(deadline, pending.next()).await {
                Ok(next) => next,
                Err(_) => return (completed, true),
            }
        } else {
            pending.next().await
        };
        match next {
            Some(item) => completed.push(item),
            None => return (completed, false),
        }
    }
}

async fn resolve_public_hosts(
    dns: &DnsEngine,
    hosts: &[String],
    timeout: Duration,
    phase_deadline: Option<tokio::time::Instant>,
    concurrency: usize,
) -> (BTreeMap<String, Vec<SocketAddr>>, Vec<String>, bool) {
    let mut pinned = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut unfinished = hosts.iter().cloned().collect::<BTreeSet<_>>();
    let dns = dns.clone();
    let mut pending = Box::pin(
        stream::iter(hosts.iter().cloned())
            .map(move |host| {
                let dns = dns.clone();
                async move {
                    let deadline = operation_deadline(timeout, phase_deadline);
                    let lookup = tokio::time::timeout_at(
                        deadline,
                        dns.resolve_host_consensus_classified(&host),
                    )
                    .await;
                    let addresses = match lookup {
                        Ok(DnsResolutionOutcome::Positive(answer)) => answer
                            .records
                            .into_iter()
                            .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
                            .filter_map(|record| record.value.parse::<IpAddr>().ok())
                            .collect::<BTreeSet<_>>(),
                        Ok(DnsResolutionOutcome::Negative { .. })
                        | Ok(DnsResolutionOutcome::Indeterminate { .. })
                        | Err(_) => BTreeSet::new(),
                    }
                    .into_iter()
                    .filter(|address| public_web_ip(*address))
                    .map(|address| SocketAddr::new(address, 0))
                    .collect::<Vec<_>>();
                    (host, addresses)
                }
            })
            .buffer_unordered(concurrency.clamp(1, MAX_DNS_CONCURRENCY)),
    );
    let (completed, budget_exhausted) =
        collect_stream_until_deadline(&mut pending, phase_deadline).await;
    drop(pending);
    for (host, addresses) in completed {
        unfinished.remove(&host);
        if addresses.is_empty() {
            skipped.push(host);
        } else {
            pinned.insert(host, addresses);
        }
    }
    skipped.extend(unfinished);
    skipped.sort();
    skipped.dedup();
    (pinned, skipped, budget_exhausted)
}

fn collect_json_strings<'a>(value: &'a Value, output: &mut Vec<&'a str>) {
    match value {
        Value::String(value) => output.push(value),
        Value::Array(values) => {
            for value in values {
                collect_json_strings(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_json_strings(value, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn quoted_xml_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut quote = None;
    let mut start = 0;
    for (index, character) in text.char_indices() {
        match quote {
            None if matches!(character, '\'' | '"') => {
                quote = Some(character);
                start = index + character.len_utf8();
            }
            Some(opening) if character == opening => {
                values.push(
                    text[start..index]
                        .replace("&amp;", "&")
                        .replace("&quot;", "\"")
                        .replace("&apos;", "'"),
                );
                quote = None;
            }
            _ => {}
        }
    }
    values
}

fn extract_known_hosts(text: &str, domain: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or_default();
        let hosts = if first.starts_with('@') {
            fields.next().unwrap_or_default()
        } else {
            first
        };
        for raw in hosts.split(',') {
            let mut candidate = raw.trim_start_matches('!');
            if candidate.starts_with('|') {
                // OpenSSH hashed hostnames are intentionally not reversible.
                continue;
            }
            if let Some(rest) = candidate.strip_prefix('[')
                && let Some((host, port)) = rest.rsplit_once("]:")
                && port.bytes().all(|byte| byte.is_ascii_digit())
            {
                candidate = host;
            }
            if let Some(name) = normalize_hostname(candidate)
                && is_subdomain(&name, domain)
            {
                names.insert(name);
            }
        }
    }
    names
}

fn possible_catalog_url(raw: &str, base: &Url, domain: &str) -> Option<String> {
    let raw = raw.trim();
    let value = raw
        .find('<')
        .and_then(|start| {
            raw[start + 1..]
                .find('>')
                .map(|end| &raw[start + 1..start + 1 + end])
        })
        .unwrap_or(raw)
        .trim_matches(|character: char| {
            character.is_whitespace()
                || matches!(character, '<' | '>' | '"' | '\'' | '(' | ')' | ',' | ';')
        });
    let url = base.join(value).ok().map(canonical_url)?;
    let path = url.path().trim_end_matches('/');
    (url_is_in_scope(&url, domain)
        && (path.ends_with("/.well-known/api-catalog") || path.ends_with("/api-catalog")))
    .then(|| url.to_string())
}

fn collect_names_and_catalogs(
    values: impl IntoIterator<Item = String>,
    base: &Url,
    domain: &str,
    parsed: &mut ParsedMetadata,
) {
    for value in values {
        parsed.names.extend(extract_observed_names(&value, domain));
        if let Some(url) = possible_catalog_url(&value, base, domain) {
            parsed.nested_catalogs.insert(url);
        }
    }
}

/// Parses one metadata response without executing scripts or interpreting
/// active content. JSON and linksets are walked as data; XML parsing is limited
/// to quoted attribute values and text extraction.
pub fn parse_metadata_document(
    endpoint: MetadataEndpoint,
    content_type: &str,
    body: &[u8],
    header_values: &str,
    base: &Url,
    domain: &str,
) -> ParsedMetadata {
    let body = String::from_utf8_lossy(body);
    let mut parsed = ParsedMetadata::default();
    parsed
        .names
        .extend(extract_observed_names(header_values, domain));
    collect_names_and_catalogs(
        header_values.lines().map(ToOwned::to_owned),
        base,
        domain,
        &mut parsed,
    );

    let json_like = content_type.to_ascii_lowercase().contains("json")
        || matches!(
            endpoint,
            MetadataEndpoint::ApiCatalog
                | MetadataEndpoint::OpenIdConfiguration
                | MetadataEndpoint::OauthAuthorizationServer
                | MetadataEndpoint::Terraform
        );
    let mut parsed_json = false;
    if json_like && let Ok(json) = serde_json::from_str::<Value>(&body) {
        let mut strings = Vec::new();
        collect_json_strings(&json, &mut strings);
        collect_names_and_catalogs(
            strings.into_iter().map(ToOwned::to_owned),
            base,
            domain,
            &mut parsed,
        );
        parsed_json = true;
    }

    if endpoint == MetadataEndpoint::SshKnownHosts {
        parsed.names.extend(extract_known_hosts(&body, domain));
    }
    if endpoint == MetadataEndpoint::HostMeta || content_type.to_ascii_lowercase().contains("xml") {
        collect_names_and_catalogs(quoted_xml_values(&body), base, domain, &mut parsed);
    }
    if !parsed_json {
        parsed.names.extend(extract_observed_names(&body, domain));
        collect_names_and_catalogs(
            body.lines().map(ToOwned::to_owned),
            base,
            domain,
            &mut parsed,
        );
    }
    parsed
}

fn relevant_header_text(headers: &HeaderMap) -> String {
    [LOCATION, CONTENT_LOCATION, LINK]
        .into_iter()
        .flat_map(|name| headers.get_all(name).iter())
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn bounded_body(
    mut response: reqwest::Response,
    max_body_bytes: usize,
) -> Result<(Vec<u8>, bool)> {
    let probe_limit = max_body_bytes.saturating_add(1);
    let mut body = Vec::with_capacity(probe_limit.min(64 * 1024));
    while body.len() < probe_limit {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = probe_limit.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    let truncated = body.len() > max_body_bytes;
    body.truncate(max_body_bytes);
    Ok((body, truncated))
}

fn push_failure(discovery: &mut MetadataDiscovery, url: &Url, reason: impl Into<String>) {
    discovery.failures.push(MetadataFailure {
        url: url.to_string(),
        reason: reason.into(),
    });
}

/// Discovers standardized metadata on the target apex and on explicitly
/// supplied in-scope hosts. All approved hostnames are resolved to public IPs
/// and pinned into reqwest before the first request, preventing DNS rebinding.
/// When configured, one absolute deadline bounds DNS pinning, HTTPS requests,
/// redirects, and body reads; observations completed before expiry are kept.
pub async fn discover_metadata(
    dns: &DnsEngine,
    domain: &str,
    hosts: Vec<String>,
    config: MetadataDiscoveryConfig,
) -> Result<MetadataDiscovery> {
    let domain = normalize_domain(domain)?;
    let mut discovery = MetadataDiscovery::default();
    if config.max_requests == 0 || phase_expired(config.phase_deadline) {
        discovery.budget_exhausted = true;
        return Ok(discovery);
    }

    let maximum_hosts = config.max_requests.div_ceil(ENDPOINTS.len()).max(1);
    let mut candidates = BTreeSet::new();
    for host in hosts {
        if let Some(host) = normalize_hostname(&host)
            && (host == domain || is_subdomain(&host, &domain))
        {
            candidates.insert(host);
        }
    }
    candidates.remove(&domain);
    let mut selected_hosts = vec![domain.clone()];
    selected_hosts.extend(candidates.into_iter().take(maximum_hosts.saturating_sub(1)));

    let (pinned_hosts, skipped, resolution_budget_exhausted) = resolve_public_hosts(
        dns,
        &selected_hosts,
        config.request_timeout,
        config.phase_deadline,
        config.dns_concurrency,
    )
    .await;
    discovery.skipped_unsafe_hosts = skipped;
    discovery.budget_exhausted = resolution_budget_exhausted;
    if pinned_hosts.is_empty() {
        return Ok(discovery);
    }

    let approved_hosts = pinned_hosts.keys().cloned().collect::<BTreeSet<_>>();
    let mut builder = Client::builder()
        .timeout(config.request_timeout)
        .connect_timeout(config.request_timeout)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .user_agent(concat!(
            "Fellaga-SubDomainFinder/",
            env!("CARGO_PKG_VERSION"),
            " metadata-discovery"
        ));
    for (host, addresses) in &pinned_hosts {
        builder = builder.resolve_to_addrs(host, addresses);
    }
    let client = builder.build()?;

    let mut pending = VecDeque::new();
    // Keep the apex first even if another hostname sorts before it.
    if approved_hosts.contains(&domain) {
        pending.extend(endpoint_urls(&domain));
    }
    for host in approved_hosts.iter().filter(|host| *host != &domain) {
        pending.extend(endpoint_urls(host));
    }
    let mut visited = BTreeSet::new();

    loop {
        if phase_expired(config.phase_deadline) {
            discovery.budget_exhausted = true;
            break;
        }
        let Some(item) = pending.pop_front() else {
            break;
        };
        let item = PendingUrl {
            url: canonical_url(item.url),
            ..item
        };
        if !url_is_in_scope(&item.url, &domain)
            || !url_uses_approved_host(&item.url, &approved_hosts)
            || !visited.insert(item.url.to_string())
        {
            continue;
        }
        if discovery.network_requests >= config.max_requests {
            discovery.budget_exhausted = true;
            break;
        }

        discovery.network_requests += 1;
        let range_end = config.max_body_bytes;
        let request = client
            .get(item.url.clone())
            .header(
                ACCEPT,
                "application/json, application/linkset+json, application/jrd+json, application/xml, text/plain;q=0.9, */*;q=0.1",
            )
            .header(RANGE, format!("bytes=0-{range_end}"))
            .send();
        let response = if let Some(deadline) = config.phase_deadline {
            match tokio::time::timeout_at(deadline, request).await {
                Ok(response) => response,
                Err(_) => {
                    discovery.budget_exhausted = true;
                    push_failure(&mut discovery, &item.url, "metadata phase deadline reached");
                    break;
                }
            }
        } else {
            request.await
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                push_failure(&mut discovery, &item.url, error.to_string());
                continue;
            }
        };
        let status = response.status();
        let headers = response.headers().clone();
        let header_values = relevant_header_text(&headers);
        let mut header_parsed = parse_metadata_document(
            item.endpoint,
            "text/plain",
            &[],
            &header_values,
            &item.url,
            &domain,
        );

        if status.is_redirection() {
            let names = std::mem::take(&mut header_parsed.names);
            discovery.unique_names.extend(names.clone());
            discovery.observations.push(MetadataObservation {
                url: item.url.to_string(),
                endpoint: item.endpoint,
                status: status.as_u16(),
                names,
                body_bytes: 0,
                body_truncated: false,
                redirect_hops: item.redirect_hops,
            });
            let redirect = headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|location| item.url.join(location).ok())
                .map(canonical_url);
            match redirect {
                Some(url)
                    if item.redirect_hops < config.max_redirects
                        && url_is_in_scope(&url, &domain)
                        && url_uses_approved_host(&url, &approved_hosts) =>
                {
                    pending.push_front(PendingUrl {
                        url,
                        endpoint: item.endpoint,
                        redirect_hops: item.redirect_hops + 1,
                    });
                }
                Some(_) if item.redirect_hops >= config.max_redirects => {
                    push_failure(&mut discovery, &item.url, "redirect limit reached");
                }
                Some(_) => {
                    push_failure(&mut discovery, &item.url, "unsafe redirect rejected");
                }
                None => {
                    push_failure(
                        &mut discovery,
                        &item.url,
                        "redirect without a valid Location",
                    );
                }
            }
            continue;
        }

        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if !status.is_success() {
            let names = std::mem::take(&mut header_parsed.names);
            discovery.unique_names.extend(names.clone());
            discovery.observations.push(MetadataObservation {
                url: item.url.to_string(),
                endpoint: item.endpoint,
                status: status.as_u16(),
                names,
                body_bytes: 0,
                body_truncated: false,
                redirect_hops: item.redirect_hops,
            });
            push_failure(&mut discovery, &item.url, format!("HTTP {status}"));
            continue;
        }

        let body_result = if let Some(deadline) = config.phase_deadline {
            match tokio::time::timeout_at(deadline, bounded_body(response, config.max_body_bytes))
                .await
            {
                Ok(body) => body,
                Err(_) => {
                    let names = std::mem::take(&mut header_parsed.names);
                    discovery.unique_names.extend(names.clone());
                    discovery.observations.push(MetadataObservation {
                        url: item.url.to_string(),
                        endpoint: item.endpoint,
                        status: status.as_u16(),
                        names,
                        body_bytes: 0,
                        body_truncated: true,
                        redirect_hops: item.redirect_hops,
                    });
                    discovery.budget_exhausted = true;
                    push_failure(
                        &mut discovery,
                        &item.url,
                        "metadata phase deadline reached while reading response body",
                    );
                    break;
                }
            }
        } else {
            bounded_body(response, config.max_body_bytes).await
        };
        let (body, body_truncated) = match body_result {
            Ok(body) => body,
            Err(error) => {
                push_failure(
                    &mut discovery,
                    &item.url,
                    format!("reading response body: {error}"),
                );
                continue;
            }
        };
        let parsed = parse_metadata_document(
            item.endpoint,
            &content_type,
            &body,
            &header_values,
            &item.url,
            &domain,
        );
        discovery.unique_names.extend(parsed.names.clone());
        discovery.observations.push(MetadataObservation {
            url: item.url.to_string(),
            endpoint: item.endpoint,
            status: status.as_u16(),
            names: parsed.names,
            body_bytes: body.len(),
            body_truncated,
            redirect_hops: item.redirect_hops,
        });
        if item.endpoint == MetadataEndpoint::ApiCatalog {
            for nested in parsed.nested_catalogs {
                if let Ok(url) = Url::parse(&nested)
                    && url_uses_approved_host(&url, &approved_hosts)
                    && !visited.contains(url.as_str())
                {
                    pending.push_back(PendingUrl {
                        url,
                        endpoint: MetadataEndpoint::ApiCatalog,
                        redirect_hops: 0,
                    });
                }
            }
        }
    }

    discovery
        .observations
        .sort_by(|left, right| left.url.cmp(&right.url));
    discovery.bytes_transferred = discovery
        .observations
        .iter()
        .map(|observation| observation.body_bytes as u64)
        .sum();
    discovery
        .failures
        .sort_by(|left, right| left.url.cmp(&right.url));
    Ok(discovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    const API_CATALOG: &str = include_str!("../tests/fixtures/metadata/api-catalog.json");
    const OPENID: &str = include_str!("../tests/fixtures/metadata/openid.json");
    const SSH_KNOWN_HOSTS: &str = include_str!("../tests/fixtures/metadata/ssh-known-hosts");
    const HOST_META: &str = include_str!("../tests/fixtures/metadata/host-meta.xml");

    #[test]
    fn endpoint_list_is_small_stable_and_standardized() {
        assert_eq!(
            ENDPOINTS.map(MetadataEndpoint::path),
            [
                "/.well-known/api-catalog",
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/ssh-known-hosts",
                "/.well-known/terraform.json",
                "/.well-known/host-meta",
            ]
        );
    }

    #[test]
    fn json_and_linksets_return_only_strict_subdomains() {
        let base = Url::parse("https://example.com/.well-known/api-catalog").unwrap();
        let parsed = parse_metadata_document(
            MetadataEndpoint::ApiCatalog,
            "application/linkset+json",
            API_CATALOG.as_bytes(),
            "<https://catalog.example.com/.well-known/api-catalog>; rel=service-desc",
            &base,
            "example.com",
        );
        assert_eq!(
            parsed.names,
            BTreeSet::from([
                "api.example.com".to_owned(),
                "catalog.example.com".to_owned(),
                "developer.example.com".to_owned(),
            ])
        );
        assert_eq!(
            parsed.nested_catalogs,
            BTreeSet::from(["https://catalog.example.com/.well-known/api-catalog".to_owned(),])
        );
        assert!(!parsed.names.contains("example.com"));
        assert!(
            !parsed
                .names
                .iter()
                .any(|name| name.ends_with("example.net"))
        );
    }

    #[test]
    fn oidc_endpoint_fields_are_extracted_as_data() {
        let base = Url::parse("https://example.com/.well-known/openid-configuration").unwrap();
        let parsed = parse_metadata_document(
            MetadataEndpoint::OpenIdConfiguration,
            "application/json",
            OPENID.as_bytes(),
            "",
            &base,
            "example.com",
        );
        assert_eq!(
            parsed.names,
            BTreeSet::from([
                "auth.example.com".to_owned(),
                "keys.example.com".to_owned(),
                "login.example.com".to_owned(),
            ])
        );
    }

    #[test]
    fn openssh_syntax_skips_wildcards_hashes_and_out_of_scope_patterns() {
        let base = Url::parse("https://example.com/.well-known/ssh-known-hosts").unwrap();
        let parsed = parse_metadata_document(
            MetadataEndpoint::SshKnownHosts,
            "text/plain",
            SSH_KNOWN_HOSTS.as_bytes(),
            "",
            &base,
            "example.com",
        );
        assert_eq!(
            parsed.names,
            BTreeSet::from(["git.example.com".to_owned(), "ssh.example.com".to_owned(),])
        );
    }

    #[test]
    fn host_meta_extracts_quoted_xml_attributes_without_an_xml_engine() {
        let base = Url::parse("https://example.com/.well-known/host-meta").unwrap();
        let parsed = parse_metadata_document(
            MetadataEndpoint::HostMeta,
            "application/xrd+xml",
            HOST_META.as_bytes(),
            "",
            &base,
            "example.com",
        );
        assert_eq!(
            parsed.names,
            BTreeSet::from([
                "accounts.example.com".to_owned(),
                "webfinger.example.com".to_owned(),
            ])
        );
    }

    #[test]
    fn scope_rejects_credentials_ports_downgrades_and_sibling_domains() {
        for accepted in [
            "https://example.com/.well-known/api-catalog",
            "https://api.example.com/.well-known/api-catalog",
        ] {
            assert!(url_is_in_scope(
                &Url::parse(accepted).unwrap(),
                "example.com"
            ));
        }
        for rejected in [
            "http://api.example.com/.well-known/api-catalog",
            "https://api.example.com:8443/.well-known/api-catalog",
            "https://user@api.example.com/.well-known/api-catalog",
            "https://example.com.evil.test/.well-known/api-catalog",
        ] {
            assert!(!url_is_in_scope(
                &Url::parse(rejected).unwrap(),
                "example.com"
            ));
        }
    }

    #[test]
    fn ssrf_filter_allows_public_addresses_only() {
        assert!(public_web_ip("1.1.1.1".parse().unwrap()));
        assert!(public_web_ip("2606:4700:4700::1111".parse().unwrap()));
        for rejected in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(!public_web_ip(rejected.parse().unwrap()), "{rejected}");
        }
    }

    #[tokio::test]
    async fn an_expired_shared_deadline_prevents_any_network_dequeue() {
        let dns = DnsEngine::new(
            1,
            Duration::from_millis(50),
            &["127.0.0.1".parse().unwrap()],
        )
        .unwrap();
        let discovery = tokio::time::timeout(
            Duration::from_millis(100),
            discover_metadata(
                &dns,
                "example.com",
                vec!["example.com".to_owned()],
                MetadataDiscoveryConfig {
                    phase_deadline: Some(tokio::time::Instant::now() - Duration::from_millis(1)),
                    ..MetadataDiscoveryConfig::default()
                },
            ),
        )
        .await
        .expect("an expired phase must return immediately")
        .unwrap();

        assert!(discovery.budget_exhausted);
        assert_eq!(discovery.network_requests, 0);
        assert!(discovery.observations.is_empty());
    }

    #[tokio::test]
    async fn deadline_collection_preserves_results_completed_before_expiry() {
        let delayed = stream::unfold(0_u8, |state| async move {
            match state {
                0 => Some(("first", 1)),
                1 => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Some(("second", 2))
                }
                _ => None,
            }
        });
        let mut delayed = Box::pin(delayed);
        let (completed, exhausted) = collect_stream_until_deadline(
            &mut delayed,
            Some(tokio::time::Instant::now() + Duration::from_millis(25)),
        )
        .await;

        assert!(exhausted);
        assert_eq!(completed, vec!["first"]);
    }
}
