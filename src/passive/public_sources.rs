//! Bounded public passive-provider connectors.
//!
//! These connectors talk only to the named third-party providers.  Every
//! response is size-limited by the parent passive transport, every returned
//! hostname is normalized against the requested suffix, and provider-driven
//! pagination is capped locally.

use super::{
    ApiKeyStore, client, commit_result_page, compact_external_error, response_bytes_limited_to,
    response_json, send_external, send_external_idempotent, send_external_streaming,
};
use crate::util::{
    extract_observed_names, normalize_domain, normalize_hostname, normalize_observed_name,
};
use anyhow::{Context, Result, bail};
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use url::Url;

const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SUBMD_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_SUBMD_LINE_BYTES: usize = 64 * 1024;
const MAX_SHREWDEYE_STREAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_SHREWDEYE_LINE_BYTES: usize = 1_024;
const MAX_SHREWDEYE_RECORDS: usize = 1_000_000;
const MAX_ARQUIVO_STREAM_BYTES: usize = 32 * 1024 * 1024;
const MAX_PUBLIC_STREAM_LINE_BYTES: usize = 64 * 1024;
const PUBLIC_STREAM_COMMIT_BATCH: usize = 1_000;
const PUBLIC_STREAM_CHECKPOINT_INTERVAL: Duration = Duration::from_millis(500);
const ARQUIVO_RESULT_LIMIT: usize = 50_000;
const MAX_RAPID_DNS_PAGES: usize = 1_000;
const MAX_SITE_DOSSIER_PAGES: usize = 1_000;
const MAX_THC_PAGES: usize = 1_000;
const THC_PAGE_SIZE: usize = 1_000;

fn canonical_domain(domain: &str) -> Result<String> {
    normalize_domain(domain).context("invalid passive-provider target domain")
}

fn normalize_many<'a>(values: impl IntoIterator<Item = &'a str>, domain: &str) -> BTreeSet<String> {
    values
        .into_iter()
        .filter_map(|value| normalize_observed_name(value, domain))
        .collect()
}

fn extract_names_from_text(text: &str, domain: &str) -> BTreeSet<String> {
    let mut names = extract_observed_names(text, domain);
    names.extend(
        text.split(|character: char| {
            !character.is_ascii_alphanumeric()
                && character != '.'
                && character != '-'
                && character != '*'
        })
        .filter_map(|token| normalize_observed_name(token, domain)),
    );
    names
}

fn submd_line_names(line: &[u8], domain: &str) -> Result<BTreeSet<String>> {
    let line = std::str::from_utf8(line).context("sub.md: non UTF-8 record")?;
    Ok(extract_names_from_text(line.trim(), domain))
}

#[derive(Debug, Deserialize)]
struct ArquivoCdxRow {
    url: String,
}

fn arquivo_cdx_line_names(line: &[u8], domain: &str) -> Result<BTreeSet<String>> {
    let row: ArquivoCdxRow =
        serde_json::from_slice(line).context("Arquivo.pt: invalid CDX JSON record")?;
    let url = Url::parse(row.url.trim()).context("Arquivo.pt: invalid archived URL")?;
    let host = url
        .host_str()
        .context("Arquivo.pt: archived URL has no hostname")?;
    Ok(normalize_observed_name(host, domain).into_iter().collect())
}

fn public_stream_line_names(line: &[u8], domain: &str) -> Result<BTreeSet<String>> {
    let line = std::str::from_utf8(line).context("ShrewdEye: non UTF-8 record")?;
    let line = line.trim();
    if line.starts_with("*.") {
        return Ok(BTreeSet::new());
    }
    let hostname = normalize_hostname(line).context("ShrewdEye: invalid hostname record")?;
    Ok(normalize_observed_name(&hostname, domain)
        .into_iter()
        .collect())
}

async fn collect_streamed_lines<F>(
    mut response: reqwest::Response,
    source: &str,
    domain: &str,
    max_bytes: usize,
    max_line_bytes: usize,
    max_records: Option<usize>,
    mut parse_line: F,
) -> Result<BTreeSet<String>>
where
    F: FnMut(&[u8], &str) -> Result<BTreeSet<String>>,
{
    if !response.status().is_success() {
        let status = response.status();
        let text = bounded_text(response, source, MAX_TEXT_BYTES).await?;
        bail!("{source}: HTTP {status}: {}", compact_external_error(&text));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!(
            "{source}: response exceeds the {} MiB stream budget",
            max_bytes / 1024 / 1024
        );
    }
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.starts_with("text/html") || value.starts_with("application/xhtml+xml")
        })
    {
        bail!("{source}: réponse HTML inattendue à la place du flux de données attendu");
    }

    let mut names = BTreeSet::new();
    let mut batch = BTreeSet::new();
    let mut carry = Vec::new();
    let mut bytes_seen = 0_usize;
    let mut records_seen = 0_usize;
    let mut last_checkpoint = Instant::now();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                commit_result_page(&mut names, std::mem::take(&mut batch));
                return Err(error).with_context(|| format!("{source}: interrupted stream"));
            }
        };
        bytes_seen = bytes_seen
            .checked_add(chunk.len())
            .with_context(|| format!("{source}: response byte counter overflow"))?;
        if bytes_seen > max_bytes {
            commit_result_page(&mut names, std::mem::take(&mut batch));
            bail!(
                "{source}: stream exceeded the {} MiB budget after committed batches",
                max_bytes / 1024 / 1024
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
                if pending > max_line_bytes {
                    commit_result_page(&mut names, std::mem::take(&mut batch));
                    bail!("{source}: record exceeds {max_line_bytes} bytes");
                }
                carry.extend_from_slice(remaining);
                break;
            };
            let segment = &remaining[..newline];
            let line_length = carry
                .len()
                .checked_add(segment.len())
                .with_context(|| format!("{source}: record length overflow"))?;
            if line_length > max_line_bytes {
                commit_result_page(&mut names, std::mem::take(&mut batch));
                bail!("{source}: record exceeds {max_line_bytes} bytes");
            }
            carry.extend_from_slice(segment);
            let line = carry.strip_suffix(b"\r").unwrap_or(&carry);
            if !line.is_empty() {
                records_seen = records_seen.saturating_add(1);
                if max_records.is_some_and(|limit| records_seen > limit) {
                    commit_result_page(&mut names, std::mem::take(&mut batch));
                    bail!("{source}: local record cap reached; committed results are partial");
                }
                match parse_line(line, domain) {
                    Ok(line_names) => batch.extend(line_names),
                    Err(error) => {
                        commit_result_page(&mut names, std::mem::take(&mut batch));
                        return Err(error);
                    }
                }
            }
            if batch.len() >= PUBLIC_STREAM_COMMIT_BATCH {
                commit_result_page(&mut names, std::mem::take(&mut batch));
                last_checkpoint = Instant::now();
            }
            carry.clear();
            offset = offset.saturating_add(newline).saturating_add(1);
        }
        // A short time checkpoint retains partial progress without turning
        // arbitrary HTTP chunk boundaries into one SQLite transaction each.
        if !batch.is_empty() && last_checkpoint.elapsed() >= PUBLIC_STREAM_CHECKPOINT_INTERVAL {
            commit_result_page(&mut names, std::mem::take(&mut batch));
            last_checkpoint = Instant::now();
        }
    }
    if !carry.is_empty() {
        let line = carry.strip_suffix(b"\r").unwrap_or(&carry);
        if !line.is_empty() {
            records_seen = records_seen.saturating_add(1);
            if max_records.is_some_and(|limit| records_seen > limit) {
                commit_result_page(&mut names, std::mem::take(&mut batch));
                bail!("{source}: local record cap reached; committed results are partial");
            }
            batch.extend(parse_line(line, domain)?);
        }
    }
    commit_result_page(&mut names, batch);
    Ok(names)
}

async fn bounded_text(
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
    String::from_utf8(body).with_context(|| format!("{source}: response is not UTF-8"))
}

fn query_page_numbers(html: &str) -> BTreeSet<usize> {
    let mut pages = BTreeSet::new();
    let mut remaining = html;
    const NEEDLE: &str = "?page=";
    while let Some(offset) = remaining.find(NEEDLE) {
        remaining = &remaining[offset + NEEDLE.len()..];
        let digit_count = remaining.bytes().take_while(u8::is_ascii_digit).count();
        if (1..=8).contains(&digit_count)
            && let Some(value) = remaining.get(..digit_count)
            && let Ok(page) = value.parse::<usize>()
            && page > 0
        {
            pages.insert(page);
        }
        if remaining.is_empty() {
            break;
        }
        let advance = if digit_count > 0 {
            digit_count
        } else {
            remaining.chars().next().map(char::len_utf8).unwrap_or(1)
        };
        remaining = &remaining[advance..];
    }
    pages
}

fn rapid_dns_page(html: &str, domain: &str) -> (BTreeSet<String>, usize) {
    let names = extract_names_from_text(html, domain);
    let maximum_page = query_page_numbers(html).into_iter().max().unwrap_or(1);
    (names, maximum_page)
}

fn site_dossier_next_path(html: &str) -> Option<String> {
    const PREFIX: &str = "<a href=\"";
    let mut remaining = html;
    while let Some(offset) = remaining.find(PREFIX) {
        remaining = &remaining[offset + PREFIX.len()..];
        let end = remaining.find('"')?;
        let candidate = &remaining[..end];
        let link_suffix = &remaining[end + 1..];
        if link_suffix.starts_with("><b>")
            && candidate.starts_with("/parentdomain/")
            && candidate.len() <= 512
            && candidate.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_')
            })
        {
            return Some(candidate.to_owned());
        }
        remaining = &remaining[end + 1..];
    }
    None
}

#[derive(Debug, Deserialize)]
struct ThcResponse {
    domains: Vec<ThcDomain>,
    next_page_state: String,
}

#[derive(Debug, Deserialize)]
struct ThcDomain {
    domain: String,
}

#[derive(Debug, Serialize)]
struct ThcRequest<'a> {
    domain: &'a str,
    page_state: &'a str,
    limit: usize,
}

fn thc_page_names(page: &ThcResponse, domain: &str) -> BTreeSet<String> {
    normalize_many(
        page.domains.iter().map(|record| record.domain.as_str()),
        domain,
    )
}

#[derive(Debug, Deserialize)]
struct HudsonRockResponse {
    data: HudsonRockData,
}

#[derive(Debug, Deserialize)]
struct HudsonRockData {
    #[serde(default)]
    employees_urls: Vec<HudsonRockUrl>,
    #[serde(default)]
    clients_urls: Vec<HudsonRockUrl>,
}

#[derive(Debug, Deserialize)]
struct HudsonRockUrl {
    url: String,
}

fn hudson_rock_names(response: &HudsonRockResponse, domain: &str) -> BTreeSet<String> {
    response
        .data
        .employees_urls
        .iter()
        .chain(&response.data.clients_urls)
        .flat_map(|record| extract_names_from_text(&record.url, domain))
        .collect()
}

#[derive(Debug, Deserialize)]
struct ThreatCrowdResponse {
    response_code: Value,
    #[serde(default)]
    subdomains: Vec<String>,
}

fn threat_crowd_names(response: &ThreatCrowdResponse, domain: &str) -> Result<BTreeSet<String>> {
    let accepted = match &response.response_code {
        Value::Number(value) => matches!(value.as_i64(), Some(0 | 1)),
        Value::String(value) => matches!(value.trim(), "0" | "1"),
        _ => false,
    };
    if !accepted {
        bail!("ThreatCrowd: unsupported response_code");
    }
    Ok(normalize_many(
        response.subdomains.iter().map(String::as_str),
        domain,
    ))
}

#[derive(Debug, Deserialize)]
struct ReconeERResponse {
    subdomains: Vec<ReconeERName>,
}

#[derive(Debug, Deserialize)]
struct ReconeERName {
    subdomain: String,
}

fn reconeer_names(response: &ReconeERResponse, domain: &str) -> BTreeSet<String> {
    normalize_many(
        response
            .subdomains
            .iter()
            .map(|record| record.subdomain.as_str()),
        domain,
    )
}

#[derive(Debug, Deserialize)]
struct ReconCloudResponse {
    cloud_assets_list: Vec<ReconCloudAsset>,
}

#[derive(Debug, Deserialize)]
struct ReconCloudAsset {
    domain: String,
}

fn recon_cloud_names(response: &ReconCloudResponse, domain: &str) -> BTreeSet<String> {
    normalize_many(
        response
            .cloud_assets_list
            .iter()
            .map(|asset| asset.domain.as_str()),
        domain,
    )
}

#[derive(Debug, Deserialize)]
struct ThreatMinerResponse {
    status_code: String,
    #[serde(default)]
    status_message: String,
    #[serde(default)]
    results: Vec<String>,
}

fn threat_miner_names(response: &ThreatMinerResponse, domain: &str) -> Result<BTreeSet<String>> {
    match response.status_code.trim() {
        "200" => Ok(normalize_many(
            response.results.iter().map(String::as_str),
            domain,
        )),
        "404" if response.results.is_empty() => Ok(BTreeSet::new()),
        status => bail!(
            "ThreatMiner: status {status}: {}",
            compact_external_error(&response.status_message)
        ),
    }
}

pub(super) async fn anubis(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external(
        "anubis",
        client(timeout)?.get(format!("https://jonlu.ca/anubis/subdomains/{domain}")),
        &domain,
    )
    .await?;
    let names = response_json::<Vec<String>>(response, "Anubis").await?;
    Ok(normalize_many(names.iter().map(String::as_str), &domain))
}

pub(super) async fn shodanct(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external(
        "shodanct",
        client(timeout)?.get(format!(
            "https://ctl.shodan.io/api/v1/domain/{domain}/hostnames"
        )),
        &domain,
    )
    .await?;
    let hostnames = response_json::<Vec<String>>(response, "Shodan CT").await?;
    Ok(normalize_many(
        hostnames.iter().map(String::as_str),
        &domain,
    ))
}

pub(super) async fn shrewdeye(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external_streaming(
        "shrewdeye",
        client(timeout)?.get(format!("https://shrewdeye.app/domains/{domain}.txt")),
        &domain,
    )
    .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(BTreeSet::new());
    }
    collect_streamed_lines(
        response,
        "ShrewdEye",
        &domain,
        MAX_SHREWDEYE_STREAM_BYTES,
        MAX_SHREWDEYE_LINE_BYTES,
        Some(MAX_SHREWDEYE_RECORDS),
        public_stream_line_names,
    )
    .await
}

pub(super) async fn arquivopt(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let result_limit = ARQUIVO_RESULT_LIMIT.saturating_add(1).to_string();
    let response = send_external_streaming(
        "arquivopt",
        client(timeout)?
            .get("https://arquivo.pt/wayback/cdx")
            .query(&[
                ("url", domain.as_str()),
                ("matchType", "domain"),
                ("output", "json"),
                ("fields", "url"),
                ("limit", result_limit.as_str()),
            ]),
        &domain,
    )
    .await?;
    collect_streamed_lines(
        response,
        "Arquivo.pt",
        &domain,
        MAX_ARQUIVO_STREAM_BYTES,
        MAX_PUBLIC_STREAM_LINE_BYTES,
        Some(ARQUIVO_RESULT_LIMIT),
        arquivo_cdx_line_names,
    )
    .await
}

pub(super) async fn thc(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut page_state = String::new();
    let mut seen_states = BTreeSet::new();

    for page_index in 0..MAX_THC_PAGES {
        let body = ThcRequest {
            domain: &domain,
            page_state: &page_state,
            limit: THC_PAGE_SIZE,
        };
        let response = send_external_idempotent(
            "thc",
            http.post("https://ip.thc.org/api/v1/lookup/subdomains")
                .json(&body),
            &format!("{domain}:{page_index}"),
        )
        .await?;
        let page = response_json::<ThcResponse>(response, "THC").await?;
        commit_result_page(&mut names, thc_page_names(&page, &domain));

        let next = page.next_page_state.trim();
        if next.is_empty() {
            return Ok(names);
        }
        if next.len() > 4_096 || !seen_states.insert(next.to_owned()) {
            bail!("THC: invalid or repeated pagination state");
        }
        page_state.clear();
        page_state.push_str(next);
    }
    bail!("THC: pagination exceeded {MAX_THC_PAGES} pages")
}

pub(super) async fn submd(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let http = client(timeout)?;
    let mut request = http
        .get("https://api.sub.md/v1/search")
        .query(&[("apex", domain.as_str())]);
    if let Some(token) = keys.optional("submd") {
        request = request.bearer_auth(token);
    }
    let response = send_external_streaming("submd", request, &domain).await?;
    collect_streamed_lines(
        response,
        "sub.md",
        &domain,
        MAX_SUBMD_STREAM_BYTES,
        MAX_SUBMD_LINE_BYTES,
        None,
        submd_line_names,
    )
    .await
}

pub(super) async fn rapiddns(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut maximum_page = 1_usize;

    for page in 1..=MAX_RAPID_DNS_PAGES {
        let response = send_external(
            "rapiddns",
            http.get(format!("https://rapiddns.io/subdomain/{domain}"))
                .query(&[("page", page), ("full", 1_usize)]),
            &format!("{domain}:{page}"),
        )
        .await?;
        let html = bounded_text(response, "RapidDNS", MAX_TEXT_BYTES).await?;
        let (page_names, advertised_maximum) = rapid_dns_page(&html, &domain);
        commit_result_page(&mut names, page_names);
        if page == 1 {
            maximum_page = advertised_maximum;
            if maximum_page > MAX_RAPID_DNS_PAGES {
                bail!(
                    "RapidDNS: provider advertised {maximum_page} pages; local cap is {MAX_RAPID_DNS_PAGES}"
                );
            }
        }
        if page >= maximum_page {
            return Ok(names);
        }
    }
    bail!("RapidDNS: pagination did not terminate")
}

pub(super) async fn sitedossier(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let http = client(timeout)?;
    let mut names = BTreeSet::new();
    let mut path = format!("/parentdomain/{domain}");
    let mut seen_paths = BTreeSet::new();

    for page in 0..MAX_SITE_DOSSIER_PAGES {
        if !seen_paths.insert(path.clone()) {
            bail!("SiteDossier: repeated pagination path");
        }
        let response = send_external(
            "sitedossier",
            // SiteDossier's public endpoint is HTTP-only. No credential is
            // sent, and the provider deliberately returns useful result pages
            // with HTTP 404 for unknown or exhausted parent listings.
            http.get(format!("http://www.sitedossier.com{path}")),
            &format!("{domain}:{page}"),
        )
        .await?;
        let (status, body) =
            response_bytes_limited_to(response, "SiteDossier", MAX_TEXT_BYTES).await?;
        if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
            bail!(
                "SiteDossier: HTTP {status}: {}",
                compact_external_error(&String::from_utf8_lossy(&body))
            );
        }
        let html = String::from_utf8(body).context("SiteDossier: response is not valid UTF-8")?;
        commit_result_page(&mut names, extract_names_from_text(&html, &domain));
        let Some(next) = site_dossier_next_path(&html) else {
            return Ok(names);
        };
        path = next;
    }
    bail!("SiteDossier: pagination exceeded {MAX_SITE_DOSSIER_PAGES} pages")
}

pub(super) async fn hudsonrock(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external(
        "hudsonrock",
        client(timeout)?
            .get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/urls-by-domain")
            .query(&[("domain", domain.as_str())]),
        &domain,
    )
    .await?;
    let response = response_json::<HudsonRockResponse>(response, "Hudson Rock").await?;
    Ok(hudson_rock_names(&response, &domain))
}

pub(super) async fn threatcrowd(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external(
        "threatcrowd",
        client(timeout)?
            // This legacy public endpoint is exposed over HTTP only. It does
            // not receive credentials, and the returned names remain
            // unverified until Fellaga's separate DNS validation stage.
            .get("http://ci-www.threatcrowd.org/searchApi/v2/domain/report/")
            .query(&[("domain", domain.as_str())]),
        &domain,
    )
    .await?;
    let response = response_json::<ThreatCrowdResponse>(response, "ThreatCrowd").await?;
    threat_crowd_names(&response, &domain)
}

pub(super) async fn reconeer(
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let token = keys.pick("reconeer")?;
    let request = client(timeout)?
        .get(format!("https://www.reconeer.com/api/domain/{domain}"))
        .header(reqwest::header::ACCEPT, "application/json")
        .header("X-API-KEY", token);
    let response = send_external("reconeer", request, &domain).await?;
    let response = response_json::<ReconeERResponse>(response, "ReconeER").await?;
    Ok(reconeer_names(&response, &domain))
}

pub(super) async fn reconcloud(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external(
        "reconcloud",
        client(timeout)?
            .get("https://recon.cloud/api/search")
            .query(&[("domain", domain.as_str())]),
        &domain,
    )
    .await?;
    let response = response_json::<ReconCloudResponse>(response, "Recon Cloud").await?;
    Ok(recon_cloud_names(&response, &domain))
}

pub(super) async fn riddler(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let query = format!("pld:{domain}");
    let response = send_external(
        "riddler",
        client(timeout)?
            .get("https://riddler.io/search")
            .query(&[("q", query.as_str()), ("view_type", "data_table")]),
        &domain,
    )
    .await?;
    let text = bounded_text(response, "Riddler", MAX_TEXT_BYTES).await?;
    Ok(extract_names_from_text(&text, &domain))
}

pub(super) async fn threatminer(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let domain = canonical_domain(domain)?;
    let response = send_external(
        "threatminer",
        client(timeout)?
            .get("https://api.threatminer.org/v2/domain.php")
            .query(&[("q", domain.as_str()), ("rt", "5")]),
        &domain,
    )
    .await?;
    let response = response_json::<ThreatMinerResponse>(response, "ThreatMiner").await?;
    threat_miner_names(&response, &domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shodan_ct_fixture_keeps_only_strict_subdomains() {
        let values: Vec<String> = serde_json::from_str(
            r#"["api.example.com","*.wild.example.com","example.com","evil.test"]"#,
        )
        .unwrap();
        assert_eq!(
            normalize_many(values.iter().map(String::as_str), "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
        );
    }

    #[test]
    fn anubis_fixture_keeps_only_the_requested_suffix() {
        let values: Vec<String> =
            serde_json::from_str(r#"["api.example.com","example.com","evil.test"]"#).unwrap();
        assert_eq!(
            normalize_many(values.iter().map(String::as_str), "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
        );
    }

    #[test]
    fn shrewdeye_fixture_keeps_only_strict_subdomains() {
        assert_eq!(
            public_stream_line_names(b"api.example.com\r", "example.com").unwrap(),
            BTreeSet::from(["api.example.com".to_owned()])
        );
        assert!(
            public_stream_line_names(b"example.com", "example.com")
                .unwrap()
                .is_empty()
        );
        assert!(
            public_stream_line_names(b"evil.test", "example.com")
                .unwrap()
                .is_empty()
        );
        assert!(
            public_stream_line_names(b"*.wild.example.com", "example.com")
                .unwrap()
                .is_empty()
        );
        assert!(public_stream_line_names(b"<html>", "example.com").is_err());
        assert!(public_stream_line_names(&[0xff], "example.com").is_err());
    }

    #[test]
    fn arquivo_cdx_fixture_extracts_only_the_archived_url_host() {
        assert_eq!(
            arquivo_cdx_line_names(
                br#"{"url":"https://deep.api.example.com/a?next=evil.test"}"#,
                "example.com"
            )
            .unwrap(),
            BTreeSet::from(["deep.api.example.com".to_owned()])
        );
        assert!(
            arquivo_cdx_line_names(br#"{"url":"https://evil.test/example.com"}"#, "example.com")
                .unwrap()
                .is_empty()
        );
        assert!(arquivo_cdx_line_names(br#"{"original":"missing"}"#, "example.com").is_err());
    }

    #[test]
    fn thc_fixture_parses_cursor_and_scoped_names() {
        let page: ThcResponse = serde_json::from_str(
            r#"{"domains":[{"domain":"a.example.com"},{"domain":"evil.test"}],"next_page_state":"cursor-2"}"#,
        )
        .unwrap();
        assert_eq!(page.next_page_state, "cursor-2");
        assert_eq!(
            thc_page_names(&page, "example.com"),
            BTreeSet::from(["a.example.com".to_owned()])
        );
    }

    #[test]
    fn submd_lines_are_strictly_normalized() {
        let text = "a.example.com\n*.b.example.com\nexample.com\nevil.test\n";
        assert_eq!(
            extract_names_from_text(text, "example.com"),
            BTreeSet::from(["a.example.com".to_owned()])
        );
        assert_eq!(
            submd_line_names(b"https://deep.api.example.com/path\r", "example.com").unwrap(),
            BTreeSet::from(["deep.api.example.com".to_owned()])
        );
        assert!(submd_line_names(&[0xff, b'\n'], "example.com").is_err());
    }

    #[test]
    fn rapid_dns_fixture_bounds_page_discovery_and_extracts_names() {
        let html = r#"<td>a.example.com</td><a class="page-link" href="/subdomain/example.com?page=7">7</a><span>evil.test</span>"#;
        let (names, maximum) = rapid_dns_page(html, "example.com");
        assert_eq!(maximum, 7);
        assert_eq!(names, BTreeSet::from(["a.example.com".to_owned()]));
        assert!(query_page_numbers("?page=999999999999999999999").is_empty());
    }

    #[test]
    fn site_dossier_accepts_only_relative_provider_paths() {
        assert_eq!(
            site_dossier_next_path(
                r#"<a href="https://evil.test/parentdomain/example.com"><b>x</b></a><a href="/parentdomain/example.com/2"><b>next</b></a>"#
            )
            .as_deref(),
            Some("/parentdomain/example.com/2")
        );
        assert!(site_dossier_next_path(r#"<a href="//evil.test/x"><b>x</b></a>"#).is_none());
    }

    #[test]
    fn hudson_rock_fixture_extracts_only_target_urls() {
        let response: HudsonRockResponse = serde_json::from_str(
            r#"{"data":{"employees_urls":[{"url":"https://staff.example.com/login"}],"clients_urls":[{"url":"https://evil.test/"},{"url":"https://api.example.com/v1"}]}}"#,
        )
        .unwrap();
        assert_eq!(
            hudson_rock_names(&response, "example.com"),
            BTreeSet::from(["api.example.com".to_owned(), "staff.example.com".to_owned()])
        );
    }

    #[test]
    fn threat_crowd_fixture_rejects_unknown_status_and_filters_scope() {
        let response: ThreatCrowdResponse = serde_json::from_str(
            r#"{"response_code":"1","subdomains":["a.example.com","evil.test"]}"#,
        )
        .unwrap();
        assert_eq!(
            threat_crowd_names(&response, "example.com").unwrap(),
            BTreeSet::from(["a.example.com".to_owned()])
        );
        let invalid: ThreatCrowdResponse =
            serde_json::from_str(r#"{"response_code":"error","subdomains":["a.example.com"]}"#)
                .unwrap();
        assert!(threat_crowd_names(&invalid, "example.com").is_err());

        let empty: ThreatCrowdResponse = serde_json::from_str(r#"{"response_code":"0"}"#).unwrap();
        assert!(
            threat_crowd_names(&empty, "example.com")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reconeer_fixture_requires_the_documented_shape() {
        let response: ReconeERResponse = serde_json::from_str(
            r#"{"subdomains":[{"subdomain":"a.example.com"},{"subdomain":"evil.test"}]}"#,
        )
        .unwrap();
        assert_eq!(
            reconeer_names(&response, "example.com"),
            BTreeSet::from(["a.example.com".to_owned()])
        );
        assert!(serde_json::from_str::<ReconeERResponse>(r#"{"results":[]}"#).is_err());
    }

    #[test]
    fn recon_cloud_fixture_requires_assets_and_filters_scope() {
        let response: ReconCloudResponse = serde_json::from_str(
            r#"{"msg_type":"result","request_id":"1","on_cache":true,"step":"done","cloud_assets_list":[{"key":"a","domain":"cdn.example.com","cloud_provider":"aws"},{"key":"b","domain":"evil.test","cloud_provider":"other"}]}"#,
        )
        .unwrap();
        assert_eq!(
            recon_cloud_names(&response, "example.com"),
            BTreeSet::from(["cdn.example.com".to_owned()])
        );
        assert!(serde_json::from_str::<ReconCloudResponse>(r#"{"results":[]}"#).is_err());
    }

    #[test]
    fn riddler_fixture_is_bounded_to_the_requested_suffix() {
        let fixture = "host,ip\napi.example.com,192.0.2.1\nevil.test,192.0.2.2\n";
        assert_eq!(
            extract_names_from_text(fixture, "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
        );
    }

    #[test]
    fn threat_miner_fixture_validates_provider_status() {
        let response: ThreatMinerResponse = serde_json::from_str(
            r#"{"status_code":"200","status_message":"Results found.","results":["a.example.com","evil.test"]}"#,
        )
        .unwrap();
        assert_eq!(
            threat_miner_names(&response, "example.com").unwrap(),
            BTreeSet::from(["a.example.com".to_owned()])
        );
        let failure: ThreatMinerResponse =
            serde_json::from_str(r#"{"status_code":"500","status_message":"failed","results":[]}"#)
                .unwrap();
        assert!(threat_miner_names(&failure, "example.com").is_err());

        let empty: ThreatMinerResponse = serde_json::from_str(r#"{"status_code":"404"}"#).unwrap();
        assert!(
            threat_miner_names(&empty, "example.com")
                .unwrap()
                .is_empty()
        );
    }
}
