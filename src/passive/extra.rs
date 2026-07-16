use super::{
    ApiKeyStore, client, response_bytes_limited, response_json, response_text, send_external,
    send_with_retry, source_policy,
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
                Err(_) if !names.is_empty() => break,
                Err(error) => return Err(error),
            },
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("connexion à Censys"),
        };
        if let Some(hits) = response.pointer("/result/hits").and_then(Value::as_array) {
            for hit in hits {
                if let Some(values) = hit.get("names").and_then(Value::as_array) {
                    names.extend(
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .filter_map(|name| normalize_observed_name(name, domain)),
                    );
                }
            }
        }
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
                Err(_) if !names.is_empty() => break,
                Err(error) => return Err(error),
            },
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("connexion à GitHub Code Search"),
        };
        let items = response.get("items").and_then(Value::as_array);
        let Some(items) = items else { break };
        if items.is_empty() {
            break;
        }
        for item in items {
            if let Some(matches) = item.get("text_matches").and_then(Value::as_array) {
                for text_match in matches {
                    if let Some(fragment) = text_match.get("fragment").and_then(Value::as_str) {
                        names.extend(extract_from_text(fragment, domain));
                    }
                }
            }
        }
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
            Err(_) if !names.is_empty() => break,
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
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error),
        };
        for value in &values {
            extract_from_json(value, domain, &mut names);
        }
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
                Err(_) if !names.is_empty() => break,
                Err(error) => return Err(error),
            },
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("lecture des résultats Intelligence X"),
        };
        if let Some(selectors) = response.get("selectors").and_then(Value::as_array) {
            for selector in selectors {
                if let Some(name) = selector.get("selectorvalue").and_then(Value::as_str)
                    && let Some(name) = normalize_observed_name(name, domain)
                {
                    names.insert(name);
                }
            }
        }
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
                Err(_) if !names.is_empty() => break,
                Err(error) => return Err(error),
            },
            Err(_) if !names.is_empty() => break,
            Err(error) => return Err(error).context("connexion à Shodan"),
        };
        names.extend(
            response
                .subdomains
                .into_iter()
                .filter_map(|label| normalize_observed_name(&format!("{label}.{domain}"), domain)),
        );
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
