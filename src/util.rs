use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn normalize_domain(input: &str) -> Result<String> {
    let raw = input.trim();
    if raw.is_empty() {
        bail!("la cible est vide");
    }
    let candidate = if raw.contains("://") {
        Url::parse(raw)?
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("URL sans nom d'hôte"))?
            .to_owned()
    } else {
        raw.trim_end_matches('.').to_owned()
    };
    let domain = candidate.to_ascii_lowercase();
    if domain.len() > 253 || !domain.contains('.') || !valid_fqdn(&domain) {
        bail!("nom de domaine invalide: {input}");
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        bail!("une adresse IP ne peut pas être énumérée comme un domaine");
    }
    Ok(domain)
}

pub fn valid_fqdn(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(valid_label)
}

pub fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

pub fn valid_relative_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.split('.').all(valid_label)
}

pub fn learnable_label(label: &str) -> bool {
    if !valid_label(label)
        || label.len() > 32
        || !label.bytes().any(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    let compact = label.replace('-', "");
    let hexish = compact.len() >= 12 && compact.bytes().all(|byte| byte.is_ascii_hexdigit());
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    !hexish && digits <= std::cmp::max(4, label.len() / 2)
}

pub fn learnable_relative_name(name: &str) -> bool {
    valid_relative_name(name) && name.split('.').all(learnable_label)
}

pub fn is_subdomain(name: &str, domain: &str) -> bool {
    name != domain && name.ends_with(&format!(".{domain}"))
}

pub fn normalize_observed_name(name: &str, domain: &str) -> Option<String> {
    let candidate = normalize_hostname(name)?;
    is_subdomain(&candidate, domain).then_some(candidate)
}

pub fn normalize_hostname(name: &str) -> Option<String> {
    let candidate = name
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (valid_fqdn(&candidate) && candidate.contains('.')).then_some(candidate)
}

pub fn reverse_hostname(name: &str) -> String {
    name.split('.').rev().collect::<Vec<_>>().join(".")
}

pub fn extract_observed_names(text: &str, domain: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut inspect = |raw: &str| {
        let raw = raw
            .trim_matches(|character: char| {
                character.is_whitespace()
                    || matches!(
                        character,
                        '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
                    )
            })
            .trim_end_matches('.');
        if raw.is_empty() {
            return;
        }
        if let Ok(url) = url::Url::parse(raw)
            && let Some(host) = url.host_str()
            && let Some(name) = normalize_observed_name(host, domain)
        {
            names.insert(name);
        }
        let mut variants = vec![raw];
        if let Some((_, value)) = raw.rsplit_once('=') {
            variants.push(value);
        }
        if let Some((_, value)) = raw.rsplit_once(':') {
            variants.push(value);
        }
        if let Some((_, value)) = raw.rsplit_once('@') {
            variants.push(value);
        }
        for variant in variants {
            let candidate = variant
                .trim_start_matches("//")
                .trim_start_matches("*.")
                .split('/')
                .next()
                .unwrap_or_default()
                .trim_end_matches('.')
                .trim_end_matches(|character: char| !character.is_ascii_alphanumeric());
            let candidate = if candidate.matches(':').count() == 1 {
                candidate
                    .rsplit_once(':')
                    .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
                    .map(|(host, _)| host)
                    .unwrap_or(candidate)
            } else {
                candidate
            };
            if let Some(name) = normalize_observed_name(candidate, domain) {
                names.insert(name);
            }
        }
    };
    for token in text.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
    }) {
        inspect(token);
    }
    names
}

pub fn labels_from_name(name: &str, domain: &str) -> BTreeSet<String> {
    name.strip_suffix(&format!(".{domain}"))
        .unwrap_or_default()
        .split('.')
        .filter(|label| valid_label(label))
        .map(ToOwned::to_owned)
        .collect()
}

pub fn read_wordlist(path: &Path) -> Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut words = Vec::new();
    for raw in fs::read_to_string(path)?.lines() {
        let word = raw
            .split('#')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if valid_relative_name(&word) && seen.insert(word.clone()) {
            words.push(word);
        }
    }
    Ok(words)
}

pub fn domain_hash(domain: &str) -> String {
    format!("{:x}", Sha256::digest(domain.as_bytes()))
}

pub fn registrable_domain(name: &str) -> Option<String> {
    let normalized = name.trim_end_matches('.').to_ascii_lowercase();
    let domain = psl::domain(normalized.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(ToOwned::to_owned)
}

pub fn public_suffix(name: &str) -> Option<String> {
    let normalized = name.trim_end_matches('.').to_ascii_lowercase();
    let suffix = psl::suffix(normalized.as_bytes())?;
    std::str::from_utf8(suffix.as_bytes())
        .ok()
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hostname_normalization_is_idempotent(
            labels in prop::collection::vec("[a-zA-Z0-9][a-zA-Z0-9-]{0,20}", 2..6)
        ) {
            let raw = format!("{}.", labels.join("."));
            if let Some(normalized) = normalize_hostname(&raw) {
                prop_assert_eq!(normalize_hostname(&normalized), Some(normalized));
            }
        }

        #[test]
        fn observed_name_never_escapes_the_requested_domain(
            label in "[a-zA-Z][a-zA-Z0-9]{0,20}"
        ) {
            let raw = format!("*.{label}.EXAMPLE.COM.");
            let normalized = normalize_observed_name(&raw, "example.com").unwrap();
            prop_assert!(normalized.ends_with(".example.com"));
            prop_assert_ne!(normalized, "example.com");
        }
    }

    #[test]
    fn domain_normalization_accepts_urls() {
        assert_eq!(
            normalize_domain("https://Example.COM/path").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn observed_names_stay_in_scope() {
        assert_eq!(
            normalize_observed_name("*.Api.Example.com", "example.com").as_deref(),
            Some("api.example.com")
        );
        assert!(normalize_observed_name("example.net", "example.com").is_none());
    }

    #[test]
    fn extracts_names_from_dns_metadata_and_urls() {
        let names = extract_observed_names(
            "10 mail.example.com. include:_spf.example.com https://api.example.com/v1 rua=mailto:dmarc@reports.example.com unrelated.net",
            "example.com",
        );
        assert_eq!(
            names,
            BTreeSet::from([
                "api.example.com".to_owned(),
                "mail.example.com".to_owned(),
                "reports.example.com".to_owned(),
            ])
        );
    }

    #[test]
    fn noisy_identifiers_are_not_learned() {
        assert!(!learnable_label("122519cc-648a-40ca-aea0-d12ad13ff4e3"));
        assert!(!learnable_label("abcdef1234567890"));
        assert!(!learnable_label("123"));
        assert!(learnable_label("api-v2"));
        assert!(learnable_relative_name("api.dev"));
    }

    #[test]
    fn global_hostnames_are_normalized_and_reversed() {
        assert_eq!(
            normalize_hostname("*.API.Example.COM.").as_deref(),
            Some("api.example.com")
        );
        assert_eq!(reverse_hostname("api.example.com"), "com.example.api");
    }

    #[test]
    fn public_suffix_list_handles_multi_label_suffixes() {
        assert_eq!(
            registrable_domain("api.shop.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            public_suffix("api.shop.example.co.uk").as_deref(),
            Some("co.uk")
        );
    }
}
