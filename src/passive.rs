use crate::archive_intelligence::{ArchiveLimits, analyze_common_crawl_warc};
use crate::model::EvidenceFamily;
use crate::util::normalize_observed_name;
use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use futures_util::{StreamExt, TryStreamExt, stream};
use reqwest::ResponseBuilderExt;
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_LENGTH, CONTENT_RANGE, HeaderMap, HeaderValue, RANGE,
    RETRY_AFTER, TRANSFER_ENCODING,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex as TokioMutex, Semaphore};
use url::Url;

mod extra;
mod keyed_sources;
mod public_sources;

#[derive(Clone, Default)]
pub struct ApiKeyStore {
    keys: BTreeMap<String, Vec<String>>,
    cursor: Arc<AtomicUsize>,
}

impl fmt::Debug for ApiKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyStore([REDACTED])")
    }
}

#[derive(Deserialize, Serialize, Default)]
struct ConfigFile {
    #[serde(default)]
    api_keys: BTreeMap<String, KeyList>,
}

impl fmt::Debug for ConfigFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigFile { api_keys: [REDACTED] }")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum KeyList {
    One(String),
    Many(Vec<String>),
}

impl fmt::Debug for KeyList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
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
        // Fellaga-native AnubisDB endpoint, distinct from the `anubis` provider.
        automatic: true,
    },
    SourceDefinition {
        name: "bevigil",
        requires_key: true,
        key_environment: Some("BEVIGIL_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "binaryedge",
        requires_key: true,
        key_environment: Some("BINARYEDGE_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "brave",
        requires_key: true,
        key_environment: Some("BRAVE_SEARCH_API_KEY"),
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
        requires_key: true,
        key_environment: Some("DRIFTNET_API_KEY"),
        automatic: true,
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
        key_environment: Some("HACKERTARGET_API_KEY"),
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
        name: "merklemap",
        requires_key: true,
        key_environment: Some("MERKLEMAP_API_TOKEN"),
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
        requires_key: true,
        key_environment: Some("OTX_API_KEY"),
        // Backward-compatible alias for the canonical `alienvault` name.
        automatic: false,
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
        automatic: true,
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
        // Backward-compatible alias for the canonical `whoisxmlapi` name.
        automatic: false,
    },
    SourceDefinition {
        name: "wayback",
        requires_key: false,
        key_environment: None,
        // Backward-compatible alias for the canonical `waybackarchive` name.
        automatic: false,
    },
    // Complete provider coverage for every module in the pinned upstream
    // audit set. Providers disabled
    // upstream remain explicitly selectable here so a remote outage or bot
    // challenge never makes a connector silently disappear from the registry.
    SourceDefinition {
        name: "alienvault",
        requires_key: true,
        key_environment: Some("ALIENVAULT_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "anubis",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "bufferover",
        requires_key: true,
        key_environment: Some("BUFFEROVER_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "c99",
        requires_key: true,
        key_environment: Some("C99_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "chinaz",
        requires_key: true,
        key_environment: Some("CHINAZ_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "digitalyama",
        requires_key: true,
        key_environment: Some("DIGITALYAMA_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "digitorus",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "dnsdb",
        requires_key: true,
        key_environment: Some("DNSDB_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "dnsdumpster",
        requires_key: true,
        key_environment: Some("DNSDUMPSTER_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "dnsrepo",
        requires_key: true,
        key_environment: Some("DNSREPO_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "domainsproject",
        requires_key: true,
        key_environment: Some("DOMAINSPROJECT_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "fofa",
        requires_key: true,
        key_environment: Some("FOFA_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "hudsonrock",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "onyphe",
        requires_key: true,
        key_environment: Some("ONYPHE_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "profundis",
        requires_key: true,
        key_environment: Some("PROFUNDIS_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "pugrecon",
        requires_key: true,
        key_environment: Some("PUGRECON_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "quake",
        requires_key: true,
        key_environment: Some("QUAKE_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "rapiddns",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "reconcloud",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "reconeer",
        requires_key: false,
        key_environment: Some("RECONEER_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "redhuntlabs",
        requires_key: true,
        key_environment: Some("REDHUNTLABS_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "riddler",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "robtex",
        requires_key: true,
        key_environment: Some("ROBTEX_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "rsecloud",
        requires_key: true,
        key_environment: Some("RSECLOUD_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "shodanct",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "sitedossier",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "submd",
        requires_key: false,
        key_environment: Some("SUBMD_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "thc",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "threatbook",
        requires_key: true,
        key_environment: Some("THREATBOOK_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "threatcrowd",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "threatminer",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "waybackarchive",
        requires_key: false,
        key_environment: None,
        automatic: true,
    },
    SourceDefinition {
        name: "whoisxmlapi",
        requires_key: true,
        key_environment: Some("WHOISXMLAPI_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "windvane",
        requires_key: true,
        key_environment: Some("WINDVANE_API_KEY"),
        automatic: true,
    },
    SourceDefinition {
        name: "zoomeyeapi",
        requires_key: true,
        key_environment: Some("ZOOMEYEAPI_API_KEY"),
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
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("APPDATA") {
        return PathBuf::from(path).join("fellaga/config.json");
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(path).join("AppData/Roaming/fellaga/config.json");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/fellaga/config.json")
}

fn config_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

#[cfg(unix)]
fn is_fellaga_config_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("fellaga"))
}

fn ensure_config_parent(path: &Path) -> Result<()> {
    let Some(parent) = config_parent(path) else {
        return Ok(());
    };

    #[cfg(unix)]
    {
        let existed = parent.exists();
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(parent).with_context(|| {
            format!("création du dossier de configuration {}", parent.display())
        })?;
        // Never chmod a generic pre-existing parent such as /tmp.  Fellaga's
        // dedicated directory, and any directory created for this path, are private.
        if !existed || is_fellaga_config_directory(parent) {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(|| {
                format!(
                    "sécurisation du dossier de configuration {}",
                    parent.display()
                )
            })?;
        }
    }

    #[cfg(not(unix))]
    fs::create_dir_all(parent)
        .with_context(|| format!("création du dossier de configuration {}", parent.display()))?;

    Ok(())
}

fn create_default_config(path: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(&ConfigFile::default())? + "\n";
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    match options.open(path) {
        Ok(mut file) => {
            file.write_all(content.as_bytes())
                .with_context(|| format!("écriture de la configuration {}", path.display()))?;
            file.sync_all().with_context(|| {
                format!("synchronisation de la configuration {}", path.display())
            })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("création de la configuration {}", path.display()));
        }
    }
    Ok(())
}

fn harden_config_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("sécurisation de la configuration {}", path.display()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl ApiKeyStore {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        ensure_config_parent(path)?;
        if !path.exists() {
            create_default_config(path)?;
        }
        harden_config_file(path)?;
        let content = fs::read_to_string(path)
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
        let source = source.to_ascii_lowercase();
        let aliases: &[&str] = match source.as_str() {
            "alienvault" | "otx" => &["alienvault", "otx"],
            "whoisxml" | "whoisxmlapi" => &["whoisxml", "whoisxmlapi"],
            _ => &[],
        };
        let names = if aliases.is_empty() {
            vec![source.as_str()]
        } else {
            aliases.to_vec()
        };
        let mut values = Vec::new();
        for name in names {
            if let Some(configured) = self.keys.get(name) {
                values.extend(configured.iter().cloned());
            }
            for variable in environment_names(name) {
                if let Ok(value) = std::env::var(variable) {
                    values.extend(split_keys(&value));
                }
            }
        }
        values.sort();
        values.dedup();
        values
    }

    fn redaction_values(&self) -> Vec<String> {
        let mut values = self
            .keys
            .values()
            .flatten()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        for source in SOURCE_DEFINITIONS {
            for variable in environment_names(source.name) {
                if let Ok(value) = std::env::var(variable) {
                    values.extend(split_keys(&value));
                }
            }
        }

        let components = values
            .iter()
            .flat_map(|value| value.split(':'))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        values.extend(components);
        values.retain(|value| !value.is_empty());
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
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

const REDACTED_SECRET: &str = "[REDACTED]";

fn sensitive_query_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "k" | "key"
            | "apikey"
            | "accesskey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "secret"
            | "clientsecret"
            | "password"
            | "passwd"
            | "auth"
            | "authorization"
            | "credential"
            | "credentials"
            | "signature"
            | "sig"
    )
}

fn redact_url(mut url: Url) -> String {
    if !url.username().is_empty() {
        let _ = url.set_username(REDACTED_SECRET);
    }
    if url.password().is_some() {
        let _ = url.set_password(Some(REDACTED_SECRET));
    }
    if url.query().is_some() {
        let pairs = url
            .query_pairs()
            .map(|(name, value)| {
                let value = if sensitive_query_name(&name) {
                    REDACTED_SECRET.to_owned()
                } else {
                    value.into_owned()
                };
                (name.into_owned(), value)
            })
            .collect::<Vec<_>>();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.into()
}

fn next_url_start(message: &str, offset: usize) -> Option<usize> {
    let remaining = &message[offset..];
    let http = remaining.find("http://");
    let https = remaining.find("https://");
    match (http, https) {
        (Some(left), Some(right)) => Some(offset + left.min(right)),
        (Some(index), None) | (None, Some(index)) => Some(offset + index),
        (None, None) => None,
    }
}

fn sanitize_embedded_urls(message: &str) -> String {
    let mut sanitized = String::with_capacity(message.len());
    let mut cursor = 0;
    while let Some(start) = next_url_start(message, cursor) {
        sanitized.push_str(&message[cursor..start]);
        let tail = &message[start..];
        let end = tail
            .char_indices()
            .find_map(|(index, character)| {
                (index > 0
                    && (character.is_whitespace()
                        || matches!(
                            character,
                            '"' | '\'' | '<' | '>' | '`' | ')' | ']' | '}' | ','
                        )))
                .then_some(start + index)
            })
            .unwrap_or(message.len());
        let candidate = &message[start..end];
        if let Ok(url) = Url::parse(candidate) {
            sanitized.push_str(&redact_url(url));
        } else {
            sanitized.push_str(candidate);
        }
        cursor = end;
    }
    sanitized.push_str(&message[cursor..]);
    sanitized
}

fn assignment_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn assignment_value_terminator(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(byte, b'&' | b',' | b';' | b')' | b']' | b'}' | b'"' | b'\'')
}

fn redact_sensitive_assignments(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut sanitized = String::with_capacity(message.len());
    let mut copied_until = 0;
    let mut cursor = 0;

    while cursor < bytes.len() {
        if !assignment_name_byte(bytes[cursor])
            || (cursor > 0 && assignment_name_byte(bytes[cursor - 1]))
        {
            cursor += 1;
            continue;
        }
        let name_start = cursor;
        while cursor < bytes.len() && assignment_name_byte(bytes[cursor]) {
            cursor += 1;
        }
        let name = &message[name_start..cursor];
        if !sensitive_query_name(name) {
            continue;
        }

        let mut separator = cursor;
        if separator < bytes.len() && matches!(bytes[separator], b'"' | b'\'') {
            separator += 1;
        }
        while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
            separator += 1;
        }
        if separator >= bytes.len() || !matches!(bytes[separator], b'=' | b':') {
            continue;
        }
        separator += 1;
        while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
            separator += 1;
        }

        let quote = (separator < bytes.len() && matches!(bytes[separator], b'"' | b'\''))
            .then_some(bytes[separator]);
        let value_start = separator + usize::from(quote.is_some());
        let mut value_end = value_start;
        if let Some(quote) = quote {
            while value_end < bytes.len() {
                if bytes[value_end] == quote
                    && (value_end == value_start || bytes[value_end - 1] != b'\\')
                {
                    break;
                }
                value_end += 1;
            }
        } else {
            while value_end < bytes.len() && !assignment_value_terminator(bytes[value_end]) {
                value_end += 1;
            }
        }
        if value_end == value_start {
            continue;
        }

        sanitized.push_str(&message[copied_until..value_start]);
        sanitized.push_str(REDACTED_SECRET);
        copied_until = value_end;
        cursor = value_end;
    }
    sanitized.push_str(&message[copied_until..]);
    sanitized
}

fn encoded_secret_variants(secret: &str) -> Vec<String> {
    let mut variants = vec![secret.to_owned()];
    let form_encoded = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", secret)
        .finish();
    if let Some(encoded) = form_encoded.strip_prefix("secret=") {
        variants.push(encoded.to_owned());
    }
    if let Ok(json) = serde_json::to_string(secret)
        && let Some(escaped) = json
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
    {
        variants.push(escaped.to_owned());
    }
    if secret.contains(':') {
        use base64::Engine as _;
        variants.push(base64::engine::general_purpose::STANDARD.encode(secret));
    }
    variants
}

fn replace_secret(message: &str, secret: &str) -> String {
    if secret.len() >= 4 {
        return message.replace(secret, REDACTED_SECRET);
    }

    let mut sanitized = String::with_capacity(message.len());
    let mut copied_until = 0;
    for (start, _) in message.match_indices(secret) {
        if start < copied_until {
            continue;
        }
        let end = start + secret.len();
        let before_is_boundary = start == 0
            || !message.as_bytes()[start - 1].is_ascii_alphanumeric()
                && !matches!(message.as_bytes()[start - 1], b'_' | b'-');
        let after_is_boundary = end == message.len()
            || !message.as_bytes()[end].is_ascii_alphanumeric()
                && !matches!(message.as_bytes()[end], b'_' | b'-');
        if before_is_boundary && after_is_boundary {
            sanitized.push_str(&message[copied_until..start]);
            sanitized.push_str(REDACTED_SECRET);
            copied_until = end;
        }
    }
    sanitized.push_str(&message[copied_until..]);
    sanitized
}

fn sanitize_external_message(message: &str, secrets: &[String]) -> String {
    let mut sanitized = sanitize_embedded_urls(message);
    sanitized = redact_sensitive_assignments(&sanitized);

    let mut variants = secrets
        .iter()
        .flat_map(|secret| encoded_secret_variants(secret))
        .filter(|secret| !secret.is_empty() && secret != REDACTED_SECRET)
        .collect::<Vec<_>>();
    variants.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    variants.dedup();
    for secret in variants {
        sanitized = replace_secret(&sanitized, &secret);
    }
    sanitized
}

pub(crate) fn sanitize_external_error(message: &str, keys: &ApiKeyStore) -> String {
    sanitize_external_message(message, &keys.redaction_values())
}

fn definition(source: &str) -> Option<SourceDefinition> {
    SOURCE_DEFINITIONS
        .iter()
        .copied()
        .find(|entry| entry.name == source)
}

fn environment_names(source: &str) -> &'static [&'static str] {
    match source {
        "alienvault" => &["ALIENVAULT_API_KEY", "OTX_API_KEY", "X_OTX_API_KEY"],
        "bevigil" => &["BEVIGIL_API_KEY"],
        "binaryedge" => &["BINARYEDGE_API_KEY"],
        "brave" => &["BRAVE_SEARCH_API_KEY"],
        "bufferover" => &["BUFFEROVER_API_KEY"],
        "builtwith" => &["BUILTWITH_API_KEY"],
        "c99" => &["C99_API_KEY"],
        "censys" => &["CENSYS_API_KEY"],
        "chinaz" => &["CHINAZ_API_KEY"],
        "circl" => &["CIRCL_PDNS_CREDENTIALS"],
        "certspotter" => &["CERTSPOTTER_API_TOKEN", "CERTSPOTTER_API_KEY"],
        "chaos" => &["CHAOS_API_KEY"],
        "digitalyama" => &["DIGITALYAMA_API_KEY"],
        "dnsdb" => &["DNSDB_API_KEY"],
        "dnsdumpster" => &["DNSDUMPSTER_API_KEY"],
        "dnsrepo" => &["DNSREPO_API_KEY"],
        "domainsproject" => &["DOMAINSPROJECT_API_KEY"],
        "driftnet" => &["DRIFTNET_API_KEY"],
        "fofa" => &["FOFA_API_KEY"],
        "fullhunt" => &["FULLHUNT_API_KEY"],
        "github" => &["GITHUB_TOKEN", "GITHUB_TOKENS"],
        "gitlab" => &["GITLAB_TOKEN"],
        "hackertarget" => &["HACKERTARGET_API_KEY"],
        "intelx" => &["INTELX_API_KEY"],
        "leakix" => &["LEAKIX_API_KEY"],
        "merklemap" => &["MERKLEMAP_API_TOKEN", "MERKLEMAP_API_KEY"],
        "netlas" => &["NETLAS_API_KEY"],
        "onyphe" => &["ONYPHE_API_KEY"],
        "otx" => &["OTX_API_KEY", "X_OTX_API_KEY"],
        "profundis" => &["PROFUNDIS_API_KEY"],
        "pugrecon" => &["PUGRECON_API_KEY"],
        "quake" => &["QUAKE_API_KEY"],
        "reconeer" => &["RECONEER_API_KEY"],
        "redhuntlabs" => &["REDHUNTLABS_API_KEY"],
        "robtex" => &["ROBTEX_API_KEY"],
        "rsecloud" => &["RSECLOUD_API_KEY"],
        "securitytrails" => &["SECURITYTRAILS_API_KEY"],
        "shodan" => &["SHODAN_API_KEY"],
        "submd" => &["SUBMD_API_KEY"],
        "threatbook" => &["THREATBOOK_API_KEY"],
        "urlscan" => &["URLSCAN_API_KEY"],
        "virustotal" => &["VIRUSTOTAL_API_KEY"],
        "whoisxmlapi" => &["WHOISXMLAPI_API_KEY", "WHOISXML_API_KEY"],
        "whoisxml" => &["WHOISXML_API_KEY"],
        "windvane" => &["WINDVANE_API_KEY"],
        "zoomeyeapi" => &["ZOOMEYEAPI_API_KEY", "ZOOMEYE_API_KEY"],
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
        "anubis"
            | "anubisdb"
            | "certificatedetails"
            | "digitorus"
            | "driftnet"
            | "hudsonrock"
            | "rapiddns"
            | "reconcloud"
            | "reconeer"
            | "riddler"
            | "sitedossier"
            | "subdomainapp"
            | "subdomaincenter"
            | "threatcrowd"
            | "threatminer"
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
        "commoncrawl" | "dnsdb" | "github" | "gitlab" | "netlas" | "robtex" | "submd" | "thc"
        | "urlscan" | "wayback" | "waybackarchive" => "high",
        "crtsh" | "certspotter" | "virustotal" | "shodan" | "censys" | "whoisxml"
        | "binaryedge" | "brave" | "merklemap" => "medium",
        _ => "low",
    };
    let rate_limit_per_minute = match name {
        "crtsh" => 6,
        "certspotter" => 12,
        "hackertarget" => 5,
        "commoncrawl" | "wayback" | "waybackarchive" => 10,
        "hudsonrock" | "rapiddns" | "reconcloud" | "riddler" | "sitedossier" | "threatcrowd"
        | "threatminer" => 5,
        "submd" | "thc" => 60,
        "github-content" | "gitlab-content" => 600,
        "urlscan" => 12,
        "binaryedge" | "brave" | "merklemap" => 20,
        _ if requires_key => 30,
        _ => 20,
    };
    SourceMetadata {
        name: name.to_owned(),
        evidence_family,
        // Match the recursive capabilities declared by the audited provider
        // connectors. The scanner still applies zone-yield ranking, global
        // connector budgets, and suffix filtering before querying child zones.
        // Parent lookup remains available to evidence families that can cover
        // a target which is itself a delegated sub-zone; scanner-side scope
        // filtering discards sibling names.
        recursive_children: matches!(
            name,
            "alienvault"
                | "otx"
                | "bufferover"
                | "certspotter"
                | "crtsh"
                | "digitorus"
                | "certificatedetails"
                | "dnsdb"
                | "driftnet"
                | "hackertarget"
                | "leakix"
                | "merklemap"
                | "reconcloud"
                | "securitytrails"
                | "shodanct"
                | "urlscan"
                | "virustotal"
        ),
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
        documented: !matches!(
            name,
            "certificatedetails"
                | "digitorus"
                | "hudsonrock"
                | "rapiddns"
                | "reconcloud"
                | "riddler"
                | "shodanct"
                | "sitedossier"
                | "subdomainapp"
                | "subdomaincenter"
                | "threatcrowd"
                | "threatminer"
        ),
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
            source.automatic && (!source.metadata.experimental || include_experimental)
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
type ExternalSourceLimiters = StdMutex<BTreeMap<String, Arc<TokioMutex<Option<Instant>>>>>;
static EXTERNAL_SOURCE_LIMITERS: OnceLock<ExternalSourceLimiters> = OnceLock::new();
type ExternalClients = StdMutex<BTreeMap<u64, reqwest::Client>>;
static EXTERNAL_CLIENTS: OnceLock<ExternalClients> = OnceLock::new();

const MAX_EXTERNAL_BODY_BYTES: usize = 16 * 1024 * 1024;
const COMMONCRAWL_INDEX_COUNT: usize = 5;
const COMMONCRAWL_BLOCKS_PER_REQUEST: usize = 15;
const COMMONCRAWL_MAX_PAGES: usize = 1_000;
const COMMONCRAWL_MAX_RESULT_LINES: usize = 150_000;
const COMMONCRAWL_MAX_BODY_BYTES: usize = 3 * MAX_EXTERNAL_BODY_BYTES;
const COMMONCRAWL_WARC_SAMPLE_LIMIT: usize = 2;
const COMMONCRAWL_MAX_WARC_MEMBER_BYTES: usize = 2 * 1024 * 1024;
const COMMONCRAWL_MAX_WARC_DECOMPRESSED_BYTES: usize = 4 * 1024 * 1024;
const MAX_INLINE_RETRY_AFTER: Duration = Duration::from_secs(5);

fn defer_retry_after(delay: Duration) -> bool {
    delay > MAX_INLINE_RETRY_AFTER
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePolicy {
    pub timeout: Duration,
    /// Maximum wall-clock time for the entire connector, including pagination,
    /// throttling and retries. This prevents one degraded provider from holding
    /// the whole passive phase indefinitely.
    pub total_timeout: Duration,
    pub attempts: usize,
    pub base_backoff: Duration,
}

#[derive(Debug)]
struct SourceBudgetExceeded {
    source: String,
    budget: Duration,
}

impl fmt::Display for SourceBudgetExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: budget total de {}s dépassé; pages terminées conservées dans le résultat courant",
            self.source,
            self.budget.as_secs_f64()
        )
    }
}

impl std::error::Error for SourceBudgetExceeded {}

#[derive(Debug)]
pub struct PassiveFetchResult {
    pub names: BTreeSet<String>,
    pub partial_warning: Option<String>,
    /// Names decoded by the provider before applying the working-set cap.
    /// Paginated connectors sum the distinct count of each decoded page, so a
    /// provider that repeats a name across pages may count it more than once.
    pub decoded_names: usize,
    /// The connector decoded more distinct names than it retained in its
    /// in-memory working set. A configured page sink still receives the full
    /// decoded pages before this cap is applied.
    pub working_set_truncated: bool,
}

pub type PassivePageSink = Arc<dyn Fn(&BTreeSet<String>) -> Result<()> + Send + Sync>;

#[derive(Default)]
struct PartialResultState {
    names: BTreeSet<String>,
    committed_pages: usize,
    decoded_names: usize,
    working_set_truncated: bool,
    persistence_error: Option<String>,
}

#[derive(Clone)]
struct PartialResultCheckpoint {
    state: Arc<StdMutex<PartialResultState>>,
    working_set_limit: usize,
    page_sink: Option<PassivePageSink>,
}

impl PartialResultCheckpoint {
    fn new(working_set_limit: usize, page_sink: Option<PassivePageSink>) -> Self {
        Self {
            state: Arc::new(StdMutex::new(PartialResultState::default())),
            working_set_limit,
            page_sink,
        }
    }

    fn commit_page(&self, names: &BTreeSet<String>) {
        let persistence_error = self
            .page_sink
            .as_ref()
            .and_then(|sink| sink(names).err())
            .map(|error| format!("persistance SQLite de page passive: {error:#}"));
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.committed_pages = state.committed_pages.saturating_add(1);
        state.decoded_names = state.decoded_names.saturating_add(names.len());
        state.working_set_truncated |= extend_btree_set_bounded(
            &mut state.names,
            names.iter().cloned(),
            self.working_set_limit,
        );
        if state.persistence_error.is_none() {
            state.persistence_error = persistence_error;
        }
    }

    fn persist_non_paginated_result(&self, names: &BTreeSet<String>) {
        let should_persist = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .committed_pages
            == 0;
        if !should_persist || names.is_empty() {
            return;
        }
        let persistence_error = self
            .page_sink
            .as_ref()
            .and_then(|sink| sink(names).err())
            .map(|error| format!("persistance SQLite du résultat passif: {error:#}"));
        if let Some(persistence_error) = persistence_error {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.persistence_error.is_none() {
                state.persistence_error = Some(persistence_error);
            }
        }
    }

    fn snapshot(&self) -> PartialResultState {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        PartialResultState {
            names: state.names.clone(),
            committed_pages: state.committed_pages,
            decoded_names: state.decoded_names,
            working_set_truncated: state.working_set_truncated,
            persistence_error: state.persistence_error.clone(),
        }
    }
}

fn extend_btree_set_bounded(
    target: &mut BTreeSet<String>,
    names: impl IntoIterator<Item = String>,
    limit: usize,
) -> bool {
    let mut truncated = false;
    for name in names {
        if target.contains(&name) {
            continue;
        }
        if target.len() < limit {
            target.insert(name);
        } else {
            truncated = true;
        }
    }
    truncated
}

tokio::task_local! {
    static PARTIAL_RESULT_CHECKPOINT: PartialResultCheckpoint;
}

/// Commits one fully decoded provider page both to the connector accumulator
/// and to a task-local checkpoint. If the total connector budget expires while
/// the next page is in flight, `fetch` can still return every committed page.
pub(super) fn commit_result_page(accumulated: &mut BTreeSet<String>, page: BTreeSet<String>) {
    if page.is_empty() {
        return;
    }
    if PARTIAL_RESULT_CHECKPOINT
        .try_with(|checkpoint| {
            checkpoint.commit_page(&page);
            extend_btree_set_bounded(
                accumulated,
                page.iter().cloned(),
                checkpoint.working_set_limit,
            )
        })
        .is_err()
    {
        accumulated.extend(page);
    }
}

pub fn source_policy(source: &str) -> SourcePolicy {
    match source {
        "crtsh" => SourcePolicy {
            timeout: Duration::from_secs(25),
            total_timeout: Duration::from_secs(35),
            attempts: 3,
            base_backoff: Duration::from_millis(750),
        },
        "commoncrawl" => SourcePolicy {
            timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(45),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        "wayback" | "waybackarchive" => SourcePolicy {
            timeout: Duration::from_secs(45),
            total_timeout: Duration::from_secs(45),
            attempts: 1,
            base_backoff: Duration::from_secs(1),
        },
        "submd" | "thc" => SourcePolicy {
            timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(45),
            attempts: 2,
            base_backoff: Duration::from_millis(750),
        },
        "hudsonrock" | "rapiddns" | "reconcloud" | "reconeer" | "riddler" | "shodanct"
        | "sitedossier" | "threatcrowd" | "threatminer" => SourcePolicy {
            timeout: Duration::from_secs(15),
            total_timeout: Duration::from_secs(30),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
        "otx" => SourcePolicy {
            timeout: Duration::from_secs(20),
            total_timeout: Duration::from_secs(25),
            attempts: 2,
            base_backoff: Duration::from_secs(1),
        },
        "binaryedge" | "brave" | "merklemap" => SourcePolicy {
            timeout: Duration::from_secs(10),
            total_timeout: Duration::from_secs(20),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
        "certspotter" | "urlscan" | "virustotal" | "shodan" | "censys" | "github" | "gitlab" => {
            SourcePolicy {
                timeout: Duration::from_secs(30),
                total_timeout: Duration::from_secs(45),
                attempts: 2,
                base_backoff: Duration::from_secs(1),
            }
        }
        _ => SourcePolicy {
            timeout: Duration::from_secs(20),
            total_timeout: Duration::from_secs(30),
            attempts: 2,
            base_backoff: Duration::from_millis(500),
        },
    }
}

fn commoncrawl_endpoint_cache() -> &'static RwLock<Option<String>> {
    COMMONCRAWL_API.get_or_init(|| RwLock::new(None))
}

fn validate_commoncrawl_endpoint(endpoint: &str) -> Result<Url> {
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
struct CertSpotterIssuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
}

fn certspotter_next_after(
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
struct CommonCrawlCollection {
    #[serde(default)]
    id: String,
    #[serde(rename = "cdx-api")]
    cdx_api: String,
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

fn select_commoncrawl_endpoints(collections: Vec<CommonCrawlCollection>) -> Vec<String> {
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
struct CommonCrawlRecordRef {
    url: String,
    filename: String,
    offset: u64,
    length: usize,
}

#[derive(Debug, Default)]
struct CommonCrawlPage {
    names: BTreeSet<String>,
    records: BTreeSet<CommonCrawlRecordRef>,
    truncated: bool,
}

#[derive(Debug, Deserialize)]
struct UrlscanResponse {
    results: Vec<UrlscanResult>,
    #[serde(default)]
    has_more: bool,
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
struct SecurityTrailsResponse {
    #[serde(default)]
    meta: SecurityTrailsMeta,
    #[serde(default)]
    records: Vec<SecurityTrailsRecord>,
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
struct NetlasItem {
    data: NetlasDomain,
}

#[derive(Debug, Deserialize)]
struct NetlasDomain {
    domain: String,
}

#[derive(Debug, Deserialize)]
struct NetlasCountResponse {
    count: usize,
}

#[derive(Debug, Serialize)]
struct NetlasDownloadRequest<'a> {
    q: &'a str,
    fields: [&'static str; 1],
    source_type: &'static str,
    size: usize,
}

const NETLAS_COMMUNITY_DOWNLOAD_CAP: usize = 200;
const NETLAS_DOWNLOAD_MAX_BYTES: usize = 16 * 1024 * 1024;
const NETLAS_DOWNLOAD_MAX_ITEM_BYTES: usize = 1024 * 1024;
const NETLAS_CHECKPOINT_RECORDS: usize = 50;
const SECURITYTRAILS_MAX_SCROLL_PAGES: usize = 1000;

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
struct NetlasArrayDecoder {
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
    fn new(max_items: usize, max_item_bytes: usize) -> Self {
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

    fn push<F>(&mut self, bytes: &[u8], visit: &mut F) -> Result<()>
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

    fn finish(&self) -> Result<()> {
        if self.state != NetlasArrayState::Done {
            bail!("Netlas: truncated JSON download array");
        }
        Ok(())
    }
}

fn valid_user_agent_override(value: &str) -> bool {
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

fn build_client(timeout: Duration) -> Result<reqwest::Client> {
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
            if attempt.previous().len() >= 5 {
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

fn client(timeout: Duration) -> Result<reqwest::Client> {
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

fn same_http_origin(previous: &Url, next: &Url) -> bool {
    previous.scheme() == next.scheme()
        && previous.host_str() == next.host_str()
        && previous.port_or_known_default() == next.port_or_known_default()
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

fn unix_reset_delay(value: &str) -> Option<Duration> {
    let reset_at = value.trim().parse::<u64>().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(reset_at.saturating_sub(now)))
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

fn retry_safe_method(method: &reqwest::Method) -> bool {
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

fn host_minimum_gap(host: &str) -> Duration {
    match host {
        "api.github.com" => Duration::from_secs(6),
        "index.commoncrawl.org" => Duration::from_secs(2),
        "crt.sh" | "web.archive.org" => Duration::from_secs(1),
        "urlscan.io" | "api.urlscan.io" => Duration::from_millis(500),
        "api.certspotter.com" => Duration::from_millis(250),
        "api.binaryedge.io" | "api.search.brave.com" | "api.merklemap.com" => {
            Duration::from_secs(3)
        }
        _ => Duration::from_millis(100),
    }
}

fn request_host(request: &reqwest::RequestBuilder) -> Option<(String, String)> {
    let request = request.try_clone()?.build().ok()?;
    let url = request.url();
    let host = url.host_str()?.to_ascii_lowercase();
    let port = url.port_or_known_default()?;
    Some((format!("{host}|{port}"), host))
}

async fn throttle_external_host(request: &reqwest::RequestBuilder) {
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

async fn throttle_external_source(source: &str) {
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
    let requests_per_minute = source_metadata(source).rate_limit_per_minute.max(1);
    let minimum_gap = Duration::from_millis(60_000_u64.div_ceil(u64::from(requests_per_minute)));
    let mut last_request = limiter.lock().await;
    if let Some(last) = *last_request
        && last.elapsed() < minimum_gap
    {
        tokio::time::sleep(minimum_gap.saturating_sub(last.elapsed())).await;
    }
    *last_request = Some(Instant::now());
}

fn retry_delay_from_headers(headers: &HeaderMap) -> Option<Duration> {
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

fn exhausted_rate_limit(response: &reqwest::Response) -> bool {
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

pub(super) fn compact_external_error(body: &str) -> String {
    const MAX_CHARACTERS: usize = 500;

    let mut compact = String::with_capacity(body.len().min(MAX_CHARACTERS));
    let mut characters = 0_usize;
    let mut pending_space = false;
    let mut truncated = false;

    for character in body.chars() {
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
struct ResponseBufferError {
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
struct BufferedExternalBody;

async fn buffer_external_response(
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

fn provider_error_message(value: &serde_json::Value) -> Option<String> {
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

async fn response_text_limited(
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
    send_with_retry_scoped(Some(source), request, attempts, base_backoff, seed, true).await
}

#[cfg(test)]
pub(super) async fn send_with_retry(
    request: reqwest::RequestBuilder,
    attempts: usize,
    base_backoff: Duration,
    seed: &str,
) -> Result<reqwest::Response> {
    send_with_retry_scoped(None, request, attempts, base_backoff, seed, true).await
}

async fn send_with_retry_scoped(
    source: Option<&str>,
    request: reqwest::RequestBuilder,
    attempts: usize,
    base_backoff: Duration,
    seed: &str,
    buffer_response_body: bool,
) -> Result<reqwest::Response> {
    let method = request
        .try_clone()
        .context("requête HTTP non clonable")?
        .build()
        .context("construction de la requête HTTP")?
        .method()
        .clone();
    let retry_safe = retry_safe_method(&method);
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

async fn enforce_source_budget<T, F>(source: &str, budget: Duration, request: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    tokio::time::timeout(budget, request).await.map_err(|_| {
        anyhow::Error::new(SourceBudgetExceeded {
            source: source.to_owned(),
            budget,
        })
    })?
}

#[cfg(test)]
async fn enforce_source_budget_preserving_partial<F>(
    source: &str,
    budget: Duration,
    request: F,
) -> Result<PassiveFetchResult>
where
    F: std::future::Future<Output = Result<BTreeSet<String>>>,
{
    enforce_source_budget_preserving_partial_with_sink(source, budget, request, usize::MAX, None)
        .await
}

async fn enforce_source_budget_preserving_partial_with_sink<F>(
    source: &str,
    budget: Duration,
    request: F,
    working_set_limit: usize,
    page_sink: Option<PassivePageSink>,
) -> Result<PassiveFetchResult>
where
    F: std::future::Future<Output = Result<BTreeSet<String>>>,
{
    let checkpoint = PartialResultCheckpoint::new(working_set_limit, page_sink);
    let result = PARTIAL_RESULT_CHECKPOINT
        .scope(
            checkpoint.clone(),
            enforce_source_budget(source, budget, request),
        )
        .await;
    match result {
        Err(error) => {
            let partial = checkpoint.snapshot();
            if error.downcast_ref::<SourceBudgetExceeded>().is_some() || !partial.names.is_empty() {
                let mut warning = format!("{error:#}");
                if let Some(persistence_error) = partial.persistence_error {
                    warning.push_str(&format!("; {persistence_error}"));
                }
                Ok(PassiveFetchResult {
                    names: partial.names,
                    partial_warning: Some(warning),
                    decoded_names: partial.decoded_names,
                    working_set_truncated: partial.working_set_truncated,
                })
            } else {
                Err(error)
            }
        }
        Ok(mut names) => {
            checkpoint.persist_non_paginated_result(&names);
            let snapshot = checkpoint.snapshot();
            let decoded_names = if snapshot.committed_pages == 0 {
                names.len()
            } else {
                snapshot.decoded_names
            };
            let result_truncated = if names.len() > working_set_limit {
                let retained = names.into_iter().take(working_set_limit).collect();
                names = retained;
                true
            } else {
                false
            };
            Ok(PassiveFetchResult {
                names,
                partial_warning: snapshot.persistence_error,
                decoded_names,
                working_set_truncated: snapshot.working_set_truncated || result_truncated,
            })
        }
    }
}

async fn fetch_detailed_with_total_budget(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: Option<PassivePageSink>,
) -> Result<PassiveFetchResult> {
    let request = async {
        match source {
            "crtsh" => crtsh(domain, timeout).await,
            "certspotter" => certspotter(domain, timeout, keys).await,
            "hackertarget" => hackertarget(domain, timeout, keys).await,
            "commoncrawl" => commoncrawl(domain, timeout).await,
            "wayback" | "waybackarchive" => wayback(domain, timeout).await,
            "urlscan" => urlscan(domain, timeout, keys).await,
            "anubis" => public_sources::anubis(domain, timeout).await,
            "anubisdb" => anubisdb(domain, timeout).await,
            "subdomainapp" => subdomainapp(domain, timeout).await,
            "virustotal" => virustotal(domain, timeout, keys).await,
            "whoisxml" | "whoisxmlapi" => whoisxml(domain, timeout, keys).await,
            "securitytrails" => securitytrails(domain, timeout, keys).await,
            "bevigil" => extra::bevigil(domain, timeout, keys).await,
            "binaryedge" => extra::binaryedge(domain, timeout, keys).await,
            "brave" => extra::brave(domain, timeout, keys).await,
            "builtwith" => extra::builtwith(domain, timeout, keys).await,
            "censys" => extra::censys(domain, timeout, keys).await,
            "circl" => extra::circl(domain, timeout, keys).await,
            "certificatedetails" | "digitorus" => extra::certificate_details(domain, timeout).await,
            "chaos" => extra::chaos(domain, timeout, keys).await,
            "driftnet" => {
                let token = keys.pick("driftnet")?;
                extra::driftnet(domain, timeout, &token).await
            }
            "fullhunt" => extra::fullhunt(domain, timeout, keys).await,
            "github" => extra::github(domain, timeout, keys).await,
            "gitlab" => extra::gitlab(domain, timeout, keys).await,
            "intelx" => extra::intelx(domain, timeout, keys).await,
            "leakix" => extra::leakix(domain, timeout, keys).await,
            "merklemap" => extra::merklemap(domain, timeout, keys).await,
            "netlas" => netlas(domain, timeout, keys).await,
            "alienvault" | "otx" => extra::otx(domain, timeout, keys).await,
            "shodan" => extra::shodan(domain, timeout, keys).await,
            "subdomaincenter" => extra::subdomain_center(domain, timeout).await,
            "bufferover" => keyed_sources::bufferover(domain, timeout, keys).await,
            "c99" => keyed_sources::c99(domain, timeout, keys).await,
            "chinaz" => keyed_sources::chinaz(domain, timeout, keys).await,
            "digitalyama" => keyed_sources::digitalyama(domain, timeout, keys).await,
            "dnsdb" => keyed_sources::dnsdb(domain, timeout, keys).await,
            "dnsdumpster" => keyed_sources::dnsdumpster(domain, timeout, keys).await,
            "dnsrepo" => keyed_sources::dnsrepo(domain, timeout, keys).await,
            "domainsproject" => keyed_sources::domainsproject(domain, timeout, keys).await,
            "fofa" => keyed_sources::fofa(domain, timeout, keys).await,
            "hudsonrock" => public_sources::hudsonrock(domain, timeout).await,
            "onyphe" => keyed_sources::onyphe(domain, timeout, keys).await,
            "profundis" => keyed_sources::profundis(domain, timeout, keys).await,
            "pugrecon" => keyed_sources::pugrecon(domain, timeout, keys).await,
            "quake" => keyed_sources::quake(domain, timeout, keys).await,
            "rapiddns" => public_sources::rapiddns(domain, timeout).await,
            "reconcloud" => public_sources::reconcloud(domain, timeout).await,
            "reconeer" => public_sources::reconeer(domain, timeout, keys).await,
            "redhuntlabs" => keyed_sources::redhuntlabs(domain, timeout, keys).await,
            "riddler" => public_sources::riddler(domain, timeout).await,
            "robtex" => keyed_sources::robtex(domain, timeout, keys).await,
            "rsecloud" => keyed_sources::rsecloud(domain, timeout, keys).await,
            "shodanct" => public_sources::shodanct(domain, timeout).await,
            "sitedossier" => public_sources::sitedossier(domain, timeout).await,
            "submd" => public_sources::submd(domain, timeout, keys).await,
            "thc" => public_sources::thc(domain, timeout).await,
            "threatbook" => keyed_sources::threatbook(domain, timeout, keys).await,
            "threatcrowd" => public_sources::threatcrowd(domain, timeout).await,
            "threatminer" => public_sources::threatminer(domain, timeout).await,
            "windvane" => keyed_sources::windvane(domain, timeout, keys).await,
            "zoomeyeapi" => keyed_sources::zoomeyeapi(domain, timeout, keys).await,
            _ => Err(anyhow::anyhow!("source passive inconnue: {source}")),
        }
    };
    let result = enforce_source_budget_preserving_partial_with_sink(
        source,
        total_budget,
        request,
        working_set_limit,
        page_sink,
    )
    .await;
    match result {
        Ok(mut fetch) => {
            if let Some(warning) = fetch.partial_warning.as_mut() {
                *warning = sanitize_external_error(warning, keys);
            }
            Ok(fetch)
        }
        Err(error) => Err(anyhow::Error::msg(sanitize_external_error(
            &format!("{error:#}"),
            keys,
        ))),
    }
}

pub async fn fetch_detailed(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        source_policy(source).total_timeout,
        usize::MAX,
        None,
    )
    .await
}

/// Runs the complete connector under a caller-supplied wall deadline while
/// retaining pages committed before the deadline. Source-specific safety
/// limits remain an upper bound when the caller supplies a larger value.
pub async fn fetch_detailed_bounded(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        total_budget.min(source_policy(source).total_timeout),
        usize::MAX,
        None,
    )
    .await
}

/// Runs a connector check with a caller-defined retained-name ceiling.  The
/// decoder may process more records, reported through `decoded_names`, while
/// preventing diagnostics from building a multi-million-name in-memory set.
pub async fn fetch_detailed_bounded_with_limit(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        total_budget.min(source_policy(source).total_timeout),
        working_set_limit.max(1),
        None,
    )
    .await
}

/// Runs a connector with a bounded in-memory working set. Fully decoded pages
/// are delivered to `page_sink` before the cap is applied so callers can keep
/// permanent observations without retaining the entire provider response.
pub async fn fetch_detailed_bounded_with_sink(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
    total_budget: Duration,
    working_set_limit: usize,
    page_sink: PassivePageSink,
) -> Result<PassiveFetchResult> {
    fetch_detailed_with_total_budget(
        source,
        domain,
        timeout,
        keys,
        total_budget.min(source_policy(source).total_timeout),
        working_set_limit,
        Some(page_sink),
    )
    .await
}

pub async fn fetch(
    source: &str,
    domain: &str,
    timeout: Duration,
    keys: &ApiKeyStore,
) -> Result<BTreeSet<String>> {
    Ok(fetch_detailed(source, domain, timeout, keys).await?.names)
}

async fn crtsh_postgres(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let mut config = tokio_postgres::Config::new();
    config
        .host("crt.sh")
        .user("guest")
        .dbname("certwatch")
        .connect_timeout(timeout.min(Duration::from_secs(10)));
    let statement_timeout_ms = timeout.as_millis().clamp(1, 30_000);
    config.options(format!("-c statement_timeout={statement_timeout_ms}"));
    let (database, connection) = config
        .connect(tokio_postgres::NoTls)
        .await
        .context("connexion PostgreSQL publique crt.sh")?;
    let connection_task = tokio::spawn(connection);
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
    connection_task.abort();
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

async fn crtsh(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
    let postgres_error = match crtsh_postgres(domain, timeout).await {
        Ok(names) if !names.is_empty() => return Ok(names),
        Ok(_) => "PostgreSQL returned no in-scope names".to_owned(),
        Err(error) => compact_external_error(&format!("{error:#}")),
    };
    crtsh_http(domain, timeout)
        .await
        .with_context(|| format!("fallback HTTP crt.sh après échec PostgreSQL: {postgres_error}"))
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

async fn hackertarget(
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

fn hostname_from_url(value: &str, domain: &str) -> Option<String> {
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

fn commoncrawl_content_range_matches(value: &str, expected_start: u64, expected_end: u64) -> bool {
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

fn parse_commoncrawl_page(body: &str, domain: &str) -> Result<CommonCrawlPage> {
    parse_commoncrawl_page_bounded(body, domain, COMMONCRAWL_MAX_RESULT_LINES)
}

fn parse_commoncrawl_page_bounded(
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
fn parse_commoncrawl_rows(body: &str, domain: &str) -> Result<BTreeSet<String>> {
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
    let response = client
        .get(url.clone())
        .header(RANGE, format!("bytes={}-{}", record.offset, end))
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
fn parse_wayback_rows(rows: Vec<Vec<String>>, domain: &str) -> BTreeSet<String> {
    parse_wayback_page(rows, domain).names
}

#[derive(Debug, Default)]
struct WaybackPage {
    names: BTreeSet<String>,
    resume_key: Option<String>,
}

fn parse_wayback_page(rows: Vec<Vec<String>>, domain: &str) -> WaybackPage {
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

async fn wayback(domain: &str, timeout: Duration) -> Result<BTreeSet<String>> {
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

async fn urlscan(domain: &str, timeout: Duration, keys: &ApiKeyStore) -> Result<BTreeSet<String>> {
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

fn trusted_pagination_url(url: &str, expected_host: &str, expected_path: &str) -> bool {
    Url::parse(url).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str() == Some(expected_host)
            && url.port_or_known_default() == Some(443)
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

async fn netlas(domain: &str, timeout: Duration, keys: &ApiKeyStore) -> Result<BTreeSet<String>> {
    let http = client(timeout)?;
    let key = keys.pick("netlas")?;
    let query = format!("domain:*.{domain} AND NOT domain:{domain}");

    let count_response = send_external(
        "netlas",
        http.get("https://app.netlas.io/api/domains_count/")
            .query(&[("q", query.as_str())])
            .header("X-API-Key", &key),
        domain,
    )
    .await
    .context("connexion au compteur de domaines Netlas")?;
    let count = response_json::<NetlasCountResponse>(count_response, "Netlas count")
        .await?
        .count;
    let requested = count.min(NETLAS_COMMUNITY_DOWNLOAD_CAP);
    if requested == 0 {
        return Ok(BTreeSet::new());
    }

    let request = NetlasDownloadRequest {
        q: &query,
        fields: ["*"],
        source_type: "include",
        size: requested,
    };
    let mut response = send_external_streaming(
        "netlas",
        http.post("https://app.netlas.io/api/domains/download/")
            .header("X-API-Key", &key)
            .json(&request),
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
        decoder.finish()?;
    }
    commit_result_page(&mut names, page_names);
    Ok(names)
}

fn securitytrails_page_names(page: &SecurityTrailsResponse, domain: &str) -> BTreeSet<String> {
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

fn securitytrails_scroll_url(scroll_id: &str) -> Result<Url> {
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

fn securitytrails_use_legacy_fallback(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::FORBIDDEN
}

fn securitytrails_next_scroll(
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

async fn securitytrails(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn key_store(entries: &[(&str, &[&str])]) -> ApiKeyStore {
        ApiKeyStore {
            keys: entries
                .iter()
                .map(|(source, values)| {
                    (
                        (*source).to_owned(),
                        values.iter().map(|value| (*value).to_owned()).collect(),
                    )
                })
                .collect(),
            cursor: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[test]
    fn key_bearing_debug_output_is_fully_redacted() {
        let store = key_store(&[("shodan", &["runtime-super-secret"])]);
        let config = ConfigFile {
            api_keys: BTreeMap::from([(
                "shodan".to_owned(),
                KeyList::One("runtime-super-secret".to_owned()),
            )]),
        };
        let list = KeyList::Many(vec!["runtime-super-secret".to_owned()]);

        for debug in [
            format!("{store:?}"),
            format!("{config:?}"),
            format!("{list:?}"),
        ] {
            assert!(debug.contains("REDACTED"));
            assert!(!debug.contains("runtime-super-secret"));
            assert!(!debug.contains("shodan"));
        }
    }

    #[test]
    fn canonical_names_share_legacy_provider_credentials() {
        let legacy = key_store(&[("otx", &["otx-secret"]), ("whoisxml", &["whoisxml-secret"])]);
        assert_eq!(legacy.values("alienvault"), vec!["otx-secret".to_owned()]);
        assert_eq!(
            legacy.values("whoisxmlapi"),
            vec!["whoisxml-secret".to_owned()]
        );

        let canonical = key_store(&[
            ("alienvault", &["alienvault-secret"]),
            ("whoisxmlapi", &["whoisxmlapi-secret"]),
        ]);
        assert_eq!(
            canonical.values("otx"),
            vec!["alienvault-secret".to_owned()]
        );
        assert_eq!(
            canonical.values("whoisxml"),
            vec!["whoisxmlapi-secret".to_owned()]
        );
    }

    #[test]
    fn external_error_sanitizer_removes_urls_assignments_and_known_key_values() {
        let store = key_store(&[
            ("shodan", &["shodan-super-secret"]),
            ("censys", &["client-identifier:client-super-secret"]),
            ("intelx", &["abc"]),
        ]);
        use base64::Engine as _;
        let basic = base64::engine::general_purpose::STANDARD
            .encode("client-identifier:client-super-secret");
        let message = format!(
            "request https://api-user:url-password@example.test/path?key=unknown-query-secret&cursor=public failed: apiKey='unknown-json-secret'; body shodan-super-secret client-identifier client-super-secret short abc Basic {basic}"
        );

        let sanitized = sanitize_external_error(&message, &store);
        for secret in [
            "api-user",
            "url-password",
            "unknown-query-secret",
            "unknown-json-secret",
            "shodan-super-secret",
            "client-identifier",
            "client-super-secret",
            "abc",
            basic.as_str(),
        ] {
            assert!(
                !sanitized.contains(secret),
                "secret encore visible: {secret}"
            );
        }
        assert!(sanitized.contains("REDACTED"));
        assert!(sanitized.contains("cursor=public"));
    }

    #[test]
    fn config_creation_preserves_existing_values() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fellaga/config.json");
        let empty = ApiKeyStore::load_or_create(&path).unwrap();
        assert!(!empty.has("shodan"));
        let configured = r#"{"api_keys":{"shodan":"fixture-secret-value"}}"#;
        fs::write(&path, configured).unwrap();

        let loaded = ApiKeyStore::load_or_create(&path).unwrap();
        assert!(loaded.has("shodan"));
        assert_eq!(fs::read_to_string(path).unwrap(), configured);
    }

    #[cfg(unix)]
    #[test]
    fn config_directory_and_file_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let config_directory = directory.path().join("fellaga");
        fs::create_dir(&config_directory).unwrap();
        fs::set_permissions(&config_directory, fs::Permissions::from_mode(0o777)).unwrap();
        let path = config_directory.join("config.json");

        ApiKeyStore::load_or_create(&path).unwrap();
        assert_eq!(
            fs::metadata(&config_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        ApiKeyStore::load_or_create(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

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
    fn netlas_download_stream_handles_chunk_boundaries_and_scope() {
        let fixture = include_bytes!("../tests/fixtures/netlas-page.json");
        let mut decoder = NetlasArrayDecoder::new(2, 1024);
        let mut names = BTreeSet::new();
        {
            let mut visit = |item: NetlasItem| -> Result<()> {
                if let Some(name) = normalize_observed_name(&item.data.domain, "example.com") {
                    names.insert(name);
                }
                Ok(())
            };
            for byte in fixture.chunks(1) {
                decoder.push(byte, &mut visit).unwrap();
            }
        }
        decoder.finish().unwrap();
        assert_eq!(names, BTreeSet::from(["edge.example.com".to_owned()]));
    }

    #[test]
    fn netlas_download_stream_rejects_truncation_trailing_data_and_excess_records() {
        let mut noop = |_item: NetlasItem| Ok(());

        let mut truncated = NetlasArrayDecoder::new(1, 1024);
        truncated
            .push(br#"[{"data":{"domain":"a.example.com"}}"#, &mut noop)
            .unwrap();
        assert!(truncated.finish().is_err());

        let mut trailing = NetlasArrayDecoder::new(1, 1024);
        assert!(trailing.push(b"[] false", &mut noop).is_err());

        let mut excessive = NetlasArrayDecoder::new(1, 1024);
        assert!(
            excessive
                .push(
                    br#"[{"data":{"domain":"a.example.com"}},{"data":{"domain":"b.example.com"}}]"#,
                    &mut noop,
                )
                .is_err()
        );

        let mut oversized = NetlasArrayDecoder::new(1, 8);
        assert!(
            oversized
                .push(br#"[{"data":{"domain":"a.example.com"}}]"#, &mut noop)
                .is_err()
        );
    }

    #[test]
    fn netlas_download_request_matches_current_api_contract_and_caps() {
        let query = "domain:*.example.com AND NOT domain:example.com";
        let request = NetlasDownloadRequest {
            q: query,
            fields: ["*"],
            source_type: "include",
            size: NETLAS_COMMUNITY_DOWNLOAD_CAP,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "q": query,
                "fields": ["*"],
                "source_type": "include",
                "size": 200
            })
        );
        assert_eq!(NETLAS_DOWNLOAD_MAX_BYTES, 16 * 1024 * 1024);
        assert_eq!(NETLAS_CHECKPOINT_RECORDS, 50);
    }

    #[test]
    fn securitytrails_contract_supports_scroll_and_legacy_shapes() {
        let list: SecurityTrailsResponse = serde_json::from_str(
            r#"{
                "meta":{"scroll_id":"opaque-next"},
                "records":[
                    {"hostname":"api.example.com"},
                    {"hostname":"outside.example.net"}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            securitytrails_page_names(&list, "example.com"),
            BTreeSet::from(["api.example.com".to_owned()])
        );

        let legacy: SecurityTrailsResponse =
            serde_json::from_str(r#"{"subdomains":["www","deep.api","mail."]}"#).unwrap();
        assert_eq!(
            securitytrails_page_names(&legacy, "example.com"),
            BTreeSet::from([
                "deep.api.example.com".to_owned(),
                "mail.example.com".to_owned(),
                "www.example.com".to_owned(),
            ])
        );
    }

    #[test]
    fn securitytrails_scroll_is_same_origin_bounded_and_non_repeating() {
        let url = securitytrails_scroll_url("//evil.test/a?key=value#fragment").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("api.securitytrails.com"));
        assert!(url.query().is_none());
        assert!(url.fragment().is_none());

        assert!(securitytrails_scroll_url("line\nbreak").is_err());
        assert!(securitytrails_scroll_url(&"x".repeat(4097)).is_err());

        let mut seen = BTreeSet::new();
        assert_eq!(
            securitytrails_next_scroll("cursor".to_owned(), &mut seen).unwrap(),
            Some("cursor".to_owned())
        );
        assert!(securitytrails_next_scroll("cursor".to_owned(), &mut seen).is_err());
        assert_eq!(
            securitytrails_next_scroll(String::new(), &mut seen).unwrap(),
            None
        );
        assert_eq!(SECURITYTRAILS_MAX_SCROLL_PAGES, 1000);
    }

    #[test]
    fn securitytrails_falls_back_only_for_exact_forbidden_status() {
        assert!(securitytrails_use_legacy_fallback(
            reqwest::StatusCode::FORBIDDEN
        ));
        for status in [
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert!(!securitytrails_use_legacy_fallback(status));
        }
    }

    #[test]
    fn deep_profile_enables_every_accessible_unique_connector_but_not_duplicate_aliases() {
        let keys = ApiKeyStore::default();
        let balanced = automatic_sources_for_profile(&keys, false);
        let deep = automatic_sources_for_profile(&keys, true);
        assert!(!balanced.contains(&"anubisdb".to_owned()));
        assert!(!balanced.contains(&"anubis".to_owned()));
        assert!(!balanced.contains(&"subdomainapp".to_owned()));
        assert!(!balanced.contains(&"driftnet".to_owned()));
        assert!(deep.contains(&"anubisdb".to_owned()));
        assert!(deep.contains(&"anubis".to_owned()));
        assert!(deep.contains(&"subdomainapp".to_owned()));
        assert!(deep.contains(&"subdomaincenter".to_owned()));
        assert!(deep.contains(&"hudsonrock".to_owned()));
        assert!(deep.contains(&"threatminer".to_owned()));
        assert!(deep.contains(&"digitorus".to_owned()));
        assert!(deep.contains(&"waybackarchive".to_owned()));
        assert!(!deep.contains(&"driftnet".to_owned()));
        assert!(!deep.contains(&"otx".to_owned()));
        assert!(!deep.contains(&"wayback".to_owned()));
        assert!(!deep.contains(&"whoisxml".to_owned()));
        assert!(!deep.contains(&"certificatedetails".to_owned()));
        assert!(!deep.contains(&"bevigil".to_owned()));
    }

    #[test]
    fn deep_profile_enables_driftnet_only_with_a_real_key() {
        let keys = key_store(&[("driftnet", &["driftnet-key"]), ("otx", &["otx-key"])]);
        let deep = automatic_sources_for_profile(&keys, true);
        assert!(deep.contains(&"driftnet".to_owned()));
        assert!(!deep.contains(&"otx".to_owned()));
        assert!(deep.contains(&"alienvault".to_owned()));
        assert!(source_metadata("driftnet").documented);
        assert_eq!(source_metadata("alienvault").authentication, "required");
    }

    #[test]
    fn registry_contains_every_audited_provider_without_duplicates() {
        let expected = BTreeSet::from([
            "alienvault",
            "anubis",
            "bevigil",
            "bufferover",
            "builtwith",
            "c99",
            "censys",
            "certspotter",
            "chaos",
            "chinaz",
            "commoncrawl",
            "crtsh",
            "digitalyama",
            "digitorus",
            "dnsdb",
            "dnsdumpster",
            "dnsrepo",
            "domainsproject",
            "driftnet",
            "fofa",
            "fullhunt",
            "github",
            "gitlab",
            "hackertarget",
            "hudsonrock",
            "intelx",
            "leakix",
            "merklemap",
            "netlas",
            "onyphe",
            "profundis",
            "pugrecon",
            "quake",
            "rapiddns",
            "reconcloud",
            "reconeer",
            "redhuntlabs",
            "riddler",
            "robtex",
            "rsecloud",
            "securitytrails",
            "shodan",
            "shodanct",
            "sitedossier",
            "submd",
            "thc",
            "threatbook",
            "threatcrowd",
            "threatminer",
            "urlscan",
            "virustotal",
            "waybackarchive",
            "whoisxmlapi",
            "windvane",
            "zoomeyeapi",
        ]);
        let registered = SOURCE_DEFINITIONS
            .iter()
            .map(|source| source.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(registered.len(), SOURCE_DEFINITIONS.len());
        let missing = expected
            .difference(&registered)
            .copied()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "audited providers missing from the registry: {missing:?}"
        );
        assert_eq!(expected.len(), 55);
    }

    #[test]
    fn targeted_connectors_are_key_gated_and_strictly_bounded() {
        let keys = key_store(&[
            ("binaryedge", &["binaryedge-key"]),
            ("brave", &["brave-key"]),
            ("merklemap", &["merklemap-token"]),
        ]);
        let automatic = automatic_sources(&keys);
        for (source, environment, family, recursive_parent) in [
            (
                "binaryedge",
                "BINARYEDGE_API_KEY",
                EvidenceFamily::PassiveDns,
                true,
            ),
            (
                "brave",
                "BRAVE_SEARCH_API_KEY",
                EvidenceFamily::WebCrawl,
                false,
            ),
            (
                "merklemap",
                "MERKLEMAP_API_TOKEN",
                EvidenceFamily::CertificateTransparency,
                true,
            ),
        ] {
            assert!(automatic.contains(&source.to_owned()));
            let status = source_statuses(&keys)
                .into_iter()
                .find(|status| status.name == source)
                .unwrap();
            assert_eq!(status.key_environment.as_deref(), Some(environment));
            assert!(status.configured);
            assert!(status.automatic);
            assert_eq!(status.metadata.evidence_family, family);
            assert_eq!(status.metadata.cost, "medium");
            assert_eq!(status.metadata.authentication, "required");
            assert!(!status.metadata.experimental);
            assert_eq!(status.metadata.recursive_children, source == "merklemap");
            assert_eq!(status.metadata.recursive_parents, recursive_parent);
            assert_eq!(source_policy(source).timeout, Duration::from_secs(10));
            assert_eq!(source_policy(source).total_timeout, Duration::from_secs(20));
        }
    }

    #[test]
    fn recursive_connector_metadata_matches_the_pinned_provider_capabilities() {
        for source in [
            "crtsh",
            "certspotter",
            "merklemap",
            "alienvault",
            "bufferover",
            "digitorus",
            "dnsdb",
            "driftnet",
            "hackertarget",
            "leakix",
            "reconcloud",
            "securitytrails",
            "shodanct",
            "urlscan",
            "virustotal",
        ] {
            assert!(source_metadata(source).recursive_children, "{source}");
        }
        for source in ["commoncrawl", "waybackarchive", "brave", "submd", "thc"] {
            assert!(!source_metadata(source).recursive_children, "{source}");
        }
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
    fn commoncrawl_uses_bounded_multi_page_index_windows() {
        assert_eq!(COMMONCRAWL_BLOCKS_PER_REQUEST, 15);
        assert_eq!(COMMONCRAWL_MAX_PAGES, 1_000);
        assert_eq!(COMMONCRAWL_MAX_RESULT_LINES, 3 * 50_000);
        assert_eq!(COMMONCRAWL_MAX_BODY_BYTES, 3 * MAX_EXTERNAL_BODY_BYTES);
        assert_eq!(COMMONCRAWL_INDEX_COUNT, 5);
    }

    #[test]
    fn commoncrawl_selects_one_collection_per_year_before_recent_fallbacks() {
        let collections = [
            ("CC-MAIN-2026-30", "2026-a"),
            ("CC-MAIN-2026-26", "2026-b"),
            ("CC-MAIN-2025-51", "2025"),
            ("CC-MAIN-2024-51", "2024"),
            ("CC-MAIN-2023-50", "2023"),
            ("CC-MAIN-2022-49", "2022"),
        ]
        .into_iter()
        .map(|(id, suffix)| CommonCrawlCollection {
            id: id.to_owned(),
            cdx_api: format!("https://index.commoncrawl.org/{suffix}-index"),
        })
        .collect();
        let endpoints = select_commoncrawl_endpoints(collections);
        assert_eq!(endpoints.len(), 5);
        assert!(endpoints[0].contains("2026-a"));
        assert!(endpoints[1].contains("2025"));
        assert!(endpoints[4].contains("2022"));
        assert!(!endpoints.iter().any(|endpoint| endpoint.contains("2026-b")));
    }

    #[test]
    fn long_retry_after_is_deferred_instead_of_blocking_the_scan() {
        assert!(!defer_retry_after(Duration::ZERO));
        assert!(!defer_retry_after(MAX_INLINE_RETRY_AFTER));
        assert!(defer_retry_after(Duration::from_secs(6)));
        assert!(defer_retry_after(Duration::from_secs(30)));
    }

    #[test]
    fn user_agent_override_accepts_only_safe_http_header_values() {
        assert!(valid_user_agent_override(
            "Fellaga/0.8 security@example.org"
        ));
        assert!(!valid_user_agent_override("Fellaga\nInjected: true"));
        assert!(!valid_user_agent_override("Fellaga/🚀"));
    }

    #[test]
    fn unstable_sources_have_bounded_individual_policies() {
        assert_eq!(source_policy("wayback").timeout, Duration::from_secs(45));
        assert_eq!(
            source_policy("wayback").total_timeout,
            Duration::from_secs(45)
        );
        assert!(source_policy("commoncrawl").total_timeout <= Duration::from_secs(45));
        assert!(source_policy("subdomaincenter").total_timeout <= Duration::from_secs(30));
        assert_eq!(source_policy("crtsh").attempts, 3);
        assert_eq!(source_policy("commoncrawl").attempts, 2);
        assert_eq!(
            host_minimum_gap("api.binaryedge.io"),
            Duration::from_secs(3)
        );
        assert_eq!(
            host_minimum_gap("api.search.brave.com"),
            Duration::from_secs(3)
        );
        assert_eq!(
            host_minimum_gap("api.merklemap.com"),
            Duration::from_secs(3)
        );
        assert!(retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
        assert!(retryable_status(reqwest::StatusCode::TOO_EARLY));
        assert!(retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
        assert!(retryable_status(
            reqwest::StatusCode::from_u16(524).unwrap()
        ));
        for method in [
            reqwest::Method::GET,
            reqwest::Method::HEAD,
            reqwest::Method::OPTIONS,
            reqwest::Method::TRACE,
        ] {
            assert!(retry_safe_method(&method), "{method} must be replay-safe");
        }
        for method in [
            reqwest::Method::POST,
            reqwest::Method::PUT,
            reqwest::Method::PATCH,
            reqwest::Method::DELETE,
        ] {
            assert!(!retry_safe_method(&method), "{method} must not be replayed");
        }
        assert_eq!(retry_after_delay("12"), Some(Duration::from_secs(12)));
        let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(60));
        let date_delay = retry_after_delay(&date).unwrap();
        assert!(date_delay > Duration::from_secs(55));
        assert!(date_delay <= Duration::from_secs(60));
        let mut headers = HeaderMap::new();
        headers.insert("ratelimit-reset", HeaderValue::from_static("17"));
        assert_eq!(
            retry_delay_from_headers(&headers),
            Some(Duration::from_secs(17))
        );
        let reset_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(30)
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ratelimit-reset",
            HeaderValue::from_str(&reset_at).unwrap(),
        );
        let reset_delay = retry_delay_from_headers(&headers).unwrap();
        assert!(reset_delay >= Duration::from_secs(29));
        assert!(reset_delay <= Duration::from_secs(30));
        assert!(
            backoff_delay("example.com", 1, Duration::from_millis(750))
                > backoff_delay("example.com", 0, Duration::from_millis(750))
        );
    }

    #[test]
    fn external_error_compaction_is_bounded_and_log_safe() {
        assert_eq!(compact_external_error("bad\n\t request"), "bad request");
        let input = format!("\u{1b}[31m{}\u{202e}", "x".repeat(1_000));
        let compact = compact_external_error(&input);
        assert!(compact.ends_with('…'));
        assert!(compact.chars().count() <= 501);
        assert!(!compact.contains('\u{1b}'));
        assert!(!compact.contains('\u{202e}'));
    }

    #[test]
    fn external_host_limiters_isolate_local_ports() {
        let client = build_client(Duration::from_secs(1)).unwrap();
        let first = request_host(&client.get("http://127.0.0.1:41001/")).unwrap();
        let second = request_host(&client.get("http://127.0.0.1:41002/")).unwrap();
        assert_ne!(first.0, second.0);
        assert_eq!(first.1, second.1);
        assert_eq!(
            request_host(&client.get("https://example.com/path")),
            Some(("example.com|443".to_owned(), "example.com".to_owned()))
        );
    }

    #[tokio::test]
    async fn connector_wall_clock_budget_cancels_a_slow_tail() {
        let started = Instant::now();
        let result = enforce_source_budget("slow-test", Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, anyhow::Error>(())
        })
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("slow-test"));
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn connector_budget_returns_pages_committed_before_a_slow_tail() {
        let result = enforce_source_budget_preserving_partial(
            "paginated-test",
            Duration::from_millis(10),
            async {
                let mut accumulated = BTreeSet::new();
                commit_result_page(
                    &mut accumulated,
                    BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned()]),
                );
                std::future::pending::<Result<BTreeSet<String>>>().await
            },
        )
        .await
        .unwrap();

        assert_eq!(
            result.names,
            BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned(),])
        );
        assert!(result.partial_warning.is_some());
        assert!(!result.working_set_truncated);
    }

    #[tokio::test]
    async fn capped_checkpoint_persists_the_full_page_before_retaining_a_partial_set() {
        let persisted = Arc::new(StdMutex::new(Vec::<BTreeSet<String>>::new()));
        let persisted_for_sink = persisted.clone();
        let sink: PassivePageSink = Arc::new(move |page| {
            persisted_for_sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(page.clone());
            Ok(())
        });
        let full_page = BTreeSet::from([
            "a.example.com".to_owned(),
            "b.example.com".to_owned(),
            "c.example.com".to_owned(),
        ]);

        let result = enforce_source_budget_preserving_partial_with_sink(
            "paginated-test",
            Duration::from_millis(10),
            async {
                let mut accumulated = BTreeSet::new();
                commit_result_page(&mut accumulated, full_page.clone());
                std::future::pending::<Result<BTreeSet<String>>>().await
            },
            2,
            Some(sink),
        )
        .await
        .unwrap();

        assert_eq!(
            result.names,
            BTreeSet::from(["a.example.com".to_owned(), "b.example.com".to_owned()])
        );
        assert!(result.working_set_truncated);
        assert_eq!(result.decoded_names, 3);
        assert!(result.partial_warning.is_some());
        assert_eq!(
            persisted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            &[full_page]
        );
    }

    #[tokio::test]
    async fn connector_returns_committed_pages_when_a_later_page_fails() {
        let result = enforce_source_budget_preserving_partial(
            "paginated-test",
            Duration::from_secs(1),
            async {
                let mut accumulated = BTreeSet::new();
                commit_result_page(
                    &mut accumulated,
                    BTreeSet::from(["api.example.com".to_owned()]),
                );
                Err(anyhow::anyhow!("page 2 returned invalid JSON"))
            },
        )
        .await
        .unwrap();

        assert_eq!(result.names, BTreeSet::from(["api.example.com".to_owned()]));
        assert!(
            result
                .partial_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("page 2"))
        );
    }

    #[tokio::test]
    async fn partial_page_checkpoints_are_isolated_between_concurrent_sources() {
        async fn one_slow_page(name: &'static str) -> Result<BTreeSet<String>> {
            let mut accumulated = BTreeSet::new();
            commit_result_page(&mut accumulated, BTreeSet::from([name.to_owned()]));
            std::future::pending::<Result<BTreeSet<String>>>().await
        }

        let (first, second) = tokio::join!(
            enforce_source_budget_preserving_partial(
                "first-test",
                Duration::from_millis(10),
                one_slow_page("one.example.com"),
            ),
            enforce_source_budget_preserving_partial(
                "second-test",
                Duration::from_millis(10),
                one_slow_page("two.example.com"),
            ),
        );

        assert_eq!(
            first.unwrap().names,
            BTreeSet::from(["one.example.com".to_owned()])
        );
        assert_eq!(
            second.unwrap().names,
            BTreeSet::from(["two.example.com".to_owned()])
        );
    }

    #[tokio::test]
    async fn a_budget_timeout_without_a_committed_page_is_deferred_not_failed() {
        let result = enforce_source_budget_preserving_partial(
            "empty-test",
            Duration::from_millis(10),
            std::future::pending::<Result<BTreeSet<String>>>(),
        )
        .await
        .unwrap();

        assert!(result.names.is_empty());
        assert!(
            result
                .partial_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("empty-test") && warning.contains("budget"))
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
        assert!(!trusted_pagination_url(
            "https://www.virustotal.com:8443/api/v3/domains/example.com/subdomains",
            "www.virustotal.com",
            "/api/v3/domains/"
        ));
    }

    #[tokio::test]
    async fn custom_api_headers_never_follow_a_cross_origin_redirect() {
        let redirect_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_address = redirect_listener.local_addr().unwrap();
        let target_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = redirect_listener.accept().unwrap();
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request);
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/sink\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(response.as_bytes()).unwrap();
        });

        let result = client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{redirect_address}/source"))
            .header("X-Key", "binaryedge-secret")
            .header("X-Subscription-Token", "brave-secret")
            .send()
            .await;
        assert!(result.is_err());
        server.join().unwrap();

        target_listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            target_listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
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
        let rows = vec![
            vec!["original".to_owned()],
            vec!["https://api.example.com/path".to_owned()],
            vec!["https://evil.test/".to_owned()],
            vec![],
            vec!["com%2Cexample%29%2F+20260718000000%21".to_owned()],
        ];
        let page = parse_wayback_page(rows.clone(), "example.com");
        let names = parse_wayback_rows(rows, "example.com");
        assert_eq!(names, BTreeSet::from(["api.example.com".to_owned()]));
        assert_eq!(
            page.resume_key.as_deref(),
            Some("com,example)/ 20260718000000!")
        );
    }

    #[test]
    fn commoncrawl_ndjson_rejects_schema_drift_instead_of_empty_success() {
        let names = parse_commoncrawl_rows(
            "{\"url\":\"https://api.example.com/path\"}\n",
            "example.com",
        )
        .unwrap();
        assert_eq!(names, BTreeSet::from(["api.example.com".to_owned()]));
        let error = parse_commoncrawl_rows(
            "<html>upstream challenge</html>\n{\"unexpected\":true}\n",
            "example.com",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("format NDJSON incohérent"));
    }

    #[test]
    fn commoncrawl_marks_an_over_limit_page_instead_of_silently_truncating_it() {
        let body = concat!(
            r#"{"url":"https://one.example.com/"}"#,
            "\n\n",
            r#"{"url":"https://two.example.com/"}"#,
            "\n",
            r#"{"url":"https://three.example.com/"}"#,
            "\n",
        );
        let page = parse_commoncrawl_page_bounded(body, "example.com", 2).unwrap();
        assert!(page.truncated);
        assert_eq!(
            page.names,
            BTreeSet::from(["one.example.com".to_owned(), "two.example.com".to_owned()])
        );
    }

    #[test]
    fn commoncrawl_endpoint_validation_accepts_only_the_official_https_origin() {
        for endpoint in [
            "https://index.commoncrawl.org/CC-MAIN-2026-30-index",
            "https://index.commoncrawl.org:443/CC-MAIN-2026-30-index",
        ] {
            let validated = validate_commoncrawl_endpoint(endpoint).unwrap();
            assert_eq!(validated.host_str(), Some("index.commoncrawl.org"));
            assert_eq!(validated.port_or_known_default(), Some(443));
        }

        for endpoint in [
            "http://index.commoncrawl.org/CC-MAIN-2026-30-index",
            "https://localhost/CC-MAIN-2026-30-index",
            "https://127.0.0.1/CC-MAIN-2026-30-index",
            "https://10.0.0.1/CC-MAIN-2026-30-index",
            "https://[::1]/CC-MAIN-2026-30-index",
            "https://commoncrawl.org/CC-MAIN-2026-30-index",
            "https://index.commoncrawl.org.evil.test/CC-MAIN-2026-30-index",
            "https://user:secret@index.commoncrawl.org/CC-MAIN-2026-30-index",
            "https://index.commoncrawl.org@127.0.0.1/CC-MAIN-2026-30-index",
            "https://index.commoncrawl.org:8443/CC-MAIN-2026-30-index",
            "https://index.commoncrawl.org/CC-MAIN-2026-30-index?url=evil.test",
            "https://index.commoncrawl.org/CC-MAIN-2026-30-index#fragment",
        ] {
            assert!(
                validate_commoncrawl_endpoint(endpoint).is_err(),
                "unsafe endpoint accepted: {endpoint}"
            );
        }
    }

    #[test]
    fn commoncrawl_warc_range_must_match_the_requested_member_exactly() {
        assert!(commoncrawl_content_range_matches(
            "bytes 42-2047/9000",
            42,
            2_047
        ));
        assert!(commoncrawl_content_range_matches(
            "BYTES 42-2047/*",
            42,
            2_047
        ));
        for value in [
            "bytes 41-2047/9000",
            "bytes 42-2048/9000",
            "bytes 42-2047/2047",
            "bytes */9000",
            "42-2047/9000",
            "bytes 42-2047/9000 trailing",
        ] {
            assert!(
                !commoncrawl_content_range_matches(value, 42, 2_047),
                "{value}"
            );
        }
    }

    #[test]
    fn commoncrawl_warc_sampling_requires_safe_bounded_in_scope_records() {
        let body = concat!(
            r#"{"url":"https://static.example.com/app.js","filename":"crawl-data/CC-MAIN-2026-30/segments/1/warc/file.warc.gz","offset":"42","length":"2048","mime":"application/javascript"}"#,
            "\n",
            r#"{"url":"https://evil.test/app.js","filename":"crawl-data/CC-MAIN-2026-30/evil.warc.gz","offset":"1","length":"100","mime":"application/javascript"}"#,
            "\n",
            r#"{"url":"https://large.example.com/app.js","filename":"crawl-data/CC-MAIN-2026-30/large.warc.gz","offset":"1","length":"999999999","mime":"application/javascript"}"#,
            "\n",
            r#"{"url":"https://unsafe.example.com/app.js","filename":"../outside.warc.gz","offset":"1","length":"100","mime":"application/javascript"}"#,
            "\n",
        );
        let page = parse_commoncrawl_page(body, "example.com").unwrap();
        assert_eq!(page.records.len(), 1);
        let record = page.records.first().unwrap();
        assert_eq!(record.url, "https://static.example.com/app.js");
        assert_eq!(record.offset, 42);
        assert_eq!(record.length, 2_048);
        assert!(page.names.contains("static.example.com"));
        assert!(page.names.contains("large.example.com"));
        assert!(page.names.contains("unsafe.example.com"));
        assert!(!page.names.contains("evil.test"));
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
    async fn terminal_429_without_headers_gets_a_safe_default_deferral() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let error = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            1,
            Duration::from_millis(1),
            "rate-limit-default-test",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("Retry-After=900s"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn terminal_503_with_retry_after_is_an_upstream_deferral_not_a_quota() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let error = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            1,
            Duration::from_millis(1),
            "upstream-deferral-test",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("service amont temporairement différé"));
        assert!(!error.contains("quota externe"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn a_generic_403_with_retry_after_is_not_mislabeled_as_quota() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let response = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            2,
            Duration::from_millis(1),
            "generic-forbidden-test",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn an_explicitly_exhausted_403_is_a_quota_deferral() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let error = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            1,
            Duration::from_millis(1),
            "explicit-rate-limit-test",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("quota externe différé"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn a_truncated_response_body_is_retried_as_a_complete_attempt() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0_u8; 1_024];
                let _ = socket.read(&mut request);
                if attempt == 0 {
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{",
                        )
                        .unwrap();
                } else {
                    socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
                        )
                        .unwrap();
                }
            }
        });
        let response = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            2,
            Duration::from_millis(1),
            "truncated-body-test",
        )
        .await
        .unwrap();
        let values = response_json::<Vec<serde_json::Value>>(response, "truncated-test")
            .await
            .unwrap();
        assert!(values.is_empty());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn a_truncated_401_body_is_not_replayed_and_keeps_its_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{",
                )
                .unwrap();
        });
        let started = Instant::now();
        let error = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .get(format!("http://{address}/")),
            3,
            Duration::from_secs(1),
            "truncated-auth-test",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("HTTP 401 Unauthorized"));
        assert!(started.elapsed() < Duration::from_millis(750));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn post_requests_are_never_automatically_replayed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_listener = listener.try_clone().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = server_listener.accept().unwrap();
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let response = send_with_retry(
            build_client(Duration::from_secs(2))
                .unwrap()
                .post(format!("http://{address}/"))
                .body("one-shot"),
            3,
            Duration::from_millis(1),
            "post-test",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        server.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[tokio::test]
    async fn terminal_transport_errors_never_expose_query_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let error = send_with_retry(
            client(Duration::from_millis(250)).unwrap().get(format!(
                "http://{address}/failure?apiKey=transport-super-secret&cursor=public"
            )),
            1,
            Duration::ZERO,
            "transport-redaction-test",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(!error.contains("transport-super-secret"));
    }

    #[tokio::test]
    async fn a_local_connection_refusal_is_not_retried() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let started = Instant::now();
        let result = send_with_retry(
            build_client(Duration::from_millis(250))
                .unwrap()
                .get(format!("http://{address}/")),
            3,
            Duration::from_millis(500),
            "connection-refused-test",
        )
        .await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(400));
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

    #[test]
    fn api_error_envelopes_and_schema_drift_are_never_empty_successes() {
        assert!(
            provider_error_message(&serde_json::json!({
                "code": 401,
                "message": "invalid api key"
            }))
            .is_some_and(|message| message.contains("invalid api key"))
        );
        assert!(
            provider_error_message(&serde_json::json!({
                "message": "anonymous access is limited"
            }))
            .is_some_and(|message| message.contains("anonymous access"))
        );
        for value in [
            serde_json::json!(false),
            serde_json::json!(0),
            serde_json::json!(0.0),
        ] {
            assert!(
                provider_error_message(&serde_json::json!({
                    "error": value,
                    "results": []
                }))
                .is_none()
            );
        }
        for value in [serde_json::json!(true), serde_json::json!(1)] {
            assert!(
                provider_error_message(&serde_json::json!({
                    "error": value,
                    "results": []
                }))
                .is_some()
            );
        }
        assert!(
            serde_json::from_value::<UrlscanResponse>(serde_json::json!({
                "message": "contract changed"
            }))
            .is_err()
        );
        assert!(serde_json::from_value::<SubdomainAppResponse>(serde_json::json!({})).is_err());
    }

    #[test]
    fn certspotter_rejects_empty_and_repeated_pagination_ids() {
        let page = vec![CertSpotterIssuance {
            id: "cursor-2".to_owned(),
            dns_names: vec!["api.example.com".to_owned()],
        }];
        assert_eq!(
            certspotter_next_after(&page, Some("cursor-1")).unwrap(),
            Some("cursor-2".to_owned())
        );
        assert!(certspotter_next_after(&page, Some("cursor-2")).is_err());

        let empty_id = vec![CertSpotterIssuance {
            id: " ".to_owned(),
            dns_names: Vec::new(),
        }];
        assert!(certspotter_next_after(&empty_id, None).is_err());
    }

    #[tokio::test]
    async fn buffered_response_preserves_url_extensions_and_reuses_the_validated_body() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct FixtureExtension(u8);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .unwrap();
        });
        let requested_url = format!("http://{address}/kept?cursor=1");
        let mut response = build_client(Duration::from_secs(2))
            .unwrap()
            .get(&requested_url)
            .send()
            .await
            .unwrap();
        response.extensions_mut().insert(FixtureExtension(7));

        let response = buffer_external_response(response, 1_024).await.unwrap();
        assert_eq!(response.url().as_str(), requested_url);
        assert_eq!(
            response.extensions().get::<FixtureExtension>(),
            Some(&FixtureExtension(7))
        );
        assert!(
            response
                .extensions()
                .get::<BufferedExternalBody>()
                .is_some()
        );

        let (status, body) = response_bytes_limited_to(response, "fixture", 1_024)
            .await
            .unwrap();
        assert!(status.is_success());
        assert_eq!(body, br#"{"ok":true}"#);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn external_client_sends_transparent_identity_and_content_negotiation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4_096];
            let read = socket.read(&mut request).unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")
                .unwrap();
            String::from_utf8_lossy(&request[..read]).to_ascii_lowercase()
        });
        let response = build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let request = server.join().unwrap();
        assert!(request.contains("user-agent: fellaga/"));
        assert!(request.contains("accept: application/json"));
        assert!(request.contains("accept-language: en-us"));
    }

    #[tokio::test]
    async fn external_client_decompresses_gzip_before_json_validation() {
        const GZIP_EMPTY_ARRAY: &[u8] = &[
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 139, 142, 5, 0, 41, 187, 76, 13, 2, 0, 0, 0,
        ];
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        GZIP_EMPTY_ARRAY.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
            socket.write_all(GZIP_EMPTY_ARRAY).unwrap();
        });
        let response = build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let values = response_json::<Vec<serde_json::Value>>(response, "gzip-test")
            .await
            .unwrap();
        assert!(values.is_empty());
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
