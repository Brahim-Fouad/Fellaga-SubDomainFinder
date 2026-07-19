//! API-key loading, secret redaction, and source selection.

use super::catalog::{
    SOURCE_DEFINITIONS, SourceId, SourceMetadata, definition, environment_names, source_metadata,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use url::Url;
#[derive(Clone, Default)]
pub struct ApiKeyStore {
    pub(super) keys: BTreeMap<String, Vec<String>>,
    pub(super) cursor: Arc<AtomicUsize>,
}

impl fmt::Debug for ApiKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyStore([REDACTED])")
    }
}

#[derive(Deserialize, Serialize, Default)]
pub(super) struct ConfigFile {
    #[serde(default)]
    pub(super) api_keys: BTreeMap<String, KeyList>,
}

impl fmt::Debug for ConfigFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigFile { api_keys: [REDACTED] }")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum KeyList {
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

    pub(super) fn values(&self, source: &str) -> Vec<String> {
        let source = source.to_ascii_lowercase();
        let aliases = definition(&source)
            .map(|entry| entry.key_aliases)
            .unwrap_or_default();
        let mut values = Vec::new();
        for name in std::iter::once(source.as_str()).chain(aliases.iter().copied()) {
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
            for variable in source.environment_names {
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

pub(super) fn sanitize_external_message(message: &str, secrets: &[String]) -> String {
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

pub fn source_statuses(keys: &ApiKeyStore) -> Vec<SourceStatus> {
    SourceId::ALL
        .iter()
        .copied()
        .map(|source_id| {
            let entry = source_id.definition();
            let name = entry.id.as_str();
            debug_assert_eq!(entry.name, name);
            let metadata = source_metadata(name);
            SourceStatus {
                name: name.to_owned(),
                requires_key: entry.requires_key,
                key_environment: entry.key_environment.map(ToOwned::to_owned),
                configured: keys.has(name),
                automatic: metadata.available
                    && entry.automatic
                    && (!entry.requires_key || keys.has(name)),
                metadata,
            }
        })
        .collect()
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
