//! Bounded, passive intelligence extraction for Common Crawl WARC responses.
//!
//! This module never executes JavaScript and never performs network requests.  The
//! WARC entry point expects the outer gzip member to have already been decompressed
//! by the caller.  Every allocation and scan is constrained by [`ArchiveLimits`].

use crate::util::{normalize_domain, normalize_observed_name};
use anyhow::{Result, bail};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeSet, VecDeque};
use std::io::Read;
use url::Url;

#[derive(Debug, Clone, Copy)]
pub struct ArchiveLimits {
    /// Maximum decompressed WARC bytes consumed from the reader.
    pub max_archive_bytes: usize,
    /// Maximum bytes in one WARC record, including the embedded HTTP headers.
    pub max_record_bytes: usize,
    /// Maximum bytes accepted for either a WARC or embedded HTTP header block.
    pub max_header_bytes: usize,
    /// Maximum response documents inspected.
    pub max_records: usize,
    /// Maximum bytes inspected from any one response document.
    pub max_document_bytes: usize,
    /// Global byte budget for repeated semantic passes over bounded documents.
    pub max_analysis_bytes: usize,
    /// Maximum distinct in-scope names returned.
    pub max_names: usize,
    /// Maximum provenance observations returned.
    pub max_evidence: usize,
    /// Maximum in-scope asset URLs returned.
    pub max_urls: usize,
    /// Maximum JavaScript string literals inspected per semantic pass.
    pub max_js_literals: usize,
    /// Maximum decoded bytes retained for one string literal.
    pub max_string_bytes: usize,
    /// Maximum JSON scalar/container nodes visited per document.
    pub max_json_values: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 16 * 1024 * 1024,
            max_record_bytes: 2 * 1024 * 1024,
            max_header_bytes: 64 * 1024,
            max_records: 128,
            max_document_bytes: 1024 * 1024,
            max_analysis_bytes: 32 * 1024 * 1024,
            max_names: 4_096,
            max_evidence: 8_192,
            max_urls: 2_048,
            max_js_literals: 4_096,
            max_string_bytes: 4_096,
            max_json_values: 32_768,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveDocumentKind {
    Html,
    Json,
    JavaScript,
    SourceMap,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveTechnique {
    WarcTarget,
    HtmlAttribute,
    JsonString,
    UrlLiteral,
    HostLiteral,
    FetchCall,
    AxiosCall,
    WebSocket,
    WebpackConfig,
    ViteConfig,
    NextConfig,
    SourceMapUrl,
    SourceMapSource,
    ConcatenatedString,
    TextToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveProvenance {
    pub archive_source: String,
    pub target_url: String,
    pub record_index: usize,
    pub document_kind: ArchiveDocumentKind,
    pub technique: ArchiveTechnique,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArchiveEvidence {
    pub fqdn: String,
    /// A relative discovery confidence, not a DNS validation result.
    pub score: u8,
    pub provenance: ArchiveProvenance,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ArchiveStats {
    pub bytes_read: usize,
    pub records_seen: usize,
    pub records_analyzed: usize,
    pub records_malformed: usize,
    pub records_oversized: usize,
    pub records_off_scope: usize,
    pub documents_truncated: usize,
    pub documents_skipped_non_text: usize,
    pub analysis_bytes: usize,
    pub archive_truncated: bool,
    pub record_limit_hit: bool,
    pub name_limit_hit: bool,
    pub evidence_limit_hit: bool,
    pub url_limit_hit: bool,
    pub analysis_limit_hit: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ArchiveDiscovery {
    pub names: BTreeSet<String>,
    pub evidence: Vec<ArchiveEvidence>,
    /// Sanitized, strictly in-scope HTTP(S)/WebSocket URLs found in static data.
    pub in_scope_urls: BTreeSet<String>,
    pub stats: ArchiveStats,
}

#[derive(Debug, Clone)]
struct BaseProvenance {
    archive_source: String,
    target_url: String,
    record_index: usize,
    document_kind: ArchiveDocumentKind,
}

struct Analyzer<'a> {
    root: &'a str,
    limits: ArchiveLimits,
    discovery: ArchiveDiscovery,
    seen_evidence: BTreeSet<(String, ArchiveTechnique, String, usize)>,
}

impl<'a> Analyzer<'a> {
    fn new(root: &'a str, limits: ArchiveLimits) -> Self {
        Self {
            root,
            limits,
            discovery: ArchiveDiscovery::default(),
            seen_evidence: BTreeSet::new(),
        }
    }

    fn reserve_scan<'b>(&mut self, text: &'b str) -> Option<&'b str> {
        let remaining = self
            .limits
            .max_analysis_bytes
            .saturating_sub(self.discovery.stats.analysis_bytes);
        if remaining == 0 {
            self.discovery.stats.analysis_limit_hit = true;
            return None;
        }
        let mut end = text.len().min(remaining);
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end < text.len() {
            self.discovery.stats.analysis_limit_hit = true;
        }
        self.discovery.stats.analysis_bytes =
            self.discovery.stats.analysis_bytes.saturating_add(end);
        Some(&text[..end])
    }

    fn inspect_value(
        &mut self,
        value: &str,
        technique: ArchiveTechnique,
        score: u8,
        provenance: &BaseProvenance,
        collect_urls: bool,
    ) {
        let Some(value) = self.reserve_scan(value) else {
            return;
        };
        let candidate_cap = self.limits.max_evidence.max(self.limits.max_names).max(1);
        for name in scoped_names(value, self.root, candidate_cap) {
            self.push_name(name, technique, score, provenance);
        }
        if collect_urls {
            let remaining = self
                .limits
                .max_urls
                .saturating_sub(self.discovery.in_scope_urls.len());
            for url in urls_in_text(value, None, self.root, remaining.saturating_add(1)) {
                self.push_url(url);
            }
        }
    }

    fn push_name(
        &mut self,
        name: String,
        technique: ArchiveTechnique,
        score: u8,
        provenance: &BaseProvenance,
    ) {
        if !self.discovery.names.contains(&name) {
            if self.discovery.names.len() >= self.limits.max_names {
                self.discovery.stats.name_limit_hit = true;
                return;
            }
            self.discovery.names.insert(name.clone());
        }
        if self.discovery.evidence.len() >= self.limits.max_evidence {
            self.discovery.stats.evidence_limit_hit = true;
            return;
        }
        let key = (
            name.clone(),
            technique,
            provenance.target_url.clone(),
            provenance.record_index,
        );
        if !self.seen_evidence.insert(key) {
            return;
        }
        self.discovery.evidence.push(ArchiveEvidence {
            fqdn: name,
            score: score.min(100),
            provenance: ArchiveProvenance {
                archive_source: provenance.archive_source.clone(),
                target_url: provenance.target_url.clone(),
                record_index: provenance.record_index,
                document_kind: provenance.document_kind,
                technique,
            },
        });
    }

    fn push_url(&mut self, url: String) {
        if self.discovery.in_scope_urls.contains(&url) {
            return;
        }
        if self.discovery.in_scope_urls.len() >= self.limits.max_urls {
            self.discovery.stats.url_limit_hit = true;
            return;
        }
        self.discovery.in_scope_urls.insert(url);
    }

    fn analyze_document(
        &mut self,
        source_url: &str,
        content_type: &str,
        body: &[u8],
        archive_source: &str,
        record_index: usize,
    ) {
        if !supported_document(source_url, content_type) {
            self.discovery.stats.documents_skipped_non_text += 1;
            return;
        }
        let document_len = body.len().min(self.limits.max_document_bytes);
        if document_len < body.len() {
            self.discovery.stats.documents_truncated += 1;
        }
        let text = String::from_utf8_lossy(&body[..document_len]);
        let kind = document_kind(source_url, content_type, &text);
        let provenance = BaseProvenance {
            archive_source: bounded_owned(archive_source, 512),
            target_url: sanitized_url(source_url, 2_048),
            record_index,
            document_kind: kind,
        };

        self.inspect_value(&text, ArchiveTechnique::TextToken, 55, &provenance, true);
        match kind {
            ArchiveDocumentKind::Html => self.analyze_html(&text, &provenance),
            ArchiveDocumentKind::Json => self.analyze_json(&text, &provenance, false, 0),
            ArchiveDocumentKind::JavaScript => self.analyze_javascript(&text, &provenance, 0),
            ArchiveDocumentKind::SourceMap => self.analyze_json(&text, &provenance, true, 0),
            ArchiveDocumentKind::Text => {}
        }
    }

    fn analyze_html(&mut self, text: &str, provenance: &BaseProvenance) {
        let Some(scannable) = self.reserve_scan(text) else {
            return;
        };
        let literals = scan_quoted_literals(
            scannable,
            self.limits.max_js_literals,
            self.limits.max_string_bytes,
            false,
        );
        for literal in literals {
            self.inspect_value(
                &literal.value,
                ArchiveTechnique::HtmlAttribute,
                72,
                provenance,
                true,
            );
        }

        // Script bodies are bounded by the containing document and the global scan budget.
        let lower = scannable.to_ascii_lowercase();
        let mut cursor = 0usize;
        let mut scripts = 0usize;
        while scripts < 64 {
            let Some(relative) = lower[cursor..].find("<script") else {
                break;
            };
            let tag_start = cursor + relative;
            let Some(open_relative) = lower[tag_start..].find('>') else {
                break;
            };
            let content_start = tag_start + open_relative + 1;
            let Some(close_relative) = lower[content_start..].find("</script") else {
                break;
            };
            let content_end = content_start + close_relative;
            let opening = &lower[tag_start..content_start];
            let content = &scannable[content_start..content_end];
            if opening.contains("application/json") || opening.contains("application/ld+json") {
                self.analyze_json(content, provenance, false, 0);
            } else {
                self.analyze_javascript(content, provenance, 0);
            }
            scripts += 1;
            cursor = content_end.saturating_add(8).min(lower.len());
        }
    }

    fn analyze_javascript(
        &mut self,
        text: &str,
        provenance: &BaseProvenance,
        embedded_depth: usize,
    ) {
        let Some(scannable) = self.reserve_scan(text) else {
            return;
        };

        for mapping in source_mapping_urls(
            scannable,
            8,
            self.limits
                .max_string_bytes
                .max(self.limits.max_document_bytes),
        ) {
            if let Some(encoded) = inline_source_map_base64(&mapping) {
                if embedded_depth < 2 {
                    let decode_cap = self.limits.max_document_bytes.saturating_add(1);
                    let estimated = encoded.len().saturating_mul(3) / 4;
                    if estimated <= decode_cap
                        && let Ok(decoded) =
                            base64::engine::general_purpose::STANDARD.decode(encoded)
                        && decoded.len() <= self.limits.max_document_bytes
                    {
                        let decoded = String::from_utf8_lossy(&decoded);
                        self.analyze_json(&decoded, provenance, true, embedded_depth + 1);
                    }
                }
                continue;
            }
            let base = Url::parse(&provenance.target_url).ok();
            for url in urls_in_text(&mapping, base.as_ref(), self.root, 2) {
                self.inspect_value(&url, ArchiveTechnique::SourceMapUrl, 84, provenance, false);
                self.push_url(url);
            }
        }

        let literals = scan_quoted_literals(
            scannable,
            self.limits.max_js_literals,
            self.limits.max_string_bytes,
            true,
        );
        for literal in &literals {
            let technique = classify_javascript_context(scannable, literal.start, &literal.value);
            self.inspect_value(
                &literal.value,
                technique,
                technique_score(technique),
                provenance,
                true,
            );
        }

        // Resolve only literal + literal expressions. Identifiers, calls and template
        // interpolation deliberately break the chain, so no code is evaluated.
        for start in 0..literals.len() {
            let mut value = literals[start].value.clone();
            let mut end = start;
            while end + 1 < literals.len()
                && end.saturating_sub(start) < 7
                && js_concat_gap(scannable, literals[end].end, literals[end + 1].start)
                && value.len().saturating_add(literals[end + 1].value.len())
                    <= self.limits.max_string_bytes
            {
                value.push_str(&literals[end + 1].value);
                end += 1;
                let context = classify_javascript_context(scannable, literals[start].start, &value);
                let technique = match context {
                    ArchiveTechnique::FetchCall
                    | ArchiveTechnique::AxiosCall
                    | ArchiveTechnique::WebSocket => context,
                    _ => ArchiveTechnique::ConcatenatedString,
                };
                self.inspect_value(
                    &value,
                    technique,
                    technique_score(technique).max(86),
                    provenance,
                    true,
                );
            }
        }
    }

    fn analyze_json(
        &mut self,
        text: &str,
        provenance: &BaseProvenance,
        source_map: bool,
        embedded_depth: usize,
    ) {
        let Some(scannable) = self.reserve_scan(text) else {
            return;
        };
        let Ok(root) = serde_json::from_str::<Value>(scannable) else {
            return;
        };
        if source_map {
            self.analyze_source_map_entries(&root, provenance);
        }
        let mut queue = VecDeque::new();
        queue.push_back((&root, None::<&str>));
        let mut visited = 0usize;
        while let Some((value, key)) = queue.pop_front() {
            if visited >= self.limits.max_json_values {
                self.discovery.stats.analysis_limit_hit = true;
                break;
            }
            visited += 1;
            match value {
                Value::String(value) => {
                    if source_map && key == Some("sourcesContent") {
                        if embedded_depth < 2 {
                            self.analyze_javascript(value, provenance, embedded_depth + 1);
                        }
                        continue;
                    }
                    let technique = classify_json_key(key, source_map);
                    self.inspect_value(
                        value,
                        technique,
                        technique_score(technique),
                        provenance,
                        true,
                    );
                }
                Value::Array(values) => {
                    for value in values {
                        if queue.len().saturating_add(visited) >= self.limits.max_json_values {
                            self.discovery.stats.analysis_limit_hit = true;
                            break;
                        }
                        queue.push_back((value, key));
                    }
                }
                Value::Object(values) => {
                    for (child_key, value) in values {
                        if queue.len().saturating_add(visited) >= self.limits.max_json_values {
                            self.discovery.stats.analysis_limit_hit = true;
                            break;
                        }
                        queue.push_back((value, Some(child_key.as_str())));
                    }
                }
                Value::Null | Value::Bool(_) | Value::Number(_) => {}
            }
        }
    }

    fn analyze_source_map_entries(&mut self, root: &Value, provenance: &BaseProvenance) {
        let Value::Object(root) = root else {
            return;
        };
        let target_base = Url::parse(&provenance.target_url).ok();
        let source_base = root
            .get("sourceRoot")
            .and_then(Value::as_str)
            .and_then(|source_root| {
                Url::parse(source_root).ok().or_else(|| {
                    target_base
                        .as_ref()
                        .and_then(|base| base.join(source_root).ok())
                })
            })
            .or(target_base);
        let Some(Value::Array(sources)) = root.get("sources") else {
            return;
        };
        for source in sources.iter().take(self.limits.max_json_values.min(512)) {
            let Some(source) = source.as_str() else {
                continue;
            };
            let resolved = Url::parse(source)
                .ok()
                .or_else(|| source_base.as_ref().and_then(|base| base.join(source).ok()));
            if let Some(url) = resolved
                && url
                    .host_str()
                    .is_some_and(|host| host_in_scope(host, self.root))
                && matches!(url.scheme(), "http" | "https")
                && url.username().is_empty()
                && url.password().is_none()
            {
                let url = sanitize_parsed_url(url);
                self.inspect_value(
                    &url,
                    ArchiveTechnique::SourceMapSource,
                    technique_score(ArchiveTechnique::SourceMapSource),
                    provenance,
                    false,
                );
                self.push_url(url);
            }
        }
    }
}

/// Analyze a decompressed Common Crawl WARC stream without buffering more than
/// `max_archive_bytes + 1` bytes. Only `WARC-Type: response` records whose target
/// URL is the apex or an in-scope host are inspected.
pub fn analyze_common_crawl_warc<R: Read>(
    reader: R,
    root_domain: &str,
    archive_source: &str,
    limits: ArchiveLimits,
) -> Result<ArchiveDiscovery> {
    let root = normalize_domain(root_domain)?;
    let read_cap = limits.max_archive_bytes.saturating_add(1);
    let mut data = Vec::with_capacity(read_cap.min(64 * 1024));
    reader
        .take(u64::try_from(read_cap).unwrap_or(u64::MAX))
        .read_to_end(&mut data)?;
    if data.starts_with(&[0x1f, 0x8b]) {
        bail!("compressed WARC input: decompress the outer gzip member first");
    }
    let archive_truncated = data.len() > limits.max_archive_bytes;
    data.truncate(limits.max_archive_bytes);

    let mut analyzer = Analyzer::new(&root, limits);
    analyzer.discovery.stats.bytes_read = data.len();
    analyzer.discovery.stats.archive_truncated = archive_truncated;
    let mut cursor = 0usize;
    let mut record_index = 0usize;

    while let Some(record_start) = find_warc_marker(&data, cursor) {
        if record_index >= limits.max_records {
            analyzer.discovery.stats.record_limit_hit = true;
            break;
        }
        record_index += 1;
        analyzer.discovery.stats.records_seen += 1;
        let Some((header_end, body_start)) =
            header_bounds(&data, record_start, limits.max_header_bytes)
        else {
            analyzer.discovery.stats.records_malformed += 1;
            cursor = record_start.saturating_add(8);
            continue;
        };
        let headers = &data[record_start..header_end];
        let Some(content_length) =
            header_value(headers, "content-length").and_then(|value| value.parse::<usize>().ok())
        else {
            analyzer.discovery.stats.records_malformed += 1;
            cursor = body_start;
            continue;
        };
        let Some(body_end) = body_start.checked_add(content_length) else {
            analyzer.discovery.stats.records_malformed += 1;
            break;
        };
        if body_end > data.len() {
            analyzer.discovery.stats.archive_truncated = true;
            break;
        }
        cursor = body_end;
        if content_length > limits.max_record_bytes {
            analyzer.discovery.stats.records_oversized += 1;
            continue;
        }
        if !header_value(headers, "warc-type")
            .is_some_and(|value| value.eq_ignore_ascii_case("response"))
        {
            continue;
        }
        let Some(target) = header_value(headers, "warc-target-uri") else {
            analyzer.discovery.stats.records_malformed += 1;
            continue;
        };
        let target = bounded_owned(target, 4_096);
        if !target_url_in_scope(&target, &root) {
            analyzer.discovery.stats.records_off_scope += 1;
            continue;
        }

        let target_safe = sanitized_url(&target, 2_048);
        if let Ok(url) = Url::parse(&target)
            && let Some(host) = url.host_str()
            && let Some(name) = normalize_observed_name(host, &root)
        {
            let provenance = BaseProvenance {
                archive_source: bounded_owned(archive_source, 512),
                target_url: target_safe.clone(),
                record_index,
                document_kind: ArchiveDocumentKind::Text,
            };
            analyzer.push_name(name, ArchiveTechnique::WarcTarget, 62, &provenance);
        }

        let response = &data[body_start..body_end];
        let Some((http_header_end, payload_start)) =
            header_bounds(response, 0, limits.max_header_bytes)
        else {
            analyzer.discovery.stats.records_malformed += 1;
            continue;
        };
        if !response[..http_header_end].starts_with(b"HTTP/") {
            analyzer.discovery.stats.records_malformed += 1;
            continue;
        }
        let http_headers = &response[..http_header_end];
        let content_type = header_value(http_headers, "content-type").unwrap_or_default();
        let available_payload = &response[payload_start..];
        let payload = if let Some(declared) = header_value(http_headers, "content-length")
            .and_then(|value| value.parse::<usize>().ok())
        {
            if declared > available_payload.len() {
                analyzer.discovery.stats.records_malformed += 1;
                continue;
            }
            &available_payload[..declared]
        } else {
            available_payload
        };
        analyzer.analyze_document(&target, content_type, payload, archive_source, record_index);
        analyzer.discovery.stats.records_analyzed += 1;
    }
    finish(analyzer.discovery)
}

/// Analyze one already-bounded HTTP body. Oversized bodies are inspected only up
/// to `max_document_bytes`, and that truncation is reported in the result.
pub fn analyze_archived_document(
    root_domain: &str,
    source_url: &str,
    content_type: &str,
    body: &[u8],
    limits: ArchiveLimits,
) -> Result<ArchiveDiscovery> {
    let root = normalize_domain(root_domain)?;
    let mut analyzer = Analyzer::new(&root, limits);
    analyzer.analyze_document(source_url, content_type, body, "document", 0);
    analyzer.discovery.stats.records_seen = 1;
    analyzer.discovery.stats.records_analyzed = 1;
    finish(analyzer.discovery)
}

fn finish(mut discovery: ArchiveDiscovery) -> Result<ArchiveDiscovery> {
    discovery.evidence.sort_by(|left, right| {
        left.fqdn
            .cmp(&right.fqdn)
            .then_with(|| right.score.cmp(&left.score))
            .then_with(|| left.provenance.technique.cmp(&right.provenance.technique))
            .then_with(|| left.provenance.target_url.cmp(&right.provenance.target_url))
    });
    Ok(discovery)
}

fn document_kind(url: &str, content_type: &str, text: &str) -> ArchiveDocumentKind {
    let content_type = content_type.to_ascii_lowercase();
    let path = Url::parse(url)
        .ok()
        .map(|url| url.path().to_ascii_lowercase())
        .unwrap_or_else(|| url.to_ascii_lowercase());
    if path.ends_with(".map")
        || content_type.contains("source-map")
        || (content_type.contains("json")
            && text.contains("\"sources\"")
            && text.contains("\"mappings\""))
    {
        ArchiveDocumentKind::SourceMap
    } else if content_type.contains("html") || path.ends_with(".html") || path.ends_with(".htm") {
        ArchiveDocumentKind::Html
    } else if content_type.contains("javascript") || path.ends_with(".js") || path.ends_with(".mjs")
    {
        ArchiveDocumentKind::JavaScript
    } else if content_type.contains("json") || path.ends_with(".json") {
        ArchiveDocumentKind::Json
    } else {
        ArchiveDocumentKind::Text
    }
}

fn supported_document(url: &str, content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    let path = Url::parse(url)
        .ok()
        .map(|url| url.path().to_ascii_lowercase())
        .unwrap_or_else(|| url.to_ascii_lowercase());
    let explicit_text = content_type.starts_with("text/")
        || [
            "javascript",
            "json",
            "xml",
            "x-www-form-urlencoded",
            "source-map",
        ]
        .iter()
        .any(|marker| content_type.contains(marker));
    let textual_extension = [
        ".html",
        ".htm",
        ".js",
        ".mjs",
        ".map",
        ".json",
        ".xml",
        ".webmanifest",
        ".txt",
    ]
    .iter()
    .any(|extension| path.ends_with(extension));
    let extensionless =
        path.ends_with('/') || !path.rsplit('/').next().unwrap_or_default().contains('.');
    explicit_text || textual_extension || (content_type.is_empty() && extensionless)
}

fn technique_score(technique: ArchiveTechnique) -> u8 {
    match technique {
        ArchiveTechnique::WebSocket => 94,
        ArchiveTechnique::FetchCall | ArchiveTechnique::AxiosCall => 92,
        ArchiveTechnique::WebpackConfig
        | ArchiveTechnique::ViteConfig
        | ArchiveTechnique::NextConfig => 88,
        ArchiveTechnique::ConcatenatedString => 86,
        ArchiveTechnique::SourceMapUrl => 84,
        ArchiveTechnique::SourceMapSource => 80,
        ArchiveTechnique::UrlLiteral => 78,
        ArchiveTechnique::HtmlAttribute => 72,
        ArchiveTechnique::JsonString => 70,
        ArchiveTechnique::HostLiteral => 68,
        ArchiveTechnique::WarcTarget => 62,
        ArchiveTechnique::TextToken => 55,
    }
}

fn classify_json_key(key: Option<&str>, source_map: bool) -> ArchiveTechnique {
    let key = key.unwrap_or_default().to_ascii_lowercase();
    if source_map && key == "sources" {
        ArchiveTechnique::SourceMapSource
    } else if ["assetprefix", "basepath", "next_public", "domains"]
        .iter()
        .any(|marker| key.contains(marker))
    {
        ArchiveTechnique::NextConfig
    } else if key.starts_with("vite_") || key.contains("vite") {
        ArchiveTechnique::ViteConfig
    } else if ["publicpath", "devserver", "webpack"]
        .iter()
        .any(|marker| key.contains(marker))
    {
        ArchiveTechnique::WebpackConfig
    } else {
        ArchiveTechnique::JsonString
    }
}

fn classify_javascript_context(
    source: &str,
    literal_start: usize,
    value: &str,
) -> ArchiveTechnique {
    let context_start = literal_start.saturating_sub(192);
    let context = &source[context_start..literal_start];
    let local_start = context
        .rfind([';', '\r', '\n'])
        .map_or(0, |position| position + 1);
    let compact = context[local_start..]
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && !matches!(character, '\'' | '"' | '`')
        })
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.ends_with("newwebsocket(") || compact.ends_with("websocket(") {
        ArchiveTechnique::WebSocket
    } else if compact.ends_with("fetch(") || compact.ends_with("window.fetch(") {
        ArchiveTechnique::FetchCall
    } else if [
        "axios(",
        "axios.get(",
        "axios.post(",
        "axios.put(",
        "axios.delete(",
        "axios.request(",
    ]
    .iter()
    .any(|suffix| compact.ends_with(suffix))
    {
        ArchiveTechnique::AxiosCall
    } else if ["publicpath:", "__webpack_public_path__=", "devserver:"]
        .iter()
        .any(|marker| compact.ends_with(marker))
        || compact.contains("webpack")
    {
        ArchiveTechnique::WebpackConfig
    } else if [
        "assetprefix:",
        "basepath:",
        "next_public_",
        "domains:",
        "__next_data__",
    ]
    .iter()
    .any(|marker| compact.ends_with(marker) || compact.contains(marker))
    {
        ArchiveTechnique::NextConfig
    } else if [
        "vite_",
        "import.meta.env",
        "server:{host:",
        "server:{proxy:",
    ]
    .iter()
    .any(|marker| compact.ends_with(marker) || compact.contains(marker))
    {
        ArchiveTechnique::ViteConfig
    } else if value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("ws://")
        || value.starts_with("wss://")
        || value.starts_with("//")
    {
        ArchiveTechnique::UrlLiteral
    } else {
        ArchiveTechnique::HostLiteral
    }
}

#[derive(Debug, Clone)]
struct QuotedLiteral {
    value: String,
    start: usize,
    end: usize,
}

fn scan_quoted_literals(
    source: &str,
    max_literals: usize,
    max_string_bytes: usize,
    javascript_comments: bool,
) -> Vec<QuotedLiteral> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() && literals.len() < max_literals {
        if javascript_comments && bytes[cursor] == b'/' && cursor + 1 < bytes.len() {
            if bytes[cursor + 1] == b'/' {
                cursor += 2;
                while cursor < bytes.len() && !matches!(bytes[cursor], b'\r' | b'\n') {
                    cursor += 1;
                }
                continue;
            }
            if bytes[cursor + 1] == b'*' {
                cursor += 2;
                while cursor + 1 < bytes.len()
                    && !(bytes[cursor] == b'*' && bytes[cursor + 1] == b'/')
                {
                    cursor += 1;
                }
                cursor = cursor.saturating_add(2).min(bytes.len());
                continue;
            }
        }
        let quote = bytes[cursor];
        if !matches!(quote, b'\'' | b'"' | b'`') {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        let mut decoded = String::new();
        while cursor < bytes.len() {
            let byte = bytes[cursor];
            if byte == quote {
                cursor += 1;
                literals.push(QuotedLiteral {
                    value: decoded,
                    start,
                    end: cursor,
                });
                break;
            }
            if byte == b'\\' {
                cursor += 1;
                if cursor >= bytes.len() {
                    break;
                }
                let escaped = bytes[cursor];
                match escaped {
                    b'n' => push_char_bounded(&mut decoded, '\n', max_string_bytes),
                    b'r' => push_char_bounded(&mut decoded, '\r', max_string_bytes),
                    b't' => push_char_bounded(&mut decoded, '\t', max_string_bytes),
                    b'/' => push_char_bounded(&mut decoded, '/', max_string_bytes),
                    b'\\' => push_char_bounded(&mut decoded, '\\', max_string_bytes),
                    b'\'' => push_char_bounded(&mut decoded, '\'', max_string_bytes),
                    b'"' => push_char_bounded(&mut decoded, '"', max_string_bytes),
                    b'x' if cursor + 2 < bytes.len() => {
                        if let Some(character) = decode_hex_char(&bytes[cursor + 1..cursor + 3]) {
                            push_char_bounded(&mut decoded, character, max_string_bytes);
                            cursor += 2;
                        }
                    }
                    b'u' if cursor + 4 < bytes.len() => {
                        if let Some(character) = decode_hex_char(&bytes[cursor + 1..cursor + 5]) {
                            push_char_bounded(&mut decoded, character, max_string_bytes);
                            cursor += 4;
                        }
                    }
                    b'\r' | b'\n' => {}
                    other => push_char_bounded(&mut decoded, char::from(other), max_string_bytes),
                }
                cursor += 1;
                continue;
            }
            let Some(character) = source[cursor..].chars().next() else {
                break;
            };
            push_char_bounded(&mut decoded, character, max_string_bytes);
            cursor += character.len_utf8();
        }
    }
    literals
}

fn push_char_bounded(output: &mut String, character: char, max_bytes: usize) {
    if output.len().saturating_add(character.len_utf8()) <= max_bytes {
        output.push(character);
    }
}

fn decode_hex_char(bytes: &[u8]) -> Option<char> {
    let text = std::str::from_utf8(bytes).ok()?;
    let value = u32::from_str_radix(text, 16).ok()?;
    char::from_u32(value)
}

fn js_concat_gap(source: &str, left: usize, right: usize) -> bool {
    if left > right || right > source.len() {
        return false;
    }
    let bytes = &source.as_bytes()[left..right];
    let mut cursor = 0usize;
    let mut pluses = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        } else if bytes[cursor] == b'+' {
            pluses += 1;
            cursor += 1;
        } else if bytes[cursor] == b'/' && cursor + 1 < bytes.len() && bytes[cursor + 1] == b'*' {
            cursor += 2;
            while cursor + 1 < bytes.len() && !(bytes[cursor] == b'*' && bytes[cursor + 1] == b'/')
            {
                cursor += 1;
            }
            if cursor + 1 >= bytes.len() {
                return false;
            }
            cursor += 2;
        } else {
            return false;
        }
    }
    pluses == 1
}

fn source_mapping_urls(source: &str, limit: usize, max_value_bytes: usize) -> Vec<String> {
    let lower = source.to_ascii_lowercase();
    let marker = "sourcemappingurl=";
    let mut values = Vec::new();
    let mut cursor = 0usize;
    while values.len() < limit {
        let Some(relative) = lower[cursor..].find(marker) else {
            break;
        };
        let start = cursor + relative + marker.len();
        let end = source[start..]
            .find(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '"' | '\'' | '*' | '<' | '>')
            })
            .map(|relative| start + relative)
            .unwrap_or(source.len());
        let value = source[start..end].trim();
        if !value.is_empty() {
            values.push(bounded_owned(value, max_value_bytes));
        }
        cursor = end.max(start.saturating_add(1));
    }
    values
}

fn inline_source_map_base64(value: &str) -> Option<&str> {
    let (metadata, payload) = value.split_once(',')?;
    let metadata = metadata.to_ascii_lowercase();
    (metadata.starts_with("data:application/json") && metadata.contains(";base64"))
        .then_some(payload)
}

fn scoped_names(text: &str, root: &str, limit: usize) -> BTreeSet<String> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let needle = root.as_bytes();
    let mut names = BTreeSet::new();
    let mut cursor = 0usize;
    while cursor.saturating_add(needle.len()) <= bytes.len() && names.len() < limit {
        let Some(relative) = lower[cursor..].find(root) else {
            break;
        };
        let match_start = cursor + relative;
        let match_end = match_start + needle.len();
        if match_end < bytes.len() && (hostname_byte(bytes[match_end]) || bytes[match_end] == b'.')
        {
            cursor = match_start.saturating_add(1);
            continue;
        }
        let mut start = match_start;
        while start > 0 && (hostname_byte(bytes[start - 1]) || bytes[start - 1] == b'.') {
            start -= 1;
        }
        let candidate = &lower[start..match_end];
        if let Some(name) = normalize_observed_name(candidate, root) {
            names.insert(name);
        }
        cursor = match_end;
    }
    names
}

fn hostname_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn urls_in_text(text: &str, base: Option<&Url>, root: &str, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let lower = text.to_ascii_lowercase();
    let mut urls = BTreeSet::new();
    let mut cursor = 0usize;
    while cursor < text.len() && urls.len() < limit {
        let mut next: Option<(usize, &str)> = None;
        for marker in ["https://", "http://", "wss://", "ws://", "//"] {
            if let Some(relative) = lower[cursor..].find(marker) {
                let position = cursor + relative;
                if next.is_none_or(|(best, _)| position < best) {
                    next = Some((position, marker));
                }
            }
        }
        let Some((start, marker)) = next else {
            break;
        };
        // Do not reinterpret the slashes inside an already matched absolute URL.
        if marker == "//" && start > 0 && text.as_bytes()[start - 1] == b':' {
            cursor = start.saturating_add(2);
            continue;
        }
        let end = text[start..]
            .find(|character: char| {
                character.is_ascii_whitespace()
                    || matches!(
                        character,
                        '"' | '\'' | '`' | '<' | '>' | ')' | ']' | '}' | ','
                    )
            })
            .map(|relative| start + relative)
            .unwrap_or(text.len());
        let raw = text[start..end].trim_end_matches(['.', ';', ':']);
        let parsed = if raw.starts_with("//") {
            Url::parse(&format!("https:{raw}"))
        } else {
            Url::parse(raw)
        };
        if let Ok(url) = parsed
            && url.host_str().is_some_and(|host| host_in_scope(host, root))
            && matches!(url.scheme(), "http" | "https" | "ws" | "wss")
            && url.username().is_empty()
            && url.password().is_none()
        {
            urls.insert(sanitize_parsed_url(url));
        }
        cursor = end.max(start.saturating_add(marker.len()));
    }

    // A sourceMappingURL is commonly relative and has no scheme marker.
    if urls.is_empty()
        && let Some(base) = base
        && let Ok(url) = base.join(text.trim())
        && url.host_str().is_some_and(|host| host_in_scope(host, root))
        && matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
    {
        urls.insert(sanitize_parsed_url(url));
    }
    urls.into_iter().take(limit).collect()
}

fn target_url_in_scope(value: &str, root: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some_and(|host| host_in_scope(host, root))
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn host_in_scope(host: &str, root: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == root || host.ends_with(&format!(".{root}"))
}

fn sanitized_url(value: &str, max_bytes: usize) -> String {
    Url::parse(value)
        .ok()
        .map(sanitize_parsed_url)
        .map(|value| bounded_owned(&value, max_bytes))
        .unwrap_or_else(|| bounded_owned(value, max_bytes))
}

fn sanitize_parsed_url(mut url: Url) -> String {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn bounded_owned(value: &str, max_bytes: usize) -> String {
    let mut end = value.len().min(max_bytes);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn find_warc_marker(data: &[u8], start: usize) -> Option<usize> {
    const MARKER: &[u8] = b"WARC/1.";
    data.get(start..)?
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .map(|relative| start + relative)
}

fn header_bounds(data: &[u8], start: usize, max_header_bytes: usize) -> Option<(usize, usize)> {
    let available = data.len().saturating_sub(start);
    let end = start.saturating_add(available.min(max_header_bytes));
    let header = data.get(start..end)?;
    if let Some(relative) = header.windows(4).position(|window| window == b"\r\n\r\n") {
        return Some((start + relative, start + relative + 4));
    }
    header
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|relative| (start + relative, start + relative + 2))
}

fn header_value<'a>(headers: &'a [u8], wanted: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(headers).ok()?;
    text.lines().find_map(|line| {
        let line = line.trim_end_matches('\r');
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted)
            .then_some(value.trim())
    })
}
