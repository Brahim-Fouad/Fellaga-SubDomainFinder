//! Deterministic, target-local hostname grammar induction.
//!
//! This module deliberately does not infer a registrable domain. The caller supplies a
//! normalized scan root, which remains the immutable scope boundary. That makes roots such as
//! `example.co.uk` safe without second-guessing the caller's Public Suffix List decision.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

const MAX_EXPANSION_RATIO: usize = 25;

const ENVIRONMENTS: &[&str] = &[
    "beta",
    "dev",
    "development",
    "int",
    "integration",
    "lab",
    "preprod",
    "prod",
    "production",
    "qa",
    "sandbox",
    "stage",
    "staging",
    "test",
    "testing",
    "uat",
];

const SERVICES: &[&str] = &[
    "admin",
    "api",
    "app",
    "assets",
    "auth",
    "backend",
    "billing",
    "cache",
    "cdn",
    "checkout",
    "console",
    "dashboard",
    "database",
    "db",
    "devops",
    "docs",
    "edge",
    "ftp",
    "gateway",
    "git",
    "gitlab",
    "graphql",
    "images",
    "img",
    "imap",
    "jenkins",
    "m",
    "mail",
    "media",
    "mobile",
    "monitor",
    "origin",
    "payments",
    "pop",
    "pop3",
    "portal",
    "proxy",
    "redis",
    "remote",
    "search",
    "smtp",
    "sql",
    "static",
    "status",
    "vpn",
    "web",
    "www",
];

const REGIONS: &[&str] = &[
    "af", "ap", "asia", "au", "ca", "central", "east", "emea", "eu", "europe", "global", "north",
    "sa", "south", "us", "west",
];

const CLOUDS: &[&str] = &[
    "akamai",
    "aws",
    "azure",
    "cf",
    "cloud",
    "cloudflare",
    "cloudfront",
    "do",
    "gcp",
    "linode",
    "oci",
    "ovh",
];

/// The semantic role assigned to one hostname token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Service,
    Environment,
    Region,
    Cloud,
    Number,
    Literal,
}

impl TokenKind {
    fn is_semantic(self) -> bool {
        matches!(
            self,
            Self::Service | Self::Environment | Self::Region | Self::Cloud
        )
    }

    fn tag(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Environment => "env",
            Self::Region => "region",
            Self::Cloud => "cloud",
            Self::Number => "number",
            Self::Literal => "literal",
        }
    }
}

/// A lexical token and the separator that occurred immediately before it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelToken {
    pub value: String,
    pub kind: TokenKind,
    pub separator_before: String,
}

/// One previously observed in-scope hostname.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameObservation {
    pub fqdn: String,
    pub observed_at: Option<i64>,
}

impl NameObservation {
    pub fn new(fqdn: impl Into<String>, observed_at: Option<i64>) -> Self {
        Self {
            fqdn: fqdn.into(),
            observed_at,
        }
    }
}

/// Resource and inference limits. Every value is enforced as a hard cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelligenceConfig {
    pub max_candidates: usize,
    pub beam_width: usize,
    pub max_expansion_ratio: usize,
    pub min_template_support: usize,
    pub max_values_per_slot: usize,
    pub numeric_radius: u32,
    pub max_numeric_span: u32,
    pub temporal_half_life_secs: i64,
    /// When omitted, the newest timestamp in the input is the deterministic reference point.
    pub reference_time: Option<i64>,
}

impl Default for IntelligenceConfig {
    fn default() -> Self {
        Self {
            max_candidates: 5_000,
            beam_width: 256,
            max_expansion_ratio: MAX_EXPANSION_RATIO,
            min_template_support: 2,
            max_values_per_slot: 16,
            numeric_radius: 1,
            max_numeric_span: 20,
            temporal_half_life_secs: 180 * 24 * 60 * 60,
            reference_time: None,
        }
    }
}

/// A serializable error suitable for CLI and JSONL callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum IntelligenceError {
    InvalidRoot(String),
    RootNotNormalized(String),
}

impl fmt::Display for IntelligenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot(root) => write!(formatter, "invalid scan root: {root}"),
            Self::RootNotNormalized(root) => {
                write!(formatter, "scan root must be normalized: {root}")
            }
        }
    }
}

impl std::error::Error for IntelligenceError {}

/// A value available to a grammar slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrammarValue {
    pub value: String,
    pub observations: usize,
    pub latest_observed_at: Option<i64>,
    /// False for a target-local transfer from another template or a numeric extrapolation.
    pub observed_in_template: bool,
    pub temporal_score_milli: u16,
}

/// A variable position in an induced template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateSlot {
    pub index: usize,
    pub kind: TokenKind,
    pub values: Vec<GrammarValue>,
}

/// A literal or variable template component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplatePart {
    Literal {
        separator_before: String,
        value: String,
    },
    Slot {
        separator_before: String,
        kind: TokenKind,
        slot_index: usize,
    },
}

/// One interpretable target-local hostname template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameTemplate {
    pub id: String,
    /// Empty for direct children of the scan root.
    pub parent_relative: String,
    pub parts: Vec<TemplatePart>,
    pub slots: Vec<TemplateSlot>,
    pub support: usize,
    pub latest_observed_at: Option<i64>,
    pub temporal_score_milli: u16,
    pub projected_cardinality: usize,
    pub observed_labels: Vec<String>,
}

/// Target-wide vocabulary learned from observations, never from a static cross-product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VocabularyEntry {
    pub kind: TokenKind,
    pub value: String,
    pub observations: usize,
    pub latest_observed_at: Option<i64>,
    pub temporal_score_milli: u16,
}

/// Serializable learned grammar that can be persisted in SQLite as JSON if desired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalGrammar {
    pub root: String,
    pub reference_time: Option<i64>,
    pub observation_count: usize,
    pub ignored_observations: usize,
    pub vocabulary: Vec<VocabularyEntry>,
    pub templates: Vec<NameTemplate>,
}

/// A bounded proposal emitted by the grammar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelligenceCandidate {
    pub fqdn: String,
    pub relative_name: String,
    pub label: String,
    pub parent_relative: String,
    pub template_id: String,
    pub score: i64,
    pub template_support: usize,
    pub temporal_score_milli: u16,
    pub generation_path: Vec<String>,
}

/// End-to-end output for callers that do not need to persist the model separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelligenceResult {
    pub grammar: LocalGrammar,
    pub candidates: Vec<IntelligenceCandidate>,
    pub effective_candidate_cap: usize,
}

#[derive(Debug, Clone, Default)]
struct ValueStats {
    observations: usize,
    latest_observed_at: Option<i64>,
}

impl ValueStats {
    fn observe(&mut self, observed_at: Option<i64>) {
        self.observations = self.observations.saturating_add(1);
        self.latest_observed_at = max_option(self.latest_observed_at, observed_at);
    }
}

#[derive(Debug, Clone)]
struct TemplateAccumulator {
    parent_relative: String,
    parts: Vec<TemplatePart>,
    values: BTreeMap<usize, BTreeMap<String, ValueStats>>,
    kinds: BTreeMap<usize, TokenKind>,
    observed_labels: BTreeSet<String>,
    latest_observed_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct BeamState {
    label: String,
    score: i64,
    path: Vec<String>,
}

/// Split a valid DNS label at hyphens and alpha/numeric boundaries, then classify its tokens.
pub fn tokenize_label(label: &str) -> Option<Vec<LabelToken>> {
    if !valid_dns_label(label) || label != label.to_ascii_lowercase() {
        return None;
    }

    let mut output = Vec::new();
    for (segment_index, segment) in label.split('-').enumerate() {
        let mut start = 0;
        let bytes = segment.as_bytes();
        while start < bytes.len() {
            let numeric = bytes[start].is_ascii_digit();
            let mut end = start + 1;
            while end < bytes.len() && bytes[end].is_ascii_digit() == numeric {
                end += 1;
            }
            let value = &segment[start..end];
            output.push(LabelToken {
                value: value.to_owned(),
                kind: classify_token(value),
                separator_before: if start == 0 && segment_index > 0 {
                    "-".to_owned()
                } else {
                    String::new()
                },
            });
            start = end;
        }
    }
    (!output.is_empty()).then_some(output)
}

/// Build an interpretable grammar from unique in-scope observations.
pub fn induce_local_grammar(
    root: &str,
    observations: &[NameObservation],
    config: &IntelligenceConfig,
) -> Result<LocalGrammar, IntelligenceError> {
    validate_root(root)?;

    let mut unique = BTreeMap::<String, Option<i64>>::new();
    let mut ignored = 0usize;
    for observation in observations {
        let fqdn = observation.fqdn.trim_end_matches('.').to_ascii_lowercase();
        if fqdn == root || !in_scope(&fqdn, root) || !valid_fqdn(&fqdn) {
            ignored = ignored.saturating_add(1);
            continue;
        }
        unique
            .entry(fqdn)
            .and_modify(|latest| *latest = max_option(*latest, observation.observed_at))
            .or_insert(observation.observed_at);
    }

    let reference_time = config
        .reference_time
        .or_else(|| unique.values().copied().flatten().max());
    let mut global = BTreeMap::<(TokenKind, String), ValueStats>::new();
    let mut accumulators = BTreeMap::<String, TemplateAccumulator>::new();

    for (fqdn, observed_at) in &unique {
        let relative = fqdn
            .strip_suffix(root)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .unwrap_or_default();
        let (label, parent_relative) = relative.split_once('.').unwrap_or((relative, ""));
        let Some(tokens) = tokenize_label(label) else {
            ignored = ignored.saturating_add(1);
            continue;
        };

        for token in &tokens {
            if token.kind != TokenKind::Literal {
                global
                    .entry((token.kind, token.value.clone()))
                    .or_default()
                    .observe(*observed_at);
            }
        }

        let mut parts = Vec::with_capacity(tokens.len());
        let mut slot_index = 0usize;
        let mut initial_values = Vec::new();
        let mut kinds = Vec::new();
        for token in tokens {
            if token.kind == TokenKind::Literal {
                parts.push(TemplatePart::Literal {
                    separator_before: token.separator_before,
                    value: token.value,
                });
            } else {
                parts.push(TemplatePart::Slot {
                    separator_before: token.separator_before,
                    kind: token.kind,
                    slot_index,
                });
                initial_values.push((slot_index, token.value));
                kinds.push((slot_index, token.kind));
                slot_index = slot_index.saturating_add(1);
            }
        }
        if slot_index == 0 {
            continue;
        }

        let key = template_key(parent_relative, &parts);
        let accumulator = accumulators
            .entry(key)
            .or_insert_with(|| TemplateAccumulator {
                parent_relative: parent_relative.to_owned(),
                parts,
                values: BTreeMap::new(),
                kinds: kinds.into_iter().collect(),
                observed_labels: BTreeSet::new(),
                latest_observed_at: None,
            });
        accumulator.observed_labels.insert(label.to_owned());
        accumulator.latest_observed_at = max_option(accumulator.latest_observed_at, *observed_at);
        for (index, value) in initial_values {
            accumulator
                .values
                .entry(index)
                .or_default()
                .entry(value)
                .or_default()
                .observe(*observed_at);
        }
    }

    let vocabulary = global
        .iter()
        .map(|((kind, value), stats)| VocabularyEntry {
            kind: *kind,
            value: value.clone(),
            observations: stats.observations,
            latest_observed_at: stats.latest_observed_at,
            temporal_score_milli: temporal_score(
                stats.latest_observed_at,
                reference_time,
                config.temporal_half_life_secs,
            ),
        })
        .collect::<Vec<_>>();

    let mut templates = accumulators
        .into_iter()
        .filter_map(|(key, accumulator)| {
            let support = accumulator.observed_labels.len();
            if support < config.min_template_support.max(1) {
                return None;
            }

            let mut slots = Vec::new();
            for (index, kind) in &accumulator.kinds {
                let mut values = accumulator
                    .values
                    .get(index)
                    .into_iter()
                    .flat_map(|values| values.iter())
                    .map(|(value, stats)| GrammarValue {
                        value: value.clone(),
                        observations: stats.observations,
                        latest_observed_at: stats.latest_observed_at,
                        observed_in_template: true,
                        temporal_score_milli: temporal_score(
                            stats.latest_observed_at,
                            reference_time,
                            config.temporal_half_life_secs,
                        ),
                    })
                    .collect::<Vec<_>>();

                if kind.is_semantic() {
                    for entry in vocabulary.iter().filter(|entry| entry.kind == *kind) {
                        if !values.iter().any(|existing| existing.value == entry.value) {
                            values.push(GrammarValue {
                                value: entry.value.clone(),
                                observations: entry.observations,
                                latest_observed_at: entry.latest_observed_at,
                                observed_in_template: false,
                                temporal_score_milli: entry.temporal_score_milli,
                            });
                        }
                    }
                } else if *kind == TokenKind::Number {
                    extend_numeric_values(&mut values, config);
                }

                values.sort_by(compare_grammar_values);
                values.truncate(config.max_values_per_slot.max(1));
                slots.push(TemplateSlot {
                    index: *index,
                    kind: *kind,
                    values,
                });
            }
            slots.sort_by_key(|slot| slot.index);
            let projected_cardinality = slots.iter().fold(1usize, |cardinality, slot| {
                cardinality.saturating_mul(slot.values.len())
            });
            let temporal_score_milli = temporal_score(
                accumulator.latest_observed_at,
                reference_time,
                config.temporal_half_life_secs,
            );
            Some(NameTemplate {
                id: format!("grammar-{:016x}", stable_hash(key.as_bytes())),
                parent_relative: accumulator.parent_relative,
                parts: accumulator.parts,
                slots,
                support,
                latest_observed_at: accumulator.latest_observed_at,
                temporal_score_milli,
                projected_cardinality,
                observed_labels: accumulator.observed_labels.into_iter().collect(),
            })
        })
        .collect::<Vec<_>>();

    templates.sort_by(|left, right| {
        right
            .support
            .cmp(&left.support)
            .then_with(|| right.temporal_score_milli.cmp(&left.temporal_score_milli))
            .then_with(|| left.id.cmp(&right.id))
    });

    Ok(LocalGrammar {
        root: root.to_owned(),
        reference_time,
        observation_count: unique.len(),
        ignored_observations: ignored,
        vocabulary,
        templates,
    })
}

/// Generate a deterministic, bounded beam of novel in-scope candidates.
pub fn generate_candidates(
    grammar: &LocalGrammar,
    config: &IntelligenceConfig,
) -> Vec<IntelligenceCandidate> {
    if validate_root(&grammar.root).is_err() {
        return Vec::new();
    }
    let ratio = config.max_expansion_ratio.min(MAX_EXPANSION_RATIO);
    let hard_cap = config
        .max_candidates
        .min(grammar.observation_count.saturating_mul(ratio));
    if hard_cap == 0 || config.beam_width == 0 {
        return Vec::new();
    }

    let observed = grammar
        .templates
        .iter()
        .flat_map(|template| {
            template
                .observed_labels
                .iter()
                .map(move |label| assemble_fqdn(label, &template.parent_relative, &grammar.root))
        })
        .collect::<BTreeSet<_>>();
    let mut generated = HashMap::<String, IntelligenceCandidate>::new();

    for template in &grammar.templates {
        let mut beam = vec![BeamState {
            label: String::new(),
            score: template_score(template),
            path: Vec::new(),
        }];
        for part in &template.parts {
            match part {
                TemplatePart::Literal {
                    separator_before,
                    value,
                } => {
                    for state in &mut beam {
                        state.label.push_str(separator_before);
                        state.label.push_str(value);
                    }
                }
                TemplatePart::Slot {
                    separator_before,
                    kind,
                    slot_index,
                } => {
                    let Some(slot) = template.slots.iter().find(|slot| slot.index == *slot_index)
                    else {
                        beam.clear();
                        break;
                    };
                    let mut expanded = Vec::with_capacity(
                        beam.len()
                            .saturating_mul(slot.values.len())
                            .min(config.beam_width),
                    );
                    for state in &beam {
                        for value in &slot.values {
                            let mut next = state.clone();
                            next.label.push_str(separator_before);
                            next.label.push_str(&value.value);
                            next.score = next.score.saturating_add(value_score(value));
                            next.path.push(format!(
                                "{}={}{}",
                                kind.tag(),
                                value.value,
                                if value.observed_in_template {
                                    ":local"
                                } else {
                                    ":transferred"
                                }
                            ));
                            expanded.push(next);
                        }
                    }
                    expanded.sort_by(|left, right| {
                        right
                            .score
                            .cmp(&left.score)
                            .then_with(|| left.label.cmp(&right.label))
                    });
                    expanded.dedup_by(|left, right| left.label == right.label);
                    expanded.truncate(config.beam_width);
                    beam = expanded;
                }
            }
        }

        for state in beam {
            if !valid_dns_label(&state.label) {
                continue;
            }
            let fqdn = assemble_fqdn(&state.label, &template.parent_relative, &grammar.root);
            if observed.contains(&fqdn) || !valid_fqdn(&fqdn) || !in_scope(&fqdn, &grammar.root) {
                continue;
            }
            let relative_name = fqdn
                .strip_suffix(&grammar.root)
                .and_then(|prefix| prefix.strip_suffix('.'))
                .unwrap_or_default()
                .to_owned();
            let candidate = IntelligenceCandidate {
                fqdn: fqdn.clone(),
                relative_name,
                label: state.label,
                parent_relative: template.parent_relative.clone(),
                template_id: template.id.clone(),
                score: state.score,
                template_support: template.support,
                temporal_score_milli: template.temporal_score_milli,
                generation_path: state.path,
            };
            match generated.get(&fqdn) {
                Some(current) if current.score >= candidate.score => {}
                _ => {
                    generated.insert(fqdn, candidate);
                }
            }
        }
    }

    let mut candidates = generated.into_values().collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.fqdn.cmp(&right.fqdn))
            .then_with(|| left.template_id.cmp(&right.template_id))
    });
    candidates.truncate(hard_cap);
    candidates
}

/// Convenience entrypoint for one-shot callers.
pub fn learn_and_generate(
    root: &str,
    observations: &[NameObservation],
    config: &IntelligenceConfig,
) -> Result<IntelligenceResult, IntelligenceError> {
    let grammar = induce_local_grammar(root, observations, config)?;
    let effective_candidate_cap = config.max_candidates.min(
        grammar
            .observation_count
            .saturating_mul(config.max_expansion_ratio.min(MAX_EXPANSION_RATIO)),
    );
    let candidates = generate_candidates(&grammar, config);
    Ok(IntelligenceResult {
        grammar,
        candidates,
        effective_candidate_cap,
    })
}

fn classify_token(value: &str) -> TokenKind {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        TokenKind::Number
    } else if ENVIRONMENTS.binary_search(&value).is_ok() {
        TokenKind::Environment
    } else if REGIONS.binary_search(&value).is_ok() {
        TokenKind::Region
    } else if CLOUDS.binary_search(&value).is_ok() {
        TokenKind::Cloud
    } else if SERVICES.binary_search(&value).is_ok() {
        TokenKind::Service
    } else {
        TokenKind::Literal
    }
}

fn validate_root(root: &str) -> Result<(), IntelligenceError> {
    let normalized = root.trim_end_matches('.').to_ascii_lowercase();
    if normalized != root {
        return Err(IntelligenceError::RootNotNormalized(root.to_owned()));
    }
    if !valid_fqdn(root) || !root.contains('.') {
        return Err(IntelligenceError::InvalidRoot(root.to_owned()));
    }
    Ok(())
}

fn valid_fqdn(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.is_ascii() && name.split('.').all(valid_dns_label)
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label.as_bytes().first() != Some(&b'-')
        && label.as_bytes().last() != Some(&b'-')
}

fn in_scope(fqdn: &str, root: &str) -> bool {
    fqdn == root
        || fqdn
            .strip_suffix(root)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn template_key(parent_relative: &str, parts: &[TemplatePart]) -> String {
    let mut key = format!("parent={parent_relative}|");
    for part in parts {
        match part {
            TemplatePart::Literal {
                separator_before,
                value,
            } => key.push_str(&format!("{separator_before}literal:{value}|")),
            TemplatePart::Slot {
                separator_before,
                kind,
                slot_index,
            } => key.push_str(&format!(
                "{separator_before}slot:{}:{slot_index}|",
                kind.tag()
            )),
        }
    }
    key
}

fn stable_hash(bytes: &[u8]) -> u64 {
    // FNV-1a is sufficient here: the human-readable template remains the source of truth.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn max_option(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left @ Some(_), None) => left,
        (None, right) => right,
    }
}

fn temporal_score(
    observed_at: Option<i64>,
    reference_time: Option<i64>,
    half_life_secs: i64,
) -> u16 {
    let (Some(observed_at), Some(reference_time)) = (observed_at, reference_time) else {
        return 500;
    };
    if observed_at >= reference_time || half_life_secs <= 0 {
        return 1_000;
    }
    let age = (reference_time - observed_at) as f64;
    let score = 1_000.0 * 2f64.powf(-age / half_life_secs as f64);
    score.round().clamp(0.0, 1_000.0) as u16
}

fn compare_grammar_values(left: &GrammarValue, right: &GrammarValue) -> std::cmp::Ordering {
    right
        .observed_in_template
        .cmp(&left.observed_in_template)
        .then_with(|| right.observations.cmp(&left.observations))
        .then_with(|| right.temporal_score_milli.cmp(&left.temporal_score_milli))
        .then_with(|| left.value.cmp(&right.value))
}

fn extend_numeric_values(values: &mut Vec<GrammarValue>, config: &IntelligenceConfig) {
    let mut remaining = config.max_values_per_slot.saturating_sub(values.len());
    if remaining == 0 {
        return;
    }
    let parsed = values
        .iter()
        .filter_map(|value| {
            value
                .value
                .parse::<u32>()
                .ok()
                .map(|number| (number, value.value.len()))
        })
        .collect::<Vec<_>>();
    if parsed.len() < 2 {
        return;
    }
    let width = parsed[0].1;
    if parsed
        .iter()
        .any(|(_, candidate_width)| *candidate_width != width)
    {
        return;
    }
    let minimum = parsed.iter().map(|(number, _)| *number).min().unwrap_or(0);
    let maximum = parsed.iter().map(|(number, _)| *number).max().unwrap_or(0);
    if maximum.saturating_sub(minimum) > config.max_numeric_span {
        return;
    }
    let start = minimum.saturating_sub(config.numeric_radius);
    let end = maximum.saturating_add(config.numeric_radius);
    for number in start..=end {
        let value = format!("{number:0width$}");
        if values.iter().any(|existing| existing.value == value) {
            continue;
        }
        values.push(GrammarValue {
            value,
            observations: 0,
            latest_observed_at: None,
            observed_in_template: false,
            temporal_score_milli: 0,
        });
        remaining -= 1;
        if remaining == 0 {
            break;
        }
    }
}

fn template_score(template: &NameTemplate) -> i64 {
    (template.support.min(i64::MAX as usize) as i64)
        .saturating_mul(100_000)
        .saturating_add(i64::from(template.temporal_score_milli) * 100)
}

fn value_score(value: &GrammarValue) -> i64 {
    let local_bonus = if value.observed_in_template {
        20_000
    } else {
        0
    };
    local_bonus
        + (value.observations.min(i64::MAX as usize) as i64).saturating_mul(5_000)
        + i64::from(value.temporal_score_milli) * 10
}

fn assemble_fqdn(label: &str, parent_relative: &str, root: &str) -> String {
    if parent_relative.is_empty() {
        format!("{label}.{root}")
    } else {
        format!("{label}.{parent_relative}.{root}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn observation(name: &str, observed_at: i64) -> NameObservation {
        NameObservation::new(name, Some(observed_at))
    }

    #[test]
    fn tokenizes_semantics_and_digit_boundaries() {
        let tokens = tokenize_label("api-dev-us-02").expect("valid label");
        assert_eq!(
            tokens.iter().map(|token| token.kind).collect::<Vec<_>>(),
            vec![
                TokenKind::Service,
                TokenKind::Environment,
                TokenKind::Region,
                TokenKind::Number,
            ]
        );
        assert_eq!(tokens[3].separator_before, "-");

        let compact = tokenize_label("node007").expect("valid label");
        assert_eq!(compact[0].kind, TokenKind::Literal);
        assert_eq!(compact[1].kind, TokenKind::Number);
        assert_eq!(compact[1].separator_before, "");
    }

    #[test]
    fn completes_a_local_matrix_and_small_numeric_range() {
        let observations = vec![
            observation("api-dev-01.example.com", 1_000),
            observation("web-prod-03.example.com", 2_000),
        ];
        let config = IntelligenceConfig {
            reference_time: Some(2_000),
            ..IntelligenceConfig::default()
        };
        let result = learn_and_generate("example.com", &observations, &config).unwrap();
        let names = result
            .candidates
            .iter()
            .map(|candidate| candidate.fqdn.as_str())
            .collect::<BTreeSet<_>>();
        assert!(names.contains("api-prod-02.example.com"));
        assert!(names.contains("web-dev-02.example.com"));
        assert!(!names.contains("api-dev-01.example.com"));
        assert!(!names.contains("web-prod-03.example.com"));
    }

    #[test]
    fn normalized_root_is_a_strict_psl_safe_boundary() {
        let observations = vec![
            observation("api-dev-01.example.co.uk", 100),
            observation("web-prod-02.example.co.uk", 200),
            observation("api-dev-03.evil-example.co.uk", 300),
            observation("notexample.co.uk", 400),
        ];
        let result = learn_and_generate(
            "example.co.uk",
            &observations,
            &IntelligenceConfig::default(),
        )
        .unwrap();
        assert_eq!(result.grammar.observation_count, 2);
        assert_eq!(result.grammar.ignored_observations, 2);
        assert!(
            result
                .candidates
                .iter()
                .all(|candidate| candidate.fqdn.ends_with(".example.co.uk"))
        );
        assert!(matches!(
            induce_local_grammar(
                "Example.co.uk.",
                &observations,
                &IntelligenceConfig::default()
            ),
            Err(IntelligenceError::RootNotNormalized(_))
        ));
    }

    #[test]
    fn candidate_cap_never_exceeds_twenty_five_times_input() {
        let observations = (0..12)
            .map(|number| {
                observation(
                    &format!(
                        "{}-{}-{number:02}.example.com",
                        SERVICES[number % 6],
                        ENVIRONMENTS[number % 6]
                    ),
                    number as i64,
                )
            })
            .collect::<Vec<_>>();
        let config = IntelligenceConfig {
            max_candidates: usize::MAX,
            beam_width: 10_000,
            max_expansion_ratio: 500,
            max_values_per_slot: 64,
            ..IntelligenceConfig::default()
        };
        let result = learn_and_generate("example.com", &observations, &config).unwrap();
        assert!(result.candidates.len() <= result.grammar.observation_count * 25);
        assert_eq!(
            result.effective_candidate_cap,
            result.grammar.observation_count * 25
        );
    }

    #[test]
    fn output_is_deterministic_and_recent_evidence_scores_higher() {
        let observations = vec![
            observation("api-dev-01.example.com", 0),
            observation("web-prod-03.example.com", 180 * 24 * 60 * 60),
        ];
        let config = IntelligenceConfig {
            reference_time: Some(180 * 24 * 60 * 60),
            ..IntelligenceConfig::default()
        };
        let first = learn_and_generate("example.com", &observations, &config).unwrap();
        let second = learn_and_generate("example.com", &observations, &config).unwrap();
        assert_eq!(first, second);

        let template = &first.grammar.templates[0];
        let service_slot = template
            .slots
            .iter()
            .find(|slot| slot.kind == TokenKind::Service)
            .unwrap();
        let api = service_slot
            .values
            .iter()
            .find(|value| value.value == "api")
            .unwrap();
        let web = service_slot
            .values
            .iter()
            .find(|value| value.value == "web")
            .unwrap();
        assert!(web.temporal_score_milli > api.temporal_score_milli);
    }

    proptest! {
        #[test]
        fn generated_names_remain_in_scope_and_bounded(
            first in 0u8..20,
            second in 21u8..40,
            requested_limit in 1usize..500,
            requested_ratio in 0usize..100,
        ) {
            let observations = vec![
                observation(&format!("api-dev-{first:02}.example.co.uk"), 100),
                observation(&format!("web-prod-{second:02}.example.co.uk"), 200),
            ];
            let config = IntelligenceConfig {
                max_candidates: requested_limit,
                beam_width: 512,
                max_expansion_ratio: requested_ratio,
                max_numeric_span: 64,
                ..IntelligenceConfig::default()
            };
            let result = learn_and_generate("example.co.uk", &observations, &config).unwrap();
            let cap = requested_limit.min(2usize.saturating_mul(requested_ratio.min(25)));
            prop_assert!(result.candidates.len() <= cap);
            for candidate in result.candidates {
                prop_assert!(candidate.fqdn.ends_with(".example.co.uk"));
                prop_assert!(valid_fqdn(&candidate.fqdn));
            }
        }
    }
}
