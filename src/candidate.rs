use crate::util::{learnable_label, valid_relative_name};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

const ENVIRONMENTS: &[&str] = &[
    "dev",
    "development",
    "test",
    "testing",
    "qa",
    "uat",
    "stage",
    "staging",
    "preprod",
    "prod",
    "production",
    "sandbox",
    "beta",
];

const HIGH_VALUE_SERVICES: &[&str] = &[
    "api",
    "app",
    "admin",
    "auth",
    "backend",
    "console",
    "dashboard",
    "gateway",
    "portal",
    "web",
];

const REGIONS: &[&str] = &[
    "us",
    "us-east",
    "us-west",
    "eu",
    "eu-west",
    "eu-central",
    "ca",
    "ap",
    "ap-south",
    "asia",
    "emea",
    "global",
];

const CLOUDS: &[&str] = &["aws", "azure", "gcp", "cloud", "do", "ovh", "cf", "edge"];

#[derive(Debug, Clone, serde::Serialize)]
pub struct MutationRule {
    pub name: String,
    pub score: i64,
    pub pattern: String,
}

pub fn default_mutation_rules() -> Vec<MutationRule> {
    [
        ("environment-suffix", 680, "{{word}}-{{env}}.{{parent}}"),
        ("environment-prefix", 670, "{{env}}-{{word}}.{{parent}}"),
        ("region-suffix", 640, "{{word}}-{{region}}.{{parent}}"),
        ("cloud-suffix", 620, "{{word}}-{{cloud}}.{{parent}}"),
        ("number-suffix", 600, "{{word}}-{{n}}.{{parent}}"),
        ("environment-level", 590, "{{word}}.{{env}}.{{parent}}"),
    ]
    .into_iter()
    .map(|(name, score, pattern)| MutationRule {
        name: name.to_owned(),
        score,
        pattern: pattern.to_owned(),
    })
    .collect()
}

pub fn load_mutation_rules(path: &Path) -> Result<Vec<MutationRule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("lecture du DSL de mutations {}", path.display()))?;
    let mut rules = Vec::new();
    for (index, raw) in content.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let parts = line.splitn(3, ':').collect::<Vec<_>>();
        let (score, name, pattern) = if parts.len() == 3 {
            let score = parts[0]
                .trim()
                .parse::<i64>()
                .with_context(|| format!("score invalide à la ligne {} du DSL", index + 1))?;
            (
                score,
                parts[1].trim().to_owned(),
                parts[2].trim().to_owned(),
            )
        } else {
            (600, format!("custom-{}", index + 1), line.to_owned())
        };
        if name.is_empty() || pattern.is_empty() {
            bail!("règle de mutation vide à la ligne {}", index + 1);
        }
        for placeholder in pattern.match_indices("{{").filter_map(|(start, _)| {
            let rest = &pattern[start + 2..];
            rest.find("}}").map(|end| &rest[..end])
        }) {
            if !matches!(
                placeholder,
                "word" | "parent" | "env" | "region" | "cloud" | "n"
            ) {
                bail!(
                    "variable de mutation inconnue '{{{{{placeholder}}}}}' à la ligne {}",
                    index + 1
                );
            }
        }
        rules.push(MutationRule {
            name,
            score,
            pattern,
        });
    }
    if rules.is_empty() {
        bail!("le DSL de mutations ne contient aucune règle");
    }
    Ok(rules)
}

fn expand_mutation_pattern(pattern: &str, word: &str, parent: &str) -> Vec<String> {
    let mut expanded = vec![
        pattern
            .replace("{{word}}", word)
            .replace("{{parent}}", parent),
    ];
    for (placeholder, values) in [
        ("{{env}}", ENVIRONMENTS),
        ("{{region}}", REGIONS),
        ("{{cloud}}", CLOUDS),
    ] {
        if expanded.iter().any(|value| value.contains(placeholder)) {
            expanded = expanded
                .into_iter()
                .flat_map(|value| {
                    values
                        .iter()
                        .map(move |replacement| value.replace(placeholder, replacement))
                })
                .collect();
        }
    }
    if expanded.iter().any(|value| value.contains("{{n}}")) {
        expanded = expanded
            .into_iter()
            .flat_map(|value| {
                (0..=20).map(move |number| value.replace("{{n}}", &number.to_string()))
            })
            .collect();
    }
    expanded
        .into_iter()
        .map(|value| {
            let mut value = value;
            while value.contains("..") {
                value = value.replace("..", ".");
            }
            value.trim_matches('.').to_owned()
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct CandidateProposal {
    pub relative_name: String,
    pub generator: String,
    pub score: i64,
}

fn proposal(
    relative_name: String,
    generator: &str,
    base_score: i64,
    learned_scores: &HashMap<String, i64>,
) -> Option<CandidateProposal> {
    valid_relative_name(&relative_name).then(|| CandidateProposal {
        relative_name,
        generator: generator.to_owned(),
        score: base_score + learned_scores.get(generator).copied().unwrap_or_default(),
    })
}

fn replace_token(label: &str, old: &str, new: &str) -> Option<String> {
    let mut tokens = label.split('-').collect::<Vec<_>>();
    let index = tokens.iter().position(|token| *token == old)?;
    tokens[index] = new;
    Some(tokens.join("-"))
}

fn numeric_neighbors(label: &str) -> Vec<String> {
    let split = label
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_ascii_digit())
        .map(|(index, character)| index + character.len_utf8())
        .unwrap_or(0);
    let (prefix, digits) = label.split_at(split);
    let Ok(number) = digits.parse::<u32>() else {
        return Vec::new();
    };
    let width = digits.len();
    let start = number.saturating_sub(2);
    (start..=number.saturating_add(2))
        .filter(|candidate| *candidate != number)
        .map(|candidate| format!("{prefix}{candidate:0width$}"))
        .collect()
}

pub fn generate_contextual(
    domain: &str,
    observed_names: impl IntoIterator<Item = String>,
    learned_scores: &HashMap<String, i64>,
    limit: usize,
) -> Vec<CandidateProposal> {
    generate_contextual_with_rules(
        domain,
        observed_names,
        learned_scores,
        &default_mutation_rules(),
        limit,
    )
}

pub fn generate_contextual_with_rules(
    domain: &str,
    observed_names: impl IntoIterator<Item = String>,
    learned_scores: &HashMap<String, i64>,
    mutation_rules: &[MutationRule],
    limit: usize,
) -> Vec<CandidateProposal> {
    let suffix = format!(".{domain}");
    let relatives = observed_names
        .into_iter()
        .filter_map(|name| name.strip_suffix(&suffix).map(ToOwned::to_owned))
        .filter(|relative| valid_relative_name(relative))
        .collect::<BTreeSet<_>>();
    let mut proposals = Vec::new();
    for relative in &relatives {
        let (label, parent) = relative
            .split_once('.')
            .map(|(label, parent)| (label, Some(parent)))
            .unwrap_or((relative.as_str(), None));
        let with_parent = |candidate: String| {
            parent
                .map(|parent| format!("{candidate}.{parent}"))
                .unwrap_or(candidate)
        };

        for environment in ENVIRONMENTS {
            if label.split('-').any(|token| token == *environment) {
                for replacement in ENVIRONMENTS {
                    if replacement == environment {
                        continue;
                    }
                    if let Some(candidate) = replace_token(label, environment, replacement)
                        && let Some(candidate) = proposal(
                            with_parent(candidate),
                            "environment-swap",
                            1_000,
                            learned_scores,
                        )
                    {
                        proposals.push(candidate);
                    }
                }
            }
        }

        for neighbor in numeric_neighbors(label) {
            if let Some(candidate) = proposal(
                with_parent(neighbor),
                "number-neighbor",
                950,
                learned_scores,
            ) {
                proposals.push(candidate);
            }
        }

        let parts = label.split('-').collect::<Vec<_>>();
        if parts.len() == 2
            && parts.iter().all(|part| learnable_label(part))
            && let Some(candidate) = proposal(
                with_parent(format!("{}-{}", parts[1], parts[0])),
                "token-order",
                800,
                learned_scores,
            )
        {
            proposals.push(candidate);
        }

        if HIGH_VALUE_SERVICES.contains(&label) {
            for environment in ["dev", "test", "staging", "prod"] {
                for candidate in [
                    format!("{label}-{environment}"),
                    format!("{environment}-{label}"),
                    format!("{label}.{environment}"),
                ] {
                    if let Some(candidate) = proposal(
                        with_parent(candidate),
                        "service-environment",
                        700,
                        learned_scores,
                    ) {
                        proposals.push(candidate);
                    }
                }
            }
        }

        for rule in mutation_rules {
            for candidate in
                expand_mutation_pattern(&rule.pattern, label, parent.unwrap_or_default())
            {
                let generator = format!("dsl:{}", rule.name);
                if let Some(candidate) = proposal(candidate, &generator, rule.score, learned_scores)
                {
                    proposals.push(candidate);
                }
                if proposals.len() >= limit.saturating_mul(4) {
                    break;
                }
            }
        }
    }

    proposals.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.relative_name.cmp(&right.relative_name))
            .then_with(|| left.generator.cmp(&right.generator))
    });
    let mut seen = BTreeSet::new();
    proposals.retain(|candidate| seen.insert(candidate.relative_name.clone()));
    proposals.truncate(limit);
    proposals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutations_are_contextual_bounded_and_ranked() {
        let candidates = generate_contextual(
            "example.com",
            [
                "api.example.com".to_owned(),
                "web-dev-01.example.com".to_owned(),
            ],
            &HashMap::from([("number-neighbor".to_owned(), 500)]),
            20,
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.relative_name == "web-dev-02")
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.relative_name == "web-staging-01")
        );
        assert!(candidates.len() <= 20);
        assert_eq!(candidates[0].generator, "number-neighbor");
    }

    #[test]
    fn mutation_dsl_expands_cloud_region_and_parent() {
        let rules = vec![MutationRule {
            name: "cloud-region".to_owned(),
            score: 900,
            pattern: "{{word}}-{{cloud}}-{{region}}.{{parent}}".to_owned(),
        }];
        let candidates = generate_contextual_with_rules(
            "example.com",
            ["api.internal.example.com".to_owned()],
            &HashMap::new(),
            &rules,
            200,
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.relative_name == "api-aws-eu.internal")
        );
    }
}
