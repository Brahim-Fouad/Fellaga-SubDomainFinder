use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeSet;

use fellaga_core::util;

use super::args::ImportFormat;
fn collect_names_from_json(value: &Value, names: &mut Vec<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_names_from_json(value, names);
            }
        }
        Value::Object(object) => {
            for key in ["name", "host", "fqdn", "hostname"] {
                if let Some(value) = object.get(key).and_then(Value::as_str) {
                    names.push(value.to_owned());
                }
            }
            if let Some(data) = object.get("data") {
                match data {
                    Value::String(value) => names.push(value.clone()),
                    _ => collect_names_from_json(data, names),
                }
            }
            for key in ["results", "hosts", "subdomains", "names", "events"] {
                if let Some(value) = object.get(key) {
                    collect_names_from_json(value, names);
                }
            }
        }
        Value::String(value) => names.push(value.clone()),
        _ => {}
    }
}

fn collect_names_from_text(content: &str, raw_names: &mut Vec<String>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.split_whitespace().next() {
            raw_names.push(name.to_owned());
        }
    }
}

fn collect_names_from_jsonl(content: &str, raw_names: &mut Vec<String>) -> Result<()> {
    for (line_index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = serde_json::from_str::<Value>(line).map_err(|error| {
            anyhow::anyhow!("invalid JSONL import at line {}: {error}", line_index + 1)
        })?;
        collect_names_from_json(&value, raw_names);
    }
    Ok(())
}

pub(crate) fn parse_import_names(
    content: &str,
    format: ImportFormat,
    domain: &str,
) -> Result<BTreeSet<String>> {
    let mut raw_names = Vec::new();
    match format {
        ImportFormat::Json => {
            let value = serde_json::from_str::<Value>(content)
                .map_err(|error| anyhow::anyhow!("invalid JSON import: {error}"))?;
            collect_names_from_json(&value, &mut raw_names);
        }
        ImportFormat::Jsonl => collect_names_from_jsonl(content, &mut raw_names)?,
        ImportFormat::Text | ImportFormat::DnsText => {
            collect_names_from_text(content, &mut raw_names);
        }
        ImportFormat::Auto => {
            if let Ok(value) = serde_json::from_str::<Value>(content) {
                collect_names_from_json(&value, &mut raw_names);
            } else {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Ok(value) = serde_json::from_str::<Value>(line) {
                        collect_names_from_json(&value, &mut raw_names);
                    } else if let Some(name) = line.split_whitespace().next() {
                        raw_names.push(name.to_owned());
                    }
                }
            }
        }
    }
    Ok(raw_names
        .into_iter()
        .filter_map(|name| util::normalize_observed_name(&name, domain))
        .collect())
}
