use anyhow::Result;
use fellaga_core::db::Database;
use fellaga_core::util;
use std::io::Read;

use super::super::args::{ExportArgs, ExportFormat, ImportArgs};
use super::super::imports::parse_import_names;
use super::AppContext;

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

pub(crate) fn import(args: ImportArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let domain = util::normalize_domain(&args.domain)?;
    let content = if args.input == std::path::Path::new("-") {
        let mut content = String::new();
        std::io::stdin().read_to_string(&mut content)?;
        content
    } else {
        std::fs::read_to_string(&args.input)?
    };
    let names = parse_import_names(&content, args.format, &domain)?;
    let source = format!("import:{:?}", args.format).to_ascii_lowercase();
    let database = Database::open(&database_path)?;
    let written = database.import_inventory(&domain, &names, &source)?;
    println!(
        "{} nom(s) importé(s) pour {} avec l'état unverified ({} écriture(s))",
        names.len(),
        domain,
        written
    );
    Ok(())
}

pub(crate) fn export(args: ExportArgs, context: &AppContext) -> Result<()> {
    let database_path = context.database_path.clone();

    let domain = args
        .domain
        .as_deref()
        .map(util::normalize_domain)
        .transpose()?;
    let database = Database::open(&database_path)?;
    let inventory = database.inventory(domain.as_deref(), args.only_live)?;
    let output = match args.format {
        ExportFormat::Jsonl => inventory
            .iter()
            .map(serde_json::to_string)
            .collect::<serde_json::Result<Vec<_>>>()?
            .join("\n"),
        ExportFormat::Csv => {
            let mut rows = vec![
                "fqdn,state,last_verified_at,first_seen,last_seen,times_seen,sources".to_owned(),
            ];
            rows.extend(inventory.iter().map(|entry| {
                [
                    csv_field(&entry.fqdn),
                    entry.state.to_string(),
                    entry
                        .last_verified_at
                        .map(|value| value.to_string())
                        .unwrap_or_default(),
                    entry.first_seen.to_string(),
                    entry.last_seen.to_string(),
                    entry.times_seen.to_string(),
                    csv_field(&entry.sources.iter().cloned().collect::<Vec<_>>().join(";")),
                ]
                .join(",")
            }));
            rows.join("\n")
        }
    };
    if let Some(path) = args.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, output + if inventory.is_empty() { "" } else { "\n" })?;
    } else if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}
