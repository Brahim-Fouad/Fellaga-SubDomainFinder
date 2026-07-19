//! Architecture fitness tests.
//!
//! These checks protect the dependency direction and the small composition
//! surfaces created during the architecture refactor. The ceilings are
//! intentionally generous: they detect a responsibility moving back into a
//! facade without failing on ordinary imports, documentation, or re-exports.

use std::fs;
use std::path::{Path, PathBuf};

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = project_root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

fn line_count(source: &str) -> usize {
    source.lines().count()
}

fn compact_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn rust_files_below(relative: &str) -> Vec<PathBuf> {
    fn visit(directory: &Path, files: &mut Vec<PathBuf>) {
        let mut entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("could not inspect {}: {error}", directory.display()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|error| panic!("could not enumerate {}: {error}", directory.display()));
        entries.sort_by_key(|entry| entry.path());

        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                visit(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    let directory = project_root().join(relative);
    let mut files = Vec::new();
    visit(&directory, &mut files);
    files
}

/// Removes items carrying a standalone `#[cfg(test)]` attribute.
///
/// This is deliberately a small source-level filter rather than a Rust parser.
/// It handles both semicolon-terminated imports/functions and braced test
/// modules, which are the test-only shapes used by this repository.
fn without_cfg_test_items(source: &str) -> String {
    let lines = source.lines().collect::<Vec<_>>();
    let mut production = String::new();
    let mut index = 0;

    while index < lines.len() {
        if lines[index].trim() != "#[cfg(test)]" {
            production.push_str(lines[index]);
            production.push('\n');
            index += 1;
            continue;
        }

        index += 1;
        while index < lines.len() && lines[index].trim_start().starts_with("#[") {
            index += 1;
        }

        let mut brace_depth = 0_i64;
        let mut saw_brace = false;
        while index < lines.len() {
            let line = lines[index];
            for character in line.chars() {
                match character {
                    '{' => {
                        saw_brace = true;
                        brace_depth += 1;
                    }
                    '}' => brace_depth -= 1,
                    _ => {}
                }
            }
            index += 1;

            let semicolon_item_finished = !saw_brace && line.trim_end().ends_with(';');
            let braced_item_finished = saw_brace && brace_depth <= 0;
            if semicolon_item_finished || braced_item_finished {
                break;
            }
        }
    }

    production
}

#[test]
fn main_remains_a_thin_composition_root() {
    let main = read("src/main.rs");
    let lines = line_count(&main);

    assert!(
        lines <= 50,
        "src/main.rs has {lines} lines; keep it as a thin composition root and move command behavior into src/cli/"
    );
    assert!(
        main.contains("cli::run().await"),
        "src/main.rs should delegate application execution to the CLI application layer"
    );
    assert!(
        !main.contains("fellaga_core::")
            && !main.contains("Scanner::")
            && !main.contains("Database::"),
        "src/main.rs must not coordinate scanning, persistence, or output directly"
    );
}

#[test]
fn public_compatibility_facades_stay_focused() {
    struct Facade {
        path: &'static str,
        ceiling: usize,
        minimum_children: usize,
        implementation_marker: Option<&'static str>,
    }

    let facades = [
        Facade {
            path: "src/scanner.rs",
            ceiling: 250,
            minimum_children: 8,
            implementation_marker: Some("implScanner"),
        },
        Facade {
            path: "src/dns.rs",
            ceiling: 150,
            minimum_children: 4,
            implementation_marker: Some("implDnsEngine"),
        },
        Facade {
            path: "src/passive.rs",
            ceiling: 200,
            minimum_children: 8,
            implementation_marker: None,
        },
        Facade {
            path: "src/db.rs",
            ceiling: 1_800,
            minimum_children: 7,
            implementation_marker: Some("implDatabase"),
        },
    ];

    for facade in facades {
        let source = read(facade.path);
        let production = without_cfg_test_items(&source);
        let lines = line_count(&source);
        let child_modules = production
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                line.starts_with("mod ") || line.starts_with("pub mod ")
            })
            .count();

        assert!(
            lines <= facade.ceiling,
            "{} has {lines} lines (ceiling {}); keep compatibility and shared types here, but move operational responsibilities into focused child modules",
            facade.path,
            facade.ceiling
        );
        assert!(
            child_modules >= facade.minimum_children,
            "{} exposes only {child_modules} child modules; it no longer looks like the focused compatibility facade established by the architecture",
            facade.path
        );
        if let Some(marker) = facade.implementation_marker {
            assert!(
                !compact_whitespace(&production).contains(marker),
                "{} contains a concrete implementation block; keep behavior in its focused child modules",
                facade.path
            );
        }
    }
}

#[test]
fn passive_production_does_not_depend_on_persistence() {
    let mut files = rust_files_below("src/passive");
    files.push(project_root().join("src/passive.rs"));

    let mut violations = Vec::new();
    for path in files {
        if path.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
        let production = without_cfg_test_items(&source);
        for (index, line) in production.lines().enumerate() {
            if line.contains("crate::db") {
                let relative = path.strip_prefix(project_root()).unwrap_or(&path);
                violations.push(format!("{}:{}", relative.display(), index + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "passive discovery must not depend on SQLite or database types; move shared contracts to a neutral module. Violations: {}",
        violations.join(", ")
    );
}

#[test]
fn confidence_uses_only_the_immutable_passive_catalog() {
    let confidence = without_cfg_test_items(&read("src/confidence.rs"));
    let forbidden_passive_references = confidence
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            line.contains("crate::passive::") && !line.contains("crate::passive::catalog::")
        })
        .map(|(index, line)| format!("{}: {}", index + 1, line.trim()))
        .collect::<Vec<_>>();

    assert!(
        forbidden_passive_references.is_empty(),
        "confidence scoring may read immutable source metadata, but must not depend on passive network runtime: {}",
        forbidden_passive_references.join(" | ")
    );

    let catalog = without_cfg_test_items(&read("src/passive/catalog.rs"));
    let network_markers = [
        "reqwest::",
        "tokio::net",
        "send_external",
        "fetch_detailed",
        "crate::db",
    ];
    let catalog_violations = network_markers
        .into_iter()
        .filter(|marker| catalog.contains(marker))
        .collect::<Vec<_>>();
    assert!(
        catalog_violations.is_empty(),
        "src/passive/catalog.rs must remain immutable metadata, not acquire network or persistence behavior. Found: {}",
        catalog_violations.join(", ")
    );
}

#[test]
fn cli_output_delegates_finding_selection_to_core_policy() {
    let output = without_cfg_test_items(&read("src/cli/output.rs"));
    let console_render = without_cfg_test_items(&read("src/cli/console/render.rs"));

    assert!(
        output.contains("fellaga_core::output::FindingSelection"),
        "CLI serialization and raw output must import the canonical FindingSelection policy"
    );
    assert!(
        output.contains("FindingSelection::new")
            && output.contains(".includes(")
            && output.contains(".project("),
        "CLI output paths must delegate both individual and whole-result filtering to FindingSelection"
    );
    assert!(
        !output.contains("ObservationState::")
            && !output.contains("finding.state")
            && !output.contains("finding.wildcard"),
        "src/cli/output.rs reimplements live/wildcard policy; keep that decision exclusively in core FindingSelection"
    );
    assert!(
        console_render.contains("fellaga_core::output::FindingSelection")
            && console_render.contains("FindingSelection::new"),
        "human finding rendering must use the same FindingSelection policy as JSON and raw output"
    );
}
