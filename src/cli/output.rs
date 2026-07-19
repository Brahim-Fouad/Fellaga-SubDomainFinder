use anyhow::Result;
use fellaga_core::model::{Finding, ScanResult};
use fellaga_core::output::FindingSelection;
use fellaga_core::scanner::ProgressEvent;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamJsonlMode {
    Disabled,
    FinalOnly,
}

pub(crate) const fn stream_jsonl_mode(enabled: bool, _only_live: bool) -> StreamJsonlMode {
    match enabled {
        false => StreamJsonlMode::Disabled,
        true => StreamJsonlMode::FinalOnly,
    }
}

pub(crate) const fn scan_progress_enabled(quiet: bool, _show: bool, _stream_jsonl: bool) -> bool {
    !quiet
}

pub(crate) const fn raw_output_diagnostic_event(event: &ProgressEvent) -> bool {
    !matches!(event, ProgressEvent::Finding(_))
}

pub(crate) fn stream_finding_line(finding: &Finding) -> String {
    serde_json::json!({"type": "finding", "finding": finding}).to_string()
}

pub(crate) fn finding_selected_for_output(
    finding: &Finding,
    include_non_live: bool,
    include_wildcard: bool,
) -> bool {
    FindingSelection::new(include_non_live, include_wildcard).includes(finding)
}

pub(crate) fn scan_result_for_output(
    result: &ScanResult,
    include_non_live: bool,
    include_wildcard: bool,
) -> ScanResult {
    FindingSelection::new(include_non_live, include_wildcard).project(result)
}

pub(crate) fn write_scan(
    path: &PathBuf,
    result: &ScanResult,
    json_output: bool,
    include_non_live: bool,
    include_wildcard: bool,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if json_output
        || path
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        let output = scan_result_for_output(result, include_non_live, include_wildcard);
        std::fs::write(path, serde_json::to_string_pretty(&output)? + "\n")?;
    } else {
        let text = raw_name_list(result.findings.iter().filter_map(|finding| {
            finding_selected_for_output(finding, include_non_live, include_wildcard)
                .then_some(finding.fqdn.as_str())
        }));
        let newline = if text.is_empty() { "" } else { "\n" };
        std::fs::write(path, text + newline)?;
    }
    Ok(())
}

pub(crate) fn write_scan_results(
    path: &PathBuf,
    results: &[ScanResult],
    json_output: bool,
    jsonl: bool,
    include_non_live: bool,
    include_wildcard: bool,
) -> Result<()> {
    if results.len() == 1 && !jsonl {
        return write_scan(
            path,
            &results[0],
            json_output,
            include_non_live,
            include_wildcard,
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = if jsonl {
        results
            .iter()
            .map(|result| {
                serde_json::to_string(&scan_result_for_output(
                    result,
                    include_non_live,
                    include_wildcard,
                ))
            })
            .collect::<serde_json::Result<Vec<_>>>()?
            .join("\n")
    } else if json_output
        || path
            .extension()
            .is_some_and(|extension| extension == "json")
    {
        let output = results
            .iter()
            .map(|result| scan_result_for_output(result, include_non_live, include_wildcard))
            .collect::<Vec<_>>();
        serde_json::to_string_pretty(&output)?
    } else {
        raw_scan_list(results, include_non_live, include_wildcard)
    };
    let newline = if text.is_empty() { "" } else { "\n" };
    std::fs::write(path, text + newline)?;
    Ok(())
}

pub(crate) fn raw_name_list<'a>(names: impl IntoIterator<Item = &'a str>) -> String {
    names
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn raw_scan_list(
    results: &[ScanResult],
    include_non_live: bool,
    include_wildcard: bool,
) -> String {
    raw_name_list(
        results
            .iter()
            .flat_map(|result| result.findings.iter())
            .filter_map(|finding| {
                finding_selected_for_output(finding, include_non_live, include_wildcard)
                    .then_some(finding.fqdn.as_str())
            }),
    )
}

pub(crate) fn write_raw_scan_list(
    results: &[ScanResult],
    include_non_live: bool,
    include_wildcard: bool,
) -> Result<()> {
    let text = raw_scan_list(results, include_non_live, include_wildcard);
    if text.is_empty() {
        return Ok(());
    }
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()?;
    Ok(())
}
