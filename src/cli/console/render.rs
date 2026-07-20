use fellaga_core::model::{Finding, ObservationState, ScanResult, StopReason};
use fellaga_core::output::FindingSelection;
use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};

use super::text::{
    NoticeKind, SUMMARY_WIDTH, TerminalStyle, Tone, classify_notice, format_duration,
    format_number, prefixed_lines, sanitize_terminal_text, wrap_text,
};

fn finding_state_tone(finding: &Finding) -> Tone {
    if finding.wildcard {
        Tone::Warn
    } else {
        match finding.state {
            ObservationState::Live => Tone::Good,
            ObservationState::Historical => Tone::Dim,
            ObservationState::Unverified => Tone::Warn,
        }
    }
}

pub(super) fn finding_line(finding: &Finding, style: TerminalStyle) -> String {
    let records = if finding.records.is_empty() {
        "no DNS records".to_owned()
    } else {
        finding
            .records
            .iter()
            .map(|record| format!("{}={}", record.record_type, record.value))
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let state = if finding.wildcard {
        "wildcard".to_owned()
    } else {
        finding.state.to_string()
    };
    let state_score = format!("{state}/{}", finding.confidence.score);
    let source_count = finding.sources.len();
    let provenance = match (source_count, finding.from_cache) {
        (0, true) => "cache".to_owned(),
        (0, false) => "no source".to_owned(),
        (1, true) => "1 source · cache".to_owned(),
        (1, false) => "1 source".to_owned(),
        (_, true) => format!("{source_count} sources · cache"),
        (_, false) => format!("{source_count} sources"),
    };
    let symbol = if finding.wildcard { "!" } else { "+" };
    let heading_prefix = format!("  {} ", style.paint(finding_state_tone(finding), symbol));
    let heading_continuation = "    ";
    let mut lines = prefixed_lines(
        style,
        &heading_prefix,
        heading_continuation,
        &finding.fqdn,
        Tone::Bold,
    );
    lines.extend(prefixed_lines(
        style,
        "      ",
        "      ",
        &format!("{state_score} · {provenance}"),
        finding_state_tone(finding),
    ));
    lines.extend(prefixed_lines(
        style,
        "      DNS  ",
        "           ",
        &records,
        Tone::Dim,
    ));
    lines.join("\n")
}

fn friendly_status(status: &str, resumable: bool) -> String {
    if resumable {
        "PARTIAL · resumable".to_owned()
    } else {
        match status {
            "completed" => "COMPLETED".to_owned(),
            "partial" => "PARTIAL".to_owned(),
            "interrupted" => "INTERRUPTED".to_owned(),
            "failed" => "FAILED".to_owned(),
            other => other.to_ascii_uppercase(),
        }
    }
}

fn friendly_phase_name(phase: &str) -> &str {
    match phase {
        "initial_discovery" => "discovery",
        "candidate_dns" => "DNS validation",
        "enrichment" => "enrichment",
        "finalization" => "finalization",
        other => other,
    }
}

fn friendly_stop_reason(reason: StopReason) -> &'static str {
    match reason {
        StopReason::QueueDrained => "queue drained",
        StopReason::PosteriorLowYield => "low marginal yield",
        StopReason::BudgetExhausted => "configured limit reached",
        StopReason::NetworkDegraded => "network degraded",
        StopReason::Interrupted => "interrupted",
    }
}

fn summary_row(style: TerminalStyle, label: &str, value: impl AsRef<str>) -> String {
    const PREFIX_WIDTH: usize = 16;
    let label = format!("{label:<12}");
    let wrapped = wrap_text(
        value.as_ref(),
        style.width.saturating_sub(PREFIX_WIDTH).max(1),
    );
    wrapped
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                format!("  {}  {line}", style.paint(Tone::Dim, &label))
            } else {
                format!("{}{line}", " ".repeat(PREFIX_WIDTH))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(super) fn render_scan_summary(
    result: &ScanResult,
    style: TerminalStyle,
    verbosity: u8,
) -> Vec<String> {
    let live = result
        .findings
        .iter()
        .filter(|finding| finding.state == ObservationState::Live && !finding.wildcard)
        .count();
    let historical = result
        .findings
        .iter()
        .filter(|finding| finding.state == ObservationState::Historical)
        .count();
    let unverified = result
        .findings
        .iter()
        .filter(|finding| finding.state == ObservationState::Unverified)
        .count();
    let wildcard = result
        .findings
        .iter()
        .filter(|finding| finding.wildcard)
        .count();

    let mut lines = Vec::new();
    lines.push(String::new());
    let heading_prefix = format!("Fellaga scan #{}  ", result.scan_id);
    let heading_continuation = " ".repeat(heading_prefix.chars().count());
    lines.extend(prefixed_lines(
        style,
        &heading_prefix,
        &heading_continuation,
        &result.domain,
        Tone::Accent,
    ));
    lines.push(style.paint(Tone::Dim, "─".repeat(style.width.clamp(40, SUMMARY_WIDTH))));
    lines.push(summary_row(
        style,
        "Status",
        friendly_status(&result.status, result.resumable),
    ));
    lines.push(summary_row(
        style,
        "Results",
        format!(
            "{} live · {} historical · {} unverified",
            format_number(live as u128),
            format_number(historical as u128),
            format_number(unverified as u128),
        ),
    ));
    let mut work = format!(
        "{} candidates · {} network · {} cache",
        format_number(result.candidates as u128),
        format_number(result.resolved_from_network as u128),
        format_number(result.cache_hits as u128),
    );
    if wildcard > 0 {
        work.push_str(&format!(
            " · {} wildcard-marked",
            format_number(wildcard as u128)
        ));
    } else if result.wildcard_detected {
        work.push_str(" · wildcard profile detected");
    }
    lines.push(summary_row(style, "Validation", work));
    lines.push(summary_row(
        style,
        "Runtime",
        format_duration(result.duration_ms),
    ));

    if !result.phase_timings.is_empty() {
        let phases = result
            .phase_timings
            .iter()
            .map(|timing| {
                format!(
                    "{} {}",
                    friendly_phase_name(&timing.phase),
                    format_duration(timing.duration_ms)
                )
            })
            .collect::<Vec<_>>()
            .join(" · ");
        lines.push(summary_row(style, "Phases", phases));
    }

    let mut traffic = Vec::new();
    if result.scheduler_metrics.dns_queries > 0 {
        traffic.push(format!(
            "{} DNS",
            format_number(result.scheduler_metrics.dns_queries as u128)
        ));
    }
    if result.scheduler_metrics.http_requests > 0 {
        traffic.push(format!(
            "{} HTTP",
            format_number(result.scheduler_metrics.http_requests as u128)
        ));
    }
    if result.scheduler_metrics.tcp_connections > 0 {
        traffic.push(format!(
            "{} TCP",
            format_number(result.scheduler_metrics.tcp_connections as u128)
        ));
    }
    if result.scheduler_metrics.tls_connections > 0 {
        traffic.push(format!(
            "{} TLS",
            format_number(result.scheduler_metrics.tls_connections as u128)
        ));
    }
    if result.scheduler_metrics.backoffs > 0 {
        traffic.push(format!(
            "{} backoffs",
            format_number(result.scheduler_metrics.backoffs as u128)
        ));
    }
    if !traffic.is_empty() {
        lines.push(summary_row(style, "Traffic", traffic.join(" · ")));
    }

    let mut coverage = Vec::new();
    if result.ct_monitor.entries_processed > 0 {
        coverage.push(format!(
            "CT {} entries",
            format_number(result.ct_monitor.entries_processed as u128)
        ));
    }
    if !result.tls_certificates.is_empty() {
        coverage.push(format!(
            "TLS {} certs",
            format_number(result.tls_certificates.len() as u128)
        ));
    }
    if !result.web_observations.is_empty() {
        coverage.push(format!(
            "Web {} resources",
            format_number(result.web_observations.len() as u128)
        ));
    }
    if !result.dns_edges.is_empty() {
        coverage.push(format!(
            "DNS graph {} edges",
            format_number(result.dns_edges.len() as u128)
        ));
    }
    let nsec_names = result
        .dnssec_walks
        .iter()
        .flat_map(|walk| walk.names.iter())
        .collect::<BTreeSet<_>>()
        .len();
    if nsec_names > 0 {
        coverage.push(format!("NSEC {} names", format_number(nsec_names as u128)));
    }
    if !coverage.is_empty() {
        lines.push(summary_row(style, "Coverage", coverage.join(" · ")));
    }

    if let Some(reason) = result.scheduler_metrics.stop_reason {
        // This reason belongs to the active candidate scheduler, not to every
        // discovery phase. Calling it the scan stop reason is misleading when
        // an explicitly bounded passive source finishes partial while the
        // candidate queue itself is empty.
        lines.push(summary_row(
            style,
            "Scheduler",
            friendly_stop_reason(reason),
        ));
    }

    if !result.warnings.is_empty() {
        let unique = result
            .warnings
            .iter()
            .map(|warning| sanitize_terminal_text(warning))
            .filter(|warning| !warning.is_empty())
            .collect::<BTreeSet<_>>();
        let limits = unique
            .iter()
            .filter(|warning| classify_notice(warning) == NoticeKind::Limit)
            .count();
        let sources = unique
            .iter()
            .filter(|warning| classify_notice(warning) == NoticeKind::Source)
            .count();
        let warnings = unique.len().saturating_sub(limits + sources);
        let mut counts = Vec::new();
        if limits > 0 {
            counts.push(format!("{limits} limits"));
        }
        if sources > 0 {
            counts.push(format!("{sources} sources"));
        }
        if warnings > 0 {
            counts.push(format!("{warnings} warnings"));
        }
        let mut notice_summary = counts.join(" · ");
        if verbosity == 0 {
            notice_summary.push_str(" · use -v for details");
        }
        lines.push(summary_row(style, "Notices", notice_summary));
        if verbosity > 0 {
            for warning in unique {
                let kind = classify_notice(&warning);
                let prefix = format!("    {} ", style.badge(kind.label(), kind.tone()));
                let continuation = " ".repeat(5 + kind.label().chars().count());
                lines.extend(prefixed_lines(
                    style,
                    &prefix,
                    &continuation,
                    &warning,
                    kind.tone(),
                ));
            }
        }
    }

    if result.resumable {
        lines.push(summary_row(
            style,
            "Resume",
            format!("fellaga scan {} --resume latest", result.domain),
        ));
    }
    lines
}

pub(super) fn render_scan_findings(
    result: &ScanResult,
    style: TerminalStyle,
    include_non_live: bool,
    include_wildcard: bool,
) -> Vec<String> {
    let selection = FindingSelection::new(include_non_live, include_wildcard);
    result
        .findings
        .iter()
        .filter(|finding| selection.includes(finding))
        .map(|finding| finding_line(finding, style))
        .collect()
}

/// Print only finalized findings. The caller must not use this in JSON, JSONL,
/// or raw-output modes; those formats own stdout completely.
pub(crate) fn print_scan_findings(
    result: &ScanResult,
    include_non_live: bool,
    include_wildcard: bool,
) {
    let style = TerminalStyle::auto(std::io::stdout().is_terminal());
    let findings = render_scan_findings(result, style, include_non_live, include_wildcard);
    if findings.is_empty() {
        return;
    }
    println!();
    println!("{}", style.paint(Tone::Bold, "Final results"));
    println!(
        "{}",
        style.paint(Tone::Dim, "─".repeat(style.width.clamp(40, SUMMARY_WIDTH)))
    );
    for finding in findings {
        println!("{finding}");
    }
    let _ = std::io::stdout().flush();
}

pub(crate) fn print_scan_summary(result: &ScanResult, verbosity: u8) {
    let style = TerminalStyle::auto(std::io::stdout().is_terminal());
    for line in render_scan_summary(result, style, verbosity) {
        println!("{line}");
    }
}
