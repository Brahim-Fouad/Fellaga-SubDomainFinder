use fellaga_core::model::{AxfrStatus, Finding, ObservationState, ScanResult, StopReason};
use fellaga_core::scanner::{PassiveSourceOutcome, ProgressEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};

const SUMMARY_WIDTH: usize = 72;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone {
    Accent,
    Good,
    Warn,
    Bad,
    Dim,
    Bold,
}

#[derive(Debug, Clone, Copy)]
struct TerminalStyle {
    color: bool,
    width: usize,
}

impl TerminalStyle {
    fn auto(terminal: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some();
        let dumb_terminal = std::env::var_os("TERM").is_some_and(|value| value == "dumb");
        Self {
            color: terminal && !no_color && !dumb_terminal,
            width: std::env::var("COLUMNS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .map(|value| value.clamp(40, 200))
                .unwrap_or(120),
        }
    }

    #[cfg(test)]
    const fn plain() -> Self {
        Self {
            color: false,
            width: 120,
        }
    }

    #[cfg(test)]
    const fn plain_with_width(width: usize) -> Self {
        Self {
            color: false,
            width,
        }
    }

    fn paint(self, tone: Tone, text: impl AsRef<str>) -> String {
        let text = text.as_ref();
        if !self.color {
            return text.to_owned();
        }
        let code = match tone {
            Tone::Accent => "36",
            Tone::Good => "32",
            Tone::Warn => "33",
            Tone::Bad => "31",
            Tone::Dim => "2",
            Tone::Bold => "1",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }

    fn badge(self, label: &str, tone: Tone) -> String {
        self.paint(tone, format!("[{label}]"))
    }
}

fn animation_enabled(terminal: bool, term: Option<&std::ffi::OsStr>) -> bool {
    terminal && term.is_none_or(|value| value != "dumb")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoticeKind {
    Limit,
    Source,
    Warning,
}

impl NoticeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Source => "source",
            Self::Warning => "warning",
        }
    }

    const fn tone(self) -> Tone {
        match self {
            Self::Limit => Tone::Warn,
            Self::Source => Tone::Warn,
            Self::Warning => Tone::Bad,
        }
    }
}

fn classify_notice(message: &str) -> NoticeKind {
    let normalized = message.to_ascii_lowercase();
    if ((normalized.contains("budget")
        || normalized.contains("limite cumulative")
        || normalized.contains("limite --max-")
        || normalized.contains("configured limit"))
        && (normalized.contains("atteint")
            || normalized.contains("atteinte")
            || normalized.contains("dépassé")
            || normalized.contains("restant")
            || normalized.contains("reached")))
        || normalized.contains("travail dns borné")
        || normalized.contains("conservé pour --resume")
        || normalized.contains("source(s) lente(s) annulée(s)")
    {
        NoticeKind::Limit
    } else if normalized.contains("quota")
        || normalized.contains("api count exceeded")
        || normalized.contains("rate limit")
        || normalized.contains("rate-limit")
        || normalized.contains("http 429")
        || normalized.contains("anti-bot")
        || normalized.contains("auth required")
        || normalized.contains("source externe différée")
    {
        NoticeKind::Source
    } else {
        NoticeKind::Warning
    }
}

fn should_render_passive_source(outcome: PassiveSourceOutcome, verbosity: u8) -> bool {
    match verbosity {
        0 => false,
        1 => matches!(
            outcome,
            PassiveSourceOutcome::Partial
                | PassiveSourceOutcome::Stale
                | PassiveSourceOutcome::Deferred
                | PassiveSourceOutcome::Skipped
        ),
        _ => true,
    }
}

fn should_render_axfr(status: AxfrStatus, verbosity: u8) -> bool {
    status == AxfrStatus::Success || verbosity > 0
}

fn is_transient_phase(name: &str, detail: &str) -> bool {
    name == "CT incrémental"
        || detail.contains("en cours depuis")
        || detail.contains("budget restant")
        || (name == "passif récursif" && detail.starts_with("zone "))
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let sanitized = sanitize_terminal_text(value);
    if sanitized.chars().count() <= max_chars {
        return sanitized;
    }
    if max_chars <= 1 {
        return "…".chars().take(max_chars).collect();
    }
    let mut output = sanitized.chars().take(max_chars - 1).collect::<String>();
    output.push('…');
    output
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn strip_terminal_escape_sequences(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' {
            match characters.next() {
                Some('[') => {
                    for control in characters.by_ref() {
                        if ('@'..='~').contains(&control) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let mut previous_escape = false;
                    for control in characters.by_ref() {
                        if control == '\u{7}' || (previous_escape && control == '\\') {
                            break;
                        }
                        previous_escape = control == '\u{1b}';
                    }
                }
                Some(_) | None => {}
            }
            continue;
        }
        if character == '\u{009b}' {
            for control in characters.by_ref() {
                if ('@'..='~').contains(&control) {
                    break;
                }
            }
            continue;
        }
        safe.push(character);
    }
    safe
}

/// Make untrusted network text safe to render in a terminal.
///
/// Provider errors occasionally contain an entire anti-bot page. Keeping the
/// HTTP context is useful, but printing markup is noisy and can include
/// terminal control characters. Preserve the prefix and replace the document
/// itself with a stable marker.
pub(crate) fn sanitize_terminal_text(value: &str) -> String {
    let value = strip_terminal_escape_sequences(value);
    let lowercase = value.to_ascii_lowercase();
    let html_start = ["<!doctype", "<html", "<head", "<body", "<script", "<title"]
        .into_iter()
        .filter_map(|marker| lowercase.find(marker))
        .min();

    let mut safe = match html_start {
        Some(index) => {
            let mut prefix = value[..index].trim_end().to_owned();
            if !prefix.is_empty() {
                prefix.push(' ');
            }
            prefix.push_str("[HTML response omitted]");
            prefix
        }
        None => value,
    };

    safe = safe
        .chars()
        .map(|character| {
            if character.is_control() || is_bidi_control(character) {
                ' '
            } else {
                character
            }
        })
        .collect();

    safe.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Wrap terminal content without losing characters. Long tokens (FQDNs,
/// hashes, TXT values) are hard-wrapped instead of ellipsized.
fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let sanitized = sanitize_terminal_text(value);
    let width = width.max(1);
    if sanitized.is_empty() {
        return vec![String::new()];
    }

    let mut lines = Vec::new();
    let mut current = String::new();
    for word in sanitized.split_whitespace() {
        let word_len = word.chars().count();
        if word_len > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let characters = word.chars().collect::<Vec<_>>();
            for chunk in characters.chunks(width) {
                lines.push(chunk.iter().collect());
            }
            continue;
        }

        let separator = usize::from(!current.is_empty());
        if current.chars().count() + separator + word_len > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn prefixed_lines(
    style: TerminalStyle,
    first_prefix: &str,
    continuation_prefix: &str,
    text: &str,
    tone: Tone,
) -> Vec<String> {
    let first_width = style
        .width
        .saturating_sub(first_prefix.chars().count())
        .max(1);
    let continuation_width = style
        .width
        .saturating_sub(continuation_prefix.chars().count())
        .max(1);
    let mut output = Vec::new();
    let mut pending = wrap_text(text, first_width).into_iter();
    if let Some(first) = pending.next() {
        output.push(format!("{first_prefix}{}", style.paint(tone, first)));
    }
    for line in pending {
        // A line wrapped for the first prefix may still be wider than the
        // continuation area. Re-wrap it without dropping any content.
        for continuation in wrap_text(&line, continuation_width) {
            output.push(format!(
                "{continuation_prefix}{}",
                style.paint(tone, continuation)
            ));
        }
    }
    output
}

fn format_number(value: impl Into<u128>) -> String {
    let digits = value.into().to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

fn format_duration(duration_ms: u128) -> String {
    if duration_ms < 1_000 {
        return format!("{duration_ms}ms");
    }
    let seconds = duration_ms / 1_000;
    if seconds < 60 {
        return format!("{:.1}s", duration_ms as f64 / 1_000.0);
    }
    if seconds < 3_600 {
        return format!("{}m{:02}s", seconds / 60, seconds % 60);
    }
    format!(
        "{}h{:02}m{:02}s",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

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

fn finding_line(finding: &Finding, style: TerminalStyle) -> String {
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

fn render_scan_summary(result: &ScanResult, style: TerminalStyle, verbosity: u8) -> Vec<String> {
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
        lines.push(summary_row(style, "Stopped", friendly_stop_reason(reason)));
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

pub(crate) struct ConsoleProgress {
    interactive: bool,
    multi_target: bool,
    verbosity: u8,
    line_active: bool,
    active_context: Option<String>,
    last_log_bucket: BTreeMap<(String, String), usize>,
    last_transient_phase: BTreeMap<(String, String), usize>,
    stderr_style: TerminalStyle,
}

impl ConsoleProgress {
    pub(crate) fn new(
        _json_output: bool,
        _raw_output: bool,
        multi_target: bool,
        verbosity: u8,
    ) -> Self {
        let stderr_terminal = std::io::stderr().is_terminal();
        Self {
            interactive: animation_enabled(stderr_terminal, std::env::var_os("TERM").as_deref()),
            multi_target,
            verbosity,
            line_active: false,
            active_context: None,
            last_log_bucket: BTreeMap::new(),
            last_transient_phase: BTreeMap::new(),
            stderr_style: TerminalStyle::auto(stderr_terminal),
        }
    }

    fn clear_progress_line(&mut self) {
        if self.interactive && self.line_active {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
        self.line_active = false;
        self.active_context = None;
    }

    pub(crate) fn finish_target(&mut self, context: &str) {
        if self.active_context.as_deref() == Some(context) {
            self.clear_progress_line();
        }
        self.last_log_bucket
            .retain(|(target, _), _| target != context);
        self.last_transient_phase
            .retain(|(target, _), _| target != context);
    }

    pub(crate) fn finish(&mut self) {
        self.clear_progress_line();
        self.last_log_bucket.clear();
        self.last_transient_phase.clear();
    }

    fn write_stderr(
        &mut self,
        context: Option<&str>,
        badge: &str,
        tone: Tone,
        detail: impl AsRef<str>,
    ) {
        self.clear_progress_line();
        let context = context
            .filter(|_| self.multi_target)
            .map(|target| format!("{} · ", sanitize_terminal_text(target)))
            .unwrap_or_default();
        let detail = format!("{context}{}", detail.as_ref());
        let prefix = format!("{} ", self.stderr_style.badge(badge, tone));
        let continuation = " ".repeat(badge.chars().count() + 3);
        for line in prefixed_lines(self.stderr_style, &prefix, &continuation, &detail, tone) {
            eprintln!("{line}");
        }
    }

    fn write_transient_phase(&mut self, context: &str, name: &str, detail: &str) {
        let context_label = if self.multi_target {
            format!(
                "{} · ",
                self.stderr_style
                    .paint(Tone::Accent, truncate_chars(context, 32))
            )
        } else {
            String::new()
        };
        let name = truncate_chars(name, 32);
        if self.interactive {
            let line = format!(
                "{} {context_label}{} — {}",
                self.stderr_style.badge("phase", Tone::Accent),
                self.stderr_style.paint(Tone::Bold, &name),
                truncate_chars(detail, 108)
            );
            eprint!("\r\x1b[2K{line}");
            let _ = std::io::stderr().flush();
            self.line_active = true;
            self.active_context = Some(context.to_owned());
            return;
        }
        let count = self
            .last_transient_phase
            .entry((context.to_owned(), name.clone()))
            .or_default();
        *count += 1;
        let log_now = *count == 1 || (*count).is_multiple_of(3);
        if !log_now {
            return;
        }
        self.write_stderr(
            Some(context),
            "phase",
            Tone::Accent,
            format!("{name} — {}", truncate_chars(detail, 108)),
        );
    }

    pub(crate) fn handle(&mut self, context: &str, event: ProgressEvent) {
        match event {
            ProgressEvent::Started { scan_id, domain } => {
                self.last_transient_phase
                    .retain(|(target, _), _| target != context);
                self.write_stderr(
                    None,
                    "scan",
                    Tone::Accent,
                    format!("{}  #{scan_id}", sanitize_terminal_text(&domain)),
                );
            }
            ProgressEvent::Phase { name, detail } => {
                self.last_log_bucket
                    .retain(|(target, _), _| target != context);
                if is_transient_phase(&name, &detail) {
                    self.write_transient_phase(context, &name, &detail);
                } else {
                    self.last_transient_phase
                        .retain(|(target, _), _| target != context);
                    self.write_stderr(
                        Some(context),
                        "phase",
                        Tone::Accent,
                        format!("{} — {}", sanitize_terminal_text(&name), detail),
                    );
                }
            }
            ProgressEvent::PassiveSource {
                source,
                outcome,
                status,
                names,
            } => {
                if !should_render_passive_source(outcome, self.verbosity) {
                    return;
                }
                let (badge, tone) = match outcome {
                    PassiveSourceOutcome::Success => ("source", Tone::Good),
                    PassiveSourceOutcome::Cached => ("cache", Tone::Accent),
                    PassiveSourceOutcome::Partial | PassiveSourceOutcome::Stale => {
                        ("partial", Tone::Warn)
                    }
                    PassiveSourceOutcome::Deferred | PassiveSourceOutcome::Skipped => {
                        ("skip", Tone::Dim)
                    }
                };
                self.write_stderr(
                    Some(context),
                    badge,
                    tone,
                    format!(
                        "{}  {} names · {}",
                        source,
                        format_number(names as u128),
                        status
                    ),
                );
            }
            ProgressEvent::AxfrAttempt(attempt) => {
                if !should_render_axfr(attempt.status, self.verbosity) {
                    return;
                }
                let (badge, tone, detail) = match attempt.status {
                    AxfrStatus::Success => (
                        "axfr",
                        Tone::Good,
                        format!(
                            "{} ({}) · {} records · {} names",
                            attempt.nameserver,
                            attempt.address,
                            format_number(attempt.records.len() as u128),
                            format_number(attempt.names.len() as u128)
                        ),
                    ),
                    AxfrStatus::Refused => (
                        "axfr",
                        Tone::Dim,
                        format!("{} ({}) · refused", attempt.nameserver, attempt.address),
                    ),
                    AxfrStatus::Empty => (
                        "axfr",
                        Tone::Dim,
                        format!("{} ({}) · empty", attempt.nameserver, attempt.address),
                    ),
                    AxfrStatus::Timeout => (
                        "axfr",
                        Tone::Warn,
                        format!("{} ({}) · timeout", attempt.nameserver, attempt.address),
                    ),
                    AxfrStatus::ProtocolError => (
                        "axfr",
                        Tone::Bad,
                        format!(
                            "{} ({}) · {}",
                            attempt.nameserver,
                            attempt.address,
                            attempt.error.as_deref().unwrap_or("protocol error")
                        ),
                    ),
                };
                self.write_stderr(Some(context), badge, tone, detail);
            }
            ProgressEvent::TlsCertificates {
                endpoints,
                network,
                successes,
                failures,
                cache_hits,
                names,
                duration_ms,
            } => self.write_stderr(
                Some(context),
                "tls",
                if successes > 0 { Tone::Good } else { Tone::Warn },
                format!(
                    "{successes}/{endpoints} successful · {failures} failed · {network} network · {cache_hits} cache · {names} names · {}",
                    format_duration(duration_ms)
                ),
            ),
            ProgressEvent::DnsGraph {
                queries,
                edges,
                names,
                child_zones,
                services,
                duration_ms,
            } => self.write_stderr(
                Some(context),
                "dns+",
                Tone::Good,
                format!(
                    "{} queries · {edges} edges · {names} names · {child_zones} child zones · {services} services · {}",
                    format_number(queries as u128),
                    format_duration(duration_ms)
                ),
            ),
            ProgressEvent::WebDiscovery {
                hosts,
                requests,
                cache_hits,
                failures,
                names,
                duration_ms,
            } => self.write_stderr(
                Some(context),
                "web",
                if failures > 0 { Tone::Warn } else { Tone::Good },
                format!(
                    "{hosts} hosts · {requests} requests · {cache_hits} cache · {failures} failed · {names} names · {}",
                    format_duration(duration_ms)
                ),
            ),
            ProgressEvent::Dnssec {
                zones,
                walked,
                protected,
                queries,
                names,
            } => self.write_stderr(
                Some(context),
                "nsec",
                Tone::Good,
                format!(
                    "{zones} zones · {walked} walked · {protected} protected · {queries} queries · {names} names"
                ),
            ),
            ProgressEvent::CtMonitor {
                logs,
                entries,
                failures,
                names,
                duration_ms,
            } => self.write_stderr(
                Some(context),
                "ct",
                if failures > 0 { Tone::Warn } else { Tone::Good },
                format!(
                    "{logs} logs · {} entries · {names} names · {failures} failed · {}",
                    format_number(entries as u128),
                    format_duration(duration_ms)
                ),
            ),
            ProgressEvent::DnsProgress {
                phase,
                processed,
                total,
                found,
                cache_hits,
                rate,
                elapsed_ms,
            } => {
                let percent = processed
                    .saturating_mul(100)
                    .checked_div(total)
                    .unwrap_or_else(|| usize::from(processed > 0) * 100)
                    .min(100);
                if !self.interactive {
                    let bucket = percent / 20;
                    let key = (context.to_owned(), phase.clone());
                    let already_logged = self.last_log_bucket.get(&key) == Some(&bucket);
                    if already_logged && processed != total {
                        return;
                    }
                    self.last_log_bucket.insert(key, bucket);
                }
                let filled = percent * 16 / 100;
                let bar = format!("{}{}", "█".repeat(filled), "░".repeat(16 - filled));
                let cache = if cache_hits > 0 {
                    format!(" · {cache_hits} cache")
                } else {
                    String::new()
                };
                let rate = if rate.is_finite() && rate >= 0.0 {
                    format!("{rate:.0} q/s")
                } else {
                    "rate unavailable".to_owned()
                };
                let phase = truncate_chars(&phase, 24);
                let context_label = if self.multi_target {
                    format!(
                        "{} · ",
                        self.stderr_style
                            .paint(Tone::Accent, truncate_chars(context, 24))
                    )
                } else {
                    String::new()
                };
                let line = if self.interactive {
                    format!(
                        "{} {context_label}{phase:<24} [{bar}] {percent:>3}% {}/{} · +{} live{cache} · {rate} · {}",
                        self.stderr_style.badge("dns", Tone::Accent),
                        format_number(processed as u128),
                        format_number(total as u128),
                        format_number(found as u128),
                        format_duration(elapsed_ms)
                    )
                } else {
                    format!(
                        "{} {context_label}{phase} · {percent}% · {}/{} · +{} live{cache} · {rate} · {}",
                        self.stderr_style.badge("dns", Tone::Accent),
                        format_number(processed as u128),
                        format_number(total as u128),
                        format_number(found as u128),
                        format_duration(elapsed_ms)
                    )
                };
                if self.interactive {
                    eprint!("\r\x1b[2K{line}");
                    let _ = std::io::stderr().flush();
                    self.line_active = true;
                    self.active_context = Some(context.to_owned());
                } else {
                    eprintln!("{line}");
                }
            }
            // Findings emitted during discovery are provisional. The final
            // wildcard and authoritative checks run later, so only the final
            // ScanResult is rendered by `print_scan_findings`.
            ProgressEvent::Finding(_) => {}
            // Scan warnings are intentionally delivered once, in the final
            // deduplicated summary. Rendering them here as well made `-v`
            // repeat every warning without adding information.
            ProgressEvent::Warning(_) => {}
            ProgressEvent::Complete => self.finish_target(context),
        }
    }
}

impl Drop for ConsoleProgress {
    fn drop(&mut self) {
        self.clear_progress_line();
    }
}

fn render_scan_findings(
    result: &ScanResult,
    style: TerminalStyle,
    include_non_live: bool,
    include_wildcard: bool,
) -> Vec<String> {
    result
        .findings
        .iter()
        .filter(|finding| {
            if finding.wildcard {
                include_wildcard
            } else {
                include_non_live || finding.state == ObservationState::Live
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use fellaga_core::model::{
        ConfidenceAssessment, CtMonitorResult, PhaseTiming, PipelineMetrics, SchedulerMetrics,
    };

    fn finding(fqdn: &str, state: ObservationState, wildcard: bool) -> Finding {
        Finding {
            fqdn: fqdn.to_owned(),
            state,
            wildcard,
            confidence: ConfidenceAssessment {
                score: if state == ObservationState::Live {
                    100
                } else {
                    25
                },
                label: if state == ObservationState::Live {
                    "confirmed".to_owned()
                } else {
                    "low".to_owned()
                },
                reasons: Vec::new(),
            },
            ..Finding::default()
        }
    }

    fn result() -> ScanResult {
        ScanResult {
            scan_id: 7,
            domain: "example.com".to_owned(),
            status: "partial".to_owned(),
            resumable: true,
            candidates: 1_234,
            resolved_from_network: 1,
            cache_hits: 2,
            duration_ms: 125_400,
            phase_timings: vec![PhaseTiming {
                phase: "candidate_dns".to_owned(),
                duration_ms: 61_000,
            }],
            wildcard_detected: true,
            findings: vec![
                finding("www.example.com", ObservationState::Live, false),
                finding("old.example.com", ObservationState::Historical, false),
                finding("wild.example.com", ObservationState::Unverified, true),
            ],
            axfr_attempts: Vec::new(),
            tls_certificates: Vec::new(),
            dns_edges: Vec::new(),
            child_zones: BTreeSet::new(),
            service_endpoints: Vec::new(),
            web_observations: Vec::new(),
            dnssec_walks: Vec::new(),
            ct_monitor: CtMonitorResult::default(),
            pipeline: PipelineMetrics::default(),
            resolver_metrics: Vec::new(),
            scheduler_metrics: SchedulerMetrics {
                dns_queries: 1_587,
                stop_reason: Some(StopReason::BudgetExhausted),
                ..SchedulerMetrics::default()
            },
            warnings: vec![
                "budget DNS actif atteint".to_owned(),
                "HackerTarget: API count exceeded".to_owned(),
                "connexion impossible".to_owned(),
            ],
        }
    }

    #[test]
    fn summaries_distinguish_live_historical_unverified_and_resume_work() {
        let output = render_scan_summary(&result(), TerminalStyle::plain(), 0).join("\n");
        assert!(output.contains("PARTIAL · resumable"));
        assert!(output.contains("1 live · 1 historical · 1 unverified"));
        assert!(output.contains("1,234 candidates · 1 network · 2 cache"));
        assert!(output.contains("1 wildcard-marked"));
        assert!(output.contains("1,587 DNS"));
        assert!(output.contains("fellaga scan example.com --resume latest"));
        assert!(output.contains("1 limits · 1 sources · 1 warnings"));
        assert!(output.contains("use -v for details"));
        assert!(!output.contains("API count exceeded"));
    }

    #[test]
    fn notices_separate_limits_provider_conditions_and_real_warnings() {
        assert_eq!(
            classify_notice("budget Web atteint; résultats conservés"),
            NoticeKind::Limit
        );
        assert_eq!(
            classify_notice("limite cumulative DNS active atteinte"),
            NoticeKind::Limit
        );
        assert_eq!(
            classify_notice("HackerTarget API count exceeded"),
            NoticeKind::Source
        );
        assert_eq!(
            classify_notice("connexion Common Crawl impossible"),
            NoticeKind::Warning
        );
    }

    #[test]
    fn repeated_long_running_phases_are_recognized_as_transient() {
        assert!(is_transient_phase(
            "graphe DNS",
            "interrogation; en cours depuis 10s"
        ));
        assert!(is_transient_phase(
            "passif récursif",
            "zone api.example.com (fille)"
        ));
        assert!(is_transient_phase("CT incrémental", "journal 1/2, lot 4"));
        assert!(!is_transient_phase("wildcard", "racine normale"));
    }

    #[test]
    fn plain_rendering_never_emits_ansi_sequences() {
        let output = render_scan_summary(&result(), TerminalStyle::plain(), 1).join("\n");
        assert!(!output.contains("\x1b["));
        assert!(
            !finding_line(
                &finding("www.example.com", ObservationState::Live, false),
                TerminalStyle::plain()
            )
            .contains("\x1b[")
        );
    }

    #[test]
    fn dumb_term_disables_animation_even_for_a_tty() {
        assert!(!animation_enabled(true, Some(std::ffi::OsStr::new("dumb"))));
        assert!(animation_enabled(
            true,
            Some(std::ffi::OsStr::new("xterm-256color"))
        ));
        assert!(!animation_enabled(false, None));
    }

    #[test]
    fn completing_one_target_keeps_another_targets_active_line() {
        let mut progress = ConsoleProgress {
            interactive: false,
            multi_target: true,
            verbosity: 0,
            line_active: true,
            active_context: Some("second.example".to_owned()),
            last_log_bucket: BTreeMap::from([
                (("first.example".to_owned(), "dns".to_owned()), 2),
                (("second.example".to_owned(), "dns".to_owned()), 3),
            ]),
            last_transient_phase: BTreeMap::from([
                (("first.example".to_owned(), "ct".to_owned()), 1),
                (("second.example".to_owned(), "ct".to_owned()), 1),
            ]),
            stderr_style: TerminalStyle::plain(),
        };

        progress.finish_target("first.example");

        assert!(progress.line_active);
        assert_eq!(progress.active_context.as_deref(), Some("second.example"));
        assert!(
            progress
                .last_log_bucket
                .keys()
                .all(|(target, _)| target == "second.example")
        );
        assert!(
            progress
                .last_transient_phase
                .keys()
                .all(|(target, _)| target == "second.example")
        );
    }

    #[test]
    fn formatting_is_compact_and_human_readable() {
        assert_eq!(format_number(1_587_u128), "1,587");
        assert_eq!(format_duration(999), "999ms");
        assert_eq!(format_duration(1_500), "1.5s");
        assert_eq!(format_duration(125_400), "2m05s");
        assert_eq!(truncate_chars("abcdefgh", 5), "abcd…");
        assert_eq!(truncate_chars("safe\x1b[31m\r\n", 32), "safe");
    }

    #[test]
    fn findings_adapt_to_narrow_terminals_without_unbounded_lines() {
        let mut long = finding(
            "a-very-long-service-name-for-a-narrow-terminal.example.com",
            ObservationState::Live,
            false,
        );
        long.records.push(fellaga_core::model::DnsRecord {
            record_type: "TXT".to_owned(),
            value: "z".repeat(200),
            ttl: 60,
        });
        for width in [40, 60, 80, 120] {
            let rendered = finding_line(&long, TerminalStyle::plain_with_width(width));
            assert!(
                rendered.lines().all(|line| line.chars().count() <= width),
                "line exceeded width {width}: {rendered:?}"
            );
            assert!(!rendered.contains('…'));
            assert_eq!(rendered.matches('z').count(), 200);
        }
    }

    #[test]
    fn verbosity_keeps_default_quiet_and_exposes_diagnostics_on_demand() {
        assert!(!should_render_passive_source(
            PassiveSourceOutcome::Partial,
            0
        ));
        assert!(should_render_passive_source(
            PassiveSourceOutcome::Partial,
            1
        ));
        assert!(!should_render_passive_source(
            PassiveSourceOutcome::Success,
            1
        ));
        assert!(should_render_passive_source(
            PassiveSourceOutcome::Success,
            2
        ));
        assert!(should_render_axfr(AxfrStatus::Success, 0));
        assert!(!should_render_axfr(AxfrStatus::Refused, 0));
        assert!(should_render_axfr(AxfrStatus::Refused, 1));
    }

    #[test]
    fn terminal_sanitizer_suppresses_html_controls_and_bidi() {
        let unsafe_text =
            "provider: HTTP 403 <!DOCTYPE html><html>secret</html>\x1b[31m\u{202e}spoof";
        let rendered = sanitize_terminal_text(unsafe_text);
        assert_eq!(rendered, "provider: HTTP 403 [HTML response omitted]");
        assert!(!rendered.contains("DOCTYPE"));
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\u{202e}'));
    }

    #[test]
    fn verbose_summary_deduplicates_and_wraps_complete_notices() {
        let mut scan = result();
        let long = format!("provider failed: {}", "detail ".repeat(40));
        scan.warnings = vec![
            long.clone(),
            long,
            "HTTP 403 <html>secret</html>".to_owned(),
        ];
        let rendered =
            render_scan_summary(&scan, TerminalStyle::plain_with_width(48), 1).join("\n");
        assert_eq!(rendered.matches("provider failed:").count(), 1);
        assert!(rendered.contains("[HTML response omitted]"));
        assert!(!rendered.contains("<html>"));
        assert!(!rendered.contains('…'));
        assert!(rendered.lines().all(|line| line.chars().count() <= 48));
    }

    #[test]
    fn finalized_findings_default_to_live_non_wildcard_results() {
        let scan = result();
        let defaults = render_scan_findings(&scan, TerminalStyle::plain(), false, false).join("\n");
        assert!(defaults.contains("www.example.com"));
        assert!(!defaults.contains("old.example.com"));
        assert!(!defaults.contains("wild.example.com"));

        let complete = render_scan_findings(&scan, TerminalStyle::plain(), true, true).join("\n");
        assert!(complete.contains("www.example.com"));
        assert!(complete.contains("old.example.com"));
        assert!(complete.contains("wild.example.com"));

        let wildcard_only =
            render_scan_findings(&scan, TerminalStyle::plain(), false, true).join("\n");
        assert!(wildcard_only.contains("www.example.com"));
        assert!(!wildcard_only.contains("old.example.com"));
        assert!(wildcard_only.contains("wild.example.com"));
    }
}
