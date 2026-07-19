use fellaga_core::model::AxfrStatus;
use fellaga_core::scanner::{PassiveSourceOutcome, ProgressEvent};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};

use super::text::{
    TerminalStyle, Tone, animation_enabled, format_duration, format_number, is_transient_phase,
    prefixed_lines, sanitize_terminal_text, should_render_axfr, should_render_passive_source,
    truncate_chars,
};

const PLAIN_TRANSIENT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub(super) struct TransientPhaseState {
    started_at: Instant,
    last_logged_at: Instant,
    progress_signature: String,
}

impl TransientPhaseState {
    pub(super) fn new(now: Instant, detail: &str) -> Self {
        Self {
            started_at: now,
            last_logged_at: now,
            progress_signature: transient_progress_signature(detail),
        }
    }
}

pub(crate) struct ConsoleProgress {
    pub(super) interactive: bool,
    pub(super) multi_target: bool,
    pub(super) verbosity: u8,
    pub(super) line_active: bool,
    pub(super) active_context: Option<String>,
    pub(super) last_log_bucket: BTreeMap<(String, String), usize>,
    pub(super) last_transient_phase: BTreeMap<(String, String), TransientPhaseState>,
    pub(super) stderr_style: TerminalStyle,
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

    pub(super) fn track_transient_phase(
        &mut self,
        context: &str,
        name: &str,
        detail: &str,
        now: Instant,
    ) -> (Duration, bool) {
        let key = (context.to_owned(), name.to_owned());
        let signature = transient_progress_signature(detail);
        let Some(state) = self.last_transient_phase.get_mut(&key) else {
            self.last_transient_phase
                .insert(key, TransientPhaseState::new(now, detail));
            return (Duration::ZERO, true);
        };

        let elapsed = now.saturating_duration_since(state.started_at);
        let progress_changed = state.progress_signature != signature;
        let heartbeat_due = now.saturating_duration_since(state.last_logged_at)
            >= PLAIN_TRANSIENT_HEARTBEAT_INTERVAL;
        let log_now = progress_changed || heartbeat_due;
        if progress_changed {
            state.progress_signature = signature;
        }
        if log_now {
            state.last_logged_at = now;
        }
        (elapsed, log_now)
    }

    fn write_transient_phase(&mut self, context: &str, name: &str, detail: &str) {
        let now = Instant::now();
        let (elapsed, log_now) = self.track_transient_phase(context, name, detail, now);
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
        let detail = transient_phase_detail(detail, elapsed);
        if self.interactive {
            let line = format!(
                "{} {context_label}{} — {}",
                self.stderr_style.badge("phase", Tone::Accent),
                self.stderr_style.paint(Tone::Bold, &name),
                truncate_chars(&detail, 108)
            );
            eprint!("\r\x1b[2K{line}");
            let _ = std::io::stderr().flush();
            self.line_active = true;
            self.active_context = Some(context.to_owned());
            return;
        }
        if !log_now {
            return;
        }
        self.write_stderr(
            Some(context),
            "phase",
            Tone::Accent,
            format!("{name} — {}", truncate_chars(&detail, 108)),
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

pub(super) fn transient_progress_signature(detail: &str) -> String {
    let mut signature = sanitize_terminal_text(detail);
    for marker in ["en cours depuis", "limite cumulative dans"] {
        signature = normalize_duration_after(&signature, marker);
    }
    signature
}

fn normalize_duration_after(detail: &str, marker: &str) -> String {
    let Some(marker_index) = detail.find(marker) else {
        return detail.to_owned();
    };
    let duration_search_start = marker_index + marker.len();
    let Some(duration_offset) =
        detail[duration_search_start..].find(|value: char| !value.is_whitespace())
    else {
        return detail.to_owned();
    };
    let duration_start = duration_search_start + duration_offset;
    if !detail[duration_start..].starts_with(|value: char| value.is_ascii_digit()) {
        return detail.to_owned();
    }
    let duration_end = detail[duration_start..]
        .find(|value: char| {
            !(value.is_ascii_digit() || matches!(value, '.' | ':' | 'h' | 'm' | 's'))
        })
        .map_or(detail.len(), |offset| duration_start + offset);

    format!(
        "{}<elapsed>{}",
        &detail[..duration_start],
        &detail[duration_end..]
    )
}

pub(super) fn transient_phase_detail(detail: &str, elapsed: Duration) -> String {
    let detail = sanitize_terminal_text(detail);
    if detail.contains("en cours depuis") {
        return detail;
    }
    let elapsed = if elapsed < Duration::from_secs(1) {
        "0s".to_owned()
    } else {
        format_duration(elapsed.as_millis())
    };
    format!("{detail} · écoulé {elapsed}")
}

impl Drop for ConsoleProgress {
    fn drop(&mut self) {
        self.clear_progress_line();
    }
}
