use super::progress::{
    ConsoleProgress, TransientPhaseState, transient_phase_detail, transient_progress_signature,
};
use super::render::{finding_line, render_scan_findings, render_scan_summary};
use super::text::{
    NoticeKind, TerminalStyle, animation_enabled, classify_notice, format_duration, format_number,
    is_transient_phase, sanitize_terminal_text, should_render_axfr, should_render_passive_source,
    truncate_chars,
};
use fellaga_core::model::{AxfrStatus, Finding, ObservationState, ScanResult, StopReason};
use fellaga_core::model::{
    ConfidenceAssessment, CtMonitorResult, PhaseTiming, PipelineMetrics, SchedulerMetrics,
};
use fellaga_core::scanner::PassiveSourceOutcome;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

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
    assert!(is_transient_phase(
        "passif",
        "8/9 source(s), 1 active(s), sans limite cumulative"
    ));
    assert!(!is_transient_phase(
        "passif",
        "9/9 source(s), terminé en 42s"
    ));
    assert!(!is_transient_phase("wildcard", "racine normale"));
}

#[test]
fn passive_heartbeat_tracks_elapsed_time_without_changing_its_progress_signature() {
    assert_eq!(
        transient_progress_signature("lecture bornée; en cours depuis 10s; 1 restante"),
        "lecture bornée; en cours depuis <elapsed>; 1 restante"
    );
    assert_eq!(
        transient_progress_signature("lecture bornée; en cours depuis 12.5s; 1 restante"),
        "lecture bornée; en cours depuis <elapsed>; 1 restante"
    );
    assert_ne!(
        transient_progress_signature("lecture bornée; en cours depuis 85s; 1 restante"),
        transient_progress_signature("lecture bornée; en cours depuis 85s; 0 restante")
    );
    assert_eq!(
        transient_progress_signature(
            "8/9 source(s), 1 active(s), en cours depuis 10s, limite cumulative dans 20s"
        ),
        transient_progress_signature(
            "8/9 source(s), 1 active(s), en cours depuis 11s, limite cumulative dans 19s"
        )
    );
    assert_eq!(
        transient_progress_signature(
            "0/1 source(s), 1 active(s): waybackarchive (délai source 45s), en cours depuis 10s, aucune limite globale"
        ),
        transient_progress_signature(
            "0/1 source(s), 1 active(s): waybackarchive (délai source 45s), en cours depuis 11s, aucune limite globale"
        )
    );
    assert_eq!(
        transient_phase_detail(
            "8/9 source(s), 1 active(s), sans limite cumulative",
            Duration::from_secs(85)
        ),
        "8/9 source(s), 1 active(s), sans limite cumulative · écoulé 1m25s"
    );
}

#[test]
fn plain_transient_progress_logs_changes_and_throttles_identical_heartbeats() {
    let mut progress = ConsoleProgress {
        interactive: false,
        multi_target: false,
        verbosity: 0,
        line_active: false,
        active_context: None,
        last_log_bucket: BTreeMap::new(),
        last_transient_phase: BTreeMap::new(),
        stderr_style: TerminalStyle::plain(),
    };
    let started = Instant::now();
    let detail = "8/9 source(s), 1 active(s), sans limite cumulative";

    let (elapsed, log_now) =
        progress.track_transient_phase("example.com", "passif", detail, started);
    assert_eq!(elapsed, Duration::ZERO);
    assert!(log_now);

    let (_, log_now) = progress.track_transient_phase(
        "example.com",
        "passif",
        detail,
        started + Duration::from_secs(10),
    );
    assert!(!log_now);

    let (_, log_now) = progress.track_transient_phase(
        "example.com",
        "passif",
        "9/9 source(s), 0 active(s), sans limite cumulative",
        started + Duration::from_secs(11),
    );
    assert!(log_now);

    let (_, log_now) = progress.track_transient_phase(
        "example.com",
        "passif",
        "9/9 source(s), 0 active(s), sans limite cumulative",
        started + Duration::from_secs(71),
    );
    assert!(log_now);
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
    let now = Instant::now();
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
            (
                ("first.example".to_owned(), "ct".to_owned()),
                TransientPhaseState::new(now, "journal 1/2"),
            ),
            (
                ("second.example".to_owned(), "ct".to_owned()),
                TransientPhaseState::new(now, "journal 1/2"),
            ),
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
    let unsafe_text = "provider: HTTP 403 <!DOCTYPE html><html>secret</html>\x1b[31m\u{202e}spoof";
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
    let rendered = render_scan_summary(&scan, TerminalStyle::plain_with_width(48), 1).join("\n");
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

    let wildcard_only = render_scan_findings(&scan, TerminalStyle::plain(), false, true).join("\n");
    assert!(wildcard_only.contains("www.example.com"));
    assert!(!wildcard_only.contains("old.example.com"));
    assert!(wildcard_only.contains("wild.example.com"));
}
