use std::time::Duration;

use crate::cli::commands::scan::{
    MAX_DOMAIN_CONCURRENCY, MAX_TLS_CONCURRENCY, MAX_WEB_CONCURRENCY, validate_scan_concurrency,
};
use crate::cli::runtime::{
    bounded_duration_hours, bounded_duration_seconds, compact_error, positive_duration_seconds,
};

#[test]
fn floating_point_timeouts_are_converted_without_panicking() {
    assert_eq!(
        positive_duration_seconds(0.25, "--timeout").unwrap(),
        Duration::from_millis(250)
    );
    for invalid in [
        0.0,
        -1.0,
        f64::NAN,
        f64::INFINITY,
        f64::MIN_POSITIVE,
        1.0e18,
        f64::MAX,
    ] {
        assert!(
            positive_duration_seconds(invalid, "--timeout").is_err(),
            "unexpectedly accepted {invalid:?}"
        );
    }
    assert_eq!(
        bounded_duration_hours(2, "--refresh-hours").unwrap(),
        Duration::from_secs(7_200)
    );
    assert_eq!(
        bounded_duration_seconds(0, "--max-runtime").unwrap(),
        Duration::ZERO
    );
    assert!(bounded_duration_seconds(u64::MAX, "--max-runtime").is_err());
    assert!(bounded_duration_hours(u64::MAX, "--refresh-hours").is_err());
}

#[test]
fn permanent_cli_errors_are_sanitized_without_truncation() {
    let payload = "x".repeat(512);
    let rendered = compact_error(&format!("provider failure: {payload}\x1b[31m\u{202e}spoof"));
    assert!(rendered.contains(&payload));
    assert!(!rendered.contains('…'));
    assert!(!rendered.contains('\x1b'));
    assert!(!rendered.contains('\u{202e}'));
    assert_eq!(
        compact_error("provider HTTP 403 <html>secret</html>"),
        "provider HTTP 403 [HTML response omitted]"
    );
}

#[test]
fn scan_concurrency_caps_bound_cross_target_network_fanout() {
    assert!(validate_scan_concurrency(1, 8, 16).is_ok());
    assert!(
        validate_scan_concurrency(
            MAX_DOMAIN_CONCURRENCY,
            MAX_WEB_CONCURRENCY,
            MAX_TLS_CONCURRENCY
        )
        .is_ok()
    );
    assert!(validate_scan_concurrency(0, 8, 16).is_err());
    assert!(validate_scan_concurrency(MAX_DOMAIN_CONCURRENCY + 1, 8, 16).is_err());
    assert!(validate_scan_concurrency(1, MAX_WEB_CONCURRENCY + 1, 16).is_err());
    assert!(validate_scan_concurrency(1, 8, MAX_TLS_CONCURRENCY + 1).is_err());
}
