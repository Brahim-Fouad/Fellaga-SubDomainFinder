use crate::cli::commands::sources::{
    source_check_error_status, source_check_result_status, validate_source_check_concurrency,
};

#[test]
fn source_check_concurrency_is_bounded() {
    assert!(validate_source_check_concurrency(1).is_ok());
    assert!(validate_source_check_concurrency(8).is_ok());
    assert!(validate_source_check_concurrency(32).is_ok());
    assert!(validate_source_check_concurrency(0).is_err());
    assert!(validate_source_check_concurrency(33).is_err());
}

#[test]
fn source_check_distinguishes_connector_deadlines_from_errors() {
    assert_eq!(
        source_check_error_status(
            "commoncrawl: budget total de 20s dépassé; résultat en cache conservé"
        ),
        "deferred_budget"
    );
    assert_eq!(
        source_check_error_status(
            "commoncrawl: limite cumulative configurée de 20s atteinte; pages conservées"
        ),
        "deferred_budget"
    );
    assert_eq!(
        source_check_error_status("commoncrawl: HTTP 502"),
        "upstream_error"
    );
    assert_eq!(
        source_check_error_status("Cert Spotter: HTTP 429; Retry-After=60s"),
        "rate_limited"
    );
    assert_eq!(
        source_check_error_status("Common Crawl: HTTP 503; Retry-After=60s"),
        "upstream_error"
    );
    assert_eq!(
        source_check_error_status("Driftnet: HTTP 524 timeout CDN amont"),
        "upstream_error"
    );
    assert_eq!(
        source_check_error_status("Cloudflare challenge: Just a moment"),
        "anti_bot"
    );
    assert_eq!(
        source_check_error_status("error sending request: connection refused"),
        "transport_error"
    );
    assert_eq!(
        source_check_error_status(
            "error sending request for url (https://index.commoncrawl.org/collinfo.json)"
        ),
        "transport_error"
    );
    assert_eq!(
        source_check_error_status("JSON Common Crawl invalide"),
        "schema_error"
    );
    assert_eq!(source_check_result_status(0, None), "empty");
    assert_eq!(
        source_check_result_status(3, Some("page 2 failed")),
        "degraded"
    );
    assert_eq!(
        source_check_result_status(0, Some("budget total de 10s dépassé")),
        "deferred_budget"
    );
}
