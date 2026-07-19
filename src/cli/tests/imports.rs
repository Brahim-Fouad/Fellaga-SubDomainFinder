use std::collections::BTreeSet;

use crate::cli::args::ImportFormat;
use crate::cli::imports::parse_import_names;

#[test]
fn json_import_extracts_only_in_scope_names() {
    assert_eq!(
        parse_import_names(
            r#"{"results":[{"host":"api.example.com"},{"host":"evil.test"}]}"#,
            ImportFormat::Json,
            "example.com",
        )
        .unwrap(),
        BTreeSet::from(["api.example.com".to_owned()])
    );
}

#[test]
fn json_import_rejects_invalid_content() {
    let error = parse_import_names(
        r#"{"host":"api.example.com""#,
        ImportFormat::Json,
        "example.com",
    )
    .unwrap_err();

    assert!(error.to_string().starts_with("invalid JSON import:"));
}

#[test]
fn jsonl_import_extracts_valid_rows() {
    assert_eq!(
        parse_import_names(
            "{\"name\":\"www.example.com\"}\n{\"fqdn\":\"dev.example.com\"}\n",
            ImportFormat::Jsonl,
            "example.com",
        )
        .unwrap(),
        BTreeSet::from(["dev.example.com".to_owned(), "www.example.com".to_owned()])
    );
}

#[test]
fn jsonl_import_rejects_the_first_invalid_row() {
    let error = parse_import_names(
        "{\"name\":\"www.example.com\"}\nnot-json\n{\"fqdn\":\"dev.example.com\"}\n",
        ImportFormat::Jsonl,
        "example.com",
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .starts_with("invalid JSONL import at line 2:")
    );
}

#[test]
fn auto_import_detects_json_and_mixed_line_formats() {
    assert_eq!(
        parse_import_names(
            r#"{"hosts":["api.example.com","outside.test"]}"#,
            ImportFormat::Auto,
            "example.com",
        )
        .unwrap(),
        BTreeSet::from(["api.example.com".to_owned()])
    );
    assert_eq!(
        parse_import_names(
            "{\"hostname\":\"www.example.com\"}\nmail.example.com A 192.0.2.1\nnot-json\n",
            ImportFormat::Auto,
            "example.com",
        )
        .unwrap(),
        BTreeSet::from(["mail.example.com".to_owned(), "www.example.com".to_owned()])
    );
}

#[test]
fn text_import_stays_text_and_filters_invalid_names() {
    assert_eq!(
        parse_import_names(
            "api.example.com metadata\n{\"name\":\"json.example.com\"}\noutside.test\ninvalid\n",
            ImportFormat::Text,
            "example.com",
        )
        .unwrap(),
        BTreeSet::from(["api.example.com".to_owned()])
    );
}

#[test]
fn dns_text_import_extracts_the_first_column() {
    assert_eq!(
        parse_import_names(
            "# ignored\nmail.example.com A 192.0.2.1\noutside.test\n",
            ImportFormat::DnsText,
            "example.com",
        )
        .unwrap(),
        BTreeSet::from(["mail.example.com".to_owned()])
    );
}
