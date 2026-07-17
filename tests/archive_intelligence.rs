use fellaga_core::archive_intelligence::{
    ArchiveLimits, ArchiveTechnique, analyze_archived_document, analyze_common_crawl_warc,
};
use proptest::prelude::*;
use std::io::{Cursor, Read};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
fn warc_response_extracts_only_strictly_scoped_names() {
    let warc = include_bytes!("fixtures/archive/commoncrawl-response.warc");
    let discovery = analyze_common_crawl_warc(
        Cursor::new(warc),
        "example.com",
        "CC-MAIN-fixture",
        ArchiveLimits::default(),
    )
    .unwrap();

    for expected in [
        "www.example.com",
        "static.example.com",
        "assets.example.com",
        "next-archive.example.com",
    ] {
        assert!(discovery.names.contains(expected), "missing {expected}");
    }
    assert!(!discovery.names.iter().any(|name| name.contains("attacker")));
    assert_eq!(discovery.stats.records_seen, 1);
    assert_eq!(discovery.stats.records_analyzed, 1);
    assert!(!discovery.stats.archive_truncated);
    assert!(
        discovery
            .evidence
            .iter()
            .all(|evidence| !evidence.provenance.target_url.contains('?'))
    );
}

#[test]
fn javascript_semantics_cover_calls_configs_concatenation_and_source_maps() {
    let source = include_bytes!("fixtures/archive/bundle.js");
    let discovery = analyze_archived_document(
        "example.com",
        "https://static.example.com/assets/bundle.js",
        "application/javascript",
        source,
        ArchiveLimits::default(),
    )
    .unwrap();

    for expected in [
        "api-v2.example.com",
        "fetch.example.com",
        "axios.example.com",
        "events.example.com",
        "webpack.example.com",
        "vite.example.com",
        "next.example.com",
        "maps.example.com",
    ] {
        assert!(discovery.names.contains(expected), "missing {expected}");
    }
    assert!(!discovery.names.iter().any(|name| name.contains("evil")));

    let techniques = discovery
        .evidence
        .iter()
        .map(|evidence| evidence.provenance.technique)
        .collect::<std::collections::BTreeSet<_>>();
    for expected in [
        ArchiveTechnique::ConcatenatedString,
        ArchiveTechnique::FetchCall,
        ArchiveTechnique::AxiosCall,
        ArchiveTechnique::WebSocket,
        ArchiveTechnique::WebpackConfig,
        ArchiveTechnique::ViteConfig,
        ArchiveTechnique::NextConfig,
        ArchiveTechnique::SourceMapUrl,
    ] {
        assert!(techniques.contains(&expected), "missing {expected:?}");
    }
    assert!(
        discovery
            .in_scope_urls
            .contains("https://maps.example.com/assets/bundle.js.map")
    );
}

#[test]
fn source_map_sources_and_embedded_sources_are_inspected_without_execution() {
    let source = include_bytes!("fixtures/archive/bundle.js.map");
    let discovery = analyze_archived_document(
        "example.com",
        "https://maps.example.com/assets/bundle.js.map",
        "application/json",
        source,
        ArchiveLimits::default(),
    )
    .unwrap();

    for expected in [
        "static.example.com",
        "src.example.com",
        "source-one.example.com",
        "source-api.example.com",
    ] {
        assert!(discovery.names.contains(expected), "missing {expected}");
    }
    assert!(!discovery.names.iter().any(|name| name.contains("attacker")));
    assert!(
        discovery
            .in_scope_urls
            .contains("https://src.example.com/client.js")
    );
    assert!(discovery.evidence.iter().any(|evidence| {
        evidence.fqdn == "source-one.example.com"
            && evidence.provenance.technique == ArchiveTechnique::SourceMapSource
    }));
    assert!(discovery.evidence.iter().any(|evidence| {
        evidence.fqdn == "source-api.example.com"
            && evidence.provenance.technique == ArchiveTechnique::FetchCall
    }));
}

#[derive(Clone)]
struct CountingReader {
    inner: Cursor<Vec<u8>>,
    bytes_read: Arc<AtomicUsize>,
}

impl Read for CountingReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes_read.fetch_add(read, Ordering::SeqCst);
        Ok(read)
    }
}

#[test]
fn reader_and_output_limits_are_hard() {
    let count = Arc::new(AtomicUsize::new(0));
    let reader = CountingReader {
        inner: Cursor::new(vec![b'x'; 100_000]),
        bytes_read: Arc::clone(&count),
    };
    let limits = ArchiveLimits {
        max_archive_bytes: 257,
        max_record_bytes: 128,
        max_header_bytes: 64,
        max_records: 2,
        max_document_bytes: 64,
        max_analysis_bytes: 128,
        max_names: 3,
        max_evidence: 4,
        max_urls: 2,
        max_js_literals: 8,
        max_string_bytes: 32,
        max_json_values: 16,
    };
    let discovery = analyze_common_crawl_warc(reader, "example.com", "bounded", limits).unwrap();
    assert!(count.load(Ordering::SeqCst) <= limits.max_archive_bytes + 1);
    assert!(discovery.stats.archive_truncated);
    assert!(discovery.names.len() <= limits.max_names);
    assert!(discovery.evidence.len() <= limits.max_evidence);
    assert!(discovery.in_scope_urls.len() <= limits.max_urls);
}

#[test]
fn compressed_outer_warc_is_rejected_explicitly() {
    let error = analyze_common_crawl_warc(
        Cursor::new([0x1f, 0x8b, 0x08, 0x00]),
        "example.com",
        "compressed",
        ArchiveLimits::default(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("decompress"));
}

#[test]
fn binary_documents_are_not_interpreted_as_hostname_evidence() {
    let discovery = analyze_archived_document(
        "example.com",
        "https://www.example.com/logo.png",
        "image/png",
        b"\x89PNG https://false-positive.example.com/",
        ArchiveLimits::default(),
    )
    .unwrap();
    assert!(discovery.names.is_empty());
    assert_eq!(discovery.stats.documents_skipped_non_text, 1);
    assert_eq!(discovery.stats.analysis_bytes, 0);
}

#[test]
fn embedded_http_content_length_excludes_trailing_record_bytes() {
    let payload = b"https://declared.example.com/";
    let trailing = b" https://poison.example.com/";
    let http_headers = format!(
        "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: {}\n\n",
        payload.len()
    );
    let mut response = http_headers.into_bytes();
    response.extend_from_slice(payload);
    response.extend_from_slice(trailing);
    let warc_headers = format!(
        "WARC/1.0\nWARC-Type: response\nWARC-Target-URI: https://www.example.com/\nContent-Length: {}\n\n",
        response.len()
    );
    let mut warc = warc_headers.into_bytes();
    warc.extend_from_slice(&response);

    let discovery = analyze_common_crawl_warc(
        Cursor::new(warc),
        "example.com",
        "content-length",
        ArchiveLimits::default(),
    )
    .unwrap();
    assert!(discovery.names.contains("declared.example.com"));
    assert!(!discovery.names.contains("poison.example.com"));
}

#[test]
fn oversized_warc_record_is_skipped_without_document_analysis() {
    let payload = b"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhttps://hidden.example.com/";
    let headers = format!(
        "WARC/1.0\nWARC-Type: response\nWARC-Target-URI: https://www.example.com/\nContent-Length: {}\n\n",
        payload.len()
    );
    let mut warc = headers.into_bytes();
    warc.extend_from_slice(payload);
    let limits = ArchiveLimits {
        max_record_bytes: 16,
        ..ArchiveLimits::default()
    };

    let discovery =
        analyze_common_crawl_warc(Cursor::new(warc), "example.com", "oversized", limits).unwrap();
    assert_eq!(discovery.stats.records_oversized, 1);
    assert_eq!(discovery.stats.records_analyzed, 0);
    assert!(discovery.names.is_empty());
}

proptest! {
    #[test]
    fn arbitrary_warc_bytes_never_escape_limits(input in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let limits = ArchiveLimits {
            max_archive_bytes: 512,
            max_record_bytes: 256,
            max_header_bytes: 96,
            max_records: 4,
            max_document_bytes: 128,
            max_analysis_bytes: 512,
            max_names: 5,
            max_evidence: 7,
            max_urls: 3,
            max_js_literals: 8,
            max_string_bytes: 48,
            max_json_values: 32,
        };
        if let Ok(discovery) = analyze_common_crawl_warc(Cursor::new(input), "example.com", "fuzz", limits) {
            prop_assert!(discovery.names.len() <= limits.max_names);
            prop_assert!(discovery.evidence.len() <= limits.max_evidence);
            prop_assert!(discovery.in_scope_urls.len() <= limits.max_urls);
            prop_assert!(discovery.stats.bytes_read <= limits.max_archive_bytes);
            prop_assert!(discovery.names.iter().all(|name| name.ends_with(".example.com")));
        }
    }
}
