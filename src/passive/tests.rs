use super::config::{ConfigFile, KeyList};
use super::pagination::*;
use super::providers::*;
use super::runtime::*;
use super::transport::*;
use super::*;
use crate::model::EvidenceFamily;
use crate::source_contract::PassivePaginationState;
use crate::util::{domain_hash, normalize_observed_name};
use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn abort_on_drop_cancels_a_pending_background_task() {
    struct DropProbe(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
    let (dropped_sender, dropped_receiver) = tokio::sync::oneshot::channel();
    let task = AbortOnDrop(tokio::spawn(async move {
        let _probe = DropProbe(Some(dropped_sender));
        let _ = started_sender.send(());
        std::future::pending::<()>().await;
    }));
    started_receiver.await.unwrap();

    drop(task);

    tokio::time::timeout(Duration::from_secs(1), dropped_receiver)
        .await
        .expect("aborted background task did not release its resources")
        .unwrap();
}

#[test]
fn crtsh_postgres_addresses_prefer_ipv4_and_remove_duplicates() {
    assert_eq!(
        ordered_crtsh_postgres_addresses([
            "[2001:db8::1]:5432".parse::<SocketAddr>().unwrap(),
            "192.0.2.10:5432".parse::<SocketAddr>().unwrap(),
            "192.0.2.10:5432".parse::<SocketAddr>().unwrap(),
        ]),
        vec![
            "192.0.2.10".parse::<IpAddr>().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap(),
        ]
    );
}

#[test]
fn crtsh_http_gets_a_bounded_head_start_before_postgres() {
    assert_eq!(
        crtsh_http_head_start(Duration::from_secs(30)),
        Duration::from_secs(8)
    );
    assert_eq!(
        crtsh_http_head_start(Duration::from_secs(5)),
        Duration::from_secs(5)
    );
}

fn key_store(entries: &[(&str, &[&str])]) -> ApiKeyStore {
    ApiKeyStore {
        keys: entries
            .iter()
            .map(|(source, values)| {
                (
                    (*source).to_owned(),
                    values.iter().map(|value| (*value).to_owned()).collect(),
                )
            })
            .collect(),
        cursor: Arc::new(AtomicUsize::new(0)),
    }
}

#[tokio::test]
async fn numeric_pagination_context_routes_independent_lanes() {
    let contract_a = PassivePaginationContract {
        lane: "lane_a",
        contract_version: 1,
        query_hash: domain_hash("fixture:lane-a"),
    };
    let contract_b = PassivePaginationContract {
        lane: "lane_b",
        contract_version: 2,
        query_hash: domain_hash("fixture:lane-b"),
    };
    let state = |contract: &PassivePaginationContract, done| PassivePaginationState {
        contract_version: contract.contract_version,
        query_hash: contract.query_hash.clone(),
        next_position: 2,
        records_seen: 1,
        expected_records: Some(1),
        expected_pages: Some(1),
        last_page_hash: domain_hash(contract.lane),
        last_page_records: 1,
        done,
        updated_at: 1,
    };
    let finished_a = Arc::new(AtomicUsize::new(0));
    let finished_b = Arc::new(AtomicUsize::new(0));
    let mut context = PassivePaginationContext::empty();
    let finished_a_sink = Arc::clone(&finished_a);
    context
        .insert(
            contract_a.clone(),
            Some(state(&contract_a, false)),
            Arc::new(|_, _| Ok(())),
            Arc::new(move || {
                finished_a_sink.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
        )
        .unwrap();
    let finished_b_sink = Arc::clone(&finished_b);
    context
        .insert(
            contract_b.clone(),
            Some(state(&contract_b, true)),
            Arc::new(|_, _| Ok(())),
            Arc::new(move || {
                finished_b_sink.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
        )
        .unwrap();

    PASSIVE_PAGINATION_CONTEXT
        .scope(Some(context), async {
            assert_eq!(
                numeric_pagination_resume(&contract_a)
                    .unwrap()
                    .next_position,
                2
            );
            assert!(!numeric_pagination_is_complete(&contract_a));
            assert!(numeric_pagination_is_complete(&contract_b));
            finish_numeric_pagination(&contract_a).unwrap();
            finish_numeric_pagination(&contract_b).unwrap();
        })
        .await;
    assert_eq!(finished_a.load(Ordering::Relaxed), 1);
    assert_eq!(finished_b.load(Ordering::Relaxed), 1);
}

#[test]
fn numeric_contract_registry_returns_all_lanes_without_duplicates() {
    let contracts = numeric_pagination_contracts("viewdns", "Example.COM.");
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0].lane, "pages");
    assert!(numeric_pagination_contracts("crtsh", "example.com").is_empty());

    let contract = contracts[0].clone();
    let mut context = PassivePaginationContext::new(
        contract.clone(),
        None,
        Arc::new(|_, _| Ok(())),
        Arc::new(|| Ok(())),
    );
    assert!(
        context
            .insert(contract, None, Arc::new(|_, _| Ok(())), Arc::new(|| Ok(())),)
            .is_err()
    );
}

#[test]
fn key_bearing_debug_output_is_fully_redacted() {
    let store = key_store(&[("shodan", &["runtime-super-secret"])]);
    let config = ConfigFile {
        api_keys: BTreeMap::from([(
            "shodan".to_owned(),
            KeyList::One("runtime-super-secret".to_owned()),
        )]),
    };
    let list = KeyList::Many(vec!["runtime-super-secret".to_owned()]);

    for debug in [
        format!("{store:?}"),
        format!("{config:?}"),
        format!("{list:?}"),
    ] {
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("runtime-super-secret"));
        assert!(!debug.contains("shodan"));
    }
}

#[test]
fn canonical_names_share_legacy_provider_credentials() {
    let legacy = key_store(&[("otx", &["otx-secret"]), ("whoisxml", &["whoisxml-secret"])]);
    assert_eq!(legacy.values("alienvault"), vec!["otx-secret".to_owned()]);
    assert_eq!(
        legacy.values("whoisxmlapi"),
        vec!["whoisxml-secret".to_owned()]
    );

    let canonical = key_store(&[
        ("alienvault", &["alienvault-secret"]),
        ("whoisxmlapi", &["whoisxmlapi-secret"]),
    ]);
    assert_eq!(
        canonical.values("otx"),
        vec!["alienvault-secret".to_owned()]
    );
    assert_eq!(
        canonical.values("whoisxml"),
        vec!["whoisxmlapi-secret".to_owned()]
    );
}

#[test]
fn external_error_sanitizer_removes_urls_assignments_and_known_key_values() {
    let store = key_store(&[
        ("shodan", &["shodan-super-secret"]),
        ("censys", &["client-identifier:client-super-secret"]),
        ("intelx", &["abc"]),
    ]);
    use base64::Engine as _;
    let basic =
        base64::engine::general_purpose::STANDARD.encode("client-identifier:client-super-secret");
    let message = format!(
        "request https://api-user:url-password@example.test/path?key=unknown-query-secret&cursor=public failed: apiKey='unknown-json-secret'; body shodan-super-secret client-identifier client-super-secret short abc Basic {basic}"
    );

    let sanitized = sanitize_external_error(&message, &store);
    for secret in [
        "api-user",
        "url-password",
        "unknown-query-secret",
        "unknown-json-secret",
        "shodan-super-secret",
        "client-identifier",
        "client-super-secret",
        "abc",
        basic.as_str(),
    ] {
        assert!(
            !sanitized.contains(secret),
            "secret encore visible: {secret}"
        );
    }
    assert!(sanitized.contains("REDACTED"));
    assert!(sanitized.contains("cursor=public"));
}

#[test]
fn config_creation_preserves_existing_values() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fellaga/config.json");
    let empty = ApiKeyStore::load_or_create(&path).unwrap();
    assert!(!empty.has("shodan"));
    let configured = r#"{"api_keys":{"shodan":"fixture-secret-value"}}"#;
    fs::write(&path, configured).unwrap();

    let loaded = ApiKeyStore::load_or_create(&path).unwrap();
    assert!(loaded.has("shodan"));
    assert_eq!(fs::read_to_string(path).unwrap(), configured);
}

#[cfg(unix)]
#[test]
fn config_directory_and_file_are_private_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let config_directory = directory.path().join("fellaga");
    fs::create_dir(&config_directory).unwrap();
    fs::set_permissions(&config_directory, fs::Permissions::from_mode(0o777)).unwrap();
    let path = config_directory.join("config.json");

    ApiKeyStore::load_or_create(&path).unwrap();
    assert_eq!(
        fs::metadata(&config_directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    ApiKeyStore::load_or_create(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn whoisxml_contract_fixture_preserves_pagination_and_scope() {
    let page: WhoisXmlResponse =
        serde_json::from_str(include_str!("../../tests/fixtures/whoisxml-page.json")).unwrap();
    let result = page.result.unwrap();
    assert_eq!(result.next_page_search_after, "cursor-2");
    let names = result
        .records
        .into_iter()
        .filter_map(|record| normalize_observed_name(&record.domain, "example.com"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "api.example.com".to_owned(),
            "deep.api.example.com".to_owned()
        ])
    );
}

#[test]
fn netlas_download_stream_handles_chunk_boundaries_and_scope() {
    let fixture = include_bytes!("../../tests/fixtures/netlas-page.json");
    let mut decoder = NetlasArrayDecoder::new(2, 1024);
    let mut names = BTreeSet::new();
    {
        let mut visit = |item: NetlasItem| -> Result<()> {
            if let Some(name) = normalize_observed_name(&item.data.domain, "example.com") {
                names.insert(name);
            }
            Ok(())
        };
        for byte in fixture.chunks(1) {
            decoder.push(byte, &mut visit).unwrap();
        }
    }
    decoder.finish().unwrap();
    assert_eq!(names, BTreeSet::from(["edge.example.com".to_owned()]));
}

#[test]
fn netlas_download_stream_rejects_truncation_trailing_data_and_excess_records() {
    let mut noop = |_item: NetlasItem| Ok(());

    let mut truncated = NetlasArrayDecoder::new(1, 1024);
    truncated
        .push(br#"[{"data":{"domain":"a.example.com"}}"#, &mut noop)
        .unwrap();
    assert!(truncated.finish().is_err());

    let mut trailing = NetlasArrayDecoder::new(1, 1024);
    assert!(trailing.push(b"[] false", &mut noop).is_err());

    let mut excessive = NetlasArrayDecoder::new(1, 1024);
    assert!(
        excessive
            .push(
                br#"[{"data":{"domain":"a.example.com"}},{"data":{"domain":"b.example.com"}}]"#,
                &mut noop,
            )
            .is_err()
    );

    let mut oversized = NetlasArrayDecoder::new(1, 8);
    assert!(
        oversized
            .push(br#"[{"data":{"domain":"a.example.com"}}]"#, &mut noop)
            .is_err()
    );
}

#[test]
fn netlas_download_request_matches_current_api_contract_and_caps() {
    let query = "domain:*.example.com AND NOT domain:example.com";
    let request = NetlasDownloadRequest {
        q: query,
        fields: ["domain"],
        source_type: "include",
        size: NETLAS_DEFAULT_DOWNLOAD_LIMIT,
    };
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({
            "q": query,
            "fields": ["domain"],
            "source_type": "include",
            "size": 200
        })
    );
    assert_eq!(NETLAS_DOWNLOAD_MAX_BYTES, 16 * 1024 * 1024);
    assert_eq!(NETLAS_CHECKPOINT_RECORDS, 50);
    assert_eq!(parse_netlas_download_limit(None).unwrap(), 200);
    assert_eq!(parse_netlas_download_limit(Some("10000")).unwrap(), 10_000);
    assert!(parse_netlas_download_limit(Some("0")).is_err());
    assert!(parse_netlas_download_limit(Some("1000001")).is_err());
    assert!(parse_netlas_download_limit(Some("invalid")).is_err());

    let http = build_client(Duration::from_secs(1)).unwrap();
    for built in [
        netlas_count_request(&http, query, "secret")
            .build()
            .unwrap(),
        netlas_download_request(&http, &request, "secret")
            .build()
            .unwrap(),
    ] {
        assert_eq!(
            built
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer secret")
        );
        assert!(!built.headers().contains_key("X-API-Key"));
    }
}

#[test]
fn securitytrails_contract_supports_scroll_and_legacy_shapes() {
    let list: SecurityTrailsResponse = serde_json::from_str(
        r#"{
                "meta":{"scroll_id":"opaque-next"},
                "records":[
                    {"hostname":"api.example.com"},
                    {"hostname":"outside.example.net"}
                ]
            }"#,
    )
    .unwrap();
    assert_eq!(
        securitytrails_page_names(&list, "example.com"),
        BTreeSet::from(["api.example.com".to_owned()])
    );

    let legacy: SecurityTrailsResponse =
        serde_json::from_str(r#"{"subdomains":["www","deep.api","mail."]}"#).unwrap();
    assert_eq!(
        securitytrails_page_names(&legacy, "example.com"),
        BTreeSet::from([
            "deep.api.example.com".to_owned(),
            "mail.example.com".to_owned(),
            "www.example.com".to_owned(),
        ])
    );
}

#[test]
fn securitytrails_scroll_is_same_origin_bounded_and_non_repeating() {
    let url = securitytrails_scroll_url("//evil.test/a?key=value#fragment").unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("api.securitytrails.com"));
    assert!(url.query().is_none());
    assert!(url.fragment().is_none());

    assert!(securitytrails_scroll_url("line\nbreak").is_err());
    assert!(securitytrails_scroll_url(&"x".repeat(4097)).is_err());

    let mut seen = BTreeSet::new();
    assert_eq!(
        securitytrails_next_scroll("cursor".to_owned(), &mut seen).unwrap(),
        Some("cursor".to_owned())
    );
    assert!(securitytrails_next_scroll("cursor".to_owned(), &mut seen).is_err());
    assert_eq!(
        securitytrails_next_scroll(String::new(), &mut seen).unwrap(),
        None
    );
    assert_eq!(SECURITYTRAILS_MAX_SCROLL_PAGES, 1000);
}

#[test]
fn securitytrails_falls_back_only_for_exact_forbidden_status() {
    assert!(securitytrails_use_legacy_fallback(
        reqwest::StatusCode::FORBIDDEN
    ));
    for status in [
        reqwest::StatusCode::UNAUTHORIZED,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        assert!(!securitytrails_use_legacy_fallback(status));
    }
}

#[test]
fn deep_profile_enables_every_accessible_unique_connector_but_not_duplicate_aliases() {
    let keys = ApiKeyStore::default();
    let balanced = automatic_sources_for_profile(&keys, false);
    let deep = automatic_sources_for_profile(&keys, true);
    assert!(!balanced.contains(&"anubisdb".to_owned()));
    assert!(!balanced.contains(&"anubis".to_owned()));
    assert!(balanced.contains(&"arquivopt".to_owned()));
    assert!(!balanced.contains(&"shrewdeye".to_owned()));
    assert!(!balanced.contains(&"subdomainapp".to_owned()));
    assert!(!balanced.contains(&"driftnet".to_owned()));
    assert!(deep.contains(&"anubisdb".to_owned()));
    assert!(deep.contains(&"anubis".to_owned()));
    assert!(deep.contains(&"arquivopt".to_owned()));
    assert!(deep.contains(&"shrewdeye".to_owned()));
    assert!(deep.contains(&"subdomainapp".to_owned()));
    assert!(deep.contains(&"subdomaincenter".to_owned()));
    assert!(deep.contains(&"hudsonrock".to_owned()));
    assert!(deep.contains(&"threatminer".to_owned()));
    assert!(deep.contains(&"digitorus".to_owned()));
    assert!(deep.contains(&"waybackarchive".to_owned()));
    assert!(!deep.contains(&"driftnet".to_owned()));
    assert!(!deep.contains(&"otx".to_owned()));
    assert!(!deep.contains(&"wayback".to_owned()));
    assert!(!deep.contains(&"whoisxml".to_owned()));
    assert!(!deep.contains(&"certificatedetails".to_owned()));
    assert!(!deep.contains(&"bevigil".to_owned()));
}

#[test]
fn exhaustive_selection_omits_runtime_aliases_without_hiding_connectors() {
    let sources = all_unique_sources().into_iter().collect::<BTreeSet<_>>();
    for (canonical, alias) in [
        ("alienvault", "otx"),
        ("digitorus", "certificatedetails"),
        ("waybackarchive", "wayback"),
        ("whoisxmlapi", "whoisxml"),
    ] {
        assert!(sources.contains(canonical));
        assert!(!sources.contains(alias));
    }
    assert_eq!(sources.len(), 64);
}

#[test]
fn deep_profile_enables_driftnet_only_with_a_real_key() {
    let keys = key_store(&[("driftnet", &["driftnet-key"]), ("otx", &["otx-key"])]);
    let deep = automatic_sources_for_profile(&keys, true);
    assert!(deep.contains(&"driftnet".to_owned()));
    assert!(!deep.contains(&"otx".to_owned()));
    assert!(deep.contains(&"alienvault".to_owned()));
    assert!(source_metadata("driftnet").documented);
    assert_eq!(source_metadata("alienvault").authentication, "required");
}

#[test]
fn reconeer_is_skipped_until_its_current_live_api_key_is_configured() {
    let empty = ApiKeyStore::default();
    let status = source_statuses(&empty)
        .into_iter()
        .find(|status| status.name == "reconeer")
        .unwrap();
    assert!(status.requires_key);
    assert!(!status.configured);
    assert!(!status.automatic);
    assert_eq!(status.metadata.authentication, "required");

    let configured = key_store(&[("reconeer", &["key"])]);
    assert!(automatic_sources_for_profile(&configured, true).contains(&"reconeer".to_owned()));
}

#[test]
fn canonical_provider_names_share_alias_cost_and_runtime_policy() {
    assert_eq!(
        source_metadata("whoisxmlapi").cost,
        source_metadata("whoisxml").cost
    );
    assert_eq!(source_policy("alienvault"), source_policy("otx"));
}

#[test]
fn content_fetch_lanes_have_explicit_internal_transport_rates() {
    for source in ["github-content", "gitlab-content"] {
        assert!(try_source_metadata(source).is_none());
        assert_eq!(internal_transport_rate_limit_per_minute(source), Some(600));
        assert_eq!(transport_rate_limit_per_minute(source), 600);
    }
    assert_eq!(
        internal_transport_rate_limit_per_minute("unknown-lane"),
        None
    );
    assert_eq!(transport_rate_limit_per_minute("unknown-lane"), 1);
}

#[tokio::test]
async fn internal_content_lane_does_not_inherit_the_one_per_minute_fallback() {
    tokio::time::timeout(Duration::from_secs(2), async {
        throttle_external_source("gitlab-content").await;
        throttle_external_source("gitlab-content").await;
    })
    .await
    .expect("the 600 requests/minute internal lane must not wait for a minute");
}

#[test]
fn registry_contains_every_audited_provider_without_duplicates() {
    let expected = BTreeSet::from([
        "alienvault",
        "anubis",
        "arquivopt",
        "bevigil",
        "bufferover",
        "builtwith",
        "c99",
        "censys",
        "certspotter",
        "chaos",
        "chinaz",
        "commoncrawl",
        "crtsh",
        "digitalyama",
        "digitorus",
        "dnsdb",
        "dnsdumpster",
        "dnsrepo",
        "domainsproject",
        "driftnet",
        "fofa",
        "fullhunt",
        "github",
        "gitlab",
        "hackertarget",
        "hudsonrock",
        "intelx",
        "leakix",
        "merklemap",
        "netlas",
        "onyphe",
        "postman",
        "profundis",
        "pugrecon",
        "quake",
        "rapiddns",
        "reconcloud",
        "reconeer",
        "redhuntlabs",
        "riddler",
        "robtex",
        "rsecloud",
        "securitytrails",
        "shodan",
        "shodanct",
        "shrewdeye",
        "sitedossier",
        "submd",
        "thc",
        "threatbook",
        "threatcrowd",
        "threatminer",
        "urlscan",
        "virustotal",
        "viewdns",
        "waybackarchive",
        "whoisxmlapi",
        "windvane",
        "zoomeyeapi",
    ]);
    let registered = SOURCE_DEFINITIONS
        .iter()
        .map(|source| source.name)
        .collect::<BTreeSet<_>>();
    let registered_ids = SOURCE_DEFINITIONS
        .iter()
        .map(|source| source.id)
        .collect::<BTreeSet<_>>();
    assert_eq!(registered.len(), SOURCE_DEFINITIONS.len());
    assert_eq!(registered_ids.len(), SOURCE_DEFINITIONS.len());
    assert_eq!(registered_ids, SourceId::ALL.iter().copied().collect());
    let native = BTreeSet::from([
        "anubisdb",
        "brave",
        "circl",
        "subdomainapp",
        "subdomaincenter",
    ]);
    let compatibility = BTreeSet::from([
        "binaryedge",
        "certificatedetails",
        "otx",
        "wayback",
        "whoisxml",
    ]);
    let expected_registry = expected
        .iter()
        .chain(&native)
        .chain(&compatibility)
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(registered, expected_registry);
    assert_eq!(expected.len(), 59);
    assert_eq!(native.len(), 5);
    assert_eq!(compatibility.len(), 5);
    assert_eq!(SOURCE_DEFINITIONS.len(), 69);
}

#[test]
fn typed_registry_round_trips_and_owns_every_auth_mapping() {
    assert_eq!(SourceId::ALL.len(), SOURCE_DEFINITIONS.len());
    for source_id in SourceId::ALL.iter().copied() {
        let entry = source_id.definition();
        assert_eq!(entry.id, source_id);
        assert_eq!(entry.name, source_id.as_str());
        assert_eq!(entry.evidence_family, source_id.evidence_family());
        assert_eq!(SourceId::parse(entry.name), Some(source_id));
        assert_eq!(definition(entry.name).map(|item| item.id), Some(source_id));
        assert_eq!(
            passive_source_evidence_family(entry.name),
            Some(entry.evidence_family)
        );
        assert_eq!(
            try_source_metadata(entry.name).map(|metadata| metadata.evidence_family),
            Some(entry.evidence_family)
        );
        assert_eq!(
            try_source_metadata(entry.name).map(|metadata| metadata.pagination),
            Some(entry.pagination)
        );
        assert_eq!(environment_names(entry.name), entry.environment_names);

        match entry.key_environment {
            Some(primary) => {
                assert!(
                    entry.environment_names.contains(&primary),
                    "{} must expose its primary credential environment",
                    entry.name
                );
            }
            None => assert!(
                entry.environment_names.is_empty(),
                "{} has credential environments without an advertised key",
                entry.name
            ),
        }
        if entry.requires_key {
            assert!(
                entry.key_environment.is_some(),
                "{} requires a key but has no credential mapping",
                entry.name
            );
        }
        for alias in entry.key_aliases {
            let alias_entry = definition(alias).expect("credential aliases stay registered");
            assert!(
                alias_entry.key_aliases.contains(&entry.name),
                "credential alias {} -> {} must be reciprocal",
                entry.name,
                alias
            );
            assert_eq!(
                alias_entry.pagination, entry.pagination,
                "credential aliases {} and {} must share pagination semantics",
                entry.name, alias
            );
        }
    }
    assert!(SourceId::parse("unknown-source").is_none());
    assert!(definition("unknown-source").is_none());
    assert!(environment_names("unknown-source").is_empty());
    assert!(passive_source_evidence_family("unknown-source").is_none());
    assert!(try_source_metadata("unknown-source").is_none());
    let unknown = source_metadata("unknown-source");
    assert!(!unknown.available);
    assert_eq!(unknown.unavailable_reason, Some("source is not registered"));
    assert!(!unknown.recursive_children);
    assert!(!unknown.recursive_parents);
    assert!(!unknown.documented);
}

#[test]
fn typed_registry_declares_the_pagination_protocol_for_every_source() {
    let names_for = |capability| {
        SOURCE_DEFINITIONS
            .iter()
            .filter(|entry| entry.pagination == capability)
            .map(|entry| entry.name)
            .collect::<BTreeSet<_>>()
    };

    assert_eq!(
        names_for(PaginationCapability::None),
        BTreeSet::from([
            "anubis",
            "anubisdb",
            "bevigil",
            "binaryedge",
            "bufferover",
            "builtwith",
            "c99",
            "certificatedetails",
            "chaos",
            "chinaz",
            "digitalyama",
            "digitorus",
            "dnsrepo",
            "domainsproject",
            "driftnet",
            "fofa",
            "fullhunt",
            "hackertarget",
            "hudsonrock",
            "leakix",
            "pugrecon",
            "reconcloud",
            "reconeer",
            "riddler",
            "shodanct",
            "subdomainapp",
            "subdomaincenter",
            "threatbook",
            "threatcrowd",
            "threatminer",
        ])
    );
    assert_eq!(
        names_for(PaginationCapability::Numeric),
        BTreeSet::from([
            "alienvault",
            "commoncrawl",
            "dnsdumpster",
            "merklemap",
            "onyphe",
            "otx",
            "rapiddns",
            "redhuntlabs",
            "rsecloud",
            "shodan",
            "viewdns",
            "windvane",
            "zoomeyeapi",
        ])
    );
    assert_eq!(
        names_for(PaginationCapability::FixedOffset),
        BTreeSet::from(["brave", "dnsdb", "quake"])
    );
    assert_eq!(
        names_for(PaginationCapability::OpaqueReplay),
        BTreeSet::from([
            "censys",
            "certspotter",
            "github",
            "gitlab",
            "postman",
            "securitytrails",
            "sitedossier",
            "thc",
            "urlscan",
            "virustotal",
            "wayback",
            "waybackarchive",
            "whoisxml",
            "whoisxmlapi",
        ])
    );
    assert_eq!(
        names_for(PaginationCapability::StreamingReplay),
        BTreeSet::from([
            "arquivopt",
            "circl",
            "crtsh",
            "netlas",
            "profundis",
            "robtex",
            "shrewdeye",
            "submd",
        ])
    );
    assert_eq!(
        names_for(PaginationCapability::AsyncPolling),
        BTreeSet::from(["intelx"])
    );

    let classified = [
        PaginationCapability::None,
        PaginationCapability::Numeric,
        PaginationCapability::FixedOffset,
        PaginationCapability::OpaqueReplay,
        PaginationCapability::StreamingReplay,
        PaginationCapability::AsyncPolling,
    ]
    .into_iter()
    .flat_map(names_for)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        classified,
        SOURCE_DEFINITIONS
            .iter()
            .map(|entry| entry.name)
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn runtime_aliases_share_pagination_semantics() {
    for (canonical, alias) in [
        ("alienvault", "otx"),
        ("digitorus", "certificatedetails"),
        ("waybackarchive", "wayback"),
        ("whoisxmlapi", "whoisxml"),
    ] {
        assert_eq!(
            definition(canonical).unwrap().pagination,
            definition(alias).unwrap().pagination,
            "runtime aliases {canonical} and {alias} must stay coherent"
        );
    }
}

#[test]
fn new_search_and_passive_dns_connectors_have_coherent_capabilities() {
    let empty = ApiKeyStore::default();
    let postman = source_statuses(&empty)
        .into_iter()
        .find(|source| source.name == "postman")
        .unwrap();
    assert!(!postman.requires_key);
    assert!(!postman.configured);
    assert!(postman.automatic);
    assert_eq!(postman.metadata.authentication, "optional");
    assert_eq!(postman.metadata.evidence_family, EvidenceFamily::CodeSearch);
    assert!(!postman.metadata.recursive_children);
    assert!(!postman.metadata.recursive_parents);

    let configured = key_store(&[("viewdns", &["viewdns-key"])]);
    let viewdns = source_statuses(&configured)
        .into_iter()
        .find(|source| source.name == "viewdns")
        .unwrap();
    assert!(viewdns.requires_key);
    assert!(viewdns.configured);
    assert!(viewdns.automatic);
    assert_eq!(viewdns.metadata.authentication, "required");
    assert_eq!(viewdns.metadata.evidence_family, EvidenceFamily::PassiveDns);
    assert!(viewdns.metadata.recursive_children);
    assert!(viewdns.metadata.recursive_parents);
    assert_eq!(environment_names("postman"), &["POSTMAN_API_KEY"]);
    assert_eq!(environment_names("viewdns"), &["VIEWDNS_API_KEY"]);
}

#[test]
fn targeted_connectors_are_key_gated_and_strictly_bounded() {
    let keys = key_store(&[
        ("brave", &["brave-key"]),
        ("merklemap", &["merklemap-token"]),
    ]);
    let automatic = automatic_sources(&keys);
    for (source, environment, family, recursive_parent) in [
        (
            "brave",
            "BRAVE_SEARCH_API_KEY",
            EvidenceFamily::WebCrawl,
            false,
        ),
        (
            "merklemap",
            "MERKLEMAP_API_TOKEN",
            EvidenceFamily::CertificateTransparency,
            true,
        ),
    ] {
        assert!(automatic.contains(&source.to_owned()));
        let status = source_statuses(&keys)
            .into_iter()
            .find(|status| status.name == source)
            .unwrap();
        assert_eq!(status.key_environment.as_deref(), Some(environment));
        assert!(status.configured);
        assert!(status.automatic);
        assert_eq!(status.metadata.evidence_family, family);
        assert_eq!(status.metadata.cost, "medium");
        assert_eq!(status.metadata.authentication, "required");
        assert!(!status.metadata.experimental);
        assert_eq!(status.metadata.recursive_children, source == "merklemap");
        assert_eq!(status.metadata.recursive_parents, recursive_parent);
        assert_eq!(source_policy(source).timeout, Duration::from_secs(10));
        let expected_total_timeout = if source == "brave" { 35 } else { 20 };
        assert_eq!(
            source_policy(source).total_timeout,
            Duration::from_secs(expected_total_timeout)
        );
    }
}

#[test]
fn retired_connector_is_visible_but_never_automatic_or_available() {
    let keys = key_store(&[("binaryedge", &["legacy-key"])]);
    let status = source_statuses(&keys)
        .into_iter()
        .find(|status| status.name == "binaryedge")
        .unwrap();
    assert!(status.configured);
    assert!(!status.automatic);
    assert!(!status.metadata.available);
    assert!(status.metadata.unavailable_reason.is_some());
    assert!(!automatic_sources_for_profile(&keys, true).contains(&status.name));
    assert!(!status.metadata.recursive_children);
    assert!(!status.metadata.recursive_parents);
}

#[test]
fn recursive_connector_metadata_matches_the_pinned_provider_capabilities() {
    for source in [
        "crtsh",
        "certspotter",
        "merklemap",
        "alienvault",
        "bufferover",
        "digitorus",
        "dnsdb",
        "driftnet",
        "hackertarget",
        "leakix",
        "reconcloud",
        "securitytrails",
        "shodanct",
        "urlscan",
        "virustotal",
    ] {
        assert!(source_metadata(source).recursive_children, "{source}");
    }
    for source in ["commoncrawl", "waybackarchive", "brave", "submd", "thc"] {
        assert!(!source_metadata(source).recursive_children, "{source}");
    }
}

#[test]
fn thc_pagination_can_drain_large_public_result_sets() {
    assert_eq!(source_metadata("thc").rate_limit_per_minute, 300);
    assert_eq!(source_policy("thc").total_timeout, Duration::from_secs(75));
    assert_eq!(host_minimum_gap("ip.thc.org"), Duration::from_millis(100));
}

#[test]
fn archived_urls_are_reduced_to_in_scope_hosts() {
    assert_eq!(
        hostname_from_url("https://deep.api.example.com/path", "example.com").as_deref(),
        Some("deep.api.example.com")
    );
    assert!(hostname_from_url("https://example.net/", "example.com").is_none());
    assert!(hostname_from_url("not a url", "example.com").is_none());
}

#[test]
fn commoncrawl_uses_bounded_multi_page_index_windows() {
    assert_eq!(COMMONCRAWL_BLOCKS_PER_REQUEST, 15);
    assert_eq!(COMMONCRAWL_MAX_PAGES, 1_000);
    assert_eq!(COMMONCRAWL_MAX_RESULT_LINES, 3 * 50_000);
    assert_eq!(COMMONCRAWL_MAX_BODY_BYTES, 3 * MAX_EXTERNAL_BODY_BYTES);
    assert_eq!(COMMONCRAWL_INDEX_COUNT, 5);
}

#[test]
fn commoncrawl_selects_one_collection_per_year_before_recent_fallbacks() {
    let collections = [
        ("CC-MAIN-2026-30", "2026-a"),
        ("CC-MAIN-2026-26", "2026-b"),
        ("CC-MAIN-2025-51", "2025"),
        ("CC-MAIN-2024-51", "2024"),
        ("CC-MAIN-2023-50", "2023"),
        ("CC-MAIN-2022-49", "2022"),
    ]
    .into_iter()
    .map(|(id, suffix)| CommonCrawlCollection {
        id: id.to_owned(),
        cdx_api: format!("https://index.commoncrawl.org/{suffix}-index"),
    })
    .collect();
    let endpoints = select_commoncrawl_endpoints(collections);
    assert_eq!(endpoints.len(), 5);
    assert!(endpoints[0].contains("2026-a"));
    assert!(endpoints[1].contains("2025"));
    assert!(endpoints[4].contains("2022"));
    assert!(!endpoints.iter().any(|endpoint| endpoint.contains("2026-b")));
}

#[test]
fn ordinary_retry_after_is_honored_and_absurd_delays_are_deferred() {
    assert!(!defer_retry_after(Duration::ZERO));
    assert!(!defer_retry_after(MAX_INLINE_RETRY_AFTER));
    assert!(!defer_retry_after(Duration::from_secs(30)));
    assert!(defer_retry_after(Duration::from_secs(15 * 60 + 1)));
}

#[test]
fn user_agent_override_accepts_only_safe_http_header_values() {
    assert!(valid_user_agent_override(
        "Fellaga/0.8 security@example.org"
    ));
    assert!(!valid_user_agent_override("Fellaga\nInjected: true"));
    assert!(!valid_user_agent_override("Fellaga/🚀"));
}

#[test]
fn unstable_sources_have_bounded_individual_policies() {
    assert_eq!(source_policy("wayback").timeout, Duration::from_secs(45));
    assert_eq!(
        source_policy("wayback").total_timeout,
        Duration::from_secs(45)
    );
    assert!(source_policy("commoncrawl").total_timeout <= Duration::from_secs(45));
    assert!(source_policy("subdomaincenter").total_timeout <= Duration::from_secs(30));
    assert_eq!(source_policy("crtsh").attempts, 3);
    assert_eq!(source_policy("commoncrawl").attempts, 2);
    assert_eq!(
        host_minimum_gap("api.search.brave.com"),
        Duration::from_secs(3)
    );
    assert_eq!(
        host_minimum_gap("api.merklemap.com"),
        Duration::from_secs(3)
    );
    assert!(retryable_status(reqwest::StatusCode::REQUEST_TIMEOUT));
    assert!(retryable_status(reqwest::StatusCode::TOO_EARLY));
    assert!(retryable_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    assert!(retryable_status(
        reqwest::StatusCode::from_u16(524).unwrap()
    ));
    for method in [
        reqwest::Method::GET,
        reqwest::Method::HEAD,
        reqwest::Method::OPTIONS,
        reqwest::Method::TRACE,
    ] {
        assert!(retry_safe_method(&method), "{method} must be replay-safe");
    }
    for method in [
        reqwest::Method::POST,
        reqwest::Method::PUT,
        reqwest::Method::PATCH,
        reqwest::Method::DELETE,
    ] {
        assert!(!retry_safe_method(&method), "{method} must not be replayed");
    }
    assert_eq!(retry_after_delay("12"), Some(Duration::from_secs(12)));
    let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(60));
    let date_delay = retry_after_delay(&date).unwrap();
    assert!(date_delay > Duration::from_secs(55));
    assert!(date_delay <= Duration::from_secs(60));
    let mut headers = HeaderMap::new();
    headers.insert("ratelimit-reset", HeaderValue::from_static("17"));
    assert_eq!(
        retry_delay_from_headers(&headers),
        Some(Duration::from_secs(17))
    );
    let reset_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_add(30)
        .to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-ratelimit-reset",
        HeaderValue::from_str(&reset_at).unwrap(),
    );
    let reset_delay = retry_delay_from_headers(&headers).unwrap();
    assert!(reset_delay >= Duration::from_secs(29));
    assert!(reset_delay <= Duration::from_secs(30));
    assert!(
        backoff_delay("example.com", 1, Duration::from_millis(750))
            > backoff_delay("example.com", 0, Duration::from_millis(750))
    );
}

#[test]
fn external_error_compaction_is_bounded_and_log_safe() {
    assert_eq!(compact_external_error("bad\n\t request"), "bad request");
    let input = format!("\u{1b}[31m{}\u{202e}", "x".repeat(1_000));
    let compact = compact_external_error(&input);
    assert!(compact.ends_with('…'));
    assert!(compact.chars().count() <= 501);
    assert!(!compact.contains('\u{1b}'));
    assert!(!compact.contains("[31m"));
    assert!(!compact.contains('\u{202e}'));
}

#[test]
fn external_html_errors_never_leak_markup_or_page_bodies() {
    let cloudflare = r#"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><script src="/cdn-cgi/challenge-platform/test.js"></script>secret page body</body></html>"#;
    let generic =
        r#"<html><head><title>Server error</title></head><body>private trace</body></html>"#;

    assert_eq!(
        compact_external_error(cloudflare),
        "HTML anti-bot challenge"
    );
    assert_eq!(compact_external_error(generic), "HTML error page");
    for compact in [
        compact_external_error(cloudflare),
        compact_external_error(generic),
    ] {
        assert!(!compact.contains('<'));
        assert!(!compact.contains("secret"));
        assert!(!compact.contains("private trace"));
    }
}

#[tokio::test]
async fn zero_source_budget_disables_only_the_cumulative_deadline() {
    let result = enforce_source_budget("unlimited-test", Duration::ZERO, async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok::<_, anyhow::Error>("complete")
    })
    .await
    .unwrap();
    assert_eq!(result, "complete");
}

#[test]
fn external_host_limiters_isolate_local_ports() {
    let client = build_client(Duration::from_secs(1)).unwrap();
    let first = request_host(&client.get("http://127.0.0.1:41001/")).unwrap();
    let second = request_host(&client.get("http://127.0.0.1:41002/")).unwrap();
    assert_ne!(first.0, second.0);
    assert_eq!(first.1, second.1);
    assert_eq!(
        request_host(&client.get("https://example.com/path")),
        Some(("example.com|443".to_owned(), "example.com".to_owned()))
    );
}

#[tokio::test]
async fn connector_wall_clock_budget_cancels_a_slow_tail() {
    let started = Instant::now();
    let result = enforce_source_budget("slow-test", Duration::from_millis(10), async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("slow-test"));
    assert!(started.elapsed() < Duration::from_millis(250));
}

#[tokio::test]
async fn connector_budget_returns_pages_committed_before_a_slow_tail() {
    let result = enforce_source_budget_preserving_partial(
        "paginated-test",
        Duration::from_millis(10),
        async {
            let mut accumulated = BTreeSet::new();
            commit_result_page(
                &mut accumulated,
                BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned()]),
            );
            std::future::pending::<Result<BTreeSet<String>>>().await
        },
    )
    .await
    .unwrap();

    assert_eq!(
        result.names,
        BTreeSet::from(["api.example.com".to_owned(), "mail.example.com".to_owned(),])
    );
    assert!(result.partial_warning.is_some());
    assert!(!result.working_set_truncated);
}

#[tokio::test]
async fn capped_checkpoint_persists_the_full_page_before_retaining_a_partial_set() {
    let persisted = Arc::new(StdMutex::new(Vec::<BTreeSet<String>>::new()));
    let persisted_for_sink = persisted.clone();
    let sink: PassivePageSink = Arc::new(move |page| {
        persisted_for_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(page.clone());
        Ok(())
    });
    let full_page = BTreeSet::from([
        "a.example.com".to_owned(),
        "b.example.com".to_owned(),
        "c.example.com".to_owned(),
    ]);

    let result = enforce_source_budget_preserving_partial_with_sink(
        "paginated-test",
        Duration::from_millis(10),
        async {
            let mut accumulated = BTreeSet::new();
            commit_result_page(&mut accumulated, full_page.clone());
            std::future::pending::<Result<BTreeSet<String>>>().await
        },
        2,
        Some(sink),
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        result.names,
        BTreeSet::from(["a.example.com".to_owned(), "b.example.com".to_owned()])
    );
    assert!(result.working_set_truncated);
    assert_eq!(result.decoded_names, 3);
    assert!(result.partial_warning.is_some());
    assert_eq!(
        persisted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        &[full_page]
    );
}

#[tokio::test]
async fn connector_returns_committed_pages_when_a_later_page_fails() {
    let result =
        enforce_source_budget_preserving_partial("paginated-test", Duration::from_secs(1), async {
            let mut accumulated = BTreeSet::new();
            commit_result_page(
                &mut accumulated,
                BTreeSet::from(["api.example.com".to_owned()]),
            );
            Err(anyhow::anyhow!("page 2 returned invalid JSON"))
        })
        .await
        .unwrap();

    assert_eq!(result.names, BTreeSet::from(["api.example.com".to_owned()]));
    assert!(
        result
            .partial_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("page 2"))
    );
}

#[tokio::test]
async fn partial_page_checkpoints_are_isolated_between_concurrent_sources() {
    async fn one_slow_page(name: &'static str) -> Result<BTreeSet<String>> {
        let mut accumulated = BTreeSet::new();
        commit_result_page(&mut accumulated, BTreeSet::from([name.to_owned()]));
        std::future::pending::<Result<BTreeSet<String>>>().await
    }

    let (first, second) = tokio::join!(
        enforce_source_budget_preserving_partial(
            "first-test",
            Duration::from_millis(10),
            one_slow_page("one.example.com"),
        ),
        enforce_source_budget_preserving_partial(
            "second-test",
            Duration::from_millis(10),
            one_slow_page("two.example.com"),
        ),
    );

    assert_eq!(
        first.unwrap().names,
        BTreeSet::from(["one.example.com".to_owned()])
    );
    assert_eq!(
        second.unwrap().names,
        BTreeSet::from(["two.example.com".to_owned()])
    );
}

#[tokio::test]
async fn a_deadline_without_a_committed_page_is_deferred_not_failed() {
    let result = enforce_source_budget_preserving_partial(
        "empty-test",
        Duration::from_millis(10),
        std::future::pending::<Result<BTreeSet<String>>>(),
    )
    .await
    .unwrap();

    assert!(result.names.is_empty());
    assert!(
        result
            .partial_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("empty-test") && warning.contains("limite"))
    );
}

#[test]
fn external_pagination_cannot_redirect_credentials_to_another_host() {
    assert!(trusted_pagination_url(
        "https://www.virustotal.com/api/v3/domains/example.com/subdomains?cursor=x",
        "www.virustotal.com",
        "/api/v3/domains/"
    ));
    assert!(!trusted_pagination_url(
        "https://evil.test/api/v3/domains/example.com/subdomains",
        "www.virustotal.com",
        "/api/v3/domains/"
    ));
    assert!(!trusted_pagination_url(
        "https://www.virustotal.com@evil.test/api/v3/domains/example.com/subdomains",
        "www.virustotal.com",
        "/api/v3/domains/"
    ));
    assert!(!trusted_pagination_url(
        "https://www.virustotal.com:8443/api/v3/domains/example.com/subdomains",
        "www.virustotal.com",
        "/api/v3/domains/"
    ));
}

#[test]
fn no_target_contact_matching_is_label_aware() {
    assert!(external_host_contacts_target("example.com", "example.com"));
    assert!(external_host_contacts_target(
        "api.example.com",
        "example.com"
    ));
    assert!(external_host_contacts_target(
        "API.EXAMPLE.COM.",
        "example.com."
    ));
    assert!(!external_host_contacts_target(
        "notexample.com",
        "example.com"
    ));
    assert!(!external_host_contacts_target(
        "example.com.invalid",
        "example.com"
    ));
    assert!(!external_host_contacts_target("example.com", "ample.com"));
}

#[tokio::test]
async fn no_target_contact_rejects_before_any_socket_request() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let request = build_client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{address}/must-not-arrive"));

    let result = with_external_target_guard(
        Some("127.0.0.1".to_owned()),
        send_with_retry(request, 2, Duration::ZERO, "no-contact-test"),
    )
    .await;

    let error = result.unwrap_err().to_string();
    assert!(error.contains("no-target-contact"));
    assert!(error.contains("127.0.0.1"));
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[tokio::test]
async fn no_target_contact_keeps_unrelated_provider_hosts_available() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let request = build_client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{address}/provider"));

    let response = with_external_target_guard(
        Some("example.com".to_owned()),
        send_with_retry(request, 1, Duration::ZERO, "unrelated-provider-test"),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.join().unwrap();
}

#[tokio::test]
async fn custom_api_headers_never_follow_a_cross_origin_redirect() {
    let redirect_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let redirect_address = redirect_listener.local_addr().unwrap();
    let target_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = redirect_listener.accept().unwrap();
        let mut request = [0_u8; 2_048];
        let _ = socket.read(&mut request);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/sink\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        socket.write_all(response.as_bytes()).unwrap();
    });

    let result = client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{redirect_address}/source"))
        .header("X-Key", "legacy-provider-secret")
        .header("X-Subscription-Token", "brave-secret")
        .send()
        .await;
    assert!(result.is_err());
    server.join().unwrap();

    target_listener.set_nonblocking(true).unwrap();
    assert!(matches!(
        target_listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn urlscan_sort_values_become_a_search_after_cursor() {
    let result = UrlscanResult {
        page: None,
        task: None,
        sort: vec![
            serde_json::json!(1_784_000_000_000_i64),
            serde_json::json!("uuid"),
        ],
    };
    assert_eq!(
        urlscan_search_after(&result).as_deref(),
        Some("1784000000000,uuid")
    );
}

#[test]
fn wayback_windows_keep_only_in_scope_hosts() {
    let rows = vec![
        vec!["original".to_owned()],
        vec!["https://api.example.com/path".to_owned()],
        vec!["https://evil.test/".to_owned()],
        vec![],
        vec!["com%2Cexample%29%2F+20260718000000%21".to_owned()],
    ];
    let page = parse_wayback_page(rows.clone(), "example.com");
    let names = parse_wayback_rows(rows, "example.com");
    assert_eq!(names, BTreeSet::from(["api.example.com".to_owned()]));
    assert_eq!(
        page.resume_key.as_deref(),
        Some("com,example)/ 20260718000000!")
    );
}

#[test]
fn commoncrawl_ndjson_rejects_schema_drift_instead_of_empty_success() {
    let names = parse_commoncrawl_rows(
        "{\"url\":\"https://api.example.com/path\"}\n",
        "example.com",
    )
    .unwrap();
    assert_eq!(names, BTreeSet::from(["api.example.com".to_owned()]));
    let error = parse_commoncrawl_rows(
        "<html>upstream challenge</html>\n{\"unexpected\":true}\n",
        "example.com",
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("format NDJSON incohérent"));
}

#[test]
fn commoncrawl_marks_an_over_limit_page_instead_of_silently_truncating_it() {
    let body = concat!(
        r#"{"url":"https://one.example.com/"}"#,
        "\n\n",
        r#"{"url":"https://two.example.com/"}"#,
        "\n",
        r#"{"url":"https://three.example.com/"}"#,
        "\n",
    );
    let page = parse_commoncrawl_page_bounded(body, "example.com", 2).unwrap();
    assert!(page.truncated);
    assert_eq!(
        page.names,
        BTreeSet::from(["one.example.com".to_owned(), "two.example.com".to_owned()])
    );
}

#[test]
fn commoncrawl_endpoint_validation_accepts_only_the_official_https_origin() {
    for endpoint in [
        "https://index.commoncrawl.org/CC-MAIN-2026-30-index",
        "https://index.commoncrawl.org:443/CC-MAIN-2026-30-index",
    ] {
        let validated = validate_commoncrawl_endpoint(endpoint).unwrap();
        assert_eq!(validated.host_str(), Some("index.commoncrawl.org"));
        assert_eq!(validated.port_or_known_default(), Some(443));
    }

    for endpoint in [
        "http://index.commoncrawl.org/CC-MAIN-2026-30-index",
        "https://localhost/CC-MAIN-2026-30-index",
        "https://127.0.0.1/CC-MAIN-2026-30-index",
        "https://10.0.0.1/CC-MAIN-2026-30-index",
        "https://[::1]/CC-MAIN-2026-30-index",
        "https://commoncrawl.org/CC-MAIN-2026-30-index",
        "https://index.commoncrawl.org.evil.test/CC-MAIN-2026-30-index",
        "https://user:secret@index.commoncrawl.org/CC-MAIN-2026-30-index",
        "https://index.commoncrawl.org@127.0.0.1/CC-MAIN-2026-30-index",
        "https://index.commoncrawl.org:8443/CC-MAIN-2026-30-index",
        "https://index.commoncrawl.org/CC-MAIN-2026-30-index?url=evil.test",
        "https://index.commoncrawl.org/CC-MAIN-2026-30-index#fragment",
    ] {
        assert!(
            validate_commoncrawl_endpoint(endpoint).is_err(),
            "unsafe endpoint accepted: {endpoint}"
        );
    }
}

#[test]
fn commoncrawl_warc_range_must_match_the_requested_member_exactly() {
    assert!(commoncrawl_content_range_matches(
        "bytes 42-2047/9000",
        42,
        2_047
    ));
    assert!(commoncrawl_content_range_matches(
        "BYTES 42-2047/*",
        42,
        2_047
    ));
    for value in [
        "bytes 41-2047/9000",
        "bytes 42-2048/9000",
        "bytes 42-2047/2047",
        "bytes */9000",
        "42-2047/9000",
        "bytes 42-2047/9000 trailing",
    ] {
        assert!(
            !commoncrawl_content_range_matches(value, 42, 2_047),
            "{value}"
        );
    }
}

#[test]
fn commoncrawl_warc_sampling_requires_safe_bounded_in_scope_records() {
    let body = concat!(
        r#"{"url":"https://static.example.com/app.js","filename":"crawl-data/CC-MAIN-2026-30/segments/1/warc/file.warc.gz","offset":"42","length":"2048","mime":"application/javascript"}"#,
        "\n",
        r#"{"url":"https://evil.test/app.js","filename":"crawl-data/CC-MAIN-2026-30/evil.warc.gz","offset":"1","length":"100","mime":"application/javascript"}"#,
        "\n",
        r#"{"url":"https://large.example.com/app.js","filename":"crawl-data/CC-MAIN-2026-30/large.warc.gz","offset":"1","length":"999999999","mime":"application/javascript"}"#,
        "\n",
        r#"{"url":"https://unsafe.example.com/app.js","filename":"../outside.warc.gz","offset":"1","length":"100","mime":"application/javascript"}"#,
        "\n",
    );
    let page = parse_commoncrawl_page(body, "example.com").unwrap();
    assert_eq!(page.records.len(), 1);
    let record = page.records.first().unwrap();
    assert_eq!(record.url, "https://static.example.com/app.js");
    assert_eq!(record.offset, 42);
    assert_eq!(record.length, 2_048);
    assert!(page.names.contains("static.example.com"));
    assert!(page.names.contains("large.example.com"));
    assert!(page.names.contains("unsafe.example.com"));
    assert!(!page.names.contains("evil.test"));
}

#[tokio::test]
async fn retry_after_is_honored_before_a_successful_retry() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            let response = if attempt == 0 {
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"
            };
            socket.write_all(response.as_bytes()).unwrap();
        }
    });
    let response = send_with_retry(
        client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        2,
        Duration::from_millis(1),
        "retry-test",
    )
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.join().unwrap();
}

#[tokio::test]
async fn terminal_429_without_headers_gets_a_safe_default_deferral() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        socket
            .write_all(
                b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
    });
    let error = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        1,
        Duration::from_millis(1),
        "rate-limit-default-test",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("Retry-After=900s"));
    server.join().unwrap();
}

#[tokio::test]
async fn terminal_503_with_retry_after_is_an_upstream_deferral_not_a_quota() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
    });
    let error = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        1,
        Duration::from_millis(1),
        "upstream-deferral-test",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("service amont temporairement différé"));
    assert!(!error.contains("quota externe"));
    server.join().unwrap();
}

#[tokio::test]
async fn a_generic_403_with_retry_after_is_not_mislabeled_as_quota() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        socket
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
    });
    let response = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        2,
        Duration::from_millis(1),
        "generic-forbidden-test",
    )
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    server.join().unwrap();
}

#[tokio::test]
async fn an_explicitly_exhausted_403_is_a_quota_deferral() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        socket
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nX-RateLimit-Remaining: 0\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
    });
    let error = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        1,
        Duration::from_millis(1),
        "explicit-rate-limit-test",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("quota externe différé"));
    server.join().unwrap();
}

#[tokio::test]
async fn a_truncated_response_body_is_retried_as_a_complete_attempt() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1_024];
            let _ = socket.read(&mut request);
            if attempt == 0 {
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{",
                    )
                    .unwrap();
            } else {
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
                    )
                    .unwrap();
            }
        }
    });
    let response = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        2,
        Duration::from_millis(1),
        "truncated-body-test",
    )
    .await
    .unwrap();
    let values = response_json::<Vec<serde_json::Value>>(response, "truncated-test")
        .await
        .unwrap();
    assert!(values.is_empty());
    server.join().unwrap();
}

#[tokio::test]
async fn a_truncated_401_body_is_not_replayed_and_keeps_its_status() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        socket
            .write_all(
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{",
            )
            .unwrap();
    });
    let started = Instant::now();
    let error = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .get(format!("http://{address}/")),
        3,
        Duration::from_secs(1),
        "truncated-auth-test",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("HTTP 401 Unauthorized"));
    assert!(started.elapsed() < Duration::from_millis(750));
    server.join().unwrap();
}

#[tokio::test]
async fn post_requests_are_never_automatically_replayed() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server_listener = listener.try_clone().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = server_listener.accept().unwrap();
        let mut request = [0_u8; 2_048];
        let _ = socket.read(&mut request);
        socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
    });
    let response = send_with_retry(
        build_client(Duration::from_secs(2))
            .unwrap()
            .post(format!("http://{address}/"))
            .body("one-shot"),
        3,
        Duration::from_millis(1),
        "post-test",
    )
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[tokio::test]
async fn explicitly_idempotent_post_requests_use_the_bounded_retry_policy() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for status in ["503 Service Unavailable", "200 OK"] {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request);
            socket
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .unwrap();
        }
    });
    let response = send_with_retry_scoped(
        None,
        build_client(Duration::from_secs(2))
            .unwrap()
            .post(format!("http://{address}/"))
            .body("read-only-search"),
        2,
        Duration::from_millis(1),
        "idempotent-post-test",
        true,
        true,
    )
    .await
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.join().unwrap();
}

#[tokio::test]
async fn explicitly_idempotent_streaming_post_retries_before_returning_a_response() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for (status, body) in [
            ("503 Service Unavailable", ""),
            ("200 OK", "api.example.com\n"),
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2_048];
            let _ = socket.read(&mut request);
            socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
        }
    });
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        send_external_streaming_idempotent(
            "github-content",
            build_client(Duration::from_secs(2))
                .unwrap()
                .post(format!("http://{address}/"))
                .body("read-only-stream-search"),
            "idempotent-streaming-post-test",
        ),
    )
    .await
    .expect("the bounded retry must complete")
    .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "api.example.com\n");
    server.join().unwrap();
}

#[tokio::test]
async fn terminal_transport_errors_never_expose_query_credentials() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let error = send_with_retry(
        client(Duration::from_millis(250)).unwrap().get(format!(
            "http://{address}/failure?apiKey=transport-super-secret&cursor=public"
        )),
        1,
        Duration::ZERO,
        "transport-redaction-test",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(!error.contains("transport-super-secret"));
}

#[tokio::test]
async fn a_local_connection_refusal_is_not_retried() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let started = Instant::now();
    let result = send_with_retry(
        build_client(Duration::from_millis(250))
            .unwrap()
            .get(format!("http://{address}/")),
        3,
        Duration::from_millis(500),
        "connection-refused-test",
    )
    .await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_millis(400));
}

#[tokio::test]
async fn external_error_bodies_are_preserved_for_diagnostics() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        let body = r#"{"error":"invalid api key"}"#;
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(response.as_bytes()).unwrap();
    });
    let response = client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    let error = response_json::<serde_json::Value>(response, "source-test")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("401 Unauthorized"));
    assert!(error.contains("invalid api key"));
    server.join().unwrap();
}

#[test]
fn api_error_envelopes_and_schema_drift_are_never_empty_successes() {
    assert!(
        provider_error_message(&serde_json::json!({
            "code": 401,
            "message": "invalid api key"
        }))
        .is_some_and(|message| message.contains("invalid api key"))
    );
    assert!(
        provider_error_message(&serde_json::json!({
            "message": "anonymous access is limited"
        }))
        .is_some_and(|message| message.contains("anonymous access"))
    );
    for value in [
        serde_json::json!(false),
        serde_json::json!(0),
        serde_json::json!(0.0),
    ] {
        assert!(
            provider_error_message(&serde_json::json!({
                "error": value,
                "results": []
            }))
            .is_none()
        );
    }
    for value in [serde_json::json!(true), serde_json::json!(1)] {
        assert!(
            provider_error_message(&serde_json::json!({
                "error": value,
                "results": []
            }))
            .is_some()
        );
    }
    assert!(
        serde_json::from_value::<UrlscanResponse>(serde_json::json!({
            "message": "contract changed"
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<SubdomainAppResponse>(serde_json::json!({})).is_err());
}

#[test]
fn certspotter_rejects_empty_and_repeated_pagination_ids() {
    let page = vec![CertSpotterIssuance {
        id: "cursor-2".to_owned(),
        dns_names: vec!["api.example.com".to_owned()],
    }];
    assert_eq!(
        certspotter_next_after(&page, Some("cursor-1")).unwrap(),
        Some("cursor-2".to_owned())
    );
    assert!(certspotter_next_after(&page, Some("cursor-2")).is_err());

    let empty_id = vec![CertSpotterIssuance {
        id: " ".to_owned(),
        dns_names: Vec::new(),
    }];
    assert!(certspotter_next_after(&empty_id, None).is_err());
}

#[tokio::test]
async fn buffered_response_preserves_url_extensions_and_reuses_the_validated_body() {
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct FixtureExtension(u8);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2_048];
        let _ = socket.read(&mut request);
        socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .unwrap();
    });
    let requested_url = format!("http://{address}/kept?cursor=1");
    let mut response = build_client(Duration::from_secs(2))
        .unwrap()
        .get(&requested_url)
        .send()
        .await
        .unwrap();
    response.extensions_mut().insert(FixtureExtension(7));

    let response = buffer_external_response(response, 1_024).await.unwrap();
    assert_eq!(response.url().as_str(), requested_url);
    assert_eq!(
        response.extensions().get::<FixtureExtension>(),
        Some(&FixtureExtension(7))
    );
    assert!(
        response
            .extensions()
            .get::<BufferedExternalBody>()
            .is_some()
    );

    let (status, body) = response_bytes_limited_to(response, "fixture", 1_024)
        .await
        .unwrap();
    assert!(status.is_success());
    assert_eq!(body, br#"{"ok":true}"#);
    server.join().unwrap();
}

#[tokio::test]
async fn external_client_sends_transparent_identity_and_content_negotiation() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4_096];
        let read = socket.read(&mut request).unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")
            .unwrap();
        String::from_utf8_lossy(&request[..read]).to_ascii_lowercase()
    });
    let response = build_client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let request = server.join().unwrap();
    assert!(request.contains("user-agent: fellaga/"));
    assert!(request.contains("accept: application/json"));
    assert!(request.contains("accept-language: en-us"));
}

#[tokio::test]
async fn external_client_decompresses_gzip_before_json_validation() {
    const GZIP_EMPTY_ARRAY: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 139, 142, 5, 0, 41, 187, 76, 13, 2, 0, 0, 0,
    ];
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2_048];
        let _ = socket.read(&mut request);
        socket
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        GZIP_EMPTY_ARRAY.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
        socket.write_all(GZIP_EMPTY_ARRAY).unwrap();
    });
    let response = build_client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    let values = response_json::<Vec<serde_json::Value>>(response, "gzip-test")
        .await
        .unwrap();
    assert!(values.is_empty());
    server.join().unwrap();
}

#[tokio::test]
async fn oversized_external_responses_are_rejected_from_headers() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1_024];
        let _ = socket.read(&mut request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            MAX_EXTERNAL_BODY_BYTES + 1
        );
        socket.write_all(response.as_bytes()).unwrap();
    });
    let response = client(Duration::from_secs(2))
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    let error = response_text(response, "source-test")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("supérieure à 16 Mio"));
    server.join().unwrap();
}
