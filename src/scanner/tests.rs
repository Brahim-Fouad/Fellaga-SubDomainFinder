use super::refresh::*;
use super::{
    BatchDnsMode, RefreshOptions, ScanOptions, ScanRunGuard, Scanner,
    active_candidate_budget_exhausted, active_candidate_work_allowed, active_resume_required,
    assess_dnssec_suspects_bounded, automatic_bulk_source_limit, cache_requires_revalidation,
    candidate_refill_capacity, candidate_uses_active_budget, candidate_uses_discovery_fast_path,
    cap_exclusive_bulk_source_names, collect_dns_outcomes_until, consume_phase_budget,
    deferred_wildcard_signature, dnssec_assessment_proves_nonexistence,
    effective_passive_concurrency, external_deferral_seconds, external_pause_status,
    external_retry_after_seconds, finish_pending_ct_task,
    finish_pending_ct_task_after_grace_with_hook, high_value_window_needs_materialization,
    high_value_window_persist_limit, indeterminate_wildcard_signature, internetdb_cache_decision,
    is_missing_api_key_error, is_preflight_auth_error, late_ct_seed_reserve,
    materialize_ct_fallback_bounded, merge_ct_fallback_names, merge_passive_names_bounded,
    merge_resolver_metrics, metadata_phase_budget, passive_connector_timing,
    passive_connector_working_set_limit, persist_routed_dns_outcomes, phase_deadline,
    prioritized_answer_addresses, refill_passive_union_from_cache, route_dns_outcomes,
    select_bounded_mutation_observations, should_expand_adaptive_wave,
    should_retry_source_after_key_added, source_bootstrap_score, source_error_is_deferred,
    source_requires_api_key, unprofiled_deepest_parents, was_recently_verified,
    wildcard_cache_algorithm_is_current, wildcard_profile_after_probe, wildcard_profile_observed,
    wildcard_signature_is_deferred, wilson_upper_bound,
};
use crate::candidate::CandidateProposal;
use crate::db::{CachedAnswer, Database, IpHostnameCacheEntry};
use crate::dns::{DnsEngine, DnsResolutionOutcome, WildcardProbeOutcome};
use crate::dnssec_proof::{DnssecOwnerState, DnssecProofAssessment, DnssecProofKind};
use crate::model::{
    CtMonitorResult, DnsRecord, Finding, ObservationState, PipelineMetrics, ResolvedHost,
    ResolverMetric,
};
use hickory_net::proto::op::{Message, MessageType, ResponseCode};
use hickory_net::proto::rr::rdata::A;
use hickory_net::proto::rr::{RData, Record, RecordType};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn scanner_test_options(include_wildcard: bool) -> ScanOptions {
    ScanOptions {
        wordlist: None,
        mutation_rules: Vec::new(),
        max_words: 1,
        active_phase_timeout: Duration::from_secs(2),
        passive: false,
        passive_sources: Vec::new(),
        api_keys: crate::passive::ApiKeyStore::default(),
        automatic_source_selection: false,
        passive_refresh: Duration::from_secs(60),
        passive_phase_timeout: Duration::from_secs(1),
        passive_zone_concurrency: 1,
        passive_concurrency: 1,
        max_passive: 1,
        passive_only: false,
        no_target_contact: false,
        axfr: false,
        axfr_timeout: Duration::from_millis(100),
        refresh_cache: false,
        verification_max_age: Duration::from_secs(86_400),
        only_live: false,
        profile: "balanced".to_owned(),
        checkpoint_every: Duration::from_secs(30),
        resume: None,
        ttl_cap: 86_400,
        negative_ttl: 300,
        include_wildcard,
        wildcard_refresh: Duration::from_secs(300),
        recursive_depth: 0,
        recursive_words: 0,
        recursive_hosts: 0,
        adaptive: false,
        pipeline: false,
        pipeline_rounds: 0,
        pipeline_budget: 0,
        tls_certificates: false,
        tls_port: 443,
        tls_timeout: Duration::from_millis(100),
        tls_refresh: Duration::from_secs(300),
        tls_max_hosts: 0,
        tls_concurrency: 1,
        dns_graph: false,
        graph_max_hosts: 0,
        service_discovery: false,
        ptr_pivot: false,
        ptr_max_ips: 0,
        internetdb_pivot: false,
        internetdb_max_ips: 0,
        internetdb_phase_timeout: Duration::from_millis(100),
        internetdb_refresh: Duration::from_secs(86_400),
        dnssec_nsec: false,
        nsec_timeout: Duration::from_millis(100),
        nsec_refresh: Duration::from_secs(300),
        nsec_max_names: 0,
        nsec_phase_timeout: Duration::from_millis(100),
        ct_monitor: false,
        ct_timeout: Duration::from_millis(100),
        ct_phase_timeout: Duration::from_millis(100),
        ct_max_logs: 0,
        ct_entries_per_log: 0,
        ct_initial_backfill: 0,
        metadata_discovery: false,
        metadata_all_hosts: false,
        metadata_max_requests: 0,
        web_discovery: false,
        web_max_hosts: 0,
        web_timeout: Duration::from_millis(100),
        web_phase_timeout: Duration::from_millis(100),
        web_refresh: Duration::from_secs(300),
        web_concurrency: 1,
        web_max_bytes: 0,
        web_assets_per_host: 0,
    }
}

async fn wildcard_test_resolver() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        loop {
            let mut packet = [0_u8; 2_048];
            let Ok((length, peer)) = socket.recv_from(&mut packet).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut response = Message::from_vec(&packet[..length]).unwrap();
            let query = response.queries[0].clone();
            response.metadata.message_type = MessageType::Response;
            response.metadata.response_code = ResponseCode::NoError;
            response.metadata.recursion_available = true;
            if query.query_type() == RecordType::A {
                response.answers.push(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A("192.0.2.44".parse().unwrap())),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, requests, task)
}

#[tokio::test]
async fn scanner_scopes_no_target_contact_to_each_passive_fetch() {
    let database = Database::in_memory().unwrap();
    let dns = DnsEngine::new_with_rate(
        4,
        Duration::from_millis(50),
        &["127.0.0.1".parse().unwrap()],
        10,
    )
    .unwrap();
    let mut options = scanner_test_options(false);
    options.passive = true;
    options.passive_sources = vec!["crtsh".to_owned()];
    options.passive_refresh = Duration::ZERO;
    options.no_target_contact = true;
    options.max_passive = 10;
    let scanner = Scanner::new(database, dns, options);
    let mut sources = BTreeMap::new();
    let mut warnings = Vec::new();

    scanner
        .collect_passive(
            "crt.sh",
            "crt.sh",
            Some(tokio::time::Instant::now() + Duration::from_secs(1)),
            &mut sources,
            &mut warnings,
        )
        .await
        .unwrap();

    assert!(sources.is_empty());
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("no-target-contact"))
    );
}

#[tokio::test]
async fn no_target_contact_keeps_passive_names_unverified_without_dns() {
    let domain = "example.test";
    let fqdn = "api.example.test";
    let new_fqdn = "new.example.test";
    let database = Database::in_memory().unwrap();
    let previous_scan = database.create_scan(domain, &json!({})).unwrap();
    database
        .persist_findings(
            previous_scan,
            domain,
            &[Finding {
                fqdn: fqdn.to_owned(),
                records: vec![DnsRecord {
                    record_type: "A".to_owned(),
                    value: "192.0.2.44".to_owned(),
                    ttl: 60,
                }],
                sources: BTreeSet::from(["dns".to_owned()]),
                state: ObservationState::Live,
                last_verified_at: Some(1_234),
                evidence_families: BTreeSet::from([crate::model::EvidenceFamily::LiveDns]),
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
    database
        .finalize_scan(previous_scan, 1, 1, 0, 1, &[])
        .unwrap();
    database
        .store_passive_cache(domain, "crtsh", &[fqdn.to_owned(), new_fqdn.to_owned()])
        .unwrap();
    let (resolver_address, requests, resolver_task) = wildcard_test_resolver().await;
    let (trusted_address, trusted_requests, trusted_task) = wildcard_test_resolver().await;
    let dns =
        DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[resolver_address], 0)
            .unwrap();
    let trusted_dns =
        DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[trusted_address], 0)
            .unwrap();
    let mut options = scanner_test_options(false);
    options.passive = true;
    options.passive_sources = vec!["crtsh".to_owned()];
    options.max_passive = 10;
    options.passive_only = true;
    options.no_target_contact = true;
    options.profile = "passive".to_owned();
    options.ct_monitor = true;
    // The core barrier must remain safe even if a library caller leaves
    // active feature flags enabled instead of going through CLI policy.
    options.axfr = true;
    options.pipeline = true;
    options.tls_certificates = true;
    options.dns_graph = true;
    options.service_discovery = true;
    options.ptr_pivot = true;
    options.dnssec_nsec = true;
    options.metadata_discovery = true;
    options.web_discovery = true;

    let result = Scanner::new(database.clone(), dns, options)
        .with_trusted_dns(trusted_dns)
        .scan(domain)
        .await
        .unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(trusted_requests.load(Ordering::SeqCst), 0);
    assert_eq!(result.resolved_from_network, 0);
    assert_eq!(result.scheduler_metrics.dns_queries, 0);
    assert_eq!(
        result
            .resolver_metrics
            .iter()
            .map(|metric| metric.requests)
            .sum::<u64>(),
        0
    );
    assert_eq!(result.findings.len(), 2);
    let finding = result
        .findings
        .iter()
        .find(|finding| finding.fqdn == fqdn)
        .unwrap();
    assert_eq!(finding.fqdn, fqdn);
    assert_eq!(finding.state, ObservationState::Unverified);
    assert!(finding.records.is_empty());
    assert!(!finding.wildcard);
    assert_eq!(
        finding.wildcard_verdict,
        crate::model::WildcardVerdict::NotProfiled
    );
    assert!(!finding.authoritative_validation);
    assert!(finding.owner_proofs.is_empty());
    assert_eq!(
        finding.generation_path,
        vec!["passive_provider_only".to_owned()]
    );

    assert_eq!(result.ct_monitor.logs_checked, 0);
    assert_eq!(result.ct_monitor.entries_processed, 0);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| { warning.contains("direct CT-log collection disabled") })
    );

    let inventory = database
        .inventory(Some(domain), false)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.fqdn.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(inventory.len(), 2);
    assert_eq!(inventory[fqdn].state, ObservationState::Live);
    assert_eq!(inventory[fqdn].last_verified_at, Some(1_234));
    assert!(inventory[fqdn].sources.contains("dns"));
    assert!(
        inventory[fqdn]
            .sources
            .iter()
            .any(|source| source.contains("crtsh"))
    );
    assert_eq!(inventory[new_fqdn].state, ObservationState::Unverified);
    assert_eq!(inventory[new_fqdn].last_verified_at, None);
    let explanation = database.explain(fqdn).unwrap();
    assert_eq!(explanation["inventory"]["state"], "live");
    assert_eq!(explanation["inventory"]["last_verified_at"], 1_234);
    assert!(
        explanation["dns_records"]
            .as_array()
            .is_some_and(|records| records.iter().any(|record| record["active"] == true))
    );
    assert!(
        explanation["evidence"]
            .as_array()
            .is_some_and(|observations| observations.iter().any(|observation| {
                observation["source"]
                    .as_str()
                    .is_some_and(|source| source.contains("crtsh"))
            }))
    );
    resolver_task.abort();
    trusted_task.abort();
}

#[tokio::test]
async fn unavailable_library_source_uses_cache_without_health_or_network_attempt() {
    let domain = "example.test";
    let fqdn = "legacy.example.test";
    let database = Database::in_memory().unwrap();
    database
        .store_passive_cache(domain, "binaryedge", &[fqdn.to_owned()])
        .unwrap();
    let (resolver_address, requests, resolver_task) = wildcard_test_resolver().await;
    let dns =
        DnsEngine::new_with_socket_addresses(4, Duration::from_millis(100), &[resolver_address], 0)
            .unwrap();
    let mut options = scanner_test_options(false);
    options.passive = true;
    options.passive_sources = vec!["binaryedge".to_owned()];
    options.max_passive = 10;
    options.passive_only = true;
    options.no_target_contact = true;
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    let result = Scanner::new(database.clone(), dns, options)
        .with_progress(Arc::new(move |event| captured.lock().unwrap().push(event)))
        .scan(domain)
        .await
        .unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].fqdn, fqdn);
    assert_eq!(result.findings[0].state, ObservationState::Unverified);
    assert!(
        !database
            .source_diagnostics(Duration::from_secs(86_400))
            .unwrap()
            .contains_key("binaryedge"),
        "an unavailable connector must not alter provider health counters"
    );
    assert!(events.lock().unwrap().iter().any(|event| matches!(
        event,
        super::ProgressEvent::PassiveSource {
            source,
            outcome,
            status,
            names,
        }
            if source == "binaryedge"
                && *outcome == super::PassiveSourceOutcome::Skipped
                && status.contains("indisponible")
                && !status.contains("clé API")
                && *names == 1
    )));
    resolver_task.abort();
}

fn proven_dnssec_denial(kind: DnssecProofKind) -> DnssecProofAssessment {
    DnssecProofAssessment {
        state: DnssecOwnerState::DoesNotExist,
        proofs: BTreeSet::from([kind]),
        ..DnssecProofAssessment::default()
    }
}

#[tokio::test]
async fn confirmed_wildcard_revalidates_fresh_cache_and_never_restores_live_state() {
    for include_wildcard in [false, true] {
        let (primary_address, primary_requests, primary_task) = wildcard_test_resolver().await;
        let (trusted_one, _, trusted_one_task) = wildcard_test_resolver().await;
        let (trusted_two, _, trusted_two_task) = wildcard_test_resolver().await;
        let primary = DnsEngine::new_with_socket_addresses(
            8,
            Duration::from_millis(250),
            &[primary_address],
            0,
        )
        .unwrap();
        let trusted = DnsEngine::new_with_socket_addresses(
            8,
            Duration::from_millis(250),
            &[trusted_one, trusted_two],
            0,
        )
        .unwrap();
        let database = Database::in_memory().unwrap();
        let domain = "example.com";
        let fqdn = "cached-wildcard.example.com".to_owned();
        let cached_answer = ResolvedHost {
            fqdn: fqdn.clone(),
            records: vec![DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.44".to_owned(),
                ttl: 60,
            }],
            from_cache: false,
            last_verified_at: Some(crate::util::now_epoch()),
            authoritative_validation: false,
            resolver_count: 2,
        };
        let seed_scan = database
            .create_scan(domain, &json!({"seed": true}))
            .unwrap();
        database
            .persist_findings(
                seed_scan,
                domain,
                &[Finding {
                    fqdn: fqdn.clone(),
                    records: cached_answer.records.clone(),
                    sources: BTreeSet::from(["dns:seed".to_owned()]),
                    state: ObservationState::Live,
                    last_verified_at: cached_answer.last_verified_at,
                    ..Finding::default()
                }],
                86_400,
            )
            .unwrap();
        database
            .update_cache_outcomes(
                Some(seed_scan),
                std::slice::from_ref(&cached_answer),
                &[],
                &[],
                300,
            )
            .unwrap();
        let scan_id = database
            .create_scan(domain, &json!({"include_wildcard": include_wildcard}))
            .unwrap();
        let scanner = Scanner::new(
            database.clone(),
            primary,
            scanner_test_options(include_wildcard),
        )
        .with_trusted_dns(trusted);
        let sources = BTreeMap::from([(fqdn.clone(), BTreeSet::from(["dns-wave-1".to_owned()]))]);
        let root_wildcard = BTreeSet::from(["A:192.0.2.44".to_owned()]);
        let wildcard_by_parent = BTreeMap::from([(domain.to_owned(), root_wildcard.clone())]);
        let reliable_wildcard_zones = BTreeSet::from([domain.to_owned()]);

        let result = scanner
            .resolve_batch_with_deadline(
                scan_id,
                domain,
                std::slice::from_ref(&fqdn),
                "wildcard regression",
                &Instant::now(),
                &sources,
                &root_wildcard,
                &HashMap::new(),
                &wildcard_by_parent,
                &reliable_wildcard_zones,
                Some(tokio::time::Instant::now() + Duration::from_secs(2)),
                BatchDnsMode::Conservative,
            )
            .await
            .unwrap();

        assert_eq!(result.cache_hits, 0, "include_wildcard={include_wildcard}");
        assert!(
            primary_requests.load(Ordering::SeqCst) > 0,
            "the fresh wildcard-shaped cache entry bypassed network revalidation"
        );
        assert_eq!(
            result.answers.iter().any(|answer| answer.fqdn == fqdn),
            include_wildcard,
            "include_wildcard must affect output only"
        );
        assert!(
            !database
                .fresh_cache(std::slice::from_ref(&fqdn))
                .unwrap()
                .contains_key(&fqdn),
            "a current wildcard match remained reusable in dns_cache"
        );
        assert!(database.inventory(Some(domain), false).unwrap().is_empty());
        assert!(
            database
                .live_scan_finding_names(scan_id)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            database.explain(&fqdn).unwrap()["quarantine"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        primary_task.abort();
        trusted_one_task.abort();
        trusted_two_task.abort();
    }
}

#[tokio::test]
async fn stale_wildcard_guard_never_authorizes_destructive_purge() {
    let (primary_address, _, primary_task) = wildcard_test_resolver().await;
    let (trusted_one, _, trusted_one_task) = wildcard_test_resolver().await;
    let (trusted_two, _, trusted_two_task) = wildcard_test_resolver().await;
    let primary =
        DnsEngine::new_with_socket_addresses(8, Duration::from_millis(250), &[primary_address], 0)
            .unwrap();
    let trusted = DnsEngine::new_with_socket_addresses(
        8,
        Duration::from_millis(250),
        &[trusted_one, trusted_two],
        0,
    )
    .unwrap();
    let database = Database::in_memory().unwrap();
    let domain = "example.com";
    let fqdn = "legitimate.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(crate::util::now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let seed_scan = database
        .create_scan(domain, &json!({"seed": true}))
        .unwrap();
    database
        .persist_findings(
            seed_scan,
            domain,
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records.clone(),
                sources: BTreeSet::from(["dns:seed".to_owned()]),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
    database
        .update_cache_outcomes(
            Some(seed_scan),
            std::slice::from_ref(&answer),
            &[],
            &[],
            300,
        )
        .unwrap();

    let signature = BTreeSet::from(["A:192.0.2.44".to_owned()]);
    let observation =
        wildcard_profile_after_probe(Some(signature.clone()), WildcardProbeOutcome::Indeterminate);
    assert!(!observation.current_probe_reliable);
    let root_wildcard = observation.signature.unwrap();
    let wildcard_by_parent = BTreeMap::from([(domain.to_owned(), root_wildcard.clone())]);
    let reliable_wildcard_zones = BTreeSet::new();
    let scan_id = database
        .create_scan(domain, &json!({"stale": true}))
        .unwrap();
    let sources = BTreeMap::from([(fqdn.clone(), BTreeSet::from(["dns:cache".to_owned()]))]);
    let scanner = Scanner::new(database.clone(), primary, scanner_test_options(false))
        .with_trusted_dns(trusted);
    let result = scanner
        .resolve_batch_with_deadline(
            scan_id,
            domain,
            std::slice::from_ref(&fqdn),
            "stale wildcard guard regression",
            &Instant::now(),
            &sources,
            &root_wildcard,
            &HashMap::new(),
            &wildcard_by_parent,
            &reliable_wildcard_zones,
            Some(tokio::time::Instant::now() + Duration::from_secs(2)),
            BatchDnsMode::Conservative,
        )
        .await
        .unwrap();

    assert!(result.answers.is_empty());
    assert!(matches!(
        database.fresh_cache(std::slice::from_ref(&fqdn)).unwrap()[&fqdn],
        CachedAnswer::Positive(_)
    ));
    let inventory = database.inventory(Some(domain), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Live);
    assert_eq!(
        database.explain(&fqdn).unwrap()["quarantine"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    primary_task.abort();
    trusted_one_task.abort();
    trusted_two_task.abort();
}

#[tokio::test]
async fn indeterminate_wildcard_profile_preserves_fresh_cache_and_live_inventory() {
    let (address, requests, server_task) = wildcard_test_resolver().await;
    let primary =
        DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[address], 0).unwrap();
    let trusted =
        DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[address], 0).unwrap();
    let database = Database::in_memory().unwrap();
    let domain = "example.com";
    let fqdn = "cached-indeterminate.example.com".to_owned();
    let answer = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(crate::util::now_epoch()),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let seed_scan = database
        .create_scan(domain, &json!({"seed": true}))
        .unwrap();
    database
        .persist_findings(
            seed_scan,
            domain,
            &[Finding {
                fqdn: fqdn.clone(),
                records: answer.records.clone(),
                sources: BTreeSet::from(["dns:seed".to_owned()]),
                state: ObservationState::Live,
                last_verified_at: answer.last_verified_at,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
    database
        .update_cache_outcomes(
            Some(seed_scan),
            std::slice::from_ref(&answer),
            &[],
            &[],
            300,
        )
        .unwrap();
    let scan_id = database
        .create_scan(domain, &json!({"indeterminate": true}))
        .unwrap();
    let scanner = Scanner::new(database.clone(), primary, scanner_test_options(false))
        .with_trusted_dns(trusted);
    let sources = BTreeMap::from([(fqdn.clone(), BTreeSet::from(["dns:cache".to_owned()]))]);
    let scan_started = Instant::now();
    let root_wildcard = indeterminate_wildcard_signature();
    let result = scanner
        .resolve_batch_with_deadline(
            scan_id,
            domain,
            std::slice::from_ref(&fqdn),
            "indeterminate wildcard regression",
            &scan_started,
            &sources,
            &root_wildcard,
            &HashMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            Some(tokio::time::Instant::now() + Duration::from_secs(1)),
            BatchDnsMode::Conservative,
        )
        .await
        .unwrap();

    assert_eq!(result.cache_hits, 1);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    // Without --include-wildcard an indeterminate cached name may stay
    // hidden from this scan, but its durable state must remain untouched.
    assert!(result.answers.is_empty());
    assert!(matches!(
        database
            .fresh_cache(std::slice::from_ref(&fqdn))
            .unwrap()
            .get(&fqdn),
        Some(crate::db::CachedAnswer::Positive(_))
    ));
    let inventory = database.inventory(Some(domain), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Live);
    assert!(
        database.explain(&fqdn).unwrap()["quarantine"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let insufficient = "single-resolver-wildcard.example.com".to_owned();
    let insufficient_answer = ResolvedHost {
        fqdn: insufficient.clone(),
        records: [
            answer.records.clone(),
            vec![DnsRecord {
                record_type: "CNAME".to_owned(),
                value: "legacy.example.net".to_owned(),
                ttl: 60,
            }],
        ]
        .concat(),
        ..answer.clone()
    };
    database
        .persist_findings(
            seed_scan,
            domain,
            &[Finding {
                fqdn: insufficient.clone(),
                records: insufficient_answer.records.clone(),
                sources: BTreeSet::from(["dns:seed".to_owned()]),
                state: ObservationState::Live,
                last_verified_at: insufficient_answer.last_verified_at,
                ..Finding::default()
            }],
            86_400,
        )
        .unwrap();
    database
        .update_cache_outcomes(
            Some(seed_scan),
            std::slice::from_ref(&insufficient_answer),
            &[],
            &[],
            300,
        )
        .unwrap();
    let insufficient_scan = database
        .create_scan(domain, &json!({"trusted": false}))
        .unwrap();
    let primary =
        DnsEngine::new_with_socket_addresses(4, Duration::from_millis(250), &[address], 0).unwrap();
    let scanner = Scanner::new(database.clone(), primary, scanner_test_options(true));
    let sources = BTreeMap::from([(
        insufficient.clone(),
        BTreeSet::from(["dns:cache".to_owned()]),
    )]);
    let before_requests = requests.load(Ordering::SeqCst);
    let scan_started = Instant::now();
    let root_wildcard = BTreeSet::from(["A:192.0.2.44".to_owned()]);
    let wildcard_by_parent = BTreeMap::from([(domain.to_owned(), root_wildcard.clone())]);
    let reliable_wildcard_zones = BTreeSet::from([domain.to_owned()]);
    let result = scanner
        .resolve_batch_with_deadline(
            insufficient_scan,
            domain,
            std::slice::from_ref(&insufficient),
            "single resolver wildcard regression",
            &scan_started,
            &sources,
            &root_wildcard,
            &HashMap::new(),
            &wildcard_by_parent,
            &reliable_wildcard_zones,
            Some(tokio::time::Instant::now() + Duration::from_secs(1)),
            BatchDnsMode::Conservative,
        )
        .await
        .unwrap();
    assert_eq!(result.cache_hits, 0);
    assert!(requests.load(Ordering::SeqCst) > before_requests);
    assert!(result.answers.is_empty());
    database
        .persist_scan_snapshot(
            insufficient_scan,
            &[Finding {
                fqdn: insufficient.clone(),
                records: insufficient_answer.records.clone(),
                sources: BTreeSet::from(["dns:single-resolver-audit".to_owned()]),
                wildcard: true,
                state: ObservationState::Unverified,
                ..Finding::default()
            }],
        )
        .unwrap();
    assert!(matches!(
        database
            .fresh_cache(std::slice::from_ref(&insufficient))
            .unwrap()
            .get(&insufficient),
        Some(crate::db::CachedAnswer::Positive(_))
    ));
    assert!(
        database
            .inventory(Some(domain), false)
            .unwrap()
            .iter()
            .any(|entry| entry.fqdn == insufficient && entry.state == ObservationState::Live)
    );
    assert!(
        database.explain(&insufficient).unwrap()["quarantine"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    server_task.abort();
}

#[test]
fn resolver_cost_metrics_include_primary_and_trusted_engines() {
    let metrics = merge_resolver_metrics(
        vec![ResolverMetric {
            resolver: "1.1.1.1".to_owned(),
            requests: 2,
            successes: 2,
            failures: 0,
            average_ms: 10,
            consecutive_failures: 0,
        }],
        vec![ResolverMetric {
            resolver: "1.1.1.1".to_owned(),
            requests: 1,
            successes: 0,
            failures: 1,
            average_ms: 40,
            consecutive_failures: 1,
        }],
    );
    assert_eq!(metrics.len(), 1);
    assert_eq!(metrics[0].requests, 3);
    assert_eq!(metrics[0].successes, 2);
    assert_eq!(metrics[0].failures, 1);
    assert_eq!(metrics[0].average_ms, 20);
    assert_eq!(metrics[0].consecutive_failures, 1);
}

#[test]
fn metadata_is_unlimited_with_the_web_phase_and_caps_explicit_budgets() {
    assert_eq!(metadata_phase_budget(None), None);
    assert_eq!(
        metadata_phase_budget(Some(Duration::from_secs(90))),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        metadata_phase_budget(Some(Duration::from_secs(7))),
        Some(Duration::from_secs(7))
    );
    assert_eq!(
        metadata_phase_budget(Some(Duration::ZERO)),
        Some(Duration::ZERO)
    );
}

#[test]
fn unlimited_passive_phase_disables_only_the_connector_cumulative_deadline() {
    let request_timeout = Duration::from_secs(10);
    let policy_total_timeout = Duration::from_secs(45);
    let (connector_budget, lease_ttl) =
        passive_connector_timing(None, request_timeout, policy_total_timeout);

    assert_eq!(connector_budget, Duration::ZERO);
    assert_eq!(
        lease_ttl,
        policy_total_timeout + super::PASSIVE_REFRESH_LEASE_GRACE
    );

    let (expired_budget, _) = passive_connector_timing(
        Some(tokio::time::Instant::now() - Duration::from_secs(1)),
        request_timeout,
        policy_total_timeout,
    );
    assert_eq!(expired_budget, Duration::ZERO);
}

#[test]
fn dnssec_quarantine_requires_a_concrete_local_denial_proof() {
    let state_only = DnssecProofAssessment {
        state: DnssecOwnerState::DoesNotExist,
        ..DnssecProofAssessment::default()
    };
    assert!(!dnssec_assessment_proves_nonexistence(&state_only));
    assert!(dnssec_assessment_proves_nonexistence(
        &proven_dnssec_denial(DnssecProofKind::NxnameNsec)
    ));
    assert!(dnssec_assessment_proves_nonexistence(
        &proven_dnssec_denial(DnssecProofKind::NxnameNsec3)
    ));
    assert!(dnssec_assessment_proves_nonexistence(
        &proven_dnssec_denial(DnssecProofKind::NsecRangeDenial)
    ));
    assert!(!dnssec_assessment_proves_nonexistence(
        &proven_dnssec_denial(DnssecProofKind::Nsec3RangeDenial)
    ));
    let ent = DnssecProofAssessment {
        state: DnssecOwnerState::EmptyNonTerminal,
        proofs: BTreeSet::from([DnssecProofKind::EmptyNonTerminal]),
        ..DnssecProofAssessment::default()
    };
    assert!(!dnssec_assessment_proves_nonexistence(&ent));
}

#[tokio::test]
async fn dnssec_suspect_assessment_is_parallel_scoped_and_capped_at_four() {
    let calls = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let maximum_in_flight = Arc::new(AtomicUsize::new(0));
    let mut suspects = (0..8)
        .rev()
        .map(|index| format!("host-{index:02}.example.com"))
        .collect::<Vec<_>>();
    suspects.extend([
        "HOST-00.EXAMPLE.COM.".to_owned(),
        "outside.test".to_owned(),
        "example.com".to_owned(),
    ]);

    let nonexistent = assess_dnssec_suspects_bounded(
        "example.com",
        suspects,
        Some(tokio::time::Instant::now() + Duration::from_secs(1)),
        {
            let calls = Arc::clone(&calls);
            let in_flight = Arc::clone(&in_flight);
            let maximum_in_flight = Arc::clone(&maximum_in_flight);
            move |fqdn| {
                let calls = Arc::clone(&calls);
                let in_flight = Arc::clone(&in_flight);
                let maximum_in_flight = Arc::clone(&maximum_in_flight);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_in_flight.fetch_max(current, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    if fqdn.starts_with("host-00") {
                        proven_dnssec_denial(DnssecProofKind::NxnameNsec)
                    } else if fqdn.starts_with("host-01") {
                        // A state without locally validated proof material
                        // must not authorize quarantine (including AD-only).
                        DnssecProofAssessment {
                            state: DnssecOwnerState::DoesNotExist,
                            ..DnssecProofAssessment::default()
                        }
                    } else if fqdn.starts_with("host-03") {
                        proven_dnssec_denial(DnssecProofKind::NsecRangeDenial)
                    } else {
                        DnssecProofAssessment::default()
                    }
                }
            }
        },
    )
    .await;

    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(maximum_in_flight.load(Ordering::SeqCst) > 1);
    assert_eq!(
        nonexistent,
        BTreeSet::from([
            "host-00.example.com".to_owned(),
            "host-03.example.com".to_owned(),
        ])
    );
}

#[tokio::test]
async fn dnssec_suspect_assessment_uses_one_absolute_deadline() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();
    let nonexistent = assess_dnssec_suspects_bounded(
        "example.com",
        (0..8).map(|index| format!("slow-{index}.example.com")),
        Some(tokio::time::Instant::now() + Duration::from_millis(35)),
        {
            let calls = Arc::clone(&calls);
            move |_fqdn| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    proven_dnssec_denial(DnssecProofKind::NxnameNsec3)
                }
            }
        },
    )
    .await;

    assert!(nonexistent.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(
        started.elapsed() < Duration::from_millis(150),
        "les évaluations ont reçu des deadlines individuelles"
    );
}

#[tokio::test]
async fn dnssec_suspect_assessment_has_no_hidden_cumulative_deadline() {
    let nonexistent = assess_dnssec_suspects_bounded(
        "example.com",
        ["wild.example.com".to_owned()],
        None,
        |_fqdn| async {
            tokio::time::sleep(Duration::from_millis(15)).await;
            proven_dnssec_denial(DnssecProofKind::NxnameNsec)
        },
    )
    .await;

    assert_eq!(nonexistent, BTreeSet::from(["wild.example.com".to_owned()]));
}

#[test]
fn dnssec_quarantine_purges_only_proven_name_and_preserves_audit() {
    let database = Database::in_memory().unwrap();
    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    let make_finding = |fqdn: &str| Finding {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        sources: BTreeSet::from(["dns-wave-1".to_owned()]),
        state: ObservationState::Live,
        last_verified_at: Some(1),
        ..Finding::default()
    };
    let proven = "proven.example.com";
    let retained = "retained.example.com";
    database
        .persist_findings(
            scan_id,
            "example.com",
            &[make_finding(proven), make_finding(retained)],
            86_400,
        )
        .unwrap();
    let cached = [proven, retained]
        .into_iter()
        .map(|fqdn| ResolvedHost {
            fqdn: fqdn.to_owned(),
            records: make_finding(fqdn).records,
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 2,
        })
        .collect::<Vec<_>>();
    database
        .update_cache_outcomes(Some(scan_id), &cached, &[], &[], 300)
        .unwrap();

    assert_eq!(
        database
            .quarantine_dnssec_nonexistent(scan_id, "example.com", &[proven.to_owned()])
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .inventory(Some("example.com"), false)
            .unwrap()
            .into_iter()
            .map(|entry| entry.fqdn)
            .collect::<Vec<_>>(),
        vec![retained]
    );
    let cache = database
        .fresh_cache(&[proven.to_owned(), retained.to_owned()])
        .unwrap();
    assert!(!cache.contains_key(proven));
    assert!(cache.contains_key(retained));
    let explanation = database.explain(proven).unwrap();
    assert_eq!(
        explanation["quarantine"][0]["reason"],
        "dnssec_validated_nonexistence"
    );
    assert!(
        explanation["dns_verifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|verification| {
                verification["outcome"] == "negative"
                    && verification["details"]["reason"] == "dnssec_validated_nonexistence"
            })
    );
    assert_eq!(explanation["scan_history"].as_array().unwrap().len(), 1);
}

#[test]
fn ct_error_fallback_merges_indexed_and_cached_names_in_scope() {
    assert_eq!(
        merge_ct_fallback_names(
            "example.com",
            vec![
                "api.example.com".to_owned(),
                "shared.example.com".to_owned(),
                "outside.test".to_owned(),
            ],
            vec![
                "cached.example.com".to_owned(),
                "SHARED.EXAMPLE.COM.".to_owned(),
            ],
        ),
        vec![
            "api.example.com".to_owned(),
            "cached.example.com".to_owned(),
            "shared.example.com".to_owned(),
        ]
    );
}

#[test]
fn ct_error_fallback_is_read_only_and_respects_max_passive() {
    let db = Database::in_memory().unwrap();
    let names = (0..500)
        .map(|index| format!("host-{index:04}.example.com"))
        .collect::<BTreeSet<_>>();
    db.store_ct_global_batch("https://ct.example/log/", 500, &names)
        .unwrap();

    let recovered = materialize_ct_fallback_bounded(&db, "example.com", 23).unwrap();

    assert_eq!(recovered.len(), 23);
    assert_eq!(
        db.ct_names_for_domain("example.com", 1_000).unwrap().len(),
        500
    );
    assert!(
        db.observation_names("example.com", "passive:ct-direct")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn late_ct_reserve_is_bounded_and_old_wildcard_caches_are_rejected() {
    assert_eq!(late_ct_seed_reserve(10_000, true), 2_000);
    assert_eq!(late_ct_seed_reserve(100, true), 20);
    assert_eq!(late_ct_seed_reserve(100, false), 0);
    assert!(!wildcard_cache_algorithm_is_current(3, 5));
    assert!(wildcard_cache_algorithm_is_current(5, 5));
}

#[tokio::test]
async fn final_ct_drain_preserves_a_result_completed_in_the_abort_race() {
    let mut tasks = tokio::task::JoinSet::new();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        release_rx.await.unwrap();
        let result = CtMonitorResult {
            entries_processed: 7,
            names: BTreeSet::from(["late.example.com".to_owned()]),
            ..CtMonitorResult::default()
        };
        let _ = completed_tx.send(());
        Ok((result, vec!["late warning".to_owned()]))
    });

    let (joined, aborted_without_result) =
        finish_pending_ct_task_after_grace_with_hook(&mut tasks, Duration::ZERO, async move {
            release_tx.send(()).unwrap();
            completed_rx.await.unwrap();
        })
        .await;

    assert!(!aborted_without_result);
    let (result, warnings) = joined.unwrap().unwrap().unwrap();
    assert_eq!(result.entries_processed, 7);
    assert!(result.names.contains("late.example.com"));
    assert_eq!(warnings, vec!["late warning"]);
}

#[tokio::test]
async fn unlimited_ct_drain_waits_for_structurally_bounded_completion() {
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok((
            CtMonitorResult {
                entries_processed: 11,
                names: BTreeSet::from(["complete.example.com".to_owned()]),
                ..CtMonitorResult::default()
            },
            Vec::new(),
        ))
    });

    let (joined, aborted_without_result) = finish_pending_ct_task(&mut tasks, None).await;

    assert!(!aborted_without_result);
    let (result, warnings) = joined.unwrap().unwrap().unwrap();
    assert_eq!(result.entries_processed, 11);
    assert!(result.names.contains("complete.example.com"));
    assert!(warnings.is_empty());
}

#[test]
fn final_seed_materialization_hides_negative_and_quarantined_names_from_scan_json() {
    let database = Database::in_memory().unwrap();
    let domain = "example.com";
    let allowed = "allowed.example.com".to_owned();
    let negative = "negative.example.com".to_owned();
    let quarantined = "quarantined.example.com".to_owned();
    let scan_id = database.create_scan(domain, &json!({})).unwrap();
    database
        .record_discovery_negatives(scan_id, std::slice::from_ref(&negative))
        .unwrap();
    database
        .quarantine_dnssec_nonexistent(scan_id, domain, std::slice::from_ref(&quarantined))
        .unwrap();
    let sources = BTreeMap::from([
        (allowed.clone(), BTreeSet::from(["passive:test".to_owned()])),
        (
            negative.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
        ),
        (
            quarantined.clone(),
            BTreeSet::from(["passive:test".to_owned()]),
        ),
    ]);
    let dns = DnsEngine::new_with_rate(
        4,
        Duration::from_millis(50),
        &["127.0.0.1".parse().unwrap()],
        10,
    )
    .unwrap();
    let scanner = Scanner::new(database.clone(), dns, scanner_test_options(false));

    let result = scanner
        .finalize_no_target_contact_scan(
            scan_id,
            domain,
            Instant::now(),
            sources,
            CtMonitorResult::default(),
            PipelineMetrics::default(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

    assert_eq!(
        result
            .findings
            .iter()
            .map(|finding| finding.fqdn.as_str())
            .collect::<Vec<_>>(),
        vec![allowed.as_str()]
    );
    let audit = database.inventory(Some(domain), false).unwrap();
    assert_eq!(audit.len(), 2);
    assert!(audit.iter().any(|entry| entry.fqdn == negative));
    assert!(audit.iter().all(|entry| entry.fqdn != quarantined));
    assert_eq!(
        database.explain(&negative).unwrap()["dns_verifications"][0]["outcome"],
        "negative"
    );
    assert_eq!(
        database.explain(&quarantined).unwrap()["quarantine"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn automatic_anubis_guard_caps_only_source_exclusive_names() {
    assert_eq!(automatic_bulk_source_limit(25_000), 2_500);
    let mut sources = BTreeMap::from([
        (
            "a.example.com".to_owned(),
            BTreeSet::from(["passive:anubisdb".to_owned()]),
        ),
        (
            "b.example.com".to_owned(),
            BTreeSet::from(["passive:anubisdb:partial".to_owned()]),
        ),
        (
            "trusted.example.com".to_owned(),
            BTreeSet::from([
                "passive:anubisdb".to_owned(),
                "passive:certspotter".to_owned(),
            ]),
        ),
    ]);
    let (before, kept) =
        cap_exclusive_bulk_source_names("example.com", &mut sources, "passive:anubisdb", 1);
    assert_eq!((before, kept), (2, 1));
    assert_eq!(sources.len(), 2);
    assert!(sources.contains_key("trusted.example.com"));
}

#[test]
fn passive_union_cap_keeps_existing_multi_source_provenance() {
    assert_eq!(passive_connector_working_set_limit(25_000, 8), 3_125);
    let mut sources = BTreeMap::new();
    assert_eq!(
        merge_passive_names_bounded(
            &mut sources,
            [
                "one.example.com".to_owned(),
                "shared.example.com".to_owned()
            ],
            "passive:first".to_owned(),
            2,
        ),
        0
    );
    assert_eq!(
        merge_passive_names_bounded(
            &mut sources,
            [
                "shared.example.com".to_owned(),
                "two.example.com".to_owned()
            ],
            "passive:second".to_owned(),
            2,
        ),
        1
    );
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources.get("shared.example.com"),
        Some(&BTreeSet::from([
            "passive:first".to_owned(),
            "passive:second".to_owned(),
        ]))
    );
    assert!(!sources.contains_key("two.example.com"));
}

#[test]
fn passive_scheduler_honors_full_cli_range_and_partitions_memory() {
    assert_eq!(effective_passive_concurrency(0), 1);
    assert_eq!(effective_passive_concurrency(8), 8);
    assert_eq!(effective_passive_concurrency(16), 16);
    assert_eq!(effective_passive_concurrency(32), 32);
    assert_eq!(effective_passive_concurrency(64), 32);

    assert_eq!(passive_connector_working_set_limit(25_000, 8), 3_125);
    assert_eq!(passive_connector_working_set_limit(25_000, 16), 1_563);
    assert_eq!(passive_connector_working_set_limit(25_000, 32), 782);
}

#[test]
fn durable_passive_refill_recovers_coverage_beyond_the_connector_cap() {
    let db = Database::in_memory().unwrap();
    let all_names = (0..20)
        .map(|index| format!("host-{index:02}.example.com"))
        .collect::<BTreeSet<_>>();
    db.store_passive_observation_page("example.com", "fixture", &all_names)
        .unwrap();
    let mut sources = all_names
        .iter()
        .take(3)
        .cloned()
        .map(|name| (name, BTreeSet::from(["passive:fixture".to_owned()])))
        .collect::<BTreeMap<_, _>>();

    let added = refill_passive_union_from_cache(
        &db,
        "example.com",
        &["fixture".to_owned()],
        &mut sources,
        10,
    )
    .unwrap();

    assert_eq!(added, 7);
    assert_eq!(sources.len(), 10);
    assert_eq!(
        sources.get("host-00.example.com"),
        Some(&BTreeSet::from(["passive:fixture".to_owned()]))
    );
    assert_eq!(
        db.passive_cache("example.com", "fixture")
            .unwrap()
            .unwrap()
            .names
            .len(),
        20
    );
}

#[test]
fn deferred_child_wildcard_parents_are_retryable_but_failed_probes_are_not() {
    let parent_by_host = HashMap::from([
        (
            "a.prod.example.com".to_owned(),
            "prod.example.com".to_owned(),
        ),
        ("b.dev.example.com".to_owned(), "dev.example.com".to_owned()),
    ]);
    let profiled = BTreeMap::new();
    let selected = BTreeSet::from(["prod.example.com".to_owned()]);
    assert_eq!(
        unprofiled_deepest_parents(parent_by_host.values().cloned(), &profiled, &selected),
        BTreeSet::from(["dev.example.com".to_owned()])
    );

    let retryable_profiled = BTreeMap::from([
        ("dev.example.com".to_owned(), deferred_wildcard_signature()),
        ("prod.example.com".to_owned(), BTreeSet::new()),
    ]);
    assert_eq!(
        unprofiled_deepest_parents(
            parent_by_host.values().cloned(),
            &retryable_profiled,
            &BTreeSet::new(),
        ),
        BTreeSet::from(["dev.example.com".to_owned()]),
        "a deferred indeterminate parent must remain eligible for a later batch"
    );

    let failed_profile = BTreeMap::from([(
        "dev.example.com".to_owned(),
        indeterminate_wildcard_signature(),
    )]);
    assert!(
        !unprofiled_deepest_parents(
            parent_by_host.values().cloned(),
            &failed_profile,
            &BTreeSet::new(),
        )
        .contains("dev.example.com"),
        "a completed but indeterminate probe must not be repeated in every wave"
    );
}

#[tokio::test]
async fn wildcard_parent_batch_truncation_is_retryable_without_a_deadline_failure() {
    let (address, _, server) = wildcard_test_resolver().await;
    let database = Database::in_memory().unwrap();
    let dns =
        DnsEngine::new_with_socket_addresses(128, Duration::from_secs(1), &[address], 0).unwrap();
    let scanner = Scanner::new(database, dns, scanner_test_options(false));
    let hosts = (0..65)
        .map(|index| format!("www.zone-{index}.example.test"))
        .collect::<Vec<_>>();
    let mut parent_by_host = HashMap::new();
    let mut wildcard_by_parent = BTreeMap::new();
    let mut reliable_wildcard_zones = BTreeSet::new();

    let first = scanner
        .register_wildcard_parents_bounded(
            &hosts,
            "example.test",
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            64,
            None,
        )
        .await;
    assert!(!first.deadline_exhausted);
    assert_eq!(first.deferred_parents, 1);

    let second = scanner
        .register_wildcard_parents_bounded(
            &hosts,
            "example.test",
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            64,
            None,
        )
        .await;
    assert!(!second.deadline_exhausted);
    assert_eq!(second.deferred_parents, 0);
    assert!(
        wildcard_by_parent
            .values()
            .all(|signature| !super::wildcard_signature_is_indeterminate(signature))
    );
    server.abort();
}

#[tokio::test]
async fn deferred_wildcard_hosts_remain_in_the_durable_seed_queue() {
    let (address, _, server) = wildcard_test_resolver().await;
    let database = Database::in_memory().unwrap();
    let scan_id = database
        .create_scan("example.test", &serde_json::json!({}))
        .unwrap();
    let hosts = (0..65)
        .map(|index| format!("www.zone-{index}.example.test"))
        .collect::<Vec<_>>();
    let seeds = hosts
        .iter()
        .map(|host| {
            (
                host.clone(),
                BTreeSet::from(["passive:fixture".to_owned()]),
                1,
            )
        })
        .collect::<Vec<_>>();
    database
        .persist_scan_seed_candidates(scan_id, &seeds, seeds.len())
        .unwrap();
    let claimed = database
        .pending_scan_seed_candidates(scan_id, seeds.len())
        .unwrap()
        .into_iter()
        .map(|(host, _, _)| host)
        .collect::<Vec<_>>();
    let dns =
        DnsEngine::new_with_socket_addresses(128, Duration::from_secs(1), &[address], 0).unwrap();
    let scanner = Scanner::new(database.clone(), dns, scanner_test_options(false));
    let root_wildcard = BTreeSet::new();
    let mut parent_by_host = HashMap::new();
    let mut wildcard_by_parent =
        BTreeMap::from([("example.test".to_owned(), root_wildcard.clone())]);
    let mut reliable_wildcard_zones = BTreeSet::new();

    let first = scanner
        .register_wildcard_parents_bounded(
            &claimed,
            "example.test",
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            64,
            None,
        )
        .await;
    assert_eq!(first.deferred_parents, 1);
    let deferred = Scanner::deferred_wildcard_hosts(
        claimed.iter().cloned(),
        &root_wildcard,
        &wildcard_by_parent,
    );
    assert_eq!(deferred.len(), 1);
    let deferred = deferred.into_iter().collect::<Vec<_>>();
    database
        .requeue_unstarted_scan_seed_candidates(scan_id, &deferred)
        .unwrap();
    let terminal = claimed
        .iter()
        .filter(|host| !deferred.contains(host))
        .cloned()
        .collect::<Vec<_>>();
    database
        .mark_scan_seed_candidates_done(scan_id, &terminal)
        .unwrap();
    assert_eq!(
        database.pending_scan_seed_candidate_count(scan_id).unwrap(),
        1
    );

    let retry = database
        .pending_scan_seed_candidates(scan_id, 1)
        .unwrap()
        .into_iter()
        .map(|(host, _, _)| host)
        .collect::<Vec<_>>();
    let second = scanner
        .register_wildcard_parents_bounded(
            &retry,
            "example.test",
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            64,
            None,
        )
        .await;
    assert_eq!(second.deferred_parents, 0);
    assert!(
        Scanner::deferred_wildcard_hosts(
            retry.iter().cloned(),
            &root_wildcard,
            &wildcard_by_parent,
        )
        .is_empty()
    );
    database
        .mark_scan_seed_candidates_done(scan_id, &retry)
        .unwrap();
    assert_eq!(
        database.pending_scan_seed_candidate_count(scan_id).unwrap(),
        0
    );
    server.abort();
}

#[tokio::test]
async fn wildcard_budget_page_ignores_deferred_parents_outside_the_current_batch() {
    let (address, _, server) = wildcard_test_resolver().await;
    let database = Database::in_memory().unwrap();
    let dns =
        DnsEngine::new_with_socket_addresses(128, Duration::from_secs(1), &[address], 0).unwrap();
    let scanner = Scanner::new(database, dns, scanner_test_options(false));
    let hosts = vec!["www.new.example.test".to_owned()];
    let mut parent_by_host = HashMap::from([(
        "www.old.example.test".to_owned(),
        "old.example.test".to_owned(),
    )]);
    let mut wildcard_by_parent =
        BTreeMap::from([("old.example.test".to_owned(), deferred_wildcard_signature())]);
    let mut reliable_wildcard_zones = BTreeSet::new();
    let mut remaining = None;

    let registration = tokio::time::timeout(
        Duration::from_secs(1),
        scanner.register_wildcard_parents_with_budget(
            &hosts,
            "example.test",
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            20,
            &mut remaining,
        ),
    )
    .await
    .expect("an unrelated deferred parent caused an unbounded profiling loop");

    assert!(!registration.deadline_exhausted);
    assert_eq!(registration.deferred_parents, 0);
    assert!(wildcard_by_parent.contains_key("new.example.test"));
    assert!(wildcard_signature_is_deferred(
        &wildcard_by_parent["old.example.test"]
    ));
    server.abort();
}

#[tokio::test]
async fn expired_enrichment_budget_sends_no_dns_and_keeps_seed_queued() {
    let (address, requests, server) = wildcard_test_resolver().await;
    let database = Database::in_memory().unwrap();
    let scan_id = database
        .create_scan("example.test", &json!({"enrichment": true}))
        .unwrap();
    let dns =
        DnsEngine::new_with_socket_addresses(8, Duration::from_millis(100), &[address], 0).unwrap();
    let scanner = Scanner::new(database.clone(), dns, scanner_test_options(false));
    let fqdn = "api.example.test".to_owned();
    let sources = BTreeMap::from([(
        fqdn.clone(),
        BTreeSet::from(["web:https://example.invalid".to_owned()]),
    )]);
    let root_wildcard = BTreeSet::new();
    let mut parent_by_host = HashMap::new();
    let mut wildcard_by_parent =
        BTreeMap::from([("example.test".to_owned(), root_wildcard.clone())]);
    let mut reliable_wildcard_zones = BTreeSet::new();
    let mut remaining = Some(Duration::ZERO);

    let resolution = scanner
        .validate_enrichment_batch_bounded(
            scan_id,
            "example.test",
            std::slice::from_ref(&fqdn),
            "expired enrichment",
            &Instant::now(),
            &sources,
            &root_wildcard,
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            20,
            &mut remaining,
        )
        .await
        .unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert!(resolution.deadline_exhausted);
    assert_eq!(resolution.not_started_hosts, vec![fqdn.clone()]);
    assert_eq!(
        database.pending_scan_seed_candidate_count(scan_id).unwrap(),
        1
    );
    let queued = database.pending_scan_seed_candidates(scan_id, 1).unwrap();
    assert_eq!(queued[0].0, fqdn);
    server.abort();
}

#[tokio::test]
async fn unlimited_late_ct_validation_drains_every_seed_page_in_one_run() {
    let (address, requests, server) = wildcard_test_resolver().await;
    let database = Database::in_memory().unwrap();
    let scan_id = database
        .create_scan("example.test", &json!({"late_ct": true}))
        .unwrap();
    let hosts = ["one.example.test", "two.example.test"]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let origins = BTreeSet::from(["passive:ct-direct".to_owned()]);
    let seeds = hosts
        .iter()
        .map(|fqdn| (fqdn.clone(), origins.clone(), 100))
        .collect::<Vec<_>>();
    database
        .persist_scan_seed_candidates(scan_id, &seeds, seeds.len())
        .unwrap();
    let dns =
        DnsEngine::new_with_socket_addresses(8, Duration::from_secs(1), &[address], 0).unwrap();
    let mut options = scanner_test_options(false);
    options.max_passive = seeds.len();
    let scanner = Scanner::new(database.clone(), dns, options);
    let sources = hosts
        .iter()
        .map(|fqdn| (fqdn.clone(), origins.clone()))
        .collect::<BTreeMap<_, _>>();
    let root_wildcard = BTreeSet::new();
    let mut parent_by_host = HashMap::new();
    let mut wildcard_by_parent =
        BTreeMap::from([("example.test".to_owned(), root_wildcard.clone())]);
    let mut reliable_wildcard_zones = BTreeSet::new();
    let mut answers = BTreeMap::new();
    let mut remaining = None;

    let drain = scanner
        .drain_late_ct_seed_validation(
            scan_id,
            "example.test",
            &Instant::now(),
            &sources,
            &root_wildcard,
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            &mut answers,
            &mut remaining,
            1,
        )
        .await
        .unwrap();

    assert_eq!(drain.pending, 0);
    assert!(!drain.deadline_exhausted);
    assert_eq!(answers.keys().cloned().collect::<Vec<_>>(), hosts);
    assert!(requests.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        database.pending_scan_seed_candidate_count(scan_id).unwrap(),
        0
    );
    server.abort();
}

#[tokio::test]
async fn explicit_active_deadline_stops_late_ct_before_claiming_work() {
    let (address, requests, server) = wildcard_test_resolver().await;
    let database = Database::in_memory().unwrap();
    let scan_id = database
        .create_scan("example.test", &json!({"late_ct": true}))
        .unwrap();
    let fqdn = "queued.example.test".to_owned();
    let origins = BTreeSet::from(["passive:ct-direct".to_owned()]);
    database
        .persist_scan_seed_candidates(scan_id, &[(fqdn.clone(), origins.clone(), 100)], 1)
        .unwrap();
    let dns =
        DnsEngine::new_with_socket_addresses(8, Duration::from_secs(1), &[address], 0).unwrap();
    let scanner = Scanner::new(database.clone(), dns, scanner_test_options(false));
    let sources = BTreeMap::from([(fqdn.clone(), origins)]);
    let root_wildcard = BTreeSet::new();
    let mut parent_by_host = HashMap::new();
    let mut wildcard_by_parent =
        BTreeMap::from([("example.test".to_owned(), root_wildcard.clone())]);
    let mut reliable_wildcard_zones = BTreeSet::new();
    let mut answers = BTreeMap::new();
    let mut remaining = Some(Duration::ZERO);

    let drain = scanner
        .drain_late_ct_seed_validation(
            scan_id,
            "example.test",
            &Instant::now(),
            &sources,
            &root_wildcard,
            &mut parent_by_host,
            &mut wildcard_by_parent,
            &mut reliable_wildcard_zones,
            &mut answers,
            &mut remaining,
            1,
        )
        .await
        .unwrap();

    assert_eq!(drain.pending, 1);
    assert!(drain.deadline_exhausted);
    assert!(answers.is_empty());
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        database.pending_scan_seed_candidate_count(scan_id).unwrap(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn recursive_passive_zones_are_marked_only_when_a_task_is_scheduled() {
    let database = Database::in_memory().unwrap();
    let dns = DnsEngine::new_with_rate(
        8,
        Duration::from_millis(50),
        &["127.0.0.1".parse().unwrap()],
        10,
    )
    .unwrap();
    let mut options = scanner_test_options(false);
    options.passive_sources.clear();
    options.profile = "deep".to_owned();
    let scanner = Scanner::new(database, dns, options);
    let mut queried = BTreeSet::from(["example.test".to_owned()]);
    let mut sources = BTreeMap::new();
    let mut warnings = Vec::new();
    let zones = (0..25)
        .map(|index| format!("zone-{index}.example.test"))
        .collect::<Vec<_>>();

    let discovered = scanner
        .collect_passive_recursively(
            "example.test",
            zones,
            None,
            &mut queried,
            &mut sources,
            &mut warnings,
        )
        .await
        .unwrap();

    assert!(discovered.is_empty());
    assert_eq!(queried, BTreeSet::from(["example.test".to_owned()]));
}

#[test]
fn verification_max_age_requeues_stale_permanent_cache_entries() {
    let mut answer = ResolvedHost {
        fqdn: "api.example.com".to_owned(),
        records: Vec::new(),
        from_cache: true,
        last_verified_at: Some(1_000),
        authoritative_validation: false,
        resolver_count: 1,
    };
    assert!(!cache_requires_revalidation(
        &answer,
        Duration::from_secs(101),
        1_100,
        false,
    ));
    assert!(cache_requires_revalidation(
        &answer,
        Duration::from_secs(99),
        1_100,
        false,
    ));
    assert!(cache_requires_revalidation(
        &answer,
        Duration::ZERO,
        1_000,
        false,
    ));
    answer.last_verified_at = None;
    assert!(cache_requires_revalidation(
        &answer,
        Duration::from_secs(3_600),
        1_100,
        false,
    ));
    answer.last_verified_at = Some(1_100);
    assert!(cache_requires_revalidation(
        &answer,
        Duration::from_secs(3_600),
        1_100,
        true,
    ));
    answer.resolver_count = 2;
    assert!(!cache_requires_revalidation(
        &answer,
        Duration::from_secs(3_600),
        1_100,
        true,
    ));
    assert!(was_recently_verified(
        Some(i64::MIN),
        Duration::MAX,
        i64::MAX,
    ));
    assert!(!was_recently_verified(Some(1_100), Duration::ZERO, 1_100,));
}

#[test]
fn lazy_refills_are_batch_bounded_and_honor_the_total_word_budget() {
    assert_eq!(candidate_refill_capacity(0, 0, 500, 1_000_000), 500);
    assert_eq!(candidate_refill_capacity(0, 500, 1_500, 1_000), 500);
    assert_eq!(candidate_refill_capacity(1_200, 1_200, 1_500, 10_000), 300);
    assert_eq!(candidate_refill_capacity(500, 500, 500, 10_000), 0);
    assert_eq!(candidate_refill_capacity(0, 10_000, 5_000, 10_000), 0);
}

#[test]
fn high_value_window_is_materialized_once_without_using_the_dns_queue_gap_as_its_cap() {
    // A 128-row DNS queue gap still persists the complete bounded 5,000
    // candidate window once; subsequent waves observe the durable feed
    // marker and skip grammar/mutation recomputation.
    assert!(high_value_window_needs_materialization(128, false));
    assert_eq!(high_value_window_persist_limit(0, 0, 20_000, 5_000), 5_000);
    assert!(!high_value_window_needs_materialization(128, true));

    // If max_words has less room than the window, filling that remaining
    // room is exhaustive for this scan and never crosses the hard budget.
    assert_eq!(
        high_value_window_persist_limit(9_700, 100, 10_000, 5_000),
        200
    );
    assert_eq!(
        high_value_window_persist_limit(usize::MAX, usize::MAX, 10, 5_000),
        0
    );
}

#[test]
fn mutation_observation_selection_bounds_huge_iterators_and_is_deterministic() {
    struct HugeObservationIterator<'a> {
        names: &'a [String],
        offset: usize,
        remaining: usize,
        polls: Arc<AtomicUsize>,
    }

    impl<'a> Iterator for HugeObservationIterator<'a> {
        type Item = (&'a str, i64);

        fn next(&mut self) -> Option<Self::Item> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            let index = self.offset % self.names.len();
            self.offset = self.offset.saturating_add(1);
            self.polls.fetch_add(1, Ordering::SeqCst);
            Some((self.names[index].as_str(), (index % 5) as i64))
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.remaining, Some(self.remaining))
        }
    }

    let names = [
        "api.example.com",
        "api.dev.example.com",
        "worker-01.example.com",
        "worker-02.prod.example.com",
        "mail.example.com",
        "admin.eu.example.com",
        "cdn-legacy.example.com",
        "vpn2.apac.example.com",
        "status.example.com",
        "auth.staging.example.com",
        "db-03.internal.example.com",
        "shop.example.com",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let scan_cap = 32;
    let keep_cap = 8;
    let first_polls = Arc::new(AtomicUsize::new(0));
    let first = select_bounded_mutation_observations(
        "example.com",
        HugeObservationIterator {
            names: &names,
            offset: 0,
            remaining: 1_000_000,
            polls: Arc::clone(&first_polls),
        },
        scan_cap,
        keep_cap,
    );
    let second_polls = Arc::new(AtomicUsize::new(0));
    let second = select_bounded_mutation_observations(
        "example.com",
        HugeObservationIterator {
            names: &names,
            offset: 0,
            remaining: 1_000_000,
            polls: Arc::clone(&second_polls),
        },
        scan_cap,
        keep_cap,
    );

    assert_eq!(first_polls.load(Ordering::SeqCst), scan_cap);
    assert_eq!(second_polls.load(Ordering::SeqCst), scan_cap);
    assert_eq!(first, second);
    assert_eq!(first.len(), keep_cap);
    assert!(first.iter().any(|name| name.contains(".prod.")));
    assert!(first.iter().any(|name| name.contains(".apac.")));
    assert!(first.iter().any(|name| name.contains("worker-")));
}

#[test]
fn unseen_targeted_sources_start_ahead_of_expensive_archives() {
    assert!(source_bootstrap_score("securitytrails") > source_bootstrap_score("wayback"));
    assert!(source_bootstrap_score("merklemap") > source_bootstrap_score("commoncrawl"));
    assert!(source_bootstrap_score("submd") > source_bootstrap_score("securitytrails"));
    assert!(source_bootstrap_score("thc") > source_bootstrap_score("securitytrails"));
}

#[test]
fn phase_budget_is_cumulative_and_saturates_at_zero() {
    let mut remaining = Some(Duration::from_secs(10));
    consume_phase_budget(&mut remaining, Duration::from_secs(4));
    assert_eq!(remaining, Some(Duration::from_secs(6)));
    consume_phase_budget(&mut remaining, Duration::from_secs(7));
    assert_eq!(remaining, Some(Duration::ZERO));

    let mut unlimited = None;
    consume_phase_budget(&mut unlimited, Duration::from_secs(99));
    assert_eq!(unlimited, None);
    assert!(phase_deadline(unlimited).is_none());
}

#[test]
fn web_budget_is_shared_across_initial_and_pipeline_rounds() {
    let mut remaining = Some(Duration::from_secs(45));
    consume_phase_budget(&mut remaining, Duration::from_secs(30));
    assert_eq!(remaining, Some(Duration::from_secs(15)));
    consume_phase_budget(&mut remaining, Duration::from_secs(20));
    assert_eq!(remaining, Some(Duration::ZERO));
}

#[test]
fn explicit_active_budget_is_independent_of_adaptive_mode_and_includes_wordlists() {
    // The scanner budget no longer receives an `adaptive` flag: an
    // explicit non-zero --active-max-runtime therefore remains effective
    // with --no-adaptive. A profile/default value of zero is represented
    // as None and remains unlimited.
    assert!(active_candidate_budget_exhausted(Some(Duration::ZERO)));
    assert!(!active_candidate_budget_exhausted(None));
    assert!(!active_candidate_work_allowed(Some(Duration::ZERO)));
    assert!(active_candidate_work_allowed(None));

    let generated = CandidateProposal {
        relative_name: "api".to_owned(),
        generator: "builtin".to_owned(),
        score: 1,
    };
    let wordlist = CandidateProposal {
        relative_name: "custom".to_owned(),
        generator: "wordlist".to_owned(),
        score: 1,
    };
    assert!(candidate_uses_active_budget(&generated));
    assert!(candidate_uses_active_budget(&wordlist));
    assert!(candidate_uses_discovery_fast_path(
        &generated, true, false, false, false
    ));
    assert!(!candidate_uses_discovery_fast_path(
        &wordlist, true, false, false, false
    ));
    assert!(!candidate_uses_discovery_fast_path(
        &generated, true, false, true, false
    ));
    assert!(!candidate_uses_discovery_fast_path(
        &generated, true, true, false, false
    ));
    assert!(!candidate_uses_discovery_fast_path(
        &generated, true, false, false, true
    ));
    // Expansion state changes fast-path eligibility, not budget ownership:
    // resumed/generated retries must remain under the active deadline.
    assert!(candidate_uses_active_budget(&generated));
    assert!(!candidate_uses_discovery_fast_path(
        &generated, false, false, false, false
    ));
}

#[test]
fn completed_last_recursive_depth_does_not_create_a_false_partial() {
    assert!(!active_resume_required(
        Some(Duration::ZERO),
        0,
        0,
        false,
        false,
    ));
    assert!(active_resume_required(
        Some(Duration::ZERO),
        0,
        0,
        false,
        true,
    ));
    assert!(active_resume_required(
        Some(Duration::ZERO),
        0,
        1,
        false,
        false,
    ));
    assert!(active_resume_required(None, 1, 0, false, false,));
}

#[test]
fn generated_fast_negatives_route_only_to_the_discovery_journal() {
    let positive = ResolvedHost {
        fqdn: "live.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.10".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(1),
        authoritative_validation: false,
        resolver_count: 2,
    };
    let routed = route_dns_outcomes(
        BatchDnsMode::GeneratedDiscovery,
        [
            DnsResolutionOutcome::Positive(positive.clone()),
            DnsResolutionOutcome::Negative {
                fqdn: "missing.example.com".to_owned(),
            },
            DnsResolutionOutcome::Indeterminate {
                fqdn: "uncertain.example.com".to_owned(),
            },
        ],
        ["deadline.example.com".to_owned()],
    );
    assert_eq!(routed.positives.len(), 1);
    assert_eq!(routed.positives[0].fqdn, positive.fqdn);
    assert_eq!(routed.positives[0].records, positive.records);
    assert!(routed.cacheable_negatives.is_empty());
    assert_eq!(
        routed.discovery_negatives,
        vec!["missing.example.com".to_owned()]
    );
    assert_eq!(
        routed.indeterminate,
        vec![
            "deadline.example.com".to_owned(),
            "uncertain.example.com".to_owned()
        ]
    );

    let conservative = route_dns_outcomes(
        BatchDnsMode::Conservative,
        [DnsResolutionOutcome::Negative {
            fqdn: "missing.example.com".to_owned(),
        }],
        [],
    );
    assert_eq!(
        conservative.cacheable_negatives,
        vec!["missing.example.com".to_owned()]
    );
    assert!(conservative.discovery_negatives.is_empty());
}

#[test]
fn discovery_negative_is_terminal_without_poisoning_an_existing_positive_cache() {
    let database = Database::in_memory().unwrap();
    let history_scan = database.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "api.example.com".to_owned();
    let positive = ResolvedHost {
        fqdn: fqdn.clone(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(1),
        authoritative_validation: false,
        resolver_count: 2,
    };
    database
        .update_cache_outcomes(
            Some(history_scan),
            std::slice::from_ref(&positive),
            &[],
            &[],
            300,
        )
        .unwrap();

    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    database
        .persist_scan_candidates_bounded(
            scan_id,
            "example.com",
            &[("api".to_owned(), "builtin".to_owned(), 1)],
            1,
        )
        .unwrap();
    assert_eq!(
        database.pending_scan_candidates(scan_id, 1).unwrap().len(),
        1
    );

    persist_routed_dns_outcomes(
        &database,
        scan_id,
        &[],
        &[],
        std::slice::from_ref(&fqdn),
        &[],
        300,
    )
    .unwrap();
    database
        .mark_scan_candidates_done(scan_id, std::slice::from_ref(&fqdn))
        .unwrap();

    assert_eq!(database.pending_scan_candidate_count(scan_id).unwrap(), 0);
    let cached = database.fresh_cache(std::slice::from_ref(&fqdn)).unwrap();
    let Some(crate::db::CachedAnswer::Positive(answer)) = cached.get(&fqdn) else {
        panic!("discovery-only negative replaced the positive cache");
    };
    assert_eq!(answer.records, positive.records);
}

#[tokio::test]
async fn active_deadline_persists_completed_outcomes_and_requeues_unfinished_work() {
    let fast = "fast.example.com".to_owned();
    let slow = "slow.example.com".to_owned();
    let started = Instant::now();
    let batch = collect_dns_outcomes_until(
        vec![fast.clone(), slow.clone()],
        2,
        Some(tokio::time::Instant::now() + Duration::from_millis(60)),
        |fqdn, network_attempted| async move {
            network_attempted.store(true, Ordering::Release);
            if fqdn.starts_with("fast.") {
                tokio::time::sleep(Duration::from_millis(10)).await;
                DnsResolutionOutcome::Positive(ResolvedHost {
                    fqdn,
                    records: vec![DnsRecord {
                        record_type: "A".to_owned(),
                        value: "192.0.2.10".to_owned(),
                        ttl: 60,
                    }],
                    from_cache: false,
                    last_verified_at: Some(1),
                    authoritative_validation: false,
                    resolver_count: 2,
                })
            } else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                DnsResolutionOutcome::Negative { fqdn }
            }
        },
        |_| {},
    )
    .await;

    assert!(batch.deadline_exhausted);
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(batch.completed.len(), 1);
    assert_eq!(batch.completed[0].fqdn(), fast);
    assert_eq!(batch.cancelled, vec![slow.clone()]);
    assert!(batch.not_started.is_empty());
    assert_eq!(batch.attempted, vec![fast.clone(), slow.clone()]);

    let database = Database::in_memory().unwrap();
    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    database
        .persist_scan_candidates_bounded(
            scan_id,
            "example.com",
            &[
                ("fast".to_owned(), "builtin".to_owned(), 2),
                ("slow".to_owned(), "builtin".to_owned(), 1),
            ],
            2,
        )
        .unwrap();
    assert_eq!(
        database.pending_scan_candidates(scan_id, 2).unwrap().len(),
        2
    );

    let attempted_hosts = batch.attempted.clone();
    let completed = batch
        .completed
        .into_iter()
        .filter_map(|outcome| match outcome {
            DnsResolutionOutcome::Positive(answer) => Some(answer),
            _ => None,
        })
        .collect::<Vec<_>>();
    database
        .mark_scan_candidates_started(scan_id, &attempted_hosts)
        .unwrap();
    database
        .update_cache_outcomes(Some(scan_id), &completed, &[], &batch.cancelled, 300)
        .unwrap();
    database
        .record_scan_candidate_results(
            scan_id,
            &[(fast.clone(), "fast".to_owned(), "builtin".to_owned(), true)],
        )
        .unwrap();
    database
        .mark_scan_candidates_done(scan_id, &[fast.clone(), slow.clone()])
        .unwrap();

    let cache = database.fresh_cache(&[fast.clone(), slow.clone()]).unwrap();
    assert!(matches!(
        cache.get(&fast),
        Some(crate::db::CachedAnswer::Positive(_))
    ));
    assert!(!cache.contains_key(&slow));
    // The unfinished generated row remains durable, but an exhausted
    // active budget cannot claim it again during this scan.
    assert!(
        database
            .pending_scan_candidates_eligible(scan_id, 10, false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(database.pending_scan_candidate_count(scan_id).unwrap(), 1);
    let retry = database
        .pending_scan_candidates_eligible(scan_id, 10, true)
        .unwrap();
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].0, "slow");
    let learning = database.scan_candidate_learning(scan_id).unwrap();
    // Candidate learning is recorded only once a row becomes terminal;
    // the cancelled packet consumed a retry but remains eligible here.
    assert_eq!(learning.total_attempts, 1);
    assert_eq!(learning.generator_attempts.get("builtin"), Some(&1));
}

#[tokio::test]
async fn expired_deadline_never_starts_an_immediately_ready_backlog() {
    let starts = Arc::new(AtomicUsize::new(0));
    let hosts = (0..10_000)
        .map(|index| format!("{index}.example.com"))
        .collect::<Vec<_>>();
    let counter = starts.clone();
    let batch = collect_dns_outcomes_until(
        hosts.clone(),
        64,
        Some(tokio::time::Instant::now() - Duration::from_millis(1)),
        move |fqdn, _network_attempted| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move { DnsResolutionOutcome::Negative { fqdn } }
        },
        |_| {},
    )
    .await;

    assert!(batch.deadline_exhausted);
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert!(batch.completed.is_empty());
    assert!(batch.cancelled.is_empty());
    assert_eq!(batch.not_started.len(), hosts.len());

    let database = Database::in_memory().unwrap();
    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    database
        .persist_scan_candidates(
            scan_id,
            "example.com",
            &[("never-sent".to_owned(), "builtin".to_owned(), 1)],
        )
        .unwrap();
    database.pending_scan_candidates(scan_id, 1).unwrap();
    database
        .requeue_unstarted_scan_candidates(scan_id, &["never-sent.example.com".to_owned()])
        .unwrap();
    assert_eq!(database.pending_scan_candidate_count(scan_id).unwrap(), 1);
}

#[tokio::test]
async fn a_scheduled_future_that_never_sends_does_not_consume_a_retry() {
    let host = "waiting-for-transport.example.com".to_owned();
    let polled = Arc::new(AtomicBool::new(false));
    let observed_poll = Arc::clone(&polled);
    let batch = collect_dns_outcomes_until(
        vec![host.clone()],
        1,
        Some(tokio::time::Instant::now() + Duration::from_millis(25)),
        move |fqdn, _network_attempted| {
            let observed_poll = Arc::clone(&observed_poll);
            async move {
                observed_poll.store(true, Ordering::Release);
                tokio::time::sleep(Duration::from_secs(1)).await;
                DnsResolutionOutcome::Negative { fqdn }
            }
        },
        |_| {},
    )
    .await;

    assert!(polled.load(Ordering::Acquire));
    assert!(batch.deadline_exhausted);
    assert!(batch.completed.is_empty());
    assert!(batch.attempted.is_empty());
    assert!(batch.cancelled.is_empty());
    assert_eq!(batch.not_started, vec![host]);
}

#[test]
fn refresh_defaults_disable_cumulative_limits_and_keep_batches_bounded() {
    let options = RefreshOptions::default();
    assert_eq!(options.max_runtime, Duration::ZERO);
    assert_eq!(options.wildcard_phase_timeout, Duration::ZERO);
    assert_eq!(options.batch_size, 256);
}

#[tokio::test]
async fn absent_refresh_deadline_waits_for_completion() {
    let result = before_refresh_deadline(None, async {
        tokio::task::yield_now().await;
        7_u8
    })
    .await;
    assert_eq!(result, Some(7));
}

#[tokio::test]
async fn expired_refresh_deadline_cancels_without_network() {
    let result = before_refresh_deadline(
        Some(tokio::time::Instant::now() - Duration::from_millis(1)),
        std::future::pending::<()>(),
    )
    .await;
    assert!(result.is_none());
}

#[test]
fn global_refresh_deadline_caps_the_shared_wildcard_phase() {
    let global = tokio::time::Instant::now() + Duration::from_secs(1);
    let capped = capped_phase_deadline(Some(global), Duration::from_secs(30));
    assert_eq!(capped, Some(global));
    assert_eq!(
        capped_phase_deadline(Some(global), Duration::ZERO),
        Some(global)
    );
    assert!(capped_phase_deadline(None, Duration::ZERO).is_none());
    assert!(refresh_deadline(Duration::ZERO).is_none());
}

#[test]
fn pathological_library_durations_expire_instead_of_panicking() {
    let before = tokio::time::Instant::now();
    let phase = phase_deadline(Some(Duration::MAX)).unwrap();
    let refresh = refresh_deadline(Duration::MAX).unwrap();
    let capped = capped_phase_deadline(None, Duration::MAX).unwrap();
    let after = tokio::time::Instant::now();
    for deadline in [phase, refresh, capped] {
        assert!(deadline >= before && deadline <= after);
    }
}

#[test]
fn wildcard_purge_requires_a_complete_reliable_refresh() {
    assert!(refresh_allows_wildcard_purge("completed", true));
    assert!(!refresh_allows_wildcard_purge("partial", true));
    assert!(!refresh_allows_wildcard_purge("interrupted", true));
    assert!(!refresh_allows_wildcard_purge("completed", false));
    assert!(refresh_can_demote_wildcard_ambiguity(true));
    assert!(!refresh_can_demote_wildcard_ambiguity(false));
}

#[test]
fn indeterminate_root_or_child_profile_makes_refresh_partial() {
    let indeterminate = super::indeterminate_wildcard_signature();
    let normal = BTreeSet::new();
    assert!(!refresh_wildcard_profile_is_reliable(None));
    assert!(!refresh_wildcard_profile_is_reliable(Some(&indeterminate)));
    assert!(refresh_wildcard_profile_is_reliable(Some(&normal)));
}

#[test]
fn stale_wildcard_profile_never_authorizes_refresh_cleanup() {
    let stale = BTreeSet::from(["A:192.0.2.44".to_owned()]);
    let observation =
        wildcard_profile_after_probe(Some(stale.clone()), WildcardProbeOutcome::Indeterminate);

    // The old signature remains available to classify matching answers
    // conservatively, but the failed current probe makes cleanup unsafe.
    assert_eq!(observation.signature.as_ref(), Some(&stale));
    assert!(refresh_wildcard_profile_is_reliable(
        observation.signature.as_ref()
    ));
    assert!(!observation.current_probe_reliable);
    assert!(!refresh_wildcard_observation_is_reliable(Some(
        &observation
    )));

    let current = wildcard_profile_after_probe(None, WildcardProbeOutcome::Wildcard(stale.clone()));
    assert!(refresh_wildcard_observation_is_reliable(Some(&current)));
}

#[tokio::test]
async fn failed_current_probe_keeps_stale_wildcard_non_destructive() {
    let database = Database::in_memory().unwrap();
    let stale = BTreeSet::from(["A:192.0.2.44".to_owned()]);
    database
        .store_wildcard_cache("example.test", &stale, None, Duration::ZERO, true)
        .unwrap();
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns = DnsEngine::new_with_socket_addresses(
        8,
        Duration::from_millis(10),
        &[silent.local_addr().unwrap()],
        0,
    )
    .unwrap();

    let observation = tokio::time::timeout(
        Duration::from_secs(1),
        wildcard_profile_observed(
            &database,
            &dns,
            "example.test",
            Duration::from_secs(3_600),
            true,
            false,
        ),
    )
    .await
    .expect("bounded wildcard probes must terminate");

    assert_eq!(observation.signature.as_ref(), Some(&stale));
    assert!(!observation.current_probe_reliable);
    assert!(!refresh_wildcard_observation_is_reliable(Some(
        &observation
    )));
}

#[test]
fn more_than_sixty_four_parent_zones_disables_cleanup() {
    assert!(refresh_parent_selection_is_complete(64, false));
    assert!(!refresh_parent_selection_is_complete(65, false));
    assert!(!refresh_parent_selection_is_complete(1, true));
}

#[test]
fn trusted_positive_matching_wildcard_is_not_live() {
    let signature = BTreeSet::from(["A:192.0.2.44".to_owned()]);
    let answer = ResolvedHost {
        fqdn: "api.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: Some(1),
        authoritative_validation: false,
        resolver_count: 3,
    };
    assert!(Scanner::answer_is_wildcard_ambiguous(
        &answer,
        &signature,
        &BTreeMap::new(),
    ));
}

#[test]
fn parent_heavy_hitters_stay_memory_bounded() {
    let mut counts = HashMap::new();
    for index in 0..100 {
        record_bounded_parent_candidate(&mut counts, format!("{index}.example.com"), 8);
    }
    for _ in 0..50 {
        record_bounded_parent_candidate(&mut counts, "prod.example.com".to_owned(), 8);
    }
    assert!(counts.len() <= 8);
    assert!(counts.contains_key("prod.example.com"));
}

#[tokio::test]
async fn completed_cleanup_quarantines_exact_matches_with_passive_evidence() {
    let database = Database::in_memory().unwrap();
    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    let make = |fqdn: &str, source: &str| Finding {
        fqdn: fqdn.to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.44".to_owned(),
            ttl: 60,
        }],
        sources: BTreeSet::from([source.to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(&BTreeSet::from([source.to_owned()]), false, false),
        state: ObservationState::Live,
        last_verified_at: Some(1),
        evidence_families: BTreeSet::new(),
        authoritative_validation: false,
        ..Finding::default()
    };
    let weak = "weak.example.com";
    let corroborated = "ct.example.com";
    database
        .persist_findings(
            scan_id,
            "example.com",
            &[
                make(weak, "bruteforce"),
                make(corroborated, "passive:crtsh"),
            ],
            86_400,
        )
        .unwrap();
    database
        .record_current_wildcard_matches(
            scan_id,
            &[weak, corroborated]
                .into_iter()
                .map(|fqdn| ResolvedHost {
                    fqdn: fqdn.to_owned(),
                    records: vec![DnsRecord {
                        record_type: "A".to_owned(),
                        value: "192.0.2.44".to_owned(),
                        ttl: 60,
                    }],
                    from_cache: false,
                    last_verified_at: Some(1),
                    authoritative_validation: false,
                    resolver_count: 2,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    database
        .stage_refresh_wildcard_candidates(scan_id, &[weak.to_owned(), corroborated.to_owned()])
        .unwrap();
    let (purged, retained) =
        apply_completed_refresh_wildcard_cleanup(&database, scan_id, "example.com", None, 1)
            .await
            .unwrap()
            .unwrap();
    assert_eq!((purged, retained), (2, 0));
    assert!(
        database
            .inventory(Some("example.com"), false)
            .unwrap()
            .is_empty()
    );
    let explanation = database.explain(corroborated).unwrap();
    assert_eq!(explanation["quarantine"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn expired_cleanup_deadline_keeps_inventory_unchanged() {
    let database = Database::in_memory().unwrap();
    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    let fqdn = "weak.example.com";
    let finding = Finding {
        fqdn: fqdn.to_owned(),
        records: Vec::new(),
        sources: BTreeSet::from(["dns-wave-2".to_owned()]),
        wildcard: false,
        from_cache: false,
        confidence: crate::confidence::assess(
            &BTreeSet::from(["dns-wave-2".to_owned()]),
            false,
            false,
        ),
        state: ObservationState::Live,
        last_verified_at: Some(1),
        evidence_families: BTreeSet::new(),
        authoritative_validation: false,
        ..Finding::default()
    };
    database
        .persist_findings(scan_id, "example.com", &[finding], 86_400)
        .unwrap();
    database
        .stage_refresh_wildcard_candidates(scan_id, &[fqdn.to_owned()])
        .unwrap();

    let result = apply_completed_refresh_wildcard_cleanup(
        &database,
        scan_id,
        "example.com",
        Some(tokio::time::Instant::now() - Duration::from_millis(1)),
        1,
    )
    .await
    .unwrap();
    assert!(result.is_none());
    assert_eq!(
        database.refresh_wildcard_candidate_count(scan_id).unwrap(),
        0
    );
    let inventory = database.inventory(Some("example.com"), false).unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].state, ObservationState::Live);
}

#[test]
fn dropping_refresh_cleanup_guard_waits_for_worker_completion() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let finished = Arc::new(AtomicBool::new(false));
    let worker_finished = Arc::clone(&finished);
    let (completion_tx, completion_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _completion = SignalRefreshCleanupCompletion(Some(completion_tx));
        while !worker_cancelled.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        std::thread::sleep(Duration::from_millis(10));
        worker_finished.store(true, Ordering::Release);
    });

    {
        let _guard = RefreshCleanupCancellation::new(cancelled, completion_rx);
    }

    assert!(finished.load(Ordering::Acquire));
    worker.join().unwrap();
}

#[test]
fn dropped_refresh_closes_its_non_resumable_checkpoint() {
    let database = Database::in_memory().unwrap();
    let scan_id = database
        .create_scan("example.com", &json!({"mode": "refresh"}))
        .unwrap();
    database
        .upsert_checkpoint(scan_id, "example.com", "running", "refresh")
        .unwrap();
    {
        let _guard = RefreshRunGuard::new(database.clone(), scan_id, Instant::now(), 12);
    }
    assert!(
        database
            .resumable_checkpoint("example.com", "latest")
            .unwrap()
            .is_none()
    );
    assert_eq!(database.history(1).unwrap()[0]["status"], "interrupted");
}

#[test]
fn dropping_a_running_scan_marks_it_interrupted_and_keeps_the_checkpoint() {
    let database = Database::in_memory().unwrap();
    let scan_id = database.create_scan("example.com", &json!({})).unwrap();
    database
        .upsert_checkpoint(scan_id, "example.com", "running", "options-hash")
        .unwrap();
    {
        let _guard = ScanRunGuard::new(database.clone(), scan_id, Instant::now());
    }

    let history = database.history(1).unwrap();
    assert_eq!(history[0]["status"], "interrupted");
    assert!(
        database
            .resumable_checkpoint("example.com", "latest")
            .unwrap()
            .is_some()
    );
}

#[test]
fn deepest_known_wildcard_ancestor_applies_to_all_descendants() {
    let root = BTreeSet::new();
    let prod = BTreeSet::from(["A:192.0.2.29".to_owned()]);
    let mut by_parent = BTreeMap::from([
        ("example.com".to_owned(), root.clone()),
        ("prod.example.com".to_owned(), prod.clone()),
    ]);
    assert_eq!(
        Scanner::applicable_wildcard_signature("a.b.c.prod.example.com", &root, &by_parent),
        &prod
    );

    by_parent.insert("c.prod.example.com".to_owned(), BTreeSet::new());
    assert!(
        Scanner::applicable_wildcard_signature("a.b.c.prod.example.com", &root, &by_parent)
            .is_empty()
    );
}

#[test]
fn only_matching_or_indeterminate_wildcard_answers_are_terminal_seeds() {
    let normal_root = BTreeSet::new();
    let wildcard = BTreeSet::from(["A:192.0.2.29".to_owned()]);
    let indeterminate = super::indeterminate_wildcard_signature();
    let by_parent = BTreeMap::from([
        ("example.com".to_owned(), normal_root.clone()),
        ("prod.example.com".to_owned(), wildcard),
        ("unknown.example.com".to_owned(), indeterminate),
    ]);
    let answer = |fqdn: &str, address: &str| ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: vec![crate::model::DnsRecord {
            record_type: "A".to_owned(),
            value: address.to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: None,
        authoritative_validation: false,
        resolver_count: 1,
    };

    assert!(Scanner::is_strict_enrichment_seed(
        &answer("api.example.com", "192.0.2.10"),
        &normal_root,
        &by_parent
    ));
    assert!(!Scanner::is_strict_enrichment_seed(
        &answer("random.prod.example.com", "192.0.2.29"),
        &normal_root,
        &by_parent
    ));
    assert!(
        Scanner::is_strict_enrichment_seed(
            &answer("mail.prod.example.com", "192.0.2.10"),
            &normal_root,
            &by_parent
        ),
        "a legitimate answer with records distinct from the wildcard must remain usable"
    );
    assert!(!Scanner::is_strict_enrichment_seed(
        &answer("api.unknown.example.com", "192.0.2.10"),
        &normal_root,
        &by_parent
    ));
}

#[test]
fn internetdb_address_selection_is_public_deduplicated_and_yield_ranked() {
    let answer = |fqdn: &str, addresses: &[&str]| ResolvedHost {
        fqdn: fqdn.to_owned(),
        records: addresses
            .iter()
            .map(|address| crate::model::DnsRecord {
                record_type: if address.contains(':') { "AAAA" } else { "A" }.to_owned(),
                value: (*address).to_owned(),
                ttl: 60,
            })
            .collect(),
        from_cache: false,
        last_verified_at: None,
        authoritative_validation: false,
        resolver_count: 2,
    };
    let first = answer(
        "a.example.com",
        &["1.1.1.1", "8.8.8.8", "10.0.0.1", "2606:4700:4700::1111"],
    );
    let second = answer("b.example.com", &["1.1.1.1", "1.1.1.1"]);
    assert_eq!(
        prioritized_answer_addresses([&first, &second], true, 3),
        vec![
            "8.8.8.8".parse::<IpAddr>().unwrap(),
            "1.1.1.1".parse::<IpAddr>().unwrap(),
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
        ]
    );
    assert_eq!(
        prioritized_answer_addresses([&first, &second], true, 1),
        vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn internetdb_cache_keeps_history_without_relabeling_empty_or_failed_snapshots() {
    let historical = BTreeSet::from(["old.example.com".to_owned()]);
    let empty = IpHostnameCacheEntry {
        hostnames: historical.clone(),
        last_success_at: 1_000,
        last_attempt_at: 1_000,
        status: "empty".to_owned(),
    };
    assert_eq!(
        internetdb_cache_decision(Some(&empty), 1_100, 3_600, 900, false),
        super::InternetDbCacheDecision::Use {
            hostnames: BTreeSet::new(),
            qualifier: ":cache",
        }
    );

    let failed = IpHostnameCacheEntry {
        hostnames: historical.clone(),
        last_success_at: 1,
        last_attempt_at: 1_000,
        status: "error".to_owned(),
    };
    assert_eq!(
        internetdb_cache_decision(Some(&failed), 1_100, 10, 900, false),
        super::InternetDbCacheDecision::Use {
            hostnames: historical,
            qualifier: ":stale",
        }
    );
    assert_eq!(
        internetdb_cache_decision(Some(&failed), 2_000, 10, 900, false),
        super::InternetDbCacheDecision::Refresh
    );
    assert_eq!(
        internetdb_cache_decision(Some(&failed), 1_100, 3_600, 900, true),
        super::InternetDbCacheDecision::Refresh
    );
}

#[test]
fn wildcard_sampling_counts_intermediate_ancestors() {
    assert_eq!(
        Scanner::ancestor_zones("a.b.prod.example.com", "example.com"),
        vec!["b.prod.example.com", "prod.example.com"]
    );
}

#[test]
fn adaptive_waves_require_a_minimum_yield_rate() {
    assert!(should_expand_adaptive_wave(true, 0, 500, 2, 5));
    assert!(should_expand_adaptive_wave(true, 1, 500, 3, 10));
    assert!(should_expand_adaptive_wave(true, 2, 1_000, 3, 0));
    assert!(should_expand_adaptive_wave(true, 3, 1_500, 3, 0));
    assert!(!should_expand_adaptive_wave(true, 0, 3_000, 3, 0));
    assert!(!should_expand_adaptive_wave(false, 20, 500, 2, 20));
}

#[test]
fn statistical_yield_bound_is_conservative_and_monotonic() {
    assert_eq!(wilson_upper_bound(0, 0), 1.0);
    assert!(wilson_upper_bound(1, 500) > 0.001);
    assert!(wilson_upper_bound(0, 3_000) < 0.001);
    assert!(wilson_upper_bound(0, 6_000) < wilson_upper_bound(0, 3_000));
    assert!(wilson_upper_bound(5, 3_000) > wilson_upper_bound(0, 3_000));
}

#[test]
fn adding_credentials_bypasses_only_legacy_missing_key_cooldowns() {
    assert!(source_requires_api_key("censys"));
    assert!(!source_requires_api_key("crtsh"));
    assert!(is_missing_api_key_error(
        "BINARYEDGE_API_KEY absent pour la source binaryedge"
    ));
    assert!(!is_missing_api_key_error(
        "binaryedge: HTTP 401 invalid api key"
    ));
    assert!(is_preflight_auth_error(
        "CENSYS_API_KEY doit être au format API_ID:API_SECRET"
    ));
    assert!(source_error_is_deferred(
        "BINARYEDGE_API_KEY absent pour la source binaryedge"
    ));
    assert!(source_error_is_deferred(
        "CENSYS_API_KEY doit être au format API_ID:API_SECRET"
    ));
    assert!(!source_error_is_deferred(
        "censys: HTTP 401 invalid api key"
    ));

    assert!(should_retry_source_after_key_added(
        "binaryedge",
        true,
        Some("BINARYEDGE_API_KEY absent pour la source binaryedge")
    ));
    assert!(!should_retry_source_after_key_added(
        "binaryedge",
        false,
        Some("BINARYEDGE_API_KEY absent pour la source binaryedge")
    ));
    assert!(should_retry_source_after_key_added(
        "otx",
        true,
        Some("OTX limite l'accès anonyme (HTTP 429)")
    ));
    assert!(!should_retry_source_after_key_added(
        "otx",
        false,
        Some("OTX limite l'accès anonyme (HTTP 429)")
    ));
    assert!(!should_retry_source_after_key_added(
        "otx",
        true,
        Some("OTX refuse la clé fournie (HTTP 429)")
    ));
    assert!(!should_retry_source_after_key_added(
        "otx",
        true,
        Some("OTX indisponible (HTTP 503)")
    ));
}

#[test]
fn external_retry_after_becomes_a_precise_adaptive_pause() {
    assert_eq!(
        external_retry_after_seconds(
            "urlscan: HTTP 429 avec Retry-After=3661s; nouvelle tentative différée"
        ),
        Some(3661)
    );
    assert_eq!(
        external_pause_status(61),
        "source externe différée, reprise dans 2 min, mémoire permanente"
    );
    assert_eq!(external_retry_after_seconds("HTTP 503"), None);
    assert_eq!(
        external_deferral_seconds("Driftnet: HTTP 403: quota exceeded"),
        Some(900)
    );
    assert_eq!(external_deferral_seconds("HTTP 403 unauthorized"), None);
}
