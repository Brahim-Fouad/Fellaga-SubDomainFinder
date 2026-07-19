use super::engine::*;
use super::policy::*;
use super::transport::*;
use super::wire::*;
use super::*;
use hickory_net::proto::rr::rdata::{A, CNAME, NS};

#[test]
fn resolver_inflight_guard_releases_load_when_a_future_is_cancelled() {
    let inflight = AtomicUsize::new(0);
    {
        let _guard = ResolverInflightGuard::new(&inflight);
        assert_eq!(inflight.load(Ordering::Relaxed), 1);
    }
    assert_eq!(inflight.load(Ordering::Relaxed), 0);
}

#[test]
fn post_send_cancellation_is_accounted_without_poisoning_resolver_health() {
    let state = Mutex::new(ResolverState::default());
    let governor = NetworkGovernor::new(NetworkControl::Adaptive, 250, 128);
    let signal = DnsSendSignal::default();
    signal.mark_sent();
    {
        let _guard = ResolverAttemptGuard::new(Some(&state), &governor, signal);
    }
    let state = state.lock().unwrap();
    assert_eq!(state.requests, 1);
    assert_eq!(state.successes, 0);
    assert_eq!(state.failures, 0);
    assert_eq!(state.consecutive_failures, 0);
    drop(state);
    governor.evaluate_pending_for_test();
    assert_eq!(governor.snapshot().backoffs, 0);
}

fn positive_records(value: &str) -> Vec<DnsRecord> {
    vec![DnsRecord {
        record_type: "A".to_owned(),
        value: value.to_owned(),
        ttl: 60,
    }]
}

#[test]
fn response_records_follow_only_the_question_cname_chain() {
    let query_name = Name::from_str("api.example.test.").unwrap();
    let alias_name = Name::from_str("edge.example.test.").unwrap();
    let final_name = Name::from_str("origin.example.test.").unwrap();
    let unrelated_name = Name::from_str("poison.example.test.").unwrap();
    let mut response = Message::new(7, MessageType::Response, OpCode::Query);
    response
        .set_response_code(ResponseCode::NoError)
        .add_query(Query::query(query_name.clone(), RecordType::A))
        // Put the terminal address before the CNAME records to verify that
        // chain validation does not depend on answer ordering.
        .add_answer(Record::from_rdata(
            final_name.clone(),
            60,
            RData::A(A("192.0.2.20".parse().unwrap())),
        ))
        .add_answer(Record::from_rdata(
            unrelated_name.clone(),
            60,
            RData::A(A("192.0.2.250".parse().unwrap())),
        ))
        .add_answer(Record::from_rdata(
            alias_name.clone(),
            60,
            RData::CNAME(CNAME(final_name)),
        ))
        .add_answer(Record::from_rdata(
            query_name,
            60,
            RData::CNAME(CNAME(alias_name)),
        ))
        .add_answer(Record::from_rdata(
            unrelated_name,
            60,
            RData::CNAME(CNAME(Name::from_str("elsewhere.example.test.").unwrap())),
        ));

    let records = response_records(&response, RecordType::A);
    let signatures = records
        .iter()
        .map(|record| format!("{}:{}", record.record_type, record.value))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        signatures,
        BTreeSet::from([
            "A:192.0.2.20".to_owned(),
            "CNAME:edge.example.test".to_owned(),
            "CNAME:origin.example.test".to_owned(),
        ])
    );
    assert!(!records.iter().any(|record| {
        record.value == "192.0.2.250" || record.value == "elsewhere.example.test"
    }));
}

#[tokio::test]
async fn positive_consensus_uses_a_majority_above_three_resolvers() {
    assert_eq!(positive_quorum(0), 1);
    assert_eq!(positive_quorum(1), 1);
    assert_eq!(positive_quorum(2), 2);
    assert_eq!(positive_quorum(3), 2);
    assert_eq!(positive_quorum(4), 3);
    assert_eq!(positive_quorum(5), 3);
    assert_eq!(positive_quorum(6), 4);

    let minority = collect_consensus_results(
        "minority.example.test",
        positive_quorum(4),
        stream::iter([
            RecordLookupOutcome::Positive(positive_records("192.0.2.10")),
            RecordLookupOutcome::Positive(positive_records("192.0.2.10")),
            RecordLookupOutcome::Negative,
            RecordLookupOutcome::Negative,
        ]),
    )
    .await;
    assert!(matches!(
        minority,
        DnsResolutionOutcome::Indeterminate { .. }
    ));

    let majority = collect_consensus_results(
        "majority.example.test",
        positive_quorum(5),
        stream::iter([
            RecordLookupOutcome::Positive(positive_records("192.0.2.10")),
            RecordLookupOutcome::Positive(positive_records("192.0.2.11")),
            RecordLookupOutcome::Positive(positive_records("192.0.2.12")),
            RecordLookupOutcome::Negative,
            RecordLookupOutcome::Negative,
        ]),
    )
    .await;
    let DnsResolutionOutcome::Positive(answer) = majority else {
        panic!("a strict majority of positive resolvers was not accepted");
    };
    assert_eq!(answer.resolver_count, 3);
}

#[tokio::test]
async fn authoritative_family_confirmation_cancels_a_silent_sibling() {
    let confirmed = tokio::time::timeout(
        Duration::from_millis(100),
        first_true_or_both(async { true }, async {
            std::future::pending::<bool>().await
        }),
    )
    .await
    .expect("authoritative confirmation waited for an irrelevant silent family");
    assert!(confirmed);
}

#[tokio::test]
async fn one_family_nxdomain_never_shortcuts_a_silent_sibling() {
    let outcome = tokio::time::timeout(
        Duration::from_millis(50),
        first_positive_or_both(async { RecordLookupOutcome::Negative }, async {
            std::future::pending::<RecordLookupOutcome>().await
        }),
    )
    .await;
    assert!(outcome.is_err());
}

async fn nxdomain_resolver() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0_u8; 2_048];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            message
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, task)
}

fn consensus_test_engine(addresses: Vec<SocketAddr>) -> DnsEngine {
    let metric_addresses = addresses.clone();
    DnsEngine {
        resolvers: Arc::new(
            metric_addresses
                .into_iter()
                .map(|address| resolver_node_at(address, Duration::from_millis(100)))
                .collect(),
        ),
        fast_resolvers: Arc::new(
            addresses
                .into_iter()
                .map(|address| FastResolver {
                    address,
                    transport: OnceCell::new(),
                })
                .collect(),
        ),
        concurrency: 8,
        timeout: Duration::from_millis(100),
        rate_limit: 0,
        governor: Arc::new(NetworkGovernor::new(NetworkControl::Fixed, 0, 8)),
        next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        cadence_reservations: Arc::new(tokio::sync::Semaphore::new(MAX_CADENCE_RESERVATIONS)),
        selection_counter: Arc::new(AtomicU64::new(0)),
        authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
        authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    }
}

fn resolver_node_at(address: SocketAddr, timeout: Duration) -> ResolverNode {
    let mut connection = ConnectionConfig::udp();
    connection.port = address.port();
    let config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        vec![NameServerConfig::new(address.ip(), true, vec![connection])],
    );
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    builder.options_mut().timeout = timeout;
    builder.options_mut().attempts = 1;
    builder.options_mut().cache_size = 0;
    ResolverNode {
        label: address.to_string(),
        resolver: Arc::new(builder.build().unwrap()),
        state: Mutex::new(ResolverState::default()),
        inflight: AtomicUsize::new(0),
    }
}

fn discovery_test_engine(addresses: &[SocketAddr], timeout: Duration) -> DnsEngine {
    DnsEngine {
        resolvers: Arc::new(
            addresses
                .iter()
                .copied()
                .map(|address| resolver_node_at(address, timeout))
                .collect(),
        ),
        fast_resolvers: Arc::new(
            addresses
                .iter()
                .copied()
                .map(|address| FastResolver {
                    address,
                    transport: OnceCell::new(),
                })
                .collect(),
        ),
        concurrency: 8,
        timeout,
        rate_limit: 0,
        governor: Arc::new(NetworkGovernor::new(NetworkControl::Fixed, 0, 8)),
        next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        cadence_reservations: Arc::new(tokio::sync::Semaphore::new(MAX_CADENCE_RESERVATIONS)),
        selection_counter: Arc::new(AtomicU64::new(0)),
        authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
        authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    }
}

fn hickory_only_test_engine(address: SocketAddr, timeout: Duration) -> DnsEngine {
    DnsEngine {
        resolvers: Arc::new(vec![resolver_node_at(address, timeout)]),
        fast_resolvers: Arc::new(Vec::new()),
        concurrency: 8,
        timeout,
        rate_limit: 0,
        governor: Arc::new(NetworkGovernor::new(NetworkControl::Fixed, 0, 8)),
        next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        cadence_reservations: Arc::new(tokio::sync::Semaphore::new(MAX_CADENCE_RESERVATIONS)),
        selection_counter: Arc::new(AtomicU64::new(0)),
        authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
        authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    }
}

async fn counting_nxdomain_resolver() -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)
{
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            message
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, requests, task)
}

async fn target_positive_a_resolver(
    target: &str,
    value: &str,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = requests.clone();
    let target = format!("{}.", target.trim_end_matches('.'));
    let value = value.parse().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            let question = &message.queries()[0];
            let positive = question.name().to_utf8().eq_ignore_ascii_case(&target)
                && question.query_type() == RecordType::A;
            message
                .set_message_type(MessageType::Response)
                .set_response_code(if positive {
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                });
            if positive {
                message.add_answer(Record::from_rdata(
                    message.queries()[0].name().clone(),
                    60,
                    RData::A(A(value)),
                ));
            }
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, requests, task)
}

async fn target_positive_a_silent_aaaa_resolver(
    target: &str,
    value: &str,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = requests.clone();
    let target = format!("{}.", target.trim_end_matches('.'));
    let value = value.parse().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            let question = &message.queries()[0];
            let target_query = question.name().to_utf8().eq_ignore_ascii_case(&target);
            if target_query && question.query_type() == RecordType::AAAA {
                continue;
            }
            let positive = target_query && question.query_type() == RecordType::A;
            message
                .set_message_type(MessageType::Response)
                .set_response_code(if positive {
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                });
            if positive {
                message.add_answer(Record::from_rdata(
                    message.queries()[0].name().clone(),
                    60,
                    RData::A(A(value)),
                ));
            }
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, requests, task)
}

async fn target_nodata_resolver(
    target: &str,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = requests.clone();
    let target = format!("{}.", target.trim_end_matches('.'));
    let task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            let target_query = message.queries()[0]
                .name()
                .to_utf8()
                .eq_ignore_ascii_case(&target);
            message
                .set_message_type(MessageType::Response)
                .set_response_code(if target_query {
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                });
            message.metadata.recursion_available = true;
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, requests, task)
}

async fn cname_nxdomain_resolver(
    target: &str,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = requests.clone();
    let target = format!("{}.", target.trim_end_matches('.'));
    let cname = Name::from_str("missing-target.example.test.").unwrap();
    let task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            let target_query = message.queries()[0]
                .name()
                .to_utf8()
                .eq_ignore_ascii_case(&target);
            message
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            if target_query {
                message.add_answer(Record::from_rdata(
                    message.queries()[0].name().clone(),
                    60,
                    RData::CNAME(CNAME(cname.clone())),
                ));
            }
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, requests, task)
}

#[tokio::test]
async fn consensus_returns_as_soon_as_a_positive_quorum_is_ready() {
    let results = stream::iter(vec![
        Box::pin(async { RecordLookupOutcome::Positive(positive_records("192.0.2.10")) })
            as futures_util::future::BoxFuture<'static, RecordLookupOutcome>,
        Box::pin(async { RecordLookupOutcome::Positive(positive_records("192.0.2.10")) }),
        Box::pin(async { std::future::pending::<RecordLookupOutcome>().await }),
    ])
    .buffer_unordered(3);
    let outcome = tokio::time::timeout(
        Duration::from_millis(250),
        collect_consensus_results("api.example.test", 2, results),
    )
    .await
    .expect("a ready positive quorum must cancel the slow tail");
    let DnsResolutionOutcome::Positive(answer) = outcome else {
        panic!("positive quorum was not accepted");
    };
    assert_eq!(answer.resolver_count, 2);
    assert_eq!(answer.records, positive_records("192.0.2.10"));
}

#[tokio::test]
async fn consensus_keeps_negative_and_partial_results_conservative() {
    let negative = collect_consensus_results(
        "missing.example.test",
        2,
        stream::iter([RecordLookupOutcome::Negative, RecordLookupOutcome::Negative]),
    )
    .await;
    assert!(matches!(negative, DnsResolutionOutcome::Negative { .. }));

    let unavailable = collect_consensus_results(
        "unknown.example.test",
        2,
        stream::iter([
            RecordLookupOutcome::Negative,
            RecordLookupOutcome::Negative,
            RecordLookupOutcome::Indeterminate,
        ]),
    )
    .await;
    assert!(matches!(
        unavailable,
        DnsResolutionOutcome::Indeterminate { .. }
    ));

    let split_vote = collect_consensus_results(
        "split.example.test",
        2,
        stream::iter([
            RecordLookupOutcome::Positive(positive_records("192.0.2.20")),
            RecordLookupOutcome::Negative,
            RecordLookupOutcome::Negative,
        ]),
    )
    .await;
    assert!(matches!(
        split_vote,
        DnsResolutionOutcome::Indeterminate { .. }
    ));
}

#[tokio::test]
async fn intentional_rate_queue_does_not_consume_the_network_timeout() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0_u8; 2_048];
            let Ok(Ok((length, peer))) =
                tokio::time::timeout(Duration::from_millis(500), server.recv_from(&mut buffer))
                    .await
            else {
                break;
            };
            let mut response = Message::from_vec(&buffer[..length]).unwrap();
            response
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NoError);
            if response.queries()[0].query_type() == RecordType::A {
                response.add_answer(Record::from_rdata(
                    response.queries()[0].name().clone(),
                    60,
                    RData::A(A("192.0.2.30".parse().unwrap())),
                ));
            }
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    // Pre-consume one 200 ms rate slot so host resolution must wait in the
    // intentional queue. Its network timeout is much shorter and must not
    // begin until a packet is actually sent.
    let engine =
        DnsEngine::new_with_socket_addresses(8, Duration::from_millis(20), &[address], 5).unwrap();
    engine.wait_for_rate_slot().await;
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        engine.resolve_host_classified("rate-limited.example.test"),
    )
    .await
    .expect("the caller's global cancellation bound remains effective");
    server_task.await.unwrap();
    let DnsResolutionOutcome::Positive(answer) = outcome else {
        panic!("the intentional rate-limit queue incorrectly consumed the network timeout");
    };
    assert_eq!(answer.records, positive_records("192.0.2.30"));
}

#[tokio::test]
async fn dead_primary_does_not_hide_a_live_secondary_before_the_host_deadline() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_address = silent.local_addr().unwrap();
    let live_address = live.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let mut buffer = [0_u8; 2_048];
            let (length, peer) = live.recv_from(&mut buffer).await.unwrap();
            let mut response = Message::from_vec(&buffer[..length]).unwrap();
            response
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NoError);
            if response.queries()[0].query_type() == RecordType::A {
                response.add_answer(Record::from_rdata(
                    response.queries()[0].name().clone(),
                    60,
                    RData::A(A("192.0.2.31".parse().unwrap())),
                ));
            }
            live.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let timeout = Duration::from_millis(50);
    let engine = DnsEngine {
        resolvers: Arc::new(vec![
            resolver_node_at(silent_address, timeout),
            resolver_node_at(live_address, timeout),
        ]),
        fast_resolvers: Arc::new(vec![
            FastResolver {
                address: silent_address,
                transport: OnceCell::new(),
            },
            FastResolver {
                address: live_address,
                transport: OnceCell::new(),
            },
        ]),
        concurrency: 8,
        timeout,
        rate_limit: 0,
        governor: Arc::new(NetworkGovernor::new(NetworkControl::Fixed, 0, 8)),
        next_query_at: Arc::new(tokio::sync::Mutex::new(Instant::now())),
        cadence_reservations: Arc::new(tokio::sync::Semaphore::new(MAX_CADENCE_RESERVATIONS)),
        selection_counter: Arc::new(AtomicU64::new(0)),
        authoritative_resolvers: Arc::new(Mutex::new(HashMap::new())),
        authoritative_server_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        engine.resolve_host_classified("secondary.example.test"),
    )
    .await
    .expect("bounded resolver operations did not terminate");
    // The positive A answer can complete the host before the concurrently
    // issued AAAA branch reaches the mock server. Do not make teardown
    // depend on a packet that cancellation is explicitly allowed to skip.
    server.abort();
    let _ = server.await;
    let DnsResolutionOutcome::Positive(answer) = outcome else {
        panic!("the healthy secondary resolver was not reached");
    };
    assert!(
        answer
            .records
            .iter()
            .any(|record| record.value == "192.0.2.31")
    );
    drop(silent);
}

#[tokio::test]
async fn authoritative_cache_is_single_flight_and_normalizes_keys() {
    let cache = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let first_calls = calls.clone();
    let second_calls = calls.clone();
    let first_cache = cache.clone();
    let second_cache = cache.clone();
    let first = authoritative_servers_cached(&first_cache, "Example.TEST.", move |_| async move {
        first_calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok(vec![(
            "ns1.example.test".to_owned(),
            vec!["192.0.2.53".parse().unwrap()],
        )])
    });
    let second = authoritative_servers_cached(&second_cache, "example.test", move |_| async move {
        second_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![(
            "should-not-run.example.test".to_owned(),
            vec!["192.0.2.54".parse().unwrap()],
        )])
    });
    let (first, second) = tokio::join!(first, second);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(first.unwrap(), second.unwrap());
}

#[tokio::test]
async fn authoritative_cache_keeps_empty_successes_but_retries_errors() {
    let empty_cache = tokio::sync::Mutex::new(HashMap::new());
    let empty_calls = Arc::new(AtomicUsize::new(0));
    let calls = empty_calls.clone();
    let first = authoritative_servers_cached(&empty_cache, "empty.test", move |_| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    })
    .await
    .unwrap();
    let calls = empty_calls.clone();
    let second = authoritative_servers_cached(&empty_cache, "empty.test.", move |_| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![("unexpected.empty.test".to_owned(), Vec::new())])
    })
    .await
    .unwrap();
    assert!(first.is_empty());
    assert!(second.is_empty());
    assert_eq!(empty_calls.load(Ordering::SeqCst), 1);

    let retry_cache = tokio::sync::Mutex::new(HashMap::new());
    let retry_calls = Arc::new(AtomicUsize::new(0));
    let calls = retry_calls.clone();
    let first = authoritative_servers_cached(&retry_cache, "retry.test", move |_| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        Err(anyhow::anyhow!("temporary failure"))
    })
    .await;
    assert!(first.is_err());
    let calls = retry_calls.clone();
    let second = authoritative_servers_cached(&retry_cache, "retry.test", move |_| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![("ns.retry.test".to_owned(), Vec::new())])
    })
    .await
    .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(retry_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn consensus_distinguishes_nxdomain_from_an_unavailable_quorum() {
    let (first, first_task) = nxdomain_resolver().await;
    let (second, second_task) = nxdomain_resolver().await;
    let negative = consensus_test_engine(vec![first, second])
        .resolve_host_consensus_classified("missing.example.test")
        .await;
    first_task.await.unwrap();
    second_task.await.unwrap();
    assert!(matches!(negative, DnsResolutionOutcome::Negative { .. }));

    let (available, available_task) = nxdomain_resolver().await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let indeterminate = consensus_test_engine(vec![available, silent.local_addr().unwrap()])
        .resolve_host_consensus_classified("unknown.example.test")
        .await;
    available_task.await.unwrap();
    assert!(matches!(
        indeterminate,
        DnsResolutionOutcome::Indeterminate { .. }
    ));
}

#[tokio::test]
async fn consensus_sends_a_and_aaaa_without_waiting_for_each_other() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let mut buffer = [0_u8; 2_048];
            let received =
                tokio::time::timeout(Duration::from_millis(500), server.recv_from(&mut buffer))
                    .await
                    .expect("A and AAAA must both be in flight")
                    .unwrap();
            let (length, peer) = received;
            requests.push((Message::from_vec(&buffer[..length]).unwrap(), peer));
        }
        let record_types = requests
            .iter()
            .map(|(message, _)| message.queries()[0].query_type())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            record_types,
            BTreeSet::from([RecordType::A, RecordType::AAAA])
        );
        for (mut response, peer) in requests {
            response
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });

    let mut engine = consensus_test_engine(vec![address]);
    engine.timeout = Duration::from_secs(2);
    let started = Instant::now();
    let outcome = engine
        .resolve_host_consensus_classified("parallel.example.test")
        .await;
    server_task.await.unwrap();
    assert!(matches!(outcome, DnsResolutionOutcome::Negative { .. }));
    assert!(started.elapsed() < Duration::from_millis(800));
}

#[tokio::test]
async fn positive_a_cancels_a_silent_aaaa_before_the_network_timeout() {
    let target = "ipv4-only.example.test";
    let (address, _, server_task) =
        target_positive_a_silent_aaaa_resolver(target, "192.0.2.70").await;
    let network_timeout = Duration::from_secs(3);
    let completion_limit = Duration::from_millis(750);

    let mut consensus = consensus_test_engine(vec![address]);
    consensus.timeout = network_timeout;
    let started = Instant::now();
    let consensus_outcome = tokio::time::timeout(
        completion_limit,
        consensus.resolve_host_consensus_classified(target),
    )
    .await
    .expect("a validated A answer waited for the silent AAAA timeout");
    let DnsResolutionOutcome::Positive(answer) = consensus_outcome else {
        panic!("the consensus path discarded a validated A answer");
    };
    assert_eq!(answer.records, positive_records("192.0.2.70"));
    assert!(started.elapsed() < completion_limit);

    let conservative = discovery_test_engine(&[address], network_timeout);
    let started = Instant::now();
    let conservative_outcome = tokio::time::timeout(
        completion_limit,
        conservative.resolve_host_classified(target),
    )
    .await
    .expect("the conservative path waited for the silent AAAA timeout");
    let DnsResolutionOutcome::Positive(answer) = conservative_outcome else {
        panic!("the conservative path discarded a validated A answer");
    };
    assert_eq!(answer.records, positive_records("192.0.2.70"));
    assert!(started.elapsed() < completion_limit);

    server_task.abort();
}

#[tokio::test]
async fn discovery_negative_requires_two_independent_nxdomain_resolvers() {
    let (primary, primary_requests, primary_task) = counting_nxdomain_resolver().await;
    let (secondary, secondary_requests, secondary_task) = counting_nxdomain_resolver().await;
    let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

    let first = engine
        .resolve_host_discovery_classified("first-missing.example.test")
        .await;
    assert!(matches!(first, DnsResolutionOutcome::Negative { .. }));
    assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
    assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

    let second = engine
        .resolve_host_discovery_classified("second-missing.example.test")
        .await;
    assert!(matches!(second, DnsResolutionOutcome::Negative { .. }));
    // Two A packets prove NXDOMAIN without an unnecessary AAAA query.
    assert_eq!(primary_requests.load(Ordering::SeqCst), 2);
    assert_eq!(secondary_requests.load(Ordering::SeqCst), 2);

    primary_task.abort();
    secondary_task.abort();
}

#[tokio::test]
async fn qualified_fast_path_requires_explicit_nxdomain_not_nodata() {
    let target = "nodata-on-primary.example.test";
    let (primary, primary_requests, primary_task) = target_nodata_resolver(target).await;
    let (secondary, secondary_requests, secondary_task) =
        target_positive_a_resolver(target, "192.0.2.45").await;
    let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

    let outcome = engine.resolve_host_discovery_classified(target).await;
    let DnsResolutionOutcome::Positive(answer) = outcome else {
        panic!("an empty NOERROR response incorrectly stopped resolver consensus");
    };
    assert_eq!(answer.records, positive_records("192.0.2.45"));
    assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
    assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

    primary_task.abort();
    secondary_task.abort();
}

#[tokio::test]
async fn nodata_is_indeterminate_on_discovery_conservative_and_consensus_paths() {
    let target = "addressless.example.test";
    let (first, _, first_task) = target_nodata_resolver(target).await;
    let (second, _, second_task) = target_nodata_resolver(target).await;
    let engine = discovery_test_engine(&[first, second], Duration::from_millis(100));

    for outcome in [
        engine.resolve_host_discovery_classified(target).await,
        engine.resolve_host_classified(target).await,
        consensus_test_engine(vec![first, second])
            .resolve_host_consensus_classified(target)
            .await,
    ] {
        assert!(matches!(
            outcome,
            DnsResolutionOutcome::Indeterminate { .. }
        ));
    }
    let health = engine.take_metrics();
    assert!(health.iter().map(|metric| metric.requests).sum::<u64>() > 0);
    assert_eq!(
        health.iter().map(|metric| metric.failures).sum::<u64>(),
        0,
        "valid NOERROR/NODATA is semantic absence, not a resolver failure"
    );

    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn hickory_fallback_distinguishes_nxdomain_from_nodata() {
    let target = "hickory-addressless.example.test";
    let (nodata, _, nodata_task) = target_nodata_resolver(target).await;
    let nodata_outcome = hickory_only_test_engine(nodata, Duration::from_millis(150))
        .resolve_host_classified(target)
        .await;
    assert!(matches!(
        nodata_outcome,
        DnsResolutionOutcome::Indeterminate { .. }
    ));
    nodata_task.abort();

    let (nxdomain, nxdomain_task) = nxdomain_resolver().await;
    let nxdomain_outcome = hickory_only_test_engine(nxdomain, Duration::from_millis(150))
        .resolve_host_classified("hickory-missing.example.test")
        .await;
    nxdomain_task.abort();
    assert!(matches!(
        nxdomain_outcome,
        DnsResolutionOutcome::Negative { .. }
    ));
}

#[tokio::test]
async fn nxdomain_with_owner_cname_is_positive_on_every_resolution_path() {
    let target = "dangling.example.test";
    let (first, _, first_task) = cname_nxdomain_resolver(target).await;
    let (second, _, second_task) = cname_nxdomain_resolver(target).await;
    let engine = discovery_test_engine(&[first, second], Duration::from_millis(100));

    for outcome in [
        engine.resolve_host_discovery_classified(target).await,
        engine.resolve_host_classified(target).await,
        consensus_test_engine(vec![first, second])
            .resolve_host_consensus_classified(target)
            .await,
    ] {
        let DnsResolutionOutcome::Positive(answer) = outcome else {
            panic!("a dangling CNAME was classified as a missing owner");
        };
        assert!(answer.records.iter().any(|record| {
            record.record_type == "CNAME" && record.value == "missing-target.example.test"
        }));
    }

    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn discovery_disagreement_never_hides_a_live_secondary_answer() {
    let target = "live-on-secondary.example.test";
    let (primary, _, primary_task) = counting_nxdomain_resolver().await;
    let (secondary, _, secondary_task) = target_positive_a_resolver(target, "192.0.2.44").await;
    let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

    let DnsResolutionOutcome::Positive(answer) =
        engine.resolve_host_discovery_classified(target).await
    else {
        panic!("a primary NXDOMAIN hid the live secondary answer");
    };
    assert_eq!(answer.records, positive_records("192.0.2.44"));

    primary_task.abort();
    secondary_task.abort();
}

#[tokio::test]
async fn conservative_and_trusted_paths_find_positive_after_primary_nxdomain() {
    let target = "live-on-secondary.example.test";
    let (primary, primary_requests, primary_task) = counting_nxdomain_resolver().await;
    let (secondary, secondary_requests, secondary_task) =
        target_positive_a_resolver(target, "192.0.2.44").await;
    let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

    let outcome = engine.resolve_host_classified(target).await;
    let DnsResolutionOutcome::Positive(answer) = outcome else {
        panic!("the conservative path stopped at the primary NXDOMAIN");
    };
    assert_eq!(answer.records, positive_records("192.0.2.44"));
    assert_eq!(primary_requests.load(Ordering::SeqCst), 2);
    assert_eq!(secondary_requests.load(Ordering::SeqCst), 2);

    // Final trusted consensus remains independent from the discovery
    // shortcut and still requires two positive resolvers.
    let (tertiary, _, tertiary_task) = target_positive_a_resolver(target, "192.0.2.44").await;
    let trusted = consensus_test_engine(vec![primary, secondary, tertiary])
        .resolve_host_consensus_classified(target)
        .await;
    let DnsResolutionOutcome::Positive(answer) = trusted else {
        panic!("trusted consensus did not retain the positive quorum");
    };
    assert_eq!(answer.resolver_count, 2);
    assert_eq!(answer.records, positive_records("192.0.2.44"));

    primary_task.abort();
    secondary_task.abort();
    tertiary_task.abort();
}

#[tokio::test]
async fn strict_two_resolver_nxdomain_needs_no_cached_health_probe() {
    let primary_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let primary = primary_server.local_addr().unwrap();
    let primary_requests = Arc::new(AtomicUsize::new(0));
    let request_count = primary_requests.clone();
    let primary_task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = primary_server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            let question = &message.queries()[0];
            let health_aaaa = question
                .name()
                .to_utf8()
                .starts_with("fellaga-negative-health-")
                && question.query_type() == RecordType::AAAA;
            message
                .set_message_type(MessageType::Response)
                .set_response_code(if health_aaaa {
                    // An empty NOERROR is not a strict NXDOMAIN and must
                    // reject the one-resolver shortcut.
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                });
            primary_server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (secondary, secondary_requests, secondary_task) = counting_nxdomain_resolver().await;
    let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(100));

    let first = engine
        .resolve_host_discovery_classified("missing-after-bad-probe.example.test")
        .await;
    assert!(matches!(first, DnsResolutionOutcome::Negative { .. }));
    assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
    assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

    primary_task.abort();
    secondary_task.abort();
}

#[tokio::test]
async fn discovery_quorum_timeout_falls_back_without_becoming_negative() {
    let primary_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let primary = primary_server.local_addr().unwrap();
    let primary_requests = Arc::new(AtomicUsize::new(0));
    let request_count = primary_requests.clone();
    let primary_task = tokio::spawn(async move {
        loop {
            let mut buffer = [0_u8; 2_048];
            let Ok((length, peer)) = primary_server.recv_from(&mut buffer).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut message = Message::from_vec(&buffer[..length]).unwrap();
            let question = &message.queries()[0];
            let drop_response = question
                .name()
                .to_utf8()
                .eq_ignore_ascii_case("timeout.example.test.")
                && question.query_type() == RecordType::A;
            if drop_response {
                continue;
            }
            message
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            primary_server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (secondary, secondary_requests, secondary_task) = counting_nxdomain_resolver().await;
    let engine = discovery_test_engine(&[primary, secondary], Duration::from_millis(40));

    let warmup = engine
        .resolve_host_discovery_classified("warmup-missing.example.test")
        .await;
    assert!(matches!(warmup, DnsResolutionOutcome::Negative { .. }));
    assert_eq!(primary_requests.load(Ordering::SeqCst), 1);
    assert_eq!(secondary_requests.load(Ordering::SeqCst), 1);

    let timed_out = engine
        .resolve_host_discovery_classified("timeout.example.test")
        .await;
    assert!(matches!(
        timed_out,
        DnsResolutionOutcome::Indeterminate { .. }
    ));
    assert!(primary_requests.load(Ordering::SeqCst) >= 3);
    assert!(secondary_requests.load(Ordering::SeqCst) >= 3);

    primary_task.abort();
    secondary_task.abort();
}

#[test]
fn resolver_health_requires_a_strict_untruncated_nxdomain() {
    let mut response = Message::new(0, MessageType::Response, OpCode::Query);
    response
        .set_message_type(MessageType::Response)
        .set_response_code(ResponseCode::NXDomain);
    assert!(is_definitive_nxdomain(&response));
    response.add_answer(Record::from_rdata(
        Name::from_str("probe.invalid.").unwrap(),
        60,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    assert!(!is_definitive_nxdomain(&response));
    response.answers.clear();
    response.set_truncated(true);
    assert!(!is_definitive_nxdomain(&response));
    response
        .set_truncated(false)
        .set_response_code(ResponseCode::NoError);
    assert!(!is_definitive_nxdomain(&response));
    response.set_response_code(ResponseCode::ServFail);
    assert!(!is_definitive_nxdomain(&response));
}

#[tokio::test]
async fn udp_transport_correlates_out_of_order_responses_and_sends_edns0() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut received = Vec::new();
        for _ in 0..2 {
            let mut buffer = [0_u8; 2_048];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            let message = Message::from_vec(&buffer[..length]).unwrap();
            assert!(message.extensions().is_some());
            assert!(message.recursion_desired());
            received.push((message, peer));
        }
        for (mut message, peer) in received.into_iter().rev() {
            message
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NXDomain);
            server
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let transport = FastUdpTransport::connect(address).await.unwrap();
    let (alpha, beta) = tokio::join!(
        transport.query(
            "alpha.example.com",
            RecordType::A,
            true,
            Duration::from_secs(1)
        ),
        transport.query(
            "beta.example.com",
            RecordType::AAAA,
            true,
            Duration::from_secs(1)
        )
    );
    server_task.await.unwrap();
    assert_eq!(
        alpha.unwrap().queries()[0].name().to_utf8(),
        "alpha.example.com."
    );
    assert_eq!(
        beta.unwrap().queries()[0].name().to_utf8(),
        "beta.example.com."
    );
}

#[tokio::test]
async fn udp_transport_rejects_a_reused_id_with_the_wrong_question() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 2_048];
        let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
        let mut request = Message::from_vec(&buffer[..length]).unwrap();
        let mut wrong = Message::new(0, MessageType::Response, OpCode::Query);
        wrong
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(
                Name::from_str("wrong.example.com.").unwrap(),
                RecordType::A,
            ));
        server
            .send_to(&wrong.to_vec().unwrap(), peer)
            .await
            .unwrap();
        request
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NXDomain);
        server
            .send_to(&request.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let transport = FastUdpTransport::connect(address).await.unwrap();
    let response = transport
        .query(
            "expected.example.com",
            RecordType::A,
            true,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    server_task.await.unwrap();
    assert_eq!(
        response.queries()[0].name().to_utf8(),
        "expected.example.com."
    );
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[tokio::test]
async fn truncated_udp_queries_fall_back_to_a_correlated_tcp_response() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0_u8; 2_048];
        let (length, peer) = udp.recv_from(&mut buffer).await.unwrap();
        let mut response = Message::from_vec(&buffer[..length]).unwrap();
        response
            .set_message_type(MessageType::Response)
            .set_truncated(true)
            .set_response_code(ResponseCode::NoError);
        udp.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap() as usize;
        let mut payload = vec![0_u8; length];
        stream.read_exact(&mut payload).await.unwrap();
        let mut response = Message::from_vec(&payload).unwrap();
        response
            .set_message_type(MessageType::Response)
            .set_truncated(false)
            .set_response_code(ResponseCode::NXDomain);
        let payload = response.to_vec().unwrap();
        stream.write_u16(payload.len() as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let resolver = FastResolver {
        address,
        transport: OnceCell::new(),
    };
    let response = resolver
        .query(
            "missing.example.test",
            RecordType::A,
            true,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
    assert!(!response.truncated());
}

#[tokio::test]
async fn dropping_a_udp_transport_stops_its_receiver_task() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = FastUdpTransport::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    let receiver = transport.receiver.clone();
    assert!(!receiver.is_finished());
    drop(transport);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !receiver.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_a_udp_query_releases_its_pending_id() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = FastUdpTransport::connect(silent.local_addr().unwrap())
        .await
        .unwrap();
    let query_transport = transport.clone();
    let query = tokio::spawn(async move {
        query_transport
            .query(
                "cancelled.example",
                RecordType::A,
                true,
                Duration::from_secs(30),
            )
            .await
    });
    for _ in 0..100 {
        if !transport.pending.lock().await.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(transport.pending.lock().await.len(), 1);
    query.abort();
    let _ = query.await;
    for _ in 0..100 {
        if transport.pending.lock().await.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(transport.pending.lock().await.is_empty());
}

#[tokio::test]
async fn udp_slot_queue_is_part_of_the_network_timeout() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transport = FastUdpTransport::connect(silent.local_addr().unwrap())
        .await
        .unwrap();
    let _all_slots = transport
        .slots
        .clone()
        .acquire_many_owned(4_096)
        .await
        .unwrap();

    let result = tokio::time::timeout(
        Duration::from_millis(200),
        transport.query(
            "queued.example",
            RecordType::A,
            true,
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("the UDP admission queue ignored the per-query deadline");

    assert!(result.is_err());
    assert!(transport.pending.lock().await.is_empty());
}

#[tokio::test]
async fn tcp_slot_queue_is_part_of_the_network_timeout() {
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        query_tcp_with_slots(
            Arc::new(tokio::sync::Semaphore::new(0)),
            "127.0.0.1:9".parse().unwrap(),
            "queued.example",
            RecordType::A,
            true,
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("the TCP admission queue ignored the per-query deadline");

    assert!(result.is_err());
}

#[test]
fn trusted_engines_can_share_one_rate_limiter() {
    let primary = DnsEngine::new_with_rate(
        8,
        Duration::from_secs(1),
        &["1.1.1.1".parse().unwrap()],
        100,
    )
    .unwrap();
    let trusted = DnsEngine::new_with_rate(
        4,
        Duration::from_secs(1),
        &["8.8.8.8".parse().unwrap()],
        500,
    )
    .unwrap()
    .share_rate_limit_with(&primary);
    assert_eq!(trusted.rate_limit, 100);
    assert!(Arc::ptr_eq(&primary.next_query_at, &trusted.next_query_at));
    assert!(Arc::ptr_eq(
        &primary.cadence_reservations,
        &trusted.cadence_reservations
    ));
}

#[tokio::test]
async fn cadence_reservation_horizon_is_bounded_under_cancellation() {
    let engine = DnsEngine::new_with_rate(
        32,
        Duration::from_secs(1),
        &["1.1.1.1".parse().unwrap()],
        10,
    )
    .unwrap();
    let base = Instant::now() + Duration::from_secs(5);
    *engine.next_query_at.lock().await = base;

    let mut waiters = Vec::new();
    for _ in 0..(MAX_CADENCE_RESERVATIONS * 4) {
        let engine = engine.clone();
        waiters.push(tokio::spawn(async move {
            engine.wait_for_rate_slot().await;
        }));
    }

    let spacing = Duration::from_secs_f64(1.0 / 10.0);
    let expected_horizon = base + spacing * MAX_CADENCE_RESERVATIONS as u32;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let horizon = *engine.next_query_at.lock().await;
            assert!(
                horizon <= expected_horizon,
                "cadence reservations escaped their bounded horizon"
            );
            if horizon == expected_horizon {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cadence waiters did not reserve the bounded slots");

    for waiter in &waiters {
        waiter.abort();
    }
    for waiter in waiters {
        let _ = waiter.await;
    }

    assert_eq!(*engine.next_query_at.lock().await, expected_horizon);
    assert_eq!(
        engine.cadence_reservations.available_permits(),
        0,
        "cancelled reservations released their permits before their slots"
    );
}

#[tokio::test]
async fn cadence_reservation_queue_respects_the_caller_deadline() {
    let engine = DnsEngine::new_with_rate(
        8,
        Duration::from_secs(1),
        &["1.1.1.1".parse().unwrap()],
        100,
    )
    .unwrap();
    let initial_horizon = *engine.next_query_at.lock().await;
    let held = engine
        .cadence_reservations
        .clone()
        .acquire_many_owned(MAX_CADENCE_RESERVATIONS as u32)
        .await
        .unwrap();

    let acquired = tokio::time::timeout(
        Duration::from_millis(250),
        engine.wait_for_rate_slot_before(tokio::time::Instant::now() + Duration::from_millis(25)),
    )
    .await
    .expect("cadence admission ignored its caller deadline");

    assert!(!acquired);
    assert_eq!(*engine.next_query_at.lock().await, initial_horizon);
    drop(held);
}

#[tokio::test]
async fn loopback_benchmark_reports_completed_queries_and_loss() {
    let result = DnsEngine::benchmark_loopback(1_000, 128, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(result.queries, 1_000);
    assert_eq!(result.completed, 1_000);
    assert_eq!(result.failures, 0);
    assert_eq!(result.loss_rate, 0.0);
    assert!(result.queries_per_second > 0.0);
}

#[test]
fn wildcard_profiles_require_an_observed_value_not_only_a_record_type() {
    let answer = ResolvedHost {
        fqdn: "random.example.com".to_owned(),
        records: vec![DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.99".to_owned(),
            ttl: 60,
        }],
        from_cache: false,
        last_verified_at: None,
        authoritative_validation: false,
        resolver_count: 1,
    };
    assert!(!DnsEngine::matches_wildcard(
        &answer,
        &BTreeSet::from(["A:*".to_owned()])
    ));
    assert!(DnsEngine::matches_wildcard(
        &answer,
        &BTreeSet::from(["A:192.0.2.99".to_owned()])
    ));
    assert!(DnsEngine::exactly_matches_wildcard(
        &answer,
        &BTreeSet::from(["A:192.0.2.99".to_owned()])
    ));
    assert!(!DnsEngine::matches_wildcard(
        &answer,
        &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
    ));
    let aliased = ResolvedHost {
        fqdn: "random.example.com".to_owned(),
        records: vec![
            DnsRecord {
                record_type: "CNAME".to_owned(),
                value: "wild.example.com".to_owned(),
                ttl: 60,
            },
            DnsRecord {
                record_type: "A".to_owned(),
                value: "192.0.2.123".to_owned(),
                ttl: 60,
            },
        ],
        from_cache: false,
        last_verified_at: None,
        authoritative_validation: false,
        resolver_count: 2,
    };
    assert!(DnsEngine::matches_wildcard(
        &aliased,
        &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
    ));
    assert!(!DnsEngine::exactly_matches_wildcard(
        &aliased,
        &BTreeSet::from(["CNAME:wild.example.com".to_owned()])
    ));
}

#[test]
fn wildcard_probe_never_treats_timeouts_or_conflicts_as_a_normal_zone() {
    assert_eq!(
        classify_wildcard_samples(Vec::new(), 2, 3),
        WildcardProbeOutcome::Indeterminate
    );
    assert_eq!(
        classify_wildcard_samples(vec![BTreeSet::from(["A:192.0.2.10".to_owned()])], 4, 5,),
        WildcardProbeOutcome::Indeterminate
    );
    assert_eq!(
        classify_wildcard_samples(Vec::new(), 3, 3),
        WildcardProbeOutcome::Normal
    );
    assert_eq!(
        classify_wildcard_samples(Vec::new(), 3, 5),
        WildcardProbeOutcome::Indeterminate,
        "three NXDOMAIN answers plus two timeouts are incomplete evidence"
    );
    assert_eq!(
        classify_wildcard_samples(
            vec![
                BTreeSet::from([
                    "A:192.0.2.10".to_owned(),
                    "CNAME:wild.example.com".to_owned(),
                ]),
                BTreeSet::from([
                    "A:192.0.2.11".to_owned(),
                    "CNAME:wild.example.com".to_owned(),
                ]),
                BTreeSet::from([
                    "A:192.0.2.12".to_owned(),
                    "CNAME:wild.example.com".to_owned(),
                ]),
            ],
            0,
            3,
        ),
        WildcardProbeOutcome::Wildcard(BTreeSet::from(["CNAME:wild.example.com".to_owned()]))
    );
    assert_eq!(
        classify_wildcard_samples(
            vec![
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
                BTreeSet::from(["A:192.0.2.11".to_owned()]),
                BTreeSet::from(["A:192.0.2.12".to_owned()]),
            ],
            0,
            3,
        ),
        WildcardProbeOutcome::Indeterminate
    );
}

#[test]
fn wildcard_probe_first_stage_finishes_only_for_conclusive_samples() {
    assert_eq!(
        conclusive_wildcard_outcome(&[], 3),
        Some(WildcardProbeOutcome::Normal)
    );

    let stable_alias = vec![
        BTreeSet::from([
            "A:192.0.2.10".to_owned(),
            "CNAME:wild.example.com".to_owned(),
        ]),
        BTreeSet::from([
            "A:192.0.2.11".to_owned(),
            "CNAME:wild.example.com".to_owned(),
        ]),
        BTreeSet::from([
            "A:192.0.2.12".to_owned(),
            "CNAME:wild.example.com".to_owned(),
        ]),
    ];
    assert_eq!(
        conclusive_wildcard_outcome(&stable_alias, 0),
        Some(WildcardProbeOutcome::Wildcard(BTreeSet::from([
            "CNAME:wild.example.com".to_owned()
        ])))
    );

    let rotating_addresses = vec![
        BTreeSet::from(["A:192.0.2.10".to_owned()]),
        BTreeSet::from(["A:192.0.2.11".to_owned()]),
        BTreeSet::from(["A:192.0.2.12".to_owned()]),
    ];
    assert_eq!(
        conclusive_wildcard_outcome(&rotating_addresses, 0),
        None,
        "a rotating wildcard must receive the second probe stage"
    );
    assert_eq!(
        conclusive_wildcard_outcome(&[BTreeSet::from(["A:192.0.2.10".to_owned()])], 1,),
        None,
        "mixed or incomplete evidence must never become normal"
    );
}

#[test]
fn wildcard_probe_second_stage_keeps_rotating_and_mixed_answers_indeterminate() {
    assert_eq!(
        classify_wildcard_samples(
            vec![
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
                BTreeSet::from(["A:192.0.2.11".to_owned()]),
                BTreeSet::from(["A:192.0.2.12".to_owned()]),
                BTreeSet::from(["A:192.0.2.13".to_owned()]),
                BTreeSet::from(["A:192.0.2.14".to_owned()]),
            ],
            0,
            5,
        ),
        WildcardProbeOutcome::Indeterminate
    );
    assert_eq!(
        classify_wildcard_samples(
            vec![
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
            ],
            3,
            5,
        ),
        WildcardProbeOutcome::Indeterminate,
        "mixed positive and negative samples must not become a normal zone"
    );
    assert_eq!(
        classify_wildcard_samples(
            vec![
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
                BTreeSet::from(["A:192.0.2.10".to_owned()]),
            ],
            2,
            5,
        ),
        WildcardProbeOutcome::Indeterminate,
        "mixed evidence must never authorize wildcard quarantine"
    );
}

#[test]
fn authoritative_zone_search_is_bounded_but_always_reaches_the_root_zone() {
    let zones = authoritative_zone_candidates("host.a.b.c.d.e.f.example.com", "example.com");
    assert_eq!(zones.len(), MAX_AUTHORITATIVE_ZONE_CANDIDATES);
    assert_eq!(
        zones.first().map(String::as_str),
        Some("a.b.c.d.e.f.example.com")
    );
    assert_eq!(zones.last().map(String::as_str), Some("example.com"));
}

#[test]
fn resolver_counters_saturate_instead_of_wrapping_or_panicking() {
    let mut state = ResolverState {
        requests: u64::MAX,
        successes: u64::MAX,
        failures: u64::MAX,
        total_ms: u64::MAX,
        consecutive_failures: u64::MAX,
        ..ResolverState::default()
    };
    record_resolver_state(&mut state, false, u64::MAX);
    record_resolver_state(&mut state, true, u64::MAX);
    assert_eq!(state.requests, u64::MAX);
    assert_eq!(state.successes, u64::MAX);
    assert_eq!(state.failures, u64::MAX);
    assert_eq!(state.total_ms, u64::MAX);
}

#[tokio::test]
async fn consensus_transport_failures_feed_the_shared_governor() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut engine =
        discovery_test_engine(&[silent.local_addr().unwrap()], Duration::from_millis(20));
    engine.governor = Arc::new(NetworkGovernor::new(NetworkControl::Adaptive, 0, 128));

    let outcome = engine
        .resolve_host_consensus_classified("silent.example")
        .await;
    assert!(matches!(
        outcome,
        DnsResolutionOutcome::Indeterminate { .. }
    ));
    engine.governor.evaluate_pending_for_test();
    assert_eq!(engine.network_governor_snapshot().backoffs, 1);
    let metrics = engine.take_metrics();
    assert_eq!(metrics.iter().map(|metric| metric.requests).sum::<u64>(), 2);
    assert_eq!(metrics.iter().map(|metric| metric.failures).sum::<u64>(), 2);
}

#[tokio::test]
async fn expired_ptr_deadline_starts_no_reverse_lookup() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = discovery_test_engine(&[silent.local_addr().unwrap()], Duration::from_secs(1));
    let (names, deadline_exhausted) = engine
        .reverse_names_until(
            vec!["1.1.1.1".parse().unwrap()],
            Some(tokio::time::Instant::now()),
        )
        .await;
    assert!(deadline_exhausted);
    assert!(names.is_empty());
    assert_eq!(
        engine
            .take_metrics()
            .iter()
            .map(|metric| metric.requests)
            .sum::<u64>(),
        0
    );
}

#[tokio::test]
async fn a_fast_failure_before_send_is_not_counted_as_a_network_attempt() {
    let target = "fallback-health.example.test";
    let (address, _, server_task) = target_positive_a_resolver(target, "192.0.2.88").await;
    let transport = FastUdpTransport::connect(address).await.unwrap();
    transport.slots.close();
    let cell = OnceCell::new();
    assert!(cell.set(transport).is_ok());

    let mut engine = discovery_test_engine(&[address], Duration::from_millis(100));
    engine.fast_resolvers = Arc::new(vec![FastResolver {
        address,
        transport: cell,
    }]);
    let outcome = engine
        .lookup_records_classified(target, RecordType::A)
        .await;
    assert!(matches!(outcome, RecordLookupOutcome::Positive(_)));

    let metrics = engine.take_metrics();
    assert_eq!(metrics.iter().map(|metric| metric.requests).sum::<u64>(), 1);
    assert_eq!(metrics.iter().map(|metric| metric.failures).sum::<u64>(), 0);
    assert_eq!(
        metrics.iter().map(|metric| metric.successes).sum::<u64>(),
        1
    );
    server_task.abort();
}

#[tokio::test]
async fn cancellation_after_udp_send_records_traffic_without_governor_pressure() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = silent.local_addr().unwrap();
    let mut engine = discovery_test_engine(&[address], Duration::from_secs(5));
    engine.governor = Arc::new(NetworkGovernor::new(NetworkControl::Adaptive, 0, 128));
    let engine = Arc::new(engine);
    let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let query = tokio::spawn({
        let engine = Arc::clone(&engine);
        let attempted = Arc::clone(&attempted);
        async move {
            engine
                .observed_fast_query_until(
                    &engine.fast_resolvers[0],
                    Some(&engine.resolvers[0]),
                    "cancelled.example.test",
                    RecordType::A,
                    true,
                    None,
                    Some(attempted),
                )
                .await
        }
    });

    let mut packet = [0_u8; 2_048];
    tokio::time::timeout(Duration::from_secs(1), silent.recv_from(&mut packet))
        .await
        .expect("the test query was never sent")
        .unwrap();
    assert!(attempted.load(Ordering::Acquire));
    query.abort();
    assert!(query.await.unwrap_err().is_cancelled());

    let metrics = engine.take_metrics();
    assert_eq!(metrics.iter().map(|metric| metric.requests).sum::<u64>(), 1);
    assert_eq!(
        metrics.iter().map(|metric| metric.successes).sum::<u64>(),
        0
    );
    assert_eq!(metrics.iter().map(|metric| metric.failures).sum::<u64>(), 0);
    engine.governor.evaluate_pending_for_test();
    assert_eq!(engine.network_governor_snapshot().backoffs, 0);
}

#[tokio::test]
async fn cancellation_before_udp_send_does_not_fabricate_metrics_or_attempts() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = silent.local_addr().unwrap();
    let transport = FastUdpTransport::connect(address).await.unwrap();
    transport.slots.close();
    let cell = OnceCell::new();
    assert!(cell.set(transport).is_ok());
    let mut engine = discovery_test_engine(&[address], Duration::from_millis(50));
    engine.fast_resolvers = Arc::new(vec![FastResolver {
        address,
        transport: cell,
    }]);
    engine.governor = Arc::new(NetworkGovernor::new(NetworkControl::Adaptive, 0, 128));
    let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let result = engine
        .observed_fast_query_until(
            &engine.fast_resolvers[0],
            Some(&engine.resolvers[0]),
            "never-sent.example.test",
            RecordType::A,
            true,
            None,
            Some(Arc::clone(&attempted)),
        )
        .await;
    assert!(result.is_err());
    assert!(!attempted.load(Ordering::Acquire));
    assert!(engine.take_metrics().is_empty());
    engine.governor.evaluate_pending_for_test();
    assert_eq!(engine.network_governor_snapshot().backoffs, 0);
}

#[tokio::test]
async fn authoritative_discovery_is_deadline_bounded_and_fully_measured() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);
    let server_task = tokio::spawn(async move {
        loop {
            let mut packet = [0_u8; 2_048];
            let Ok((length, peer)) = server.recv_from(&mut packet).await else {
                break;
            };
            request_count.fetch_add(1, Ordering::SeqCst);
            let mut response = Message::from_vec(&packet[..length]).unwrap();
            let query = response.queries()[0].clone();
            response
                .set_message_type(MessageType::Response)
                .set_response_code(ResponseCode::NoError);
            response.metadata.recursion_available = true;
            match query.query_type() {
                RecordType::NS => {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::NS(NS(Name::from_str("ns1.example.test.").unwrap())),
                    ));
                }
                RecordType::A => {
                    response.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A("192.0.2.53".parse().unwrap())),
                    ));
                }
                RecordType::AAAA => {}
                unexpected => panic!("unexpected query type: {unexpected}"),
            }
            server
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let engine = discovery_test_engine(&[address], Duration::from_secs(1));

    let servers = engine
        .authoritative_servers_until(
            "example.test",
            Some(tokio::time::Instant::now() + Duration::from_secs(1)),
        )
        .await
        .unwrap();
    assert_eq!(
        servers,
        vec![(
            "ns1.example.test".to_owned(),
            vec!["192.0.2.53".parse().unwrap()]
        )]
    );
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    let metrics = engine.take_metrics();
    assert_eq!(metrics.iter().map(|metric| metric.requests).sum::<u64>(), 3);
    assert_eq!(
        metrics.iter().map(|metric| metric.successes).sum::<u64>(),
        3
    );
    assert_eq!(metrics.iter().map(|metric| metric.failures).sum::<u64>(), 0);
    server_task.abort();

    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = discovery_test_engine(&[silent.local_addr().unwrap()], Duration::from_secs(2));
    let started = Instant::now();
    let result = engine
        .authoritative_servers_until(
            "deadline.example.test",
            Some(tokio::time::Instant::now() + Duration::from_millis(25)),
        )
        .await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_millis(500));
    let metrics = engine.take_metrics();
    assert_eq!(metrics.iter().map(|metric| metric.requests).sum::<u64>(), 1);
    assert_eq!(metrics.iter().map(|metric| metric.failures).sum::<u64>(), 1);
}

#[test]
fn resolver_pool_prefers_the_healthier_profile_but_keeps_exploration() {
    let engine = DnsEngine::new(
        10,
        Duration::from_secs(1),
        &["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()],
    )
    .unwrap();
    engine.seed_metrics(&HashMap::from([
        (
            "1.1.1.1".to_owned(),
            ResolverMetric {
                resolver: "1.1.1.1".to_owned(),
                requests: 100,
                successes: 50,
                failures: 50,
                average_ms: 500,
                consecutive_failures: 3,
            },
        ),
        (
            "8.8.8.8".to_owned(),
            ResolverMetric {
                resolver: "8.8.8.8".to_owned(),
                requests: 100,
                successes: 100,
                failures: 0,
                average_ms: 20,
                consecutive_failures: 0,
            },
        ),
    ]));
    let exploratory = engine.resolver_order();
    let adaptive = engine.resolver_order();
    assert_eq!(exploratory[0], 0);
    assert_eq!(adaptive[0], 1);
}

#[test]
fn shared_dns_engines_contribute_to_one_governor_window() {
    let primary = DnsEngine::new_with_rate_and_control(
        128,
        Duration::from_secs(1),
        &["1.1.1.1".parse().unwrap()],
        250,
        NetworkControl::Adaptive,
    )
    .unwrap();
    let trusted = DnsEngine::new_with_rate_and_control(
        128,
        Duration::from_secs(1),
        &["8.8.8.8".parse().unwrap()],
        250,
        NetworkControl::Adaptive,
    )
    .unwrap()
    .share_rate_limit_with(&primary);
    assert!(Arc::ptr_eq(&primary.governor, &trusted.governor));

    primary.governor.observe_delta(60, 0, 6_000);
    trusted.governor.observe_delta(40, 3, 4_000);
    primary.governor.evaluate_pending_for_test();

    assert_eq!(primary.network_governor_snapshot().backoffs, 1);
    assert_eq!(trusted.network_governor_snapshot().current_rate, 35);
    assert_eq!(primary.network_governor_snapshot().current_concurrency, 16);
}

#[test]
fn seeded_resolver_history_is_not_replayed_into_the_first_governor_window() {
    let engine = DnsEngine::new_with_rate_and_control(
        128,
        Duration::from_secs(1),
        &["1.1.1.1".parse().unwrap()],
        250,
        NetworkControl::Adaptive,
    )
    .unwrap();
    engine.seed_metrics(&HashMap::from([(
        "1.1.1.1".to_owned(),
        ResolverMetric {
            resolver: "1.1.1.1".to_owned(),
            requests: 10_000,
            successes: 0,
            failures: 10_000,
            average_ms: 10_000,
            consecutive_failures: 10_000,
        },
    )]));

    engine.observe_network_outcome(true, 10);
    engine.governor.evaluate_pending_for_test();

    let snapshot = engine.network_governor_snapshot();
    assert_eq!(snapshot.current_rate, 50);
    assert_eq!(snapshot.current_concurrency, 32);
    assert_eq!(snapshot.backoffs, 0);
}

#[test]
fn duplicate_resolver_addresses_cannot_fake_an_independent_quorum() {
    let address = "1.1.1.1".parse().unwrap();
    let engine = DnsEngine::new(10, Duration::from_secs(1), &[address, address]).unwrap();
    assert_eq!(engine.resolvers.len(), 1);
    assert_eq!(engine.fast_resolvers.len(), 1);
}

#[test]
fn authoritative_transports_are_reused_per_address() {
    let engine = DnsEngine::new(10, Duration::from_secs(1), &["1.1.1.1".parse().unwrap()]).unwrap();
    let address = "192.0.2.53:53".parse().unwrap();
    let first = engine.authoritative_resolver(address).unwrap();
    let second = engine.authoritative_resolver(address).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn authoritative_transport_cache_is_bounded() {
    let engine = DnsEngine::new(10, Duration::from_secs(1), &["1.1.1.1".parse().unwrap()]).unwrap();
    for port in 1..=(MAX_AUTHORITATIVE_TRANSPORTS as u16 + 1) {
        engine
            .authoritative_resolver(SocketAddr::new("192.0.2.53".parse().unwrap(), port))
            .unwrap();
    }
    assert_eq!(
        engine.authoritative_resolvers.lock().unwrap().len(),
        MAX_AUTHORITATIVE_TRANSPORTS
    );
}

#[tokio::test]
async fn authoritative_zone_cache_is_bounded() {
    let cache = tokio::sync::Mutex::new(HashMap::new());
    for index in 0..=MAX_AUTHORITATIVE_SERVER_CACHE_ENTRIES {
        authoritative_servers_cached(&cache, &format!("zone-{index}.test"), |_| async {
            Ok(Vec::new())
        })
        .await
        .unwrap();
    }
    assert_eq!(
        cache.lock().await.len(),
        MAX_AUTHORITATIVE_SERVER_CACHE_ENTRIES
    );
}
