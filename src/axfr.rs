use crate::dns::DnsEngine;
use crate::model::{AxfrAttempt, AxfrStatus, DnsRecord};
use crate::util::normalize_observed_name;
use futures_util::{StreamExt, stream};
use hickory_net::client::{Client, ClientHandle};
use hickory_net::proto::op::ResponseCode;
use hickory_net::proto::rr::Name;
use hickory_net::proto::serialize::binary::BinEncodable;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

const AXFR_CONCURRENCY: usize = 4;
const AXFR_MAX_TARGETS: usize = 8;
const AXFR_MAX_RECORDS: usize = 250_000;
const AXFR_MAX_BYTES: usize = 64 * 1024 * 1024;
static AXFR_GATE: Semaphore = Semaphore::const_new(AXFR_CONCURRENCY);

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct TransferBudget {
    records: usize,
    bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum BudgetExceeded {
    Records,
    Bytes,
}

impl TransferBudget {
    fn consume(
        &mut self,
        record_bytes: usize,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<(), BudgetExceeded> {
        if self.records >= max_records {
            return Err(BudgetExceeded::Records);
        }
        let Some(next_bytes) = self.bytes.checked_add(record_bytes) else {
            return Err(BudgetExceeded::Bytes);
        };
        if next_bytes > max_bytes {
            return Err(BudgetExceeded::Bytes);
        }
        self.records += 1;
        self.bytes = next_bytes;
        Ok(())
    }
}

async fn transfer_one(
    domain: &str,
    nameserver: &str,
    address: IpAddr,
    operation_timeout: Duration,
) -> AxfrAttempt {
    let _permit = AXFR_GATE
        .acquire()
        .await
        .expect("le sémaphore AXFR statique ne doit jamais être fermé");
    let mut attempt = AxfrAttempt {
        nameserver: nameserver.to_owned(),
        address: address.to_string(),
        status: AxfrStatus::ProtocolError,
        error: None,
        records: Vec::new(),
        names: BTreeSet::new(),
    };
    let Some(deadline) = Instant::now().checked_add(operation_timeout) else {
        attempt.error = Some("durée maximale AXFR hors plage".to_owned());
        return attempt;
    };
    let zone = match Name::from_str(&format!("{domain}.")) {
        Ok(zone) => zone,
        Err(error) => {
            attempt.error = Some(error.to_string());
            return attempt;
        }
    };
    let socket = SocketAddr::new(address, 53);
    let (stream, sender) = TcpClientStream::new(socket, None, None, TokioRuntimeProvider::new());
    let connected_stream = match timeout_at(deadline, stream).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(error)) => {
            attempt.status = classify_protocol_error(&error.to_string());
            attempt.error = Some(error.to_string());
            return attempt;
        }
        Err(_) => {
            attempt.status = AxfrStatus::Timeout;
            attempt.error = Some("timeout de connexion TCP".to_owned());
            return attempt;
        }
    };
    let (mut client, background) = Client::<TokioRuntimeProvider>::new(connected_stream, sender);
    let _background = AbortOnDrop(tokio::spawn(background));
    let mut transfer = client.zone_transfer(zone, None);
    let mut budget = TransferBudget::default();
    let mut completed = false;
    'transfer: loop {
        match timeout_at(deadline, transfer.next()).await {
            Ok(Some(Ok(response))) => {
                let response_code = response.metadata.response_code;
                if let Some(status) = classify_response_code(response_code) {
                    attempt.status = status;
                    attempt.error = Some(format!(
                        "réponse AXFR DNS {response_code} reçue de {nameserver}"
                    ));
                    break 'transfer;
                }
                for record in &response.answers {
                    if Instant::now() >= deadline {
                        attempt.status = AxfrStatus::Timeout;
                        attempt.error =
                            Some("deadline absolue du transfert AXFR dépassée".to_owned());
                        break 'transfer;
                    }
                    let record_bytes = match record.to_bytes() {
                        Ok(encoded) => encoded.len(),
                        Err(error) => {
                            attempt.status = AxfrStatus::ProtocolError;
                            attempt.error = Some(format!(
                                "impossible de mesurer un enregistrement AXFR: {error}"
                            ));
                            break 'transfer;
                        }
                    };
                    if let Err(exceeded) =
                        budget.consume(record_bytes, AXFR_MAX_RECORDS, AXFR_MAX_BYTES)
                    {
                        attempt.status = AxfrStatus::ProtocolError;
                        attempt.error = Some(match exceeded {
                            BudgetExceeded::Records => format!(
                                "plafond AXFR dépassé: plus de {AXFR_MAX_RECORDS} enregistrements"
                            ),
                            BudgetExceeded::Bytes => format!(
                                "plafond AXFR dépassé: plus de {} Mio de données DNS",
                                AXFR_MAX_BYTES / (1024 * 1024)
                            ),
                        });
                        break 'transfer;
                    }
                    let fqdn = record
                        .name
                        .to_utf8()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if let Some(name) = normalize_observed_name(&fqdn, domain) {
                        attempt.names.insert(name);
                    }
                    attempt.records.push(DnsRecord {
                        record_type: record.record_type().to_string(),
                        value: record.data.to_string().trim_end_matches('.').to_owned(),
                        ttl: record.ttl,
                    });
                }
            }
            Ok(Some(Err(error))) => {
                attempt.status = classify_protocol_error(&error.to_string());
                attempt.error = Some(error.to_string());
                break;
            }
            Ok(None) => {
                completed = true;
                break;
            }
            Err(_) => {
                attempt.status = AxfrStatus::Timeout;
                attempt.error = Some("deadline absolue du transfert AXFR dépassée".to_owned());
                break;
            }
        }
    }
    drop(transfer);
    if completed {
        attempt.status = classify_completed_transfer(&attempt.records);
        if attempt.status == AxfrStatus::Empty {
            attempt.error = Some(
                "transfert incomplet ou vide: paire de SOA d'ouverture et de fermeture identiques absente"
                    .to_owned(),
            );
        }
    }
    attempt
}

fn classify_response_code(response_code: ResponseCode) -> Option<AxfrStatus> {
    match response_code {
        ResponseCode::NoError => None,
        ResponseCode::Refused => Some(AxfrStatus::Refused),
        _ => Some(AxfrStatus::ProtocolError),
    }
}

fn classify_protocol_error(error: &str) -> AxfrStatus {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("refused") || normalized.contains("refus") {
        AxfrStatus::Refused
    } else if normalized.contains("timeout") || normalized.contains("timed out") {
        AxfrStatus::Timeout
    } else {
        AxfrStatus::ProtocolError
    }
}

fn classify_completed_transfer(records: &[DnsRecord]) -> AxfrStatus {
    match (records.first(), records.last()) {
        (Some(opening), Some(closing))
            if records.len() >= 2
                && opening.record_type.eq_ignore_ascii_case("SOA")
                && closing.record_type.eq_ignore_ascii_case("SOA")
                && opening.value == closing.value =>
        {
            AxfrStatus::Success
        }
        _ => AxfrStatus::Empty,
    }
}

fn unique_targets(
    servers: Vec<(String, Vec<IpAddr>)>,
    warnings: &mut Vec<String>,
) -> Vec<(String, IpAddr)> {
    let mut by_server = BTreeMap::<String, BTreeSet<IpAddr>>::new();
    for (nameserver, addresses) in servers {
        let nameserver = nameserver.trim().trim_end_matches('.').to_ascii_lowercase();
        if nameserver.is_empty() {
            warnings.push("AXFR: nom de serveur vide ignoré".to_owned());
            continue;
        }
        by_server.entry(nameserver).or_default().extend(addresses);
    }

    let mut seen_addresses = BTreeSet::new();
    let mut targets = Vec::new();
    for (nameserver, addresses) in by_server {
        if addresses.is_empty() {
            warnings.push(format!("AXFR: aucune IP pour {nameserver}"));
            continue;
        }
        for address in addresses {
            if seen_addresses.insert(address) {
                targets.push((nameserver.clone(), address));
            }
        }
    }
    targets
}

fn bounded_targets(
    mut targets: Vec<(String, IpAddr)>,
    warnings: &mut Vec<String>,
) -> Vec<(String, IpAddr)> {
    if targets.len() > AXFR_MAX_TARGETS {
        warnings.push(format!(
            "AXFR: {} cible(s) autoritaire(s) trouvée(s), seules les {AXFR_MAX_TARGETS} premières seront testées",
            targets.len()
        ));
        targets.truncate(AXFR_MAX_TARGETS);
    }
    targets
}

pub async fn attempt_axfr(
    dns: &DnsEngine,
    domain: &str,
    operation_timeout: Duration,
) -> (Vec<AxfrAttempt>, Vec<String>) {
    let servers = match dns.authoritative_servers(domain).await {
        Ok(servers) => servers,
        Err(error) => return (Vec::new(), vec![format!("AXFR: {error:#}")]),
    };
    let mut warnings = Vec::new();
    let targets = bounded_targets(unique_targets(servers, &mut warnings), &mut warnings);
    let mut attempts = Vec::new();
    {
        let mut pending = stream::iter(targets)
            .map(|(nameserver, address)| async move {
                transfer_one(domain, &nameserver, address, operation_timeout).await
            })
            .buffer_unordered(AXFR_CONCURRENCY);
        while let Some(attempt) = pending.next().await {
            let succeeded = attempt.status == AxfrStatus::Success;
            attempts.push(attempt);
            if succeeded {
                break;
            }
        }
    }
    attempts.sort_by(|left, right| {
        (&left.nameserver, &left.address).cmp(&(&right.nameserver, &right.address))
    });
    (attempts, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn soa() -> DnsRecord {
        DnsRecord {
            record_type: "SOA".to_owned(),
            value: "ns1.example.test. hostmaster.example.test. 1 60 60 60 60".to_owned(),
            ttl: 60,
        }
    }

    #[test]
    fn axfr_requires_opening_and_closing_soa() {
        assert_eq!(classify_completed_transfer(&[]), AxfrStatus::Empty);
        assert_eq!(classify_completed_transfer(&[soa()]), AxfrStatus::Empty);
        assert_eq!(
            classify_completed_transfer(&[soa(), soa()]),
            AxfrStatus::Success
        );

        let a = DnsRecord {
            record_type: "A".to_owned(),
            value: "192.0.2.1".to_owned(),
            ttl: 60,
        };
        assert_eq!(
            classify_completed_transfer(&[a.clone(), soa(), soa(), a]),
            AxfrStatus::Empty
        );

        let mut changed_soa = soa();
        changed_soa.value = "ns1.example.test. hostmaster.example.test. 2 60 60 60 60".to_owned();
        assert_eq!(
            classify_completed_transfer(&[soa(), changed_soa]),
            AxfrStatus::Empty
        );
    }

    #[test]
    fn axfr_budget_accepts_exact_caps_and_rejects_overflow() {
        let mut budget = TransferBudget::default();
        assert_eq!(budget.consume(6, 2, 10), Ok(()));
        assert_eq!(budget.consume(4, 2, 10), Ok(()));
        assert_eq!(
            budget,
            TransferBudget {
                records: 2,
                bytes: 10
            }
        );
        assert_eq!(budget.consume(0, 2, 10), Err(BudgetExceeded::Records));

        let mut byte_budget = TransferBudget::default();
        assert_eq!(byte_budget.consume(11, 2, 10), Err(BudgetExceeded::Bytes));
        assert_eq!(byte_budget, TransferBudget::default());
        assert_eq!(
            byte_budget.consume(usize::MAX, usize::MAX, usize::MAX),
            Ok(())
        );
        assert_eq!(
            byte_budget.consume(1, usize::MAX, usize::MAX),
            Err(BudgetExceeded::Bytes)
        );

        let mut record_cap = TransferBudget {
            records: AXFR_MAX_RECORDS,
            bytes: 0,
        };
        assert_eq!(
            record_cap.consume(0, AXFR_MAX_RECORDS, AXFR_MAX_BYTES),
            Err(BudgetExceeded::Records)
        );
        let mut byte_cap = TransferBudget {
            records: 0,
            bytes: AXFR_MAX_BYTES,
        };
        assert_eq!(
            byte_cap.consume(1, AXFR_MAX_RECORDS, AXFR_MAX_BYTES),
            Err(BudgetExceeded::Bytes)
        );
    }

    #[test]
    fn axfr_targets_deduplicate_servers_and_addresses() {
        let shared: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();
        let third: IpAddr = "192.0.2.3".parse().unwrap();
        let mut warnings = Vec::new();
        let targets = unique_targets(
            vec![
                ("NS1.EXAMPLE.TEST.".to_owned(), vec![shared, shared]),
                ("ns1.example.test".to_owned(), vec![second]),
                ("ns2.example.test".to_owned(), vec![shared, third]),
                ("empty.example.test".to_owned(), Vec::new()),
            ],
            &mut warnings,
        );

        assert_eq!(
            targets,
            vec![
                ("ns1.example.test".to_owned(), shared),
                ("ns1.example.test".to_owned(), second),
                ("ns2.example.test".to_owned(), third),
            ]
        );
        assert_eq!(warnings, vec!["AXFR: aucune IP pour empty.example.test"]);
    }

    #[test]
    fn axfr_targets_are_capped_to_a_bounded_phase() {
        let targets = (0..(AXFR_MAX_TARGETS + 3))
            .map(|index| {
                (
                    format!("ns{index}.example.test"),
                    IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, index as u8 + 1)),
                )
            })
            .collect::<Vec<_>>();
        let mut warnings = Vec::new();
        let bounded = bounded_targets(targets, &mut warnings);
        assert_eq!(bounded.len(), AXFR_MAX_TARGETS);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("seules les 8 premières"));
    }

    #[tokio::test]
    async fn axfr_background_is_aborted_when_transfer_is_cancelled() {
        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _probe = DropProbe(task_dropped);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        drop(AbortOnDrop(task));

        tokio::time::timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("la tâche AXFR annulée doit libérer immédiatement ses ressources");
    }

    #[test]
    fn refused_and_timeouts_are_distinct() {
        assert_eq!(classify_response_code(ResponseCode::NoError), None);
        assert_eq!(
            classify_response_code(ResponseCode::Refused),
            Some(AxfrStatus::Refused)
        );
        assert_eq!(
            classify_response_code(ResponseCode::ServFail),
            Some(AxfrStatus::ProtocolError)
        );
        assert_eq!(
            classify_protocol_error("Query Refused"),
            AxfrStatus::Refused
        );
        assert_eq!(classify_protocol_error("timed out"), AxfrStatus::Timeout);
        assert_eq!(
            classify_protocol_error("invalid transfer response"),
            AxfrStatus::ProtocolError
        );
    }
}
