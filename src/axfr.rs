use crate::dns::DnsEngine;
use crate::model::{AxfrAttempt, AxfrStatus, DnsRecord};
use crate::util::normalize_observed_name;
use futures_util::{StreamExt, stream};
use hickory_client::client::{Client, ClientHandle};
use hickory_client::proto::rr::Name;
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::timeout;

async fn transfer_one(
    domain: &str,
    nameserver: &str,
    address: IpAddr,
    operation_timeout: Duration,
) -> AxfrAttempt {
    let mut attempt = AxfrAttempt {
        nameserver: nameserver.to_owned(),
        address: address.to_string(),
        status: AxfrStatus::ProtocolError,
        error: None,
        records: Vec::new(),
        names: BTreeSet::new(),
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
    let client_future = Client::new(stream, sender, None);
    let (mut client, background) = match timeout(operation_timeout, client_future).await {
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
    tokio::spawn(background);
    let mut transfer = client.zone_transfer(zone, None);
    loop {
        match timeout(operation_timeout, transfer.next()).await {
            Ok(Some(Ok(response))) => {
                for record in response.answers() {
                    let fqdn = record
                        .name()
                        .to_utf8()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if let Some(name) = normalize_observed_name(&fqdn, domain) {
                        attempt.names.insert(name);
                    }
                    attempt.records.push(DnsRecord {
                        record_type: record.record_type().to_string(),
                        value: record.data().to_string().trim_end_matches('.').to_owned(),
                        ttl: record.ttl(),
                    });
                }
            }
            Ok(Some(Err(error))) => {
                attempt.status = classify_protocol_error(&error.to_string());
                attempt.error = Some(error.to_string());
                return attempt;
            }
            Ok(None) => break,
            Err(_) => {
                attempt.status = AxfrStatus::Timeout;
                attempt.error = Some("timeout pendant le transfert AXFR".to_owned());
                return attempt;
            }
        }
    }
    attempt.status = classify_completed_transfer(&attempt.records);
    if attempt.status == AxfrStatus::Empty {
        attempt.error =
            Some("transfert incomplet ou vide: paire SOA d'ouverture/fermeture absente".to_owned());
    }
    attempt
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
    let soa_count = records
        .iter()
        .filter(|record| record.record_type.eq_ignore_ascii_case("SOA"))
        .count();
    if soa_count >= 2 {
        AxfrStatus::Success
    } else {
        AxfrStatus::Empty
    }
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
    let mut targets = Vec::new();
    let mut warnings = Vec::new();
    for (nameserver, addresses) in servers {
        if addresses.is_empty() {
            warnings.push(format!("AXFR: aucune IP pour {nameserver}"));
            continue;
        }
        for address in addresses {
            targets.push((nameserver.clone(), address));
        }
    }
    let mut attempts = stream::iter(targets)
        .map(|(nameserver, address)| async move {
            transfer_one(domain, &nameserver, address, operation_timeout).await
        })
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;
    attempts.sort_by(|left, right| {
        (&left.nameserver, &left.address).cmp(&(&right.nameserver, &right.address))
    });
    (attempts, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn refused_and_timeouts_are_distinct() {
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
