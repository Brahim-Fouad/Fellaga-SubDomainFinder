use crate::db::{Database, TlsCacheEntry};
use crate::dns::{DnsEngine, DnsResolutionOutcome};
use crate::model::{ResolvedHost, TlsCertificateObservation};
use crate::util::{normalize_observed_name, now_epoch};
use anyhow::{Context, Result, anyhow};
use futures_util::{StreamExt, stream};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const MAX_DIFFERENTIAL_ENDPOINTS: usize = 4;

#[derive(Debug)]
struct TlsInspection {
    endpoint: String,
    peer_address: SocketAddr,
    fingerprint_sha256: String,
    names: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerNameMode {
    Sni,
    NoSni,
}

#[derive(Debug, Clone)]
struct DifferentialCandidate {
    endpoint: String,
    port: u16,
    address: SocketAddr,
    sni_fingerprint_sha256: String,
}

#[derive(Debug, Default)]
pub struct TlsDiscovery {
    pub observations: Vec<TlsCertificateObservation>,
    pub attempted_network: usize,
    pub successful_network: usize,
    pub failed_network: usize,
    pub cache_hits: usize,
    /// Default-certificate probes attempted without SNI. These counters are
    /// intentionally separate from the main SNI/cache counters above.
    pub differential_attempted: usize,
    pub differential_successful: usize,
    pub differential_failed: usize,
    /// Successful no-SNI probes whose certificate differs from the SNI result.
    pub differential_distinct: usize,
    pub unique_names: BTreeSet<String>,
    pub duration_ms: u128,
}

fn remaining_before(deadline: Instant, phase: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .with_context(|| format!("délai TLS dépassé pendant {phase}"))
}

fn connect_tcp(endpoint: &str, addresses: Vec<SocketAddr>, deadline: Instant) -> Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        let remaining = remaining_before(deadline, "la connexion TCP")?;
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                let remaining = remaining_before(deadline, "la connexion TCP")?;
                stream.set_read_timeout(Some(remaining))?;
                stream.set_write_timeout(Some(remaining))?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(Into::into)
        .unwrap_or_else(|| anyhow!("aucune adresse TLS pour {endpoint}")))
}

fn write_all_before(stream: &mut TcpStream, mut data: &[u8], deadline: Instant) -> Result<()> {
    while !data.is_empty() {
        let remaining = remaining_before(deadline, "l'écriture STARTTLS")?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(data) {
            Ok(0) => return Err(anyhow!("connexion STARTTLS fermée pendant l'écriture")),
            Ok(written) => data = &data[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(anyhow!(
                    "délai TLS dépassé pendant l'écriture STARTTLS: {error}"
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_until(stream: &mut TcpStream, markers: &[&str], deadline: Instant) -> Result<String> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 2_048];
    while response.len() < 16_384 {
        let remaining = remaining_before(deadline, "la lecture STARTTLS")?;
        stream.set_read_timeout(Some(remaining))?;
        let count = match stream.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(anyhow!(
                    "délai TLS dépassé pendant la lecture STARTTLS: {error}"
                ));
            }
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        let text = String::from_utf8_lossy(&response);
        if markers.iter().any(|marker| {
            text.lines()
                .any(|line| line.to_ascii_uppercase().starts_with(marker))
        }) {
            return Ok(text.into_owned());
        }
    }
    Err(anyhow!("réponse STARTTLS inattendue"))
}

fn prepare_starttls(stream: &mut TcpStream, transport: &str, deadline: Instant) -> Result<()> {
    match transport {
        "smtp-starttls" => {
            read_until(stream, &["220"], deadline)?;
            write_all_before(stream, b"EHLO fellaga.local\r\n", deadline)?;
            read_until(stream, &["250 "], deadline)?;
            write_all_before(stream, b"STARTTLS\r\n", deadline)?;
            read_until(stream, &["220"], deadline)?;
        }
        "imap-starttls" => {
            read_until(stream, &["* OK"], deadline)?;
            write_all_before(stream, b"a001 STARTTLS\r\n", deadline)?;
            read_until(stream, &["A001 OK"], deadline)?;
        }
        "pop3-starttls" => {
            read_until(stream, &["+OK"], deadline)?;
            write_all_before(stream, b"STLS\r\n", deadline)?;
            read_until(stream, &["+OK"], deadline)?;
        }
        _ => {}
    }
    Ok(())
}

fn connect_tls_before(
    connector: &SslConnector,
    endpoint: &str,
    stream: TcpStream,
    deadline: Instant,
    server_name_mode: ServerNameMode,
) -> Result<SslStream<TcpStream>> {
    remaining_before(deadline, "la négociation TLS")?;
    stream.set_nonblocking(true)?;
    let mut configuration = connector.configure()?;
    configuration.set_verify_hostname(false);
    configuration.set_use_server_name_indication(server_name_mode == ServerNameMode::Sni);
    let mut handshake = configuration.connect(endpoint, stream);
    loop {
        match handshake {
            Ok(tls) => {
                remaining_before(deadline, "la négociation TLS")?;
                tls.get_ref().set_nonblocking(false)?;
                return Ok(tls);
            }
            Err(HandshakeError::WouldBlock(mid_handshake)) => {
                let remaining = remaining_before(deadline, "la négociation TLS")?;
                std::thread::sleep(remaining.min(Duration::from_millis(2)));
                handshake = mid_handshake.handshake();
            }
            Err(error) => return Err(anyhow!("handshake TLS {endpoint}: {error}")),
        }
    }
}

fn inspect_certificate(
    endpoint: String,
    domain: String,
    port: u16,
    transport: String,
    addresses: Vec<SocketAddr>,
    deadline: Instant,
) -> Result<TlsInspection> {
    inspect_certificate_with_server_name(
        endpoint,
        domain,
        port,
        transport,
        addresses,
        deadline,
        ServerNameMode::Sni,
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_certificate_with_server_name(
    endpoint: String,
    domain: String,
    port: u16,
    transport: String,
    addresses: Vec<SocketAddr>,
    deadline: Instant,
    server_name_mode: ServerNameMode,
) -> Result<TlsInspection> {
    let mut stream = connect_tcp(&endpoint, addresses, deadline)?;
    prepare_starttls(&mut stream, &transport, deadline)?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // L'objectif est l'inventaire du certificat présenté, même s'il est expiré,
    // auto-signé ou mal configuré. STARTTLS n'envoie que la négociation minimale.
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let tls = connect_tls_before(&connector, &endpoint, stream, deadline, server_name_mode)
        .with_context(|| format!("handshake TLS {endpoint}:{port}"))?;
    let peer_address = tls
        .get_ref()
        .peer_addr()
        .with_context(|| format!("adresse distante TLS absente sur {endpoint}:{port}"))?;
    let certificate = tls
        .ssl()
        .peer_certificate()
        .with_context(|| format!("certificat absent sur {endpoint}:{port}"))?;
    let fingerprint = certificate.digest(MessageDigest::sha256())?;
    let fingerprint_sha256 = fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut names = BTreeSet::new();
    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        for general_name in subject_alt_names {
            if let Some(name) = general_name.dnsname()
                && let Some(name) = normalize_observed_name(name, &domain)
            {
                names.insert(name);
            }
        }
    }
    for entry in certificate.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(name) = entry.data().to_string()
            && let Some(name) = normalize_observed_name(&name, &domain)
        {
            names.insert(name);
        }
    }
    Ok(TlsInspection {
        endpoint,
        peer_address,
        fingerprint_sha256,
        names,
    })
}

fn differential_priority(domain: &str, candidate: &DifferentialCandidate) -> (u8, u8, u16) {
    let apex_rank = u8::from(candidate.endpoint != domain);
    let port_rank = match candidate.port {
        443 => 0,
        8443 => 1,
        9443 => 2,
        _ => 3,
    };
    (apex_rank, port_rank, candidate.port)
}

fn select_differential_candidates(
    domain: &str,
    mut candidates: Vec<DifferentialCandidate>,
) -> Vec<DifferentialCandidate> {
    candidates.sort_by(|left, right| {
        differential_priority(domain, left)
            .cmp(&differential_priority(domain, right))
            .then_with(|| left.endpoint.cmp(&right.endpoint))
            .then_with(|| left.address.cmp(&right.address))
    });
    let mut seen = BTreeSet::new();
    candidates.retain(|candidate| seen.insert(candidate.address));
    candidates.truncate(MAX_DIFFERENTIAL_ENDPOINTS);
    candidates
}

fn no_sni_provenance(address: IpAddr) -> String {
    match address {
        IpAddr::V4(address) => format!("no-sni:{address}"),
        IpAddr::V6(address) => format!("no-sni:[{address}]"),
    }
}

async fn resolve_endpoint_before(
    dns: &DnsEngine,
    endpoint: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<Vec<SocketAddr>> {
    let outcome = tokio::time::timeout_at(deadline, dns.resolve_host_classified(endpoint))
        .await
        .with_context(|| format!("délai TLS dépassé pendant la résolution de {endpoint}"))?;
    let answer = match outcome {
        DnsResolutionOutcome::Positive(answer) => answer,
        DnsResolutionOutcome::Negative { .. } => {
            return Err(anyhow!("aucune adresse TLS pour {endpoint}"));
        }
        DnsResolutionOutcome::Indeterminate { .. } => {
            return Err(anyhow!("résolution TLS indéterminée pour {endpoint}"));
        }
    };
    let addresses = socket_addresses(&answer, port)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(anyhow!("aucune adresse TLS pour {endpoint}"));
    }
    Ok(addresses)
}

fn socket_addresses(answer: &ResolvedHost, port: u16) -> impl Iterator<Item = SocketAddr> + '_ {
    answer
        .records
        .iter()
        .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA"))
        .filter_map(|record| record.value.parse().ok())
        .filter(|address| is_public_tls_ip(*address))
        .map(move |address| SocketAddr::new(address, port))
}

fn is_public_tls_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
                || address == Ipv4Addr::BROADCAST)
        }
        IpAddr::V6(address) => {
            if let Some(embedded) = address.to_ipv4() {
                return is_public_tls_ip(IpAddr::V4(embedded));
            }
            let segments = address.segments();
            !(address == Ipv6Addr::UNSPECIFIED
                || address == Ipv6Addr::LOCALHOST
                || address.is_multicast()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || segments[0] & 0xffc0 == 0xfec0
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && matches!(segments[2], 0 | 1))
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

fn cached_observation(
    endpoint: String,
    port: u16,
    cache: TlsCacheEntry,
) -> TlsCertificateObservation {
    TlsCertificateObservation {
        endpoint,
        port,
        fingerprint_sha256: cache.fingerprint_sha256,
        names: cache.names.into_iter().collect(),
        from_cache: true,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn discover(
    database: &Database,
    dns: &DnsEngine,
    domain: &str,
    endpoints: Vec<(String, u16, String)>,
    timeout: Duration,
    refresh: Duration,
    concurrency: usize,
) -> Result<TlsDiscovery> {
    let started = Instant::now();
    // One absolute deadline governs DNS resolution, SNI handshakes, and all
    // optional no-SNI comparisons. A later task never receives a fresh budget.
    let blocking_deadline = started
        .checked_add(timeout)
        .context("délai TLS trop grand")?;
    let async_deadline = tokio::time::Instant::from_std(blocking_deadline);
    let now = now_epoch();
    let freshness = refresh.as_secs().min(i64::MAX as u64) as i64;
    let mut discovery = TlsDiscovery::default();
    let mut network = Vec::new();
    for (endpoint, port, transport) in endpoints.into_iter().collect::<BTreeSet<_>>() {
        let cached = database.tls_cache(domain, &endpoint, port)?;
        if let Some(cache) = &cached
            && now.saturating_sub(cache.updated_at) < freshness
        {
            discovery.cache_hits += 1;
            let observation = cached_observation(endpoint, port, cache.clone());
            discovery.unique_names.extend(observation.names.clone());
            discovery.observations.push(observation);
        } else {
            network.push((endpoint, port, transport, cached));
        }
    }
    discovery.attempted_network = network.len();
    let domain_owned = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut inspections = stream::iter(network)
        .map(|(endpoint, port, transport, stale)| {
            let domain = domain_owned.clone();
            let dns = dns.clone();
            async move {
                let inspected_endpoint = endpoint.clone();
                let inspected_transport = transport.clone();
                let result = async {
                    let addresses =
                        resolve_endpoint_before(&dns, &inspected_endpoint, port, async_deadline)
                            .await?;
                    let task = tokio::task::spawn_blocking(move || {
                        inspect_certificate(
                            inspected_endpoint,
                            domain,
                            port,
                            inspected_transport,
                            addresses,
                            blocking_deadline,
                        )
                    });
                    tokio::time::timeout_at(async_deadline, task)
                        .await
                        .context("délai TLS absolu dépassé")?
                        .map_err(|error| anyhow!("tâche TLS interrompue: {error}"))?
                }
                .await;
                (endpoint, port, transport, stale, result)
            }
        })
        .buffer_unordered(concurrency.max(1));
    let mut differential_candidates = Vec::new();
    while let Some((endpoint, port, transport, stale, result)) = inspections.next().await {
        match result {
            Ok(inspection) => {
                discovery.successful_network += 1;
                if transport == "tcp-tls" {
                    differential_candidates.push(DifferentialCandidate {
                        endpoint: inspection.endpoint.clone(),
                        port,
                        address: inspection.peer_address,
                        sni_fingerprint_sha256: inspection.fingerprint_sha256.clone(),
                    });
                }
                let cache = database.store_tls_cache(
                    domain,
                    &inspection.endpoint,
                    port,
                    &inspection.fingerprint_sha256,
                    &inspection.names,
                )?;
                let names = cache.names.into_iter().collect::<BTreeSet<_>>();
                discovery.unique_names.extend(names.clone());
                discovery.observations.push(TlsCertificateObservation {
                    endpoint: inspection.endpoint,
                    port,
                    fingerprint_sha256: inspection.fingerprint_sha256,
                    names,
                    from_cache: false,
                });
            }
            Err(_) => {
                discovery.failed_network += 1;
                if let Some(cache) = stale {
                    discovery.cache_hits += 1;
                    let observation = cached_observation(endpoint, port, cache);
                    discovery.unique_names.extend(observation.names.clone());
                    discovery.observations.push(observation);
                }
            }
        }
    }

    // Differential discovery is deliberately TCP-TLS only. STARTTLS protocols
    // require an application dialogue and are never replayed without SNI.
    let differential_candidates =
        select_differential_candidates(&domain_owned, differential_candidates);
    discovery.differential_attempted = differential_candidates.len();
    let mut differential = stream::iter(differential_candidates)
        .map(|candidate| {
            let domain = domain_owned.clone();
            async move {
                let endpoint = candidate.endpoint.clone();
                let address = candidate.address;
                let task = tokio::task::spawn_blocking(move || {
                    inspect_certificate_with_server_name(
                        endpoint,
                        domain,
                        candidate.port,
                        "tcp-tls".to_owned(),
                        vec![address],
                        blocking_deadline,
                        ServerNameMode::NoSni,
                    )
                });
                let result = tokio::time::timeout_at(async_deadline, task)
                    .await
                    .context("délai TLS différentiel absolu dépassé")?
                    .map_err(|error| anyhow!("tâche TLS différentielle interrompue: {error}"))?;
                Ok::<_, anyhow::Error>((candidate, result))
            }
        })
        .buffer_unordered(concurrency.clamp(1, MAX_DIFFERENTIAL_ENDPOINTS));
    while let Some(result) = differential.next().await {
        match result {
            Ok((candidate, Ok(inspection))) => {
                discovery.differential_successful += 1;
                if inspection.fingerprint_sha256 != candidate.sni_fingerprint_sha256 {
                    discovery.differential_distinct += 1;
                    discovery.unique_names.extend(inspection.names.clone());
                    discovery.observations.push(TlsCertificateObservation {
                        endpoint: no_sni_provenance(candidate.address.ip()),
                        port: candidate.port,
                        fingerprint_sha256: inspection.fingerprint_sha256,
                        names: inspection.names,
                        from_cache: false,
                    });
                }
            }
            Ok((_, Err(_))) | Err(_) => {
                discovery.differential_failed += 1;
            }
        }
    }
    discovery
        .observations
        .sort_by(|left, right| (&left.endpoint, left.port).cmp(&(&right.endpoint, right.port)));
    discovery.duration_ms = started.elapsed().as_millis();
    Ok(discovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DnsRecord;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::ssl::{NameType, SniError, SslAcceptor, SslMethod};
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509, X509NameBuilder};
    use std::net::TcpListener;
    use std::thread;

    fn test_credentials(common_name: &str, sans: &[&str]) -> (PKey<Private>, X509) {
        let key = PKey::from_rsa(Rsa::generate(2_048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", common_name).unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
        let serial = serial.to_asn1_integer().unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(1).unwrap();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_serial_number(&serial).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate.set_not_before(&not_before).unwrap();
        certificate.set_not_after(&not_after).unwrap();
        let mut san = SubjectAlternativeName::new();
        for name in sans {
            san.dns(name);
        }
        let san = san.build(&certificate.x509v3_context(None, None)).unwrap();
        certificate.append_extension(san).unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        (key, certificate.build())
    }

    fn test_tls_acceptor() -> SslAcceptor {
        let (key, certificate) = test_credentials("api.example.com", &["api.example.com"]);

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&certificate).unwrap();
        acceptor.check_private_key().unwrap();
        acceptor.build()
    }

    fn differential_tls_acceptor() -> SslAcceptor {
        let (default_key, default_certificate) = test_credentials(
            "default-only.example.com",
            &["default-only.example.com", "outside.invalid"],
        );
        let (sni_key, sni_certificate) =
            test_credentials("sni-only.example.com", &["sni-only.example.com"]);
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&default_key).unwrap();
        acceptor.set_certificate(&default_certificate).unwrap();
        acceptor.check_private_key().unwrap();
        acceptor.set_servername_callback(move |ssl, _alert| {
            if ssl.servername(NameType::HOST_NAME) == Some("api.example.com") {
                ssl.set_certificate(&sni_certificate)
                    .map_err(|_| SniError::ALERT_FATAL)?;
                ssl.set_private_key(&sni_key)
                    .map_err(|_| SniError::ALERT_FATAL)?;
            }
            Ok(())
        });
        acceptor.build()
    }

    fn assert_starttls_dialog(
        transport: &str,
        greeting: &'static [u8],
        exchanges: Vec<(&'static [u8], &'static [u8])>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(greeting).unwrap();
            for (expected, response) in exchanges {
                let mut received = vec![0_u8; expected.len()];
                stream.read_exact(&mut received).unwrap();
                assert_eq!(received, expected);
                stream.write_all(response).unwrap();
            }
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        prepare_starttls(
            &mut client,
            transport,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn cached_observation_preserves_certificate_names() {
        let observation = cached_observation(
            "api.example.com".to_owned(),
            443,
            TlsCacheEntry {
                fingerprint_sha256: "aa".repeat(32),
                names: vec!["deep.api.example.com".to_owned()],
                updated_at: 1,
            },
        );
        assert!(observation.from_cache);
        assert!(observation.names.contains("deep.api.example.com"));
    }

    #[test]
    fn tls_resolution_is_supplied_by_the_shared_dns_engine() {
        let source = include_str!("tls.rs");
        for forbidden in [
            ["Tokio", "Resolver"].concat(),
            ["lookup", "_host"].concat(),
            ["ToSocket", "Addrs"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden resolver: {forbidden}"
            );
        }
        assert!(source.contains("dns: &DnsEngine"));

        let answer = ResolvedHost {
            fqdn: "api.example.com".to_owned(),
            records: vec![
                DnsRecord {
                    record_type: "A".to_owned(),
                    value: "8.8.8.8".to_owned(),
                    ttl: 60,
                },
                DnsRecord {
                    record_type: "TXT".to_owned(),
                    value: "ignored".to_owned(),
                    ttl: 60,
                },
            ],
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 1,
        };
        assert_eq!(
            socket_addresses(&answer, 443).collect::<Vec<_>>(),
            vec!["8.8.8.8:443".parse().unwrap()]
        );
    }

    #[test]
    fn tls_resolution_rejects_non_public_ipv4_and_ipv6_destinations() {
        let records = [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
        ]
        .into_iter()
        .map(|value| DnsRecord {
            record_type: if value.contains(':') { "AAAA" } else { "A" }.to_owned(),
            value: value.to_owned(),
            ttl: 60,
        })
        .collect();
        let answer = ResolvedHost {
            fqdn: "api.example.com".to_owned(),
            records,
            from_cache: false,
            last_verified_at: Some(1),
            authoritative_validation: false,
            resolver_count: 2,
        };

        assert_eq!(
            socket_addresses(&answer, 443).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "8.8.8.8:443".parse().unwrap(),
                "[2606:4700:4700::1111]:443".parse().unwrap(),
            ])
        );
    }

    #[test]
    fn starttls_uses_only_the_minimal_protocol_dialog() {
        assert_starttls_dialog(
            "smtp-starttls",
            b"220 mail.example ESMTP\r\n",
            vec![
                (
                    b"EHLO fellaga.local\r\n",
                    b"250-mail.example\r\n250 STARTTLS\r\n",
                ),
                (b"STARTTLS\r\n", b"220 Ready to start TLS\r\n"),
            ],
        );
        assert_starttls_dialog(
            "imap-starttls",
            b"* OK IMAP ready\r\n",
            vec![(b"a001 STARTTLS\r\n", b"a001 OK Begin TLS\r\n")],
        );
        assert_starttls_dialog(
            "pop3-starttls",
            b"+OK POP3 ready\r\n",
            vec![(b"STLS\r\n", b"+OK Begin TLS\r\n")],
        );
    }

    #[test]
    fn starttls_slow_drip_cannot_extend_the_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"220 deliberately slow SMTP greeting\r\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        });
        let mut client = TcpStream::connect(address).unwrap();
        let timeout = Duration::from_millis(90);
        let started = Instant::now();
        let error = prepare_starttls(&mut client, "smtp-starttls", started + timeout).unwrap_err();
        let elapsed = started.elapsed();
        drop(client);
        server.join().unwrap();

        assert!(error.to_string().contains("délai TLS dépassé"), "{error:#}");
        assert!(
            elapsed < Duration::from_millis(350),
            "STARTTLS a dépassé la deadline: {elapsed:?}"
        );
    }

    #[test]
    fn stalled_tls_handshake_respects_the_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(400));
        });

        let timeout = Duration::from_millis(90);
        let started = Instant::now();
        let error = inspect_certificate(
            address.ip().to_string(),
            "example.com".to_owned(),
            address.port(),
            "tcp-tls".to_owned(),
            vec![address],
            started + timeout,
        )
        .unwrap_err();
        let elapsed = started.elapsed();
        server.join().unwrap();

        assert!(error.to_string().contains("handshake TLS"), "{error:#}");
        assert!(
            elapsed < Duration::from_millis(350),
            "le handshake a dépassé la deadline: {elapsed:?}"
        );
    }

    #[test]
    fn nonblocking_tls_handshake_still_extracts_a_certificate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = test_tls_acceptor();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            acceptor.accept(stream).unwrap();
        });

        let inspection = inspect_certificate(
            address.ip().to_string(),
            "example.com".to_owned(),
            address.port(),
            "tcp-tls".to_owned(),
            vec![address],
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(inspection.fingerprint_sha256.len(), 64);
        assert!(inspection.names.contains("api.example.com"));
    }

    #[test]
    fn sni_and_no_sni_extract_distinct_strictly_scoped_certificates() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = differential_tls_acceptor();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                acceptor.accept(stream).unwrap();
            }
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let sni = inspect_certificate_with_server_name(
            "api.example.com".to_owned(),
            "example.com".to_owned(),
            address.port(),
            "tcp-tls".to_owned(),
            vec![address],
            deadline,
            ServerNameMode::Sni,
        )
        .unwrap();
        let no_sni = inspect_certificate_with_server_name(
            "api.example.com".to_owned(),
            "example.com".to_owned(),
            address.port(),
            "tcp-tls".to_owned(),
            vec![address],
            deadline,
            ServerNameMode::NoSni,
        )
        .unwrap();
        server.join().unwrap();

        assert_ne!(sni.fingerprint_sha256, no_sni.fingerprint_sha256);
        assert!(sni.names.contains("sni-only.example.com"));
        assert!(!sni.names.contains("default-only.example.com"));
        assert!(no_sni.names.contains("default-only.example.com"));
        assert!(!no_sni.names.contains("outside.invalid"));
        assert_eq!(sni.peer_address, address);
        assert_eq!(no_sni.peer_address, address);
        assert_eq!(no_sni_provenance(address.ip()), "no-sni:127.0.0.1");
    }

    #[test]
    fn differential_selection_is_prioritized_deduplicated_and_bounded() {
        let candidates = vec![
            ("z.example.com", "127.0.0.1:443"),
            ("example.com", "127.0.0.1:443"),
            ("b.example.com", "127.0.0.2:443"),
            ("c.example.com", "127.0.0.3:8443"),
            ("d.example.com", "127.0.0.4:9443"),
            ("e.example.com", "127.0.0.5:10443"),
            ("f.example.com", "127.0.0.6:443"),
        ]
        .into_iter()
        .map(|(endpoint, address)| DifferentialCandidate {
            endpoint: endpoint.to_owned(),
            port: address.rsplit_once(':').unwrap().1.parse().unwrap(),
            address: address.parse().unwrap(),
            sni_fingerprint_sha256: "aa".repeat(32),
        })
        .collect();

        let selected = select_differential_candidates("example.com", candidates);
        assert_eq!(selected.len(), MAX_DIFFERENTIAL_ENDPOINTS);
        assert_eq!(selected[0].endpoint, "example.com");
        assert_eq!(
            selected
                .iter()
                .map(|candidate| candidate.address)
                .collect::<BTreeSet<_>>()
                .len(),
            selected.len()
        );
        assert!(!selected.iter().any(|candidate| {
            candidate.endpoint == "z.example.com"
                && candidate.address == "127.0.0.1:443".parse().unwrap()
        }));
    }

    #[test]
    fn sni_and_no_sni_share_one_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(300));
        });

        let started = Instant::now();
        let deadline = started + Duration::from_millis(80);
        let first = inspect_certificate_with_server_name(
            "api.example.com".to_owned(),
            "example.com".to_owned(),
            address.port(),
            "tcp-tls".to_owned(),
            vec![address],
            deadline,
            ServerNameMode::Sni,
        );
        assert!(first.is_err());
        let second_started = Instant::now();
        let second = inspect_certificate_with_server_name(
            "api.example.com".to_owned(),
            "example.com".to_owned(),
            address.port(),
            "tcp-tls".to_owned(),
            vec![address],
            deadline,
            ServerNameMode::NoSni,
        );
        let second_elapsed = second_started.elapsed();
        let total_before_join = started.elapsed();
        server.join().unwrap();

        let second_error = second.unwrap_err();
        assert!(
            second_error
                .to_string()
                .contains("délai TLS dépassé pendant la connexion TCP"),
            "le second probe a démarré une nouvelle opération: {second_error:#}"
        );
        assert!(
            second_elapsed < Duration::from_millis(100),
            "le probe no-SNI a reçu un nouveau budget: {second_elapsed:?}"
        );
        assert!(
            total_before_join < Duration::from_millis(180),
            "la deadline partagée a été prolongée: {total_before_join:?}"
        );
    }
}
