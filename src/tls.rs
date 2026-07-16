use crate::db::{Database, TlsCacheEntry};
use crate::model::TlsCertificateObservation;
use crate::util::{normalize_observed_name, now_epoch};
use anyhow::{Context, Result, anyhow};
use futures_util::{StreamExt, stream};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct TlsInspection {
    endpoint: String,
    fingerprint_sha256: String,
    names: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub struct TlsDiscovery {
    pub observations: Vec<TlsCertificateObservation>,
    pub attempted_network: usize,
    pub successful_network: usize,
    pub failed_network: usize,
    pub cache_hits: usize,
    pub unique_names: BTreeSet<String>,
    pub duration_ms: u128,
}

fn remaining_before(deadline: Instant, phase: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .with_context(|| format!("délai TLS dépassé pendant {phase}"))
}

fn connect_tcp(endpoint: &str, port: u16, deadline: Instant) -> Result<TcpStream> {
    let addresses = (endpoint, port)
        .to_socket_addrs()
        .with_context(|| format!("résolution TLS de {endpoint}"))?
        .collect::<Vec<_>>();
    remaining_before(deadline, "la résolution du nom")?;
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
) -> Result<SslStream<TcpStream>> {
    remaining_before(deadline, "la négociation TLS")?;
    stream.set_nonblocking(true)?;
    let mut configuration = connector.configure()?;
    configuration.set_verify_hostname(false);
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
    timeout: Duration,
) -> Result<TlsInspection> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("délai TLS trop grand")?;
    let mut stream = connect_tcp(&endpoint, port, deadline)?;
    prepare_starttls(&mut stream, &transport, deadline)?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // L'objectif est l'inventaire du certificat présenté, même s'il est expiré,
    // auto-signé ou mal configuré. STARTTLS n'envoie que la négociation minimale.
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let tls = connect_tls_before(&connector, &endpoint, stream, deadline)
        .with_context(|| format!("handshake TLS {endpoint}:{port}"))?;
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
        fingerprint_sha256,
        names,
    })
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
    domain: &str,
    endpoints: Vec<(String, u16, String)>,
    timeout: Duration,
    refresh: Duration,
    concurrency: usize,
) -> Result<TlsDiscovery> {
    let started = Instant::now();
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
    let domain_owned = domain.to_owned();
    let mut inspections = stream::iter(network)
        .map(|(endpoint, port, transport, stale)| {
            let domain = domain_owned.clone();
            async move {
                let inspected_endpoint = endpoint.clone();
                let result = tokio::task::spawn_blocking(move || {
                    inspect_certificate(inspected_endpoint, domain, port, transport, timeout)
                })
                .await
                .map_err(|error| anyhow!("tâche TLS interrompue: {error}"))
                .and_then(|result| result);
                (endpoint, port, stale, result)
            }
        })
        .buffer_unordered(concurrency.max(1));
    while let Some((endpoint, port, stale, result)) = inspections.next().await {
        match result {
            Ok(inspection) => {
                discovery.successful_network += 1;
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
    discovery
        .observations
        .sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
    discovery.duration_ms = started.elapsed().as_millis();
    Ok(discovery)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::ssl::{SslAcceptor, SslMethod};
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::x509::{X509, X509NameBuilder};
    use std::net::TcpListener;
    use std::thread;

    fn test_tls_acceptor() -> SslAcceptor {
        let key = PKey::from_rsa(Rsa::generate(2_048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "api.example.com").unwrap();
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
        let san = SubjectAlternativeName::new()
            .dns("api.example.com")
            .build(&certificate.x509v3_context(None, None))
            .unwrap();
        certificate.append_extension(san).unwrap();
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = certificate.build();

        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&certificate).unwrap();
        acceptor.check_private_key().unwrap();
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
            timeout,
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
            Duration::from_secs(2),
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(inspection.fingerprint_sha256.len(), 64);
        assert!(inspection.names.contains("api.example.com"));
    }
}
