use crate::db::{Database, TlsCacheEntry};
use crate::model::TlsCertificateObservation;
use crate::util::{normalize_observed_name, now_epoch};
use anyhow::{Context, Result, anyhow};
use futures_util::{StreamExt, stream};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
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

fn connect_tcp(endpoint: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addresses = (endpoint, port)
        .to_socket_addrs()
        .with_context(|| format!("résolution TLS de {endpoint}"))?
        .collect::<Vec<_>>();
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(Into::into)
        .unwrap_or_else(|| anyhow!("aucune adresse TLS pour {endpoint}")))
}

fn read_until(stream: &mut TcpStream, markers: &[&str]) -> Result<String> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 2_048];
    while response.len() < 16_384 {
        let count = stream.read(&mut buffer)?;
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

fn prepare_starttls(stream: &mut TcpStream, transport: &str) -> Result<()> {
    match transport {
        "smtp-starttls" => {
            read_until(stream, &["220"])?;
            stream.write_all(b"EHLO fellaga.local\r\n")?;
            read_until(stream, &["250 "])?;
            stream.write_all(b"STARTTLS\r\n")?;
            read_until(stream, &["220"])?;
        }
        "imap-starttls" => {
            read_until(stream, &["* OK"])?;
            stream.write_all(b"a001 STARTTLS\r\n")?;
            read_until(stream, &["A001 OK"])?;
        }
        "pop3-starttls" => {
            read_until(stream, &["+OK"])?;
            stream.write_all(b"STLS\r\n")?;
            read_until(stream, &["+OK"])?;
        }
        _ => {}
    }
    Ok(())
}

fn inspect_certificate(
    endpoint: String,
    domain: String,
    port: u16,
    transport: String,
    timeout: Duration,
) -> Result<TlsInspection> {
    let mut stream = connect_tcp(&endpoint, port, timeout)?;
    prepare_starttls(&mut stream, &transport)?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    // L'objectif est l'inventaire du certificat présenté, même s'il est expiré,
    // auto-signé ou mal configuré. STARTTLS n'envoie que la négociation minimale.
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let mut configuration = connector.configure()?;
    configuration.set_verify_hostname(false);
    let tls = configuration
        .connect(&endpoint, stream)
        .map_err(|error| anyhow!("handshake TLS {endpoint}:{port}: {error}"))?;
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
    use std::net::TcpListener;
    use std::thread;

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
        prepare_starttls(&mut client, transport).unwrap();
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
}
