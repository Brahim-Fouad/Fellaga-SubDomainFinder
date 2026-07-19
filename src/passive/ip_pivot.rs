//! Bounded IP-to-hostname enrichment through third-party passive data.

use super::{client, compact_external_error, response_bytes_limited_to, send_external};
use crate::util::normalize_hostname;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const INTERNETDB_MAX_BODY_BYTES: usize = 256 * 1024;
const INTERNETDB_MAX_HOSTNAMES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InternetDbLookup {
    pub hostnames: BTreeSet<String>,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
struct InternetDbResponse {
    ip: String,
    #[serde(default)]
    hostnames: Vec<String>,
}

fn parse_internetdb_response(body: &[u8], requested: IpAddr) -> Result<InternetDbLookup> {
    if body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'<')
    {
        bail!("Shodan InternetDB: réponse HTML inattendue à la place de JSON");
    }
    let response: InternetDbResponse =
        serde_json::from_slice(body).context("Shodan InternetDB: schéma JSON incompatible")?;
    let returned = response
        .ip
        .parse::<IpAddr>()
        .context("Shodan InternetDB: adresse de réponse invalide")?;
    if returned != requested {
        bail!("Shodan InternetDB: response address does not match the requested address");
    }
    let mut hostnames = BTreeSet::new();
    let mut truncated = false;
    for hostname in response.hostnames {
        let Some(hostname) = normalize_hostname(&hostname) else {
            continue;
        };
        if hostnames.contains(&hostname) {
            continue;
        }
        if hostnames.len() >= INTERNETDB_MAX_HOSTNAMES {
            truncated = true;
            break;
        }
        hostnames.insert(hostname);
    }
    Ok(InternetDbLookup {
        hostnames,
        truncated,
    })
}

pub(crate) async fn lookup_internetdb(
    address: IpAddr,
    timeout: Duration,
) -> Result<InternetDbLookup> {
    if !is_public_internet_address(address) {
        bail!("Shodan InternetDB: non-public address rejected");
    }
    let address_text = address.to_string();
    let response = send_external(
        "shodan-internetdb",
        client(timeout)?.get(format!("https://internetdb.shodan.io/{address_text}")),
        &address_text,
    )
    .await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(InternetDbLookup {
            hostnames: BTreeSet::new(),
            truncated: false,
        });
    }
    let (status, body) =
        response_bytes_limited_to(response, "Shodan InternetDB", INTERNETDB_MAX_BODY_BYTES).await?;
    if !status.is_success() {
        bail!(
            "Shodan InternetDB: HTTP {status}: {}",
            compact_external_error(&String::from_utf8_lossy(&body))
        );
    }
    parse_internetdb_response(&body, address)
}

pub(crate) fn is_public_internet_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
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

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(embedded) = address.to_ipv4() {
        return is_public_ipv4(embedded);
    }
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xffc0 == 0xfec0
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && matches!(segments[2], 0 | 1))
        || segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x2001 && segments[1] == 0x0002)
        || (segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020))
        || (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internetdb_response_validates_address_and_bounds_hostnames() {
        let requested: IpAddr = "1.1.1.1".parse().unwrap();
        let body =
            br#"{"ip":"1.1.1.1","hostnames":["api.example.com","API.EXAMPLE.COM.","bad host"]}"#;
        let parsed = parse_internetdb_response(body, requested).unwrap();
        assert_eq!(
            parsed.hostnames,
            BTreeSet::from(["api.example.com".to_owned()])
        );
        assert!(!parsed.truncated);
        assert!(parse_internetdb_response(br#"{"ip":"8.8.8.8"}"#, requested).is_err());
        assert!(parse_internetdb_response(b"<html>", requested).is_err());

        let mut repeated = vec!["dup.example.com"; INTERNETDB_MAX_HOSTNAMES + 10];
        repeated.push("tail.example.com");
        let body = serde_json::to_vec(&serde_json::json!({
            "ip": "1.1.1.1",
            "hostnames": repeated,
        }))
        .unwrap();
        let parsed = parse_internetdb_response(&body, requested).unwrap();
        assert_eq!(
            parsed.hostnames,
            BTreeSet::from(["dup.example.com".to_owned(), "tail.example.com".to_owned(),])
        );
        assert!(!parsed.truncated);

        let unique = (0..=INTERNETDB_MAX_HOSTNAMES)
            .map(|index| format!("host-{index}.example.com"))
            .collect::<Vec<_>>();
        let body = serde_json::to_vec(&serde_json::json!({
            "ip": "1.1.1.1",
            "hostnames": unique,
        }))
        .unwrap();
        let parsed = parse_internetdb_response(&body, requested).unwrap();
        assert_eq!(parsed.hostnames.len(), INTERNETDB_MAX_HOSTNAMES);
        assert!(parsed.truncated);
    }

    #[test]
    fn internetdb_rejects_non_public_ranges() {
        for address in [
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_internet_address(address.parse().unwrap()));
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(is_public_internet_address(address.parse().unwrap()));
        }
    }
}
