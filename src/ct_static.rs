//! Bounded reader for the C2SP Static Certificate Transparency API.
//!
//! Static CT logs expose immutable groups of 256 entries instead of the
//! dynamic RFC 6962 `get-entries` endpoint.  This module deliberately keeps
//! transport, parsing, and scope filtering separate from SQLite persistence so
//! the scanner can commit one complete tile at a time.
//!
//! The current trust boundary is HTTPS plus immutable-payload conflict checks.
//! The parser requires a C2SP note signature section, but does not yet verify
//! that signature or a tile's Merkle inclusion against the checkpoint root.

use crate::passive::response_bytes_limited_to;
use crate::util::normalize_hostname;
use anyhow::{Context, Result, bail};
use base64::Engine;
use openssl::nid::Nid;
use openssl::x509::X509;
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use url::Url;

const TILE_WIDTH: usize = 256;
const MAX_CHECKPOINT_BYTES: usize = 64 * 1024;
const MAX_TILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_BATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_TILES_PER_SYNC: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCheckpoint {
    pub origin: String,
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub signature_lines: usize,
}

#[derive(Debug, Clone)]
pub struct StaticTile {
    pub path: String,
    pub checkpoint_size: u64,
    pub checkpoint_hash: String,
    pub content_hash: String,
    pub payload: Vec<u8>,
}

/// Previously committed immutable payload.  A tile is reused only when both
/// the checkpoint identity and this digest still match; otherwise the network
/// copy is fetched and parsed again.
#[derive(Debug, Clone)]
pub struct CachedStaticTile {
    pub content_hash: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct StaticCtBatch {
    pub monitoring_prefix: String,
    pub checkpoint_origin: String,
    pub checkpoint_size: u64,
    pub checkpoint_hash: String,
    pub reset_cursor: bool,
    pub next_cursor: u64,
    pub entries_processed: usize,
    pub names: BTreeSet<String>,
    pub tiles: Vec<StaticTile>,
}

#[derive(Debug, Clone)]
struct ParsedTileEntry {
    certificate_der: Vec<u8>,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize, field: &str) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("dépassement d'index dans une tuile CT statique")?;
        let value = self
            .bytes
            .get(self.position..end)
            .with_context(|| format!("tuile CT statique tronquée dans {field}"))?;
        self.position = end;
        Ok(value)
    }

    fn u16(&mut self, field: &str) -> Result<u16> {
        let value = self.take(2, field)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn u24(&mut self, field: &str) -> Result<usize> {
        let value = self.take(3, field)?;
        Ok(((value[0] as usize) << 16) | ((value[1] as usize) << 8) | value[2] as usize)
    }

    fn opaque_u16(&mut self, field: &str) -> Result<&'a [u8]> {
        let length = self.u16(&format!("longueur de {field}"))? as usize;
        self.take(length, field)
    }

    fn opaque_u24(&mut self, field: &str) -> Result<&'a [u8]> {
        let length = self.u24(&format!("longueur de {field}"))?;
        self.take(length, field)
    }
}

/// Parses a bounded C2SP checkpoint and requires a syntactically present note
/// signature section. This function does not perform signature verification.
pub fn parse_checkpoint(body: &[u8]) -> Result<StaticCheckpoint> {
    if body.len() > MAX_CHECKPOINT_BYTES {
        bail!("checkpoint CT statique trop volumineux");
    }
    let text = std::str::from_utf8(body).context("checkpoint CT statique non UTF-8")?;
    let normalized = text.replace("\r\n", "\n");
    let mut sections = normalized.splitn(2, "\n\n");
    let payload = sections.next().unwrap_or_default();
    let signatures = sections.next().unwrap_or_default();
    let mut lines = payload.lines();
    let origin = lines.next().unwrap_or_default().trim().to_owned();
    if origin.is_empty()
        || origin.contains(char::is_whitespace)
        || origin.contains("..")
        || origin.starts_with("http://")
        || origin.starts_with("https://")
    {
        bail!("origine de checkpoint CT statique invalide");
    }
    let tree_size = lines
        .next()
        .context("taille absente du checkpoint CT statique")?
        .trim()
        .parse::<u64>()
        .context("taille invalide du checkpoint CT statique")?;
    let root = base64::engine::general_purpose::STANDARD
        .decode(
            lines
                .next()
                .context("racine absente du checkpoint CT statique")?
                .trim(),
        )
        .context("racine base64 invalide du checkpoint CT statique")?;
    let root_hash: [u8; 32] = root
        .try_into()
        .map_err(|_| anyhow::anyhow!("racine du checkpoint CT statique différente de 32 octets"))?;
    if lines.any(|line| !line.trim().is_empty()) {
        bail!("lignes d'extension non prises en charge dans le checkpoint CT statique");
    }
    let signature_lines = signatures
        .lines()
        .filter(|line| line.starts_with('—') || line.starts_with("-- "))
        .count();
    if signature_lines == 0 {
        bail!("checkpoint CT statique sans signature de note");
    }
    Ok(StaticCheckpoint {
        origin,
        tree_size,
        root_hash,
        signature_lines,
    })
}

fn tile_index_path(index: u64) -> String {
    let decimal = index.to_string();
    let padding = (3 - decimal.len() % 3) % 3;
    let padded = format!("{}{}", "0".repeat(padding), decimal);
    let groups = padded
        .as_bytes()
        .chunks(3)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("000"))
        .collect::<Vec<_>>();
    groups
        .iter()
        .enumerate()
        .map(|(position, group)| {
            if position + 1 == groups.len() {
                (*group).to_owned()
            } else {
                format!("x{group}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn data_tile_path(index: u64, partial_width: Option<usize>) -> Result<String> {
    let base = format!("tile/data/{}", tile_index_path(index));
    match partial_width {
        Some(width @ 1..=255) => Ok(format!("{base}.p/{width}")),
        Some(_) => bail!("largeur partielle CT statique hors plage"),
        None => Ok(base),
    }
}

fn parse_data_tile(payload: &[u8], expected_entries: usize) -> Result<Vec<ParsedTileEntry>> {
    if expected_entries == 0 || expected_entries > TILE_WIDTH {
        bail!("nombre d'entrées attendu hors plage pour une tuile CT statique");
    }
    let mut cursor = Cursor::new(payload);
    let mut entries = Vec::with_capacity(expected_entries);
    while cursor.remaining() > 0 {
        if entries.len() >= expected_entries {
            bail!("tuile CT statique contenant trop d'entrées");
        }
        cursor.take(8, "timestamp")?;
        let entry_type = cursor.u16("type d'entrée")?;
        let certificate_der = match entry_type {
            0 => cursor.opaque_u24("certificat X509")?.to_vec(),
            1 => {
                cursor.take(32, "hachage de l'émetteur du précertificat")?;
                cursor.opaque_u24("TBSCertificate")?;
                Vec::new()
            }
            other => bail!("type d'entrée CT statique inconnu: {other}"),
        };
        cursor.opaque_u16("extensions CT")?;
        let certificate_der = if entry_type == 1 {
            cursor.opaque_u24("précertificat complet")?.to_vec()
        } else {
            certificate_der
        };
        let chain = cursor.opaque_u16("empreintes de chaîne")?;
        if chain.len() % 32 != 0 {
            bail!("vecteur d'empreintes CT statique mal aligné");
        }
        entries.push(ParsedTileEntry { certificate_der });
    }
    if entries.len() != expected_entries {
        bail!(
            "tuile CT statique incomplète: {} entrée(s), {expected_entries} attendue(s)",
            entries.len()
        );
    }
    Ok(entries)
}

fn certificate_names(der: &[u8]) -> Result<BTreeSet<String>> {
    let certificate = X509::from_der(der).context("certificat X509 de tuile CT invalide")?;
    let mut names = BTreeSet::new();
    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        for general_name in subject_alt_names {
            if let Some(name) = general_name.dnsname()
                && let Some(name) = normalize_hostname(name)
            {
                names.insert(name);
            }
        }
    }
    for entry in certificate.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(name) = entry.data().to_string()
            && let Some(name) = normalize_hostname(&name)
        {
            names.insert(name);
        }
    }
    Ok(names)
}

fn expected_checkpoint_origin(log_url: &str) -> Result<String> {
    let parsed = Url::parse(log_url).context("URL de journal CT invalide")?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        bail!("un journal CT statique doit utiliser HTTPS");
    }
    let mut origin = format!("{}{}", parsed.host_str().unwrap_or_default(), parsed.path());
    while origin.ends_with('/') {
        origin.pop();
    }
    Ok(origin)
}

/// Returns monitoring prefixes in preference order.  Static CT has separate
/// submission and monitoring URLs; Chrome currently publishes the submission
/// URL, so known Let's Encrypt production logs need the documented `log` to
/// `mon` host mapping.  The original URL remains a standards-compatible
/// fallback for operators serving both APIs on one origin.
pub fn monitoring_prefixes(log_url: &str) -> Result<Vec<String>> {
    let parsed = Url::parse(log_url).context("URL de journal CT invalide")?;
    if parsed.scheme() != "https" {
        bail!("un journal CT statique doit utiliser HTTPS");
    }
    let host = parsed.host_str().context("hôte de journal CT absent")?;
    let mut prefixes = Vec::new();
    if let Some(rest) = host.strip_prefix("log.")
        && rest.ends_with(".ct.letsencrypt.org")
    {
        let mut monitoring = parsed.clone();
        monitoring
            .set_host(Some(&format!("mon.{rest}")))
            .map_err(|_| anyhow::anyhow!("hôte de monitoring CT invalide"))?;
        prefixes.push(monitoring.to_string());
    }
    prefixes.push(parsed.to_string());
    prefixes.sort();
    prefixes.dedup();
    prefixes.sort_by_key(|prefix| (!prefix.contains("://mon."), prefix.clone()));
    Ok(prefixes)
}

async fn fetch_checkpoint(client: &Client, prefix: &str) -> Result<StaticCheckpoint> {
    let url = format!("{}/checkpoint", prefix.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("connexion au checkpoint CT statique {url}"))?;
    let (status, body) =
        response_bytes_limited_to(response, "checkpoint CT statique", MAX_CHECKPOINT_BYTES).await?;
    if !status.is_success() {
        bail!("checkpoint CT statique: HTTP {status}");
    }
    parse_checkpoint(&body)
}

/// Fetches at most `entry_budget` entries and 64 immutable data tiles.  The
/// returned cursor advances only across completely parsed entries, allowing
/// the caller to commit tile payload and extracted names transactionally.
pub async fn fetch_static_delta(
    client: &Client,
    log_url: &str,
    stored_cursor: Option<u64>,
    entry_budget: usize,
    initial_backfill: usize,
) -> Result<StaticCtBatch> {
    fetch_static_delta_with_cache(
        client,
        log_url,
        stored_cursor,
        entry_budget,
        initial_backfill,
        |_, _, _| Ok(None),
    )
    .await
}

/// Same bounded reader as [`fetch_static_delta`], with a synchronous lookup
/// for immutable payloads already committed locally.  Cache errors are
/// surfaced; corrupt or digest-mismatched payloads are ignored and fetched
/// again.  Compatibility is deliberately conservative: cached bytes must have
/// been observed under this exact checkpoint size and root hash.
pub async fn fetch_static_delta_with_cache<F>(
    client: &Client,
    log_url: &str,
    stored_cursor: Option<u64>,
    entry_budget: usize,
    initial_backfill: usize,
    mut cached_tile: F,
) -> Result<StaticCtBatch>
where
    F: FnMut(&str, u64, &str) -> Result<Option<CachedStaticTile>>,
{
    let expected_origin = expected_checkpoint_origin(log_url)?;
    let mut selected = None;
    let mut errors = Vec::new();
    for prefix in monitoring_prefixes(log_url)? {
        match fetch_checkpoint(client, &prefix).await {
            Ok(checkpoint) if checkpoint.origin == expected_origin => {
                selected = Some((prefix, checkpoint));
                break;
            }
            Ok(checkpoint) => errors.push(format!(
                "{prefix}: origine {} différente de {expected_origin}",
                checkpoint.origin
            )),
            Err(error) => errors.push(format!("{prefix}: {error:#}")),
        }
    }
    let (monitoring_prefix, checkpoint) = selected
        .with_context(|| format!("aucune API CT statique compatible ({})", errors.join(" | ")))?;
    let checkpoint_hash = base64::engine::general_purpose::STANDARD.encode(checkpoint.root_hash);
    let backfill = checkpoint
        .tree_size
        .saturating_sub(initial_backfill.min(u64::MAX as usize) as u64);
    let (mut cursor, reset_cursor) = match stored_cursor {
        Some(cursor) if cursor <= checkpoint.tree_size => (cursor, false),
        Some(_) => (backfill, true),
        None => (backfill, false),
    };
    let mut batch = StaticCtBatch {
        monitoring_prefix: monitoring_prefix.clone(),
        checkpoint_origin: checkpoint.origin,
        checkpoint_size: checkpoint.tree_size,
        checkpoint_hash: checkpoint_hash.clone(),
        reset_cursor,
        next_cursor: cursor,
        ..StaticCtBatch::default()
    };
    if entry_budget == 0 || cursor >= checkpoint.tree_size {
        return Ok(batch);
    }

    let mut batch_payload_bytes = 0_usize;
    while cursor < checkpoint.tree_size
        && batch.entries_processed < entry_budget
        && batch.tiles.len() < MAX_TILES_PER_SYNC
    {
        let tile_index = cursor / TILE_WIDTH as u64;
        let tile_start = tile_index * TILE_WIDTH as u64;
        let full_tiles = checkpoint.tree_size / TILE_WIDTH as u64;
        let partial_width = (tile_index == full_tiles)
            .then_some((checkpoint.tree_size % TILE_WIDTH as u64) as usize)
            .filter(|width| *width > 0);
        let expected_entries = partial_width.unwrap_or(TILE_WIDTH);
        let path = data_tile_path(tile_index, partial_width)?;
        let cached = cached_tile(&path, checkpoint.tree_size, &checkpoint_hash)?.filter(|cached| {
            format!("{:x}", Sha256::digest(&cached.payload)) == cached.content_hash
                && cached.payload.len() <= MAX_TILE_BYTES
        });
        let (payload, content_hash) = if let Some(cached) = cached {
            (cached.payload, cached.content_hash)
        } else {
            let url = format!("{}/{}", monitoring_prefix.trim_end_matches('/'), path);
            let response = client
                .get(&url)
                .send()
                .await
                .with_context(|| format!("connexion à la tuile CT statique {url}"))?;
            let (status, payload) =
                response_bytes_limited_to(response, "tuile CT statique", MAX_TILE_BYTES).await?;
            if !status.is_success() {
                bail!("tuile CT statique {path}: HTTP {status}");
            }
            let content_hash = format!("{:x}", Sha256::digest(&payload));
            (payload, content_hash)
        };
        if batch_payload_bytes.saturating_add(payload.len()) > MAX_BATCH_BYTES {
            break;
        }
        let payload_len = payload.len();
        let entries = parse_data_tile(&payload, expected_entries)
            .with_context(|| format!("décodage de la tuile CT statique {path}"))?;
        let offset = cursor.saturating_sub(tile_start) as usize;
        let remaining_budget = entry_budget.saturating_sub(batch.entries_processed);
        let take = entries
            .len()
            .saturating_sub(offset)
            .min(remaining_budget)
            .min(checkpoint.tree_size.saturating_sub(cursor) as usize);
        if take == 0 {
            bail!("la tuile CT statique {path} ne permet pas d'avancer le curseur");
        }
        for entry in entries.iter().skip(offset).take(take) {
            batch
                .names
                .extend(certificate_names(&entry.certificate_der)?);
        }
        batch.tiles.push(StaticTile {
            path,
            checkpoint_size: checkpoint.tree_size,
            checkpoint_hash: checkpoint_hash.clone(),
            content_hash,
            payload,
        });
        batch_payload_bytes = batch_payload_bytes.saturating_add(payload_len);
        cursor = cursor.saturating_add(take as u64);
        batch.entries_processed = batch.entries_processed.saturating_add(take);
        batch.next_cursor = cursor;
    }
    Ok(batch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn checkpoint(origin: &str, size: u64) -> Vec<u8> {
        format!(
            "{origin}\n{size}\n{}\n\n— {origin} dGVzdA==\n",
            STANDARD.encode([7_u8; 32])
        )
        .into_bytes()
    }

    #[test]
    fn checkpoint_is_bounded_and_requires_a_note_signature_section() {
        let parsed = parse_checkpoint(&checkpoint("log.example/2026h2", 513)).unwrap();
        assert_eq!(parsed.origin, "log.example/2026h2");
        assert_eq!(parsed.tree_size, 513);
        assert_eq!(parsed.root_hash, [7_u8; 32]);
        assert_eq!(parsed.signature_lines, 1);

        let unsigned = format!("log.example/2026h2\n1\n{}\n", STANDARD.encode([0_u8; 32]));
        assert!(parse_checkpoint(unsigned.as_bytes()).is_err());
    }

    #[test]
    fn parses_pinned_letsencrypt_checkpoint_contract() {
        let checkpoint = parse_checkpoint(include_bytes!(
            "../tests/fixtures/ct/letsencrypt-sycamore-2026h2.checkpoint"
        ))
        .unwrap();
        assert_eq!(checkpoint.origin, "log.sycamore.ct.letsencrypt.org/2026h2");
        assert_eq!(checkpoint.tree_size, 364_480_299);
        assert_eq!(checkpoint.root_hash.len(), 32);
        assert_eq!(checkpoint.signature_lines, 4);
    }

    #[test]
    fn tile_paths_follow_the_c2sp_three_digit_hierarchy() {
        assert_eq!(data_tile_path(0, None).unwrap(), "tile/data/000");
        assert_eq!(data_tile_path(7, Some(12)).unwrap(), "tile/data/007.p/12");
        assert_eq!(
            data_tile_path(1_234_067, None).unwrap(),
            "tile/data/x001/x234/067"
        );
        assert!(data_tile_path(0, Some(256)).is_err());
    }

    #[test]
    fn lets_encrypt_submission_urls_map_to_their_monitoring_origin() {
        let prefixes =
            monitoring_prefixes("https://log.sycamore.ct.letsencrypt.org/2026h2/").unwrap();
        assert_eq!(
            prefixes.first().unwrap(),
            "https://mon.sycamore.ct.letsencrypt.org/2026h2/"
        );
        assert!(prefixes.iter().any(|prefix| prefix.contains("://log.")));
    }

    #[test]
    fn parser_rejects_truncation_unknown_types_and_bad_chain_vectors() {
        assert!(parse_data_tile(&[], 1).is_err());

        let mut unknown = vec![0_u8; 8];
        unknown.extend_from_slice(&9_u16.to_be_bytes());
        assert!(parse_data_tile(&unknown, 1).is_err());

        let mut x509 = vec![0_u8; 8];
        x509.extend_from_slice(&0_u16.to_be_bytes());
        x509.extend_from_slice(&[0, 0, 1, 0]);
        x509.extend_from_slice(&0_u16.to_be_bytes());
        x509.extend_from_slice(&1_u16.to_be_bytes());
        x509.push(0);
        assert!(parse_data_tile(&x509, 1).is_err());
    }

    #[tokio::test]
    #[ignore = "live interoperability probe"]
    async fn live_letsencrypt_static_log_smoke() {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let batch = fetch_static_delta(
            &client,
            "https://log.sycamore.ct.letsencrypt.org/2026h2/",
            None,
            1,
            1,
        )
        .await
        .unwrap();
        assert_eq!(batch.entries_processed, 1);
        assert_eq!(batch.tiles.len(), 1);
        assert_eq!(batch.next_cursor, batch.checkpoint_size);
    }
}
