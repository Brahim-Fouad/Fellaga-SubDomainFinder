# Fellaga

[![CI](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/actions/workflows/ci.yml/badge.svg)](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Brahim-Fouad/Fellaga-SubDomainFinder)](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/blob/main/Cargo.toml)

Fellaga is a fast, adaptive subdomain enumerator written in Rust for Kali Linux and other GNU/Linux systems. It combines passive intelligence, high-throughput DNS validation, strict zone-transfer checks, recursive discovery, and a permanent local SQLite knowledge base.

> [!WARNING]
> Use Fellaga only on domains you own or are explicitly authorized to assess. DNS brute force, AXFR attempts, HTTP requests, and TLS handshakes are active and observable operations.

## Highlights

- Native asynchronous DNS engine with correlated UDP queries, EDNS0, TCP fallback, resolver balancing, retries, and global rate limiting.
- Adaptive `deep` scan by default: passive sources, Certificate Transparency, a one-million-candidate corpus, recursive DNS, AXFR, DNSSEC/NSEC, Web and JavaScript discovery, TLS/STARTTLS, and bounded PTR pivots.
- Persistent, lazy candidate scheduling: passive/authoritative seeds and active word generators are consumed in bounded SQLite-backed waves instead of being materialized in memory before DNS starts.
- Hierarchical wildcard detection, rotating-answer recognition, exact-signature filtering, trusted-resolver consensus, and optional authoritative validation.
- Permanent SQLite inventory with `live`, `historical`, and `unverified` states; positive evidence is retained while weak wildcard-only false positives are purged automatically.
- Evidence-family scoring so multiple providers backed by the same underlying dataset are not counted as independent proof.
- Checkpoints every 30 seconds and `--resume latest` for interrupted or time-limited scans; queued work, retry counts, source provenance, and learning counters survive a restart.
- Text, JSON, per-domain JSONL, streaming JSONL, CSV export, and import support for common enumeration tools.
- No telemetry, no remote cache synchronization, and no automatic sharing of targets, findings, or learned patterns.

Fellaga does not claim market leadership without reproducible evidence. The repository includes a controlled DNS laboratory and a benchmark harness so coverage, false positives, throughput, and resource use can be measured transparently.

## Install

### Kali or Debian on x86-64

Download the release package and install it with APT. Checksums, a Sigstore-signed manifest, and GitHub attestations are available for independent verification:

```bash
curl -fLO https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/download/v0.8.2/fellaga_0.8.2-1_amd64.deb
sudo apt install ./fellaga_0.8.2-1_amd64.deb
fellaga --version
```

Portable x86-64 and ARM64 archives, checksums, SBOMs, Sigstore material, and GitHub attestations are available on the [latest release page](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/latest).

### Build from source

```bash
git clone https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder.git
cd Fellaga-SubDomainFinder
./install.sh
```

The source installer builds the optimized binary with Rust 1.95 or newer and places it in `~/.local/bin` by default. See the [installation guide](docs/installation.md) for ARM64, archive installation, release verification, upgrades, and source prerequisites.

## Quick start

Replace `your-domain.example` with an authorized target:

```bash
# Adaptive deep scan with safe resource limits
fellaga scan your-domain.example

# Show only currently validated DNS names
fellaga scan your-domain.example --only-live

# Passive discovery without the active enrichment pipeline
fellaga scan your-domain.example --profile passive

# Stream each finding as JSONL when it is produced
fellaga scan your-domain.example --stream-jsonl > findings.jsonl

# Resume the newest checkpoint
fellaga scan your-domain.example --resume latest
```

The default scan processes one domain at a time, caps DNS traffic at 100 queries per second, uses at most 128 concurrent DNS requests, and stops after 1,800 seconds per domain. Adaptive waves stop low-yield generated candidates early, but do not silently abandon an unfinished user wordlist or the bounded passive seed queue. Transient candidate-resolution failures receive at most three total attempts. These safeguards can be changed explicitly, but disabling them may saturate the local connection, public resolvers, or the target.

Long-running phases emit periodic progress on standard error. Initial passive collection, direct CT monitoring, and AXFR run concurrently, while passive work has a separate profile-specific active-time budget so waiting in unrelated phases does not consume it. Names returned on completed connector pages are retained even if a later page times out; the affected source is reported as partial rather than silently discarded.

Fellaga displays all retained states by default:

| State | Meaning |
| --- | --- |
| `live` | The name has a DNS validation that is still within the configured freshness window. |
| `historical` | The name was previously validated but has not been confirmed recently. |
| `unverified` | The name lacks DNS confirmation, or a positive answer remains ambiguous because it matches a confirmed or indeterminate wildcard profile. |

Use `--only-live` when downstream tooling must receive only fresh DNS results. Use `fellaga explain <fqdn>` to inspect retained provenance, state, validation history, DNS records, and stored confidence metadata.

## Common workflows

```bash
# Read targets from a file or standard input
fellaga scan --targets-file authorized-domains.txt
printf '%s\n' a.example b.example | fellaga scan -

# Check source configuration and current connector health
fellaga sources
fellaga sources --check --target your-domain.example

# Test resolvers before an intensive authorized scan
fellaga resolvers test

# Inspect and export the permanent local inventory
fellaga list --domain your-domain.example
fellaga explain api.your-domain.example
fellaga export --domain your-domain.example --format jsonl -o inventory.jsonl

# Revalidate known names without deleting historical observations
fellaga refresh your-domain.example
```

Run `fellaga <command> --help` for the complete option list.

## Documentation

- [Documentation home](docs/README.md)
- [Installation and upgrades](docs/installation.md)
- [Scanning and command reference](docs/usage.md)
- [Discovery, validation, wildcard handling, and stopping rules](docs/discovery-engine.md)
- [Passive sources and credentials](docs/sources.md)
- [SQLite, retention, privacy, and cache behavior](docs/local-data.md)
- [Release integrity and provenance verification](docs/release-verification.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Candidate corpus provenance](data/CORPUS_LICENSE.md)

## Local data and privacy

The default database is `~/.local/share/fellaga/fellaga.db`; the default API-key configuration is `~/.config/fellaga/config.json`. Fellaga creates its dedicated Unix directories with mode `0700` and its configuration, SQLite database, WAL/SHM files, and migration backups with mode `0600`.

API keys are stored as plain JSON, not encrypted. Protect the user account and disk, never commit the configuration or database, and redact target data before sharing diagnostic output. Passive providers receive the queried domain, while resolvers and target services can observe active DNS, HTTP, and TLS traffic. “No telemetry” does not make reconnaissance anonymous.

## License

Fellaga is released under the [MIT License](LICENSE). The embedded candidate corpus is derived from a pinned SecLists revision; see [corpus provenance](data/CORPUS_LICENSE.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
