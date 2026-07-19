# Fellaga

[![CI](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/actions/workflows/ci.yml/badge.svg)](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Brahim-Fouad/Fellaga-SubDomainFinder)](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.95+](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/blob/main/Cargo.toml)

Fellaga is a fast, adaptive subdomain enumerator written in Rust for Kali Linux and other GNU/Linux systems. It combines passive intelligence, high-throughput DNS validation, strict zone-transfer checks, recursive discovery, and a permanent local SQLite knowledge base.

> [!WARNING]
> Use Fellaga only on domains you own or are explicitly authorized to assess. DNS brute force, AXFR attempts, HTTP requests, and TLS handshakes are active and observable operations.

## Highlights

- Native asynchronous DNS engine with correlated UDP queries, EDNS0, TCP fallback, resolver balancing, retries, and one shared adaptive network governor for discovery, consensus, DNSSEC, Web, and TLS preparation.
- Adaptive `deep` scan by default: 69 registered passive connector names across canonical, Fellaga-native, and compatibility integrations, Certificate Transparency, a one-million-candidate corpus, recursive DNS, AXFR, DNSSEC/NSEC, Web and JavaScript discovery, TLS/STARTTLS, and bounded PTR and IP-to-hostname pivots.
- Protocol-aware DNS discovery follows bounded DNS-SD, NAPTR, URI, SPF, DMARC, MTA-STS, TLS reporting, and BIMI relationships without querying names outside the authorized root.
- Target-local grammar induction learns service, environment, region, cloud, separator, and numeric conventions from retained names, then emits a bounded ranked candidate beam.
- Static CT tiles provide a durable fallback when a log no longer exposes the legacy entry API; tile payloads, checkpoint identity, extracted names, and cursors are committed together in SQLite.
- Standardized metadata and semantic static analysis extract names from API catalogs, OpenID/OAuth metadata, SSH known-hosts data, Terraform discovery, HTML, JSON, JavaScript, source maps, and bounded Common Crawl WARC records without executing scripts.
- Differential TLS compares a small prioritized set of SNI and no-SNI certificates, exposing default virtual-host names while sharing one deadline and never turning an out-of-scope SAN into active work.
- Brave Search follows provider totals for up to ten 20-result pages. MerkleMap follows validated provider totals for up to 1,000 pages, preserving every completed page under the connector wall deadline. The retired BinaryEdge compatibility connector remains visible for legacy configuration and provenance, but it is unavailable and never selected automatically.
- High-volume SubMD results are consumed as a bounded line stream and checkpointed after at most 1,000 names or 500 ms of received streaming progress. THC cursor pagination uses up to five paced page requests per second, can consume up to 1,000 pages of 1,000 records, rejects repeated states, and remains constrained by the passive-phase and connector wall deadlines.
- Keyless archive and public-feed coverage includes Arquivo.pt CDX replay and ShrewdEye's domain feed. Both are streamed with strict record, line, response-size, suffix, and wall-time limits, with volume/time checkpoints that avoid one SQLite transaction per HTTP chunk.
- A single bounded Shodan InternetDB wave enriches public IP addresses already confirmed by the scan. It never sweeps an address range, retains permanent IP-to-hostname observations locally, and submits every in-scope name to the normal wildcard-aware DNS validation pipeline.
- The default `deep` profile selects every locally accessible connector whose metadata permits automatic execution, including eligible experimental providers. `--all-sources` likewise executes each unique implementation once; compatibility names remain available for explicit selection but are not added as duplicate requests. The retired BinaryEdge entry remains unavailable, and every provider still obeys connection, rate, response-size, and wall-time safeguards.
- Persistent, lazy candidate scheduling: passive/authoritative seeds and active word generators are consumed in bounded SQLite-backed waves instead of being materialized in memory before DNS starts.
- Yield-aware source scheduling learns each connector's marginal unique-name yield, reliability, and latency; complete pages remain usable when a later page reaches its deadline, and source checks distinguish `success`, `empty`, `degraded`, `deferred_budget`, `skipped_missing_key`, `rate_limited`, `auth_required`, `anti_bot`, `upstream_error`, `transport_error`, `tls_error`, `schema_error`, `timeout`, and the uncategorized `error` fallback.
- Hierarchical wildcard detection, rotating-answer recognition, exact-signature filtering, trusted-resolver consensus, authoritative validation, and locally validated DNSSEC denial proofs for purging proven synthesized owners.
- Permanent SQLite inventory with `live`, `historical`, and `unverified` states; a complete refresh quarantines exact wildcard-signature matches only after fresh trusted-resolver consensus, while retaining their provenance and validation history.
- Evidence-family scoring so multiple providers backed by the same underlying dataset are not counted as independent proof.
- Cost-aware local scheduling rewards only first-seen live discoveries, records network cost, and uses a conservative statistical yield bound to decide when more brute force is no longer useful.
- Checkpoints every 30 seconds and `--resume latest` for interrupted or time-limited scans; queued work, retry counts, source provenance, and learning counters survive a restart.
- Text, JSON, per-domain JSONL, streaming JSONL, CSV export, and import support for common enumeration tools.
- No telemetry, no remote cache synchronization, and no automatic sharing of targets, findings, or learned patterns.

## Install

### Kali or Debian on x86-64

Download the release package and install it with APT. Checksums, a Sigstore-signed manifest, and GitHub attestations are available for independent verification:

```bash
curl -fLO https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/download/v0.11.0/fellaga_0.11.0-1_amd64.deb
sudo apt install ./fellaga_0.11.0-1_amd64.deb
fellaga --version
```

Portable x86-64 and ARM64 archives, dependency SBOMs, offline license
inventories, checksums, Sigstore material, and GitHub attestations are available
on the [latest release page](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/latest).

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

# Fast bounded scan with broad DNS discovery and shorter enrichment budgets
fellaga scan your-domain.example --profile turbo

# Show only currently validated DNS names
fellaga scan your-domain.example --only-live

# Print only final discovered names, one per line
fellaga scan your-domain.example --show

# Raw output restricted to currently validated non-wildcard names
fellaga scan your-domain.example --show --only-live

# Passive discovery without the active enrichment pipeline
fellaga scan your-domain.example --profile passive

# Provider-only discovery with no DNS, HTTP, or TLS contact to the target
fellaga scan your-domain.example --profile passive --no-target-contact --show

# Provider-only run across every unique source implementation, including experimental sources
fellaga scan your-domain.example --profile passive --no-target-contact --all-sources --show

# Stream each finding as JSONL when it is produced
fellaga scan your-domain.example --stream-jsonl > findings.jsonl

# Resume the newest checkpoint
fellaga scan your-domain.example --resume latest
```

`--show` keeps standard output as a sorted, deduplicated FQDN list. Progress, connector status, and warnings remain visible on standard error; add `--quiet` when a pipeline also requires silent diagnostics.

The default scan processes one domain at a time, caps shared DNS traffic at 250 logical queries per second, and keeps at most 128 host resolutions in flight. The rate cap remains active across validation and enrichment traffic unless `--dns-rate-limit 0` explicitly disables it. Runtime limits are profile-specific: `deep` stops after 600 seconds, `balanced` and `turbo` after 300 seconds, and `passive` after 180 seconds unless `--max-runtime` overrides the limit. The default `deep` profile also gives wildcard profiling and active candidate work a shared 120-second budget. Embedded and user wordlists, mutations, retries, and recursive candidate generation all consume that budget. At the deadline, completed outcomes are kept, unfinished names are requeued as indeterminate, and the scan can continue later with `--resume latest`. Set `--active-max-runtime 0` to disable this time bound. `--no-adaptive` disables low-yield stopping and uses the configured recursion ceilings, but it does not disable ranking, time limits, or DNS rate safeguards. Transient candidate-resolution failures receive at most three total attempts.

`--profile passive` still performs wildcard probes, DNS validation, and direct CT-log indexing. Add `--no-target-contact` when the run must be limited to third-party passive-provider APIs. CT data can still arrive through providers such as crt.sh and Cert Spotter, while the direct CT-log indexer is disabled because some public logs can be hosted under the target's own domain. All names returned by this mode are intentionally `unverified`; no target DNS, HTTP, TLS, AXFR, or other direct target connection is attempted. Existing `live` or `historical` inventory state and DNS records are preserved when the same name is observed passively.

Long-running phases emit periodic progress on standard error. Direct CT-log indexing reports the selected log, durable cursor, entry range, request timeout, and remaining phase budget. It runs opportunistically in the background and never gates the first DNS-validation wave; its `deep`/`balanced`/`passive`/`turbo` budgets are 30/10/30/5 seconds. One process-wide CT indexer runs at a time, and a completed global pass establishes a ten-minute SQLite freshness window that prevents duplicate raw-log work. Initial passive collection and AXFR remain bounded independently; passive budgets are 45/25/60/15 seconds and AXFR allows four concurrent transfers globally with a four-second default per nameserver. Passive connector concurrency accepts and honors values from 1 through 32, crt.sh uses a bounded HTTP-first PostgreSQL fallback, and a cancelled certificate-database connector aborts its pending database connection task. Wildcard certificate patterns remain patterns and are never converted into concrete host findings. Wildcard detection starts with three randomized probes and spends two additional probes only when the first stage is ambiguous. Web and JavaScript discovery also uses one cumulative profile budget across the initial crawl and later pipeline rounds. Completed connector pages are committed to permanent SQLite observations as they arrive, while the active in-memory source set remains bounded. Web fetches are likewise retained after a later operation times out, and the affected phase is reported as partial. Final JSON records include `phase_timings` for initial discovery, candidate DNS, enrichment, and finalization.

The InternetDB pivot is enabled for active profiles and is disabled by `--profile passive` or `--no-internetdb`. Profile defaults query at most 16, 8, and 4 already-confirmed public IP addresses in `deep`, `balanced`, and `turbo`, with cumulative budgets of 20, 10, and 5 seconds respectively. Use `--internetdb-ips`, `--internetdb-max-runtime`, and `--internetdb-refresh-hours` to tune those bounds and successful-cache refreshes.

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

Required and optional provider credentials can be supplied through environment variables or `~/.config/fellaga/config.json`; missing required keys are skipped locally. Fellaga sends a transparent `Fellaga/<version>` HTTP user agent with the project URL by default, and `FELLAGA_USER_AGENT` provides an optional organization-specific override. See [passive sources and credentials](docs/sources.md) for all 69 registry names, accepted variables, experimental provider behavior, bounded connector semantics, and health statuses.

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

API keys are stored as plain JSON, not encrypted. Protect the user account and disk, never commit the configuration or database, and redact target data before sharing diagnostic output. Passive providers receive the queried domain. Active DNS, HTTP, and TLS traffic remains visible to resolvers and target services even though Fellaga sends no telemetry.

## License

Fellaga is released under the [MIT License](LICENSE). The embedded candidate corpus is derived from a pinned SecLists revision; see [corpus provenance](data/CORPUS_LICENSE.md) and [third-party notices](THIRD_PARTY_NOTICES.md). Release packages also include the complete generated Rust dependency license inventory.
