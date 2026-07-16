# Changelog

All notable changes to Fellaga are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Published releases and downloadable artifacts are available on [GitHub Releases](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases).

## [Unreleased]

## [0.8.3] - 2026-07-16

### Added

- added `fellaga benchmark candidate-pipeline`, a deterministic ten-million-candidate exercise of fixture generation, SQLite persistence, bounded scheduling, native DNS dispatch, result accounting, and artifact provenance;
- added refresh progress, `--quiet`, a five-minute default refresh limit, configurable validation batches, and interruption-safe non-resumable checkpoints;
- added deadline-aware cumulative budgets for direct CT monitoring and NSEC traversal.

### Changed

- cancel slower trusted-resolver work as soon as positive consensus is reached, skip duplicate fallback against a timed-out fast resolver, and cache authoritative nameserver discovery with single-flight loading;
- exclude intentional DNS rate-limit queue time from per-operation network timeouts while keeping every network operation and phase deadline bounded;
- route Web, TLS, PTR, authoritative, trusted-consensus, and direct NSEC traffic through the configured shared DNS cadence;
- cap cross-target, Web, TLS, passive, CT, NSEC, and enrichment concurrency while preserving partial results from completed work;
- page refresh inventory and cache reads with stable SQLite cursors, rank parent wildcard zones in bounded memory, and stage wildcard matches in SQLite;
- harden the competitor benchmark with isolated homes, equal-key validation, fresh output directories, process-group timeouts, recursive redaction, resolver fairness metadata, executable and input hashes, strict repetition accounting, and fail-closed qualification reports;
- separate the 100,000-query transport test from the ten-million-candidate pipeline test and give each an independent wall timeout.

### Fixed

- prevent a stale wildcard signature from authorizing destructive cleanup when current randomized probes are indeterminate;
- apply completed wildcard cleanup in one cancellable transaction, roll it back on timeout or interruption, retain independently supported names as `unverified`, and remove weak wildcard-only inventory, cache, scan findings, and DNS records;
- recalculate historical scan result counts after wildcard cleanup and disable all cleanup when parent-zone coverage or current wildcard classification is incomplete;
- keep low-rate DNS queues from turning valid hosts into indeterminate results before their requests are sent;
- enforce `--dns-rate-limit` for direct NSEC traffic in addition to its local traversal cap;
- preserve completed refresh batches and close the refresh checkpoint safely on timeout, Ctrl+C, or future cancellation.

## [0.8.2] - 2026-07-16

### Added

- added separate persistent SQLite queues for high-value discovery seeds and active generated candidates, including durable priorities, merged provenance, feed cursors, retry counters, and resume-safe learning counters;
- added bounded, resumable wordlist paging with non-UTF-8-tolerant decoding, oversized-line handling, and fixed per-page line and byte limits;
- added periodic phase heartbeats for passive collection, DNS validation, graph, Web, TLS, recursive, pipeline, and other potentially long-running work;
- added a real CLI DNS laboratory covering wildcard filtering and complete versus refused AXFR behavior.

### Changed

- start DNS validation from small adaptive waves instead of inserting the complete embedded corpus into SQLite before the first query;
- interleave high-value passive, CT, AXFR, cached, and learned seeds with active candidates, then continue draining the bounded seed queue after adaptive brute-force generation stops;
- run initial passive collection, direct CT monitoring, and AXFR concurrently;
- charge passive time limits only while passive phases are active, share a global passive connector concurrency limit across root and child zones, and retain completed pages from a connector that later times out;
- retry transient candidate DNS failures up to three total attempts across the original run and resumed runs, while definitive negative responses remain terminal;
- ensure an unfinished explicit wordlist is processed independently of low-yield adaptive stopping;
- reuse prepared SQLite statements during atomic scan finalization, add queue-selection indexes, and move superseded-queue cleanup outside the completion-critical transaction;
- keep the existing conservative defaults: one active target, 100 DNS requests per second, 128 in-flight DNS operations, bounded source work, 30-second checkpoints, and a 1,800-second per-target limit.

### Fixed

- exclude exact wildcard-signature matches from normal scan output even when another discovery source supplied the name; `--include-wildcard` remains the explicit opt-in;
- preserve legitimate answers whose records differ from a wildcard pool, and purge only weak wildcard-only inventory rows and orphaned positive cache entries;
- preserve seed provenance, queue position, retry state, and previously validated positive results across interruption and `--resume`;
- prevent resumed or duplicate queue work from double-counting candidate learning;
- repair additive v8 columns before creating dependent indexes and wrap same-version schema repair in one rollback-safe transaction;
- classify an immediate AXFR refusal as `refused` instead of waiting for the transfer timeout.

## [0.8.1] - 2026-07-16

### Changed

- rebuilt the public README as a concise English project entry point;
- added dedicated English guides for installation, usage, discovery, sources, local data, and release verification;
- translated contributor, security, benchmark, test-laboratory, fixture, and developer-script documentation to English;
- translated and completed the built-in command help so every public option has an English description;
- packaged the complete English guide set in both release archives and the Debian package, preserving relative documentation paths;
- documented the actual passive-profile behavior, resource limits, wildcard refresh behavior, output states, and immutable release-verification process.

### Fixed

- made `--stream-jsonl --only-live` wait for each domain's final wildcard classification so stale, unverified, or wildcard findings cannot leak into the live-only stream;
- corrected the wildcard refresh help text and shortened mutation-DSL help so terminal wrapping does not corrupt the placeholder list.

## [0.8.0] - 2026-07-16

Initial public release of Fellaga.

### Added

- asynchronous Rust DNS engine with correlated UDP queries, EDNS0, TCP fallback, rate limiting, and trusted-resolver validation;
- permanent SQLite inventory with `live`, `historical`, and `unverified` states, an append-only validation journal, checkpoints, and resume support;
- passive sources, incremental Certificate Transparency, strict AXFR, NSEC, DNS graph, Web/JavaScript, TLS/STARTTLS, and contextual mutations;
- hierarchical wildcard detection, evidence families, and explained confidence scores;
- pinned and compressed one-million-candidate corpus derived from SecLists;
- text, JSON, JSONL, streaming JSONL, import, export, explanation, source-health, and resolver-test interfaces;
- reproducible competitor benchmark, controlled DNS laboratory, property tests, fuzz target, and CI/release workflows.

### Security and reliability

- conservative defaults for concurrency, DNS rate, active domains, and maximum runtime;
- adaptive `deep` profile by default, including low-yield wave termination;
- absolute timeouts and bounded work for AXFR, TLS, NSEC, Web, CT, and external providers;
- private/local Web destination filtering and redirect validation;
- private Unix permissions for configuration, SQLite, WAL/SHM, and migration backups;
- purge of weak wildcard observations and orphaned positive cache records without deleting independent evidence;
- local-only learning with no telemetry or automatic database sharing.

### Distribution

- public MIT repository with security policy, contribution guide, third-party notices, and verifiable corpus provenance;
- verifiable v0.8.0 release with x86-64 and ARM64 GNU/Linux archives, an amd64 Debian package, architecture SBOMs, checksums, a keyless Sigstore signature over the checksum manifest, and GitHub attestations.

[Unreleased]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/compare/v0.8.3...HEAD
[0.8.3]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.3
[0.8.2]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.2
[0.8.1]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.1
[0.8.0]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.0
