# Changelog

All notable changes to Fellaga are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

A version is available only when its artifacts appear on [GitHub Releases](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases). A changelog entry or Git tag alone does not prove that publication succeeded.

## [Unreleased]

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

[Unreleased]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.1
[0.8.0]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.0
