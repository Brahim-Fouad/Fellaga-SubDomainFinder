# Changelog

All notable changes to Fellaga are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Published releases and downloadable artifacts are available on [GitHub Releases](https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases).

## [Unreleased]

### Added

- add `scan --profile passive --no-target-contact` for provider-only collection that retains unverified provenance while preventing target DNS, HTTP, TLS, AXFR, wildcard, and enrichment traffic;
- add a pinned Tranco top-30 observational campaign with isolated no-key competitor runs, executable provenance, live progress, and descriptive-only reporting;
- expand the passive registry to 65 connector names with 55 canonical integrations, six Fellaga-native connectors, four compatibility names, capability metadata, bounded pagination, and incremental page persistence;
- add current provider contracts for Censys Platform v3, Netlas streamed downloads, SecurityTrails scrolling, four-family Driftnet summaries, and full code-search content extraction.

### Changed

- select all 61 locally accessible unique canonical and Fellaga-native connectors in the default deep profile while keeping duplicate compatibility names opt-in;
- walk five yearly Common Crawl indexes breadth-first, follow Wayback resume keys, rotate code-search credentials on quota responses, and retain completed pages before later failures;
- use generic `json`, `jsonl`, `text`, and `dns-text` import format names without coupling the runtime interface to another enumeration product.

### Fixed

- fail closed when an external benchmark tool's no-DNS dry run exits successfully but still reports a semantic DNS-resolution requirement;
- disable direct CT-log indexing in `--no-target-contact` mode when a public log endpoint could belong to the target, while retaining CT provider connectors;
- preserve existing live or historical inventory state, verification time, and DNS records when provider-only observations are merged;
- treat empty no-result provider payloads as empty results, keep mixed Driftnet evidence in the aggregator family, and reject repeated cursors, unsafe pagination destinations, oversized streams, or truncated records without discarding completed checkpoints.

## [0.9.2] - 2026-07-17

### Added

- add `scan --show` for final raw FQDN output that is silent, sorted, deduplicated, wildcard-finalized, and compatible with `--only-live`.

## [0.9.1] - 2026-07-17

### Changed

- charge DNS retry counters only after the transport accepts a packet, so pre-send cancellation remains resumable while post-send cancellation is accounted for;
- validate and canonicalize Chrome CT log URLs, resolve and pin only public addresses, disable proxy and redirect handling, and apply one cumulative deadline across RFC 6962 and Static CT operations;
- select mutation inputs from a deterministic 20,000-observation window, retain at most 5,000 diverse high-value names, and materialize that window once per resumable scan;
- reject inconsistent provider pagination instead of treating schema drift or repeated cursors as a successful end of results.

### Fixed

- include UDP and TCP admission queues, sends, retries, and fallback work in the caller-owned DNS timeout; bound authoritative resolver caches, sockets, nameservers, and address fan-out;
- feed trusted consensus, authoritative checks, fast-path failures, and Hickory fallbacks into accurate resolver metrics and the shared adaptive network governor;
- revalidate fresh cache entries shaped by a confirmed wildcard, quarantine only current exact matches backed by resolver consensus or authoritative validation, and prevent `--include-wildcard` from restoring reusable positive state;
- preserve existing live cache and inventory state when wildcard profiling is incomplete, indeterminate, a record superset, or supported by only one non-authoritative resolver, while retaining non-destructive audit evidence for later refreshes;
- prevent conventional NSEC3 range evidence from authorizing destructive wildcard cleanup and canonicalize escaped ASCII octets during DNSSEC name ordering;
- separate SQLite seed reservation from sent DNS attempts, requeue unfinished work safely, enforce the three-attempt ceiling across seed, active, named, and recursive claims, claim late CT seeds atomically, and make resume/checkpoint transitions idempotent;
- keep live outcomes stronger than duplicate negative or error outcomes in one persistence wave, scope wildcard cleanup to the requested root, and prevent wildcard findings from materializing as reusable live records;
- back up unversioned legacy SQLite databases before migration, preserve immutable checkpoint domains, and saturate persistent counters and legacy scheduler values instead of wrapping or propagating invalid floats;
- prevent detached CT materialization or refresh-marker workers from outliving cancellation, make tile/name/cursor commits atomically cancellable under SQLite contention, and retain a CT result that completes at the final join boundary;
- reject mismatched or truncated Common Crawl byte ranges, repeated Cert Spotter cursors, unsafe VirusTotal pagination ports, and inconsistent BinaryEdge, Brave, Driftnet, MerkleMap, and Shodan progress fields;
- accept provider envelopes with `error: false`, `error: 0`, or `error: 0.0`, reject impossible generated FQDNs, bound mutation and grammar cross-products, keep cancelled candidates out of adaptive learning, saturate scores and counters, and return CLI errors instead of panicking on pathological duration values.

## [0.9.0] - 2026-07-16

### Added

- added a target-local hostname grammar that learns service, environment, region, cloud, separator, and numeric conventions under deterministic beam and expansion limits;
- added bounded DNS-SD, NAPTR, URI, SPF, DMARC, MTA-STS, TLS reporting, and BIMI discovery while keeping external relationships as non-querying features;
- added standardized HTTPS metadata discovery for API Catalog, OpenID Connect, OAuth authorization-server metadata, SSH known hosts, Terraform discovery, and host-meta;
- added a Static CT tile reader with durable tile/checkpoint caching and automatic fallback from unavailable RFC 6962 entry endpoints;
- added bounded Common Crawl WARC sampling and semantic static extraction from HTML, JSON, JavaScript calls and configuration, string composition, and source maps;
- added differential SNI/no-SNI TLS certificate inspection for a maximum of four prioritized endpoints;
- added locally validated NSEC and compact NXNAME denial classification for a bounded wildcard-suspect set, with conservative NSEC3 exact-owner and Opt-Out handling that never promotes an ordinary range proof to destructive cleanup;
- added SQLite schema v9 foundations for discovery actions, intelligence relationships, DNSSEC proofs, CT tiles, and scheduler arms, with bounded public APIs for action queues, learned templates, CT cache data, and cost-aware generator ranking;
- added `wildcard_verdict`, `owner_proofs`, `generation_path`, and `discovery_score` to findings, plus final `scheduler_metrics`.

### Changed

- made adaptive network pressure control the default: configured DNS rate and concurrency are ceilings, with loss/latency backoff and cautious recovery;
- rank active generators with a deterministic cost-adjusted Beta-UCB score and reward only same-scan, first-seen, live, non-wildcard discoveries;
- use a one-sided Wilson yield bound over consecutive active waves before stopping statistically low-yield brute force;
- route metadata hostname resolution through Fellaga's configured consensus DNS engine and pin only public addresses;
- use the adaptive concurrency snapshot in bulk DNS operations and expose the final stop reason and network backoffs in human and JSON output.

### Fixed

- purge positive cache and active inventory state when locally validated DNSSEC proof establishes that a wildcard-synthesized candidate does not exist, while retaining provenance and an append-only audit event;
- keep unsigned, AD-only, empty-non-terminal, Opt-Out, contradictory, or otherwise inconclusive DNSSEC evidence from authorizing cleanup;
- bound archive range downloads, decompression, document analysis, output cardinality, redirects, and metadata bodies;
- preserve v8 data transactionally during the v9 migration, reject future schemas, and repair partially initialized v9 databases without deleting observations.

## [0.8.6] - 2026-07-16

### Added

- added structured incremental CT progress with the selected log, durable cursor, tree size, entry range, per-request timeout, remaining phase budget, committed batch, and final materialization status;
- added persistent `degraded` and `deferred` source-health states so partial pages, local preflight failures, phase cancellation, and provider failures remain distinct;
- added bounded passive-cache reads and immediate SQLite page commits while retaining the complete permanent observation history;
- added CI and release consistency checks for Cargo, Debian, changelog and documentation versions, download URLs, and the closed seven-asset release set.

### Changed

- use the documented authenticated Driftnet Certificate Transparency endpoint and require a real Driftnet token; require an OTX key instead of repeatedly attempting unavailable anonymous access;
- select experimental connectors automatically only when the registry marks them safe for automation and every required credential is configured; browser-facing anti-bot connectors remain explicit;
- share transparent HTTP identity, connection pools, compression, content negotiation, source and host rate limits, complete-attempt body validation, safe-method retries, bounded error bodies, and strict same-origin pagination across connectors;
- validate provider JSON envelopes and pagination contracts explicitly, retain completed pages after later failures, and report pagination caps as degraded rather than complete success;
- keep passive connector and timeout checkpoints bounded in memory, persist full decoded pages before truncation, and refill the globally ranked candidate set from SQLite up to `--max-passive`.

### Fixed

- prevent missing API keys from incrementing provider failure streaks, and make a newly configured key bypass legacy missing-key cooldowns immediately;
- distinguish transport failures, schema drift, anti-bot responses, upstream 5xx maintenance, quotas, authentication failures, timeouts, and phase-budget deferrals in `sources --check`;
- avoid replaying POST or PATCH requests, handle HTTP 524 and truncated successful bodies correctly, and apply long `Retry-After` guidance without blocking the scan;
- eliminate unbounded error-string compaction, the second full-body HTTP copy, and loss of response URL/extensions after retry validation;
- make direct CT cancellation cursor-safe, cap decompressed response bodies and target materialization, keep reused `ct-direct` evidence idempotent, avoid SQLite rereads after abort, release the global CT gate before target materialization, and mark the global refresh complete only when every selected log succeeds;
- avoid rewarding duplicate raw source volume, prevent large AnubisDB responses from monopolizing automatic validation, and keep same-provider network/cache provenance from being duplicated;
- record only actually started passive requests as deferred when the shared phase budget ends.

## [0.8.5] - 2026-07-16

### Added

- added credentialed BinaryEdge passive-DNS discovery through `BINARYEDGE_API_KEY`, MerkleMap Certificate Transparency search through `MERKLEMAP_API_TOKEN`, and Brave Web discovery through `BRAVE_SEARCH_API_KEY`;
- added targeted one-page fast paths for the three new connectors, with at most one follow-up page when the provider reports additional raw results.

### Changed

- run direct incremental CT-log indexing opportunistically in the background so unfinished raw-log work cannot delay the first DNS-validation wave, and reduce its `deep`/`balanced`/`passive`/`turbo` budgets to 30/10/30/5 seconds;
- serialize raw CT-log indexing through one process-wide single-flight gate and reuse a completed global pass from SQLite for ten minutes, avoiding duplicate work across concurrent or successive target scans;
- reduce passive-source budgets to 45/25/60/15 seconds for `deep`/`balanced`/`passive`/`turbo`, bound each connector by the remaining phase time, and preserve complete pages from a later failed or timed-out request;
- rank sources from marginal unique-name yield, reliability, and latency, with metadata-based bootstrap priorities for connectors that do not yet have local history;
- raise the guarded default DNS rate from 100 to 250 requests per second while retaining one shared limiter across validation and enrichment traffic;
- use three wildcard probes for conclusive routine classification and spend two additional probes only when the first stage is ambiguous;
- invalidate older wildcard profiles after tightening mixed and incomplete-sample classification, and keep unprofiled child zones unverified instead of inheriting a normal root result;
- restrict external HTTP redirects to the same scheme, host, and port so credential headers cannot cross origins; partial pages remain permanent without being marked as a complete fresh cache;
- default AXFR to four seconds per nameserver and enforce a process-wide limit of four concurrent transfers.

## [0.8.4] - 2026-07-16

### Added

- added `--active-max-runtime` and structured `phase_timings` so active candidate work has an attributable shared time bound;
- added `--web-max-runtime` with one cumulative Web and JavaScript budget shared by initial enrichment and later pipeline rounds;
- added periodic heartbeats while direct CT and AXFR checks are still running;
- added bounded parallelism and true whole-connector deadlines to `sources --check`, with immediate human-readable results as each source finishes;
- added detailed candidate-pipeline timings for wordlist loading, queue counts, claims, DNS journaling, finalization, and total SQLite work;
- added architecture-bound CycloneDX dependency SBOMs and offline Rust license inventories to release archives and the Debian package.

### Changed

- replace the previous 1,800-second scan default with profile-specific limits: 600 seconds for `deep`, 300 for `balanced` and `turbo`, and 180 for `passive`; `--max-runtime 0` remains the explicit unlimited mode;
- cap the default recursive word and parent ceilings at 1,000 each for `deep` and `turbo`, avoiding accidental multi-million candidate cross-products;
- require a sustained yield from later adaptive DNS waves, limit those waves to 1,000 names, and charge recursive candidate generation to the same active budget;
- coalesce each Common Crawl 15-block index window into one URL-only request and defer long `Retry-After` waits into the persistent source scheduler;
- qualify generated-candidate NXDOMAIN fast paths with resolver health probes, keep their negatives journal-only, and use full consensus for retained names, wordlists, retries, refresh, wildcard, Web, and TLS work;
- force per-name verification indexes in candidate finalization, align lazy wordlist pages with scheduler batches, and group negative inventory updates;
- make full-coverage benchmarks pass an explicit active runtime and verify the exact active-corpus count against PureDNS capacity evidence.

### Fixed

- enforce the default 120-second `deep` active budget across embedded and user wordlists, mutations, retries, resumed active work, and recursive candidate generation; preserve completed outcomes at the deadline and requeue unfinished work for `--resume latest`;
- keep time and DNS rate safeguards active with `--no-adaptive`; only `--active-max-runtime 0` disables the active-candidate time bound;
- quarantine exact wildcard matches only after a complete refresh with fresh trusted-resolver consensus, while preserving provenance and validation history;
- return fresh or stale Web cache entries when the cumulative Web deadline expires before DNS pinning, without starting an HTTP request;
- retain completed passive pages under a connector deadline and report them accurately in both scans and `sources --check`;
- recover release reruns by deleting an interrupted draft without permitting an existing published release to be overwritten.

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
- apply completed wildcard cleanup in one cancellable transaction, roll it back on timeout or interruption, quarantine exact current-consensus wildcard matches even when passive history exists, and retain all provenance for `explain`;
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
- preserve legitimate answers whose records differ from a wildcard pool, and quarantine exact wildcard-signature matches while retaining their stored provenance and validation history;
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

[Unreleased]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/compare/v0.9.2...HEAD
[0.9.2]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.9.2
[0.9.1]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.9.1
[0.9.0]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.9.0
[0.8.6]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.6
[0.8.5]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.5
[0.8.4]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.4
[0.8.3]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.3
[0.8.2]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.2
[0.8.1]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.1
[0.8.0]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v0.8.0
