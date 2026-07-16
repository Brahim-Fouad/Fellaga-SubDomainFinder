# Discovery engine

Fellaga separates discovery from validation. A provider response, certificate name, archive URL, mutation, or learned word becomes a candidate; it does not automatically become a live finding. Candidates are normalized, scoped, deduplicated, prioritized, and then validated through the DNS engine.

## Discovery stages

1. Load permanent local observations and learned candidate priorities.
2. Query selected passive providers and incrementally read Certificate Transparency data while strict AXFR checks run independently.
3. Detect wildcard behavior for the target and relevant child zones.
4. Persist high-value discovery seeds and active generated candidates in separate SQLite queues, then validate them in interleaved bounded waves.
5. Inspect the DNS graph and detect walkable NSEC zones.
6. Extract in-scope names from Web content, JavaScript, source maps, archives, TLS certificates, and STARTTLS endpoints.
7. Feed new evidence back into the bounded event pipeline for recursive validation and enrichment.
8. Store normalized evidence, validation events, graph edges, source health, and learning statistics locally.

The `passive` profile disables stages that directly contact target application services or authoritative servers for enrichment, but passive-provider requests, CT collection, wildcard probes, and DNS validation still use the network.

Initial passive collection, direct CT monitoring, and AXFR are independent futures and run concurrently. Their results are merged only after each bounded phase finishes, so a slow provider does not serialize unrelated CT or zone-transfer work.

## Persistent candidate scheduler

Fellaga has two durable per-scan queues:

- the **seed queue** stores names discovered through passive providers, CT, AXFR, retained observations, and other high-value evidence together with merged source provenance and a priority;
- the **active queue** stores relative names emitted by the user wordlist, mutation rules, local learning, and the embedded corpus together with their generator and score.

The scheduler claims small batches atomically, marks them as processing, and records the number of attempts. The first adaptive batch contains up to 500 names, the second up to 1,500, and subsequent batches up to 1,000. When both queues have work, seed candidates receive most of each wave while active discovery continues alongside them. Queue rows and generator feed cursors remain in SQLite across an interruption.

A transient DNS error requeues a claimed name until it reaches three total attempts. Definitive negative and validated positive outcomes are terminal. `--resume latest` also requeues rows that were left in the processing state by an interrupted process. Attempt and success counters are persisted independently from disposable queue rows so final learning remains accurate and is applied once.

Active generation is lazy: the one-million-name corpus is traversed with a durable priority cursor instead of being materialized in the per-scan queue before DNS begins. A user wordlist uses a durable byte cursor and scheduler-sized pages capped at 16,384 lines or 4 MiB. Non-UTF-8 input and oversized lines cannot create an unbounded read. Adaptive low-yield stopping can pause expansion without discarding queued work. Wildcard profiling and active candidate work share the profile-specific time budget; `deep` defaults to 120 seconds. Embedded and user wordlists, mutations, retries, resumed active work, and recursive candidate generation share this budget. At its deadline, completed outcomes are committed, unfinished names are recorded as indeterminate and requeued, and the checkpoint can be continued with `--resume latest`. Set `--active-max-runtime 0` to disable this time bound.

## Discovery methods

| Method | Behavior |
| --- | --- |
| Passive connectors | Queries a registry of public and credentialed services with per-provider rate limits, bounded responses, retry policy, partial-page retention, and permanent merged observations. |
| Certificate Transparency | Combines provider results with direct incremental CT-log monitoring and extracts in-scope SAN/CN names. |
| DNS brute force | Processes an embedded one-million-candidate corpus, user wordlists, mutations, and locally learned patterns in prioritized waves. |
| Recursive discovery | Tests high-yield labels below validated parents up to the selected profile depth. |
| AXFR | Attempts TCP zone transfers against authoritative nameservers and accepts only complete protocol-valid transfers. |
| DNS graph | Follows bounded MX, NS, SOA, TXT, CAA, SRV, HTTPS, and SVCB relationships and records child zones and service endpoints. |
| DNSSEC | Detects NSEC, NSEC3, and minimal NSEC responses; walks only bounded, enumerable NSEC chains. |
| Web and archives | Extracts in-scope hostnames from headers, redirects, HTML, JavaScript, JSON, manifests, source maps, Common Crawl, Wayback, and urlscan data. |
| TLS and STARTTLS | Extracts SAN/CN names from selected TLS endpoints and performs minimal STARTTLS negotiation for supported mail protocols. |
| PTR | Queries only IP addresses already confirmed during the scan; it does not sweep address ranges. |

## DNS validation

The native Rust transport correlates parallel UDP requests, uses EDNS0, retries bounded failures, balances configured resolvers, and falls back to TCP when a response is truncated. Fast discovery resolvers and final trusted resolvers can be configured separately.

Fresh generated candidates use a negative fast path only when two independent resolvers return strict, untruncated NXDOMAIN responses for the candidate's A query. Any disagreement, NODATA response, CNAME, timeout, or malformed packet falls back to the full conservative A and AAAA path. These discovery negatives are written only to the append-only validation journal: they never replace a positive cache entry or demote retained inventory. Seeds, explicit wordlists, resumed candidates, indeterminate retries, wildcard probes, refresh, Web, and TLS resolution always use the conservative resolver path.

By default, Fellaga uses `1.1.1.1`, `8.8.8.8`, and `9.9.9.9` for both pools and shares the global DNS rate limit across validation work. Trusted-resolver consensus and authoritative checks reduce false live results caused by poisoned caches, inconsistent resolvers, or wildcard DNS.

Trusted validation uses bounded concurrency after the primary batch, and both stages share the configured DNS rate limit. DNS progress is emitted as cache entries and network outcomes complete, while phase heartbeats cover bounded enrichment operations.

TLS and Web hostname pinning reuse the same configured DNS engine and shared rate limiter. They do not start a separate system resolver or bypass `--resolvers`; Web targets are still filtered to public IP addresses before requests are sent.

## Wildcard detection and cleanup

Fellaga tests five randomized labels per relevant zone. Three or more positive probes classify the zone as wildcard only when they share a stable record value; three or more definitive NXDOMAIN responses with no positive probe classify it as normal. Mixed responses, incomplete evidence, and rotating pools without a stable value remain indeterminate. A stable CNAME remains usable even when its terminal addresses rotate.

Wildcard profiles are reused for six hours by default. After that window, Fellaga revalidates the zone, including a SOA query and a new set of randomized probes. Set `--wildcard-refresh-hours 0` to force refresh on every scan.

A candidate whose answer matches the applicable stable wildcard signature is excluded from default scan output, even when CT, passive, Web, or TLS discovery also supplied the name. This avoids presenting a discovered label as live when DNS cannot distinguish it from a synthesized wildcard response. A positive answer with records distinct from the wildcard signature remains eligible for validation and enrichment.

For permanent storage, Fellaga treats a wildcard-signature match as ambiguity, not proof that the exact owner is absent. A complete bounded refresh can add the name to the root-scoped wildcard quarantine only after a current resolver consensus matches a freshly confirmed profile. Passive and historical evidence remains stored and visible through `explain`, but cannot make an answer that is currently indistinguishable from the wildcard visible in normal inventory. The reusable positive cache and materialized live state are demoted, while provenance, validation history, and the quarantine audit entry remain stored. A later validated non-wildcard finding automatically lifts the quarantine. Partial or indeterminate refreshes never apply cleanup.

Use `--include-wildcard` only when downstream analysis explicitly needs weak wildcard matches.

## Strict AXFR classification

An AXFR attempt is successful only when the TCP transfer is complete and contains the opening and closing SOA records required by the protocol. Attempts are recorded as one of:

- `success`
- `refused`
- `empty`
- `timeout`
- `protocol_error`

An empty answer, refusal, timeout, or incomplete transfer is never counted as a successful source of names.

## Evidence families and confidence

Fellaga maps raw providers to underlying evidence families:

- `authoritative`
- `live_dns`
- `certificate_transparency`
- `passive_dns`
- `web_archive`
- `web_crawl`
- `code_search`
- `aggregator`

Multiple CT providers therefore count as one CT family, not several independent techniques. Confidence also considers current state, authoritative support, wildcard similarity, and whether validation occurred in the current scan. Use `fellaga explain <fqdn>` to see the reasons rather than treating the numeric score as an opaque verdict.

## Performance and stopping rules

Several independent limits prevent an intensive scan from running forever or exhausting the local connection:

- one active target by default;
- 100 DNS requests per second globally;
- 128 concurrent host-resolution tasks;
- profile-specific per-target limits of 600 seconds for `deep`, 300 for `balanced` and `turbo`, and 180 for `passive`;
- bounded response sizes and per-provider timeouts;
- a profile-specific passive active-time budget shared across root and recursive passive phases;
- a global passive connector semaphore shared by root and child zones;
- bounded AXFR, CT, NSEC, Web, TLS, graph, PTR, and pipeline work, including one cumulative Web/JavaScript deadline shared across all crawl rounds;
- adaptive candidate waves that stop after insufficient yield;
- a profile-specific active DNS budget shared by wildcard profiling, embedded and user wordlists, mutations, retries, resumed work, and recursive candidate generation;
- persistent lazy SQLite-backed seed and active batches so millions of candidates do not need to remain in memory or be inserted before validation begins;
- a persistent checkpoint every 30 seconds.

The passive budget advances only while passive work is running; time spent waiting for concurrent CT/AXFR completion or later non-passive phases is not charged to it. A connector that times out after returning one or more complete pages contributes those names as a partial result and is reported as degraded. Periodic heartbeats cover passive collection, CT, AXFR, DNS validation, and long enrichment phases. Final scan objects expose phase timings for performance diagnosis.

Scan completion and learning are committed atomically. Prepared SQLite statements are reused for large word and pattern updates, and queue-selection indexes support bounded claims. Queue cleanup runs after the completion transaction on a best-effort basis and leaves the committed scan status unchanged.

`--no-adaptive` disables low-yield stopping and uses the configured recursion ceilings, while ranking, time limits, concurrency bounds, and DNS rate safeguards remain active. `--active-max-runtime 0` disables only the active DNS time bound, `--dns-rate-limit 0` disables the DNS rate cap, and `--max-runtime 0` disables the per-domain global time limit. The default `deep` profile keeps a 120-second active budget.
