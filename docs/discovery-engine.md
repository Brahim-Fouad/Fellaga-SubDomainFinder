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

The scheduler claims small batches atomically, marks them as processing, and records the number of attempts. The first adaptive batch contains up to 500 names, the second up to 1,500, and subsequent batches up to 5,000. When both queues have work, seed candidates receive most of each wave while active discovery continues alongside them. Queue rows and generator feed cursors remain in SQLite across an interruption.

A transient DNS error requeues a claimed name until it reaches three total attempts. Definitive negative and validated positive outcomes are terminal. `--resume` also requeues rows that were left in the processing state by an interrupted process. Attempt and success counters are persisted independently from disposable queue rows so final learning remains accurate and is applied once.

Active generation is lazy: the one-million-name corpus is traversed with a durable priority cursor instead of being materialized before DNS begins. A user wordlist uses a durable byte cursor and bounded pages of at most 1,024 lines or 4 MiB. Non-UTF-8 input and oversized lines cannot create an unbounded read. Adaptive low-yield stopping can stop generated corpus expansion, but it does not abandon an unfinished explicit wordlist, pending seed work, or bounded retries.

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

By default, Fellaga uses `1.1.1.1`, `8.8.8.8`, and `9.9.9.9` for both pools and shares the global DNS rate limit across validation work. Trusted-resolver consensus and authoritative checks reduce false live results caused by poisoned caches, inconsistent resolvers, or wildcard DNS.

Trusted validation uses bounded concurrency after the primary batch, and both stages share the configured DNS rate limit. Long validation batches emit progress heartbeats independently from individual resolver completion, so delayed responses remain visible without changing their timeout semantics.

TLS and Web hostname pinning reuse the same configured DNS engine and shared rate limiter. They do not start a separate system resolver or bypass `--resolvers`; Web targets are still filtered to public IP addresses before requests are sent.

## Wildcard detection and cleanup

Fellaga tests five randomized labels per relevant zone. Three or more positive probes classify the zone as wildcard; three or more definitive NXDOMAIN responses with no positive probe classify it as normal; mixed or incomplete evidence remains indeterminate. The wildcard signature is the union of record values returned by the positive probes, allowing later candidates to be matched against rotating answer pools.

Wildcard profiles are reused for six hours by default. After that window, Fellaga revalidates the zone, including a SOA query and a new set of randomized probes. Set `--wildcard-refresh-hours 0` to force refresh on every scan.

A candidate whose answer exactly matches the applicable wildcard signature is excluded from default scan output, even when CT, passive, Web, or TLS discovery also supplied the name. This avoids presenting a discovered label as live when DNS cannot distinguish it from a synthesized wildcard response. A positive answer with records distinct from the wildcard pool remains eligible for validation and enrichment.

For permanent storage, Fellaga purges weak wildcard-only observations and their orphaned positive cache records. Independent evidence is not destroyed: the name remains in the local inventory with wildcard context and is not emitted as a normal live result. Indeterminate wildcard zones are handled conservatively as unverified unless independent rules can establish an authoritative result.

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
- 128 concurrent DNS requests;
- a 1,800-second limit per target;
- bounded response sizes and per-provider timeouts;
- a profile-specific passive active-time budget shared across root and recursive passive phases;
- a global passive connector semaphore shared by root and child zones;
- bounded AXFR, CT, NSEC, Web, TLS, graph, PTR, and pipeline work;
- adaptive candidate waves that stop after insufficient yield;
- persistent lazy SQLite-backed seed and active batches so millions of candidates do not need to remain in memory or be inserted before validation begins;
- a persistent checkpoint every 30 seconds.

The passive budget advances only while passive work is running; time spent waiting for concurrent CT/AXFR completion or later non-passive phases is not charged to it. A connector that times out after returning one or more complete pages contributes those names as a partial result and is reported as degraded. Periodic heartbeats cover passive collection, DNS validation, and long enrichment phases.

Scan completion and learning are committed atomically. Prepared SQLite statements are reused for large word and pattern updates, and queue-selection indexes support bounded claims. Queue cleanup runs after the completion transaction on a best-effort basis and leaves the committed scan status unchanged.

`--no-adaptive`, `--dns-rate-limit 0`, and `--max-runtime 0` disable important safeguards. The default deep profile keeps all three enabled.
