# Discovery engine

Fellaga separates discovery from validation. A provider response, certificate name, archive URL, mutation, or learned word becomes a candidate; it does not automatically become a live finding. Candidates are normalized, scoped, deduplicated, prioritized, and then validated through the DNS engine.

## Discovery stages

1. Load permanent local observations and learned candidate priorities.
2. Query selected passive providers and incrementally read Certificate Transparency data.
3. Detect wildcard behavior for the target and relevant child zones.
4. Validate prioritized candidates in persistent SQLite-backed waves.
5. Attempt strict AXFR, inspect the DNS graph, and detect walkable NSEC zones.
6. Extract in-scope names from Web content, JavaScript, source maps, archives, TLS certificates, and STARTTLS endpoints.
7. Feed new evidence back into the bounded event pipeline for recursive validation and enrichment.
8. Store normalized evidence, validation events, graph edges, source health, and learning statistics locally.

The `passive` profile disables stages that directly contact target application services or authoritative servers for enrichment, but passive-provider requests, CT collection, wildcard probes, and DNS validation still use the network.

## Discovery methods

| Method | Behavior |
| --- | --- |
| Passive connectors | Queries a registry of public and credentialed services with per-provider rate limits, bounded responses, retry policy, and permanent merged observations. |
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

## Wildcard detection and cleanup

Fellaga tests five randomized labels per relevant zone. Three or more positive probes classify the zone as wildcard; three or more definitive NXDOMAIN responses with no positive probe classify it as normal; mixed or incomplete evidence remains indeterminate. The wildcard signature is the union of record values returned by the positive probes, allowing later candidates to be matched against rotating answer pools.

Wildcard profiles are reused for six hours by default. After that window, Fellaga revalidates the zone, including a SOA query and a new set of randomized probes. Set `--wildcard-refresh-hours 0` to force refresh on every scan.

A candidate that matches the wildcard signature is removed when it is supported only by weak DNS observations. Strong independent evidence, such as a complete AXFR, authoritative DNSSEC evidence, CT or presented-certificate evidence, can retain the name while marking it as wildcard-related. The cleanup path also removes orphaned positive cache records created solely by rejected wildcard observations; unrelated historical evidence is preserved.

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
- bounded AXFR, CT, NSEC, Web, TLS, graph, PTR, and pipeline work;
- adaptive candidate waves that stop after insufficient yield;
- SQLite-backed batches so millions of candidates do not need to remain in memory;
- a persistent checkpoint every 30 seconds.

`--no-adaptive`, `--dns-rate-limit 0`, and `--max-runtime 0` deliberately remove important safeguards. They are not required for the default deep scan.
