# Usage

Fellaga accepts one or more authorized domains and runs a persistent discovery and validation pipeline. The default `deep` profile aims for broad coverage, has no cumulative runtime deadline, and stops when its finite work queues drain or adaptive candidate generation converges.

## Targets

Pass domains directly, load one domain per line from a file, or read standard input:

```bash
fellaga scan a.example b.example
fellaga scan --targets-file authorized-domains.txt
printf '%s\n' a.example b.example | fellaga scan -
```

Blank lines and text after `#` are ignored in target files. Targets are normalized and deduplicated before scanning.

## Scan profiles

```bash
fellaga scan your-domain.example --profile deep
```

| Profile | Intended use | Main limits |
| --- | --- | --- |
| `deep` | Broad, adaptive discovery; the default. | Up to 1,000,000 primary brute-force words, depth 5, 10 pipeline rounds, no global event ceiling. |
| `balanced` | Smaller routine reconnaissance. | 5,000 primary brute-force words, depth 3, 2 pipeline rounds, no global event ceiling. |
| `passive` | Provider and CT collection with DNS validation but without AXFR, brute force, Web/TLS/DNS-graph/NSEC enrichment, or the event pipeline. | No brute-force candidates; depth 1. |
| `turbo` | Broad candidate generation with less enrichment depth than `deep`. | Up to 1,000,000 primary brute-force words, depth 3, 4 pipeline rounds, no global event ceiling. |

The table lists structural per-stage limits. Seed queues and recursive candidates are persisted in bounded SQLite pages; the deduplicated event queue has no global event ceiling by default. A positive `--pipeline-limit` is an explicit ceiling; the former `--pipeline-budget` spelling remains a hidden compatibility alias. Adaptive mode ranks candidates and stops statistically exhausted candidate waves early.

Fellaga streams the embedded corpus through two persistent queues while DNS validation runs: a seed queue for passive, CT, AXFR, cached, and learned observations, and an active queue for wordlists, mutations, learned patterns, and corpus entries. Bounded interleaved waves prioritize useful seeds; when both queues contain work, the first wave reserves about three quarters of its slots for seeds.

Low-yield adaptive stopping applies to active candidate waves. Later adaptive waves are limited to 1,000 names and must sustain a minimum yield. This convergence rule is based on observed marginal discoveries, not elapsed time. `--active-max-runtime` defaults to `0`; setting a positive value opts into a shared wall-clock deadline for wildcard profiling and active candidate work. When an explicit deadline is reached, Fellaga commits completed DNS outcomes and keeps unfinished names queued for `--resume latest`.

`--passive-only` skips brute-force generation but keeps active enrichment enabled. `--profile passive` disables AXFR and active Web, TLS, graph, NSEC, PTR, and pipeline stages. It still performs provider HTTP requests, CT collection, wildcard probes, and DNS validation.

For provider-only collection without direct target contact, combine the passive profile with `--no-target-contact`:

```bash
fellaga scan your-domain.example --profile passive --no-target-contact --show --include-non-live
```

This mode queries only third-party passive-provider APIs. CT names remain available through provider connectors such as crt.sh and Cert Spotter, but the direct CT-log indexer is disabled because a public log endpoint can be hosted under the target's own domain. It issues no target DNS requests and performs no target HTTP, TLS, AXFR, wildcard probes, or other direct target connections. Every returned name is reported as `unverified` because live status and wildcard behavior were deliberately not tested. New names are stored as `unverified`; an existing `live` or `historical` inventory entry, its last verification time, and its DNS-record activity are not downgraded by a provider-only observation. The flag is rejected with any profile other than `passive`.

Add `--all-sources` to select every unique source implementation, including experimental providers:

```bash
fellaga scan your-domain.example --profile passive --no-target-contact --all-sources --show --include-non-live
```

Each canonical or Fellaga-native implementation is selected once. Compatibility aliases remain explicitly selectable through `--passive-sources`, but `--all-sources` does not execute them a second time beside their canonical implementation. Missing required credentials are skipped before network contact, while public and optional-key providers may still report runtime authentication, anti-bot, schema, upstream, rate-limit, or timeout failures.

## Custom mutation rules

Pass a mutation DSL file with `--mutations`. Blank lines and text after `#` are ignored. A rule is `score:name:pattern`; a line containing only a pattern receives a default score and an automatically generated rule name.

```text
# custom-mutations.txt
720:service-environment:{{word}}-{{env}}.{{parent}}
680:regional-api:api-{{region}}.{{parent}}
640:numbered-service:{{word}}-{{n}}.{{parent}}
```

Supported placeholders are `{{word}}`, `{{parent}}`, `{{env}}`, `{{region}}`, `{{cloud}}`, and `{{n}}`. Number expansion covers 0 through 20; environment, region, and cloud values use Fellaga's built-in controlled lists.

```bash
fellaga scan your-domain.example --mutations custom-mutations.txt
```

## Execution controls

| Control | Default | Purpose |
| --- | ---: | --- |
| `--domain-concurrency` | `1` | Prevents multiple large targets from multiplying network load; accepted range is 1-4. |
| `--concurrency` | `128` | Limits concurrent host-resolution tasks; the shared rate limit controls DNS traffic. |
| `--dns-rate-limit` | `250` | Caps the shared DNS request rate per second; the safeguard remains active across validation and enrichment. |
| `--network-control` | `adaptive` | Starts below the configured rate/concurrency ceilings, backs off on loss or latency growth, and cautiously increases pressure after healthy windows. Use `fixed` only when a controlled network should use the configured ceilings immediately. |
| `--active-max-runtime` | `0` | Optional cumulative deadline for active candidate work; `0` lets the queue run to convergence. |
| `--max-runtime` | `0` | Optional cumulative deadline for each domain; `0` lets the complete scan finish. |
| `--checkpoint-every` | `30` | Persists resumable progress every 30 seconds. |
| `--verification-max-age` | `24` | Treats a cached DNS validation as live for 24 hours. |
| `--internetdb-ips` | profile | Limits the single Shodan InternetDB wave to 16/8/disabled/4 confirmed public IP addresses for `deep`/`balanced`/`passive`/`turbo`; accepted override range is 1-64. |
| `--internetdb-max-runtime` | `0` | Optional cumulative InternetDB deadline; positive values up to 60 seconds opt into one. |
| `--internetdb-refresh-hours` | `24` | Refreshes a successful IP-to-hostname cache entry after 24 hours without deleting permanent observations. |

Passive collection has no cumulative deadline by default. `--passive-concurrency` controls the process-wide connector concurrency and accepts values from 1 through 32; `--passive-zone-concurrency` controls recursive child-zone work. `--passive-max-runtime` accepts a positive opt-in deadline. Each HTTP request still has its own timeout, and pagination, response-size, and working-set limits remain finite.

NSEC, direct CT collection, and Web/JavaScript discovery likewise default to `0` for their cumulative runtime options. Direct CT indexing runs in the background while the first DNS wave begins; before finalization, an unlimited scan waits for the configured finite log and entry set to complete. Only one direct CT indexer runs process-wide, and a completed global refresh is reused from SQLite for ten minutes. `--nsec-max-runtime`, `--ct-max-runtime`, and `--web-max-runtime` accept positive opt-in deadlines. Web concurrency is capped at 16 and TLS concurrency at 32, and every network operation keeps a per-request timeout.

Automatic AXFR uses a four-second timeout per nameserver and a process-wide limit of four concurrent transfers. Wildcard classification starts with three randomized labels. Two additional labels are queried only when the initial sample cannot conclusively classify the zone, limiting routine DNS traffic while retaining the five-probe evidence path for rotating or mixed answers. PTR enrichment shares an active-DNS deadline only when the user configured one.

Active profiles perform one finite Shodan InternetDB wave after DNS validation. Only public IP addresses from current strict, non-wildcard answers are eligible; Fellaga does not enumerate an address range. The provider cadence is limited to one request per second, each request has at most five seconds, at most 256 hostnames are accepted per IP, and at most 2,000 names are accepted for the phase. Results are suffix-filtered, stored permanently in the local IP-to-hostname cache, and re-enter the ordinary wildcard-aware DNS validation pipeline. `--no-internetdb` disables the pivot; `--internetdb-ips`, `--internetdb-max-runtime`, and `--internetdb-refresh-hours` tune its limits and successful-cache refresh interval. The `passive` profile disables it.

All cumulative scan and phase runtime controls default to `0`. Positive values opt into elapsed-time cutoffs. `--dns-rate-limit 0` separately disables the DNS rate cap. `--no-adaptive` disables low-yield convergence and uses the configured recursion ceilings; structural candidate limits, concurrency controls, per-request timeouts, and the DNS rate cap remain enabled. These expert controls can create very high traffic and should be used only in an isolated laboratory or an explicitly authorized environment with suitable resolvers.

If a user-configured deadline is reached or the scan is interrupted with Ctrl+C, the latest checkpoint remains available:

```bash
fellaga scan your-domain.example --resume latest
```

`--resume latest` restores the two candidate queues, feed cursors, merged seed provenance, attempt counts, and durable learning counters. It also reconciles passive state: complete fresh connector results come directly from SQLite, while a connector cancelled during pagination remains stale and is retried. This prevents an existing DNS candidate queue from hiding unfinished passive work. Transient DNS failures are attempted no more than three times in total, including packets sent before an interruption. Work cancelled while waiting for rate, concurrency, or socket admission remains queued without consuming an attempt; cancellation after a send remains charged as traffic but does not count as a resolver failure. A definitive negative answer is terminal for that queue item. Previously validated positive cache entries are reclassified through the normal wildcard and freshness rules instead of being downgraded merely because the scan restarted.

### Large wordlists

User wordlists are read lazily, without holding the SQLite write lock during file I/O. Each read page follows the requested scheduler batch and is capped at 16,384 lines or 4 MiB, whichever comes first. Invalid names are skipped, non-UTF-8 bytes are decoded safely, and an oversized line is discarded in bounded chunks. The byte cursor and oversized-line state are stored in SQLite, so `--resume latest` continues from the committed position rather than rereading the file from the beginning.

```bash
fellaga scan your-domain.example --wordlist candidates.txt --resume latest
```

## Freshness and output states

Fellaga retains observations permanently but does not present every old positive response as currently live:

- `live`: DNS validation is within `--verification-max-age` or succeeded during the current scan.
- `historical`: the name was validated in the past but is no longer fresh.
- `unverified`: a passive or imported observation lacks DNS confirmation, or a positive answer remains ambiguous because it matches a confirmed or indeterminate wildcard profile.

Normal human output, `--show`, text files, final JSON/JSONL, streaming JSONL, and `fellaga list` display only final live, non-wildcard names by default. Historical and unverified observations remain in SQLite and are available explicitly. Wildcard-quarantined names remain hidden from `fellaga list`, including with `--all`, but their evidence and quarantine history remain available through `fellaga explain`:

```bash
fellaga scan your-domain.example --include-non-live
fellaga list --domain your-domain.example --all
fellaga export --domain your-domain.example --only-live --format csv -o live.csv
```

All final output formats are live and non-wildcard by default. Add `--include-non-live` for retained historical or unverified findings, or `--include-wildcard` when wildcard-marked candidates are explicitly wanted. `--only-live` remains available to state the default filtering policy explicitly in automation. A name whose latest decisive validation is negative is not merged back into current scan output, but its evidence stays available through `fellaga explain`.

Use `--refresh-cache` to force network refresh during a scan, or revalidate the existing inventory directly:

```bash
fellaga refresh your-domain.example
```

Refresh has no cumulative deadline by default and commits validation results in bounded batches. Its progress total includes retained inventory and positive cache-only names, so the final cache pass remains visible. Exact wildcard matches are staged in SQLite and a root-scoped quarantine is applied only after a complete refresh with fresh trusted-resolver consensus. Ambiguous supersets and indeterminate profiles remain retained as `unverified`; provenance and validation history are never deleted. Progress is written to stderr; use `--quiet` to suppress it. A positive `--max-runtime` opts into a global deadline, while `--batch-size` selects a batch size from 1 to 4096. On an explicit timeout or Ctrl+C, completed validation batches remain committed, unprocessed and indeterminate names retain their state, staged wildcard changes are rolled back, and the non-resumable checkpoint is closed safely.

## Output formats

```bash
# Human-readable final findings with live phase progress
fellaga scan your-domain.example

# Final live, non-wildcard FQDN list, sorted and deduplicated
fellaga scan your-domain.example --show > subdomains.txt

# Include retained historical and unverified names explicitly
fellaga scan your-domain.example --show --include-non-live > retained-subdomains.txt

# One final JSON document
fellaga scan your-domain.example --json > result.json

# One compact result object per domain
fellaga scan --targets-file authorized-domains.txt --jsonl > results.jsonl

# Finalized finding events after each domain completes classification
fellaga scan your-domain.example --stream-jsonl > findings.jsonl

# Final live-only events after each domain completes wildcard classification
fellaga scan your-domain.example --stream-jsonl --only-live > live-findings.jsonl
```

Progress is written to standard error. Machine-readable output stays on standard output. On an interactive terminal, Fellaga uses compact phase badges and one updating DNS progress line; redirected output switches to plain, throttled records. The default view suppresses individual provider failures and prints one aggregate count. Use `-v` for deduplicated warning details in the final summary plus degraded, skipped, or partial-source progress, and `-vv` for every source status. FQDNs and DNS records wrap without truncation. Diagnostics are sanitized and wrapped, while oversized provider response bodies are summarized instead of dumped into the terminal. ANSI controls, bidirectional controls, and external HTML error bodies are removed before terminal rendering. Set `NO_COLOR=1` or `TERM=dumb` to disable styling. `--quiet` disables the complete human renderer, including final findings, progress, and the summary.

`--show` suppresses the human summary, waits for final wildcard classification, then writes one sorted and deduplicated live, non-wildcard FQDN per line. Add `--include-non-live` for retained historical and unverified names, `--include-wildcard` for explicitly requested wildcard candidates, or `--quiet` when standard error must also remain silent. `--show` is mutually exclusive with `--json`, `--jsonl`, and `--stream-jsonl`. `--output` or `--output-dir` applies the same live-only default to text files. Raw, JSON, and JSONL data never contains terminal styling.

Long operations emit periodic counters rather than leaving the terminal apparently frozen. Repeated phase heartbeats update in place on interactive terminals and are deduplicated when redirected. Passive heartbeats report completed, active, and remaining sources; DNS-validation heartbeats report completed work. Concurrent multi-target scans prefix progress with the target so events cannot be mistaken for another domain.

`--stream-jsonl` waits for each domain's wildcard and authoritative classification, then emits finalized finding events without adding a final domain record. It is live and non-wildcard by default, so provisional candidates never leak into the stream. Add `--include-non-live` or `--include-wildcard` only when those final classified states are explicitly wanted; `--only-live` makes the default filter explicit.

The public `Finding` object includes `fqdn`, DNS `records`, `sources`, `wildcard`, `from_cache`, `confidence`, `state`, `last_verified_at`, `evidence_families`, `authoritative_validation`, `wildcard_verdict`, `owner_proofs`, `generation_path`, and `discovery_score`. The final domain object includes `phase_timings` plus `scheduler_metrics`, which reports the logical `dns_queries` observed across the primary and trusted engines, directly measured metadata/Web request and body costs, TLS/TCP attempts, exclusive discoveries, adaptive backoffs, effective rate bounds, the remaining-yield upper bound, and the stop reason. A logical DNS query can still require a UDP retry or TCP fallback; use the controlled resolver benchmark when measuring raw transport throughput.

Standardized metadata discovery is enabled for active profiles. `--metadata-discovery auto` checks the apex and a small priority set of validated identity/API/mail hosts, `all` permits every selected validated Web host within the configured request-count ceiling, and `off` disables the phase. `--no-web` also disables this target-facing HTTP phase. Metadata hosts are resolved through Fellaga's configured consensus engine with bounded concurrency, pinned to public addresses, and restricted to HTTPS port 443 with bounded redirects, response bodies, and per-request timeouts. It shares a Web-phase deadline only when the user configured one.

## Sources and resolvers

Inspect configured sources without starting a scan:

```bash
fellaga sources
fellaga sources --json
fellaga sources --check --target your-domain.example
```

Use `--passive-sources` for an explicit comma-separated allowlist and `--exclude-sources` to remove providers. The registry currently exposes 69 connector names: 59 canonical provider integrations, five Fellaga-native connectors, and five compatibility names. Runtime availability and health appear in `fellaga sources` and `fellaga sources --check`.

`--all-sources` selects every unique canonical or Fellaga-native implementation, including experimental entries, once. Compatibility aliases remain available through an explicit `--passive-sources` allowlist but are not added as duplicate requests by `--all-sources`. A retired or otherwise unavailable entry remains visible through `fellaga sources` and `sources --check`, but is never contacted. A connector whose required credential is absent is skipped during local preflight without making a network request; `sources --check` reports that condition as `skipped_missing_key`. Scans retain permanent cached observations from skipped connectors, and experimental sources can still return explicit runtime failures.

Provider environment aliases, composite credential formats, and connector-specific pagination or stream ceilings are documented in [Passive sources and credentials](sources.md). Those ceilings, response-size limits, rate controls, and per-request timeouts remain active without imposing a default cumulative deadline.

The keyless `arquivopt` connector streams domain-matched Arquivo.pt CDX records, while the keyless experimental `shrewdeye` connector streams ShrewdEye's public per-domain feed. Both validate the requested suffix and persist completed batches under strict record, line, response-size, and request-timeout limits.

Initial passive collection and AXFR checks run concurrently, while the direct CT-log monitor runs as a background task. DNS validation can begin without waiting for unfinished raw CT indexing. With the default unlimited cumulative settings, every finite connector workload is allowed to complete; per-request failures do not discard pages already committed. If a paginated connector returns valid pages and a later request fails, Fellaga saves the names already collected and marks the source partial/degraded.

Passive certificate extraction rejects wildcard patterns as host findings instead of removing the `*.` prefix and materializing a false concrete name. Concrete names from the same certificate remain eligible. High-volume THC pagination can issue up to five paced page requests per second under its page and record ceilings. Cancelling the certificate-database connector aborts its pending database connection task instead of leaving detached work.

Test resolver behavior before intensive work:

```bash
fellaga resolvers test --help
```

The resolver test reports whether each candidate passes NXDOMAIN, DNSSEC, and answer-consistency checks, together with observed latency. Resolver selection remains explicit: pass accepted addresses through `--resolvers` and `--trusted-resolvers`.

## Inventory commands

| Command | Purpose |
| --- | --- |
| `fellaga list` | List live non-quarantined inventory by default; add `--all`/`--all-states` for retained historical and unverified non-quarantined rows. |
| `fellaga explain <fqdn>` | Show retained evidence, state, validation records, DNS records, wildcard-quarantine history, scan history, and stored confidence metadata. |
| `fellaga history` | Show recent scan runs. |
| `fellaga stats` | Show local cache and learning statistics. |
| `fellaga knowledge` | Show high-yield words and patterns learned locally. |
| `fellaga refresh <domain>` | Revalidate known names without erasing history. |
| `fellaga import` | Import JSON, JSONL, plain-text, or DNS-text data as unverified observations. |
| `fellaga export` | Export retained inventory as JSONL or CSV. |
| `fellaga cache prune` | Remove expired negative DNS cache entries and abandoned temporary candidate queues. |

Run `fellaga <command> --help` for the authoritative option list for the installed version.
