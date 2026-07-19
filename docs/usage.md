# Usage

Fellaga accepts one or more authorized domains and runs a bounded discovery and validation pipeline. The default `deep` profile aims for broad coverage while enforcing resource limits and stopping low-yield candidate waves.

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
| `deep` | Broad, adaptive discovery; the default. | Up to 1,000,000 primary brute-force words, 120-second shared active-candidate budget, depth 5, 10 pipeline rounds, 100,000 pipeline events. |
| `balanced` | Faster routine reconnaissance. | 5,000 primary brute-force words, 45-second shared active-candidate budget, depth 3, 2 pipeline rounds, 5,000 pipeline events. |
| `passive` | Provider and CT collection with DNS validation but without AXFR, brute force, Web/TLS/DNS-graph/NSEC enrichment, or the event pipeline. | No brute-force candidates; depth 1. |
| `turbo` | Broad candidate generation with less enrichment depth than `deep`. | Up to 1,000,000 primary brute-force words, 60-second shared active-candidate budget, depth 3, 4 pipeline rounds, 250,000 pipeline events. |

The table lists per-stage limits. Seed queues, recursive candidates, mutations, and pipeline events are additional bounded inputs. Adaptive mode ranks candidates and stops low-yield waves early.

Fellaga streams the embedded corpus through two persistent queues while DNS validation runs: a seed queue for passive, CT, AXFR, cached, and learned observations, and an active queue for wordlists, mutations, learned patterns, and corpus entries. Bounded interleaved waves prioritize useful seeds; when both queues contain work, the first wave reserves about three quarters of its slots for seeds.

Low-yield adaptive stopping applies to active candidate waves. Later adaptive waves are limited to 1,000 names and must sustain a minimum yield. The profile-specific `--active-max-runtime` clock covers wildcard profiling and active candidate work. Embedded and user wordlists, mutations, retries, resumed active work, and recursive candidate generation all consume the same budget. When the deadline is reached, Fellaga commits every completed DNS outcome, records unfinished names as indeterminate, and keeps them queued under the existing three-attempt limit. Continue the checkpoint with `--resume latest`.

`--passive-only` skips brute-force generation but keeps active enrichment enabled. `--profile passive` disables AXFR and active Web, TLS, graph, NSEC, PTR, and pipeline stages. It still performs provider HTTP requests, CT collection, wildcard probes, and DNS validation.

For provider-only collection without direct target contact, combine the passive profile with `--no-target-contact`:

```bash
fellaga scan your-domain.example --profile passive --no-target-contact --show
```

This mode queries only third-party passive-provider APIs. CT names remain available through provider connectors such as crt.sh and Cert Spotter, but the direct CT-log indexer is disabled because a public log endpoint can be hosted under the target's own domain. It issues no target DNS requests and performs no target HTTP, TLS, AXFR, wildcard probes, or other direct target connections. Every returned name is reported as `unverified` because live status and wildcard behavior were deliberately not tested. New names are stored as `unverified`; an existing `live` or `historical` inventory entry, its last verification time, and its DNS-record activity are not downgraded by a provider-only observation. The flag is rejected with any profile other than `passive`.

Add `--all-sources` when the purpose is to request every registered name, including experimental providers and duplicate compatibility names:

```bash
fellaga scan your-domain.example --profile passive --no-target-contact --all-sources --show
```

This is broader than the default `deep` selection only because it also runs the four duplicate compatibility names. Missing required credentials are skipped before network contact, while public and optional-key providers may still report runtime authentication, anti-bot, schema, upstream, rate-limit, or timeout failures.

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

## Default safety limits

| Control | Default | Purpose |
| --- | ---: | --- |
| `--domain-concurrency` | `1` | Prevents multiple large targets from multiplying network load; accepted range is 1-4. |
| `--concurrency` | `128` | Limits concurrent host-resolution tasks; the shared rate limit controls DNS traffic. |
| `--dns-rate-limit` | `250` | Caps the shared DNS request rate per second; the safeguard remains active across validation and enrichment. |
| `--network-control` | `adaptive` | Starts below the configured rate/concurrency ceilings, backs off on loss or latency growth, and cautiously increases pressure after healthy windows. Use `fixed` only when a controlled network should use the configured ceilings immediately. |
| `--active-max-runtime` | profile | Bounds all active candidate work; `deep` defaults to 120 seconds and `0` disables the bound. |
| `--max-runtime` | profile | Stops each domain after 600/300/180/300 seconds for `deep`/`balanced`/`passive`/`turbo`. |
| `--checkpoint-every` | `30` | Persists resumable progress every 30 seconds. |
| `--verification-max-age` | `24` | Treats a cached DNS validation as live for 24 hours. |

Passive collection also has profile-specific safeguards: an active-time budget, a global connector concurrency limit, and a child-zone concurrency limit. The default active-time budgets are 45 seconds for `deep`, 25 for `balanced`, 60 for `passive`, and 15 for `turbo`; the global connector concurrency default is 8. Use `--passive-max-runtime`, `--passive-concurrency`, and `--passive-zone-concurrency` to override them. A value of `0` for `--passive-max-runtime` disables only the passive-time safeguard; the per-connector request limits still apply.

NSEC, direct CT collection, and Web/JavaScript discovery have separate cumulative per-target safeguards. `--nsec-max-runtime` defaults to 180/90/60 seconds for `deep`/`balanced`/`turbo`; `--ct-max-runtime` defaults to 30/10/30/5 seconds for `deep`/`balanced`/`passive`/`turbo`; `--web-max-runtime` defaults to 90/45/0/45 seconds. Direct CT-log indexing is opportunistic: it runs in the background while initial discovery proceeds, and an unfinished CT task never delays the first DNS-validation wave. Only one direct CT indexer runs process-wide; a completed global refresh is reused from SQLite for ten minutes. The Web budget is shared by the initial crawl and every later pipeline round. Completed requests, extracted names, and committed cache entries remain available when a budget is reached, and remaining work in that phase is skipped. A value of `0` disables only that total-phase safeguard. Web concurrency is capped at 16 and TLS concurrency at 32 to keep multi-target scans from multiplying connection pressure unexpectedly.

Automatic AXFR uses a four-second timeout per nameserver and a process-wide limit of four concurrent transfers. Wildcard classification starts with three randomized labels. Two additional labels are queried only when the initial sample cannot conclusively classify the zone, limiting routine DNS traffic while retaining the five-probe evidence path for rotating or mixed answers.

`--active-max-runtime 0` disables the active DNS time bound. `--dns-rate-limit 0` disables the DNS rate cap, and `--max-runtime 0` disables the global time limit. `--no-adaptive` disables low-yield stopping and uses the configured recursion ceilings; ranking, the active budget, global deadline, concurrency limits, and DNS rate cap remain enabled. These expert controls can create very high traffic and should be used only in an isolated laboratory or an explicitly authorized environment with suitable resolvers.

If a scan reaches its time limit or is interrupted with Ctrl+C, the latest checkpoint remains available:

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

All states are displayed by default. Restrict a scan, inventory listing, or export to fresh DNS names when required:

```bash
fellaga scan your-domain.example --only-live
fellaga list --domain your-domain.example --only-live
fellaga export --domain your-domain.example --only-live --format csv -o live.csv
```

Use `--refresh-cache` to force network refresh during a scan, or revalidate the existing inventory directly:

```bash
fellaga refresh your-domain.example
```

Refresh stops after five minutes by default and commits validation results in bounded batches. Its progress total includes retained inventory and positive cache-only names, so the final cache pass remains visible. Exact wildcard matches are staged in SQLite and a root-scoped quarantine is applied only after a complete refresh with fresh trusted-resolver consensus. Ambiguous supersets and indeterminate profiles remain retained as `unverified`; provenance and validation history are never deleted. Progress is written to stderr; use `--quiet` to suppress it. Use `--max-runtime 0` to remove the global limit or `--batch-size` to select a batch size from 1 to 4096. On timeout or Ctrl+C, completed validation batches remain committed, unprocessed and indeterminate names retain their state, staged wildcard changes are rolled back, and the non-resumable checkpoint is closed safely.

## Output formats

```bash
# Human-readable streaming output
fellaga scan your-domain.example

# Final raw FQDN list, sorted and deduplicated
fellaga scan your-domain.example --show > subdomains.txt

# Final raw list restricted to live non-wildcard names
fellaga scan your-domain.example --show --only-live > live-subdomains.txt

# One final JSON document
fellaga scan your-domain.example --json > result.json

# One compact result object per domain
fellaga scan --targets-file authorized-domains.txt --jsonl > results.jsonl

# One finding event as soon as it is validated
fellaga scan your-domain.example --stream-jsonl > findings.jsonl

# Final live-only events after each domain completes wildcard classification
fellaga scan your-domain.example --stream-jsonl --only-live > live-findings.jsonl
```

Progress is written to standard error. Machine-readable output stays on standard output. `--show` suppresses progress and the human summary, waits for final wildcard classification, then writes one sorted and deduplicated FQDN per line. It includes every retained state by default; combine it with `--only-live` for final live non-wildcard names only. `--show` is mutually exclusive with `--json`, `--jsonl`, and `--stream-jsonl`. `--quiet` disables progress messages, and `--output` or `--output-dir` writes scan results to files.

Long operations emit periodic heartbeats rather than leaving the terminal apparently frozen. Passive heartbeats report completed, active, and remaining sources plus the active-time budget. DNS-validation heartbeats report completed work, and the enrichment phases periodically report how long their current bounded operation has been running.

Normally, `--stream-jsonl` emits an event immediately and does not add a final domain record. With `--only-live`, Fellaga defers those events until each domain has completed its final wildcard classification, ensuring that the stream contains only final `live` non-wildcard findings.

The public `Finding` object includes `fqdn`, DNS `records`, `sources`, `wildcard`, `from_cache`, `confidence`, `state`, `last_verified_at`, `evidence_families`, `authoritative_validation`, `wildcard_verdict`, `owner_proofs`, `generation_path`, and `discovery_score`. The final domain object includes `phase_timings` plus `scheduler_metrics`, which reports the logical `dns_queries` observed across the primary and trusted engines, directly measured metadata/Web request and body costs, TLS/TCP attempts, exclusive discoveries, adaptive backoffs, effective rate bounds, the remaining-yield upper bound, and the stop reason. A logical DNS query can still require a UDP retry or TCP fallback; use the controlled resolver benchmark when measuring raw transport throughput.

Standardized metadata discovery is enabled for active profiles. `--metadata-discovery auto` checks the apex and a small priority set of validated identity/API/mail hosts, `all` permits every selected validated Web host within the same request budget, and `off` disables the phase. `--no-web` also disables this target-facing HTTP phase. Metadata hosts are resolved through Fellaga's configured consensus engine with bounded concurrency, pinned to public addresses, and restricted to HTTPS port 443 with bounded redirects and response bodies. DNS pinning and all metadata HTTP work share the remaining Web-phase budget and an additional 30-second hard cap; observations completed before the deadline are retained.

## Sources and resolvers

Inspect configured sources without starting a scan:

```bash
fellaga sources
fellaga sources --json
fellaga sources --check --target your-domain.example
```

Use `--passive-sources` for an explicit comma-separated allowlist and `--exclude-sources` to remove providers. The registry currently exposes 67 connector names: 57 canonical provider integrations, five Fellaga-native connectors, and five compatibility names. This is implementation coverage, not a provider-availability claim.

`--all-sources` includes every available registered connector. A retired or otherwise unavailable entry remains visible through `fellaga sources` and `sources --check`, but is never contacted. A connector whose required credential is absent is skipped during local preflight without making a network request; `sources --check` reports that condition as `skipped_missing_key`. Scans retain permanent cached observations from skipped connectors. Experimental sources can return explicit runtime failures, and compatibility names duplicate a canonical provider request. Use an explicit allowlist for minimum traffic and `--all-sources` for diagnostics or a symmetric all-source benchmark policy.

Provider environment aliases, composite credential formats, and connector-specific pagination or stream ceilings are documented in [Passive sources and credentials](sources.md). Those page ceilings are hard safety bounds; each connector also obeys the shorter remaining passive-phase and per-source wall deadlines.

Initial passive collection and AXFR checks run concurrently, while the direct CT-log monitor runs as an opportunistic background task. DNS validation can begin without waiting for unfinished raw CT indexing. The passive budget is charged only for elapsed passive phases, not for CT, AXFR, DNS validation, or other unrelated work. Each connector receives a deadline bounded by the remaining phase budget. If a paginated connector returns valid pages and then times out, Fellaga saves the names already collected, marks the source result as partial/degraded, and reports the condition in progress output and scan warnings.

Test resolver behavior before intensive work:

```bash
fellaga resolvers test --help
```

The resolver test reports whether each candidate passes NXDOMAIN, DNSSEC, and answer-consistency checks, together with observed latency. Resolver selection remains explicit: pass accepted addresses through `--resolvers` and `--trusted-resolvers`.

## Inventory commands

| Command | Purpose |
| --- | --- |
| `fellaga list` | List the retained inventory, optionally by domain or live state. |
| `fellaga explain <fqdn>` | Show retained evidence, state, validation records, DNS records, scan history, and stored confidence metadata. |
| `fellaga history` | Show recent scan runs. |
| `fellaga stats` | Show local cache and learning statistics. |
| `fellaga knowledge` | Show high-yield words and patterns learned locally. |
| `fellaga refresh <domain>` | Revalidate known names without erasing history. |
| `fellaga import` | Import JSON, JSONL, plain-text, or DNS-text data as unverified observations. |
| `fellaga export` | Export retained inventory as JSONL or CSV. |
| `fellaga cache prune` | Remove expired negative DNS cache entries and abandoned temporary candidate queues. |

Run `fellaga <command> --help` for the authoritative option list for the installed version.
