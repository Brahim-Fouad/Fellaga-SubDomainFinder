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
| `deep` | Broad, adaptive discovery; the default. | Up to 1,000,000 initial candidates, depth 5, 10 pipeline rounds, 100,000 pipeline events. |
| `balanced` | Faster routine reconnaissance. | 5,000 initial candidates, depth 3, 2 pipeline rounds, 5,000 pipeline events. |
| `passive` | Provider and CT collection with DNS validation but without AXFR, brute force, Web/TLS/DNS-graph/NSEC enrichment, or the event pipeline. | No brute-force candidates; depth 1. |
| `turbo` | Broad candidate generation with less enrichment depth than `deep`. | Up to 1,000,000 initial candidates, depth 3, 4 pipeline rounds, 250,000 pipeline events. |

The table lists upper bounds. Adaptive mode ranks candidates and stops low-yield waves early.

Fellaga streams the embedded corpus through two persistent queues while DNS validation runs: a seed queue for passive, CT, AXFR, cached, and learned observations, and an active queue for wordlists, mutations, learned patterns, and corpus entries. Bounded interleaved waves prioritize useful seeds; when both queues contain work, the first wave reserves about three quarters of its slots for seeds.

Low-yield adaptive stopping applies to generated active candidates. Fellaga still drains the bounded seed queue, retries transiently failed queued names, and continues an explicit `--wordlist` until its durable cursor reaches the end or another configured hard limit stops the scan.

`--passive-only` skips brute-force generation but keeps active enrichment enabled. `--profile passive` disables AXFR and active Web, TLS, graph, NSEC, PTR, and pipeline stages. It still performs provider HTTP requests, CT collection, wildcard probes, and DNS validation.

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
| `--concurrency` | `128` | Limits in-flight DNS work. |
| `--dns-rate-limit` | `100` | Caps the shared DNS request rate per second. |
| `--max-runtime` | `1800` | Stops each domain after 30 minutes. |
| `--checkpoint-every` | `30` | Persists resumable progress every 30 seconds. |
| `--verification-max-age` | `24` | Treats a cached DNS validation as live for 24 hours. |

Passive collection also has profile-specific safeguards: an active-time budget, a global connector concurrency limit, and a child-zone concurrency limit. The default active-time budgets are 75 seconds for `deep`, 45 for `balanced`, 90 for `passive`, and 30 for `turbo`; the global connector concurrency default is 8. Use `--passive-max-runtime`, `--passive-concurrency`, and `--passive-zone-concurrency` to override them. A value of `0` for `--passive-max-runtime` disables only the passive-time safeguard; the per-connector request limits still apply.

NSEC and direct CT collection have separate cumulative per-target safeguards. `--nsec-max-runtime` defaults to 180/90/60 seconds for `deep`/`balanced`/`turbo`; `--ct-max-runtime` defaults to 90/30/90/20 seconds for `deep`/`balanced`/`passive`/`turbo`. Partial results and committed cache batches are retained when either budget is reached. A value of `0` disables only that total-phase safeguard. Web concurrency is capped at 16 and TLS concurrency at 32 to keep multi-target scans from multiplying connection pressure unexpectedly.

`--dns-rate-limit 0` disables the DNS rate cap, and `--max-runtime 0` disables the global time limit. `--no-adaptive` asks Fellaga to exhaust configured candidate waves. These expert controls can create very high traffic and should be used only in an isolated laboratory or an explicitly authorized environment with suitable resolvers.

If a scan reaches its time limit or is interrupted with Ctrl+C, the latest checkpoint remains available:

```bash
fellaga scan your-domain.example --resume latest
```

Resume restores the two candidate queues, feed cursors, merged seed provenance, attempt counts, and durable learning counters. Transient DNS failures are attempted no more than three times in total, including attempts made before an interruption. A definitive negative answer is terminal for that queue item. Previously validated positive cache entries are reclassified through the normal wildcard and freshness rules instead of being downgraded merely because the scan restarted.

### Large wordlists

User wordlists are read lazily, without holding the SQLite write lock during file I/O. Each read page examines at most 1,024 lines or 4 MiB, whichever comes first. Invalid names are skipped, non-UTF-8 bytes are decoded safely, and an oversized line is discarded in bounded chunks. The byte cursor and oversized-line state are stored in SQLite, so `--resume` continues from the committed position rather than rereading the file from the beginning.

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

Refresh stops after five minutes by default and commits validation results in 256-name batches. Wildcard matches are staged in SQLite and the final purge is applied in one cancellable transaction. Progress is written to stderr; use `--quiet` to suppress it. Use `--max-runtime 0` to remove the global limit or `--batch-size` to select a batch size from 1 to 4096. On timeout or Ctrl+C, completed validation batches remain committed, unprocessed and indeterminate names retain their state, destructive wildcard cleanup is rolled back, and the non-resumable checkpoint is closed safely.

## Output formats

```bash
# Human-readable streaming output
fellaga scan your-domain.example

# One final JSON document
fellaga scan your-domain.example --json > result.json

# One compact result object per domain
fellaga scan --targets-file authorized-domains.txt --jsonl > results.jsonl

# One finding event as soon as it is validated
fellaga scan your-domain.example --stream-jsonl > findings.jsonl

# Final live-only events after each domain completes wildcard classification
fellaga scan your-domain.example --stream-jsonl --only-live > live-findings.jsonl
```

Progress is written to standard error. Machine-readable output stays on standard output. `--quiet` disables progress messages, and `--output` or `--output-dir` writes scan results to files.

Long operations emit periodic heartbeats rather than leaving the terminal apparently frozen. Passive heartbeats report completed, active, and remaining sources plus the active-time budget. DNS-validation heartbeats report completed work, and the enrichment phases periodically report how long their current bounded operation has been running.

Normally, `--stream-jsonl` emits an event immediately and does not add a final domain record. With `--only-live`, Fellaga defers those events until each domain has completed its final wildcard classification, ensuring that the stream contains only final `live` non-wildcard findings.

The public `Finding` object includes `fqdn`, DNS `records`, `sources`, `wildcard`, `from_cache`, `confidence`, `state`, `last_verified_at`, `evidence_families`, and `authoritative_validation`.

## Sources and resolvers

Inspect configured sources without starting a scan:

```bash
fellaga sources
fellaga sources --json
fellaga sources --check --target your-domain.example
```

Use `--passive-sources` for an explicit comma-separated allowlist and `--exclude-sources` to remove providers. `--all-sources` also attempts connectors whose required credentials are missing and therefore normally creates predictable configuration errors; it is mainly a connector-diagnostic option.

The initial passive phase, direct CT-log monitor, and AXFR checks run concurrently. The passive budget is charged only for elapsed passive phases, not for CT, AXFR, DNS validation, or other unrelated work. If a paginated connector returns valid pages and then times out, Fellaga saves the names already collected, marks the source result as partial/degraded, and reports the condition in progress output and scan warnings.

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
| `fellaga import` | Import Subfinder, Amass, BBOT, or massdns data as unverified observations. |
| `fellaga export` | Export retained inventory as JSONL or CSV. |
| `fellaga cache prune` | Remove only cache entries that are defined as expired. |

Run `fellaga <command> --help` for the authoritative option list for the installed version.
