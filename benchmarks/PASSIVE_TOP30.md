# Passive Tranco top-30 observation

This campaign compares the names returned by passive provider workflows for a
pinned public popularity corpus. It prohibits direct contact with the target
domains. It is separate from the authorized active benchmark and must not be
run through `benchmarks/run.sh`.

The corpus is the first 30 rows of Tranco list `74J5X`, generated on
2026-07-17 from rankings covering 2026-06-18 through 2026-07-17. The permanent
snapshot is <https://tranco-list.eu/list/74J5X/1000000>. Infrastructure domains
are present because Tranco ranks pay-level domains, not only browser-facing
websites.

Being present in a popularity list is not authorization to assess a domain.
This runner therefore has no mode that performs target validation, DNS brute
force, resolver-based enrichment, HTTP probing, or TLS probing. Passive data
providers still observe requests about the named domains; review their terms,
credentials, and rate limits before running the campaign.

This is deliberately a no-key comparison. Every tool run starts from an empty
environment and receives only a fixed `PATH`, locale, UTC timezone, `NO_COLOR`,
and fresh `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, and
`XDG_STATE_HOME`. Credentials, proxy variables, cloud configuration, SSH
agents, netrc settings, existing user configuration, and API keys are neither
read nor copied. The manifest records this allowlist policy.

## Tool policy

The runner recognizes four tools and invokes only these modes:

- Fellaga: `scan --profile passive --no-target-contact --show` with a fresh
  state database for every run. Direct CT-log indexing is disabled; CT names
  can still be returned by third-party provider connectors.
- Subfinder: its passive source workflow with update checks disabled, without
  its active switch or a resolver override.
- Amass: `enum -passive` with an explicit empty configuration file, without a
  resolver override or inherited system credentials.
- BBOT: passive subdomain modules with `dns.disable=true` and
  `speculate=false`.

Before BBOT is admitted, the runner performs a dry-run against the reserved
`example.invalid` name with the exact no-DNS policy. Some BBOT versions reject
DNS-disabled configurations when an enabled module consumes DNS events. A
failed preflight marks BBOT as skipped; the runner never forces the scan and
never relaxes the DNS prohibition. Its preflight uses a separate empty no-key
home with the same XDG isolation.

Fellaga, Subfinder, and Amass must also pass a no-target help preflight proving
that every required safety flag exists. An incompatible binary is skipped
before any listed domain is processed. Subfinder is capped at five HTTP
requests per second, Fellaga at four passive connector tasks, and every tool is
run serially with a one-second cooldown. Amass and BBOT do not expose equivalent
global HTTP controls, so wall times are recorded observations, not comparable
performance measurements.

Tools that are not installed are recorded as missing. The available safe
subset still runs. Executable paths can be pinned with these optional
variables:

- `FELLAGA_PASSIVE_TOP30_FELLAGA_BIN`
- `FELLAGA_PASSIVE_TOP30_SUBFINDER_BIN`
- `FELLAGA_PASSIVE_TOP30_AMASS_BIN`
- `FELLAGA_PASSIVE_TOP30_BBOT_BIN`

## Run

Linux or WSL with Bash and Python 3 is required. The default is one repetition,
a 180-second wall deadline per tool and domain, and a two-hour discovery
campaign deadline.

```bash
python3 benchmarks/passive_top30_report.py verify-source

FELLAGA_PASSIVE_TOP30_OUT=benchmarks/results/passive-top30-74J5X \
  bash benchmarks/run-passive-top30.sh
```

Fellaga and Amass require real POSIX permissions for their isolated private
configuration. When the repository is under `/mnt/c` in WSL, place the output
on the Linux filesystem instead:

```bash
FELLAGA_PASSIVE_TOP30_OUT="$HOME/fellaga-results/passive-top30-74J5X" \
  bash benchmarks/run-passive-top30.sh
```

The runner verifies `chmod` semantics before any listed domain is sent to a
provider and exits with a clear error on an incompatible output filesystem.

Optional controls:

- `FELLAGA_PASSIVE_TOP30_REPETITIONS`: `1` to `10`, default `1`.
- `FELLAGA_PASSIVE_TOP30_TIMEOUT`: per-run wall deadline, default `180`.
- `FELLAGA_PASSIVE_TOP30_TIMEOUT_GRACE`: shutdown grace, default `5`.
- `FELLAGA_PASSIVE_TOP30_PREFLIGHT_TIMEOUT`: help and BBOT safety preflight
  deadline, default `60`. The older
  `FELLAGA_PASSIVE_TOP30_BBOT_PREFLIGHT_TIMEOUT` name remains an alias.
- `FELLAGA_PASSIVE_TOP30_MAX_RUNTIME`: discovery campaign deadline, default
  `7200` seconds.
- `FELLAGA_PASSIVE_TOP30_COOLDOWN`: delay between runs, default `1` second.
- `FELLAGA_PASSIVE_TOP30_FAILURE_THRESHOLD`: consecutive failures before a
  tool circuit breaker opens, default `3`.
- `FELLAGA_PASSIVE_TOP30_SUBFINDER_RATE_LIMIT`: global Subfinder HTTP rate,
  default `5` requests per second.
- `FELLAGA_PASSIVE_TOP30_FELLAGA_CONCURRENCY`: Fellaga passive connector
  concurrency, default `4`.
- `FELLAGA_PASSIVE_TOP30_CLEANUP_TIMEOUT`: final ephemeral-state cleanup
  deadline, default `60` seconds.
- `FELLAGA_PASSIVE_TOP30_REDACTION_TIMEOUT`: final redaction deadline, default
  `60` seconds.
- `FELLAGA_PASSIVE_TOP30_MAX_FILE_BYTES`: per-process regular-file limit,
  default `268435456` bytes.
- `FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_FILES`: cumulative retained-file limit,
  default `50000`.
- `FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_BYTES`: cumulative retained-size limit,
  default `2147483648` bytes (2 GiB).

The output directory must not already exist. It contains a campaign manifest,
per-run timings and normalized names, a JSON-lines run ledger, the BBOT
preflight evidence when applicable, and `report.json`. The manifest records
each runnable executable's resolved path, SHA-256 hash, bounded version probe,
the repository commit and worktree state, and every wall-time limit. The
executable is hashed immediately before every launch and again when each run
is recorded. BBOT also binds and rechecks its installed Python distribution
tree. Retained preflight and
per-run artifacts are hash-verified during report generation, including an
exact path-and-hash inventory of BBOT's JSON tree. A tool cannot leave a child
process running after its leader exits: the supervisor terminates the process
group and marks that run as failed. Per-run homes and Fellaga SQLite state are
deleted immediately after their evidence is recorded. Final cleanup is bounded
and verified before the report can be complete. Wildcard patterns are counted
and excluded; they are never converted into concrete hosts. Tool order rotates
across both domains and repetitions, so a one-repetition campaign does not
always favor the same first tool. Three consecutive failures disable only that
tool; the other safe tools continue. The final report is regenerated after the
bounded redaction pass. The runner exits non-zero if any tool is missing or
skipped, a run is absent or failed, a circuit breaker or deadline is reached,
or artifact integrity fails; `report.json` is still retained when it can be
validated. The cumulative campaign quota is checked after every run.

## Interpretation limits

`report.json` provides descriptive counts and timings only. It always sets:

```json
{
  "qualification_eligible": false,
  "qualification_passed": false,
  "best_tool_claim_allowed": false,
  "timing_comparable": false,
  "source_health_comparable": false
}
```

The corpus has no controlled ground truth and the policy prohibits direct
validation. More returned names do not prove greater recall, accuracy, or
superiority. Missing or skipped tools and failed runs are recorded as
additional reason codes, never hidden. Names from failed, timed-out,
interrupted, or parser-rejected runs remain available as evidence but are
excluded from coverage and median-success metrics. A process exit code cannot
normalize provider health across different tools; successful runs therefore
retain `source_health: unknown`, and empty successes are reported explicitly.

## Attribution and data terms

The pinned rows, hashes, URLs, provider composition, citation, and explicit
non-MIT notice are in `benchmarks/data/tranco-74J5X-top30.json` and
`benchmarks/data/README.md`. No single license is asserted for the Tranco
aggregate or the excerpt. Preserve the requested Tranco citation and review
the mixed upstream terms before redistribution or commercial use.
