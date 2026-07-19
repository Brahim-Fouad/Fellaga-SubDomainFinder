# Passive top-30 observation campaign

This campaign compares passive-observational subdomain output over a pinned
public popularity corpus. It does not contact, resolve, probe, or validate the
listed domains. It is separate from the authorized active benchmark and must
not be run through `benchmarks/run.sh`.

The corpus is the first 30 rows of Tranco list `74J5X`, generated on
2026-07-17 from rankings covering 2026-06-18 through 2026-07-17. The permanent
snapshot is <https://tranco-list.eu/list/74J5X/1000000>. A popularity ranking is
not authorization to assess a domain.

Passive providers still receive requests about the named domains. Review each
provider's terms, credentials, and rate limits before running the campaign.

## Local toolset

The runner has no built-in comparison-tool names, package names, commands, or
special cases. It reads the `passive-observational` campaign from a validated
local toolset. The default path is:

```text
benchmarks/toolset.local.json
```

Override it with `FELLAGA_PASSIVE_TOP30_TOOLSET`. The local file defines:

- a neutral ID for each discoverer and the subject ID;
- the real executable name or path;
- identity and version-probe metadata;
- a `passive-observational` argv template;
- an optional no-target preflight;
- a generic output contract;
- the mandatory passive contact policy.

Every passive discoverer must declare this fail-closed policy:

```json
{
  "target_contact": "prohibited",
  "direct_dns": false,
  "direct_http_or_tls": false
}
```

The generic output kinds are `line_stdout`, `line_file`, `finding_json`, and
`dns_event_tree`. File and tree outputs must use the isolated `output_file` or
`output_directory` context supplied by the runner. Commands are rendered as
NUL-delimited argument arrays. Shell evaluation and command-string execution
are not used.

The runner never invents an executable name. If a configured executable cannot
be resolved inside the fixed system path, that tool is recorded as missing.
An optional preflight is rendered from the same toolset and checked against its
required literals and forbidden regular expressions. A failed preflight marks
only that tool as skipped; the contact policy is never relaxed.

## Isolation and safety

Every run starts with an empty environment. It receives only a fixed system
`PATH`, C UTF-8 locale, UTC timezone, `NO_COLOR`, and fresh `HOME` and XDG
directories. Credentials, proxy variables, cloud configuration, SSH agents,
netrc files, existing configuration, and API keys are not inherited.

The runner also provides isolated state and output paths. A command may use
only the placeholders declared by its toolset contract. The campaign rejects
output paths outside the corresponding isolated context.

The normalized toolset snapshot and its canonical SHA-256 hash are embedded in
the campaign manifest. The manifest also records resolved executable paths,
executable hashes, bounded identity probes, repository state, contact policy,
timeouts, and the preflight evidence inventory. Executable hashes are checked
before every launch and again when a run is recorded.

## Run

Linux or WSL with Bash and Python 3 is required. Validate the corpus and local
toolset first:

```bash
python3 benchmarks/passive_top30_report.py verify-source
python3 benchmarks/toolset.py validate --config benchmarks/toolset.local.json
```

Then start the campaign:

```bash
FELLAGA_PASSIVE_TOP30_OUT=benchmarks/results/passive-top30-74J5X \
  bash benchmarks/run-passive-top30.sh
```

To run the exact pinned top-five prefix while keeping the same manifest and
integrity checks:

```bash
FELLAGA_PASSIVE_TOP30_DOMAIN_LIMIT=5 \
FELLAGA_PASSIVE_TOP30_OUT="$HOME/fellaga-results/passive-top5-74J5X" \
  bash benchmarks/run-passive-top30.sh
```

Private per-run configuration needs real POSIX permissions. If the repository
is under `/mnt/c` in WSL, put the output on the Linux filesystem:

```bash
FELLAGA_PASSIVE_TOP30_OUT="$HOME/fellaga-results/passive-top30-74J5X" \
  bash benchmarks/run-passive-top30.sh
```

The runner verifies permission semantics before any domain is sent to a passive
provider.

Optional controls:

- `FELLAGA_PASSIVE_TOP30_TOOLSET`: local toolset path; default
  `benchmarks/toolset.local.json`.
- `FELLAGA_PASSIVE_TOP30_REPETITIONS`: `1` to `10`; default `1`.
- `FELLAGA_PASSIVE_TOP30_DOMAIN_LIMIT`: exact leading corpus size, `1` to `30`;
  default `30`. The selected prefix is recorded and verified in the manifest.
- `FELLAGA_PASSIVE_TOP30_TIMEOUT`: per-run wall deadline; default `180` seconds.
- `FELLAGA_PASSIVE_TOP30_TIMEOUT_GRACE`: shutdown grace; default `5` seconds.
- `FELLAGA_PASSIVE_TOP30_PREFLIGHT_TIMEOUT`: preflight deadline; default `60`.
- `FELLAGA_PASSIVE_TOP30_MAX_RUNTIME`: campaign deadline; default `7200`.
- `FELLAGA_PASSIVE_TOP30_COOLDOWN`: delay between runs; default `1` second.
- `FELLAGA_PASSIVE_TOP30_FAILURE_THRESHOLD`: consecutive failures before the
  per-tool circuit breaker opens; default `3`.
- `FELLAGA_PASSIVE_TOP30_CLEANUP_TIMEOUT`: cleanup deadline; default `60`.
- `FELLAGA_PASSIVE_TOP30_REDACTION_TIMEOUT`: redaction deadline; default `60`.
- `FELLAGA_PASSIVE_TOP30_MAX_FILE_BYTES`: per-process file limit; default
  `268435456` bytes.
- `FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_FILES`: retained-file limit; default
  `50000`.
- `FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_BYTES`: retained-size limit; default
  `2147483648` bytes.

The output directory must not already exist. It contains the bound manifest,
per-run timings, normalized names, a JSON-lines ledger, retained preflight
evidence, and `report.json`. Tool order rotates across domains and repetitions.
Failures disable only the affected tool. Process groups are terminated on
timeout, per-run private state is removed after evidence is recorded, retained
artifacts are redacted, and cumulative quotas are checked after every run.

Wildcard patterns, malformed names, non-host values, and out-of-scope values
are excluded and counted. Failed, timed-out, interrupted, or structurally
unparseable runs do not contribute to coverage or success medians.

## Interpretation limits

The report derives its complete tool list and subject from the bound toolset.
It provides descriptive counts and timings only and always sets:

```json
{
  "qualification_eligible": false,
  "qualification_passed": false,
  "best_tool_claim_allowed": false,
  "timing_comparable": false,
  "source_health_comparable": false
}
```

The corpus has no controlled ground truth and direct validation is prohibited.
More returned names do not prove greater recall, accuracy, or superiority.
Missing tools, skipped tools, failed runs, and artifact-integrity failures are
reported explicitly.

## Attribution and data terms

The pinned rows, hashes, URLs, provider composition, citation, and explicit
non-MIT notice are in `benchmarks/data/tranco-74J5X-top30.json` and
`benchmarks/data/README.md`. No single license is asserted for the aggregate or
excerpt. Preserve the requested citation and review the mixed upstream terms
before redistribution or commercial use.
