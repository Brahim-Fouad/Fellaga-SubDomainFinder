# Fellaga benchmark suite

This directory contains two separate workflows:

- `run.sh` performs an active, qualification-grade comparison on controlled or explicitly authorized domains.
- `run-passive-top30.sh` performs a no-target-contact observation on the pinned worldwide top-30 corpus. Never give that third-party corpus to the active runner.

The active runner is product-neutral. Executables, commands, output formats, DNS controls, and campaign roles come from a local toolset file. Product names and command-line assumptions do not live in the runner or report generator.

## Toolset

Copy [`toolset.example.json`](toolset.example.json) to the default local path and replace every placeholder executable and command with the adapters installed on this machine:

```bash
cp benchmarks/toolset.example.json benchmarks/toolset.local.json
python3 benchmarks/toolset.py validate --config benchmarks/toolset.local.json
```

Alternatively, set `FELLAGA_BENCH_TOOLSET` to another absolute or repository-relative JSON file. The active campaign defines these roles:

- `subject`: the engine being evaluated.
- `discoverers`: every engine included in qualification and ranking. The subject and capacity guard must be members.
- `validator`: the common final DNS validator used for every successful discovery output.
- `capacity_guard`: the discoverer whose candidate-corpus capacity is checked before target work begins.
- `provenance_only`: helper executables whose identity must be bound even though they do not receive a target directly.
- `credential_participants`: discoverers that must receive the same provider credentials in `equal-keys` mode.

Commands are argv arrays. They are rendered as NUL-delimited arguments and are never evaluated by a shell. The supported output contracts are `line_stdout`, `line_file`, `finding_json`, and `dns_event_tree`. Every non-stdout output path is confined to the fresh campaign directory.

At campaign creation, the runner validates the complete toolset, captures executable versions and hashes, and embeds both the normalized toolset snapshot and its SHA-256 hash in manifest schema 3. The report derives all participants and requirements from that embedded snapshot; it does not trust a later local configuration file.

## Requirements and authorization

Install the executables configured in the toolset, plus `bash`, `jq`, `python3`, `zstd`, GNU `timeout`, `git`, `sha256sum`, and `awk`. Packet capture with `tshark` is optional. When packet capture is available to root, DNS request counts come from traffic; otherwise only subject-provided internal counts may be available.

The domain file must contain only domains for which every configured active technique is explicitly authorized. `FELLAGA_BENCH_AUTHORIZED=YES` is a mandatory written-scope acknowledgement.

The runner refuses an existing output directory. Each command receives a process-group wall timeout. Interruptions and timeouts stop the complete process group, and failed runs remain visible but cannot enter rankings. Logs are redacted after every command and again during exit cleanup.

## No-key campaign

```bash
cp benchmarks/authorized-domains.example.txt benchmarks/authorized-domains.txt
# Replace the placeholder domains and review their written authorization.
FELLAGA_BENCH_AUTHORIZED=YES \
FELLAGA_BENCH_TOOLSET=benchmarks/toolset.local.json \
FELLAGA_BENCH_RESOLVERS_FILE=/absolute/path/to/curated-resolvers.txt \
  benchmarks/run.sh no-key benchmarks/authorized-domains.txt
```

No-key mode uses an isolated home and removes credential-shaped environment variables before launching participants. Identity probes run with a minimal environment that contains no provider credentials.

## Equal-keys campaign

```bash
cp benchmarks/keys-manifest.example.json benchmarks/keys-manifest.json
# Make configured_tools equal the toolset's credential_participants list,
# then set participants_configured=true only after every adapter is configured.
FELLAGA_BENCH_AUTHORIZED=YES \
FELLAGA_BENCH_TOOLSET=benchmarks/toolset.local.json \
FELLAGA_BENCH_RESOLVERS_FILE=/absolute/path/to/curated-resolvers.txt \
FELLAGA_BENCH_KEYS_HOME=/absolute/path/to/prepared-isolated-home \
KEYS_MANIFEST=benchmarks/keys-manifest.json \
  benchmarks/run.sh equal-keys benchmarks/authorized-domains.txt
```

Each provider entry needs a unique `name`, a unique `subject_env`, `participants_configured: true`, and a `configured_tools` array exactly equal to the active toolset's `credential_participants` set. The variable named by `subject_env` must exist. Credential values are never copied into artifacts. The prepared home is copied to a temporary isolated home and deleted on exit.

## Ground truth and qualification

Add `ground-truth/<domain>.txt` for every authorized domain. Each file contains the expected live names for that controlled zone. A qualification campaign needs at least 30 domains and at least three repetitions.

For every successful discovery run, the same configured validator produces the final live-name set. `report.py` calculates true positives, false positives, false negatives, precision, recall, F1, false-discovery rate, validated exclusives, per-domain wins, duration, and memory. It fails closed on missing runs, duplicate runs, malformed outputs, inconsistent timing, changed provenance, incomplete ground truth, or a toolset snapshot mismatch.

The subject qualifies only when all existing gates pass, including:

- 100% ground-truth recall on every subject run and in aggregate.
- less than 0.5% aggregate false-discovery rate.
- a win on at least 80% of ranked domains.
- at least 10% more validated true positives in aggregate than the best alternative per domain.
- end-to-end duration no more than twice that best-coverage alternative.
- at least 25,000 controlled DNS queries per second with less than 1% loss.
- a complete ten-million-candidate pipeline with less than 1% loss and less than 1 GiB peak memory.

`FELLAGA_BENCH_REQUIRE_PASS=1` is the default. Set it to `0` only while developing the harness.

## Runtime and capacity controls

- `FELLAGA_BENCH_MAX_RUNTIME`: subject per-domain runtime, default `1800` seconds.
- `FELLAGA_BENCH_ACTIVE_MAX_RUNTIME`: subject active-phase budget, defaulting to the maximum runtime; `0` disables only this internal active deadline.
- `FELLAGA_BENCH_DISCOVERY_TIMEOUT`: wall timeout for every discoverer, default maximum runtime plus 60 seconds.
- `FELLAGA_BENCH_VALIDATION_TIMEOUT`: wall timeout for the common validator, default `300` seconds.
- `FELLAGA_BENCH_DNS_ENGINE_TIMEOUT`: controlled subject transport timeout, default `900` seconds.
- `FELLAGA_BENCH_PIPELINE_TIMEOUT`: ten-million-candidate subject pipeline timeout, default `5400` seconds.
- `FELLAGA_BENCH_TIMEOUT_GRACE`: interrupt-to-kill grace period, default `5` seconds.
- `FELLAGA_BENCH_REPETITIONS`: repetitions per domain and discoverer, minimum and default `3`.
- `FELLAGA_BENCH_DNS_RATE`: shared DNS rate supplied to adapters that expose it, default `1000`.
- `FELLAGA_BENCH_DNS_CONCURRENCY`: shared DNS concurrency supplied to adapters that expose it, default `100`.
- `FELLAGA_BENCH_RESOLVERS_FILE`: required curated resolver list.
- `FELLAGA_BENCH_RESOLVER_QUERIES`: controlled transport sample, minimum and default `100000`.
- `FELLAGA_BENCH_PIPELINE_CANDIDATES`: fixed at `10000000` for qualification.
- `FELLAGA_BENCH_PIPELINE_BYTES_PER_CANDIDATE`: disk estimate, default `2048` bytes.
- `FELLAGA_BENCH_PIPELINE_FIXED_BYTES`: fixed disk allowance, default `2147483648` bytes.
- `FELLAGA_BENCH_PIPELINE_DISK_MARGIN_PERCENT`: disk safety multiplier, default `125` percent.
- `FELLAGA_BENCH_CAPACITY_GUARD_HEADROOM_PERCENT`: candidate-corpus capacity allowance, default `125` percent.
- `FELLAGA_BENCH_PROFILE_BASELINES`: `none`, `all`, or a comma-separated subset of `deep,balanced,passive,turbo`; the subject adapter must expose a `profile` context or parameter.

Before generating the large pipeline fixture, `disk-preflight.json` proves that the output filesystem has sufficient space. After the one-million-name corpus is decompressed, `capacity-guard-preflight.json` proves that the configured DNS rate and discovery timeout can cover the corpus with the requested headroom. Both calculations are embedded in the manifest and revalidated by the report.

Optional profile rows are written to `subject-profile-baselines.jsonl`; they never alter qualification rows or ranking inputs. `dns-transport.json` and `candidate-pipeline.json` are bound to the campaign ID, subject binary hash, and relevant corpus hash.
