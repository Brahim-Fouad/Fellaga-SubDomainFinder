# Fellaga benchmark suite

For the pinned worldwide Tranco top-30 corpus, use the separate
[no-target-contact passive observation](PASSIVE_TOP30.md). It permits an
available safe subset of Fellaga, Subfinder, Amass, and BBOT, records missing
or policy-incompatible tools, isolates every run in no-key mode, and reports
observational counts without a ranking. Do not pass that third-party corpus
to the active runner described below.

The suite produces separate `no-key` and `equal-keys` campaigns. Every campaign runs at least three repetitions and rotates tool order between repetitions. Each Fellaga repetition starts with a fresh SQLite database and configuration file. Each `summary.jsonl` row records discovery, validation, and end-to-end status and duration, peak memory, raw names, names validated by `dnsx`, DNS-query count, and log paths.

The manifest binds the campaign ID, repository commit, executable hashes and versions, input hashes, credential mode, resolver set, DNS controls, and capacity preflights. The runner refuses an existing output directory so an earlier artifact cannot be reused accidentally.

Every discovery and validation command has a process-group wall timeout. A timed-out or externally interrupted command receives a graceful interrupt followed by forced termination of the complete process group. Failed and timed-out runs remain in the report and are excluded from rankings.

When the benchmark runs as root with `tshark`, DNS queries are counted from network traffic. Otherwise Fellaga exposes its internal count and competitor counts remain `null`.

## Requirements

Install `fellaga`, `subfinder`, `amass`, `bbot`, `puredns`, `massdns`, `dnsx`, `jq`, `python3`, `zstd`, GNU `timeout`, `git`, `sha256sum`, `readlink`, and `awk`. `tshark` is optional. Puredns requires `massdns` and an explicit curated resolver list.

The target file must contain only domains that are explicitly authorized for every active technique invoked by the compared tools. The `FELLAGA_BENCH_AUTHORIZED=YES` guard is mandatory.

## Run without API keys

```bash
cp benchmarks/authorized-domains.example.txt benchmarks/authorized-domains.txt
# Replace the placeholder with authorized domains before continuing.
FELLAGA_BENCH_AUTHORIZED=YES \
FELLAGA_BENCH_RESOLVERS_FILE=/absolute/path/to/curated-resolvers.txt \
  benchmarks/run.sh no-key benchmarks/authorized-domains.txt
```

The no-key campaign uses an isolated home and clears supported provider variables before launching each tool.

## Run with equal credentials

```bash
cp benchmarks/keys-manifest.example.json benchmarks/keys-manifest.json
# Complete the provider evidence only after configuring the same keys for each listed tool.
FELLAGA_BENCH_AUTHORIZED=YES \
FELLAGA_BENCH_RESOLVERS_FILE=/absolute/path/to/curated-resolvers.txt \
FELLAGA_BENCH_KEYS_HOME=/absolute/path/to/prepared-isolated-home \
KEYS_MANIFEST=benchmarks/keys-manifest.json \
  benchmarks/run.sh equal-keys benchmarks/authorized-domains.txt
```

`equal-keys` requires at least one provider. Every provider needs a unique name and environment variable, `competitors_configured: true`, and `configured_tools` containing `fellaga`, `subfinder`, `amass`, and `bbot`. The corresponding Fellaga environment variable must exist. `FELLAGA_BENCH_KEYS_HOME` points to a prepared home containing competitor configuration files; the runner copies it to a temporary isolated home and removes that copy on exit. The result manifest records provider identifiers, configured tool names, isolation status, and the key-manifest hash without recording credential values.

Text logs are redacted after each command and again from the exit trap. `SIGINT`, `SIGTERM`, and `SIGHUP` stop active process groups and packet capture before the final redaction pass. Binary packet captures and SQLite files are not rewritten.

## Ground truth

Add `ground-truth/<domain>.txt` containing the expected live names for each controlled domain. `report.py` calculates true positives, false positives, false negatives, precision, recall, F1, false discovery rate, validated exclusives, and wins per domain. Qualification requires ground truth for every domain, successful discovery and validation runs for every required tool, at least 30 authorized domains, at least three repetitions, and full Fellaga recall for every domain and repetition.

## Runtime controls

The defaults are intended for a full coverage campaign. Override them explicitly when developing the harness:

- `FELLAGA_BENCH_MAX_RUNTIME`: Fellaga's internal per-domain runtime, default `1800` seconds.
- `FELLAGA_BENCH_ACTIVE_MAX_RUNTIME`: Fellaga's active discovery budget, defaulting to `FELLAGA_BENCH_MAX_RUNTIME` (`1800` seconds by default). Set it to `0` to disable the active-phase deadline. The default leaves the full hard per-domain runtime available to active discovery.
- `FELLAGA_BENCH_DISCOVERY_TIMEOUT`: wall timeout for every discovery tool, default internal runtime plus 60 seconds.
- `FELLAGA_BENCH_VALIDATION_TIMEOUT`: wall timeout for every `dnsx` validation, default `300` seconds.
- `FELLAGA_BENCH_DNS_ENGINE_TIMEOUT`: wall timeout for the controlled DNS transport benchmark, default `900` seconds.
- `FELLAGA_BENCH_PIPELINE_TIMEOUT`: wall timeout for the ten-million-candidate pipeline benchmark, default `5400` seconds.
- `FELLAGA_BENCH_TIMEOUT_GRACE`: interrupt-to-kill grace period, default `5` seconds.
- `FELLAGA_BENCH_REPETITIONS`: repetitions per domain and tool, minimum and default `3`.
- `FELLAGA_BENCH_DNS_RATE`: shared DNS request limit for tools that expose a strict QPS control, default `1000`.
- `FELLAGA_BENCH_DNS_CONCURRENCY`: shared DNS concurrency where the CLI exposes it, default `100`.
- `FELLAGA_BENCH_RESOLVERS_FILE`: required curated resolver list used by Fellaga, puredns, dnsx, Subfinder, Amass, and BBOT brute-force DNS.
- `FELLAGA_BENCH_RESOLVER_QUERIES`: controlled transport query count, minimum and default `100000`; this representative sample takes about four seconds at the 25,000 qps gate.
- `FELLAGA_BENCH_PIPELINE_CANDIDATES`: deterministic candidate-pipeline size, exactly `10000000`, matching the Rust benchmark limit.
- `FELLAGA_BENCH_PIPELINE_BYTES_PER_CANDIDATE`: conservative disk estimate per pipeline candidate, default `2048` bytes.
- `FELLAGA_BENCH_PIPELINE_FIXED_BYTES`: fixed allowance for the permanent corpus, SQLite base, journals, and temporary files, default `2147483648` bytes (2 GiB).
- `FELLAGA_BENCH_PIPELINE_DISK_MARGIN_PERCENT`: safety multiplier applied to the disk estimate, default `125` percent.
- `FELLAGA_BENCH_PUREDNS_HEADROOM_PERCENT`: capacity allowance for PureDNS work beyond one corpus query per candidate, default `125` percent.
- `FELLAGA_BENCH_PROFILE_BASELINES`: optional Fellaga end-to-end profile baselines; use `all`, `none`, or a comma-separated subset of `deep,balanced,passive,turbo`. The default is `none`.
- `FELLAGA_BENCH_REQUIRE_PASS`: return a non-zero exit status when a qualification gate fails, default `1`; set it to `0` only while developing the harness.

Fellaga, puredns, and the common dnsx validation receive the same resolver set and explicit QPS limit. Subfinder and Amass receive the same resolver set, and Amass receives the same concurrency cap. BBOT receives the resolver list for brute-force DNS and the same concurrency cap; its CLI does not expose a strict global DNS QPS limit, which is recorded in `manifest.json`.

## Capacity preflights

The ten-million-candidate pipeline starts only when the output filesystem has enough free space. The default estimate is:

```text
required bytes = (10,000,000 x 2,048 + 2,147,483,648) x 125%
               = 28,284,354,560 bytes
```

Tune the per-candidate and fixed values only from measurements made on the same Fellaga schema and filesystem. A failed filesystem inspection, an invalid estimate, or insufficient space stops the campaign before the large fixture is generated. The complete calculation is saved in `disk-preflight.json` and copied into `manifest.json`.

After the one-million-name active corpus is decompressed, the runner also checks PureDNS capacity. It calculates `ceil(corpus candidates x headroom / QPS)` and refuses a discovery timeout shorter than that lower bound. The default one-million-name corpus, 125 percent headroom, and 1,000 QPS require at least 1,250 seconds, which fits the default 1,860-second discovery wall timeout. `puredns-preflight.json` records the corpus size, estimated minimum duration, capacity, and minimum coherent QPS. The manifest independently records `provenance.inputs.active_corpus_candidates`, and report generation requires it to match the PureDNS preflight exactly.

## Fellaga profile baselines

Profile baselines can be added to the same isolated campaign:

```bash
FELLAGA_BENCH_AUTHORIZED=YES \
FELLAGA_BENCH_RESOLVERS_FILE=/absolute/path/to/curated-resolvers.txt \
FELLAGA_BENCH_PROFILE_BASELINES=all \
  benchmarks/run.sh no-key benchmarks/authorized-domains.txt
```

The runner measures `deep`, `balanced`, `passive`, and `turbo` with the same end-to-end discovery and `dnsx` validation path. Each non-deep run receives a fresh SQLite database and configuration. The existing qualification run supplies the `deep` baseline, avoiding duplicate network work. Baseline rows are written only to `fellaga-profile-baselines.jsonl`; `summary.jsonl`, competitor rankings, and qualification gates remain unchanged.

## Performance gates

`dns-transport.json` measures native resolver throughput on a controlled loopback server. `candidate-pipeline.json` is produced by Fellaga from a fresh deterministic ten-million-name fixture and measures loading, SQLite persistence, scheduling, and DNS dispatch. Qualification requires every stage count to equal the requested count and peak memory to remain below 1 GiB. Both artifacts must match the campaign ID and Fellaga binary hash; the candidate result must also match the generated fixture hash.

`report.py --require-pass` returns non-zero unless all timing fields are finite and internally consistent, every required run is present, every Fellaga domain/repetition has full controlled-ground-truth recall, the artifacts match campaign provenance, and every other qualification gate passes. Extra repetitions are rejected. Wins and validated gain use true positives rather than raw output size.
