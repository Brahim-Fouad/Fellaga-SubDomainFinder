# Reproducible Fellaga benchmark

The benchmark produces separate `no-key` and `equal-keys` campaigns. Each `summary.jsonl` row records the domain, tool, exit status, duration, peak memory, raw names, names validated by `dnsx`, DNS-query count, and errors. Original outputs are retained for audit, and the manifest records exact executable versions.

When the benchmark runs as root with `tshark`, DNS queries are counted from network traffic. Otherwise Fellaga exposes its internal count and competitor counts remain `null`.

## Requirements

Install `fellaga`, `subfinder`, `amass`, `bbot`, `puredns`, `dnsx`, `jq`, `python3`, and `zstd`. `tshark` is optional.

The target file must contain only domains that are explicitly authorized for every active technique invoked by the compared tools. The `FELLAGA_BENCH_AUTHORIZED=YES` guard is mandatory.

## Run without API keys

```bash
cp benchmarks/authorized-domains.example.txt benchmarks/authorized-domains.txt
# Replace the placeholder with authorized domains before continuing.
FELLAGA_BENCH_AUTHORIZED=YES \
  benchmarks/run.sh no-key benchmarks/authorized-domains.txt
```

The no-key campaign uses an isolated home and removes supported provider variables so tools do not silently inherit user credentials.

## Run with equal credentials

```bash
cp benchmarks/keys-manifest.example.json benchmarks/keys-manifest.json
# Mark a provider true only after the same credential is configured for every competitor.
FELLAGA_BENCH_AUTHORIZED=YES \
KEYS_MANIFEST=benchmarks/keys-manifest.json \
  benchmarks/run.sh equal-keys benchmarks/authorized-domains.txt
```

`equal-keys` refuses to start until every provider in the manifest has `competitors_configured: true` and the corresponding Fellaga environment variable exists. Secret values are never copied into benchmark results.

## Ground truth

Add `ground-truth/<domain>.txt` containing the expected live names for a controlled domain. `report.py` can then calculate recall, false positives, validated exclusives, and wins per domain. Without ground truth, these metrics remain explicitly `null`; the report must not present raw name counts as proof of accuracy or market leadership.
