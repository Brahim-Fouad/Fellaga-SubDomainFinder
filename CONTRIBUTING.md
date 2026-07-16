# Contributing to Fellaga

Thank you for contributing. Changes must preserve three core properties: traceable findings, bounded network load by default, and no automatic transmission of the local database.

## Before you start

- Use only a DNS zone that you control or are explicitly authorized to test.
- Search existing issues before opening a new one.
- Never attach API keys, a real SQLite database, confidential targets, or unredacted scan output.
- Keep undocumented connectors isolated, bounded, and marked `experimental`.
- Do not add authentication or CAPTCHA bypasses.
- Keep discussions respectful and attach reproducible measurements to technical comparisons.

Security vulnerabilities in Fellaga must follow [SECURITY.md](SECURITY.md), not a public issue.

## Development environment

The Cargo package is `fellaga-subdomainfinder`. It builds the `fellaga` binary and the `fellaga_core` library target. The minimum supported Rust version is 1.95.

On Kali or Debian, install Rust/Cargo, a C toolchain, OpenSSL development headers, `pkg-config`, Zstandard, Docker, and DNS utilities. Docker and `dig` are required only for the controlled DNS laboratory.

Run the same core checks as CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --locked
tests/dns-lab/verify.sh
```

The DNS laboratory is the preferred way to test rotating and multilevel wildcards, AXFR classification, NSEC/NSEC3, NXDOMAIN rewriting, truncation, and TCP fallback. A public-domain scan is not a reproducible fixture and must never replace the laboratory.

## Prepare a change

1. Keep each pull request focused on one coherent problem.
2. Add a regression test that fails before a bug fix whenever practical.
3. Preserve compatibility of public JSON fields, or document and justify the intended break.
4. Bound every new network loop with a timeout, response limit, work budget, and cancellation path.
5. Record evidence provenance and the correct evidence family so correlated providers are not counted twice.
6. Update the README, detailed guide, and changelog when user-visible behavior changes.
7. Benchmark coverage and performance changes with a documented corpus, configuration, and measurement set.

A pull request should describe its risk, verification method, and the exact tests that were run.

## Embedded corpus

The distributed corpus is derived from a pinned SecLists revision. Read [data/CORPUS_LICENSE.md](data/CORPUS_LICENSE.md) before modifying it.

```bash
git clone https://github.com/danielmiessler/SecLists.git
git -C SecLists checkout 8a7c5daa498962e240a52c9b29164174478ffe78
SECLISTS_ROOT="$PWD/SecLists" ./scripts/build-corpus.sh
```

The generator verifies both source fingerprints, canonical content, and the compressed artifact. A SecLists update must change the generator, manifest, notices, and archive together, with an explanation of the coverage impact.

## Dependencies and licenses

Commit `Cargo.lock` with dependency changes. Review the license and provenance
of redistributed material, and update
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) when required. CI validates the
deterministic Cargo dependency SBOM generator and its offline license inventory;
these generated files complement review rather than replacing it.

## Pull-request checklist

- [ ] The target and test data are controlled or explicitly authorized.
- [ ] Formatting, Clippy, tests, and relevant laboratories pass.
- [ ] New network work is bounded and cancellable.
- [ ] No secret, target database, or confidential finding is included.
- [ ] Public behavior and compatibility impact are documented.
- [ ] Coverage and performance changes include reproducible measurements.
