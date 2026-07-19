# Architecture

Fellaga is organized as a small command-line shell around a reusable Rust
library. The architecture keeps discovery policy, external protocols,
persistence, and terminal presentation separate while preserving the public
paths used by existing integrations.

## High-level flow

```text
fellaga binary
  -> CLI parsing and presentation
  -> scan application coordinator
  -> discovery engines and passive connectors
  -> DNS validation and wildcard classification
  -> SQLite inventory and validation journal
  -> selected findings returned to every output mode
```

The binary entry point only starts the asynchronous runtime and delegates to
`cli`. Command handlers translate user input into library options; they do not
implement DNS, source, or database behavior.

## Component boundaries

| Component | Responsibility |
| --- | --- |
| `cli` | Arguments, profiles, command dispatch, imports, terminal rendering, and machine-readable output. |
| `scanner` | Application-level scan planning, phase coordination, checkpoints, cancellation, and final result assembly. |
| `passive` | Source registry, connector execution, HTTP handling, pagination, and response decoding. |
| `dns` | DNS wire operations, transports, resolver health, consensus, authoritative checks, and record classification. |
| `db` | SQLite connection lifecycle, migrations, scans, observations, passive state, learning, and read models. |
| `model` and shared contracts | Stable values exchanged across components without infrastructure dependencies. |
| `output` | One canonical finding-selection policy shared by human, JSON, JSONL, CSV, and raw-list output. |

Large public modules use a compatibility façade: the historical public types
and functions remain available from `fellaga_core::scanner`,
`fellaga_core::passive`, `fellaga_core::dns`, and `fellaga_core::db`, while the
implementation is divided into private, cohesive child modules. This keeps the
library API stable without forcing unrelated implementation details into one
file.

## Dependency rules

- The CLI depends on the public library API; the library never depends on the
  CLI or terminal renderer.
- Passive connectors depend on shared pagination contracts, not on SQLite.
- Confidence scoring reads immutable source metadata, not connector runtime or
  network code.
- Persistence adapters may store domain contracts, but domain contracts contain
  no SQL, HTTP, DNS, filesystem, or credential details.
- All final-output modes use the same `FindingSelection` predicate so a name
  cannot be considered live in one renderer and invalid in another.
- Credentials and provider response bodies stay at the connector boundary and
  are never embedded in durable pagination state.

These rules are checked by architecture tests in addition to normal unit and
integration tests.

## Scan execution and concurrency

`ScanPlan` converts command options into explicit execution limits before a
scan begins. Unlimited phases are represented as `TimeLimit::Unlimited`, not as
special timeout arithmetic scattered through the coordinator.

The coordinator owns phase lifetime and cancellation. Independent work runs in
parallel where it improves throughput, including passive collection, AXFR,
candidate validation, and bounded enrichment. DNS work passes through the
shared network governor and bounded in-flight queues. Workers return through
owned task groups; checkpoints record durable progress, and finalization waits
for required finite work instead of leaving detached background tasks.

Parallelism is therefore a throughput mechanism, not a substitute for
completion semantics. Per-request timeouts, response-size limits, retry limits,
pagination termination, candidate convergence, Ctrl+C, and optional explicit
wall-clock limits remain independent controls.

## Finding truth and persistence

Discovery and validation are separate stages. A passive observation can create
an `unverified` name, but only the validation pipeline can make it `live`.
Wildcard classification is applied before output selection. SQLite retains the
observation history and append-only validation evidence even when the current
state becomes historical or quarantined.

The output boundary then applies one policy to the completed findings:

- normal output: live and non-wildcard;
- `--include-non-live`: also historical and unverified;
- `--include-wildcard`: explicitly include wildcard-marked candidates;
- `--show`: change the encoding to one FQDN per line, not the truth policy.

## Extending Fellaga

When adding a passive source, add its static metadata to the catalog and keep
transport, decoding, pagination, and authentication inside the passive
component. Return normalized observations and evidence; do not write directly
to SQLite or bypass final DNS and wildcard validation.

When adding a discovery phase, expose a bounded operation to the scanner and
make cancellation, progress, checkpoint behavior, and network-governor use
explicit. New output modes must consume `FindingSelection` rather than
reimplementing live or wildcard checks.

## Verification

The normal quality gate is:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --locked
```

The CI and release workflows run the same codebase on clean Linux runners. DNS
behavior is exercised with controlled fixtures and local protocol tests; release
validation must not depend on scanning third-party domains.
