# Local data, retention, and privacy

Fellaga uses SQLite as a permanent local inventory and learning store. It has no telemetry client, account system, central Fellaga service, or database-sharing feature.

## Default paths

| Data | Default path | Override |
| --- | --- | --- |
| SQLite database | `~/.local/share/fellaga/fellaga.db` | `--db PATH` or `FELLAGA_DB` |
| API-key configuration | `~/.config/fellaga/config.json` | `--config PATH` or `FELLAGA_CONFIG` |

`XDG_DATA_HOME` and `XDG_CONFIG_HOME` are respected when set.

On Unix, Fellaga protects its dedicated data and configuration directories with mode `0700`. The configuration, SQLite database, WAL/SHM files, and migration backups use mode `0600`. Existing parent directories keep their current permissions.

## Retention model

Positive DNS observations and supporting evidence do not expire automatically. This preserves historical knowledge even when a service later disappears or a provider becomes unavailable.

Negative DNS cache entries are temporary. A name that does not exist today can therefore be discovered in a later scan.

The inventory distinguishes:

- `live`: a fresh DNS validation exists;
- `historical`: a positive DNS validation exists but is older than the active freshness window;
- `unverified`: the name lacks current DNS confirmation, or its positive response remains ambiguous because it matches a confirmed or indeterminate wildcard profile.

The default freshness window is 24 hours. Change it with `--verification-max-age`. This setting changes presentation and validation decisions; it does not erase older evidence.

## Refresh and cleanup

Revalidate all known names for one domain:

```bash
fellaga refresh your-domain.example
```

Refresh is non-resumable and has no cumulative deadline by default (`--max-runtime 0`). It finishes after the retained inventory and positive cache-only keyset queues drain. A positive `--max-runtime` opts into a global refresh deadline. Fellaga includes both queues in progress totals and commits each completed validation batch. A bounded parent-zone ranking and SQLite-backed wildcard staging keep memory use stable. On an explicit deadline or Ctrl+C, completed validation batches remain committed, while unprocessed names and indeterminate DNS results keep their previous state. Root-scoped wildcard quarantine runs only after a complete refresh with fresh trusted-resolver consensus, inside one cancellable transaction that rolls back on interruption. Ambiguous supersets remain `unverified`; provenance, observations, and validation history remain stored. Per-request DNS timeouts, batch sizes, concurrency, and wildcard-probe limits remain active regardless of the cumulative setting.

Force a scan to bypass fresh caches:

```bash
fellaga scan your-domain.example --refresh-cache
```

Remove entries that are explicitly defined as expired:

```bash
fellaga cache prune
```

`cache prune` removes expired negative DNS cache entries and abandoned temporary candidates from completed or superseded scan queues. It preserves permanent positive observations, retained inventory, provenance, and learning tables. Wildcard handling is conservative: only exact matches with current trusted consensus can enter the root-scoped quarantine. The reusable positive cache and materialized live state are demoted, while the stored name, provenance, observations, validation history, and quarantine audit entry remain available. Passive or historical evidence remains visible through `explain` but does not override a current exact wildcard match. A later validated non-wildcard finding lifts the quarantine.

Use `fellaga explain <fqdn>` before deciding that a retained historical name is a false positive. Human, text, JSON, JSONL, and streaming JSONL scan output is live and non-wildcard by default; `--only-live` can state that policy explicitly in automation, while `--include-non-live` and `--include-wildcard` opt into other final states. Wildcard-quarantined names remain hidden from `fellaga list`, even with `--all`, while their retained evidence stays available through `fellaga explain`.

## Local learning

Fellaga records the yield of words, relative patterns, generators, and resolver choices. Successful labels and paths are prioritized in future scans, with contextual statistics for properties such as TLD, DNS depth, and DNS provider. Exploration prevents the ranking from becoming permanently locked to early results.

The local database supports `list`, `refresh`, `explain`, and resume operations. Fellaga never uploads it.

## Resumable work queues

Each running scan stores two bounded work queues in SQLite. The seed queue contains full names and merged provenance from passive, CT, AXFR, cached, and learned discovery. The active queue contains generated relative names, priorities, and generator identities. Separate feed rows store cursors for the embedded corpus and optional user wordlist, so Fellaga does not need to insert or retain the entire candidate space in memory.

Queue claims are atomic and include an attempt counter. Rows left in the processing state are requeued with `--resume latest`. Embedded and user wordlists, mutations, retries, resumed active work, and recursive candidate generation have no cumulative deadline by default. They stop when the finite generator feeds and durable queues drain or adaptive low-yield convergence pauses expansion. A positive `--active-max-runtime` opts into a deadline without discarding queued work. Transient DNS failures receive at most three total attempts across runs, while definitive answers become terminal. Durable per-scan generator totals and attempted-word rows preserve learning accuracy even after terminal candidate rows are cleaned up.

The final scan status, checkpoint completion, generator learning, successful words and patterns, and cleanup of temporary learning rows are committed in one transaction. The transaction is guarded against applying the same scan's learning twice. Prepared statements and queue-selection indexes keep finalization and bounded claims predictable on large databases. Physical deletion of completed or superseded queue rows is maintenance work performed after the completion commit; its failure does not reopen or fail the scan.

The v8-to-v9 migration is transactional and creates a timestamped pre-v9 backup before changing an existing database. Fellaga adds required columns before dependent indexes, preserves observations and validation history exactly, repairs an interrupted same-version v9 initialization additively, and rolls back the complete migration if any statement fails. A database created by a newer unsupported schema version is rejected instead of being modified.

## Backup

Create a consistent SQLite backup while no scan is writing to the database:

```bash
sqlite3 ~/.local/share/fellaga/fellaga.db \
  ".backup '$HOME/fellaga-backup.db'"
```

Also protect the configuration separately if it contains API keys. Never upload either file to a public issue or repository.

Schema migrations are transactional and create a backup before modifying an existing database. Historical observations are retained across supported migrations.

## Privacy boundaries

Scans remain observable even with telemetry disabled:

- passive providers receive the domain in API or HTTP requests;
- recursive resolvers observe DNS questions;
- authoritative DNS servers can observe validation, wildcard, NSEC, and AXFR traffic;
- target services can observe Web, TLS, and STARTTLS connections.

Select providers and resolvers according to the assessment rules, and do not scan confidential targets through third-party services unless that disclosure is authorized.
