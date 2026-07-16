# Local data, retention, and privacy

Fellaga uses SQLite as a permanent local inventory and learning store. It has no telemetry client, account system, central Fellaga service, or database-sharing feature.

## Default paths

| Data | Default path | Override |
| --- | --- | --- |
| SQLite database | `~/.local/share/fellaga/fellaga.db` | `--db PATH` or `FELLAGA_DB` |
| API-key configuration | `~/.config/fellaga/config.json` | `--config PATH` or `FELLAGA_CONFIG` |

`XDG_DATA_HOME` and `XDG_CONFIG_HOME` are respected when set.

On Unix, Fellaga protects its dedicated data and configuration directories with mode `0700`. The configuration, SQLite database, WAL/SHM files, and migration backups use mode `0600`. A generic pre-existing parent directory supplied by the user is not silently re-permissioned.

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

Force a scan to bypass fresh caches:

```bash
fellaga scan your-domain.example --refresh-cache
```

Remove entries that are explicitly defined as expired:

```bash
fellaga cache prune
```

`cache prune` is not a command to erase permanent positive observations. Wildcard cleanup occurs as part of scanning and validation: weak names that match a wildcard profile and their orphaned positive cache records are purged, while names with independent evidence remain available with wildcard context.

Use `fellaga explain <fqdn>` before deciding that a retained historical name is a false positive. Use `--only-live` when stale or unverified names must not reach downstream automation.

## Local learning

Fellaga records the yield of words, relative patterns, generators, and resolver choices. Successful labels and paths are prioritized in future scans, with contextual statistics for properties such as TLD, DNS depth, and DNS provider. Exploration prevents the ranking from becoming permanently locked to early results.

The learning database stays on the local machine. Domain inventories are necessarily stored locally so that `list`, `refresh`, `explain`, and resume operations work, but Fellaga does not upload them.

## Backup

Create a consistent SQLite backup while no scan is writing to the database:

```bash
sqlite3 ~/.local/share/fellaga/fellaga.db \
  ".backup '$HOME/fellaga-backup.db'"
```

Also protect the configuration separately if it contains API keys. Never upload either file to a public issue or repository.

Schema migrations are transactional and create a backup before modifying an existing database. Historical observations are retained across supported migrations.

## Privacy boundaries

No telemetry does not make a scan anonymous:

- passive providers receive the domain in API or HTTP requests;
- recursive resolvers observe DNS questions;
- authoritative DNS servers can observe validation, wildcard, NSEC, and AXFR traffic;
- target services can observe Web, TLS, and STARTTLS connections.

Select providers and resolvers according to the assessment rules, and do not scan confidential targets through third-party services unless that disclosure is authorized.
