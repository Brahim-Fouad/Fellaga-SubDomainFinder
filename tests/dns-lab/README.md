# Controlled DNS laboratory

`verify.sh` builds a disposable BIND container and checks rotating wildcards, multilevel wildcards, NXDOMAIN rewriting, dangling CNAMEs, delegated child zones with glue, NSEC, NSEC3, observable UDP truncation with TCP fallback, complete AXFR, and refused AXFR.

When `FELLAGA_BIN` is set, the same run also performs two real CLI scans. It verifies from Fellaga's JSON output that a record distinct from the wildcard is retained, an exact wildcard match is suppressed, a complete AXFR is `success`, and a denied transfer is `refused`. All discovery methods that could contact an external service are disabled for these scans.

The empty or incomplete AXFR classification is covered by Rust unit tests because a conforming authoritative server frames even a host-empty zone with opening and closing SOA records.

The base checks require Docker and `dig`. CLI integration additionally requires Python 3 and a built Fellaga binary.

```bash
tests/dns-lab/verify.sh
```

To include the CLI integration (the mode used by CI):

```bash
cargo build --locked --bin fellaga
FELLAGA_BIN=target/debug/fellaga tests/dns-lab/verify.sh
```

The laboratory listens only on loopback, contacts no external target, and removes its temporary container and Fellaga database automatically. The CLI mode temporarily uses `127.0.0.1:53` because Fellaga currently accepts resolver IP addresses rather than custom resolver ports; the dig-only mode uses `127.0.0.1:53535`.

Set `FELLAGA_DNS_LAB_KEEP=1` to retain the temporary database, JSON results, logs, and exact shell-escaped commands for troubleshooting.
