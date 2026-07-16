# Controlled DNS laboratory

`verify.sh` builds a disposable BIND container and checks rotating wildcards, multilevel wildcards, NXDOMAIN rewriting, dangling CNAMEs, delegated child zones with glue, NSEC, NSEC3, observable UDP truncation with TCP fallback, complete AXFR, and refused AXFR.

The empty or incomplete AXFR classification is covered by Rust unit tests because a conforming authoritative server frames even a host-empty zone with opening and closing SOA records.

Requirements: Docker and `dig`.

```bash
tests/dns-lab/verify.sh
```

The laboratory listens only on `127.0.0.1:53535`, contacts no external target, and removes its temporary container automatically.
