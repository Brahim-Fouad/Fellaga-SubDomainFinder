# Passive sources and credentials

Fellaga 0.8.5 registers 30 passive connectors. It also has separate opportunistic direct CT-log monitoring, authoritative AXFR, DNS graph, DNSSEC, Web, TLS, and active DNS candidate generation; those mechanisms are not counted as passive connectors.

## Inspect the registry

```bash
fellaga sources
fellaga sources --json
fellaga sources --check --target your-domain.example
```

The registry reports authentication requirements, automatic selection, evidence family, recursive capabilities, estimated cost, rate policy, experimental status, success ratio, latency, recent errors, and adaptive pause state.

`sources --check` performs real provider requests. Use an authorized target and expect the provider to observe it. Human output is emitted as each connector finishes; `--timeout` is a wall deadline for the complete connector including pagination, and `--concurrency` controls 1-32 parallel checks.

## Connector catalog

No required credential:

- `anubisdb`
- `certificatedetails`
- `certspotter` (optional token)
- `commoncrawl`
- `crtsh`
- `driftnet`
- `hackertarget`
- `otx` (optional key)
- `subdomainapp`
- `subdomaincenter`
- `urlscan` (optional key)
- `wayback`

Credentialed connectors:

| Connector | Environment variable |
| --- | --- |
| `bevigil` | `BEVIGIL_API_KEY` |
| `binaryedge` | `BINARYEDGE_API_KEY` |
| `brave` | `BRAVE_SEARCH_API_KEY` |
| `builtwith` | `BUILTWITH_API_KEY` |
| `censys` | `CENSYS_API_KEY` |
| `chaos` | `CHAOS_API_KEY` |
| `circl` | `CIRCL_PDNS_CREDENTIALS` |
| `fullhunt` | `FULLHUNT_API_KEY` |
| `github` | `GITHUB_TOKEN` or `GITHUB_TOKENS` |
| `gitlab` | `GITLAB_TOKEN` |
| `intelx` | `INTELX_API_KEY` |
| `leakix` | `LEAKIX_API_KEY` |
| `merklemap` | `MERKLEMAP_API_TOKEN` |
| `netlas` | `NETLAS_API_KEY` |
| `securitytrails` | `SECURITYTRAILS_API_KEY` |
| `shodan` | `SHODAN_API_KEY` |
| `virustotal` | `VIRUSTOTAL_API_KEY` |
| `whoisxml` | `WHOISXML_API_KEY` |

The three targeted connectors added in v0.8.5 cover distinct evidence families:

| Connector | Evidence family | Targeted query behavior |
| --- | --- | --- |
| `binaryedge` | `passive_dns` | Queries the domain-to-subdomain API; starts with page 1 and reads at most page 2 when the response reports more events. |
| `merklemap` | `certificate_transparency` | Searches certificates for `*.domain`; starts with page 0 and reads at most one additional page when the result count indicates more raw data. |
| `brave` | `web_crawl` | Searches the Web for `site:domain`; starts with one result page and reads at most one additional page when the API reports more results. |

All three require credentials and are selected automatically when their key is configured. Their one-page fast path minimizes latency for routine scans, while the bounded second page captures additional high-value names without turning a targeted lookup into an open-ended crawl. Names from a completed page remain available if the follow-up page fails or reaches its deadline.

`anubisdb`, `certificatedetails`, `driftnet`, `subdomainapp`, and `subdomaincenter` are marked experimental. The `deep` profile enables accessible experimental connectors; other profiles omit them from automatic selection. Experimental connectors are isolated, rate-limited, and may fail when an upstream undocumented endpoint changes.

## Configuration file

The default file is `~/.config/fellaga/config.json`. It is created automatically with a restrictive Unix file mode. Each source accepts one string or a list of strings:

```json
{
  "api_keys": {
    "github": ["github-token-one", "github-token-two"],
    "securitytrails": "securitytrails-token",
    "censys": "api-id:api-secret",
    "circl": "username:password",
    "intelx": "api-host:api-key"
  }
}
```

These values are placeholders. The file is plain JSON and is not an encrypted secret store. Never commit it, attach it to an issue, or include it in scan artifacts.

Use `--config PATH` or `FELLAGA_CONFIG` to select another file. Environment variables and configuration-file values are merged, deduplicated, and rotated when several keys are available.

## Source selection

With no explicit source arguments, Fellaga selects accessible connectors for the chosen profile and skips providers whose required key is absent.

```bash
# Explicit allowlist
fellaga scan your-domain.example --passive-sources crtsh,certspotter,commoncrawl

# Automatic selection except selected providers
fellaga scan your-domain.example --exclude-sources hackertarget,urlscan

# Diagnostic mode that also attempts unavailable connectors
fellaga scan your-domain.example --all-sources
```

An explicitly selected source bypasses its adaptive pause. `--all-sources` attempts every connector; providers without required credentials return a configuration error.

## Caching, retries, and provider protection

Passive observations are merged permanently. A later empty or partial provider response cannot erase previously acquired names. The default provider refresh interval is 24 hours and can be changed with `--passive-refresh-hours`.

The shared HTTP layer reuses connections, limits requests per provider, caps response bodies, validates sensitive pagination destinations, rejects redirects that change scheme, host, or port, and retries selected transient statuses with exponential backoff and jitter. Short `Retry-After` values are honored inline; longer waits are persisted as an adaptive pause instead of holding the scan open. Each connector receives only the time remaining in the passive phase, with a small handoff margin so a slow source cannot hold the next phase open. Common Crawl covers the same 15-block window per index in one field-restricted request rather than three sequential requests.

The scheduler records marginal unique names rather than raw response size, then combines that yield with connector reliability and latency when ordering future work. A fast connector that repeatedly contributes new names therefore moves ahead of a slow or duplicate-heavy source. New connectors receive a metadata-based bootstrap priority so they can establish real yield history.

Three consecutive failures place an automatically selected source in a 24-hour adaptive pause. A successful but zero-yield response is tracked separately from a failure. Retained observations remain available, and a later success resets the failure streak. Use `fellaga sources` to view the current source state and retry eligibility.
