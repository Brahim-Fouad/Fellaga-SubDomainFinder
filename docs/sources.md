# Passive sources and credentials

Fellaga 0.9.1 registers 30 passive connectors. It also has separate opportunistic direct CT-log monitoring, authoritative AXFR, DNS graph, DNSSEC, Web, TLS, and active DNS candidate generation; those mechanisms are not counted as passive connectors.

## Inspect the registry

```bash
fellaga sources
fellaga sources --json
fellaga sources --check --target your-domain.example
```

The registry reports authentication requirements, automatic selection, evidence family, recursive capabilities, estimated cost, rate policy, experimental status, success ratio, latency, recent errors, and adaptive pause state.

`sources --check` performs real provider requests. Use an authorized target and expect the provider to observe it. Human output is emitted as each connector finishes; `--timeout` is a wall deadline for the complete connector including pagination, and `--concurrency` controls 1-32 parallel checks.

Each completed check has an explicit status:

| Status | Meaning |
| --- | --- |
| `success` | The connector completed and returned one or more in-scope names. |
| `empty` | The connector completed normally but returned no in-scope names. |
| `degraded` | At least one completed page produced names, but a later page or operation ended with a warning. The completed names are retained. |
| `deferred_budget` | The connector reached its bounded source or passive-phase budget before completing and produced no retained names in that check. |
| `skipped_missing_key` | The connector requires a credential that is not configured, so no network request was made. |
| `rate_limited` | The provider returned a quota or rate-limit response, including `Retry-After` guidance. |
| `auth_required` | The provider rejected the configured credential or required authentication at request time. |
| `anti_bot` | A browser challenge, CAPTCHA, Cloudflare page, or unexpected HTML response blocked the machine-readable endpoint. |
| `upstream_error` | The provider returned a transient server-side 5xx response. |
| `transport_error` | The request failed before an application response, for example because of DNS or connection failure. |
| `tls_error` | TLS negotiation or certificate validation failed before a usable provider response was received. |
| `schema_error` | The provider returned a payload that did not match the connector's validated schema. |
| `timeout` | A network operation timed out independently of the connector's explicit total-budget deadline. |
| `error` | The connector failed for a reason that did not match a more specific category. The bounded error text remains available for diagnosis. |

The JSON form exposes the same status values together with the connector metadata, duration, retained-name count, and any bounded error or warning.

## Connector catalog

No required credential:

- `anubisdb`
- `certificatedetails`
- `certspotter` (optional token)
- `commoncrawl`
- `crtsh`
- `hackertarget`
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
| `driftnet` | `DRIFTNET_API_KEY` |
| `fullhunt` | `FULLHUNT_API_KEY` |
| `github` | `GITHUB_TOKEN` or `GITHUB_TOKENS` |
| `gitlab` | `GITLAB_TOKEN` |
| `intelx` | `INTELX_API_KEY` |
| `leakix` | `LEAKIX_API_KEY` |
| `merklemap` | `MERKLEMAP_API_TOKEN` |
| `netlas` | `NETLAS_API_KEY` |
| `otx` | `OTX_API_KEY` or `X_OTX_API_KEY` |
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

Driftnet queries its [official authenticated Certificate Transparency API](https://driftnet.io/api-docs/certificate-transparency) and requires `DRIFTNET_API_KEY`. OTX passive DNS requires `OTX_API_KEY` or its compatible alias `X_OTX_API_KEY`. Neither connector is selected automatically until a key is configured.

`anubisdb`, `certificatedetails`, `driftnet`, `subdomainapp`, and `subdomaincenter` are marked experimental. The `deep` profile may enable an experimental connector only when its registry entry allows automatic use and all required credentials are present. `certificatedetails` and `subdomaincenter` are manual connectors because their public Web surfaces can present browser or anti-bot controls. Manual and anti-bot connectors are never activated by automatic profile selection, including `deep`; run one explicitly with `--passive-sources` or include it intentionally with `--all-sources`.

## Configuration file

The default file is `~/.config/fellaga/config.json`. It is created automatically with a restrictive Unix file mode. Each source accepts one string or a list of strings:

```json
{
  "api_keys": {
    "github": ["github-token-one", "github-token-two"],
    "securitytrails": "securitytrails-token",
    "driftnet": "driftnet-token",
    "otx": "otx-token",
    "censys": "api-id:api-secret",
    "circl": "username:password",
    "intelx": "api-host:api-key"
  }
}
```

These values are placeholders. The file is plain JSON and is not an encrypted secret store. Never commit it, attach it to an issue, or include it in scan artifacts.

Use `--config PATH` or `FELLAGA_CONFIG` to select another file. Environment variables and configuration-file values are merged, deduplicated, and rotated when several keys are available.

Fellaga identifies itself transparently to HTTP providers by default:

```text
Fellaga/<version> (+https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder)
```

Set `FELLAGA_USER_AGENT` when an organization or provider needs a specific contact string:

```bash
export FELLAGA_USER_AGENT='Fellaga/0.9.1 (security-team@example.org)'
```

The override is optional. It must be non-empty ASCII, contain no control characters, and fit within 256 characters. It changes only the HTTP `User-Agent`; it does not turn a manual connector into an automatic one.

## Source selection

With no explicit source arguments, Fellaga selects accessible connectors for the chosen profile and skips providers whose required key is absent. Automatic selection also respects the registry's manual flag, so browser-facing or anti-bot connectors remain disabled even in `deep`.

```bash
# Explicit allowlist
fellaga scan your-domain.example --passive-sources crtsh,certspotter,commoncrawl

# Automatic selection except selected providers
fellaga scan your-domain.example --exclude-sources hackertarget,urlscan

# Diagnostic mode that also attempts unavailable connectors
fellaga scan your-domain.example --all-sources
```

An explicitly selected source bypasses its adaptive pause. `--all-sources` is an explicit diagnostic request that attempts every connector; providers without required credentials are reported as unavailable.

## Caching, retries, and provider protection

Passive observations are merged permanently. A later empty or partial provider response cannot erase previously acquired names. The default provider refresh interval is 24 hours and can be changed with `--passive-refresh-hours`.

The shared HTTP layer reuses connections, limits requests per provider, caps decompressed response bodies, validates sensitive pagination destinations, rejects redirects that change scheme, host, or port, and retries selected transient statuses with exponential backoff and jitter. Automatic request replay is restricted to safe read methods; credentialed state-changing requests are never replayed. Short `Retry-After` values are honored inline; longer waits are persisted as an adaptive pause instead of holding the scan open. Each connector receives only the time remaining in the passive phase, with a small handoff margin so a slow source cannot hold the next phase open. Common Crawl covers the same 15-block window per index in one field-restricted request rather than three sequential requests.

Each completely decoded provider page is committed immediately to permanent SQLite observations. The connector and scan working sets keep only a bounded candidate slice, so a large archive or passive-DNS response does not need to be duplicated across every active source before `--max-passive` is applied. A later timeout therefore preserves durable page data without turning the permanent inventory into an unbounded RAM requirement.

The scheduler records marginal unique names rather than raw response size, then combines that yield with connector reliability and latency when ordering future work. A fast connector that repeatedly contributes new names therefore moves ahead of a slow or duplicate-heavy source. New connectors receive a metadata-based bootstrap priority so they can establish real yield history.

Three consecutive provider failures place an automatically selected source in a 24-hour adaptive pause. A missing credential is a local preflight skip, not a provider failure, and adding a key makes the source immediately eligible even if an older Fellaga version recorded a missing-key cooldown. A successful but zero-yield response is tracked separately from a failure. Partial results are recorded as degraded, and work deferred by a phase budget is recorded separately; neither state increases the consecutive-failure counter or starts a failure cooldown. Retained observations remain available, and a later success resets the failure streak. Use `fellaga sources` to view the current source state and retry eligibility.
