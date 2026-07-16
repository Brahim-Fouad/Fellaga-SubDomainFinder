# Passive sources and credentials

Fellaga 0.8 registers 27 passive connectors. It also has separate direct CT-log monitoring, authoritative AXFR, DNS graph, DNSSEC, Web, TLS, and active DNS candidate generation; those mechanisms are not counted as passive connectors.

## Inspect the registry

```bash
fellaga sources
fellaga sources --json
fellaga sources --check --target your-domain.example
```

The registry reports authentication requirements, automatic selection, evidence family, recursive capabilities, estimated cost, rate policy, experimental status, success ratio, latency, recent errors, and adaptive pause state.

`sources --check` performs real provider requests. Use an authorized target and expect the provider to observe it.

## Connector catalog

No required credential:

- `anubisdb`
- `certificatedetails`
- `certspotter` (optional token)
- `commoncrawl`
- `crtsh`
- `driftnet`
- `hackertarget`
- `subdomainapp`
- `subdomaincenter`
- `urlscan` (optional key)
- `wayback`

Credentialed connectors:

| Connector | Environment variable |
| --- | --- |
| `bevigil` | `BEVIGIL_API_KEY` |
| `builtwith` | `BUILTWITH_API_KEY` |
| `censys` | `CENSYS_API_KEY` |
| `chaos` | `CHAOS_API_KEY` |
| `circl` | `CIRCL_PDNS_CREDENTIALS` |
| `fullhunt` | `FULLHUNT_API_KEY` |
| `github` | `GITHUB_TOKEN` or `GITHUB_TOKENS` |
| `gitlab` | `GITLAB_TOKEN` |
| `intelx` | `INTELX_API_KEY` |
| `leakix` | `LEAKIX_API_KEY` |
| `netlas` | `NETLAS_API_KEY` |
| `otx` | `OTX_API_KEY` or `X_OTX_API_KEY` |
| `securitytrails` | `SECURITYTRAILS_API_KEY` |
| `shodan` | `SHODAN_API_KEY` |
| `virustotal` | `VIRUSTOTAL_API_KEY` |
| `whoisxml` | `WHOISXML_API_KEY` |

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

The shared HTTP layer reuses connections, limits requests per provider, caps response bodies, validates sensitive pagination destinations, and retries selected transient statuses with exponential backoff and jitter. `Retry-After` is respected without blocking unrelated providers.

Three consecutive failures place an automatically selected source in a 24-hour adaptive pause. Its retained observations remain available, and a later success resets the failure streak. Use `fellaga sources` to view the current source state and retry eligibility.
