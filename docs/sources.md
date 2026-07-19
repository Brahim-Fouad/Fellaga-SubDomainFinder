# Passive sources and credentials

The current Fellaga registry contains 67 connector names: 57 canonical provider integrations, five Fellaga-native connectors, and five compatibility entries. Registry coverage means an entry is present and addressable; it does not mean that every provider is currently reachable, keyless, stable, or productive.

Fellaga also has separate opportunistic direct CT-log monitoring, authoritative AXFR, DNS graph, DNSSEC, Web, TLS, and active DNS candidate generation. Those mechanisms are not counted as passive connectors.

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
| `skipped_unavailable` | The registry entry is deliberately unavailable, so no network request was made. The JSON `error` field contains the registry reason, such as a retired provider. This is not a provider failure and does not affect adaptive health counters. |
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

### Canonical connectors

The 57 canonical connector names are:

- `alienvault`, `anubis`, `bevigil`, `bufferover`, `builtwith`, `c99`, `censys`, `certspotter`, `chaos`, `chinaz`, `commoncrawl`
- `crtsh`, `digitalyama`, `digitorus`, `dnsdb`, `dnsdumpster`, `dnsrepo`, `domainsproject`, `driftnet`, `fofa`, `fullhunt`
- `github`, `gitlab`, `hackertarget`, `hudsonrock`, `intelx`, `leakix`, `merklemap`, `netlas`, `onyphe`, `postman`, `profundis`
- `pugrecon`, `quake`, `rapiddns`, `reconcloud`, `reconeer`, `redhuntlabs`, `riddler`, `robtex`, `rsecloud`, `securitytrails`, `shodan`
- `shodanct`, `sitedossier`, `submd`, `thc`, `threatbook`, `threatcrowd`, `threatminer`, `urlscan`, `virustotal`, `viewdns`, `waybackarchive`, `whoisxmlapi`, `windvane`, `zoomeyeapi`

Fellaga retains ten additional names:

| Name | Role |
| --- | --- |
| `anubisdb` | Fellaga-native AnubisDB connector, distinct from the canonical `anubis` endpoint. |
| `binaryedge` | Retired compatibility connector retained for legacy configuration and cached provenance; unavailable and never selected automatically. |
| `brave` | Fellaga-native Web-search connector. |
| `certificatedetails` | Compatibility name for the `digitorus` implementation. |
| `circl` | Fellaga-native CIRCL passive-DNS connector. |
| `otx` | Compatibility name for `alienvault`. |
| `subdomainapp` | Fellaga-native public aggregator connector. |
| `subdomaincenter` | Fellaga-native Web connector. |
| `wayback` | Compatibility name for `waybackarchive`. |
| `whoisxml` | Compatibility name for `whoisxmlapi`. |

Compatibility names preserve existing configurations and cached provenance. Selecting both a canonical name and its compatibility name can query the same provider twice; prefer the canonical name in a hand-written allowlist.

### Authentication

These 19 connectors require no configured credential: `anubis`, `anubisdb`, `certificatedetails`, `commoncrawl`, `crtsh`, `digitorus`, `hudsonrock`, `rapiddns`, `reconcloud`, `riddler`, `shodanct`, `sitedossier`, `subdomainapp`, `subdomaincenter`, `thc`, `threatcrowd`, `threatminer`, `wayback`, and `waybackarchive`.

Five connectors accept an optional credential and still run without it: `certspotter`, `hackertarget`, `postman`, `submd`, and `urlscan`. Every other credentialed connector is skipped locally when its required value is absent.

`crtsh` gives its public HTTP interface an eight-second head start. A failed or stalled HTTP request falls back to PostgreSQL with the remaining request budget; a valid HTTP response, including an empty result, avoids a duplicate database query. PostgreSQL addresses are resolved once per request, deduplicated, and attempted with IPv4 before IPv6 so an unavailable local IPv6 route cannot prevent the fallback.

| Connector | Requirement | Accepted environment variable(s) |
| --- | --- | --- |
| `certspotter` | Optional | `CERTSPOTTER_API_TOKEN` or `CERTSPOTTER_API_KEY` |
| `hackertarget` | Optional | `HACKERTARGET_API_KEY` |
| `postman` | Optional | `POSTMAN_API_KEY` |
| `reconeer` | Required | `RECONEER_API_KEY` |
| `submd` | Optional | `SUBMD_API_KEY` |
| `urlscan` | Optional | `URLSCAN_API_KEY` |
| `alienvault` | Required | `ALIENVAULT_API_KEY`, `OTX_API_KEY`, or `X_OTX_API_KEY` |
| `bevigil` | Required | `BEVIGIL_API_KEY` |
| `binaryedge` | Unavailable (provider retired) | Legacy `BINARYEDGE_API_KEY` values remain readable but are never sent |
| `brave` | Required | `BRAVE_SEARCH_API_KEY` |
| `bufferover` | Required | `BUFFEROVER_API_KEY` |
| `builtwith` | Required | `BUILTWITH_API_KEY` |
| `c99` | Required | `C99_API_KEY` |
| `censys` | Required | `CENSYS_API_KEY` |
| `chaos` | Required | `PDCP_API_KEY` (`CHAOS_API_KEY` remains accepted) |
| `chinaz` | Required | `CHINAZ_API_KEY` |
| `circl` | Required | `CIRCL_PDNS_CREDENTIALS` |
| `digitalyama` | Required | `DIGITALYAMA_API_KEY` |
| `dnsdb` | Required | `DNSDB_API_KEY` |
| `dnsdumpster` | Required | `DNSDUMPSTER_API_KEY` |
| `dnsrepo` | Required | `DNSREPO_API_KEY` |
| `domainsproject` | Required | `DOMAINSPROJECT_API_KEY` |
| `driftnet` | Required | `DRIFTNET_API_KEY` |
| `fofa` | Required | `FOFA_API_KEY` |
| `fullhunt` | Required | `FULLHUNT_API_KEY` |
| `github` | Required | `GITHUB_TOKEN` or `GITHUB_TOKENS` |
| `gitlab` | Required | `GITLAB_TOKEN` |
| `intelx` | Required | `INTELX_API_KEY` |
| `leakix` | Required | `LEAKIX_API_KEY` |
| `merklemap` | Required | `MERKLEMAP_API_TOKEN` or `MERKLEMAP_API_KEY` |
| `netlas` | Required | `NETLAS_API_KEY` |
| `onyphe` | Required | `ONYPHE_API_KEY` |
| `otx` | Required | `ALIENVAULT_API_KEY`, `OTX_API_KEY`, or `X_OTX_API_KEY` |
| `profundis` | Required | `PROFUNDIS_API_KEY` |
| `pugrecon` | Required | `PUGRECON_API_KEY` |
| `quake` | Required | `QUAKE_API_KEY` |
| `redhuntlabs` | Required | `REDHUNTLABS_API_KEY` |
| `robtex` | Required | `ROBTEX_API_KEY` |
| `rsecloud` | Required | `RSECLOUD_API_KEY` |
| `securitytrails` | Required | `SECURITYTRAILS_API_KEY` |
| `shodan` | Required | `SHODAN_API_KEY` |
| `threatbook` | Required | `THREATBOOK_API_KEY` |
| `virustotal` | Required | `VIRUSTOTAL_API_KEY` |
| `viewdns` | Required | `VIEWDNS_API_KEY` |
| `whoisxml` | Required | `WHOISXML_API_KEY` or `WHOISXMLAPI_API_KEY` |
| `whoisxmlapi` | Required | `WHOISXMLAPI_API_KEY` or `WHOISXML_API_KEY` |
| `windvane` | Required | `WINDVANE_API_KEY` |
| `zoomeyeapi` | Required | `ZOOMEYEAPI_API_KEY` or `ZOOMEYE_API_KEY` |

### Connector-specific pagination and stream bounds

| Connector | Current behavior |
| --- | --- |
| `binaryedge` | Retained compatibility entry only; the retired provider is unavailable and no request is started. |
| `brave` | Reads at most ten 20-result Web-search pages and stops when the provider reports no further results. |
| `merklemap` | Starts at page 0 and follows validated result totals for up to 1,000 pages. |
| `censys` | Reads at most ten 100-result pages; cursor values are limited to 8 KiB and must not repeat. |
| `netlas` | Performs one count request and one streamed download; the default limit is 200 records and `FELLAGA_NETLAS_DOWNLOAD_LIMIT` can explicitly raise it to any integer from 1 through 1,000,000 when the configured plan permits. |
| `postman` | Searches public request metadata in pages of 25, follows at most 100 distinct cursors, and rejects cursors longer than 8 KiB or repeated pages. `POSTMAN_API_KEY` is optional and never changes the public-visibility filter. |
| `securitytrails` | Follows at most 1,000 distinct scroll identifiers of at most 4,096 bytes; an exact HTTP 403 selects the legacy non-scroll endpoint. |
| `thc` | Reads at most 1,000 pages of 1,000 records; pagination state is limited to 4,096 bytes and must not repeat. |
| `robtex` | Streams the forward lookup, then performs reverse lookups for at most 1,000 unique IP addresses. |
| `viewdns` | Reads documented 1,000-record pages for at most 1,000 pages, validates the echoed domain and page counters, and rejects empty or repeated pages before the reported end. |

Unless a tighter rule is listed above, connectors that expose continued pages, cursors, resume keys, or trusted next links stop after 1,000 continuations. This is a hard safety ceiling, not an expected runtime: the shorter connector and passive-phase wall deadlines normally stop a low-throughput provider first. Every completely decoded page is checkpointed before the next request.

Censys uses the current Platform v3 global-search contract: `POST /v3/global/search/query`, Bearer PAT authentication, `cert.names` projection, and cursor pagination capped at ten pages. Set `CENSYS_API_KEY` to `PAT` or `PAT:ORGANIZATION_ID`; prefix a value with `platform:` to disable compatibility fallback. Existing v2 Basic Auth users can set `legacy:API_ID:API_SECRET`. An unprefixed two-part value is attempted as the current `PAT:ORGANIZATION_ID` format first and falls back to v2 only when the first v3 request is rejected for authentication.

Driftnet requires `DRIFTNET_API_KEY` and queries four authenticated summary families concurrently with a hard concurrency ceiling of four: `ct/log`, `scan/protocols`, `scan/domains`, and `domain/rdns`. Every request uses `summarize=host` with a 10,000-value cap, filters names back to the requested suffix, and checkpoints each completed endpoint independently. Errors and non-zero provider `summary.other` counts are aggregated only after all four endpoint summaries have been attempted, so one slow or failed family cannot hide successful results from the others. OTX passive DNS accepts `ALIENVAULT_API_KEY`, `OTX_API_KEY`, or `X_OTX_API_KEY`.

### Bounded high-volume connectors

`submd` reads the provider's line-oriented response as a stream instead of buffering the complete feed. A configured `SUBMD_API_KEY` is sent as a Bearer token. The stream is capped at 64 MiB, each unfinished record at 64 KiB, and normalized names are checkpointed after at most 1,000 distinct names and before every subsequent network read. Completed records therefore survive a later stream error or deadline even when a transport chunk contains fewer than 1,000 names.

`thc` requests 1,000 records per page, uses up to five paced page requests per second, checkpoints every completely decoded page, and accepts up to 1,000 pages within the remaining passive-phase budget and its 75-second connector ceiling. Empty pagination state completes the query; a repeated state, a state longer than 4,096 bytes, or a thousandth page that still advertises more work is reported as a bounded provider failure rather than allowing an endless loop.

`netlas` uses the current two-request API workflow with Bearer authentication: it first queries `domains_count`, then submits the same exact-domain-excluding query to `domains/download` with a domain-only projection. Fellaga conservatively requests at most 200 records by default. Set `FELLAGA_NETLAS_DOWNLOAD_LIMIT` to an integer from 1 through 1,000,000 only when the configured Netlas plan permits the larger download. Its top-level JSON array is decoded directly from the response stream with 16 MiB total, 1 MiB per-record, and 50-record checkpoint limits; a malformed or oversized tail cannot discard earlier completed checkpoints. If the provider count or response shows that the selected limit truncated the result set, Fellaga retains completed records and reports a partial/error outcome instead of complete success.

`securitytrails` starts with the scroll-capable `domains/list` API, checkpoints every decoded page, and follows at most 1,000 distinct opaque scroll identifiers inside the fixed `https://api.securitytrails.com` origin. An exact HTTP 403 selects the legacy domain-subdomains endpoint; other HTTP failures never silently change workflows. Scroll identifiers are length-bounded, safely encoded as one path segment, and rejected when repeated.

`dnsdb`, `profundis`, and `robtex` also consume line-oriented responses incrementally. Their streams are capped at 128 MiB with a 64 KiB unfinished-record limit. They checkpoint after at most 1,000 distinct names and at each completed transport chunk; DNSDB additionally validates its SAF terminal condition and account-specific offset ceiling.

`circl` consumes its passive-DNS response incrementally with a 128 MiB stream ceiling and a 64 KiB unfinished-line limit. It accepts at most 100,000 non-empty lines, checkpoints every 1,000 decoded lines and before awaiting the next transport chunk, and preserves completed records after a later transport or decoding failure. A further non-empty line changes the result to degraded; trailing blank lines do not create a false truncation warning.

The `github` and `gitlab` code-search connectors continue through remaining raw files and result pages when an individual content download fails. Successful fragments and files are checkpointed immediately, while a bounded failure summary is reported after pagination completes. GitHub rotates every configured token at most once on the current page when authentication or quota signals require it, and advances only after a valid response.

`postman` searches request resources through the documented public search API. It requests the maximum 25 records per page, keeps the public-visibility filter even when an optional `POSTMAN_API_KEY` is configured, scans structured result fields for plain and safely percent-encoded hostnames, and checkpoints a page only after validating its totals, fingerprint, and continuation cursor.

`viewdns` uses the documented subdomain-discovery endpoint with `VIEWDNS_API_KEY`. It accepts numeric pagination fields represented as JSON numbers or strings, validates the provider's echoed target and current page, filters every returned name to the requested suffix, and reports inconsistent totals or premature empty pages without discarding previously committed pages.

`commoncrawl` selects up to five valid indexes from distinct years, then walks them breadth-first for at most 1,000 page rounds within the connector deadline. Each request covers 15 compressed index blocks and accepts at most 150,000 result lines in a 48 MiB decompressed response. Fellaga samples at most two trusted WARC members, each capped at 2 MiB compressed and 4 MiB decompressed.

### Experimental and runtime-failing providers

The registry marks `anubis`, `anubisdb`, `certificatedetails`, `digitorus`, `driftnet`, `hudsonrock`, `rapiddns`, `reconcloud`, `reconeer`, `riddler`, `sitedossier`, `subdomainapp`, `subdomaincenter`, `threatcrowd`, and `threatminer` as experimental. The default `deep` profile enables every locally accessible connector whose metadata permits automatic execution, including eligible experimental entries. Four duplicate compatibility names (`certificatedetails`, `otx`, `wayback`, and `whoisxml`) remain opt-in to prevent duplicate provider traffic. `--all-sources` selects the corresponding unique implementations once; compatibility aliases remain explicitly selectable.

BinaryEdge retired its service and is represented separately as an unavailable compatibility entry. Fellaga keeps the name so existing configuration and cached provenance remain understandable, but neither automatic selection, explicit selection, nor `--all-sources` sends a request to the retired endpoint.

Registry coverage is intentionally separate from provider health. ReconCloud and Riddler are known to encounter anti-bot protection, while ThreatMiner has experienced API failures. ReconeER can return runtime authentication failures, and SiteDossier or ThreatCrowd can be unavailable or structurally inconsistent. Fellaga keeps these connectors explicit so checks can report `auth_required`, `anti_bot`, `schema_error`, `upstream_error`, or another bounded status instead of silently pretending that the provider succeeded. It does not bypass authentication, CAPTCHA, Cloudflare, or other provider controls.

## Configuration file

The default file is `~/.config/fellaga/config.json`. It is created automatically with a restrictive Unix file mode. Each source accepts one string or a list of strings:

```json
{
  "api_keys": {
    "github": ["github-token-one", "github-token-two"],
    "securitytrails": "securitytrails-token",
    "driftnet": "driftnet-token",
    "otx": "otx-token",
    "censys": "censys-personal-access-token:organization-id",
    "circl": "username:password",
    "dnsrepo": "access-token:api-key",
    "domainsproject": "username:password",
    "fofa": "analyst@example.org:api-key",
    "intelx": "public.intelx.io:api-key",
    "redhuntlabs": "https://api.redhuntlabs.com/community/v1/domains/subdomains:api-key",
    "zoomeyeapi": "zoomeye.org:api-key"
  }
}
```

These values are placeholders. The file is plain JSON and is not an encrypted secret store. Never commit it, attach it to an issue, or include it in scan artifacts.

Composite credentials use these exact formats:

| Connector | Accepted value | Validation |
| --- | --- | --- |
| `censys` | `PAT`, `PAT:ORGANIZATION_ID`, `platform:PAT`, `platform:PAT:ORGANIZATION_ID`, or `legacy:API_ID:API_SECRET` | `platform:` disables the v2 compatibility fallback. An unprefixed two-field value falls back to v2 only after an HTTP 401 from the first v3 request. |
| `circl` | `USERNAME:PASSWORD` | Split at the first colon and used as HTTP Basic Auth. |
| `dnsrepo` | `ACCESS_TOKEN:API_KEY` | Both fields are required; additional colons are rejected. |
| `domainsproject` | `USERNAME:PASSWORD` | Both fields are required; additional colons are rejected. |
| `fofa` | `EMAIL:API_KEY` | Both fields are required, the first must contain `@`, and additional colons are rejected. |
| `intelx` | `API_HOST:API_KEY` | The host must be `public.intelx.io`, `free.intelx.io`, or `2.intelx.io`. |
| `redhuntlabs` | `HTTPS_ENDPOINT:API_KEY` | The endpoint must use HTTPS on a `redhuntlabs.com` hostname and contain no credentials, query, or fragment. |
| `zoomeyeapi` | `HOST_SUFFIX:API_KEY` | The suffix must be exactly `zoomeye.org` or `zoomeye.hk`; do not include the `api.` prefix. |

Use `--config PATH` or `FELLAGA_CONFIG` to select another file. Environment variables and configuration-file values are merged, deduplicated, and rotated when several keys are available. A single environment value can contain several credentials separated by commas, semicolons, or newlines; JSON arrays are clearer when several composite credentials are configured.

The `alienvault` and `otx` configuration keys share credentials, as do `whoisxmlapi` and `whoisxml`. Their environment aliases are merged the same way. Cert Spotter accepts both `CERTSPOTTER_API_TOKEN` and `CERTSPOTTER_API_KEY`; MerkleMap accepts both `MERKLEMAP_API_TOKEN` and `MERKLEMAP_API_KEY`.

Fellaga identifies itself transparently to HTTP providers by default:

```text
Fellaga/<version> (+https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder)
```

Set `FELLAGA_USER_AGENT` when an organization or provider needs a specific contact string:

```bash
export FELLAGA_USER_AGENT='Fellaga/0.10.1 (security-team@example.org)'
```

The override is optional. It must be non-empty ASCII, contain no control characters, and fit within 256 characters. It changes only the HTTP `User-Agent`; it does not alter source selection.

## Source selection

With no explicit source arguments, Fellaga selects accessible connectors for the chosen profile and skips providers whose required key is absent. The default `deep` profile selects every eligible canonical and Fellaga-native connector whose metadata permits automatic execution; duplicate compatibility names are omitted unless explicitly selected, and the retired BinaryEdge entry remains unavailable. Provider safeguards and adaptive pauses remain active, so broad selection does not mean unlimited traffic or waiting.

```bash
# Explicit allowlist
fellaga scan your-domain.example --passive-sources crtsh,certspotter,commoncrawl

# Automatic selection except selected providers
fellaga scan your-domain.example --exclude-sources hackertarget,urlscan

# Select every unique source implementation, including experimental entries
fellaga scan your-domain.example --all-sources
```

An explicitly selected source bypasses its adaptive pause. `--all-sources` selects each available canonical or Fellaga-native implementation once, including experimental entries; it does not add a compatibility alias beside the corresponding implementation. Compatibility aliases remain valid in explicit allowlists for existing configurations. Unavailable registry entries remain visible in `fellaga sources` but are never scheduled. `fellaga sources --check` reports those entries as `skipped_unavailable`, with zero names, zero duration, and no network request. Providers without required credentials are skipped locally as `skipped_missing_key`; public or optional-key providers can still fail at runtime. Unknown connector identifiers are rejected before scheduling rather than receiving inferred capabilities.

## Caching, retries, and provider protection

Passive observations are merged permanently. A later empty or partial provider response cannot erase previously acquired names. The default provider refresh interval is 24 hours and can be changed with `--passive-refresh-hours`.

The shared HTTP layer reuses connections, limits requests per provider, caps decompressed response bodies, validates sensitive pagination destinations, rejects redirects that change scheme, host, or port, and retries selected transient statuses with exponential backoff and jitter. Automatic request replay is restricted to safe read methods; credentialed state-changing requests are never replayed. Short `Retry-After` values are honored inline; longer waits are persisted as an adaptive pause instead of holding the scan open. Each connector receives only the time remaining in the passive phase, with a small handoff margin so a slow source cannot hold the next phase open. Common Crawl uses one field-restricted request for each 15-block page and advances its selected yearly indexes breadth-first.

Each completely decoded provider page is committed immediately to permanent SQLite observations. The connector and scan working sets keep only a bounded candidate slice, so a large archive or passive-DNS response does not need to be duplicated across every active source before `--max-passive` is applied. A later timeout therefore preserves durable page data without turning the permanent inventory into an unbounded RAM requirement.

Passive connector concurrency accepts values from 1 through 32 and the selected value controls both scheduling width and per-task working-set partitioning. Certificate wildcard patterns are rejected as host findings rather than being converted into a concrete apex or child name; concrete names found in the same response are retained. Cancelling or timing out the CT database connector aborts its pending connection task so it cannot continue detached from the scan.

Passive refreshes use a generation number stored with each evidence row, making page replay idempotent without creating or deleting a second per-name marker set. An expiring SQLite lease allows only one process to refresh the same domain/source pair; a concurrent scan keeps the existing cache instead of duplicating provider traffic. Numeric connectors retain each completed lane across a crash and publish cache freshness only after every expected lane is complete and its advertised totals are satisfied. An unfinished generation older than 90 days restarts from page one, while all discovered names and provenance remain permanent.

The scheduler records marginal unique names rather than raw response size, then combines that yield with connector reliability and latency when ordering future work. A fast connector that repeatedly contributes new names therefore moves ahead of a slow or duplicate-heavy source. New connectors receive a metadata-based bootstrap priority so they can establish real yield history.

Three consecutive provider failures place an automatically selected source in a 24-hour adaptive pause. A missing credential is a local preflight skip, not a provider failure, and adding a key makes the source immediately eligible even if an older Fellaga version recorded a missing-key cooldown. A successful but zero-yield response is tracked separately from a failure. Partial results are recorded as degraded, and work deferred by a phase budget is recorded separately; neither state increases the consecutive-failure counter or starts a failure cooldown. Retained observations remain available, and a later success resets the failure streak. Use `fellaga sources` to view the current source state and retry eligibility.
