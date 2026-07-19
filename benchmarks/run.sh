#!/usr/bin/env bash
set -euo pipefail
umask 077

MODE="${1:-}"
DOMAINS_FILE="${2:-}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BENCH_OUT:-$ROOT/benchmarks/results/$STAMP-$MODE}"
BENCH_MAX_RUNTIME="${FELLAGA_BENCH_MAX_RUNTIME:-1800}"
BENCH_ACTIVE_MAX_RUNTIME="${FELLAGA_BENCH_ACTIVE_MAX_RUNTIME:-$BENCH_MAX_RUNTIME}"
BENCH_DNS_RATE="${FELLAGA_BENCH_DNS_RATE:-1000}"
BENCH_DNS_CONCURRENCY="${FELLAGA_BENCH_DNS_CONCURRENCY:-100}"
BENCH_RESOLVER_QUERIES="${FELLAGA_BENCH_RESOLVER_QUERIES:-100000}"
BENCH_RESOLVER_CONCURRENCY="${FELLAGA_BENCH_RESOLVER_CONCURRENCY:-128}"
BENCH_PIPELINE_CANDIDATES="${FELLAGA_BENCH_PIPELINE_CANDIDATES:-10000000}"
BENCH_PIPELINE_BATCH="${FELLAGA_BENCH_PIPELINE_BATCH:-4096}"
BENCH_PIPELINE_CONCURRENCY="${FELLAGA_BENCH_PIPELINE_CONCURRENCY:-128}"
BENCH_REPETITIONS="${FELLAGA_BENCH_REPETITIONS:-3}"
BENCH_TIMEOUT_GRACE="${FELLAGA_BENCH_TIMEOUT_GRACE:-5}"
BENCH_REQUIRE_PASS="${FELLAGA_BENCH_REQUIRE_PASS:-1}"
BENCH_PIPELINE_BYTES_PER_CANDIDATE="${FELLAGA_BENCH_PIPELINE_BYTES_PER_CANDIDATE:-2048}"
BENCH_PIPELINE_FIXED_BYTES="${FELLAGA_BENCH_PIPELINE_FIXED_BYTES:-2147483648}"
BENCH_PIPELINE_DISK_MARGIN_PERCENT="${FELLAGA_BENCH_PIPELINE_DISK_MARGIN_PERCENT:-125}"
BENCH_CAPACITY_GUARD_HEADROOM_PERCENT="${FELLAGA_BENCH_CAPACITY_GUARD_HEADROOM_PERCENT:-125}"
BENCH_PROFILE_BASELINES_SPEC="${FELLAGA_BENCH_PROFILE_BASELINES:-none}"
RESOLVERS_SOURCE="${FELLAGA_BENCH_RESOLVERS_FILE:-}"
TOOLSET_SOURCE="${FELLAGA_BENCH_TOOLSET:-$ROOT/benchmarks/toolset.local.json}"

if [[ "$MODE" != "no-key" && "$MODE" != "equal-keys" ]]; then
  echo "usage: $0 no-key|equal-keys DOMAINS_FILE" >&2
  exit 2
fi
[[ "${FELLAGA_BENCH_AUTHORIZED:-}" == "YES" ]] || {
  echo "Set FELLAGA_BENCH_AUTHORIZED=YES only after written scope verification." >&2
  exit 3
}
[[ -f "$DOMAINS_FILE" ]] || { echo "domains file not found" >&2; exit 2; }

for value in "$BENCH_MAX_RUNTIME" "$BENCH_ACTIVE_MAX_RUNTIME" \
  "$BENCH_DNS_RATE" "$BENCH_DNS_CONCURRENCY" \
  "$BENCH_RESOLVER_QUERIES" "$BENCH_RESOLVER_CONCURRENCY" \
  "$BENCH_PIPELINE_CANDIDATES" "$BENCH_PIPELINE_BATCH" \
  "$BENCH_PIPELINE_CONCURRENCY" "$BENCH_REPETITIONS" "$BENCH_TIMEOUT_GRACE" \
  "$BENCH_REQUIRE_PASS" "$BENCH_PIPELINE_BYTES_PER_CANDIDATE" \
  "$BENCH_PIPELINE_FIXED_BYTES" "$BENCH_PIPELINE_DISK_MARGIN_PERCENT" \
  "$BENCH_CAPACITY_GUARD_HEADROOM_PERCENT"; do
  [[ "$value" =~ ^[0-9]+$ ]] || {
    echo "benchmark numeric settings must be non-negative integers" >&2
    exit 2
  }
done
[[ "$BENCH_REQUIRE_PASS" == "0" || "$BENCH_REQUIRE_PASS" == "1" ]] || {
  echo "FELLAGA_BENCH_REQUIRE_PASS must be 0 or 1" >&2
  exit 2
}
(( BENCH_MAX_RUNTIME > 0 && BENCH_DNS_RATE > 0 && BENCH_DNS_CONCURRENCY > 0 \
  && BENCH_RESOLVER_QUERIES >= 100000 )) || {
  echo "runtime and DNS rate must be positive; transport requires at least 100000 queries" >&2
  exit 2
}
(( BENCH_RESOLVER_CONCURRENCY > 0 && BENCH_REPETITIONS >= 3 )) || {
  echo "resolver concurrency must be positive and repetitions must be at least 3" >&2
  exit 2
}
(( BENCH_PIPELINE_CANDIDATES == 10000000 && BENCH_PIPELINE_BATCH > 0 \
  && BENCH_PIPELINE_CONCURRENCY > 0 )) || {
  echo "candidate pipeline requires exactly 10000000 candidates and positive batch/concurrency" >&2
  exit 2
}
(( BENCH_PIPELINE_BYTES_PER_CANDIDATE > 0 \
  && BENCH_PIPELINE_DISK_MARGIN_PERCENT >= 100 \
  && BENCH_CAPACITY_GUARD_HEADROOM_PERCENT >= 100 )) || {
  echo "pipeline bytes per candidate must be positive; disk and capacity-guard margins must be at least 100 percent" >&2
  exit 2
}

BENCH_PROFILE_BASELINES=()
case "${BENCH_PROFILE_BASELINES_SPEC,,}" in
  ""|none)
    ;;
  all)
    BENCH_PROFILE_BASELINES=(deep balanced passive turbo)
    ;;
  *)
    IFS=',' read -r -a requested_profiles <<< "${BENCH_PROFILE_BASELINES_SPEC,,}"
    for profile in "${requested_profiles[@]}"; do
      case "$profile" in
        deep|balanced|passive|turbo)
          if [[ " ${BENCH_PROFILE_BASELINES[*]} " != *" $profile "* ]]; then
            BENCH_PROFILE_BASELINES+=("$profile")
          fi
          ;;
        *)
          echo "FELLAGA_BENCH_PROFILE_BASELINES accepts none, all, or a comma-separated subset of deep,balanced,passive,turbo" >&2
          exit 2
          ;;
      esac
    done
    ;;
esac

BENCH_DISCOVERY_TIMEOUT="${FELLAGA_BENCH_DISCOVERY_TIMEOUT:-$((BENCH_MAX_RUNTIME + 60))}"
BENCH_VALIDATION_TIMEOUT="${FELLAGA_BENCH_VALIDATION_TIMEOUT:-300}"
BENCH_DNS_ENGINE_TIMEOUT="${FELLAGA_BENCH_DNS_ENGINE_TIMEOUT:-900}"
BENCH_PIPELINE_TIMEOUT="${FELLAGA_BENCH_PIPELINE_TIMEOUT:-5400}"
for value in "$BENCH_DISCOVERY_TIMEOUT" "$BENCH_VALIDATION_TIMEOUT" \
  "$BENCH_DNS_ENGINE_TIMEOUT" "$BENCH_PIPELINE_TIMEOUT"; do
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || {
    echo "all command wall timeouts must be positive integers" >&2
    exit 2
  }
done

for command in jq zstd python3 timeout git sha256sum awk; do
  command -v "$command" >/dev/null || {
    echo "missing prerequisite: $command" >&2
    exit 4
  }
done

[[ -f "$TOOLSET_SOURCE" ]] || {
  echo "FELLAGA_BENCH_TOOLSET must name a benchmark toolset JSON file" >&2
  exit 4
}

[[ -f "$RESOLVERS_SOURCE" ]] || {
  echo "FELLAGA_BENCH_RESOLVERS_FILE must name a curated resolver list" >&2
  exit 4
}

[[ ! -e "$OUT" ]] || {
  echo "benchmark output already exists; use a fresh BENCH_OUT to prevent stale artifacts" >&2
  exit 6
}
mkdir -p "$OUT/raw" "$OUT/live" "$OUT/logs" "$OUT/state" "$OUT/config"

TOOLSET_RUNTIME="$OUT/config/toolset.runtime.json"
if ! python3 - "$ROOT/benchmarks" "$TOOLSET_SOURCE" "$TOOLSET_RUNTIME" <<'PY'
import json
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from toolset import (  # noqa: E402
    capture_identity,
    load_toolset,
    normalized_snapshot,
    resolve_executable,
    snapshot_hash,
)

config = load_toolset(pathlib.Path(sys.argv[2]))
snapshot = normalized_snapshot(config)
active = snapshot["campaigns"]["active"]
subject = snapshot["subject"]
required_tools = list(dict.fromkeys([subject, *active["discoverers"]]))
provenance_tools = list(
    dict.fromkeys([*required_tools, active["validator"], *active["provenance_only"]])
)
identity_environment = {
    "PATH": __import__("os").environ.get("PATH", ""),
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "NO_COLOR": "1",
}
identities = {
    tool: capture_identity(config, tool, env=identity_environment)
    for tool in provenance_tools
}
failed = [
    tool
    for tool, identity in identities.items()
    if identity.get("version_probe_status") != "success" or not identity.get("version")
]
if failed:
    raise SystemExit("unsuccessful identity probe: " + ", ".join(failed))
resolved_executables = {
    tool: str(resolve_executable(config, tool)) for tool in provenance_tools
}
document = {
    "snapshot": snapshot,
    "sha256": snapshot_hash(snapshot),
    "roles": {
        "subject": subject,
        "discoverers": active["discoverers"],
        "required_tools": required_tools,
        "validator": active["validator"],
        "capacity_guard": active["capacity_guard"],
        "provenance_only": active["provenance_only"],
        "credential_participants": active["credential_participants"],
    },
    "identities": identities,
    "resolved_executables": resolved_executables,
}
pathlib.Path(sys.argv[3]).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
then
  echo "active benchmark toolset validation or identity capture failed" >&2
  exit 4
fi

SUBJECT="$(jq -r '.roles.subject' "$TOOLSET_RUNTIME")"
VALIDATOR="$(jq -r '.roles.validator' "$TOOLSET_RUNTIME")"
CAPACITY_GUARD="$(jq -r '.roles.capacity_guard' "$TOOLSET_RUNTIME")"
SUBJECT_BIN="$(jq -r --arg tool "$SUBJECT" '.resolved_executables[$tool]' "$TOOLSET_RUNTIME")"
mapfile -t DISCOVERERS < <(jq -r '.roles.discoverers[]' "$TOOLSET_RUNTIME")
mapfile -t REQUIRED_TOOLS < <(jq -r '.roles.required_tools[]' "$TOOLSET_RUNTIME")
mapfile -t PROVENANCE_TOOLS < <(
  jq -r '.roles.required_tools[], .roles.validator, .roles.provenance_only[]' \
    "$TOOLSET_RUNTIME" | awk '!seen[$0]++'
)
mapfile -t CREDENTIAL_PARTICIPANTS < <(
  jq -r '.roles.credential_participants[]' "$TOOLSET_RUNTIME"
)
if (( ${#BENCH_PROFILE_BASELINES[@]} > 0 )) && ! jq -e --arg tool "$SUBJECT" '
  ((.snapshot.tools[$tool].commands.active.required_context // []) +
   (.snapshot.tools[$tool].parameters // {} | keys))
  | index("profile") != null
' "$TOOLSET_RUNTIME" >/dev/null; then
  echo "profile baselines require a configurable profile field on the subject adapter" >&2
  exit 4
fi

render_tool_command() {
  local tool="$1" phase="$2" values_file="$3" result_name="$4"
  local -n result="$result_name"
  result=()
  mapfile -d '' -t result < <(
    python3 - "$ROOT/benchmarks" "$TOOLSET_SOURCE" "$tool" "$phase" \
      "$values_file" <<'PY'
import json
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from toolset import load_toolset, render_argv  # noqa: E402

config = load_toolset(pathlib.Path(sys.argv[2]))
tool, phase = sys.argv[3:5]
values = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
definition = config["tools"][tool]
command = definition["commands"][phase]
allowed = set(command.get("required_context", [])) | set(
    definition.get("parameters", {})
)
context = {key: value for key, value in values.items() if key in allowed}
argv = render_argv(config, tool, phase, context)
sys.stdout.buffer.write(b"".join(value.encode() + b"\0" for value in argv))
PY
  )
  (( ${#result[@]} > 0 )) || {
    echo "toolset rendered an empty command for $tool/$phase" >&2
    return 4
  }
}

render_tool_output() {
  local tool="$1" phase="$2" values_file="$3"
  python3 - "$ROOT/benchmarks" "$TOOLSET_SOURCE" "$tool" "$phase" \
    "$values_file" <<'PY'
import json
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from toolset import load_toolset, render_output  # noqa: E402

config = load_toolset(pathlib.Path(sys.argv[2]))
tool, phase = sys.argv[3:5]
values = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
definition = config["tools"][tool]
command = definition["commands"][phase]
allowed = set(command.get("required_context", [])) | set(
    definition.get("parameters", {})
)
context = {key: value for key, value in values.items() if key in allowed}
print(json.dumps(render_output(config, tool, phase, context), sort_keys=True))
PY
}

DISK_PREFLIGHT="$OUT/disk-preflight.json"
if ! python3 "$ROOT/benchmarks/preflight.py" disk \
  --path "$OUT" \
  --candidates "$BENCH_PIPELINE_CANDIDATES" \
  --bytes-per-candidate "$BENCH_PIPELINE_BYTES_PER_CANDIDATE" \
  --fixed-bytes "$BENCH_PIPELINE_FIXED_BYTES" \
  --margin-percent "$BENCH_PIPELINE_DISK_MARGIN_PERCENT" \
  --output "$DISK_PREFLIGHT" > "$OUT/logs/disk-preflight.stdout"; then
  disk_status="$(jq -r '.status // "error"' "$DISK_PREFLIGHT" 2>/dev/null || echo error)"
  disk_required="$(jq -r '.required_free_bytes // "unknown"' "$DISK_PREFLIGHT" 2>/dev/null || echo unknown)"
  disk_available="$(jq -r '.available_free_bytes // "unknown"' "$DISK_PREFLIGHT" 2>/dev/null || echo unknown)"
  echo "candidate pipeline disk preflight failed: status=$disk_status required_bytes=$disk_required available_bytes=$disk_available" >&2
  exit 6
fi

ACTIVE_CAPTURE_PID=""
BENCH_ISOLATED_HOME=""

stop_capture() {
  local capture_pid="$1"
  kill -INT "$capture_pid" >/dev/null 2>&1 || true
  for _ in {1..50}; do
    kill -0 "$capture_pid" >/dev/null 2>&1 || break
    sleep 0.1
  done
  if kill -0 "$capture_pid" >/dev/null 2>&1; then
    kill -KILL "$capture_pid" >/dev/null 2>&1 || true
  fi
  wait "$capture_pid" 2>/dev/null || true
}

cleanup_campaign() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ -n "$ACTIVE_CAPTURE_PID" ]]; then
    stop_capture "$ACTIVE_CAPTURE_PID"
    ACTIVE_CAPTURE_PID=""
  fi
  if [[ -d "$OUT/logs" ]]; then
    python3 "$ROOT/benchmarks/redact.py" "$OUT/logs" >/dev/null 2>&1 || true
  fi
  if [[ -n "$BENCH_ISOLATED_HOME" && -d "$BENCH_ISOLATED_HOME" ]]; then
    case "$BENCH_ISOLATED_HOME" in
      "${TMPDIR:-/tmp}"/fellaga-benchmark-keys.*)
        rm -rf -- "$BENCH_ISOLATED_HOME"
        ;;
      *)
        echo "refusing to remove unexpected isolated home: $BENCH_ISOLATED_HOME" >&2
        ;;
    esac
  fi
  exit "$status"
}

trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap cleanup_campaign EXIT

RESOLVERS_FILE="$OUT/config/resolvers.txt"
python3 - "$RESOLVERS_SOURCE" > "$RESOLVERS_FILE" <<'PY'
import ipaddress
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
seen = set()
for number, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
    value = raw.split("#", 1)[0].strip()
    if not value:
        continue
    try:
        normalized = str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise SystemExit(f"invalid resolver at {source}:{number}: {value}") from exc
    if normalized not in seen:
        seen.add(normalized)
        print(normalized)
if not seen:
    raise SystemExit("resolver list is empty")
PY
RESOLVERS_CSV="$(paste -sd, "$RESOLVERS_FILE")"
RESOLVER_COUNT="$(wc -l < "$RESOLVERS_FILE")"
RESOLVERS_SHA256="$(sha256sum "$RESOLVERS_FILE" | awk '{print $1}')"

if [[ "$MODE" == "equal-keys" ]]; then
  manifest="${KEYS_MANIFEST:-}"
  [[ -f "$manifest" ]] || {
    echo "KEYS_MANIFEST is required in equal-keys mode" >&2
    exit 5
  }
  credential_participants_json="$(jq -c '.roles.credential_participants | sort' "$TOOLSET_RUNTIME")"
  jq -e --argjson participants "$credential_participants_json" '
    .policy == "same-provider-keys" and
    (.providers | type == "array" and length > 0) and
    ([.providers[].name] | length == (unique | length)) and
    ([.providers[].subject_env] | length == (unique | length)) and
    all(.providers[];
      (.name | type == "string" and test("^[a-z0-9][a-z0-9_-]{0,63}$")) and
      (.subject_env | type == "string" and test("^[A-Z][A-Z0-9_]{2,127}$")) and
      .participants_configured == true and
      (.configured_tools | type == "array") and
      ((.configured_tools | sort) == $participants)
    )
  ' "$manifest" >/dev/null || {
    echo "invalid equal-keys manifest: providers must cover the toolset credential participants exactly" >&2
    exit 5
  }
  while IFS= read -r variable; do
    [[ -n "${!variable:-}" ]] || {
      echo "missing variable: $variable" >&2
      exit 5
    }
  done < <(
    jq -r '.providers[].subject_env' "$manifest"
  )
  keys_home="${FELLAGA_BENCH_KEYS_HOME:-}"
  [[ -d "$keys_home" ]] || {
    echo "FELLAGA_BENCH_KEYS_HOME must name a prepared participant configuration home" >&2
    exit 5
  }
  BENCH_ISOLATED_HOME="$(mktemp -d "${TMPDIR:-/tmp}/fellaga-benchmark-keys.XXXXXX")"
  cp -a "$keys_home"/. "$BENCH_ISOLATED_HOME"/
  export HOME="$BENCH_ISOLATED_HOME"
  export XDG_CONFIG_HOME="$HOME/.config"
  credential_evidence="$({
    jq -c '{
      mode: "equal-keys",
      isolated_home: true,
      policy,
      providers: [.providers[] | {
        name,
        subject_env,
        configured_tools: (.configured_tools | sort)
      }]
    }' "$manifest"
  })"
else
  credential_evidence='{"mode":"no-key","isolated_home":true,"policy":"no-credentials","providers":[]}'
fi

if [[ "$MODE" == "no-key" ]]; then
  export HOME="$OUT/no-key-home"
  export XDG_CONFIG_HOME="$HOME/.config"
  mkdir -p "$XDG_CONFIG_HOME"
  unset BEVIGIL_API_KEY BUILTWITH_API_KEY CENSYS_API_KEY \
    CENSYS_API_ID CENSYS_API_SECRET CERTSPOTTER_API_TOKEN \
    CHAOS_API_KEY CIRCL_PDNS_CREDENTIALS FULLHUNT_API_KEY \
    GITHUB_TOKEN GITHUB_TOKENS GITLAB_TOKEN INTELX_API_KEY \
    LEAKIX_API_KEY NETLAS_API_KEY OTX_API_KEY X_OTX_API_KEY \
    SECURITYTRAILS_API_KEY SHODAN_API_KEY URLSCAN_API_KEY \
    VIRUSTOTAL_API_KEY WHOISXML_API_KEY || true
  while IFS='=' read -r variable _; do
    case "$variable" in
      *_API_KEY|*_API_TOKEN|*_API_ID|*_TOKEN|*_TOKENS|*_SECRET|*_CREDENTIALS|*_PASSWORD)
        unset "$variable"
        ;;
    esac
  done < <(env)
fi

python3 "$ROOT/benchmarks/names.py" domains "$DOMAINS_FILE" \
  > "$OUT/authorized-domains.txt"
mapfile -t authorized_domains < "$OUT/authorized-domains.txt"
if (( ${#authorized_domains[@]} == 0 )); then
  echo "no authorized domain was provided" >&2
  exit 2
fi

corpus="$OUT/raw/candidates-1m.txt"
corpus_timing="$OUT/logs/corpus.time.json"
python3 "$ROOT/benchmarks/timed.py" \
  --timeout "$BENCH_VALIDATION_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
  "$corpus_timing" -- zstd -dc "$ROOT/data/candidates-1m.txt.zst" \
  > "$corpus" 2> "$OUT/logs/corpus.stderr" || true
if [[ "$(jq -r '.status' "$corpus_timing")" != "success" ]]; then
  echo "unable to prepare the active benchmark corpus within its deadline" >&2
  exit 6
fi
python3 "$ROOT/benchmarks/redact.py" "$OUT/logs/corpus.stderr"
ACTIVE_CORPUS_CANDIDATES="$(awk 'NF { candidates++ } END { print candidates + 0 }' "$corpus")"
(( ACTIVE_CORPUS_CANDIDATES > 0 )) || {
  echo "active benchmark corpus contains no candidates" >&2
  exit 6
}

CAPACITY_GUARD_PREFLIGHT="$OUT/capacity-guard-preflight.json"
if ! python3 "$ROOT/benchmarks/preflight.py" active-resolver \
  --corpus "$corpus" \
  --rate-qps "$BENCH_DNS_RATE" \
  --timeout-seconds "$BENCH_DISCOVERY_TIMEOUT" \
  --headroom-percent "$BENCH_CAPACITY_GUARD_HEADROOM_PERCENT" \
  --output "$CAPACITY_GUARD_PREFLIGHT" > "$OUT/logs/capacity-guard-preflight.stdout"; then
  capacity_status="$(jq -r '.status // "error"' "$CAPACITY_GUARD_PREFLIGHT" 2>/dev/null || echo error)"
  capacity_minimum_rate="$(jq -r '.minimum_coherent_rate_qps // "unknown"' "$CAPACITY_GUARD_PREFLIGHT" 2>/dev/null || echo unknown)"
  capacity_estimated_seconds="$(jq -r '.estimated_minimum_seconds // "unknown"' "$CAPACITY_GUARD_PREFLIGHT" 2>/dev/null || echo unknown)"
  echo "capacity-guard preflight failed: status=$capacity_status estimated_seconds=$capacity_estimated_seconds timeout_seconds=$BENCH_DISCOVERY_TIMEOUT minimum_rate_qps=$capacity_minimum_rate" >&2
  exit 8
fi
if ! jq -e --argjson candidates "$ACTIVE_CORPUS_CANDIDATES" \
  '.corpus_candidates == $candidates' "$CAPACITY_GUARD_PREFLIGHT" >/dev/null; then
  echo "capacity-guard preflight corpus count does not match the active corpus" >&2
  exit 8
fi
capacity_guard_preflight_tmp="$OUT/config/capacity-guard-preflight.tmp.json"
jq --arg tool "$CAPACITY_GUARD" '. + {tool: $tool}' \
  "$CAPACITY_GUARD_PREFLIGHT" > "$capacity_guard_preflight_tmp"
mv -- "$capacity_guard_preflight_tmp" "$CAPACITY_GUARD_PREFLIGHT"

versions="$(jq -c '.identities | with_entries(.value = .value.version)' "$TOOLSET_RUNTIME")"
executables="$(jq -c '.identities' "$TOOLSET_RUNTIME")"

pipeline_corpus="$OUT/raw/candidates-10m.txt"
CAMPAIGN_ID="$STAMP-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
candidate_raw="$OUT/candidate-pipeline.raw.json"
candidate_timing="$OUT/candidate-pipeline.time.json"
candidate_database="$OUT/state/candidate-pipeline.sqlite"
python3 "$ROOT/benchmarks/timed.py" \
  --timeout "$BENCH_PIPELINE_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
  "$candidate_timing" -- \
  "$SUBJECT_BIN" --db "$candidate_database" benchmark candidate-pipeline \
    --wordlist "$pipeline_corpus" --candidates "$BENCH_PIPELINE_CANDIDATES" \
    --batch-size "$BENCH_PIPELINE_BATCH" --concurrency "$BENCH_PIPELINE_CONCURRENCY" \
    --timeout 2 --campaign-id "$CAMPAIGN_ID" --output "$candidate_raw" \
  > "$OUT/logs/candidate-pipeline.stdout" \
  2> "$OUT/logs/candidate-pipeline.stderr" || true
if [[ "$(jq -r '.status' "$candidate_timing")" != "success" || ! -s "$candidate_raw" \
  || ! -s "$pipeline_corpus" ]]; then
  echo "candidate pipeline benchmark failed or is unavailable" >&2
  exit 7
fi

repository_commit="$(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse --verify HEAD)"
repository_dirty=false
[[ -z "$(git -c safe.directory="$ROOT" -C "$ROOT" status --porcelain)" ]] || repository_dirty=true
domains_sha256="$(sha256sum "$OUT/authorized-domains.txt" | awk '{print $1}')"
corpus_archive_sha256="$(sha256sum "$ROOT/data/candidates-1m.txt.zst" | awk '{print $1}')"
corpus_sha256="$(sha256sum "$corpus" | awk '{print $1}')"
pipeline_corpus_sha256="$(sha256sum "$pipeline_corpus" | awk '{print $1}')"
expected_subject_sha256="$(jq -r --arg tool "$SUBJECT" '.[$tool].sha256' <<< "$executables")"
if ! jq -e --arg campaign_id "$CAMPAIGN_ID" \
  --arg wordlist_sha256 "$pipeline_corpus_sha256" \
  --arg binary_sha256 "$expected_subject_sha256" \
  '.campaign_id == $campaign_id and
   .wordlist_sha256 == $wordlist_sha256 and
   .binary_sha256 == $binary_sha256' "$candidate_raw" >/dev/null; then
  echo "candidate pipeline returned mismatched campaign, fixture, or binary provenance" >&2
  exit 7
fi
keys_manifest_sha256=null
if [[ "$MODE" == "equal-keys" ]]; then
  keys_manifest_sha256="\"$(sha256sum "$manifest" | awk '{print $1}')\""
fi
domains_json="$(jq -Rsc 'split("\n") | map(select(length > 0))' "$OUT/authorized-domains.txt")"
baseline_profiles_json="$(printf '%s\n' "${BENCH_PROFILE_BASELINES[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
disk_preflight_json="$(jq -c . "$DISK_PREFLIGHT")"
capacity_guard_preflight_json="$(jq -c . "$CAPACITY_GUARD_PREFLIGHT")"
toolset_snapshot_json="$(jq -c '.snapshot' "$TOOLSET_RUNTIME")"
toolset_sha256="$(jq -r '.sha256' "$TOOLSET_RUNTIME")"
required_tools_json="$(jq -c '.roles.required_tools' "$TOOLSET_RUNTIME")"
dns_controls_json="$(jq -c '
  $root as $document
  | [$document.roles.required_tools[], $document.roles.validator, $document.roles.provenance_only[]]
  | unique
  | map({key: ., value: ($document.snapshot.tools[.].dns_controls // [])})
  | map(select(.value | length > 0))
  | from_entries
' --argjson root "$(jq -c . "$TOOLSET_RUNTIME")" <<< '{}')"
jq -n \
  --arg campaign_id "$CAMPAIGN_ID" \
  --arg mode "$MODE" \
  --argjson started_at "$(date -u +%s)" \
  --argjson versions "$versions" \
  --argjson executables "$executables" \
  --arg subject "$SUBJECT" \
  --arg repository_commit "$repository_commit" \
  --argjson repository_dirty "$repository_dirty" \
  --argjson authorized_domains "$domains_json" \
  --argjson repetitions "$BENCH_REPETITIONS" \
  --argjson active_max_runtime "$BENCH_ACTIVE_MAX_RUNTIME" \
  --argjson discovery_timeout "$BENCH_DISCOVERY_TIMEOUT" \
  --argjson validation_timeout "$BENCH_VALIDATION_TIMEOUT" \
  --argjson transport_timeout "$BENCH_DNS_ENGINE_TIMEOUT" \
  --argjson pipeline_timeout "$BENCH_PIPELINE_TIMEOUT" \
  --argjson timeout_grace "$BENCH_TIMEOUT_GRACE" \
  --argjson dns_rate "$BENCH_DNS_RATE" \
  --argjson dns_concurrency "$BENCH_DNS_CONCURRENCY" \
  --argjson transport_queries "$BENCH_RESOLVER_QUERIES" \
  --argjson transport_concurrency "$BENCH_RESOLVER_CONCURRENCY" \
  --argjson pipeline_candidates "$BENCH_PIPELINE_CANDIDATES" \
  --argjson pipeline_batch "$BENCH_PIPELINE_BATCH" \
  --argjson pipeline_concurrency "$BENCH_PIPELINE_CONCURRENCY" \
  --argjson pipeline_bytes_per_candidate "$BENCH_PIPELINE_BYTES_PER_CANDIDATE" \
  --argjson pipeline_fixed_bytes "$BENCH_PIPELINE_FIXED_BYTES" \
  --argjson pipeline_disk_margin "$BENCH_PIPELINE_DISK_MARGIN_PERCENT" \
  --argjson capacity_guard_headroom "$BENCH_CAPACITY_GUARD_HEADROOM_PERCENT" \
  --argjson baseline_profiles "$baseline_profiles_json" \
  --argjson disk_preflight "$disk_preflight_json" \
  --argjson capacity_guard_preflight "$capacity_guard_preflight_json" \
  --argjson required_tools "$required_tools_json" \
  --argjson dns_controls "$dns_controls_json" \
  --argjson toolset_snapshot "$toolset_snapshot_json" \
  --arg toolset_sha256 "$toolset_sha256" \
  --argjson resolver_count "$RESOLVER_COUNT" \
  --arg resolvers_sha256 "$RESOLVERS_SHA256" \
  --arg domains_sha256 "$domains_sha256" \
  --arg corpus_archive_sha256 "$corpus_archive_sha256" \
  --arg corpus_sha256 "$corpus_sha256" \
  --argjson active_corpus_candidates "$ACTIVE_CORPUS_CANDIDATES" \
  --arg pipeline_corpus_sha256 "$pipeline_corpus_sha256" \
  --argjson keys_manifest_sha256 "$keys_manifest_sha256" \
  --argjson credential_evidence "$credential_evidence" \
  '{
    schema_version: 3,
    campaign_id: $campaign_id,
    mode: $mode,
    started_at: $started_at,
    versions: $versions,
    authorized_domains: $authorized_domains,
    repetitions: $repetitions,
    toolset: {
      campaign: "active",
      sha256: $toolset_sha256,
      snapshot: $toolset_snapshot
    },
    configuration: {
      required_repetitions: $repetitions,
      required_tools: $required_tools,
      subject: $subject,
      subject_active_max_runtime_seconds: $active_max_runtime,
      discovery_timeout_seconds: $discovery_timeout,
      validation_timeout_seconds: $validation_timeout,
      dns_transport_timeout_seconds: $transport_timeout,
      candidate_pipeline_timeout_seconds: $pipeline_timeout,
      timeout_grace_seconds: $timeout_grace,
      dns_rate_limit: $dns_rate,
      dns_concurrency: $dns_concurrency,
      dns_transport_queries: $transport_queries,
      dns_transport_concurrency: $transport_concurrency,
      candidate_pipeline_candidates: $pipeline_candidates,
      candidate_pipeline_batch: $pipeline_batch,
      candidate_pipeline_concurrency: $pipeline_concurrency,
      candidate_pipeline_bytes_per_candidate: $pipeline_bytes_per_candidate,
      candidate_pipeline_fixed_bytes: $pipeline_fixed_bytes,
      candidate_pipeline_disk_margin_percent: $pipeline_disk_margin,
      capacity_guard_headroom_percent: $capacity_guard_headroom,
      subject_profile_baselines: $baseline_profiles,
      subject_cache_mode: "fresh_database_per_run",
      subject_config_mode: "fresh_file_per_run"
    },
    provenance: {
      repository: {commit: $repository_commit, dirty: $repository_dirty},
      executables: $executables,
      inputs: {
        domains_sha256: $domains_sha256,
        active_corpus_archive_sha256: $corpus_archive_sha256,
        active_corpus_sha256: $corpus_sha256,
        active_corpus_candidates: $active_corpus_candidates,
        pipeline_corpus_sha256: $pipeline_corpus_sha256,
        resolvers_sha256: $resolvers_sha256,
        toolset_sha256: $toolset_sha256,
        keys_manifest_sha256: $keys_manifest_sha256
      }
    },
    credentials: $credential_evidence,
    preflight: {
      candidate_pipeline_disk: $disk_preflight,
      capacity_guard: $capacity_guard_preflight
    },
    dns_fairness: {
      rate_limit_qps: $dns_rate,
      concurrency: $dns_concurrency,
      resolver_count: $resolver_count,
      resolvers_sha256: $resolvers_sha256,
      controls: $dns_controls
    }
  }' > "$OUT/manifest.json"

jq --arg status "$(jq -r '.status' "$candidate_timing")" \
  --argjson exit_code "$(jq -r '.exit_code' "$candidate_timing")" \
  --argjson wall_seconds "$(jq -r '.duration_seconds' "$candidate_timing")" \
  --argjson rss "$(jq -r '.max_rss_kib' "$candidate_timing")" \
  --arg campaign_id "$CAMPAIGN_ID" \
  --arg subject_sha256 "$(jq -r --arg tool "$SUBJECT" '.provenance.executables[$tool].sha256' "$OUT/manifest.json")" \
  --arg corpus_sha256 "$pipeline_corpus_sha256" \
  '. + {
    engine_status: (.status // "unknown"),
    status: $status,
    exit_code: $exit_code,
    wall_seconds: $wall_seconds,
    max_rss_kib: $rss,
    campaign_id: (.campaign_id // $campaign_id),
    subject_sha256: $subject_sha256,
    corpus_sha256: $corpus_sha256,
    candidates: (.requested_candidates // .candidates // 0)
  }' "$candidate_raw" > "$OUT/candidate-pipeline.json"
python3 "$ROOT/benchmarks/redact.py" \
  "$OUT/logs/candidate-pipeline.stdout" "$OUT/logs/candidate-pipeline.stderr"
if [[ "$(jq -r '.status' "$candidate_timing")" != "success" ]]; then
  echo "candidate pipeline benchmark failed or is unavailable" >&2
  exit 7
fi

safe_output_path() {
  local candidate="$1" allowed_root="$2"
  python3 - "$candidate" "$allowed_root" <<'PY'
import pathlib
import sys

candidate = pathlib.Path(sys.argv[1]).resolve()
allowed = pathlib.Path(sys.argv[2]).resolve()
try:
    candidate.relative_to(allowed)
except ValueError as exc:
    raise SystemExit(f"toolset output escapes campaign directory: {candidate}") from exc
print(candidate)
PY
}

run_tool() {
  local domain="$1" tool="$2" repetition="$3"
  local subject_profile="${4:-deep}"
  local result_file="${5:-$OUT/summary.jsonl}"
  local benchmark_kind="${6:-qualification}"
  local base="$domain.$tool.r$repetition"
  if [[ "$benchmark_kind" == "subject_profile_baseline" ]]; then
    [[ "$tool" == "$SUBJECT" ]] || {
      echo "profile baselines support only the configured subject" >&2
      return 2
    }
    base="$domain.subject-profile-$subject_profile.r$repetition"
  fi
  local raw="$OUT/raw/$base.txt"
  local normalized="$OUT/raw/$base.normalized.txt"
  local live_raw="$OUT/live/$base.validator.txt"
  local live="$OUT/live/$base.txt"
  local discovery_timing="$OUT/logs/$base.discovery.time.json"
  local validation_timing="$OUT/logs/$base.validation.time.json"
  local discovery_error="$OUT/logs/$base.discovery.stderr"
  local validation_error="$OUT/logs/$base.validation.stderr"
  local discovery_stdout="$OUT/logs/$base.discovery.stdout"
  local validation_stdout="$OUT/logs/$base.validation.stdout"
  local parse_error="$OUT/logs/$base.parse.stderr"
  local historical=null dns_queries=null capture_pid="" capture=""
  local discovery_override="" validation_override=""
  local discovery_values="$OUT/config/$base.active-context.json"
  local validation_values="$OUT/config/$base.validate-context.json"
  local tool_database="$OUT/state/$base.sqlite"
  local tool_config="$OUT/config/$base.json"
  local requested_output="$OUT/raw/$base.tool-output"
  local requested_output_dir="$OUT/raw/$base.tool-output-tree"

  jq -n \
    --arg domain "$domain" --arg target "$domain" \
    --arg output "$requested_output" --arg output_path "$requested_output" \
    --arg output_file "$requested_output" --arg output_dir "$requested_output_dir" \
    --arg database "$tool_database" --arg database_path "$tool_database" \
    --arg config "$tool_config" --arg config_path "$tool_config" \
    --arg profile "$subject_profile" --arg corpus "$corpus" \
    --arg wordlist "$corpus" --arg candidate_corpus "$corpus" \
    --arg resolver_file "$RESOLVERS_FILE" --arg resolvers_file "$RESOLVERS_FILE" \
    --arg trusted_resolver_file "$RESOLVERS_FILE" \
    --arg trusted_resolvers_file "$RESOLVERS_FILE" \
    --arg resolver_csv "$RESOLVERS_CSV" --arg resolvers_csv "$RESOLVERS_CSV" \
    --argjson max_runtime "$BENCH_MAX_RUNTIME" \
    --argjson active_max_runtime "$BENCH_ACTIVE_MAX_RUNTIME" \
    --argjson dns_rate "$BENCH_DNS_RATE" \
    --argjson dns_concurrency "$BENCH_DNS_CONCURRENCY" \
    '{domain:$domain,target:$target,output:$output,output_path:$output_path,
      output_file:$output_file,output_dir:$output_dir,database:$database,
      database_path:$database_path,config:$config,config_path:$config_path,
      profile:$profile,corpus:$corpus,resolver_file:$resolver_file,
      wordlist:$wordlist,candidate_corpus:$candidate_corpus,
      resolvers_file:$resolvers_file,resolver_csv:$resolver_csv,
      trusted_resolver_file:$trusted_resolver_file,
      trusted_resolvers_file:$trusted_resolvers_file,
      resolvers_csv:$resolvers_csv,max_runtime:$max_runtime,
      active_max_runtime:$active_max_runtime,dns_rate:$dns_rate,
      dns_concurrency:$dns_concurrency,rate_limit:$dns_rate,
      concurrency:$dns_concurrency}' > "$discovery_values"

  if command -v tshark >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
    capture="$OUT/logs/$base.pcapng"
    tshark -q -i any -f 'udp port 53 or tcp port 53' -w "$capture" \
      > "$OUT/logs/$base.tshark" 2>&1 &
    capture_pid=$!
    ACTIVE_CAPTURE_PID="$capture_pid"
    sleep 0.2
  fi

  local discovery_output_json discovery_kind discovery_source
  discovery_output_json="$(render_tool_output "$tool" active "$discovery_values")"
  discovery_kind="$(jq -r '.kind' <<< "$discovery_output_json")"
  case "$discovery_kind" in
    line_stdout)
      discovery_source="$requested_output"
      ;;
    line_file|finding_json|dns_event_tree)
      discovery_source="$(jq -r '.path' <<< "$discovery_output_json")"
      discovery_source="$(safe_output_path "$discovery_source" "$OUT/raw")"
      ;;
    *)
      echo "unsupported active output kind for $tool: $discovery_kind" >&2
      return 4
      ;;
  esac
  if [[ "$discovery_kind" == "dns_event_tree" ]]; then
    mkdir -p "$discovery_source"
  else
    mkdir -p "$(dirname -- "$discovery_source")"
  fi
  local active_argv=()
  render_tool_command "$tool" active "$discovery_values" active_argv
  if [[ "$discovery_kind" == "line_stdout" ]]; then
    python3 "$ROOT/benchmarks/timed.py" \
      --timeout "$BENCH_DISCOVERY_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
      "$discovery_timing" -- "${active_argv[@]}" \
      > "$discovery_source" 2> "$discovery_error" || true
    : > "$discovery_stdout"
  else
    python3 "$ROOT/benchmarks/timed.py" \
      --timeout "$BENCH_DISCOVERY_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
      "$discovery_timing" -- "${active_argv[@]}" \
      > "$discovery_stdout" 2> "$discovery_error" || true
  fi

  touch "$parse_error"
  local extracted="$raw"
  case "$discovery_kind" in
    line_stdout|line_file)
      touch "$discovery_source"
      extracted="$discovery_source"
      ;;
    finding_json)
      local finding_metadata="$OUT/logs/$base.finding-metadata.json"
      if python3 "$ROOT/benchmarks/names.py" fellaga "$domain" "$discovery_source" \
        --metadata "$finding_metadata" > "$raw" 2> "$parse_error"; then
        historical="$(jq -r '.historical_names' "$finding_metadata")"
      elif [[ "$(jq -r '.status' "$discovery_timing")" == "success" ]]; then
        discovery_override="error"
      fi
      ;;
    dns_event_tree)
      if ! python3 "$ROOT/benchmarks/names.py" dns-events "$domain" \
        "$discovery_source" > "$raw" 2> "$parse_error"; then
        [[ "$(jq -r '.status' "$discovery_timing")" != "success" ]] || \
          discovery_override="error"
      fi
      ;;
  esac
  touch "$extracted"
  if ! python3 "$ROOT/benchmarks/names.py" normalize "$domain" "$extracted" \
    > "$normalized" 2>> "$parse_error"; then
    [[ "$(jq -r '.status' "$discovery_timing")" != "success" ]] || \
      discovery_override="error"
  fi

  local pre_validation_discovery_status
  pre_validation_discovery_status="${discovery_override:-$(jq -r '.status' "$discovery_timing")}"
  if [[ "$pre_validation_discovery_status" == "success" ]]; then
    local requested_live_output="$OUT/live/$base.validator-output"
    local requested_live_dir="$OUT/live/$base.validator-output-tree"
    jq -n \
      --arg domain "$domain" --arg target "$domain" \
      --arg input "$normalized" --arg input_path "$normalized" \
      --arg input_file "$normalized" \
      --arg output "$requested_live_output" \
      --arg output_path "$requested_live_output" \
      --arg output_file "$requested_live_output" \
      --arg output_dir "$requested_live_dir" \
      --arg resolver_file "$RESOLVERS_FILE" \
      --arg resolvers_file "$RESOLVERS_FILE" \
      --arg trusted_resolver_file "$RESOLVERS_FILE" \
      --arg trusted_resolvers_file "$RESOLVERS_FILE" \
      --arg resolver_csv "$RESOLVERS_CSV" --arg resolvers_csv "$RESOLVERS_CSV" \
      --argjson dns_rate "$BENCH_DNS_RATE" \
      --argjson dns_concurrency "$BENCH_DNS_CONCURRENCY" \
      '{domain:$domain,target:$target,input:$input,input_path:$input_path,
        input_file:$input_file,output:$output,output_path:$output_path,
        output_file:$output_file,output_dir:$output_dir,
        resolver_file:$resolver_file,resolvers_file:$resolvers_file,
        trusted_resolver_file:$trusted_resolver_file,
        trusted_resolvers_file:$trusted_resolvers_file,
        resolver_csv:$resolver_csv,resolvers_csv:$resolvers_csv,
        dns_rate:$dns_rate,dns_concurrency:$dns_concurrency,
        rate_limit:$dns_rate,concurrency:$dns_concurrency}' \
      > "$validation_values"
    local validation_output_json validation_kind validation_source
    validation_output_json="$(render_tool_output "$VALIDATOR" validate "$validation_values")"
    validation_kind="$(jq -r '.kind' <<< "$validation_output_json")"
    case "$validation_kind" in
      line_stdout)
        validation_source="$requested_live_output"
        ;;
      line_file|finding_json|dns_event_tree)
        validation_source="$(jq -r '.path' <<< "$validation_output_json")"
        validation_source="$(safe_output_path "$validation_source" "$OUT/live")"
        ;;
      *)
        echo "unsupported validation output kind: $validation_kind" >&2
        return 4
        ;;
    esac
    if [[ "$validation_kind" == "dns_event_tree" ]]; then
      mkdir -p "$validation_source"
    else
      mkdir -p "$(dirname -- "$validation_source")"
    fi
    local validate_argv=()
    render_tool_command "$VALIDATOR" validate "$validation_values" validate_argv
    if [[ "$validation_kind" == "line_stdout" ]]; then
      python3 "$ROOT/benchmarks/timed.py" \
        --timeout "$BENCH_VALIDATION_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
        "$validation_timing" -- "${validate_argv[@]}" \
        > "$validation_source" 2> "$validation_error" || true
      : > "$validation_stdout"
    else
      python3 "$ROOT/benchmarks/timed.py" \
        --timeout "$BENCH_VALIDATION_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
        "$validation_timing" -- "${validate_argv[@]}" \
        > "$validation_stdout" 2> "$validation_error" || true
    fi
    local validation_extracted="$live_raw"
    case "$validation_kind" in
      line_stdout|line_file)
        touch "$validation_source"
        validation_extracted="$validation_source"
        ;;
      finding_json)
        if ! python3 "$ROOT/benchmarks/names.py" fellaga "$domain" \
          "$validation_source" > "$live_raw" 2>> "$parse_error"; then
          [[ "$(jq -r '.status' "$validation_timing")" != "success" ]] || \
            validation_override="error"
        fi
        ;;
      dns_event_tree)
        if ! python3 "$ROOT/benchmarks/names.py" dns-events "$domain" \
          "$validation_source" > "$live_raw" 2>> "$parse_error"; then
          [[ "$(jq -r '.status' "$validation_timing")" != "success" ]] || \
            validation_override="error"
        fi
        ;;
    esac
    touch "$validation_extracted"
    if ! python3 "$ROOT/benchmarks/names.py" normalize "$domain" "$validation_extracted" \
      > "$live" 2>> "$parse_error"; then
      [[ "$(jq -r '.status' "$validation_timing")" != "success" ]] || \
        validation_override="error"
    fi
  else
    printf '%s\n' \
      '{"duration_seconds":0,"error":null,"exit_code":null,"forced_kill":false,"grace_seconds":0,"interrupted":false,"max_rss_kib":0,"status":"skipped","timeout_seconds":0}' \
      > "$validation_timing"
    : > "$validation_stdout"
    : > "$validation_error"
    : > "$live_raw"
    : > "$live"
  fi

  python3 "$ROOT/benchmarks/redact.py" \
    "$discovery_error" "$validation_error" "$parse_error" \
    "$discovery_stdout" "$validation_stdout"

  if [[ -n "$capture_pid" ]]; then
    stop_capture "$capture_pid"
    ACTIVE_CAPTURE_PID=""
    local query_frames="$OUT/logs/$base.dns-query-frames.txt"
    local tshark_timing="$OUT/logs/$base.tshark-read.time.json"
    python3 "$ROOT/benchmarks/timed.py" --timeout 30 --grace 2 \
      "$tshark_timing" -- \
      tshark -r "$capture" -Y 'dns.flags.response == 0' -T fields -e frame.number \
      > "$query_frames" 2>> "$OUT/logs/$base.tshark" || true
    if [[ "$(jq -r '.status' "$tshark_timing")" == "success" ]]; then
      dns_queries="$(wc -l < "$query_frames")"
    fi
  elif [[ "$tool" == "$SUBJECT" && "$discovery_kind" == "finding_json" ]]; then
    dns_queries="$(
      jq '[.resolver_metrics[]?.requests] | add // 0' "$discovery_source" 2>/dev/null || \
        echo null
    )"
  fi

  local discovery_status validation_status discovery_exit validation_exit
  local discovery_duration validation_duration end_to_end
  local discovery_rss validation_rss max_rss
  discovery_status="${discovery_override:-$(jq -r '.status' "$discovery_timing")}"
  validation_status="${validation_override:-$(jq -r '.status' "$validation_timing")}"
  discovery_exit="$(jq -r '.exit_code' "$discovery_timing")"
  validation_exit="$(jq -r '.exit_code' "$validation_timing")"
  discovery_duration="$(jq -r '.duration_seconds' "$discovery_timing")"
  validation_duration="$(jq -r '.duration_seconds' "$validation_timing")"
  end_to_end="$(
    jq -n --argjson discovery "$discovery_duration" \
      --argjson validation "$validation_duration" '$discovery + $validation'
  )"
  discovery_rss="$(jq -r '.max_rss_kib' "$discovery_timing")"
  validation_rss="$(jq -r '.max_rss_kib' "$validation_timing")"
  if (( discovery_rss >= validation_rss )); then
    max_rss="$discovery_rss"
  else
    max_rss="$validation_rss"
  fi

  jq -nc \
    --arg campaign_id "$CAMPAIGN_ID" \
    --arg domain "$domain" --arg tool "$tool" \
    --arg subject "$SUBJECT" \
    --arg profile "$subject_profile" \
    --arg benchmark_kind "$benchmark_kind" \
    --argjson repetition "$repetition" \
    --arg discovery_status "$discovery_status" \
    --arg validation_status "$validation_status" \
    --argjson status "$discovery_exit" \
    --argjson discovery_exit_code "$discovery_exit" \
    --argjson validation_exit_code "$validation_exit" \
    --argjson duration "$end_to_end" \
    --argjson discovery_duration "$discovery_duration" \
    --argjson validation_duration "$validation_duration" \
    --argjson max_rss_kib "$max_rss" \
    --argjson discovery_max_rss_kib "$discovery_rss" \
    --argjson validation_max_rss_kib "$validation_rss" \
    --argjson raw_names "$(wc -l < "$normalized")" \
    --argjson live_names "$(wc -l < "$live")" \
    --argjson historical_names "$historical" \
    --argjson dns_queries "$dns_queries" \
    --arg raw_output "raw/$base.normalized.txt" \
    --arg live_output "live/$base.txt" \
    --arg discovery_error_log "logs/$base.discovery.stderr" \
    --arg validation_error_log "logs/$base.validation.stderr" \
    --arg parse_error_log "logs/$base.parse.stderr" \
    '{
      campaign_id: $campaign_id,
      domain: $domain,
      tool: $tool,
      profile: (if $tool == $subject then $profile else null end),
      benchmark_kind: $benchmark_kind,
      repetition: $repetition,
      status: $status,
      discovery_status: $discovery_status,
      validation_status: $validation_status,
      discovery_exit_code: $discovery_exit_code,
      validation_exit_code: $validation_exit_code,
      duration_seconds: $duration,
      discovery_duration_seconds: $discovery_duration,
      validation_duration_seconds: $validation_duration,
      end_to_end_duration_seconds: $duration,
      max_rss_kib: $max_rss_kib,
      discovery_max_rss_kib: $discovery_max_rss_kib,
      validation_max_rss_kib: $validation_max_rss_kib,
      raw_names: $raw_names,
      live_names: $live_names,
      historical_names: $historical_names,
      dns_queries: $dns_queries,
      raw_output: $raw_output,
      live_output: $live_output,
      discovery_error_log: $discovery_error_log,
      validation_error_log: $validation_error_log,
      parse_error_log: $parse_error_log
    }' >> "$result_file"
}

tools=("${REQUIRED_TOOLS[@]}")
for (( repetition = 1; repetition <= BENCH_REPETITIONS; repetition++ )); do
  for domain in "${authorized_domains[@]}"; do
    # Rotate the first tool between repetitions to reduce fixed-order bias.
    offset=$(( (repetition - 1) % ${#tools[@]} ))
    for (( index = 0; index < ${#tools[@]}; index++ )); do
      tool="${tools[$(( (index + offset) % ${#tools[@]} ))]}"
      run_tool "$domain" "$tool" "$repetition"
    done
  done
done

if (( ${#BENCH_PROFILE_BASELINES[@]} > 0 )); then
  baseline_results="$OUT/subject-profile-baselines.jsonl"
  : > "$baseline_results"
  for profile in "${BENCH_PROFILE_BASELINES[@]}"; do
    if [[ "$profile" == "deep" ]]; then
      jq -c \
        --arg subject "$SUBJECT" \
        'select(.tool == $subject) | .benchmark_kind = "subject_profile_baseline"' \
        "$OUT/summary.jsonl" >> "$baseline_results"
      continue
    fi
    for (( repetition = 1; repetition <= BENCH_REPETITIONS; repetition++ )); do
      for domain in "${authorized_domains[@]}"; do
        run_tool "$domain" "$SUBJECT" "$repetition" "$profile" \
          "$baseline_results" subject_profile_baseline
      done
    done
  done
fi

dns_timing="$OUT/dns-transport.time.json"
dns_raw="$OUT/dns-transport.raw.json"
python3 "$ROOT/benchmarks/timed.py" \
  --timeout "$BENCH_DNS_ENGINE_TIMEOUT" --grace "$BENCH_TIMEOUT_GRACE" \
  "$dns_timing" -- \
  "$SUBJECT_BIN" resolvers benchmark --queries "$BENCH_RESOLVER_QUERIES" \
    --concurrency "$BENCH_RESOLVER_CONCURRENCY" --output "$dns_raw" \
  > "$OUT/logs/dns-transport.stdout" 2> "$OUT/logs/dns-transport.stderr" || true
[[ -s "$dns_raw" ]] || printf '{}\n' > "$dns_raw"
python3 "$ROOT/benchmarks/redact.py" \
  "$OUT/logs/dns-transport.stdout" "$OUT/logs/dns-transport.stderr"
jq --arg status "$(jq -r '.status' "$dns_timing")" \
  --argjson exit_code "$(jq -r '.exit_code' "$dns_timing")" \
  --argjson elapsed "$(jq -r '.duration_seconds' "$dns_timing")" \
  --argjson rss "$(jq -r '.max_rss_kib' "$dns_timing")" \
  --arg campaign_id "$CAMPAIGN_ID" \
  --arg subject_sha256 "$(jq -r --arg tool "$SUBJECT" '.provenance.executables[$tool].sha256' "$OUT/manifest.json")" \
  '. + {
    status: $status,
    exit_code: $exit_code,
    wall_seconds: $elapsed,
    max_rss_kib: $rss,
    campaign_id: $campaign_id,
    subject_sha256: $subject_sha256
  }' "$dns_raw" > "$OUT/dns-transport.json"

report_args=("$OUT")
if [[ "$BENCH_REQUIRE_PASS" == "1" ]]; then
  report_args=(--require-pass "${report_args[@]}")
fi
python3 "$ROOT/benchmarks/report.py" "${report_args[@]}"
echo "$OUT"
