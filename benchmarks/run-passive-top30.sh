#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="$ROOT/benchmarks/passive_top30_report.py"
NAMES="$ROOT/benchmarks/names.py"
TIMED="$ROOT/benchmarks/timed.py"
REDACT="$ROOT/benchmarks/redact.py"
SOURCE_CSV="$ROOT/benchmarks/data/tranco-74J5X-top30.csv"

REPETITIONS="${FELLAGA_PASSIVE_TOP30_REPETITIONS:-1}"
DISCOVERY_TIMEOUT="${FELLAGA_PASSIVE_TOP30_TIMEOUT:-180}"
TIMEOUT_GRACE="${FELLAGA_PASSIVE_TOP30_TIMEOUT_GRACE:-5}"
PREFLIGHT_TIMEOUT="${FELLAGA_PASSIVE_TOP30_PREFLIGHT_TIMEOUT:-${FELLAGA_PASSIVE_TOP30_BBOT_PREFLIGHT_TIMEOUT:-60}}"
CAMPAIGN_MAX_RUNTIME="${FELLAGA_PASSIVE_TOP30_MAX_RUNTIME:-7200}"
COOLDOWN="${FELLAGA_PASSIVE_TOP30_COOLDOWN:-1}"
FAILURE_THRESHOLD="${FELLAGA_PASSIVE_TOP30_FAILURE_THRESHOLD:-3}"
SUBFINDER_RATE_LIMIT="${FELLAGA_PASSIVE_TOP30_SUBFINDER_RATE_LIMIT:-5}"
FELLAGA_PASSIVE_CONCURRENCY="${FELLAGA_PASSIVE_TOP30_FELLAGA_CONCURRENCY:-4}"
CLEANUP_TIMEOUT="${FELLAGA_PASSIVE_TOP30_CLEANUP_TIMEOUT:-60}"
REDACTION_TIMEOUT="${FELLAGA_PASSIVE_TOP30_REDACTION_TIMEOUT:-60}"
MAX_FILE_BYTES="${FELLAGA_PASSIVE_TOP30_MAX_FILE_BYTES:-268435456}"
MAX_CAMPAIGN_FILES="${FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_FILES:-50000}"
MAX_CAMPAIGN_BYTES="${FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_BYTES:-2147483648}"
OUT="${FELLAGA_PASSIVE_TOP30_OUT:-$ROOT/benchmarks/results/passive-top30-$(date -u +%Y%m%dT%H%M%SZ)}"

integer_between() {
  local value="$1" minimum="$2" maximum="$3" label="$4"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < minimum || value > maximum )); then
    echo "$label must be an integer between $minimum and $maximum" >&2
    exit 2
  fi
}

positive_number() {
  local value="$1" label="$2"
  if ! python3 - "$value" <<'PY'
import math
import sys

try:
    value = float(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if math.isfinite(value) and value > 0 else 1)
PY
  then
    echo "$label must be a finite number greater than zero" >&2
    exit 2
  fi
}

command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required" >&2
  exit 2
}
integer_between "$REPETITIONS" 1 10 FELLAGA_PASSIVE_TOP30_REPETITIONS
integer_between "$DISCOVERY_TIMEOUT" 1 3600 FELLAGA_PASSIVE_TOP30_TIMEOUT
positive_number "$TIMEOUT_GRACE" FELLAGA_PASSIVE_TOP30_TIMEOUT_GRACE
integer_between "$PREFLIGHT_TIMEOUT" 1 600 FELLAGA_PASSIVE_TOP30_PREFLIGHT_TIMEOUT
integer_between "$CAMPAIGN_MAX_RUNTIME" 60 86400 FELLAGA_PASSIVE_TOP30_MAX_RUNTIME
integer_between "$COOLDOWN" 1 60 FELLAGA_PASSIVE_TOP30_COOLDOWN
integer_between "$FAILURE_THRESHOLD" 1 10 FELLAGA_PASSIVE_TOP30_FAILURE_THRESHOLD
integer_between "$SUBFINDER_RATE_LIMIT" 1 20 FELLAGA_PASSIVE_TOP30_SUBFINDER_RATE_LIMIT
integer_between "$FELLAGA_PASSIVE_CONCURRENCY" 1 8 FELLAGA_PASSIVE_TOP30_FELLAGA_CONCURRENCY
integer_between "$CLEANUP_TIMEOUT" 1 60 FELLAGA_PASSIVE_TOP30_CLEANUP_TIMEOUT
integer_between "$REDACTION_TIMEOUT" 1 60 FELLAGA_PASSIVE_TOP30_REDACTION_TIMEOUT
integer_between "$MAX_FILE_BYTES" 1048576 1073741824 FELLAGA_PASSIVE_TOP30_MAX_FILE_BYTES
integer_between "$MAX_CAMPAIGN_FILES" 1000 1000000 FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_FILES
integer_between "$MAX_CAMPAIGN_BYTES" 67108864 107374182400 FELLAGA_PASSIVE_TOP30_MAX_CAMPAIGN_BYTES

if [[ -e "$OUT" ]]; then
  echo "passive top-30 output already exists: $OUT" >&2
  exit 6
fi

python3 "$REPORT" verify-source >/dev/null
mkdir -p "$OUT"/{logs,names,preflight,raw,state}

# Fellaga and Amass protect their private configuration with POSIX modes.
# Windows-mounted WSL filesystems can reject chmod even though normal writes
# succeed, so fail before any real-domain provider request is attempted.
if ! python3 - "$OUT" <<'PY'
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
probe = root / ".posix-mode-probe"
compatible = True
try:
    probe.mkdir(mode=0o700)
    probe.chmod(0o700)
    if stat.S_IMODE(probe.stat().st_mode) != 0o700:
        raise OSError("output filesystem does not preserve mode 0700")
    probe.chmod(0o750)
    if stat.S_IMODE(probe.stat().st_mode) != 0o750:
        raise OSError("output filesystem does not preserve mode 0750")
except OSError:
    compatible = False
finally:
    try:
        probe.rmdir()
    except OSError:
        pass
raise SystemExit(0 if compatible else 1)
PY
then
  echo "passive top-30 output must be on a POSIX-permission filesystem; use a Linux path under WSL" >&2
  exit 6
fi

# Invoked through the EXIT trap below.
# shellcheck disable=SC2329
finalize_campaign() {
  local original_exit=$?
  local cleanup_exit=0
  local redaction_exit=0
  local report_exit=0
  trap - EXIT
  if python3 "$TIMED" --timeout "$CLEANUP_TIMEOUT" --grace "$TIMEOUT_GRACE" \
    --max-file-bytes "$MAX_FILE_BYTES" \
    "$OUT/cleanup.timing.json" -- python3 "$REPORT" cleanup-all "$OUT" \
    >/dev/null 2>&1; then
    printf 'complete\n' > "$OUT/cleanup.status"
  else
    printf 'failed\n' > "$OUT/cleanup.status"
    echo "passive top-30 ephemeral cleanup failed: $OUT" >&2
    cleanup_exit=10
  fi
  if python3 "$TIMED" --timeout "$REDACTION_TIMEOUT" --grace "$TIMEOUT_GRACE" \
    --max-file-bytes "$MAX_FILE_BYTES" \
    "$OUT/redaction.timing.json" -- python3 "$REDACT" \
    "$OUT/logs" "$OUT/preflight" "$OUT/raw" >/dev/null 2>&1; then
    printf 'complete\n' > "$OUT/redaction.status"
  else
    printf 'failed\n' > "$OUT/redaction.status"
    echo "passive top-30 artifact redaction failed: $OUT" >&2
    redaction_exit=9
  fi
  if [[ -f "$OUT/manifest.json" ]]; then
    python3 "$REPORT" report "$OUT" --output "$OUT/report.json" \
      --require-complete >/dev/null || report_exit=$?
    if [[ -f "$OUT/report.json" ]] && (( report_exit == 0 || report_exit == 3 )); then
      echo "descriptive passive report: $OUT/report.json"
    else
      echo "[passive-top30] report generation failed" >&2
    fi
    if (( report_exit == 3 )); then
      echo "[passive-top30] campaign incomplete or invalid; see report.json" >&2
    fi
  fi
  if (( original_exit != 0 )); then
    exit "$original_exit"
  fi
  if (( cleanup_exit != 0 )); then
    exit "$cleanup_exit"
  fi
  if (( redaction_exit != 0 )); then
    exit "$redaction_exit"
  fi
  exit "$report_exit"
}
trap finalize_campaign EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

declare -A tool_bins=()
declare -a runnable_args=()
declare -a missing_args=()
declare -a skipped_args=()
declare -a runnable_tools=()
ISOLATED_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

resolve_tool() {
  local tool="$1" variable="$2" override="" executable=""
  override="${!variable-}"
  if [[ -n "$override" ]]; then
    if [[ -x "$override" && ! -d "$override" ]]; then
      executable="$override"
    else
      missing_args+=(--missing "$tool=configured_executable_not_found")
      return
    fi
  else
    executable="$(command -v "$tool" 2>/dev/null || true)"
    if [[ -z "$executable" ]]; then
      missing_args+=(--missing "$tool=executable_not_found")
      return
    fi
  fi
  executable="$(python3 - "$executable" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).resolve(strict=True))
PY
)"
  if [[ ! -x "$executable" || -d "$executable" ]]; then
    missing_args+=(--missing "$tool=resolved_executable_not_found")
    return
  fi
  tool_bins["$tool"]="$executable"
}

resolve_tool fellaga FELLAGA_PASSIVE_TOP30_FELLAGA_BIN
resolve_tool subfinder FELLAGA_PASSIVE_TOP30_SUBFINDER_BIN
resolve_tool amass FELLAGA_PASSIVE_TOP30_AMASS_BIN
resolve_tool bbot FELLAGA_PASSIVE_TOP30_BBOT_BIN

standard_preflight() {
  local tool="$1"
  local directory="$OUT/preflight/$tool"
  local exit_code=0
  local pattern
  local -a command=()
  local -a required_patterns=()
  mkdir -p "$directory"/{home,config,data,cache,state}
  case "$tool" in
    fellaga)
      command=("${tool_bins[$tool]}" scan --help)
      required_patterns=(--profile --no-target-contact --all-sources --show --passive-concurrency)
      ;;
    subfinder)
      command=("${tool_bins[$tool]}" -duc -h)
      required_patterns=(-duc -all -rl -d)
      ;;
    amass)
      command=("${tool_bins[$tool]}" enum -h)
      required_patterns=(-passive -config -d)
      ;;
    *)
      return 2
      ;;
  esac
  python3 "$TIMED" \
    --timeout "$PREFLIGHT_TIMEOUT" --grace "$TIMEOUT_GRACE" \
    --max-file-bytes "$MAX_FILE_BYTES" \
    "$directory/timing.json" -- \
    env -i -- \
      "PATH=$ISOLATED_PATH" "LANG=C.UTF-8" "LC_ALL=C.UTF-8" \
      "TZ=UTC" "NO_COLOR=1" \
      "HOME=$directory/home" \
      "XDG_CONFIG_HOME=$directory/config" \
      "XDG_DATA_HOME=$directory/data" \
      "XDG_CACHE_HOME=$directory/cache" \
      "XDG_STATE_HOME=$directory/state" \
      "${command[@]}" \
    > "$directory/stdout.txt" 2> "$directory/stderr.txt" || exit_code=$?
  if ! python3 "$REDACT" "$directory" >/dev/null 2>&1; then
    echo "passive top-30 preflight redaction failed: $tool" >&2
    return 9
  fi
  if (( exit_code != 0 )); then
    skipped_args+=(--skipped "$tool=help_preflight_failed")
    unset "tool_bins[$tool]"
    return
  fi
  for pattern in "${required_patterns[@]}"; do
    if ! grep -Fq -- "$pattern" "$directory/stdout.txt" "$directory/stderr.txt"; then
      skipped_args+=(--skipped "$tool=required_flag_missing")
      unset "tool_bins[$tool]"
      return
    fi
  done
  runnable_tools+=("$tool")
  runnable_args+=(--runnable "$tool=${tool_bins[$tool]}")
}

for tool in fellaga subfinder amass; do
  if [[ -n "${tool_bins[$tool]+present}" ]]; then
    standard_preflight "$tool"
  fi
done

if [[ -n "${tool_bins[bbot]+present}" ]]; then
  bbot_preflight="$OUT/preflight/bbot"
  mkdir -p "$bbot_preflight"/{home,config,data,cache,state,output}
  declare -a bbot_preflight_env=(
    env -i
    --
    "PATH=$ISOLATED_PATH"
    "LANG=C.UTF-8"
    "LC_ALL=C.UTF-8"
    "TZ=UTC"
    "NO_COLOR=1"
    "HOME=$bbot_preflight/home"
    "XDG_CONFIG_HOME=$bbot_preflight/config"
    "XDG_DATA_HOME=$bbot_preflight/data"
    "XDG_CACHE_HOME=$bbot_preflight/cache"
    "XDG_STATE_HOME=$bbot_preflight/state"
  )
  preflight_exit=0
  python3 "$TIMED" \
    --timeout "$PREFLIGHT_TIMEOUT" --grace "$TIMEOUT_GRACE" \
    --max-file-bytes "$MAX_FILE_BYTES" \
    "$bbot_preflight/timing.json" -- \
    "${bbot_preflight_env[@]}" "${tool_bins[bbot]}" -y -t example.invalid \
      -f subdomain-enum -rf passive \
      -c dns.disable=true speculate=false \
      -om json -o "$bbot_preflight/output" --dry-run \
    > "$bbot_preflight/stdout.txt" 2> "$bbot_preflight/stderr.txt" || preflight_exit=$?
  if ! python3 "$REDACT" "$bbot_preflight" >/dev/null 2>&1; then
    echo "passive top-30 preflight redaction failed: bbot" >&2
    exit 9
  fi
  bbot_preflight_semantic_error=0
  if grep -Eiq '\[ERRR\]|dnsresolve[^[:cntrl:]]*(is required|required)|required[^[:cntrl:]]*dnsresolve' \
    "$bbot_preflight/stdout.txt" "$bbot_preflight/stderr.txt"; then
    bbot_preflight_semantic_error=1
  fi
  if (( preflight_exit == 0 && bbot_preflight_semantic_error == 0 )); then
    runnable_tools+=(bbot)
    runnable_args+=(--runnable "bbot=${tool_bins[bbot]}")
  else
    if (( bbot_preflight_semantic_error != 0 )); then
      skipped_args+=(--skipped "bbot=no_dns_preflight_semantic_error")
    else
      skipped_args+=(--skipped "bbot=no_dns_preflight_failed")
    fi
    unset 'tool_bins[bbot]'
  fi
fi

python3 "$REPORT" prepare "$OUT" --repetitions "$REPETITIONS" \
  --discovery-timeout "$DISCOVERY_TIMEOUT" \
  --timeout-grace "$TIMEOUT_GRACE" \
  --preflight-timeout "$PREFLIGHT_TIMEOUT" \
  --campaign-max-runtime "$CAMPAIGN_MAX_RUNTIME" \
  --cooldown "$COOLDOWN" \
  --failure-threshold "$FAILURE_THRESHOLD" \
  --subfinder-rate-limit "$SUBFINDER_RATE_LIMIT" \
  --fellaga-passive-concurrency "$FELLAGA_PASSIVE_CONCURRENCY" \
  --cleanup-timeout "$CLEANUP_TIMEOUT" \
  --redaction-timeout "$REDACTION_TIMEOUT" \
  --max-file-bytes "$MAX_FILE_BYTES" \
  --campaign-max-files "$MAX_CAMPAIGN_FILES" \
  --campaign-max-bytes "$MAX_CAMPAIGN_BYTES" \
  "${runnable_args[@]}" "${missing_args[@]}" "${skipped_args[@]}"

python3 "$REPORT" quota-check "$OUT" >/dev/null

run_one() {
  local tool="$1" rank="$2" domain="$3" repetition="$4"
  local base
  base="$(printf '%02d' "$rank")-$domain.$tool.r$repetition"
  local timing="$OUT/logs/$base.timing.json"
  local stdout="$OUT/raw/$base.stdout.txt"
  local stderr="$OUT/logs/$base.stderr.txt"
  local parser_stderr="$OUT/logs/$base.parser.stderr.txt"
  local raw_tree="$OUT/logs/$base.raw-tree.json"
  local raw_tree_directory="$OUT/raw/$base.extra"
  local names="$OUT/names/$base.txt"
  local parse_status=success
  local isolation="$OUT/isolation/$base"
  mkdir -p "$isolation"/{home,config,data,cache,state}
  mkdir -p "$raw_tree_directory"
  local -a isolated_env=(
    env -i
    --
    "PATH=$ISOLATED_PATH"
    "LANG=C.UTF-8"
    "LC_ALL=C.UTF-8"
    "TZ=UTC"
    "NO_COLOR=1"
    "HOME=$isolation/home"
    "XDG_CONFIG_HOME=$isolation/config"
    "XDG_DATA_HOME=$isolation/data"
    "XDG_CACHE_HOME=$isolation/cache"
    "XDG_STATE_HOME=$isolation/state"
  )

  : > "$stdout"
  : > "$stderr"
  : > "$parser_stderr"
  : > "$names"

  # Fail before execution if the binary (or BBOT package tree) changed after
  # the isolated preflight and campaign manifest were created.
  python3 "$REPORT" verify-tool "$OUT" "$tool"

  case "$tool" in
    fellaga)
      python3 "$TIMED" \
        --timeout "$current_run_timeout" --grace "$TIMEOUT_GRACE" \
        --max-file-bytes "$MAX_FILE_BYTES" \
        "$timing" -- \
        "${isolated_env[@]}" "${tool_bins[fellaga]}" \
          --db "$OUT/state/$base.sqlite" \
          scan --profile passive --no-target-contact --all-sources \
          --passive-concurrency "$FELLAGA_PASSIVE_CONCURRENCY" \
          --passive-zone-concurrency 1 --show "$domain" \
        > "$stdout" 2> "$stderr" || true
      if ! python3 "$NAMES" normalize-observational "$domain" "$stdout" \
        > "$names" 2> "$parser_stderr"; then
        parse_status=error
      fi
      ;;
    subfinder)
      python3 "$TIMED" \
        --timeout "$current_run_timeout" --grace "$TIMEOUT_GRACE" \
        --max-file-bytes "$MAX_FILE_BYTES" \
        "$timing" -- \
        "${isolated_env[@]}" "${tool_bins[subfinder]}" \
          -silent -duc -all -rl "$SUBFINDER_RATE_LIMIT" -d "$domain" \
        > "$stdout" 2> "$stderr" || true
      if ! python3 "$NAMES" normalize-observational "$domain" "$stdout" \
        > "$names" 2> "$parser_stderr"; then
        parse_status=error
      fi
      ;;
    amass)
      python3 "$TIMED" \
        --timeout "$current_run_timeout" --grace "$TIMEOUT_GRACE" \
        --max-file-bytes "$MAX_FILE_BYTES" \
        "$timing" -- \
        "${isolated_env[@]}" "${tool_bins[amass]}" \
          enum -passive -config /dev/null -d "$domain" \
        > "$stdout" 2> "$stderr" || true
      if ! python3 "$NAMES" normalize-observational "$domain" "$stdout" \
        > "$names" 2> "$parser_stderr"; then
        parse_status=error
      fi
      ;;
    bbot)
      local directory="$raw_tree_directory"
      python3 "$TIMED" \
        --timeout "$current_run_timeout" --grace "$TIMEOUT_GRACE" \
        --max-file-bytes "$MAX_FILE_BYTES" \
        "$timing" -- \
        "${isolated_env[@]}" "${tool_bins[bbot]}" -y -t "$domain" \
          -f subdomain-enum -rf passive \
          -c dns.disable=true speculate=false \
          -om json -o "$directory" \
        > "$stdout" 2> "$stderr" || true
      if ! python3 "$NAMES" bbot-observational "$domain" "$directory" \
        > "$names" 2> "$parser_stderr"; then
        parse_status=error
      fi
      ;;
    *)
      echo "unsupported passive tool: $tool" >&2
      return 2
      ;;
  esac

  if ! python3 "$REDACT" "$stdout" "$stderr" "$parser_stderr" \
    "$raw_tree_directory" >/dev/null 2>&1; then
    echo "passive top-30 per-run redaction failed: $base" >&2
    return 9
  fi
  python3 "$REPORT" tree-manifest "$OUT" "$raw_tree_directory" "$raw_tree"
  python3 "$REPORT" record "$OUT" \
    --tool "$tool" --domain "$domain" --rank "$rank" --repetition "$repetition" \
    --timing "$timing" --names "$names" --stdout "$stdout" --stderr "$stderr" \
    --parser-stderr "$parser_stderr" --raw-tree "$raw_tree" \
    --parse-status "$parse_status"
  IFS=$'\t' read -r last_run_status last_run_duration last_run_names < <(
    python3 - "$timing" "$names" "$parse_status" <<'PY'
import json
import pathlib
import sys

timing = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
names = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
status = timing["status"] if timing["status"] != "success" else sys.argv[3]
print(f"{status}\t{float(timing['duration_seconds']):.3f}\t{len(names)}")
PY
  )
  python3 "$REPORT" cleanup-run "$OUT" "$isolation" "$OUT/state/$base.sqlite"
  python3 "$REPORT" quota-check "$OUT" >/dev/null
}

tool_count="${#runnable_tools[@]}"
completed_runs=0
total_runs=$((REPETITIONS * tool_count * 30))
campaign_started_epoch="$(date +%s)"
declare -A failure_streak=()
declare -A disabled_tools=()
for (( repetition = 1; repetition <= REPETITIONS; repetition++ )); do
  while IFS=, read -r rank domain; do
    declare -a ordered_tools=()
    if (( tool_count > 0 )); then
      offset=$(( (rank - 1 + repetition - 1) % tool_count ))
      for (( index = 0; index < tool_count; index++ )); do
        ordered_tools+=("${runnable_tools[$(( (index + offset) % tool_count ))]}")
      done
    fi
    for tool in "${ordered_tools[@]}"; do
      if [[ -n "${disabled_tools[$tool]+disabled}" ]]; then
        continue
      fi
      elapsed=$(( $(date +%s) - campaign_started_epoch ))
      remaining=$(( CAMPAIGN_MAX_RUNTIME - elapsed ))
      if (( remaining <= 0 )); then
        echo "[passive-top30] campaign deadline reached after ${elapsed}s" >&2
        break 3
      fi
      current_run_timeout="$DISCOVERY_TIMEOUT"
      if (( remaining < current_run_timeout )); then
        current_run_timeout="$remaining"
      fi
      next_run=$((completed_runs + 1))
      printf '[passive-top30] start %d/%d repetition=%d rank=%s tool=%s domain=%s\n' \
        "$next_run" "$total_runs" "$repetition" "$rank" "$tool" "$domain" >&2
      run_one "$tool" "$rank" "$domain" "$repetition"
      completed_runs="$next_run"
      printf '[passive-top30] complete %d/%d tool=%s domain=%s status=%s duration=%ss names=%s\n' \
        "$completed_runs" "$total_runs" "$tool" "$domain" \
        "$last_run_status" "$last_run_duration" "$last_run_names" >&2
      if [[ "$last_run_status" == success ]]; then
        failure_streak["$tool"]=0
      else
        failure_streak["$tool"]=$(( ${failure_streak[$tool]:-0} + 1 ))
        if (( failure_streak[$tool] >= FAILURE_THRESHOLD )); then
          disabled_tools["$tool"]=1
          printf '[passive-top30] circuit breaker tool=%s consecutive_failures=%d\n' \
            "$tool" "${failure_streak[$tool]}" >&2
        fi
      fi
      sleep "$COOLDOWN"
    done
  done < "$SOURCE_CSV"
done

exit 0
