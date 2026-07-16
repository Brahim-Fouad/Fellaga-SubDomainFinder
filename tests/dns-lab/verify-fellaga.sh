#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fellaga_bin="${1:?usage: verify-fellaga.sh /path/to/fellaga}"
temporary="$(mktemp -d)"
cleanup() {
  local status=$?
  trap - EXIT
  if [[ "${FELLAGA_DNS_LAB_KEEP:-0}" == "1" ]]; then
    echo "Fellaga DNS lab artifacts retained in $temporary" >&2
  else
    rm -rf -- "$temporary"
  fi
  exit "$status"
}
trap cleanup EXIT

run_scan() {
  local target="$1" output="$2"
  local log="$temporary/${target}.log"
  local stdout="$temporary/${target}.stdout"
  local command_file="$temporary/${target}.command"
  local -a command=(
    env "XDG_CONFIG_HOME=$temporary/config"
    "$fellaga_bin"
    --db "$temporary/fellaga.db"
    --config "$temporary/config/config.json"
    scan "$target"
    --profile balanced
    --wordlist "$root/cli-wordlist.txt"
    --max-words 3
    --no-passive
    --no-ct-monitor
    --no-web
    --no-tls
    --no-dns-graph
    --no-service-discovery
    --no-ptr
    --no-nsec
    --no-pipeline
    --depth 1
    --resolvers 127.0.0.1
    --trusted-resolvers 127.0.0.1
    --timeout 1
    --concurrency 32
    --dns-rate-limit 0
    --axfr-timeout 3
    --max-runtime 30
    --checkpoint-every 1
    --json
    --quiet
    --output "$output"
  )
  printf '%q ' "${command[@]}" >"$command_file"
  printf '\n' >>"$command_file"
  if ! "${command[@]}" >"$stdout" 2>"$log"; then
    echo "Fellaga DNS laboratory scan failed for $target" >&2
    echo "Command: $(<"$command_file")" >&2
    cat "$log" >&2
    return 1
  fi
}

lab_result="$temporary/lab.test.json"
refused_result="$temporary/refused.lab.test.json"
run_scan lab.test "$lab_result"
run_scan refused.lab.test "$refused_result"

python3 - "$lab_result" "$refused_result" "$temporary/fellaga.db" <<'PY'
import json
import sqlite3
import sys

lab_path, refused_path, database_path = sys.argv[1:]
with open(lab_path, encoding="utf-8") as handle:
    lab = json.load(handle)
with open(refused_path, encoding="utf-8") as handle:
    refused = json.load(handle)

findings = {finding["fqdn"]: finding for finding in lab["findings"]}
with sqlite3.connect(database_path) as connection:
    wildcard_rows = connection.execute(
        "SELECT zone, signature_json FROM wildcard_cache ORDER BY zone"
    ).fetchall()

assert lab["wildcard_detected"] is True, "root wildcard was not detected"
assert "does-not-exist.lab.test" not in findings, (
    "a candidate matching the wildcard leaked into final findings"
)

www = findings.get("www.lab.test")
assert www is not None, "the unique www record was removed with wildcard matches"
assert www["state"] == "live", (
    "the unique www record was not validated live: "
    f"finding={www!r}, wildcard_cache={wildcard_rows!r}"
)
assert www["wildcard"] is False, "the unique www record was marked as wildcard"
assert any(
    record["record_type"] == "A" and record["value"] == "192.0.2.10"
    for record in www["records"]
), "the unique www A record is missing"

api = findings.get("api.lab.test")
assert api is not None, "the unique AAAA-only api record was removed"
assert api["state"] == "live" and api["wildcard"] is False
assert any(
    record["record_type"] == "AAAA" and record["value"] == "2001:db8::10"
    for record in api["records"]
), "the unique api AAAA record is missing"

successful = [
    attempt for attempt in lab["axfr_attempts"]
    if attempt["status"] == "success"
]
assert successful, "the complete AXFR was not classified as success"
assert "www.lab.test" in successful[0]["names"]

statuses = {attempt["status"] for attempt in refused["axfr_attempts"]}
assert "refused" in statuses, (
    "the refused AXFR was not classified as refused: "
    f"attempts={refused['axfr_attempts']!r}"
)

print(
    "Fellaga CLI DNS lab: unique wildcard exceptions retained, wildcard "
    "matches suppressed, complete/refused AXFR statuses validated"
)
PY
