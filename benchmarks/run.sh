#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
DOMAINS_FILE="${2:-}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${BENCH_OUT:-$ROOT/benchmarks/results/$STAMP-$MODE}"
BENCH_MAX_RUNTIME="${FELLAGA_BENCH_MAX_RUNTIME:-1800}"
BENCH_DNS_RATE="${FELLAGA_BENCH_DNS_RATE:-100}"
BENCH_RESOLVER_QUERIES="${FELLAGA_BENCH_RESOLVER_QUERIES:-100000}"
BENCH_RESOLVER_CONCURRENCY="${FELLAGA_BENCH_RESOLVER_CONCURRENCY:-128}"

if [[ "$MODE" != "no-key" && "$MODE" != "equal-keys" ]]; then
  echo "usage: $0 no-key|equal-keys FICHIER_DOMAINES" >&2
  exit 2
fi
[[ "${FELLAGA_BENCH_AUTHORIZED:-}" == "YES" ]] || {
  echo "Définissez FELLAGA_BENCH_AUTHORIZED=YES après vérification écrite du périmètre." >&2
  exit 3
}
[[ -f "$DOMAINS_FILE" ]] || { echo "fichier de domaines absent" >&2; exit 2; }

for command in fellaga subfinder amass bbot puredns dnsx jq zstd python3; do
  command -v "$command" >/dev/null || { echo "prérequis absent: $command" >&2; exit 4; }
done

if [[ "$MODE" == "equal-keys" ]]; then
  manifest="${KEYS_MANIFEST:-}"
  [[ -f "$manifest" ]] || { echo "KEYS_MANIFEST est obligatoire en mode equal-keys" >&2; exit 5; }
  while IFS=$'\t' read -r variable configured; do
    [[ "$configured" == "true" ]] || { echo "$variable non configurée chez tous les concurrents" >&2; exit 5; }
    [[ -n "${!variable:-}" ]] || { echo "variable absente: $variable" >&2; exit 5; }
  done < <(jq -r '.providers[] | [.fellaga_env, (.competitors_configured|tostring)] | @tsv' "$manifest")
fi

mkdir -p "$OUT/raw" "$OUT/live" "$OUT/logs"
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
fi
{
  printf '{"mode":%s,"started_at":%s,"versions":{' "$(jq -Rn --arg v "$MODE" '$v')" "$(date -u +%s)"
  first=1
  for tool in fellaga subfinder amass bbot puredns dnsx; do
    version="$($tool --version 2>&1 | head -n1 || true)"
    [[ $first -eq 1 ]] || printf ','
    first=0
    printf '%s:%s' "$(jq -Rn --arg v "$tool" '$v')" "$(jq -Rn --arg v "$version" '$v')"
  done
  printf '}}\n'
} > "$OUT/manifest.json"

run_tool() {
  local domain="$1" tool="$2"
  local raw="$OUT/raw/$domain.$tool.txt"
  local timing="$OUT/logs/$domain.$tool.time" error="$OUT/logs/$domain.$tool.stderr"
  local status=0 historical=null dns_queries=null capture_pid=""
  local capture="$OUT/logs/$domain.$tool.pcapng"
  if command -v tshark >/dev/null 2>&1 && [[ "$(id -u)" -eq 0 ]]; then
    tshark -q -i any -f 'udp port 53 or tcp port 53' -w "$capture" \
      >"$OUT/logs/$domain.$tool.tshark" 2>&1 &
    capture_pid=$!
    sleep 0.2
  fi
  case "$tool" in
    fellaga)
      python3 "$ROOT/benchmarks/timed.py" "$timing" fellaga scan "$domain" \
        --profile deep --max-runtime "$BENCH_MAX_RUNTIME" \
        --dns-rate-limit "$BENCH_DNS_RATE" --json \
        >"$raw.json" 2>"$error" || status=$?
      jq -r '.findings[]? | select(.state == "live") | .fqdn' "$raw.json" 2>/dev/null | sort -u >"$raw" || true
      historical="$(jq '[.findings[]? | select(.state == "historical")] | length' "$raw.json" 2>/dev/null || echo 0)"
      ;;
    subfinder)
      python3 "$ROOT/benchmarks/timed.py" "$timing" subfinder -silent -all -d "$domain" -o "$raw" 2>"$error" || status=$?
      ;;
    amass)
      python3 "$ROOT/benchmarks/timed.py" "$timing" amass enum -active -d "$domain" -o "$raw" 2>"$error" || status=$?
      ;;
    bbot)
      local directory="$OUT/raw/$domain.bbot"
      python3 "$ROOT/benchmarks/timed.py" "$timing" bbot -y -t "$domain" -p subdomain-enum -o "$directory" 2>"$error" || status=$?
      find "$directory" -type f -name '*.txt' -print0 2>/dev/null | xargs -0 -r cat | grep -Eo "([[:alnum:]-]+\.)+$domain" | sort -u >"$raw" || true
      ;;
    puredns)
      local corpus="$OUT/raw/candidates-1m.txt"
      [[ -f "$corpus" ]] || zstd -dc "$ROOT/data/candidates-1m.txt.zst" > "$corpus"
      python3 "$ROOT/benchmarks/timed.py" "$timing" puredns bruteforce "$corpus" "$domain" --write "$raw" 2>"$error" || status=$?
      ;;
  esac
  if [[ -n "$capture_pid" ]]; then
    kill -INT "$capture_pid" >/dev/null 2>&1 || true
    wait "$capture_pid" 2>/dev/null || true
    dns_queries="$(tshark -r "$capture" -Y 'dns.flags.response == 0' -T fields -e frame.number 2>/dev/null | wc -l)"
  elif [[ "$tool" == "fellaga" ]]; then
    dns_queries="$(jq '[.resolver_metrics[]?.requests] | add // 0' "$raw.json" 2>/dev/null || echo null)"
  fi
  touch "$raw"
  sed -E 's/^\*\.//' "$raw" | tr '[:upper:]' '[:lower:]' | grep -E "\.$domain$" | sort -u >"$raw.normalized" || true
  dnsx -silent -l "$raw.normalized" -o "$OUT/live/$domain.$tool.txt" 2>>"$error" || true
  read -r elapsed rss < "$timing" || { elapsed=0; rss=0; }
  jq -nc --arg domain "$domain" --arg tool "$tool" --argjson status "$status" \
    --argjson duration "$elapsed" --argjson max_rss_kib "$rss" \
    --argjson raw_names "$(wc -l < "$raw.normalized")" \
    --argjson live_names "$(wc -l < "$OUT/live/$domain.$tool.txt")" \
    --argjson historical_names "$historical" \
    --argjson dns_queries "$dns_queries" \
    --arg error "$(tail -n 20 "$error" 2>/dev/null || true)" \
    '{domain:$domain,tool:$tool,status:$status,duration_seconds:$duration,max_rss_kib:$max_rss_kib,raw_names:$raw_names,live_names:$live_names,historical_names:$historical_names,dns_queries:$dns_queries,error:$error}' \
    >> "$OUT/summary.jsonl"
}

while IFS= read -r domain; do
  domain="${domain%%#*}"
  domain="$(echo "$domain" | xargs | tr '[:upper:]' '[:lower:]')"
  [[ "$domain" =~ ^[a-z0-9.-]+\.[a-z]{2,}$ ]] || continue
  for tool in fellaga subfinder amass bbot puredns; do
    run_tool "$domain" "$tool"
  done
done < "$DOMAINS_FILE"

python3 "$ROOT/benchmarks/timed.py" "$OUT/dns-engine.time" \
  fellaga resolvers benchmark --queries "$BENCH_RESOLVER_QUERIES" \
  --concurrency "$BENCH_RESOLVER_CONCURRENCY" \
  --output "$OUT/dns-engine.json" >/dev/null
read -r dns_elapsed dns_rss < "$OUT/dns-engine.time"
jq --argjson elapsed "$dns_elapsed" --argjson rss "$dns_rss" \
  '. + {wall_seconds:$elapsed,max_rss_kib:$rss}' "$OUT/dns-engine.json" \
  > "$OUT/dns-engine.json.tmp"
mv "$OUT/dns-engine.json.tmp" "$OUT/dns-engine.json"
python3 "$ROOT/benchmarks/report.py" "$OUT"
echo "$OUT"
