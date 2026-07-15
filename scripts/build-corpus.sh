#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
seclists=${SECLISTS_ROOT:-/usr/share/seclists}
top="$seclists/Discovery/DNS/subdomains-top1million-110000.txt"
bitquark="$seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
output="$root/data/candidates-1m.txt.zst"

for source in "$top" "$bitquark"; do
  if [[ ! -f "$source" ]]; then
    echo "Source SecLists introuvable: $source" >&2
    exit 1
  fi
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

awk '
  function valid_label(label) {
    return length(label) >= 1 && length(label) <= 63 &&
      label ~ /^[a-z0-9][a-z0-9-]*[a-z0-9]$/
  }
  function valid_name(name, count, parts, i) {
    if (length(name) > 253 || name !~ /^[a-z0-9.-]+$/) return 0
    count = split(name, parts, ".")
    for (i = 1; i <= count; i++) if (!valid_label(parts[i])) return 0
    return 1
  }
  {
    gsub(/\r/, "")
    value=tolower($0)
    if (valid_name(value) && !seen[value]++) print value
  }
' "$top" "$bitquark" > "$tmp/base.txt"

cp "$tmp/base.txt" "$tmp/candidates.txt"
for environment in dev test staging prod qa uat preprod sandbox beta; do
  awk -v env="$environment" '
    {
      split($0, parts, ".")
      first=parts[1] "-" env
      if (length(first) > 63) next
      output=first
      for (i=2; i<=length(parts); i++) output=output "." parts[i]
      print output
    }
  ' "$tmp/base.txt" >> "$tmp/candidates.txt"
done

awk '!seen[$0]++ { print; if (++count == 1000000) exit }' \
  "$tmp/candidates.txt" > "$tmp/candidates-1m.txt"
count=$(wc -l < "$tmp/candidates-1m.txt")
if [[ "$count" -ne 1000000 ]]; then
  echo "Le corpus généré contient $count entrées au lieu de 1000000" >&2
  exit 1
fi

zstd -19 --threads=0 --force "$tmp/candidates-1m.txt" -o "$output"
sha256sum "$output"
