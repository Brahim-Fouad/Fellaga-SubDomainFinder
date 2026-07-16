#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
seclists=${SECLISTS_ROOT:-/usr/share/seclists}
top="$seclists/Discovery/DNS/subdomains-top1million-110000.txt"
bitquark="$seclists/Discovery/DNS/bitquark-subdomains-top100000.txt"
output=${OUTPUT:-"$root/data/candidates-1m.txt.zst"}

readonly seclists_revision=8a7c5daa498962e240a52c9b29164174478ffe78
readonly top_sha256=949b441f39cea44d88b14cca38315a09567cd057aede8b6a549bce4ea1827a9e
readonly bitquark_sha256=f5e0acdfc136bb08fa86a3b346d44780aabfe5bfac45935fdc5507578bbb8400
readonly corpus_text_sha256=1a7f4dc7633897efe8ef3a1e9992bc2516b7ee9852c0b1126057f3c70f081ea2
readonly corpus_archive_sha256=cde7d80ff87e21ef2c6d3021b09931a469e4ca965f2bc7816e4c143682681d9b

for command in awk sha256sum wc zstd; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Commande requise introuvable: $command" >&2
    exit 1
  fi
done

for source in "$top" "$bitquark"; do
  if [[ ! -f "$source" ]]; then
    echo "Source SecLists introuvable: $source" >&2
    exit 1
  fi
done

verify_sha256() {
  local path=$1
  local expected=$2
  local actual
  actual=$(sha256sum "$path" | awk '{print $1}')
  if [[ "$actual" != "$expected" ]]; then
    echo "Empreinte inattendue pour $path" >&2
    echo "Attendue: $expected" >&2
    echo "Obtenue:  $actual" >&2
    echo "Utilisez SecLists $seclists_revision sans modification locale." >&2
    exit 1
  fi
}

verify_sha256 "$top" "$top_sha256"
verify_sha256 "$bitquark" "$bitquark_sha256"

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

verify_sha256 "$tmp/candidates-1m.txt" "$corpus_text_sha256"

mkdir -p "$(dirname "$output")"
zstd -q -19 --threads=0 --force "$tmp/candidates-1m.txt" -o "$output"
verify_sha256 "$output" "$corpus_archive_sha256"

echo "SecLists: $seclists_revision"
echo "$corpus_text_sha256  candidates-1m.txt (contenu canonique)"
echo "$corpus_archive_sha256  $output"
