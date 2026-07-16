#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"

missing=()
for command in cargo cc make perl; do
  command -v "$command" >/dev/null 2>&1 || missing+=("$command")
done
if (( ${#missing[@]} > 0 )); then
  echo "Prérequis absents: ${missing[*]}" >&2
  echo "Sous Kali: sudo apt install cargo rustc build-essential perl pkg-config" >&2
  exit 1
fi

cd "$ROOT"
cargo build --release --locked --features vendored-openssl
install -Dm755 target/release/fellaga "$PREFIX/bin/fellaga"

echo "Fellaga installé dans $PREFIX/bin/fellaga"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "Ajoutez à votre shell: export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
