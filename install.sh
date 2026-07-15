#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Cargo est requis. Sous Kali: sudo apt install cargo rustc" >&2
  exit 1
fi

cd "$ROOT"
cargo build --release --locked
install -Dm755 target/release/fellaga "$PREFIX/bin/fellaga"

echo "Fellaga installé dans $PREFIX/bin/fellaga"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "Ajoutez à votre shell: export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
