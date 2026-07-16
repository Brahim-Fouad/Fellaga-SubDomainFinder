#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"

missing=()
for command in cargo rustc cc cmake make perl pkg-config; do
  command -v "$command" >/dev/null 2>&1 || missing+=("$command")
done
if (( ${#missing[@]} > 0 )); then
  echo "Missing prerequisites: ${missing[*]}" >&2
  echo "On Kali: sudo apt install cargo rustc build-essential cmake perl pkg-config" >&2
  exit 1
fi

required_rust="1.95.0"
installed_rust="$(rustc --version | awk '{print $2}')"
if [[ "$(printf '%s\n%s\n' "$required_rust" "$installed_rust" | sort -V | head -n 1)" != "$required_rust" ]]; then
  echo "Rust $required_rust or newer is required; found $installed_rust" >&2
  exit 1
fi

cd "$ROOT"
cargo build --release --locked --features vendored-openssl
install -Dm755 target/release/fellaga "$PREFIX/bin/fellaga"

echo "Fellaga installed in $PREFIX/bin/fellaga"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "Add this to your shell configuration: export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
