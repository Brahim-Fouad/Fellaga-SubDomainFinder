# Fellaga candidate corpus

`candidates-1m.txt.zst` is generated from the SecLists tag `2025.3`, pinned to
commit `8a7c5daa498962e240a52c9b29164174478ffe78`:

| Source | SHA-256 | Lines |
| --- | --- | ---: |
| `Discovery/DNS/subdomains-top1million-110000.txt` | `949b441f39cea44d88b14cca38315a09567cd057aede8b6a549bce4ea1827a9e` | 114442 |
| `Discovery/DNS/bitquark-subdomains-top100000.txt` | `f5e0acdfc136bb08fa86a3b346d44780aabfe5bfac45935fdc5507578bbb8400` | 100000 |

Upstream: <https://github.com/danielmiessler/SecLists>

SecLists is distributed under the MIT License. Its complete copyright and
license notice is reproduced in `THIRD_PARTY_NOTICES.md`.

## Transformation

The generator lowercases and validates source entries, preserves their source
order, removes duplicates, then appends a fixed sequence of environment
suffixes until it has exactly 1,000,000 unique relative names. It does not read
the Fellaga database, scan output, API configuration or target-specific local
learning.

Canonical artifact fingerprints:

- uncompressed UTF-8/LF content:
  `1a7f4dc7633897efe8ef3a1e9992bc2516b7ee9852c0b1126057f3c70f081ea2`;
- distributed Zstandard archive:
  `cde7d80ff87e21ef2c6d3021b09931a469e4ca965f2bc7816e4c143682681d9b`.

The distributed archive was produced with Zstandard CLI 1.5.7, GNU Awk 5.3.2
and GNU coreutils 9.10. The uncompressed fingerprint is the canonical content
identity; a different compressor version may produce different archive bytes.

## Rebuild and verification

```bash
git clone https://github.com/danielmiessler/SecLists.git
git -C SecLists checkout 8a7c5daa498962e240a52c9b29164174478ffe78
SECLISTS_ROOT="$PWD/SecLists" ./scripts/build-corpus.sh
```

The script refuses source files whose fingerprints do not match the pinned
revision and verifies both the canonical content and compressed artifact. The
machine-readable provenance is in `corpus-manifest.json`.
