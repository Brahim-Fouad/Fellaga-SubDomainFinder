# Fellaga candidate corpus

The compressed candidate corpus is generated deterministically from these SecLists files:

- `Discovery/DNS/subdomains-top1million-110000.txt`
- `Discovery/DNS/bitquark-subdomains-top100000.txt`

SecLists is distributed under the MIT License. Source project:
https://github.com/danielmiessler/SecLists

Fellaga lowercases and validates the source entries, preserves their order, deduplicates them, and appends deterministic environment variants until the corpus contains exactly 1,000,000 unique relative names. The build procedure is in `scripts/build-corpus.sh`.

The generated corpus is redistributed under the same MIT terms as Fellaga. No target-specific observations or local learning data are included.
