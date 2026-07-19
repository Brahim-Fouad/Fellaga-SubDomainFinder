# Third-party notices

This file records third-party data redistributed by Fellaga and explicit
upstream design attribution. Rust dependency versions are pinned in
`Cargo.lock`. Every release archive and Debian package also contains
`THIRD_PARTY_LICENSES.txt`, generated from the locked Cargo graph and the
license files in the resolved crate sources. The architecture SBOMs contain
the same resolved dependency graph and bind it to the packaged binary digest.

## Tranco top-30 benchmark excerpt

The passive observational benchmark includes a factual 30-row excerpt of the
Tranco standard daily list with permanent ID `74J5X`, generated on
2026-07-17. Its permanent source and methodology record are available at
<https://tranco-list.eu/list/74J5X/1000000>.

Requested citation:

Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej
Korczynski, and Wouter Joosen. 2019. "Tranco: A Research-Oriented Top Sites
Ranking Hardened Against Manipulation," Proceedings of NDSS 2019.
<https://doi.org/10.14722/ndss.2019.23386>

No single license is asserted here for the Tranco aggregate or the factual
excerpt, and the excerpt is not represented as covered by Fellaga's MIT
license. Tranco documents mixed upstream terms, including CC BY 3.0 for
Majestic, CC BY-SA 4.0 for CrUX, and CC BY-NC 4.0 for Cloudflare Radar. See
<https://tranco-list.eu/> and `benchmarks/data/tranco-74J5X-top30.json` for
the pinned attribution, retrieval URLs, and hashes.

## SecLists

Fellaga redistributes a generated candidate corpus derived from these files in
SecLists tag `2025.3`, commit
`8a7c5daa498962e240a52c9b29164174478ffe78`:

- `Discovery/DNS/subdomains-top1million-110000.txt`
- `Discovery/DNS/bitquark-subdomains-top100000.txt`

Upstream project: <https://github.com/danielmiessler/SecLists>

MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## xsubfind3r

Fellaga credits xsubfind3r for inspiration in connector architecture and
interface conventions. This attribution is pinned to release `1.1.2`, commit
`eace325a1d654a37064e5f1e2845d4d81335d537`.

Upstream project: <https://github.com/hueristiq/xsubfind3r>

MIT License

Copyright (c) 2021 Hueristiq

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
