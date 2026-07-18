# Connector fixtures

This directory contains sanitized normal-response fixtures for WhoisXML, Netlas, BinaryEdge, MerkleMap, Brave Search, Censys, and Driftnet. They are intentionally minimal and contain no secret or personal data. The tests validate connector parsing, pagination fields represented by those fixtures, and strict in-scope name filtering. Other connectors use small inline payloads next to their parser tests when a separate redistributable fixture would add no coverage.

Generic HTTP handling for `429`, `Retry-After`, partial bodies, structured errors, excessive response size, and credential-safe pagination is tested in `src/passive.rs`.

For every connector contract change, add or update sanitized normal, terminal-pagination, and degraded-schema cases where the provider contract permits redistribution. Shared HTTP failure behavior remains covered once in the transport layer instead of being duplicated for every provider.
