# Connector fixtures

This directory contains sanitized normal-response fixtures for WhoisXML, Netlas, BinaryEdge, MerkleMap, and Brave Search. They are intentionally minimal and contain no secret or personal data. The tests validate connector parsing, pagination fields represented by those fixtures, and strict in-scope name filtering.

Generic HTTP handling for `429`, `Retry-After`, partial bodies, structured errors, excessive response size, and credential-safe pagination is tested in `src/passive.rs`.

Before a new connector is enabled by default, add sanitized fixtures for a normal page, terminal pagination, and a degraded or changed schema when the upstream contract permits redistribution.
