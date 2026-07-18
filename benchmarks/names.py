#!/usr/bin/env python3
"""Strict domain and FQDN normalization for benchmark inputs and outputs."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections.abc import Iterable, Iterator
from typing import Any


ASCII_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_OBSERVATIONAL_NAMES = 500_000
MAX_JSON_FILE_BYTES = 64 * 1024 * 1024


class NameError(ValueError):
    """Raised when a value is not a canonical DNS name."""


class ObservationalLimitError(ValueError):
    """Raised when an observational output exceeds its unique-name budget."""


def _raise_observational_limit() -> None:
    raise ObservationalLimitError(
        f"observational output exceeds {MAX_OBSERVATIONAL_NAMES} unique names"
    )


def _merge_observational_names(target: set[str], source: set[str]) -> None:
    unseen = source.difference(target)
    if len(unseen) > MAX_OBSERVATIONAL_NAMES - len(target):
        _raise_observational_limit()
    target.update(source)


def _ascii_name(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or any(character.isspace() for character in candidate):
        raise NameError("name is empty or contains whitespace")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NameError("name is not valid IDNA") from exc
    if len(candidate) > 253:
        raise NameError("name exceeds 253 characters")
    labels = candidate.split(".")
    if any(not ASCII_LABEL.fullmatch(label) for label in labels):
        raise NameError("name contains an invalid DNS label")
    return candidate


def normalize_domain(value: str) -> str:
    domain = _ascii_name(value)
    labels = domain.split(".")
    if len(labels) < 2:
        raise NameError("target must contain at least two labels")
    if labels[-1].isdigit():
        raise NameError("target cannot end in a numeric-only label")
    return domain


def normalize_fqdn(value: str, domain: str, *, allow_apex: bool = False) -> str:
    canonical_domain = normalize_domain(domain)
    candidate = value.strip()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    fqdn = _ascii_name(candidate)
    if fqdn == canonical_domain:
        if allow_apex:
            return fqdn
        raise NameError("the zone apex is not a subdomain")
    if not fqdn.endswith("." + canonical_domain):
        raise NameError("name is outside the target domain")
    return fqdn


def normalize_candidate(value: str, domain: str) -> str | None:
    """Return a subdomain, ignore a safe apex, and reject every other value."""
    canonical_domain = normalize_domain(domain)
    candidate = value.strip()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    fqdn = _ascii_name(candidate)
    if fqdn == canonical_domain:
        return None
    if not fqdn.endswith("." + canonical_domain):
        raise NameError("name is outside the target domain")
    return fqdn


def normalized_lines(
    lines: Iterable[str], domain: str, *, allow_apex: bool = False
) -> tuple[set[str], int]:
    names: set[str] = set()
    rejected = 0
    for line in lines:
        candidate = line.strip()
        if not candidate:
            continue
        try:
            normalized = (
                normalize_fqdn(candidate, domain, allow_apex=True)
                if allow_apex
                else normalize_candidate(candidate, domain)
            )
            if normalized is not None:
                names.add(normalized)
        except NameError:
            rejected += 1
    return names, rejected


def observational_lines(
    lines: Iterable[str], domain: str
) -> tuple[set[str], int, int]:
    """Normalize concrete names while excluding wildcard patterns as evidence."""
    names: set[str] = set()
    rejected = 0
    excluded_wildcards = 0
    for line in lines:
        candidate = line.strip()
        if not candidate:
            continue
        if candidate.startswith("*."):
            try:
                normalize_fqdn(candidate[2:], domain, allow_apex=True)
            except NameError:
                rejected += 1
            else:
                excluded_wildcards += 1
            continue
        try:
            normalized = normalize_candidate(candidate, domain)
            if normalized is not None:
                if (
                    normalized not in names
                    and len(names) >= MAX_OBSERVATIONAL_NAMES
                ):
                    _raise_observational_limit()
                names.add(normalized)
        except NameError:
            rejected += 1
    return names, rejected, excluded_wildcards


def read_name_file(
    path: pathlib.Path, domain: str, *, allow_apex: bool = False
) -> tuple[set[str], int]:
    if not path.exists():
        return set(), 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return normalized_lines(handle, domain, allow_apex=allow_apex)


def read_observational_name_file(
    path: pathlib.Path, domain: str
) -> tuple[set[str], int, int]:
    if not path.exists():
        return set(), 0, 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return observational_lines(handle, domain)


def _json_records(path: pathlib.Path) -> Iterator[Any]:
    if path.stat().st_size > MAX_JSON_FILE_BYTES:
        raise ValueError(f"BBOT JSON file exceeds {MAX_JSON_FILE_BYTES} bytes: {path}")
    text = path.read_text(encoding="utf-8", errors="strict")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            if line.strip():
                yield json.loads(line)
    else:
        if isinstance(document, list):
            yield from document
        else:
            yield document


def fellaga_names(path: pathlib.Path, domain: str) -> tuple[set[str], int, int]:
    document = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise ValueError("Fellaga output does not contain a findings array")
    live: set[str] = set()
    historical = 0
    rejected = 0
    for finding in document["findings"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("fqdn"), str):
            rejected += 1
            continue
        state = finding.get("state")
        if state == "historical":
            historical += 1
        if state != "live":
            continue
        try:
            normalized = normalize_candidate(finding["fqdn"], domain)
            if normalized is not None:
                live.add(normalized)
        except NameError:
            rejected += 1
    return live, historical, rejected


def bbot_names(directory: pathlib.Path, domain: str) -> tuple[set[str], int]:
    names: set[str] = set()
    rejected = 0
    for path in sorted(directory.rglob("*.json")):
        for record in _json_records(path):
            if not isinstance(record, dict):
                continue
            event_type = str(record.get("type", record.get("event_type", ""))).upper()
            value = record.get("data")
            if event_type != "DNS_NAME":
                continue
            if not isinstance(value, str):
                rejected += 1
                continue
            try:
                normalized = normalize_candidate(value, domain)
                if normalized is not None:
                    names.add(normalized)
            except NameError:
                rejected += 1
    return names, rejected


def bbot_observational_names(
    directory: pathlib.Path, domain: str
) -> tuple[set[str], int, int]:
    names: set[str] = set()
    rejected = 0
    excluded_wildcards = 0
    for path in sorted(directory.rglob("*.json")):
        for record in _json_records(path):
            if not isinstance(record, dict):
                continue
            event_type = str(record.get("type", record.get("event_type", ""))).upper()
            value = record.get("data")
            if event_type != "DNS_NAME":
                continue
            if not isinstance(value, str):
                rejected += 1
                continue
            candidate = value.strip()
            if candidate.startswith("*."):
                try:
                    normalize_fqdn(candidate[2:], domain, allow_apex=True)
                except NameError:
                    rejected += 1
                else:
                    excluded_wildcards += 1
                continue
            try:
                normalized = normalize_candidate(candidate, domain)
            except NameError:
                rejected += 1
                continue
            if normalized is None:
                continue
            if normalized not in names and len(names) >= MAX_OBSERVATIONAL_NAMES:
                _raise_observational_limit()
            names.add(normalized)
    return names, rejected, excluded_wildcards


def _write_names(names: Iterable[str]) -> None:
    for name in sorted(set(names)):
        print(name)


def _domains(path: pathlib.Path) -> int:
    domains: set[str] = set()
    errors: list[str] = []
    for number, source_line in enumerate(
        path.read_text(encoding="utf-8", errors="strict").splitlines(), start=1
    ):
        candidate = source_line.split("#", 1)[0].strip()
        if not candidate:
            continue
        try:
            domains.add(normalize_domain(candidate))
        except NameError as exc:
            errors.append(f"{path}:{number}: {exc}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 2
    _write_names(domains)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    domains_parser = subparsers.add_parser("domains")
    domains_parser.add_argument("path", type=pathlib.Path)

    normalize_parser = subparsers.add_parser("normalize")
    normalize_parser.add_argument("domain")
    normalize_parser.add_argument("paths", type=pathlib.Path, nargs="+")

    observation_parser = subparsers.add_parser("normalize-observational")
    observation_parser.add_argument("domain")
    observation_parser.add_argument("paths", type=pathlib.Path, nargs="+")

    fellaga_parser = subparsers.add_parser("fellaga")
    fellaga_parser.add_argument("domain")
    fellaga_parser.add_argument("path", type=pathlib.Path)
    fellaga_parser.add_argument("--metadata", type=pathlib.Path)

    bbot_parser = subparsers.add_parser("bbot")
    bbot_parser.add_argument("domain")
    bbot_parser.add_argument("directory", type=pathlib.Path)

    bbot_observation_parser = subparsers.add_parser("bbot-observational")
    bbot_observation_parser.add_argument("domain")
    bbot_observation_parser.add_argument("directory", type=pathlib.Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.action == "domains":
        return _domains(args.path)
    if args.action == "normalize":
        names: set[str] = set()
        rejected = 0
        for path in args.paths:
            normalized, path_rejected = read_name_file(path, args.domain)
            names.update(normalized)
            rejected += path_rejected
        _write_names(names)
        if rejected:
            print(f"rejected {rejected} malformed or out-of-scope name(s)", file=sys.stderr)
            return 3
        return 0
    if args.action == "normalize-observational":
        names: set[str] = set()
        rejected = 0
        excluded_wildcards = 0
        for path in args.paths:
            try:
                normalized, path_rejected, path_wildcards = (
                    read_observational_name_file(path, args.domain)
                )
                _merge_observational_names(names, normalized)
            except ObservationalLimitError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 4
            rejected += path_rejected
            excluded_wildcards += path_wildcards
        _write_names(names)
        if excluded_wildcards:
            print(f"excluded_wildcards={excluded_wildcards}", file=sys.stderr)
        if rejected:
            print(f"excluded_invalid_or_out_of_scope={rejected}", file=sys.stderr)
        return 0
    if args.action == "fellaga":
        names, historical, rejected = fellaga_names(args.path, args.domain)
        _write_names(names)
        if args.metadata:
            args.metadata.write_text(
                json.dumps(
                    {"historical_names": historical, "rejected_names": rejected}
                )
                + "\n",
                encoding="utf-8",
            )
        if rejected:
            print(f"rejected {rejected} malformed or out-of-scope name(s)", file=sys.stderr)
            return 3
        return 0
    if args.action == "bbot":
        names, rejected = bbot_names(args.directory, args.domain)
        _write_names(names)
        if rejected:
            print(f"rejected {rejected} malformed or out-of-scope name(s)", file=sys.stderr)
            return 3
        return 0
    if args.action == "bbot-observational":
        try:
            names, rejected, excluded_wildcards = bbot_observational_names(
                args.directory, args.domain
            )
        except ObservationalLimitError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 4
        _write_names(names)
        if excluded_wildcards:
            print(f"excluded_wildcards={excluded_wildcards}", file=sys.stderr)
        if rejected:
            print(f"excluded_invalid_or_out_of_scope={rejected}", file=sys.stderr)
        return 0
    raise AssertionError("unreachable action")


if __name__ == "__main__":
    raise SystemExit(main())
