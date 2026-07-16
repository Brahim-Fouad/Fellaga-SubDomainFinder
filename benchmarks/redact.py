#!/usr/bin/env python3
"""Remove credential-like environment values from benchmark text logs."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys


SECRET_NAME = re.compile(
    r"(?:^|_)(?:API_KEY|API_TOKEN|API_ID|TOKEN|TOKENS|SECRET|CREDENTIALS|PASSWORD)$",
    re.IGNORECASE,
)
MINIMUM_SECRET_LENGTH = 4
SKIPPED_SUFFIXES = {".pcap", ".pcapng", ".sqlite", ".db"}


def environment_secrets(environment: dict[str, str] | None = None) -> list[str]:
    values = os.environ if environment is None else environment
    secrets: set[str] = set()
    for name, value in values.items():
        if not SECRET_NAME.search(name) or not value:
            continue
        candidates = [value]
        candidates.extend(re.split(r"[\s,:;]+", value))
        secrets.update(
            candidate
            for candidate in candidates
            if len(candidate) >= MINIMUM_SECRET_LENGTH
        )
    return sorted(secrets, key=len, reverse=True)


def redact_text(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, "[REDACTED]")
    return text


def redact_file(path: pathlib.Path, secrets: list[str]) -> None:
    if not path.exists():
        return
    if path.suffix.lower() in SKIPPED_SUFFIXES:
        return
    payload = path.read_bytes()
    if b"\x00" in payload:
        return
    original = payload.decode("utf-8", errors="replace")
    redacted = redact_text(original, secrets)
    if redacted != original:
        path.write_text(redacted, encoding="utf-8")


def redact_path(path: pathlib.Path, secrets: list[str]) -> None:
    if path.is_dir():
        for candidate in path.rglob("*"):
            if candidate.is_file():
                redact_file(candidate, secrets)
        return
    redact_file(path, secrets)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=pathlib.Path, nargs="+")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    secrets = environment_secrets()
    for path in args.paths:
        redact_path(path, secrets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
