#!/usr/bin/env python3
"""Remove credential-like environment values from benchmark text logs."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import sys
import tempfile


SECRET_NAME = re.compile(
    r"(?:^|_)(?:API_KEY|API_TOKEN|API_ID|TOKEN|TOKENS|SECRET|CREDENTIALS|PASSWORD)$",
    re.IGNORECASE,
)
MINIMUM_SECRET_LENGTH = 4
SKIPPED_SUFFIXES = {".pcap", ".pcapng", ".sqlite", ".db"}
CHUNK_SIZE = 1024 * 1024
REPLACEMENT = b"[REDACTED]"


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


def _redact_stream(source: object, destination: object, secrets: list[bytes]) -> None:
    maximum = max(len(secret) for secret in secrets)
    buffer = b""
    while True:
        chunk = source.read(CHUNK_SIZE)  # type: ignore[attr-defined]
        final = not chunk
        buffer += chunk
        limit = len(buffer) if final else max(0, len(buffer) - maximum + 1)
        cursor = 0
        output = bytearray()
        while cursor < limit:
            matches = [
                (buffer.find(secret, cursor), -len(secret), secret)
                for secret in secrets
            ]
            matches = [match for match in matches if match[0] >= 0]
            if not matches:
                output.extend(buffer[cursor:limit])
                cursor = limit
                break
            index, _negative_length, secret = min(matches)
            if index >= limit:
                output.extend(buffer[cursor:limit])
                cursor = limit
                break
            output.extend(buffer[cursor:index])
            output.extend(REPLACEMENT)
            cursor = index + len(secret)
        destination.write(output)  # type: ignore[attr-defined]
        buffer = buffer[cursor:]
        if final:
            if buffer:
                destination.write(buffer)  # type: ignore[attr-defined]
            return


def redact_file(
    path: pathlib.Path, secrets: list[str], root: pathlib.Path | None = None
) -> None:
    if not secrets or path.is_symlink():
        return
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        return
    if root is not None:
        try:
            path.resolve(strict=True).relative_to(root)
        except (FileNotFoundError, ValueError):
            return
    if path.suffix.lower() in SKIPPED_SUFFIXES:
        return
    encoded = [secret.encode("utf-8") for secret in secrets if secret]
    if not encoded:
        return
    temporary_name = ""
    try:
        with path.open("rb") as source:
            prefix = source.read(8192)
            if b"\x00" in prefix:
                return
            source.seek(0)
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
            ) as destination:
                temporary_name = destination.name
                _redact_stream(source, destination, encoded)
        os.chmod(temporary_name, stat.S_IMODE(metadata.st_mode))
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def redact_path(path: pathlib.Path, secrets: list[str]) -> None:
    if path.is_symlink():
        return
    if path.is_dir():
        root = path.resolve(strict=True)
        for candidate in path.rglob("*"):
            if candidate.is_symlink():
                continue
            redact_file(candidate, secrets, root)
        return
    parent = path.parent.resolve(strict=True) if path.parent.exists() else None
    redact_file(path, secrets, parent)


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
