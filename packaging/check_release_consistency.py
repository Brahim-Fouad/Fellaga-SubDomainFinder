#!/usr/bin/env python3
"""Fail when release versions, documented downloads, or asset names diverge."""

from __future__ import annotations

import re
from pathlib import Path


EXPECTED_ASSET_TEMPLATES = {
    "SHA256SUMS",
    "SHA256SUMS.sigstore.json",
    "fellaga-v${VERSION}-aarch64-unknown-linux-gnu.cdx.json",
    "fellaga-v${VERSION}-aarch64-unknown-linux-gnu.tar.gz",
    "fellaga-v${VERSION}-x86_64-unknown-linux-gnu.cdx.json",
    "fellaga-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz",
    "fellaga_${VERSION}-1_amd64.deb",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def cargo_package_version(text: str) -> str | None:
    package = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", text)
    if not package:
        return None
    match = re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', package.group(1), re.M)
    return match.group(1) if match else None


def cargo_lock_package_version(text: str, package_name: str) -> str | None:
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", text):
        if re.search(rf'(?m)^name = "{re.escape(package_name)}"$', block):
            match = re.search(
                r'(?m)^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', block
            )
            return match.group(1) if match else None
    return None


def shell_array(text: str, name: str) -> set[str] | None:
    matches = list(
        re.finditer(
            rf"(?ms)^\s*{re.escape(name)}=\(\s*$\n(.*?)^\s*\)\s*$", text
        )
    )
    if not matches:
        return None
    return set(re.findall(r'^\s*"([^"]+)"\s*$', matches[-1].group(1), re.M))


def require_tokens(label: str, text: str, tokens: list[str]) -> list[str]:
    return [f"{label}: missing {token!r}" for token in tokens if token not in text]


def check_repository(root: Path) -> list[str]:
    errors: list[str] = []
    cargo = read(root / "Cargo.toml")
    version = cargo_package_version(cargo)
    if version is None:
        return ["Cargo.toml: package version is missing or is not X.Y.Z"]

    lock_version = cargo_lock_package_version(
        read(root / "Cargo.lock"), "fellaga-subdomainfinder"
    )
    if lock_version != version:
        errors.append(
            f"Cargo.lock: fellaga-subdomainfinder is {lock_version!r}, expected {version!r}"
        )

    debian = read(root / "packaging/debian/changelog")
    expected_debian = f"fellaga ({version}-1) unstable; urgency=medium"
    if debian.splitlines()[0] != expected_debian:
        errors.append(
            "packaging/debian/changelog: first line must be " + repr(expected_debian)
        )

    changelog = read(root / "CHANGELOG.md")
    first_release = re.search(r"(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]", changelog)
    if first_release is None or first_release.group(1) != version:
        actual = first_release.group(1) if first_release else None
        errors.append(f"CHANGELOG.md: first release is {actual!r}, expected {version!r}")
    errors.extend(
        require_tokens(
            "CHANGELOG.md",
            changelog,
            [
                f"[Unreleased]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/compare/v{version}...HEAD",
                f"[{version}]: https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder/releases/tag/v{version}",
            ],
        )
    )

    deb = f"fellaga_{version}-1_amd64.deb"
    repository = "https://github.com/Brahim-Fouad/Fellaga-SubDomainFinder"
    errors.extend(
        require_tokens(
            "README.md",
            read(root / "README.md"),
            [f"{repository}/releases/download/v{version}/{deb}", f"./{deb}"],
        )
    )
    errors.extend(
        require_tokens(
            "docs/installation.md",
            read(root / "docs/installation.md"),
            [
                f"{repository}/releases/download/v{version}/{deb}",
                f"fellaga-v{version}-x86_64-unknown-linux-gnu.tar.gz",
                f"fellaga-v{version}-aarch64-unknown-linux-gnu.tar.gz",
                f"version={version}",
            ],
        )
    )
    errors.extend(
        require_tokens(
            "docs/release-verification.md",
            read(root / "docs/release-verification.md"),
            [
                f"Fellaga v{version} contains seven assets",
                f"fellaga-v{version}-x86_64-unknown-linux-gnu.cdx.json",
                f"fellaga-v{version}-x86_64-unknown-linux-gnu.tar.gz",
                f"release.yml@refs/tags/v{version}",
                f"git rev-parse 'v{version}^{{commit}}'",
            ],
        )
    )
    errors.extend(
        require_tokens(
            "docs/sources.md",
            read(root / "docs/sources.md"),
            ["The current Fellaga registry contains 69 connector names"],
        )
    )

    workflow = read(root / ".github/workflows/release.yml")
    assets = shell_array(workflow, "expected")
    if assets is None:
        errors.append(".github/workflows/release.yml: expected asset array is missing")
    elif assets != EXPECTED_ASSET_TEMPLATES:
        missing = sorted(EXPECTED_ASSET_TEMPLATES - assets)
        unexpected = sorted(assets - EXPECTED_ASSET_TEMPLATES)
        errors.append(
            ".github/workflows/release.yml: final asset set differs; "
            f"missing={missing}, unexpected={unexpected}"
        )

    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = check_repository(root)
    if errors:
        for error in errors:
            print(f"release consistency error: {error}")
        return 1
    print("Release versions, documented downloads, and seven-asset set are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
