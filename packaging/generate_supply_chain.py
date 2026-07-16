#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM and bundled Cargo license inventory."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any
from urllib.parse import quote
import uuid


GENERATOR_NAME = "fellaga-supply-chain-generator"
GENERATOR_VERSION = "1"
LICENSE_PREFIXES = (
    "COPYING",
    "COPYRIGHT",
    "LICENCE",
    "LICENSE",
    "NOTICE",
    "UNLICENSE",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cargo_purl(name: str, version: str) -> str:
    safe = "-._~"
    return f"pkg:cargo/{quote(name, safe=safe)}@{quote(version, safe=safe)}"


def package_ref(package: dict[str, Any]) -> str:
    package_id = package["id"]
    suffix = hashlib.sha256(package_id.encode("utf-8")).hexdigest()[:16]
    return (
        f"urn:cargo:{quote(package['name'], safe='-._~')}:"
        f"{quote(package['version'], safe='-._~')}:{suffix}"
    )


def workspace_package_ref(package: dict[str, Any]) -> str:
    identity = f"workspace:{package['name']}:{package['version']}"
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return (
        f"urn:cargo:{quote(package['name'], safe='-._~')}:"
        f"{quote(package['version'], safe='-._~')}:{suffix}"
    )


def dependency_kinds(edge: dict[str, Any]) -> set[str]:
    kinds: set[str] = set()
    entries = edge.get("dep_kinds") or []
    if not entries:
        return {"normal"}
    for entry in entries:
        kind = entry.get("kind") or "normal"
        if kind != "dev":
            kinds.add(kind)
    return kinds


def resolve_release_graph(
    metadata: dict[str, Any],
) -> tuple[str, set[str], dict[str, set[str]], dict[str, set[str]]]:
    resolve = metadata.get("resolve") or {}
    root_id = resolve.get("root")
    if not root_id:
        members = metadata.get("workspace_members") or []
        if len(members) != 1:
            raise ValueError("unable to identify one Cargo workspace root")
        root_id = members[0]

    nodes = {node["id"]: node for node in resolve.get("nodes") or []}
    if root_id not in nodes:
        raise ValueError("Cargo metadata does not contain the root resolve node")

    included = {root_id}
    outgoing: dict[str, set[str]] = {}
    incoming_kinds: dict[str, set[str]] = {}
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        node = nodes.get(package_id)
        if node is None:
            raise ValueError(f"missing resolve node for {package_id}")
        for edge in node.get("deps") or []:
            kinds = dependency_kinds(edge)
            if not kinds:
                continue
            child_id = edge["pkg"]
            outgoing.setdefault(package_id, set()).add(child_id)
            incoming_kinds.setdefault(child_id, set()).update(kinds)
            if child_id not in included:
                included.add(child_id)
                pending.append(child_id)

    if len(included) <= 1:
        raise ValueError("Cargo release graph contains no third-party dependencies")
    return root_id, included, outgoing, incoming_kinds


def component_licenses(package: dict[str, Any]) -> list[dict[str, Any]]:
    expression = package.get("license")
    if expression:
        return [{"expression": expression}]
    license_file = package.get("license_file")
    if license_file:
        return [{"license": {"name": f"License file: {Path(license_file).name}"}}]
    raise ValueError(
        f"Cargo package {package['name']} {package['version']} has no license metadata"
    )


def external_references(package: dict[str, Any]) -> list[dict[str, str]]:
    references: list[dict[str, str]] = []
    repository = package.get("repository")
    homepage = package.get("homepage")
    if repository:
        references.append({"type": "vcs", "url": repository})
    if homepage and homepage != repository:
        references.append({"type": "website", "url": homepage})
    return references


def license_files(package: dict[str, Any]) -> list[Path]:
    manifest_path = Path(package["manifest_path"])
    root = manifest_path.parent
    paths: dict[str, Path] = {}

    declared = package.get("license_file")
    if declared:
        declared_path = Path(declared)
        if not declared_path.is_absolute():
            declared_path = root / declared_path
        if declared_path.is_file():
            paths[str(declared_path.resolve())] = declared_path

    if root.is_dir():
        for candidate in root.iterdir():
            if not candidate.is_file():
                continue
            upper_name = candidate.name.upper()
            if upper_name.startswith(LICENSE_PREFIXES):
                paths.setdefault(str(candidate.resolve()), candidate)

    return sorted(
        paths.values(),
        key=lambda path: (path.name.casefold(), path.name, sha256_file(path)),
    )


def read_license_text(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError(f"license file is unexpectedly large: {path}")
    if b"\x00" in raw:
        raise ValueError(f"license file is not plain text: {path}")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def build_documents(
    metadata: dict[str, Any],
    *,
    target: str,
    lock_path: Path,
    binary_path: Path,
    source_date_epoch: int,
) -> tuple[dict[str, Any], str]:
    root_id, included, outgoing, incoming_kinds = resolve_release_graph(metadata)
    packages = {package["id"]: package for package in metadata["packages"]}
    missing = included.difference(packages)
    if missing:
        raise ValueError(f"Cargo metadata is missing packages: {sorted(missing)}")

    root = packages[root_id]
    lock_sha256 = sha256_file(lock_path)
    binary_sha256 = sha256_file(binary_path)
    refs = {package_id: package_ref(packages[package_id]) for package_id in included}
    # Cargo encodes an absolute checkout path in the workspace package ID.
    # Keep the root reference reproducible across checkout directories while
    # retaining Cargo's stable package IDs for registry dependencies.
    refs[root_id] = workspace_package_ref(root)

    components: list[dict[str, Any]] = []
    dependency_packages = sorted(
        (packages[package_id] for package_id in included if package_id != root_id),
        key=lambda package: (package["name"], package["version"], package["id"]),
    )
    for package in dependency_packages:
        package_id = package["id"]
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": refs[package_id],
            "name": package["name"],
            "version": package["version"],
            "purl": cargo_purl(package["name"], package["version"]),
            "licenses": component_licenses(package),
            "properties": [
                {"name": "fellaga:cargo-package-id", "value": package_id},
                {
                    "name": "fellaga:dependency-kinds",
                    "value": ",".join(sorted(incoming_kinds.get(package_id) or {"normal"})),
                },
                {"name": "fellaga:target", "value": target},
            ],
        }
        checksum = package.get("checksum")
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        references = external_references(package)
        if references:
            component["externalReferences"] = references
        components.append(component)

    root_ref = refs[root_id]
    timestamp = dt.datetime.fromtimestamp(
        source_date_epoch, tz=dt.timezone.utc
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    serial_seed = f"{root['name']}:{root['version']}:{target}:{lock_sha256}"
    serial = uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)

    dependency_entries: list[dict[str, Any]] = []
    for package_id in sorted(included, key=lambda item: refs[item]):
        child_refs = sorted(
            refs[child]
            for child in outgoing.get(package_id, set())
            if child in included
        )
        dependency_entries.append({"ref": refs[package_id], "dependsOn": child_refs})

    sbom: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": GENERATOR_NAME,
                        "version": GENERATOR_VERSION,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "fellaga",
                "version": root["version"],
                "purl": cargo_purl(root["name"], root["version"]),
                "hashes": [{"alg": "SHA-256", "content": binary_sha256}],
                "licenses": component_licenses(root),
                "properties": [
                    {"name": "fellaga:cargo-lock-sha256", "value": lock_sha256},
                    {"name": "fellaga:binary-target", "value": target},
                ],
            },
        },
        "components": components,
        "dependencies": dependency_entries,
    }

    inventory: list[str] = [
        "Fellaga third-party Rust dependency licenses",
        "=" * 48,
        "",
        f"Fellaga version: {root['version']}",
        f"Target: {target}",
        f"Cargo.lock SHA-256: {lock_sha256}",
        f"Binary SHA-256: {binary_sha256}",
        f"Dependency packages: {len(dependency_packages)}",
        "",
        "This inventory was generated from `cargo metadata --locked` and the",
        "license files shipped in Cargo's resolved package sources. It is bundled",
        "with the release and does not require network access after installation.",
        "",
    ]
    license_text_count = 0
    for package in dependency_packages:
        package_id = package["id"]
        files = license_files(package)
        inventory.extend(
            [
                "=" * 79,
                f"Package: {package['name']} {package['version']}",
                f"Declared license: {package.get('license') or '<license-file>'}",
                f"Cargo package ID: {package_id}",
                f"Source: {package.get('source') or '<workspace/path>'}",
                f"Repository: {package.get('repository') or '<not declared>'}",
                "Dependency kinds: "
                + ",".join(sorted(incoming_kinds.get(package_id) or {"normal"})),
                "License files: " + (", ".join(path.name for path in files) or "<none>"),
                "",
            ]
        )
        if not files:
            inventory.extend(
                [
                    "No standalone license file was present in Cargo's resolved",
                    "package source. Refer to the declared SPDX expression above.",
                    "",
                ]
            )
            continue
        for path in files:
            license_text_count += 1
            inventory.extend(
                [
                    f"----- BEGIN {package['name']} {package['version']} / {path.name} -----",
                    read_license_text(path).rstrip("\n"),
                    f"----- END {package['name']} {package['version']} / {path.name} -----",
                    "",
                ]
            )

    if license_text_count == 0:
        raise ValueError("no dependency license text was found in Cargo package sources")
    return sbom, "\n".join(inventory).rstrip() + "\n"


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def load_cargo_metadata(
    manifest_path: Path, target: str, features: list[str]
) -> dict[str, Any]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--manifest-path",
        str(manifest_path),
    ]
    if features:
        command.extend(["--features", ",".join(features)])
    completed = subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-path", type=Path, default=Path("Cargo.toml"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--licenses", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--features", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = args.manifest_path.resolve()
    lock_path = manifest_path.parent / "Cargo.lock"
    if not manifest_path.is_file() or not lock_path.is_file():
        raise SystemExit("Cargo.toml and Cargo.lock must both exist")
    if not args.binary.is_file():
        raise SystemExit(f"release binary does not exist: {args.binary}")

    metadata = load_cargo_metadata(manifest_path, args.target, args.features)
    sbom, licenses = build_documents(
        metadata,
        target=args.target,
        lock_path=lock_path,
        binary_path=args.binary,
        source_date_epoch=args.source_date_epoch,
    )
    write_atomic(args.sbom, json.dumps(sbom, indent=2, ensure_ascii=False) + "\n")
    write_atomic(args.licenses, licenses)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
