import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "generate_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("generate_supply_chain", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SupplyChainGenerationTests(unittest.TestCase):
    def package(self, root, package_id, name, version, license_expression):
        package_root = root / name
        package_root.mkdir()
        (package_root / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        (package_root / "LICENSE").write_text(
            f"License text for {name}\n", encoding="utf-8"
        )
        return {
            "id": package_id,
            "name": name,
            "version": version,
            "license": license_expression,
            "license_file": None,
            "manifest_path": str(package_root / "Cargo.toml"),
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "repository": f"https://example.invalid/{name}",
            "homepage": None,
            "checksum": hashlib.sha256(package_id.encode()).hexdigest(),
        }

    def fixture(self, root):
        packages = [
            self.package(root, "root 1.2.3", "fellaga-subdomainfinder", "1.2.3", "MIT"),
            self.package(root, "runtime 2.0.0", "runtime", "2.0.0", "MIT"),
            self.package(root, "builder 3.0.0", "builder", "3.0.0", "Apache-2.0"),
            self.package(root, "dev-only 4.0.0", "dev-only", "4.0.0", "BSD-3-Clause"),
        ]
        return {
            "packages": packages,
            "workspace_members": ["root 1.2.3"],
            "resolve": {
                "root": "root 1.2.3",
                "nodes": [
                    {
                        "id": "root 1.2.3",
                        "deps": [
                            {
                                "pkg": "runtime 2.0.0",
                                "dep_kinds": [{"kind": None, "target": None}],
                            },
                            {
                                "pkg": "builder 3.0.0",
                                "dep_kinds": [{"kind": "build", "target": None}],
                            },
                            {
                                "pkg": "dev-only 4.0.0",
                                "dep_kinds": [{"kind": "dev", "target": None}],
                            },
                        ],
                    },
                    {"id": "runtime 2.0.0", "deps": []},
                    {"id": "builder 3.0.0", "deps": []},
                    {"id": "dev-only 4.0.0", "deps": []},
                ],
            },
        }

    def test_generates_dependency_sbom_and_offline_license_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            metadata = self.fixture(root)
            lock_path = root / "Cargo.lock"
            binary_path = root / "fellaga"
            lock_path.write_text("locked\n", encoding="utf-8")
            binary_path.write_bytes(b"binary")

            sbom, inventory = MODULE.build_documents(
                metadata,
                target="x86_64-unknown-linux-gnu",
                lock_path=lock_path,
                binary_path=binary_path,
                source_date_epoch=1_700_000_000,
            )

            names = {component["name"] for component in sbom["components"]}
            self.assertEqual(names, {"runtime", "builder"})
            self.assertNotIn("dev-only", inventory)
            self.assertIn("License text for runtime", inventory)
            self.assertIn("License text for builder", inventory)
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.6")
            expected_root_ref = MODULE.workspace_package_ref(metadata["packages"][0])
            self.assertEqual(sbom["metadata"]["component"]["bom-ref"], expected_root_ref)
            self.assertTrue(
                any(entry["ref"] == expected_root_ref for entry in sbom["dependencies"])
            )
            self.assertEqual(
                sbom["metadata"]["component"]["hashes"][0]["content"],
                hashlib.sha256(b"binary").hexdigest(),
            )
            self.assertGreater(len(sbom["dependencies"]), 1)
            json.dumps(sbom)

    def test_output_is_stable_for_identical_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            metadata = self.fixture(root)
            lock_path = root / "Cargo.lock"
            binary_path = root / "fellaga"
            lock_path.write_text("locked\n", encoding="utf-8")
            binary_path.write_bytes(b"binary")
            arguments = {
                "target": "aarch64-unknown-linux-gnu",
                "lock_path": lock_path,
                "binary_path": binary_path,
                "source_date_epoch": 1_700_000_000,
            }

            first = MODULE.build_documents(metadata, **arguments)
            second = MODULE.build_documents(metadata, **arguments)

            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
