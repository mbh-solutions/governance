from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from governance_eval.adoption import (
    AdoptionError,
    CONFIG_PATH,
    MANIFEST_PATH,
    NATIVE_AUTHORITY_MODE,
    NATIVE_GOVERNANCE_REPOSITORY,
    NATIVE_GOVERNANCE_REPOSITORY_ID,
    NATIVE_WORKFLOW_PATH,
    _canonical_json,
    generate_adoption_bundle,
    prove_adoption_bundle,
    validate_adoption_config,
    validate_native_adoption_config,
)
from governance_eval.hashing import sha256_bytes
from governance_eval.sqlite_policy import POLICY_SHA256


class AdoptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = Path(__file__).resolve().parents[1]
        self.governance_sha = "a" * 40
        self.rollback_sha = "b" * 40

    def test_bundle_is_byte_stable_and_proof_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            self._target(target)
            before = self._state(target)
            first = root / "first"
            second = root / "second"
            manifests = [
                generate_adoption_bundle(
                    repo_root=target,
                    output_dir=output,
                    github_repository="owner/repository",
                    repository_id=123,
                    governance_sha=self.governance_sha,
                    verifier_app_id=456,
                    rollback_sha=self.rollback_sha,
                    source_root=self.source,
                )
                for output in (first, second)
            ]

            self.assertEqual(manifests[0], manifests[1])
            self.assertEqual(self._files(first), self._files(second))
            proof = prove_adoption_bundle(
                repo_root=target,
                bundle_dir=first,
                artifacts_dir=root / "proof",
                github_repository="owner/repository",
            )
            self.assertEqual(proof["status"], "PASS")
            self.assertEqual(before, self._state(target))
            self.assertEqual(len(proof["capabilities"]), 10)

    def test_native_bundle_is_default_and_has_no_target_workflow_or_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            self._target(target)
            bundle = root / "bundle"

            manifest = generate_adoption_bundle(
                repo_root=target,
                output_dir=bundle,
                github_repository="owner/repository",
                repository_id=123,
                governance_sha=self.governance_sha,
                rollback_sha=self.rollback_sha,
                source_root=self.source,
            )
            proof = prove_adoption_bundle(
                repo_root=target,
                bundle_dir=bundle,
                artifacts_dir=root / "proof",
                github_repository="owner/repository",
            )
            config = json.loads((bundle / CONFIG_PATH).read_text(encoding="utf-8"))

            self.assertEqual(
                self._files(bundle).keys(),
                {
                    CONFIG_PATH,
                    ".github/governance/supportability-standard.md",
                    MANIFEST_PATH,
                },
            )
            self.assertNotIn("verifier", config)
            self.assertNotIn("verifier", manifest)
            self.assertEqual(
                manifest["enforcement"],
                {
                    "mode": NATIVE_AUTHORITY_MODE,
                    "workflow": {
                        "repository": NATIVE_GOVERNANCE_REPOSITORY,
                        "repository_id": NATIVE_GOVERNANCE_REPOSITORY_ID,
                        "path": NATIVE_WORKFLOW_PATH,
                        "sha": self.governance_sha,
                    },
                },
            )
            self.assertEqual(proof["enforcement"], manifest["enforcement"])
            hostile = {**config, "command": "python attacker.py"}
            with self.assertRaises(AdoptionError):
                validate_native_adoption_config(
                    hostile, governance_sha=self.governance_sha
                )

            manifest_path = bundle / MANIFEST_PATH
            hostile_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            hostile_manifest["enforcement"]["workflow"]["repository"] = (
                "attacker/governance"
            )
            unsigned = {**hostile_manifest}
            unsigned.pop("bundle_sha256")
            hostile_manifest["bundle_sha256"] = sha256_bytes(_canonical_json(unsigned))
            manifest_path.write_bytes(_canonical_json(hostile_manifest))
            with self.assertRaisesRegex(AdoptionError, "enforcement binding"):
                prove_adoption_bundle(
                    repo_root=target,
                    bundle_dir=bundle,
                    artifacts_dir=root / "hostile-proof",
                    github_repository="owner/repository",
                )

    def test_proof_rejects_arbitrary_configuration_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            self._target(target)
            bundle = root / "bundle"
            generate_adoption_bundle(
                repo_root=target,
                output_dir=bundle,
                github_repository="owner/repository",
                repository_id=123,
                governance_sha=self.governance_sha,
                verifier_app_id=456,
                rollback_sha=self.rollback_sha,
                source_root=self.source,
            )
            config_path = bundle / CONFIG_PATH
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["command"] = "python attacker.py"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            with self.assertRaises(AdoptionError):
                prove_adoption_bundle(
                    repo_root=target,
                    bundle_dir=bundle,
                    artifacts_dir=root / "proof",
                    github_repository="owner/repository",
                )

    def test_configuration_rejects_every_target_control_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            self._target(target)
            bundle = root / "bundle"
            generate_adoption_bundle(
                repo_root=target,
                output_dir=bundle,
                github_repository="owner/repository",
                repository_id=123,
                governance_sha=self.governance_sha,
                verifier_app_id=456,
                rollback_sha=self.rollback_sha,
                source_root=self.source,
            )
            original = json.loads((bundle / CONFIG_PATH).read_text(encoding="utf-8"))
            mutations = {
                "executable": {"executable": "python"},
                "command": {"command": "python attacker.py"},
                "arguments": {"arguments": ["--exit-zero"]},
                "environment": {"environment": {"TOKEN": "attacker"}},
                "threshold": {"max_complexity": 99},
                "include": {"include": ["safe.py"]},
                "exclude": {"exclude": ["unsafe.py"]},
                "traversal": {"evaluation_root": "../../outside"},
            }
            for name, mutation in mutations.items():
                with self.subTest(name=name):
                    hostile = {**original, **mutation}
                    with self.assertRaises(AdoptionError):
                        validate_adoption_config(
                            hostile,
                            governance_sha=self.governance_sha,
                            verifier_app_id=456,
                        )

    def test_sqlite_profile_requires_discovery_and_binds_eleven_capabilities(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            self._target(target)
            package = target / "src/package"
            package.mkdir(parents=True)
            (package / "database.py").write_text(
                "import sqlite3\n"
                "def query(connection: sqlite3.Connection) -> None:\n"
                "    connection.execute('SELECT coalesce(NULL, 1)')\n",
                encoding="utf-8",
            )
            (target / "pyproject.toml").write_text(
                '[project]\nname = "fixture"\nversion = "0.0.1"\n'
                '[tool.setuptools.packages.find]\nwhere = ["src"]\n',
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "."], cwd=target, check=True, timeout=10)
            subprocess.run(
                ["git", "commit", "-qm", "sqlite fixture"],
                cwd=target,
                check=True,
                timeout=10,
            )

            with self.assertRaisesRegex(AdoptionError, "trusted opt-in"):
                generate_adoption_bundle(
                    repo_root=target,
                    output_dir=root / "standard",
                    github_repository="owner/repository",
                    repository_id=123,
                    governance_sha=self.governance_sha,
                    verifier_app_id=456,
                    rollback_sha=self.rollback_sha,
                    source_root=self.source,
                )

            bundle = root / "sqlite"
            manifest = generate_adoption_bundle(
                repo_root=target,
                output_dir=bundle,
                github_repository="owner/repository",
                repository_id=123,
                governance_sha=self.governance_sha,
                verifier_app_id=456,
                rollback_sha=self.rollback_sha,
                source_root=self.source,
                profile="python.sqlite.v1",
            )
            proof = prove_adoption_bundle(
                repo_root=target,
                bundle_dir=bundle,
                artifacts_dir=root / "proof",
                github_repository="owner/repository",
            )
            config = json.loads((bundle / CONFIG_PATH).read_text(encoding="utf-8"))

            self.assertEqual(manifest["profile"], "python.sqlite.v1")
            self.assertEqual(manifest["sqlite_policy_sha256"], POLICY_SHA256)
            self.assertEqual(config["profile"], "python.sqlite.v1")
            self.assertEqual(config["adapters"][-1]["capability"], "sql_supportability")
            self.assertEqual(len(proof["capabilities"]), 11)
            self.assertEqual(
                proof["profile_discovery"]["required_profile"], "python.sqlite.v1"
            )

    def _target(self, path: Path) -> None:
        path.mkdir()
        for command in (
            ("init", "-q"),
            ("config", "user.email", "governance@example.invalid"),
            ("config", "user.name", "Governance Test"),
        ):
            subprocess.run(["git", *command], cwd=path, check=True, timeout=10)
        (path / "pyproject.toml").write_text(
            '[project]\nname = "fixture"\nversion = "0.0.1"\nrequires-python = ">=3.12"\n',
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "."], cwd=path, check=True, timeout=10)
        subprocess.run(
            ["git", "commit", "-qm", "fixture"], cwd=path, check=True, timeout=10
        )

    def _state(self, path: Path) -> tuple[str, str]:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
        return head, status

    def _files(self, root: Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }


if __name__ == "__main__":
    unittest.main()
