from __future__ import annotations

import base64
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from unittest import mock

from governance_eval.capability_catalog import (
    SQLITE_PROFILE_ADAPTERS,
    STANDARD_PROFILE_ADAPTERS,
    get_capability_adapter,
)
from governance_eval.candidate_bundle import recompute_decision
from governance_eval.docker_runtime import _profile_payload
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.standard_profile import (
    PROFILE_MARKER,
    SQLITE_PROFILE_MARKER,
    _apply_wheel_closure,
    _fixed_commands,
    _import_cycle_errors,
    _integrity_result,
    _release_workspace_directories,
    _source_snapshot,
    _write_sqlite_profile,
)
from governance_eval.unittest_runner import _accepted
from test_execution_plan_v2 import _receipt


def _stream(content: bytes) -> dict[str, object]:
    return {
        "captured_base64": base64.b64encode(content).decode("ascii"),
        "captured_bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "truncated": False,
    }


def _canonical_sha256(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class StandardProfileTests(unittest.TestCase):
    def test_standard_profile_does_not_add_sqlite_source_closure(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("package/generated.py", "VALUE = 1\n")
        package_result = {"status": "PASS", "evidence": {"errors": []}}

        _apply_wheel_closure(
            "python.standard.v1", buffer.getvalue(), package_result, None, []
        )

        self.assertEqual(package_result["status"], "PASS")
        self.assertEqual(package_result["evidence"]["errors"], [])

    def test_standard_profile_matches_rollback_golden_bytes(self) -> None:
        golden = json.loads(
            (
                Path(__file__).resolve().parents[1]
                / "fixtures/sqlite/standard_profile_rollback_golden.json"
            ).read_text(encoding="utf-8")
        )
        capabilities = [
            {
                "capability": capability,
                "adapter_id": adapter_id,
                "assurance_class": assurance,
                "status": "PASS",
                "evidence": {},
            }
            for capability, adapter_id, assurance in STANDARD_PROFILE_ADAPTERS
        ]
        payload = {
            "schema_version": "1.0",
            "profile": "python.standard.v1",
            "status": "PASS",
            "capabilities": capabilities,
        }
        framed = (
            PROFILE_MARKER
            + json.dumps(payload, sort_keys=True, separators=(",", ":"))
            + "\n"
        )

        self.assertEqual(
            golden["rollback_sha"], "c07b2ecf831fa2e3c68481a782a7e9e50d9dbc86"
        )
        adapters = [list(item) for item in STANDARD_PROFILE_ADAPTERS]
        self.assertEqual(adapters, golden["standard_profile_adapters"])
        self.assertEqual(
            _canonical_sha256(adapters), golden["standard_profile_adapters_sha256"]
        )
        runner = json.loads(
            json.dumps(
                asdict(
                    get_capability_adapter(
                        "standard_profile", "python.standard-profile.v1"
                    )
                )
            )
        )
        self.assertEqual(runner, golden["runner"])
        self.assertEqual(_canonical_sha256(runner), golden["runner_sha256"])
        step = compile_execution_plan_v2(
            _receipt(),
            capability="standard_profile",
            adapter_id="python.standard-profile.v1",
        ).step
        self.assertEqual(step, golden["standard_plan_step"])
        self.assertEqual(_canonical_sha256(step), golden["standard_plan_step_sha256"])
        self.assertEqual(framed, golden["canonical_profile_payload"])
        self.assertEqual(
            sha256(framed.encode()).hexdigest(),
            golden["canonical_profile_payload_sha256"],
        )
        ai = {"status": "AI_REVIEW_UNAVAILABLE", "findings": []}
        pass_decision = recompute_decision({"capability_status": "PASS"}, ai, "a" * 40)
        blocking_decision = recompute_decision(
            {"capability_status": "BLOCK_TECHNICAL"}, ai, "a" * 40
        )
        self.assertEqual(pass_decision, golden["pass_decision"])
        self.assertEqual(
            _canonical_sha256(pass_decision), golden["pass_decision_sha256"]
        )
        self.assertEqual(blocking_decision, golden["blocking_decision"])
        self.assertEqual(
            _canonical_sha256(blocking_decision),
            golden["blocking_decision_sha256"],
        )

    def test_unittest_rejects_zero_and_skipped_only(self) -> None:
        self.assertFalse(
            _accepted(
                {
                    "tests_run": 0,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 0,
                    "successful": True,
                }
            )
        )
        self.assertFalse(
            _accepted(
                {
                    "tests_run": 2,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 2,
                    "successful": True,
                }
            )
        )
        self.assertTrue(
            _accepted(
                {
                    "tests_run": 2,
                    "failures": 0,
                    "errors": 0,
                    "skipped": 1,
                    "successful": True,
                }
            )
        )

    def test_commands_are_fixed_and_offline(self) -> None:
        commands = _fixed_commands(
            Path("/workspace"),
            Path("/workspace/.governance-output/build-source"),
            ["src/example.py", "tests/test_example.py"],
            Path("/workspace/.governance-output"),
        )
        by_capability = {item[0]: item[3] for item in commands}
        self.assertIn("lint.mccabe.max-complexity=10", by_capability["complexity"])
        self.assertIn("--strict", by_capability["typecheck"])
        self.assertIn("--no-incremental", by_capability["typecheck"])
        self.assertIn("--cache-dir=/dev/null", by_capability["typecheck"])
        for option in ("--no-deps", "--no-index", "--no-build-isolation"):
            self.assertIn(option, by_capability["build"])
        self.assertFalse(
            any("sh" == argument for command in commands for argument in command[3])
        )

    def test_architecture_cycle_and_source_mutation_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.py").write_text("import two\n", encoding="utf-8")
            (root / "two.py").write_text("import one\n", encoding="utf-8")
            self.assertEqual(
                _import_cycle_errors(root, ["one.py", "two.py"]),
                ["import cycle: one -> two"],
            )
            initial = _source_snapshot(root)
            (root / "created.py").write_text("value = 1\n", encoding="utf-8")
            result = _integrity_result(root, initial)
            self.assertEqual(result["status"], "BLOCK_TECHNICAL")
            self.assertEqual(result["evidence"]["changed_files"], ["created.py"])

    def test_releases_container_owned_directories_for_host_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "generated" / "nested"
            nested.mkdir(parents=True)
            nested.chmod(0o500)

            _release_workspace_directories(root, nested.stat().st_uid)

            self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o777)

    def test_sqlite_profile_sidecar_is_host_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".governance-output").mkdir()
            with mock.patch(
                "governance_eval.standard_profile.os.fchmod", wraps=os.fchmod
            ) as chmod:
                _write_sqlite_profile(workspace, {"status": "PASS"})

            self.assertEqual(chmod.call_args.args[1], 0o644)

    def test_profile_marker_requires_exact_typed_capabilities(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(),
            capability="standard_profile",
            adapter_id="python.standard-profile.v1",
        )
        capabilities = [
            {
                "capability": capability,
                "adapter_id": adapter_id,
                "assurance_class": assurance,
                "status": "PASS",
                "evidence": {},
            }
            for capability, adapter_id, assurance in STANDARD_PROFILE_ADAPTERS
        ]
        payload = {
            "schema_version": "1.0",
            "profile": "python.standard.v1",
            "status": "PASS",
            "capabilities": capabilities,
        }
        raw = (
            PROFILE_MARKER + json.dumps(payload, separators=(",", ":")) + "\n"
        ).encode()
        outcome = {"stdout": _stream(raw)}
        self.assertEqual(_profile_payload(plan, outcome), capabilities)

        capabilities[0] = {**capabilities[0], "assurance_class": "COOPERATIVE_DYNAMIC"}
        hostile = (
            PROFILE_MARKER + json.dumps(payload, separators=(",", ":")) + "\n"
        ).encode()
        self.assertIsNone(_profile_payload(plan, {"stdout": _stream(hostile)}))

    def test_sqlite_profile_marker_requires_appended_exact_capability(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(),
            capability="standard_profile",
            adapter_id="python.sqlite-profile.v1",
        )
        capabilities = [
            {
                "capability": capability,
                "adapter_id": adapter_id,
                "assurance_class": assurance,
                "status": "PASS",
                "evidence": {},
            }
            for capability, adapter_id, assurance in SQLITE_PROFILE_ADAPTERS
        ]
        payload = {
            "schema_version": "1.0",
            "profile": "python.sqlite.v1",
            "status": "PASS",
            "capabilities": capabilities,
        }
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            output = workspace / ".governance-output" / "sqlite-profile.json"
            output.parent.mkdir()

            def encoded(value: dict[str, object]) -> bytes:
                content = json.dumps(value, separators=(",", ":")).encode()
                output.write_bytes(content)
                compact = {
                    "schema_version": "1.0",
                    "profile": "python.sqlite.v1",
                    "status": "PASS",
                    "capabilities_path": ".governance-output/sqlite-profile.json",
                    "capabilities_sha256": sha256(content).hexdigest(),
                }
                return (
                    SQLITE_PROFILE_MARKER
                    + json.dumps(compact, separators=(",", ":"))
                    + "\n"
                ).encode()

            self.assertEqual(
                _profile_payload(
                    plan, {"stdout": _stream(encoded(payload))}, workspace
                ),
                capabilities,
            )

            payload["capabilities"] = capabilities[:-1]
            self.assertIsNone(
                _profile_payload(plan, {"stdout": _stream(encoded(payload))}, workspace)
            )


if __name__ == "__main__":
    unittest.main()
