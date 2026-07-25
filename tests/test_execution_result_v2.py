from __future__ import annotations

import base64
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from os import chdir
from pathlib import Path
from tempfile import TemporaryDirectory

from governance_eval.capability_catalog import (
    SQLITE_PROFILE_ADAPTERS,
    STANDARD_PROFILE_ADAPTERS,
)
from governance_eval.docker_runtime import (
    _result as host_result,
)
from governance_eval.docker_runtime import docker_run_argv, runtime_root_path
from governance_eval.execution_plan_v2 import ExecutionPlanV2, compile_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.hashing import sha256_json
from governance_eval.sqlite_policy import (
    CERTIFIED_SQLITE_IDENTITY,
    POLICY_ID,
    POLICY_SHA256,
)
from governance_eval.sqlite_supportability import (
    MAX_AST_NODES,
    MAX_SOURCE_BYTES,
    _limit_evidence,
)
from test_execution_plan_v2 import _receipt

_WHEEL_SHA256 = "a" * 64


def _stream(content: bytes = b"") -> dict[str, object]:
    return {
        "captured_base64": base64.b64encode(content).decode("ascii"),
        "captured_bytes": len(content),
        "sha256": sha256(content).hexdigest(),
        "truncated": False,
    }


def _result() -> tuple[dict[str, object], object, object]:
    receipt = _receipt()
    plan = compile_execution_plan_v2(
        receipt, capability="lint", adapter_id="python.ruff-check.v1"
    )
    runtime_root = runtime_root_path(plan)
    command = [
        plan.runtime["docker_path"],
        f"--host={plan.runtime['docker_host']}",
        "run",
        "--rm",
        "--name=governance-123",
        "--read-only",
        "--network=none",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=128",
        "--memory=536870912",
        "--cpus=1.0",
        "--env=HOME=/workspace/.home",
        "--env=TMPDIR=/workspace/.tmp",
        "--env=PYTHONNOUSERSITE=1",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--workdir=/workspace",
        "--mount",
        f"type=bind,src={runtime_root / 'workspace'},dst=/workspace",
        "--mount",
        f"type=bind,src={runtime_root / 'toolchain'},dst=/opt/governance-toolchain,readonly",
        plan.runtime["image"],
        *plan.step["argv"],
    ]
    payload: dict[str, object] = {
        "schema_version": "2.0",
        "artifact_id": "",
        "plan_id": plan.plan_id,
        "checkout_receipt_id": receipt.receipt_id,
        "capability_status": "PASS",
        "runtime": {
            "image": plan.runtime["image"],
            "policy_id": plan.runtime["policy_id"],
            "docker_path": plan.runtime["docker_path"],
            "docker_sha256": plan.runtime["docker_sha256"],
            "docker_host": plan.runtime["docker_host"],
            "toolchain": "ruff==0.15.21",
            "toolchain_sha256": plan.runtime["toolchain_sha256"],
        },
        "command": command,
        "started_at": "2026-07-19T12:00:00Z",
        "completed_at": "2026-07-19T12:00:01Z",
        "duration_seconds": 1.0,
        "timeout_seconds": 120,
        "termination": "EXITED",
        "exit_code": 0,
        "stdout": _stream(),
        "stderr": _stream(),
        "errors": [],
    }
    payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
    return payload, plan, receipt


def _sqlite_evidence() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "policy_id": POLICY_ID,
        "policy_sha256": POLICY_SHA256,
        "wheel_sha256": _WHEEL_SHA256,
        "gate_implementation": "PASS",
        "repo_sql_supportability": "PASS",
        "sql_behavior_proof": "PASS",
        "files": [
            {"path": "package/db.py", "bytes": 1, "sha256": sha256(b"x").hexdigest()}
        ],
        "sinks": [{"path": "package/db.py", "line": 1, "sink": "execute"}],
        "receiver_provenance": [
            {
                "path": "package/db.py",
                "line": 1,
                "receiver": "connection",
                "proof": "sqlite annotation",
            }
        ],
        "resources": [],
        "preparations": [
            {
                "path": "package/db.py",
                "line": 1,
                "sink": "execute",
                "selector": None,
                "sql_sha256": sha256(b"SELECT 1").hexdigest(),
                "status": "PASS",
                "error": None,
            }
        ],
        "sqlite_identity": {**CERTIFIED_SQLITE_IDENTITY, "observed_functions": []},
        "counts": {
            "ast_nodes": 1,
            "files": 1,
            "sinks": 1,
            "source_bytes": 1,
            "sql_statements": 1,
        },
        "limits": _limit_evidence(),
        "started_at": "2026-07-19T12:00:00Z",
        "completed_at": "2026-07-19T12:00:01Z",
        "errors": [],
    }


def _sqlite_result() -> tuple[dict[str, object], object, object]:
    receipt = _receipt()
    plan = compile_execution_plan_v2(
        receipt,
        capability="standard_profile",
        adapter_id="python.sqlite-profile.v1",
    )
    root = runtime_root_path(plan)
    command = docker_run_argv(
        docker=Path(plan.runtime["docker_path"]),
        docker_host=plan.runtime["docker_host"],
        plan=plan,
        workspace=root / "workspace",
        toolchain_root=root / "toolchain",
        container_name="governance-sqlite-profile",
    )
    capabilities = [
        {
            "capability": capability,
            "adapter_id": adapter_id,
            "assurance_class": assurance,
            "status": "PASS",
            "evidence": (
                _sqlite_evidence()
                if capability == "sql_supportability"
                else {"wheel_sha256": _WHEEL_SHA256}
                if capability == "package_audit"
                else {}
            ),
        }
        for capability, adapter_id, assurance in SQLITE_PROFILE_ADAPTERS
    ]
    started = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
    outcome = {
        "termination": "EXITED",
        "exit_code": 0,
        "stdout": _stream(),
        "stderr": _stream(),
        "started_at": started,
        "completed_at": started + timedelta(seconds=1),
    }
    payload = host_result(
        plan,
        receipt,
        None,
        plan.runtime["docker_host"],
        command,
        started,
        outcome=outcome,
        errors=[],
        profile=capabilities,
    )
    return payload, plan, receipt


class ExecutionResultV2Tests(unittest.TestCase):
    def test_accepts_typed_profile_and_rejects_assurance_mutation(self) -> None:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt,
            capability="standard_profile",
            adapter_id="python.standard-profile.v1",
        )
        root = runtime_root_path(plan)
        command = docker_run_argv(
            docker=Path(plan.runtime["docker_path"]),
            docker_host=plan.runtime["docker_host"],
            plan=plan,
            workspace=root / "workspace",
            toolchain_root=root / "toolchain",
            container_name="governance-profile",
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
        started = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        outcome = {
            "termination": "EXITED",
            "exit_code": 0,
            "stdout": _stream(),
            "stderr": _stream(),
            "started_at": started,
            "completed_at": started + timedelta(seconds=1),
        }
        payload = host_result(
            plan,
            receipt,
            None,
            plan.runtime["docker_host"],
            command,
            started,
            outcome=outcome,
            errors=[],
            profile=capabilities,
        )
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

        payload["capabilities"][5]["assurance_class"] = "EVALUATOR_AUTHORITATIVE"
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )

    def test_accepts_sqlite_profile_and_rejects_capability_omission(self) -> None:
        payload, plan, receipt = _sqlite_result()
        capabilities = payload["capabilities"]
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

        for mutation in (
            "pass error",
            "orphan preparation",
            "provenance",
            "AST bound",
            "source bound",
            "function",
            "wheel",
            "resource",
        ):
            with self.subTest(mutation=mutation):
                hostile = deepcopy(payload)
                evidence = hostile["capabilities"][-1]["evidence"]
                if mutation == "pass error":
                    evidence["preparations"][0]["error"] = "not authorized"
                elif mutation == "orphan preparation":
                    evidence["preparations"].append(
                        {**evidence["preparations"][0], "line": 2}
                    )
                    evidence["counts"]["sql_statements"] += 1
                elif mutation == "provenance":
                    evidence["receiver_provenance"][0]["line"] = 2
                elif mutation == "AST bound":
                    evidence["counts"]["ast_nodes"] = MAX_AST_NODES + 1
                elif mutation == "source bound":
                    evidence["counts"]["source_bytes"] = MAX_SOURCE_BYTES + 1
                elif mutation == "function":
                    evidence["sqlite_identity"]["observed_functions"] = ["abs"]
                elif mutation == "wheel":
                    evidence["wheel_sha256"] = "b" * 64
                else:
                    evidence["resources"] = ["package/missing.sql"]
                hostile["artifact_id"] = sha256_json({**hostile, "artifact_id": ""})
                self.assertEqual(
                    validate_execution_result_v2(hostile, plan, receipt)[
                        "integrity_status"
                    ],
                    "INTEGRITY_INVALID",
                )

        hostile = deepcopy(payload)
        hostile["capabilities"][-1]["evidence"]["policy_sha256"] = "0" * 64
        hostile["artifact_id"] = sha256_json({**hostile, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(hostile, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )

        payload["capabilities"] = capabilities[:-1]
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )

    def test_rejects_hostile_sqlite_evidence_semantics(self) -> None:
        payload, plan, receipt = _sqlite_result()
        for mutation in (
            "null wheel identities",
            "reversed evidence time",
            "duplicate preparation",
            "traversal paths",
            "zero AST",
            "zero sinks",
        ):
            with self.subTest(mutation=mutation):
                hostile = deepcopy(payload)
                evidence = hostile["capabilities"][-1]["evidence"]
                if mutation == "null wheel identities":
                    evidence["wheel_sha256"] = None
                    next(
                        item
                        for item in hostile["capabilities"]
                        if item["capability"] == "package_audit"
                    )["evidence"]["wheel_sha256"] = None
                elif mutation == "reversed evidence time":
                    evidence["started_at"] = "2026-07-19T12:00:02Z"
                elif mutation == "duplicate preparation":
                    evidence["preparations"].append(
                        deepcopy(evidence["preparations"][0])
                    )
                    evidence["counts"]["sql_statements"] += 1
                elif mutation == "traversal paths":
                    for collection in (
                        evidence["files"],
                        evidence["sinks"],
                        evidence["receiver_provenance"],
                        evidence["preparations"],
                    ):
                        collection[0]["path"] = "../escape.py"
                elif mutation == "zero AST":
                    evidence["counts"]["ast_nodes"] = 0
                else:
                    evidence["sinks"] = []
                    evidence["receiver_provenance"] = []
                    evidence["preparations"] = []
                    evidence["counts"]["sinks"] = 0
                    evidence["counts"]["sql_statements"] = 0
                hostile["artifact_id"] = sha256_json({**hostile, "artifact_id": ""})
                self.assertEqual(
                    validate_execution_result_v2(hostile, plan, receipt)[
                        "integrity_status"
                    ],
                    "INTEGRITY_INVALID",
                )

    def test_accepts_exact_host_result(self) -> None:
        payload, plan, receipt = _result()

        assessment = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(assessment["integrity_status"], "INTEGRITY_VALID")

    def test_accepts_safe_unicode_sqlite_evidence_path(self) -> None:
        payload, plan, receipt = _sqlite_result()
        evidence = payload["capabilities"][-1]["evidence"]
        path = "package/" + "é" * 129 + ".py"
        for collection in (
            evidence["files"],
            evidence["sinks"],
            evidence["receiver_provenance"],
            evidence["preparations"],
        ):
            collection[0]["path"] = path
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

        assessment = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(assessment["integrity_status"], "INTEGRITY_VALID")

    def test_rejects_rehashed_command_runtime_and_output_mutation(self) -> None:
        for mutation in ("command", "image", "output", "mounts"):
            with self.subTest(mutation=mutation):
                payload, plan, receipt = _result()
                hostile = deepcopy(payload)
                if mutation == "command":
                    hostile["command"][-1] = "--exit-zero"
                elif mutation == "image":
                    hostile["runtime"]["image"] = "python@sha256:" + "0" * 64
                else:
                    if mutation == "output":
                        hostile["stdout"]["captured_base64"] = "WA=="
                    else:
                        trusted_root = runtime_root_path(plan)
                        attacker_root = (
                            Path("C:/attacker-controlled") / trusted_root.name
                        )
                        hostile["command"] = [
                            item.replace(str(trusted_root), str(attacker_root))
                            for item in hostile["command"]
                        ]
                hostile["artifact_id"] = sha256_json({**hostile, "artifact_id": ""})

                assessment = validate_execution_result_v2(hostile, plan, receipt)

                self.assertEqual(assessment["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_combined_over_limit_and_truncated_pass(self) -> None:
        payload, plan, receipt = _result()
        payload["stdout"] = _stream(b"a" * 40000)
        payload["stderr"] = _stream(b"b" * 40000)
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )

    def test_rejects_below_limit_truncated_block_evidence(self) -> None:
        payload, plan, receipt = _result()
        payload["capability_status"] = "BLOCK_TECHNICAL"
        payload["termination"] = "OUTPUT_LIMIT"
        payload["exit_code"] = 137
        payload["stdout"]["truncated"] = True
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

        result = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_short_command_and_invalid_timing(self) -> None:
        mutations = (
            ("short command", {"command": ["docker"]}),
            ("reversed time", {"completed_at": "2026-07-19T11:59:59Z"}),
            ("bad duration", {"duration_seconds": 9.0}),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                payload, plan, receipt = _result()
                payload.update(mutation)
                payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

                result = validate_execution_result_v2(payload, plan, receipt)

                self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_result_that_matches_rehashed_mutated_plan(self) -> None:
        payload, plan, receipt = _result()
        plan_payload = deepcopy(plan.to_json())
        plan_payload["runtime"]["network"] = "bridge"
        plan_payload["plan_id"] = sha256_json(
            {key: value for key, value in plan_payload.items() if key != "plan_id"}
        )
        hostile_plan = ExecutionPlanV2(**plan_payload)
        payload["plan_id"] = hostile_plan.plan_id
        payload["command"][6] = "--network=bridge"
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

        result = validate_execution_result_v2(payload, hostile_plan, receipt)

        self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_execution_longer_than_plan_timeout(self) -> None:
        payload, plan, receipt = _result()
        payload["completed_at"] = "2026-07-19T12:02:01Z"
        payload["duration_seconds"] = 121.0
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

        result = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

    def test_accepts_only_exact_timeout_deadline(self) -> None:
        for duration, completed_at, expected in (
            (119.999, "2026-07-19T12:01:59.999000Z", "INTEGRITY_INVALID"),
            (120.0, "2026-07-19T12:02:00Z", "INTEGRITY_VALID"),
            (120.001, "2026-07-19T12:02:00.001000Z", "INTEGRITY_INVALID"),
        ):
            with self.subTest(duration=duration):
                payload, plan, receipt = _result()
                payload["capability_status"] = "BLOCK_TECHNICAL"
                payload["termination"] = "TIMED_OUT"
                payload["exit_code"] = 137
                payload["completed_at"] = completed_at
                payload["duration_seconds"] = duration
                payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

                result = validate_execution_result_v2(payload, plan, receipt)

                self.assertEqual(result["integrity_status"], expected)

    def test_result_schema_cannot_be_replaced_by_target_checkout(self) -> None:
        _, plan, receipt = _result()
        original = Path.cwd()
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "TASK.md").write_text("target", encoding="utf-8")
            (root / "AGENTS.md").write_text("target", encoding="utf-8")
            schema = root / "schemas" / "v2" / "execution_result.schema.json"
            schema.parent.mkdir(parents=True)
            schema.write_text("{}", encoding="utf-8")
            try:
                chdir(root)
                result = validate_execution_result_v2(
                    {"artifact_id": "0" * 64}, plan, receipt
                )
            finally:
                chdir(original)

        self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

    def test_rejects_exited_result_without_exit_code(self) -> None:
        payload, plan, receipt = _result()
        payload["capability_status"] = "BLOCK_TECHNICAL"
        payload["exit_code"] = None
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})

        result = validate_execution_result_v2(payload, plan, receipt)

        self.assertEqual(result["integrity_status"], "INTEGRITY_INVALID")

        payload, plan, receipt = _result()
        payload["stdout"]["truncated"] = True
        payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
        self.assertEqual(
            validate_execution_result_v2(payload, plan, receipt)["integrity_status"],
            "INTEGRITY_INVALID",
        )


if __name__ == "__main__":
    unittest.main()
