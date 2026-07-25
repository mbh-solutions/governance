from __future__ import annotations

import unittest
from copy import deepcopy
from os import chdir
from pathlib import Path
from tempfile import TemporaryDirectory

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.execution_plan_v2 import (
    ExecutionPlanV2Error,
    assess_execution_plan_v2,
    compile_execution_plan_v2,
)
from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_named
from governance_eval.sqlite_policy import POLICY_SHA256


def _receipt() -> CheckoutReceipt:
    receipt = CheckoutReceipt(
        schema_version="1.0",
        receipt_id="",
        repository={"id": 123, "full_name": "markheck-solutions/governance"},
        pull_request={
            "number": 81,
            "url": "https://github.com/markheck-solutions/governance/pull/81",
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "base_tree_sha": "c" * 40,
            "head_tree_sha": "d" * 40,
        },
        evaluator={
            "repository_id": 123,
            "repository_full_name": "markheck-solutions/governance",
            "commit_sha": "e" * 40,
            "tree_sha": "f" * 40,
        },
        workflow={
            "workflow_ref": "markheck-solutions/governance/.github/workflows/governance.yml@refs/heads/main",
            "run_id": 999,
            "run_attempt": 1,
            "server_url": "https://github.com",
            "api_url": "https://api.github.com",
            "observed_at": "2026-07-19T12:00:00Z",
        },
        git_path=str(Path("C:/trusted/git.exe")),
        git_sha256="3" * 64,
        docker={
            "path": str(Path("C:/trusted/docker.exe")),
            "sha256": "4" * 64,
            "host": "npipe:////./pipe/docker_engine",
        },
        config_sha256="1" * 64,
        standard_sha256="2" * 64,
    )
    payload = receipt.to_json()
    payload.pop("receipt_id")
    return CheckoutReceipt(**{**receipt.__dict__, "receipt_id": sha256_json(payload)})


class ExecutionPlanV2Tests(unittest.TestCase):
    def test_compiles_fixed_standard_profile_from_receipt(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(),
            capability="standard_profile",
            adapter_id="python.standard-profile.v1",
        )

        payload = plan.to_json()
        validate_named("execution_plan_v2", payload)
        self.assertEqual(payload["step"]["timeout_seconds"], 300)
        self.assertEqual(
            payload["runtime"]["toolchain_sha256"],
            "a3febf305b754c41ab62abeee10437ad550b82d7810d8492393ca0cae5b3784d",
        )
        self.assertEqual(
            payload["step"]["argv"],
            [
                "python",
                "-P",
                "-s",
                "-m",
                "governance_eval.standard_profile",
                "--workspace",
                "/workspace",
                "--benchmark-root",
                "/opt/governance-toolchain/benchmark",
                "--evaluator-sha",
                "e" * 40,
            ],
        )

    def test_compiles_fixed_sqlite_profile_as_standard_extension(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(),
            capability="standard_profile",
            adapter_id="python.sqlite-profile.v1",
        )

        payload = plan.to_json()
        validate_named("execution_plan_v2", payload)
        self.assertEqual(payload["step"]["timeout_seconds"], 300)
        self.assertEqual(payload["step"]["sqlite_policy_sha256"], POLICY_SHA256)
        self.assertEqual(
            payload["step"]["argv"],
            [
                "python",
                "-P",
                "-s",
                "-m",
                "governance_eval.standard_profile",
                "--workspace",
                "/workspace",
                "--benchmark-root",
                "/opt/governance-toolchain/benchmark",
                "--profile",
                "python.sqlite.v1",
                "--evaluator-sha",
                "e" * 40,
            ],
        )

    def test_compiles_only_from_authenticated_checkout_receipt(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(), capability="lint", adapter_id="python.ruff-check.v1"
        )

        payload = plan.to_json()
        validate_named("execution_plan_v2", payload)
        self.assertEqual(payload["checkout_receipt_id"], _receipt().receipt_id)
        self.assertEqual(payload["target"]["tree_sha"], "d" * 40)
        self.assertEqual(payload["evaluator"]["tree_sha"], "f" * 40)
        self.assertEqual(
            payload["runtime"]["image"],
            "python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d",
        )
        self.assertEqual(payload["runtime"]["policy_id"], "docker.lockdown.v1")
        self.assertEqual(
            payload["step"]["argv"],
            [
                "/opt/governance-toolchain/ruff",
                "check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                ".",
            ],
        )
        self.assertEqual(
            payload["runtime"]["toolchain_sha256"],
            "68971e86ff2a4bd44f45dc2dd28e590e785fea12dc966410ae269173ce6d64db",
        )

    def test_rejects_fabricated_or_mutated_receipt(self) -> None:
        receipt = _receipt()
        for field, value in (
            ("receipt_id", "0" * 64),
            ("config_sha256", "9" * 64),
        ):
            with self.subTest(field=field):
                hostile = CheckoutReceipt(**{**receipt.__dict__, field: value})
                with self.assertRaisesRegex(
                    ExecutionPlanV2Error, "checkout receipt integrity is invalid"
                ):
                    compile_execution_plan_v2(
                        hostile,
                        capability="lint",
                        adapter_id="python.ruff-check.v1",
                    )

    def test_rejects_self_hashed_schema_invalid_receipt(self) -> None:
        cases = (
            ({"run_id": "not-an-integer"}, "schema is invalid"),
            ({"observed_at": "not-a-date"}, "observed_at is invalid"),
        )
        for workflow_change, expected in cases:
            with self.subTest(workflow_change=workflow_change):
                receipt = _receipt()
                workflow = {**receipt.workflow, **workflow_change}
                hostile = CheckoutReceipt(
                    **{**receipt.__dict__, "workflow": workflow, "receipt_id": ""}
                )
                payload = hostile.to_json()
                payload.pop("receipt_id")
                hostile = CheckoutReceipt(
                    **{**hostile.__dict__, "receipt_id": sha256_json(payload)}
                )

                with self.assertRaisesRegex(ExecutionPlanV2Error, expected):
                    compile_execution_plan_v2(
                        hostile,
                        capability="lint",
                        adapter_id="python.ruff-check.v1",
                    )

    def test_receipt_schema_cannot_be_replaced_by_target_checkout(self) -> None:
        receipt = _receipt()
        hostile = CheckoutReceipt(
            **{
                **receipt.__dict__,
                "workflow": {**receipt.workflow, "run_id": "not-an-integer"},
                "receipt_id": "",
            }
        )
        unsigned = hostile.to_json()
        unsigned.pop("receipt_id")
        hostile = CheckoutReceipt(
            **{**hostile.__dict__, "receipt_id": sha256_json(unsigned)}
        )
        original = Path.cwd()
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "TASK.md").write_text("target", encoding="utf-8")
            (root / "AGENTS.md").write_text("target", encoding="utf-8")
            schema = root / "schemas" / "v1" / "checkout_receipt.schema.json"
            schema.parent.mkdir(parents=True)
            schema.write_text("{}", encoding="utf-8")
            try:
                chdir(root)
                with self.assertRaisesRegex(
                    ExecutionPlanV2Error, "checkout receipt schema is invalid"
                ):
                    compile_execution_plan_v2(
                        hostile,
                        capability="lint",
                        adapter_id="python.ruff-check.v1",
                    )
            finally:
                chdir(original)

    def test_rejects_self_hashed_pull_request_url_mismatch(self) -> None:
        receipt = _receipt()
        hostile = CheckoutReceipt(
            **{
                **receipt.__dict__,
                "pull_request": {
                    **receipt.pull_request,
                    "url": "https://github.com/markheck-solutions/other/pull/999",
                },
                "receipt_id": "",
            }
        )
        unsigned = hostile.to_json()
        unsigned.pop("receipt_id")
        hostile = CheckoutReceipt(
            **{**hostile.__dict__, "receipt_id": sha256_json(unsigned)}
        )

        with self.assertRaisesRegex(ExecutionPlanV2Error, "pull request URL"):
            compile_execution_plan_v2(
                hostile, capability="lint", adapter_id="python.ruff-check.v1"
            )

    def test_blocks_rehashed_runtime_or_command_mutation(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(), capability="lint", adapter_id="python.ruff-check.v1"
        )
        for path, value in (
            (("runtime", "image"), "python:latest"),
            (("runtime", "policy_id"), "docker.unlocked.v1"),
            (("step", "argv"), ["sh", "-c", "ruff check . || true"]),
        ):
            with self.subTest(path=path):
                payload = deepcopy(plan.to_json())
                payload[path[0]][path[1]] = value
                unsigned = {
                    key: item for key, item in payload.items() if key != "plan_id"
                }
                payload["plan_id"] = sha256_json(unsigned)

                result = assess_execution_plan_v2(payload, _receipt())

                self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")


if __name__ == "__main__":
    unittest.main()
