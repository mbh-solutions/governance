from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from governance_eval.capability_catalog import get_capability_adapter
from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named
from governance_eval.sqlite_policy import POLICY_SHA256

_IMAGE = (
    "python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d"
)
_POLICY_ID = "docker.lockdown.v1"
_RUFF_SHA256 = "68971e86ff2a4bd44f45dc2dd28e590e785fea12dc966410ae269173ce6d64db"
_PROFILE_TOOLCHAIN_SHA256 = (
    "a3febf305b754c41ab62abeee10437ad550b82d7810d8492393ca0cae5b3784d"
)


class ExecutionPlanV2Error(ValueError):
    pass


@dataclass(frozen=True)
class ExecutionPlanV2:
    schema_version: str
    plan_id: str
    checkout_receipt_id: str
    repository: dict[str, Any]
    pull_request: int
    target: dict[str, str]
    evaluator: dict[str, str]
    runtime: dict[str, Any]
    step: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "checkout_receipt_id": self.checkout_receipt_id,
            "repository": self.repository,
            "pull_request": self.pull_request,
            "target": self.target,
            "evaluator": self.evaluator,
            "runtime": self.runtime,
            "step": self.step,
        }


def compile_execution_plan_v2(
    receipt: CheckoutReceipt, *, capability: str, adapter_id: str
) -> ExecutionPlanV2:
    _validate_receipt(receipt)
    try:
        adapter = get_capability_adapter(capability, adapter_id)
    except KeyError as exc:
        raise ExecutionPlanV2Error(
            f"unsupported capability adapter: {capability}/{adapter_id}"
        ) from exc
    if (capability, adapter_id) == ("lint", "python.ruff-check.v1"):
        toolchain_sha256 = _RUFF_SHA256
        toolchain = {"ruff": "0.15.21"}
        argv = ["/opt/governance-toolchain/ruff", *adapter.arguments]
    elif capability == "standard_profile" and adapter_id in {
        "python.standard-profile.v1",
        "python.sqlite-profile.v1",
    }:
        toolchain_sha256 = _PROFILE_TOOLCHAIN_SHA256
        toolchain = {
            "governance-eval": "0.1.0",
            "mypy": "2.2.0",
            "ruff": "0.15.21",
            "setuptools": "83.0.0",
        }
        argv = [
            "python",
            *adapter.arguments,
            "--evaluator-sha",
            receipt.evaluator["commit_sha"],
        ]
    else:
        raise ExecutionPlanV2Error("adapter has no authenticated Docker implementation")
    step = {
        "step_id": adapter.capability,
        "adapter_id": adapter.adapter_id,
        "toolchain": toolchain,
        "argv": argv,
        "working_directory": "/workspace",
        "timeout_seconds": adapter.timeout_seconds,
        "output_limit_bytes": adapter.output_limit_bytes,
    }
    if adapter_id == "python.sqlite-profile.v1":
        step["sqlite_policy_sha256"] = POLICY_SHA256
    plan = ExecutionPlanV2(
        schema_version="2.0",
        plan_id="",
        checkout_receipt_id=receipt.receipt_id,
        repository=dict(receipt.repository),
        pull_request=receipt.pull_request["number"],
        target={
            "commit_sha": receipt.pull_request["head_sha"],
            "tree_sha": receipt.pull_request["head_tree_sha"],
        },
        evaluator=dict(receipt.evaluator),
        runtime={
            "runtime_id": "docker.python-toolchain.v1",
            "policy_id": _POLICY_ID,
            "image": _IMAGE,
            "network": "none",
            "user": "65532:65532",
            "read_only_root": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "pids_limit": 128,
            "memory_bytes": 536870912,
            "cpus": "1.0",
            "toolchain_sha256": toolchain_sha256,
            "docker_path": receipt.docker["path"],
            "docker_sha256": receipt.docker["sha256"],
            "docker_host": receipt.docker["host"],
        },
        step=step,
    )
    return replace(plan, plan_id=sha256_json(_unsigned(plan)))


def assess_execution_plan_v2(payload: Any, receipt: CheckoutReceipt) -> dict[str, Any]:
    errors: list[str] = []
    try:
        step = payload.get("step") if isinstance(payload, dict) else None
        raw_capability = step.get("step_id") if isinstance(step, dict) else ""
        raw_adapter_id = step.get("adapter_id") if isinstance(step, dict) else ""
        capability = raw_capability if isinstance(raw_capability, str) else ""
        adapter_id = raw_adapter_id if isinstance(raw_adapter_id, str) else ""
        expected = compile_execution_plan_v2(
            receipt, capability=capability, adapter_id=adapter_id
        ).to_json()
    except ExecutionPlanV2Error as exc:
        errors.append(str(exc))
        expected = None
    if not isinstance(payload, dict):
        errors.append("execution plan v2 must be an object")
    elif expected is not None and payload != expected:
        errors.append("execution plan v2 differs from evaluator-owned plan")
    return {
        "schema_version": "2.0",
        "capability_status": "BLOCK_TECHNICAL" if errors else "PASS",
        "plan_id": payload.get("plan_id", "") if isinstance(payload, dict) else "",
        "errors": errors,
    }


def _validate_receipt(receipt: CheckoutReceipt) -> None:
    if not isinstance(receipt, CheckoutReceipt):
        raise ExecutionPlanV2Error("checkout receipt is invalid")
    payload = receipt.to_json()
    try:
        validate_packaged_named("checkout_receipt", payload)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        raise ExecutionPlanV2Error("checkout receipt schema is invalid") from exc
    if not _receipt_url_matches_identity(payload):
        raise ExecutionPlanV2Error("checkout receipt pull request URL is invalid")
    receipt_id = payload.pop("receipt_id", None)
    if receipt_id != sha256_json(payload):
        raise ExecutionPlanV2Error("checkout receipt integrity is invalid")
    observed_at = receipt.workflow.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        raise ExecutionPlanV2Error("checkout receipt observed_at is invalid")
    try:
        datetime.fromisoformat(observed_at.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ExecutionPlanV2Error("checkout receipt observed_at is invalid") from exc


def _receipt_url_matches_identity(payload: dict[str, Any]) -> bool:
    repository = payload["repository"]["full_name"]
    pull_request = payload["pull_request"]
    parsed = urlparse(pull_request["url"])
    expected_path = f"/{repository}/pull/{pull_request['number']}"
    return (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.path == expected_path
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _unsigned(plan: ExecutionPlanV2) -> dict[str, Any]:
    payload = plan.to_json()
    payload.pop("plan_id")
    return payload
