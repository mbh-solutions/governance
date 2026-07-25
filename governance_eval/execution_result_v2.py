from __future__ import annotations

import base64
import binascii
import math
from datetime import datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

from governance_eval.capability_catalog import (
    is_profile_runner,
    profile_adapters,
    runner_profile,
)
from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.docker_runtime import docker_run_argv, runtime_root_path
from governance_eval.execution_plan_v2 import ExecutionPlanV2, assess_execution_plan_v2
from governance_eval.hashing import sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named
from governance_eval.sqlite_policy import (
    ALLOWED_FUNCTIONS,
    CERTIFIED_SQLITE_IDENTITY,
    POLICY_ID,
    POLICY_SHA256,
)
from governance_eval.sqlite_supportability import (
    MAX_AST_NODES,
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_SINKS,
    MAX_SOURCE_BYTES,
    MAX_STATEMENTS,
    _limit_evidence,
)

_TIMING_TOLERANCE_SECONDS = 0.001


def validate_execution_result_v2(
    payload: Any, plan: ExecutionPlanV2, receipt: CheckoutReceipt
) -> dict[str, Any]:
    error = _integrity_error(payload, plan, receipt)
    errors = [] if error is None else [error]
    return {
        "schema_version": "2.0",
        "integrity_status": "INTEGRITY_INVALID" if errors else "INTEGRITY_VALID",
        "artifact_id": payload.get("artifact_id", "")
        if isinstance(payload, dict)
        else "",
        "errors": errors,
    }


def _integrity_error(
    payload: Any, plan: ExecutionPlanV2, receipt: CheckoutReceipt
) -> str | None:
    identity_error = _identity_error(payload, plan, receipt)
    if identity_error is not None:
        return identity_error
    binding_error = _runtime_error(payload, plan)
    if binding_error is not None:
        return binding_error
    output_error = _output_error(payload, plan)
    if output_error is not None:
        return output_error
    outcome_error = _outcome_error(payload)
    if outcome_error is not None:
        return outcome_error
    profile_error = _profile_error(payload, plan)
    if profile_error is not None:
        return profile_error
    return _timing_error(payload, plan.step["timeout_seconds"])


def _identity_error(
    payload: Any, plan: ExecutionPlanV2, receipt: CheckoutReceipt
) -> str | None:
    plan_assessment = assess_execution_plan_v2(plan.to_json(), receipt)
    if plan_assessment["capability_status"] != "PASS":
        return "execution result v2 plan is not evaluator-owned"
    if not isinstance(payload, dict):
        return "execution result v2 must be an object"
    try:
        validate_packaged_named("execution_result_v2", payload)
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        return f"execution result v2 schema invalid: {exc}"
    if payload["artifact_id"] != sha256_json({**payload, "artifact_id": ""}):
        return "execution result v2 artifact id is invalid"
    if payload["plan_id"] != plan.plan_id:
        return "execution result v2 plan id mismatch"
    if payload["checkout_receipt_id"] != receipt.receipt_id:
        return "execution result v2 checkout receipt mismatch"
    return None


def _output_error(payload: dict[str, Any], plan: ExecutionPlanV2) -> str | None:
    for name in ("stdout", "stderr"):
        error = _stream_error(name, payload[name])
        if error is not None:
            return error
    captured = payload["stdout"]["captured_bytes"] + payload["stderr"]["captured_bytes"]
    if captured > plan.step["output_limit_bytes"]:
        return "execution result v2 combined output exceeds plan limit"
    truncated = any(payload[name]["truncated"] for name in ("stdout", "stderr"))
    if truncated and captured != plan.step["output_limit_bytes"]:
        return "execution result v2 truncated output does not equal plan limit"
    if payload["capability_status"] == "PASS" and any(
        payload[name]["truncated"] for name in ("stdout", "stderr")
    ):
        return "execution result v2 PASS output cannot be truncated"
    return None


def _runtime_error(payload: dict[str, Any], plan: ExecutionPlanV2) -> str | None:
    runtime = payload["runtime"]
    toolchain = (
        plan.step["adapter_id"]
        if is_profile_runner(plan.step["adapter_id"])
        else "ruff==0.15.21"
    )
    expected = {
        "image": plan.runtime["image"],
        "policy_id": plan.runtime["policy_id"],
        "toolchain": toolchain,
        "toolchain_sha256": plan.runtime["toolchain_sha256"],
        "docker_path": plan.runtime["docker_path"],
        "docker_sha256": plan.runtime["docker_sha256"],
        "docker_host": plan.runtime["docker_host"],
    }
    if any(runtime[field] != value for field, value in expected.items()):
        return "execution result v2 runtime mismatch"
    if payload["timeout_seconds"] != plan.step["timeout_seconds"]:
        return "execution result v2 timeout mismatch"
    if not payload["command"]:
        return (
            None
            if payload["termination"] == "NOT_STARTED"
            else "execution result v2 command is missing"
        )
    if len(payload["command"]) < 2:
        return "execution result v2 command shape is invalid"
    if payload["command"][1] != f"--host={runtime['docker_host']}":
        return "execution result v2 Docker host mismatch"
    return _command_error(payload["command"], runtime["docker_path"], plan)


def _command_error(
    command: list[str], docker_path: str, plan: ExecutionPlanV2
) -> str | None:
    try:
        name = next(
            item.split("=", 1)[1] for item in command if item.startswith("--name=")
        )
        mount = next(
            item
            for item in command
            if item.startswith("type=bind,") and item.endswith(",dst=/workspace")
        )
        workspace = mount.removeprefix("type=bind,src=").removesuffix(",dst=/workspace")
        toolchain_mount = next(
            item
            for item in command
            if item.startswith("type=bind,")
            and item.endswith(",dst=/opt/governance-toolchain,readonly")
        )
        toolchain_root = toolchain_mount.removeprefix("type=bind,src=").removesuffix(
            ",dst=/opt/governance-toolchain,readonly"
        )
        docker_host = command[1].removeprefix("--host=")
    except (StopIteration, IndexError):
        return "execution result v2 command shape is invalid"
    mount_error = _mount_error(workspace, toolchain_root, plan)
    if mount_error is not None:
        return mount_error
    expected = docker_run_argv(
        docker=Path(docker_path),
        docker_host=docker_host,
        plan=plan,
        workspace=Path(workspace),
        toolchain_root=Path(toolchain_root),
        container_name=name,
    )
    if command != expected:
        return "execution result v2 command mismatch"
    return None


def _mount_error(
    workspace_value: str, toolchain_value: str, plan: ExecutionPlanV2
) -> str | None:
    workspace = Path(workspace_value)
    toolchain = Path(toolchain_value)
    expected_root = runtime_root_path(plan)
    if workspace != expected_root / "workspace":
        return "execution result v2 workspace mount is not plan-bound"
    if toolchain != expected_root / "toolchain":
        return "execution result v2 mounts are not plan-bound"
    return None


def _stream_error(name: str, stream: dict[str, Any]) -> str | None:
    try:
        content = base64.b64decode(stream["captured_base64"], validate=True)
    except (binascii.Error, ValueError):
        return f"execution result v2 {name} encoding is invalid"
    if len(content) != stream["captured_bytes"]:
        return f"execution result v2 {name} length is invalid"
    if sha256(content).hexdigest() != stream["sha256"]:
        return f"execution result v2 {name} digest is invalid"
    return None


def _outcome_error(payload: dict[str, Any]) -> str | None:
    termination = payload["termination"]
    exit_code = payload["exit_code"]
    if termination == "NOT_STARTED":
        if exit_code is not None:
            return "execution result v2 not-started exit code is invalid"
    elif not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return "execution result v2 terminated exit code is invalid"
    passed = payload["capability_status"] == "PASS"
    clean_exit = (
        payload["termination"] == "EXITED"
        and payload["exit_code"] == 0
        and not payload["errors"]
    )
    if passed != clean_exit:
        return "execution result v2 outcome is inconsistent"
    return None


def _profile_error(payload: dict[str, Any], plan: ExecutionPlanV2) -> str | None:
    capabilities = payload.get("capabilities")
    is_profile = is_profile_runner(plan.step["adapter_id"])
    if not is_profile:
        return (
            "execution result v2 unexpected profile capabilities"
            if capabilities is not None
            else None
        )
    if capabilities is None:
        return (
            "execution result v2 PASS profile evidence is missing"
            if payload["capability_status"] == "PASS"
            else None
        )
    if payload["termination"] != "EXITED":
        return "execution result v2 profile evidence has invalid termination"
    expected_adapters = profile_adapters(runner_profile(plan.step["adapter_id"]))
    if not isinstance(capabilities, list) or len(capabilities) != len(
        expected_adapters
    ):
        return "execution result v2 profile capability set is invalid"
    for item, expected in zip(capabilities, expected_adapters, strict=True):
        capability, adapter_id, assurance = expected
        if (
            not isinstance(item, dict)
            or item.get("capability") != capability
            or item.get("adapter_id") != adapter_id
            or item.get("assurance_class") != assurance
            or item.get("status") not in {"PASS", "BLOCK_TECHNICAL"}
            or not isinstance(item.get("evidence"), dict)
        ):
            return "execution result v2 profile capability identity is invalid"
    all_passed = all(item["status"] == "PASS" for item in capabilities)
    if payload["capability_status"] == "PASS" and not all_passed:
        return "execution result v2 profile outcome is inconsistent"
    if runner_profile(plan.step["adapter_id"]) == "python.sqlite.v1":
        return _sqlite_evidence_error(capabilities[-1], capabilities)
    return None


def _sqlite_evidence_error(
    capability: dict[str, Any], capabilities: list[dict[str, Any]]
) -> str | None:
    evidence = capability.get("evidence")
    if not isinstance(evidence, dict):
        return "execution result v2 SQLite evidence is invalid"
    try:
        validate_packaged_named("sqlite_supportability_evidence", evidence)
    except SchemaValidationError:
        return "execution result v2 SQLite evidence schema is invalid"
    if (
        evidence.get("policy_id") != POLICY_ID
        or evidence.get("policy_sha256") != POLICY_SHA256
    ):
        return "execution result v2 SQLite policy identity is invalid"
    package = next(
        (item for item in capabilities if item.get("capability") == "package_audit"),
        {},
    )
    package_wheel = (
        package.get("evidence", {}).get("wheel_sha256")
        if isinstance(package.get("evidence"), dict)
        else None
    )
    if evidence.get("wheel_sha256") != package_wheel:
        return "execution result v2 SQLite wheel identity is invalid"
    identity = evidence.get("sqlite_identity")
    certified = (
        {key: identity.get(key) for key in CERTIFIED_SQLITE_IDENTITY}
        if isinstance(identity, dict)
        else None
    )
    if capability.get("status") == "PASS" and _sqlite_pass_contradiction(
        evidence, certified
    ):
        return "execution result v2 SQLite PASS evidence is contradictory"
    return None


def _sqlite_pass_contradiction(
    evidence: dict[str, Any], certified: dict[str, Any] | None
) -> bool:
    files = evidence.get("files", [])
    sinks = evidence.get("sinks", [])
    provenance = evidence.get("receiver_provenance", [])
    preparations = evidence.get("preparations", [])
    counts = evidence.get("counts", {})
    identity = evidence.get("sqlite_identity", {})
    functions = identity.get("observed_functions", [])
    return bool(
        evidence.get("gate_implementation") != "PASS"
        or evidence.get("repo_sql_supportability") != "PASS"
        or evidence.get("sql_behavior_proof") != "PASS"
        or evidence.get("errors") != []
        or not _sha256(evidence.get("wheel_sha256"))
        or certified != CERTIFIED_SQLITE_IDENTITY
        or not files
        or not sinks
        or len(provenance) != len(sinks)
        or not preparations
        or _sqlite_preparation_contradiction(preparations)
        or _sqlite_count_contradiction(counts, files, sinks, preparations)
        or _sqlite_binding_contradiction(
            files, sinks, provenance, preparations, evidence
        )
        or evidence.get("limits") != _limit_evidence()
        or _sqlite_evidence_timing_contradiction(evidence)
        or functions != sorted(set(functions))
        or not set(functions).issubset(ALLOWED_FUNCTIONS)
    )


def _sqlite_preparation_contradiction(preparations: list[Any]) -> bool:
    return any(
        not isinstance(item, dict)
        or item.get("status") != "PASS"
        or item.get("error") is not None
        for item in preparations
    )


def _sqlite_count_contradiction(
    counts: dict[str, Any],
    files: list[Any],
    sinks: list[Any],
    preparations: list[Any],
) -> bool:
    return bool(
        counts.get("files") != len(files)
        or counts.get("sinks") != len(sinks)
        or counts.get("sql_statements") != len(preparations)
        or counts.get("source_bytes")
        != sum(item.get("bytes", -1) for item in files if isinstance(item, dict))
        or not 1 <= counts.get("ast_nodes", -1) <= MAX_AST_NODES
        or not 0 <= counts.get("files", -1) <= MAX_FILES
        or not 0 <= counts.get("sinks", -1) <= MAX_SINKS
        or not 1 <= counts.get("source_bytes", -1) <= MAX_SOURCE_BYTES
        or not 0 <= counts.get("sql_statements", -1) <= MAX_STATEMENTS
        or any(item.get("bytes", MAX_FILE_BYTES + 1) > MAX_FILE_BYTES for item in files)
    )


def _sqlite_binding_contradiction(
    files: list[Any],
    sinks: list[Any],
    provenance: list[Any],
    preparations: list[Any],
    evidence: dict[str, Any],
) -> bool:
    file_paths = [item.get("path") for item in files if isinstance(item, dict)]
    sink_keys = [_sink_key(item) for item in sinks]
    preparation_keys = [_sink_key(item) for item in preparations]
    preparation_identities = [_preparation_identity(item) for item in preparations]
    sink_locations = [_location_key(item) for item in sinks]
    provenance_locations = [_location_key(item) for item in provenance]
    resources = evidence.get("resources", [])
    return bool(
        len(file_paths) != len(files)
        or len(file_paths) != len(set(file_paths))
        or len(file_paths) != len({str(path).casefold() for path in file_paths})
        or any(not _safe_path(path) for path in file_paths)
        or len(sink_keys) != len(set(sink_keys))
        or None in sink_keys
        or len(provenance_locations) != len(set(provenance_locations))
        or None in provenance_locations
        or set(sink_locations) != set(provenance_locations)
        or set(preparation_keys) != set(sink_keys)
        or None in preparation_identities
        or len(preparation_identities) != len(set(preparation_identities))
        or any(key[0] not in file_paths for key in sink_keys if key)
        or len(resources) != len(set(resources))
        or any(not _safe_path(path) for path in resources)
        or any(path not in file_paths for path in resources)
    )


def _sink_key(item: Any) -> tuple[str, int, str] | None:
    if not isinstance(item, dict):
        return None
    path, line, sink = item.get("path"), item.get("line"), item.get("sink")
    if (
        not isinstance(path, str)
        or not isinstance(line, int)
        or not isinstance(sink, str)
    ):
        return None
    return path, line, sink


def _location_key(item: Any) -> tuple[str, int] | None:
    if not isinstance(item, dict):
        return None
    path, line = item.get("path"), item.get("line")
    if not isinstance(path, str) or not isinstance(line, int):
        return None
    return path, line


def _preparation_identity(
    item: Any,
) -> tuple[str, int, str, str | None, str] | None:
    if not isinstance(item, dict):
        return None
    path = item.get("path")
    line = item.get("line")
    sink = item.get("sink")
    selector = item.get("selector")
    digest = item.get("sql_sha256")
    if (
        not isinstance(path, str)
        or not isinstance(line, int)
        or not isinstance(sink, str)
        or selector is not None
        and not isinstance(selector, str)
        or not isinstance(digest, str)
    ):
        return None
    return path, line, sink, selector, digest


def _safe_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sqlite_evidence_timing_contradiction(evidence: dict[str, Any]) -> bool:
    try:
        started = _timestamp(evidence["started_at"])
        completed = _timestamp(evidence["completed_at"])
    except (KeyError, TypeError, ValueError):
        return True
    return completed < started or (completed - started).total_seconds() > 120


def _timing_error(payload: dict[str, Any], timeout_seconds: int) -> str | None:
    try:
        duration = float(payload["duration_seconds"])
        started = _timestamp(payload["started_at"])
        completed = _timestamp(payload["completed_at"])
    except (OverflowError, TypeError, ValueError):
        return "execution result v2 timing is invalid"
    if not math.isfinite(duration) or duration < 0:
        return "execution result v2 duration is invalid"
    if completed < started:
        return "execution result v2 timestamps are out of order"
    elapsed = (completed - started).total_seconds()
    if abs(elapsed - duration) > _TIMING_TOLERANCE_SECONDS:
        return "execution result v2 duration does not match timestamps"
    if payload["termination"] == "TIMED_OUT":
        if duration < timeout_seconds:
            return "execution result v2 timeout occurred before plan deadline"
        if duration > timeout_seconds:
            return "execution result v2 timeout exceeded plan deadline"
    elif duration > timeout_seconds:
        return "execution result v2 duration exceeds plan timeout"
    return None


def _timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z suffix")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
