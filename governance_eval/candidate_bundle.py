from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from governance_eval.capability_catalog import (
    get_capability_adapter,
    is_profile_runner,
    runner_profile,
)
from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.execution_plan_v2 import ExecutionPlanV2, assess_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.sqlite_policy import POLICY_SHA256
from governance_eval.sqlite_supportability import validate_profile_discovery


SCHEMA_VERSION = "governance_candidate_bundle.v1"
ARTIFACT_NAME_PREFIX = "governance-candidate-evidence"
PAYLOAD_FILES = (
    "checkout-receipt.json",
    "execution-plan.json",
    "execution-result.json",
)
ALL_FILES = (*PAYLOAD_FILES, "candidate-bundle.json")
BLOCKING_SEVERITIES = frozenset({"P0", "P1", "P2"})


class CandidateBundleError(ValueError):
    pass


def build_candidate_bundle(
    *,
    receipt: CheckoutReceipt,
    plan: ExecutionPlanV2,
    result: Mapping[str, Any],
    workflow_path: str,
    workflow_commit_sha: str,
    workflow_file_sha256: str,
    event_name: str,
    ai_review: Mapping[str, Any],
    profile: str,
    profile_discovery: Mapping[str, Any],
    adoption_manifest_sha256: str,
) -> dict[str, bytes]:
    receipt_payload = receipt.to_json()
    plan_payload = plan.to_json()
    result_payload = dict(result)
    _validate_identity_inputs(
        receipt_payload,
        workflow_path,
        workflow_commit_sha,
        workflow_file_sha256,
        event_name,
    )
    plan_assessment = assess_execution_plan_v2(plan_payload, receipt)
    if plan_assessment["capability_status"] != "PASS":
        raise CandidateBundleError("execution plan is not evaluator-owned")
    result_assessment = validate_execution_result_v2(result_payload, plan, receipt)
    if result_assessment["integrity_status"] != "INTEGRITY_VALID":
        raise CandidateBundleError("execution result integrity is invalid")
    adapter = get_capability_adapter(plan.step["step_id"], plan.step["adapter_id"])
    if (
        is_profile_runner(adapter.adapter_id)
        and runner_profile(adapter.adapter_id) != profile
    ):
        raise CandidateBundleError("execution plan profile differs from configuration")
    if not is_profile_runner(adapter.adapter_id) and profile != "python.standard.v1":
        raise CandidateBundleError("SQLite evidence requires the typed profile runner")
    validate_profile_discovery(profile_discovery, selected_profile=profile)
    if not _hex(adoption_manifest_sha256, 64):
        raise CandidateBundleError("adoption manifest identity is invalid")
    normalized_ai = _normalize_ai_review(ai_review, receipt.pull_request["head_sha"])
    decision = _decision(result_payload, normalized_ai)
    payloads = {
        "checkout-receipt.json": _canonical_json(receipt_payload),
        "execution-plan.json": _canonical_json(plan_payload),
        "execution-result.json": _canonical_json(result_payload),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "repository": dict(receipt.repository),
        "pull_request": dict(receipt.pull_request),
        "evaluator": dict(receipt.evaluator),
        "workflow": {
            "path": workflow_path,
            "commit_sha": workflow_commit_sha,
            "file_sha256": workflow_file_sha256,
            "event": event_name,
            "run_id": receipt.workflow["run_id"],
            "run_attempt": receipt.workflow["run_attempt"],
            "observed_at": receipt.workflow["observed_at"],
        },
        "configuration_sha256": receipt.config_sha256,
        "standard_sha256": receipt.standard_sha256,
        "profile": profile,
        "profile_discovery": dict(profile_discovery),
        "adoption_manifest_sha256": adoption_manifest_sha256,
        "adapter": {
            "capability": adapter.capability,
            "adapter_id": adapter.adapter_id,
            "assurance_class": adapter.assurance_class,
        },
        "artifact_name": artifact_name(
            receipt.workflow["run_id"], receipt.workflow["run_attempt"]
        ),
        "ai_review": normalized_ai,
        "decision": decision,
        "files": {
            name: {"sha256": sha256(content).hexdigest(), "bytes": len(content)}
            for name, content in sorted(payloads.items())
        },
    }
    if profile == "python.sqlite.v1":
        if plan.step.get("sqlite_policy_sha256") != POLICY_SHA256:
            raise CandidateBundleError("SQLite policy plan binding is invalid")
        manifest["sqlite_policy_sha256"] = POLICY_SHA256
    payloads["candidate-bundle.json"] = _canonical_json(manifest)
    return payloads


def write_candidate_bundle(
    output_dir: Path, payloads: Mapping[str, bytes], *, target_root: Path
) -> None:
    output = output_dir.resolve()
    target = target_root.resolve()
    if output == target or target in output.parents:
        raise CandidateBundleError("candidate evidence must be outside target checkout")
    if output.exists() and (output.is_symlink() or any(output.iterdir())):
        raise CandidateBundleError("candidate evidence directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    if set(payloads) != set(ALL_FILES):
        raise CandidateBundleError("candidate evidence file set is invalid")
    for name in ALL_FILES:
        destination = output / name
        destination.write_bytes(payloads[name])


def artifact_name(run_id: int, run_attempt: int) -> str:
    if run_id < 1 or run_attempt < 1:
        raise CandidateBundleError("run identity must be positive")
    return f"{ARTIFACT_NAME_PREFIX}-{run_id}-{run_attempt}"


def recompute_decision(
    result: Mapping[str, Any], ai_review: Mapping[str, Any], head_sha: str
) -> dict[str, Any]:
    return _decision(dict(result), _normalize_ai_review(ai_review, head_sha))


def _decision(
    result: Mapping[str, Any], ai_review: Mapping[str, Any]
) -> dict[str, Any]:
    reasons: list[str] = []
    if result.get("capability_status") != "PASS":
        reasons.append("DETERMINISTIC_CAPABILITY_FAILED")
    if _blocking_ai_findings(ai_review):
        reasons.append("VALID_EXACT_HEAD_AI_FINDING")
    return {
        "status": "BLOCK_TECHNICAL" if reasons else "PASS",
        "reasons": reasons,
    }


def _normalize_ai_review(value: Mapping[str, Any], head_sha: str) -> dict[str, Any]:
    status = value.get("status")
    if status not in {"AVAILABLE", "AI_REVIEW_UNAVAILABLE"}:
        raise CandidateBundleError("AI review status is invalid")
    raw_findings = value.get("findings", [])
    if not isinstance(raw_findings, list) or len(raw_findings) > 100:
        raise CandidateBundleError("AI review findings are invalid")
    findings = [_normalize_finding(item, head_sha) for item in raw_findings]
    if status == "AI_REVIEW_UNAVAILABLE" and findings:
        raise CandidateBundleError("unavailable AI review cannot contain findings")
    return {"status": status, "findings": findings}


def _normalize_finding(value: Any, head_sha: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidateBundleError("AI review finding is invalid")
    severity = value.get("severity")
    finding_head = value.get("head_sha")
    resolved = value.get("resolved")
    valid = value.get("valid")
    if severity not in {"P0", "P1", "P2", "P3"}:
        raise CandidateBundleError("AI review finding severity is invalid")
    if (
        finding_head != head_sha
        or not isinstance(resolved, bool)
        or not isinstance(valid, bool)
    ):
        raise CandidateBundleError("AI review finding identity is invalid")
    return {
        "severity": severity,
        "head_sha": finding_head,
        "valid": valid,
        "resolved": resolved,
    }


def _blocking_ai_findings(ai_review: Mapping[str, Any]) -> bool:
    return any(
        item["valid"]
        and not item["resolved"]
        and item["severity"] in BLOCKING_SEVERITIES
        for item in ai_review["findings"]
    )


def _validate_identity_inputs(
    receipt: Mapping[str, Any],
    workflow_path: str,
    workflow_commit_sha: str,
    workflow_file_sha256: str,
    event_name: str,
) -> None:
    if workflow_path != ".github/workflows/governance-candidate.yml":
        raise CandidateBundleError("candidate workflow path is invalid")
    if not _hex(workflow_commit_sha, 40) or not _hex(workflow_file_sha256, 64):
        raise CandidateBundleError("candidate workflow identity is invalid")
    if event_name != "pull_request":
        raise CandidateBundleError("candidate event is invalid")
    if workflow_commit_sha != receipt["pull_request"]["head_sha"]:
        raise CandidateBundleError("candidate workflow commit is not the PR head")


def _hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
