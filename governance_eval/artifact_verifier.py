from __future__ import annotations

import json
import stat
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from governance_eval.candidate_bundle import (
    ALL_FILES,
    PAYLOAD_FILES,
    SCHEMA_VERSION,
    artifact_name,
    recompute_decision,
)
from governance_eval.capability_catalog import (
    PROFILE_ADAPTERS,
    get_capability_adapter,
    is_profile_runner,
    runner_profile,
)
from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.docker_runtime import MAX_EVIDENCE_BYTES
from governance_eval.execution_plan_v2 import ExecutionPlanV2, assess_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.sqlite_supportability import validate_profile_discovery
from governance_eval.sqlite_policy import POLICY_SHA256


VERIFIER_SCHEMA_VERSION = "governance_verifier_receipt.v1"
REQUIRED_CONTEXT = "Governance / Authoritative Decision"
GITHUB_ACTIONS_APP_ID = 15368
MAX_ARCHIVE_BYTES = MAX_EVIDENCE_BYTES
MAX_ENTRY_BYTES = MAX_EVIDENCE_BYTES
MAX_TOTAL_BYTES = MAX_EVIDENCE_BYTES
MAX_COMPRESSION_RATIO = 100


class ArtifactVerificationError(ValueError):
    pass


@dataclass(frozen=True)
class VerifierContext:
    repository_id: int
    repository_full_name: str
    pull_request: int
    base_sha: str
    head_sha: str
    head_tree_sha: str
    current_head_sha: str
    workflow_path: str
    workflow_commit_sha: str
    workflow_file_sha256: str
    evaluator_repository_id: int
    evaluator_repository_full_name: str
    evaluator_sha: str
    evaluator_tree_sha: str
    configuration_sha256: str
    standard_sha256: str
    run_id: int
    run_attempt: int
    run_event: str
    run_status: str
    run_conclusion: str
    run_app_id: int
    artifact_id: int
    artifact_name: str
    artifact_digest: str
    artifact_created_at: str
    verified_at: str
    verifier_app_id: int
    profile: str = "python.standard.v1"
    adoption_manifest_sha256: str = ""
    sqlite_policy_sha256: str = ""
    max_age_seconds: int = 3600


def verify_candidate_artifact(
    archive_path: Path, context: VerifierContext
) -> dict[str, Any]:
    _validate_archive_file(archive_path)
    archive_sha256 = _file_sha256(archive_path)
    try:
        payloads = _read_archive(archive_path, context, archive_sha256)
        manifest = _json(payloads["candidate-bundle.json"], "candidate bundle")
        receipt_payload = _json(payloads["checkout-receipt.json"], "checkout receipt")
        plan_payload = _json(payloads["execution-plan.json"], "execution plan")
        result_payload = _json(payloads["execution-result.json"], "execution result")
        _verify_manifest_files(manifest, payloads)
        receipt = _receipt(receipt_payload)
        plan = _plan(plan_payload)
        _verify_execution(receipt, plan, result_payload)
        _verify_context(manifest, receipt, plan, context)
        decision = recompute_decision(
            result_payload, manifest["ai_review"], context.head_sha
        )
        if manifest.get("decision") != decision:
            raise ArtifactVerificationError("candidate decision differs from verifier")
        if decision["status"] != "PASS":
            raise ArtifactVerificationError(
                "deterministic candidate decision is blocking"
            )
        errors: list[str] = []
        result = "PASS"
    except (ArtifactVerificationError, KeyError, TypeError, ValueError) as exc:
        errors = [str(exc)]
        result = "REJECT"
    return _verifier_receipt(context, archive_sha256, result, errors)


def check_run_request(receipt: Mapping[str, Any]) -> dict[str, Any]:
    if receipt.get("schema_version") != VERIFIER_SCHEMA_VERSION:
        raise ArtifactVerificationError("verifier receipt schema is invalid")
    result = receipt.get("result")
    if result not in {"PASS", "REJECT"}:
        raise ArtifactVerificationError("verifier receipt result is invalid")
    check = receipt.get("check")
    if not isinstance(check, Mapping):
        raise ArtifactVerificationError("verifier receipt check is invalid")
    if check.get("name") != REQUIRED_CONTEXT:
        raise ArtifactVerificationError("required context identity is invalid")
    if check.get("app_id") != receipt.get("verifier_app_id") or check.get(
        "head_sha"
    ) != receipt.get("head_sha"):
        raise ArtifactVerificationError("required check binding is invalid")
    unsigned = dict(receipt)
    receipt_sha256 = unsigned.pop("receipt_sha256", None)
    if receipt_sha256 != sha256(_canonical_json(unsigned)).hexdigest():
        raise ArtifactVerificationError("verifier receipt integrity is invalid")
    conclusion = "success" if result == "PASS" else "failure"
    return {
        "name": REQUIRED_CONTEXT,
        "head_sha": check["head_sha"],
        "status": "completed",
        "conclusion": conclusion,
        "external_id": receipt["receipt_sha256"],
        "output": {
            "title": f"Governance verifier: {result}",
            "summary": "\n".join(receipt["errors"])
            if receipt["errors"]
            else "Exact evidence verified.",
        },
    }


def _read_archive(
    path: Path, context: VerifierContext, archive_sha256: str
) -> dict[str, bytes]:
    if context.artifact_digest != f"sha256:{archive_sha256}":
        raise ArtifactVerificationError("artifact digest mismatch")
    try:
        with zipfile.ZipFile(path) as archive:
            return _read_zip_entries(archive)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ArtifactVerificationError("artifact archive is malformed") from exc


def _validate_archive_file(path: Path) -> None:
    try:
        if not path.is_file() or path.is_symlink():
            raise ArtifactVerificationError("artifact archive is not a regular file")
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ArtifactVerificationError("artifact archive exceeds size limit")
    except OSError as exc:
        raise ArtifactVerificationError("artifact archive is unavailable") from exc


def _read_zip_entries(archive: zipfile.ZipFile) -> dict[str, bytes]:
    infos = archive.infolist()
    names = [_safe_entry_name(info) for info in infos]
    if len(names) != len(set(names)) or len(names) != len(
        set(name.casefold() for name in names)
    ):
        raise ArtifactVerificationError("artifact archive contains duplicate entries")
    if set(names) != set(ALL_FILES):
        raise ArtifactVerificationError("artifact archive file set is invalid")
    total = sum(info.file_size for info in infos)
    if total > MAX_TOTAL_BYTES:
        raise ArtifactVerificationError("artifact archive expands beyond limit")
    return {
        name: _read_entry(archive, info)
        for name, info in zip(names, infos, strict=True)
    }


def _safe_entry_name(info: zipfile.ZipInfo) -> str:
    name = info.filename
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if (
        not name
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or name in {".", ".."}
        or info.is_dir()
    ):
        raise ArtifactVerificationError("artifact archive path is unsafe")
    if file_type not in {0, stat.S_IFREG} or info.extra:
        raise ArtifactVerificationError("artifact archive links are forbidden")
    if info.file_size > MAX_ENTRY_BYTES:
        raise ArtifactVerificationError("artifact archive entry exceeds size limit")
    compressed = max(info.compress_size, 1)
    if info.file_size > compressed * MAX_COMPRESSION_RATIO:
        raise ArtifactVerificationError("artifact archive compression ratio is unsafe")
    return name


def _read_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with archive.open(info) as stream:
        data = stream.read(MAX_ENTRY_BYTES + 1)
    if len(data) != info.file_size or len(data) > MAX_ENTRY_BYTES:
        raise ArtifactVerificationError("artifact archive entry size is invalid")
    return data


def _verify_manifest_files(
    manifest: Mapping[str, Any], payloads: Mapping[str, bytes]
) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ArtifactVerificationError("candidate bundle schema is invalid")
    files = manifest.get("files")
    if not isinstance(files, Mapping) or set(files) != set(PAYLOAD_FILES):
        raise ArtifactVerificationError("candidate bundle file manifest is invalid")
    for name in PAYLOAD_FILES:
        identity = files[name]
        if not isinstance(identity, Mapping):
            raise ArtifactVerificationError("candidate bundle file identity is invalid")
        if identity.get("bytes") != len(payloads[name]):
            raise ArtifactVerificationError("candidate bundle file length mismatch")
        if identity.get("sha256") != sha256(payloads[name]).hexdigest():
            raise ArtifactVerificationError("candidate bundle content digest mismatch")


def _receipt(payload: Mapping[str, Any]) -> CheckoutReceipt:
    try:
        return CheckoutReceipt(**dict(payload))
    except TypeError as exc:
        raise ArtifactVerificationError("checkout receipt shape is invalid") from exc


def _plan(payload: Mapping[str, Any]) -> ExecutionPlanV2:
    try:
        return ExecutionPlanV2(**dict(payload))
    except TypeError as exc:
        raise ArtifactVerificationError("execution plan shape is invalid") from exc


def _verify_execution(
    receipt: CheckoutReceipt, plan: ExecutionPlanV2, result: Mapping[str, Any]
) -> None:
    assessment = assess_execution_plan_v2(plan.to_json(), receipt)
    if assessment["capability_status"] != "PASS":
        raise ArtifactVerificationError("execution plan is not evaluator-owned")
    integrity = validate_execution_result_v2(dict(result), plan, receipt)
    if integrity["integrity_status"] != "INTEGRITY_VALID":
        raise ArtifactVerificationError("execution result integrity is invalid")


def _verify_context(
    manifest: Mapping[str, Any],
    receipt: CheckoutReceipt,
    plan: ExecutionPlanV2,
    context: VerifierContext,
) -> None:
    _verify_run_context(context)
    expected = _expected_manifest_context(manifest, receipt, plan, context)
    for label, actual, wanted in expected:
        if actual != wanted:
            raise ArtifactVerificationError(f"{label} mismatch")
    adapter = manifest.get("adapter")
    if not isinstance(adapter, Mapping):
        raise ArtifactVerificationError("adapter identity is missing")
    trusted = get_capability_adapter(plan.step["step_id"], plan.step["adapter_id"])
    expected_adapter = {
        "capability": trusted.capability,
        "adapter_id": trusted.adapter_id,
        "assurance_class": trusted.assurance_class,
    }
    if dict(adapter) != expected_adapter:
        raise ArtifactVerificationError("adapter assurance identity mismatch")
    discovery = manifest.get("profile_discovery")
    if not isinstance(discovery, Mapping):
        raise ArtifactVerificationError("profile discovery receipt is missing")
    validate_profile_discovery(discovery, selected_profile=context.profile)
    if (
        is_profile_runner(plan.step["adapter_id"])
        and runner_profile(plan.step["adapter_id"]) != context.profile
    ):
        raise ArtifactVerificationError("execution profile selection mismatch")
    if (
        not is_profile_runner(plan.step["adapter_id"])
        and context.profile != "python.standard.v1"
    ):
        raise ArtifactVerificationError(
            "SQLite evidence lacks the typed profile runner"
        )
    _verify_freshness(manifest, context)


def _expected_manifest_context(
    manifest: Mapping[str, Any],
    receipt: CheckoutReceipt,
    plan: ExecutionPlanV2,
    context: VerifierContext,
) -> list[tuple[str, Any, Any]]:
    return [
        ("repository", manifest["repository"], dict(receipt.repository)),
        (
            "bundle pull request",
            manifest.get("pull_request"),
            dict(receipt.pull_request),
        ),
        ("bundle evaluator", manifest.get("evaluator"), dict(receipt.evaluator)),
        (
            "repository",
            receipt.repository,
            {"id": context.repository_id, "full_name": context.repository_full_name},
        ),
        ("pull request", receipt.pull_request["number"], context.pull_request),
        ("base SHA", receipt.pull_request["base_sha"], context.base_sha),
        ("head SHA", receipt.pull_request["head_sha"], context.head_sha),
        ("head tree", receipt.pull_request["head_tree_sha"], context.head_tree_sha),
        ("current head", context.current_head_sha, context.head_sha),
        (
            "evaluator repository id",
            receipt.evaluator["repository_id"],
            context.evaluator_repository_id,
        ),
        (
            "evaluator repository",
            receipt.evaluator["repository_full_name"],
            context.evaluator_repository_full_name,
        ),
        ("evaluator SHA", receipt.evaluator["commit_sha"], context.evaluator_sha),
        ("evaluator tree", receipt.evaluator["tree_sha"], context.evaluator_tree_sha),
        ("plan head", plan.target["commit_sha"], context.head_sha),
        ("plan tree", plan.target["tree_sha"], context.head_tree_sha),
        ("configuration", receipt.config_sha256, context.configuration_sha256),
        ("standard", receipt.standard_sha256, context.standard_sha256),
    ] + _manifest_pairs(manifest, context)


def _manifest_pairs(
    manifest: Mapping[str, Any], context: VerifierContext
) -> list[tuple[str, Any, Any]]:
    workflow = manifest.get("workflow")
    if not isinstance(workflow, Mapping):
        raise ArtifactVerificationError("workflow identity is missing")
    return [
        ("workflow path", workflow.get("path"), context.workflow_path),
        ("workflow commit", workflow.get("commit_sha"), context.workflow_commit_sha),
        ("workflow file", workflow.get("file_sha256"), context.workflow_file_sha256),
        ("workflow event", workflow.get("event"), context.run_event),
        ("run id", workflow.get("run_id"), context.run_id),
        ("run attempt", workflow.get("run_attempt"), context.run_attempt),
        ("artifact name", manifest.get("artifact_name"), context.artifact_name),
        (
            "configuration",
            manifest.get("configuration_sha256"),
            context.configuration_sha256,
        ),
        ("standard", manifest.get("standard_sha256"), context.standard_sha256),
        ("profile", manifest.get("profile"), context.profile),
        (
            "adoption manifest",
            manifest.get("adoption_manifest_sha256"),
            context.adoption_manifest_sha256,
        ),
        (
            "SQLite policy",
            manifest.get("sqlite_policy_sha256"),
            context.sqlite_policy_sha256 or None,
        ),
    ]


def _verify_run_context(context: VerifierContext) -> None:
    if context.run_event != "pull_request" or context.run_status != "completed":
        raise ArtifactVerificationError("candidate workflow run state is invalid")
    if (
        context.run_conclusion != "success"
        or context.run_app_id != GITHUB_ACTIONS_APP_ID
    ):
        raise ArtifactVerificationError("candidate workflow producer is invalid")
    if context.artifact_name != artifact_name(context.run_id, context.run_attempt):
        raise ArtifactVerificationError("artifact name is not run-attempt bound")
    if context.verifier_app_id < 1:
        raise ArtifactVerificationError("verifier App identity is invalid")
    if context.profile not in PROFILE_ADAPTERS:
        raise ArtifactVerificationError("verifier profile is unsupported")
    if len(context.adoption_manifest_sha256) != 64 or any(
        character not in "0123456789abcdef"
        for character in context.adoption_manifest_sha256
    ):
        raise ArtifactVerificationError("adoption manifest identity is invalid")
    if context.profile == "python.sqlite.v1" and (
        context.sqlite_policy_sha256 != POLICY_SHA256
        or context.sqlite_policy_sha256 != context.sqlite_policy_sha256.lower()
    ):
        raise ArtifactVerificationError("SQLite policy identity is invalid")
    if context.profile != "python.sqlite.v1" and context.sqlite_policy_sha256:
        raise ArtifactVerificationError("unexpected SQLite policy identity")


def _verify_freshness(manifest: Mapping[str, Any], context: VerifierContext) -> None:
    workflow = manifest["workflow"]
    observed = _timestamp(workflow["observed_at"])
    created = _timestamp(context.artifact_created_at)
    verified = _timestamp(context.verified_at)
    if not observed <= created <= verified:
        raise ArtifactVerificationError("artifact timestamps are inconsistent")
    age = (verified - created).total_seconds()
    if age < 0 or age > context.max_age_seconds:
        raise ArtifactVerificationError("artifact evidence is stale")


def _verifier_receipt(
    context: VerifierContext, archive_sha256: str, result: str, errors: list[str]
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "result": result,
        "repository": {
            "id": context.repository_id,
            "full_name": context.repository_full_name,
        },
        "pull_request": context.pull_request,
        "head_sha": context.head_sha,
        "run_id": context.run_id,
        "run_attempt": context.run_attempt,
        "artifact": {
            "id": context.artifact_id,
            "name": context.artifact_name,
            "digest": context.artifact_digest,
            "archive_sha256": archive_sha256,
        },
        "verifier_app_id": context.verifier_app_id,
        "profile": context.profile,
        "adoption_manifest_sha256": context.adoption_manifest_sha256,
        "sqlite_policy_sha256": context.sqlite_policy_sha256 or None,
        "verified_at": context.verified_at,
        "errors": errors,
        "check": {
            "name": REQUIRED_CONTEXT,
            "head_sha": context.head_sha,
            "app_id": context.verifier_app_id,
        },
        "context": asdict(context),
    }
    unsigned = _canonical_json(payload)
    payload["receipt_sha256"] = sha256(unsigned).hexdigest()
    return payload


def _json(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ArtifactVerificationError) as exc:
        raise ArtifactVerificationError(f"{label} JSON is malformed") from exc
    if not isinstance(value, Mapping):
        raise ArtifactVerificationError(f"{label} JSON must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactVerificationError("JSON contains duplicate keys")
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise ArtifactVerificationError(f"unsupported JSON constant: {value}")


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ArtifactVerificationError("timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ArtifactVerificationError("timestamp is invalid") from exc
    return parsed.astimezone(UTC)


def _file_sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ArtifactVerificationError("artifact archive is unavailable") from exc
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
