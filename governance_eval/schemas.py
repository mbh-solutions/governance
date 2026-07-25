from __future__ import annotations

import json
from hashlib import sha256
from importlib.resources import files
from pathlib import Path
from typing import Any

from governance_eval.paths import repo_root
from governance_eval.schema_validator import SchemaValidationError, validate

SCHEMA_FILES = {
    "evaluation_case": "evaluation_case.schema.json",
    "detector_evidence": "detector_evidence.schema.json",
    "review_finding": "review_finding.schema.json",
    "benchmark_run_result": "benchmark_run_result.schema.json",
    "final_decision": "final_decision.schema.json",
    "target_pack": "target_pack.schema.json",
    "target_evaluation_result": "target_evaluation_result.schema.json",
    "supportability_config": "supportability_config.schema.json",
    "supportability_gate_result": "supportability_gate_result.schema.json",
    "architecture_gate_result": "architecture_gate_result.schema.json",
    "delivery_receipt": "delivery_receipt.schema.json",
    "governance_merge_group_receipt": "governance_merge_group_receipt.schema.json",
    "bootstrap_audit_receipt": "bootstrap_audit_receipt.schema.json",
    "codex_connector_snapshot": "codex_connector_snapshot.schema.json",
    "codex_connector_evidence_result": "codex_connector_evidence_result.schema.json",
    "codex_connector_snapshot_v2": "codex_connector_snapshot.schema.json",
    "codex_connector_evidence_result_v2": "codex_connector_evidence_result.schema.json",
    "codex_connector_evidence_result_v3": "codex_connector_evidence_result.schema.json",
    "codex_connector_evidence_result_v4": "codex_connector_evidence_result.schema.json",
    "execution_plan": "execution_plan.schema.json",
    "execution_plan_v2": "execution_plan.schema.json",
    "checkout_receipt": "checkout_receipt.schema.json",
    "execution_result": "execution_result.schema.json",
    "execution_result_v2": "execution_result.schema.json",
    "governance_toolchain_receipt": "governance_toolchain_receipt.schema.json",
    "governance_toolchain_evaluation_receipt": "governance_toolchain_evaluation_receipt.schema.json",
    "governance_toolchain_shadow_receipt": "governance_toolchain_shadow_receipt.schema.json",
    "governance_toolchain_artifact_binding": "governance_toolchain_artifact_binding.schema.json",
    "profile_discovery": "profile_discovery.schema.json",
    "sqlite_supportability_evidence": "sqlite_supportability_evidence.schema.json",
}

SCHEMA_VERSIONS = {
    "execution_plan_v2": "v2",
    "execution_result_v2": "v2",
    "codex_connector_snapshot_v2": "v2",
    "codex_connector_evidence_result_v2": "v2",
    "codex_connector_evidence_result_v3": "v3",
    "codex_connector_evidence_result_v4": "v4",
}

_PACKAGED_SCHEMA_SHA256 = {
    "checkout_receipt": "8856cd39a7093eafcfad0b8cfb509e74b33c17eb24985e8205aef4b1c7eed90a",
    "execution_plan_v2": "12571a6362108beba7f435c41b017e31c97256234295652936a9d306a7d85917",
    "execution_result_v2": "5584b2903e6992cf548d2fcbc12544965f4cbef4b45b15c32efbaa808626778b",
    "profile_discovery": "5b5a3bae2fe207d848f6305ace7b334b731a5218e0f0dd81b9ec3f504953fa07",
    "sqlite_supportability_evidence": "f3aff6e104e3bf527ca75faed8aa6191757bd6eef879a946909cd713af082c72",
}


def load_schema(name: str, root: Path | None = None) -> dict[str, Any]:
    if name not in SCHEMA_FILES:
        raise KeyError(f"unknown schema {name!r}")
    repository_root = repo_root(root)
    version = SCHEMA_VERSIONS.get(name, "v1")
    path = repository_root / "schemas" / version / SCHEMA_FILES[name]
    return json.loads(path.read_text(encoding="utf-8"))


def validate_named(name: str, instance: Any, root: Path | None = None) -> None:
    validate(instance, load_schema(name, root))


def validate_packaged_named(name: str, instance: Any) -> None:
    if name not in _PACKAGED_SCHEMA_SHA256:
        raise KeyError(f"schema {name!r} is not trusted package data")
    version = SCHEMA_VERSIONS.get(name, "v1")
    resource = files("governance_eval").joinpath(
        "schema_data", version, SCHEMA_FILES[name]
    )
    try:
        schema_bytes = resource.read_bytes()
        schema_text = schema_bytes.decode("utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:
        raise SchemaValidationError(
            "trusted schema is unavailable or malformed"
        ) from exc
    canonical = schema_text.replace("\r\n", "\n").encode("utf-8")
    if sha256(canonical).hexdigest() != _PACKAGED_SCHEMA_SHA256[name]:
        raise SchemaValidationError("trusted schema digest is invalid")
    try:
        schema = json.loads(schema_text)
    except json.JSONDecodeError as exc:
        raise SchemaValidationError("trusted schema is malformed") from exc
    if not isinstance(schema, dict):
        raise SchemaValidationError("trusted schema must be an object")
    validate(instance, schema)
