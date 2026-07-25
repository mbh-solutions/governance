from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance_eval.adoption import (
    CONFIG_PATH,
    MANIFEST_PATH,
    NATIVE_AUTHORITY_MODE,
    NATIVE_GOVERNANCE_REPOSITORY,
    NATIVE_GOVERNANCE_REPOSITORY_ID,
    NATIVE_WORKFLOW_PATH,
    STANDARD_PATH,
    WORKFLOW_PATH,
    AdoptionError,
    validate_adoption_config,
    validate_adoption_manifest,
    validate_native_adoption_config,
    validate_native_adoption_manifest,
)
from governance_eval.candidate_bundle import (
    build_candidate_bundle,
    write_candidate_bundle,
)
from governance_eval.checkout_receipt import bind_checkout
from governance_eval.capability_catalog import profile_runner
from governance_eval.docker_runtime import execute_ruff_docker
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.hashing import sha256_file
from governance_eval.sqlite_supportability import (
    SQLiteSupportabilityError,
    discover_repository_profile,
    validate_profile_discovery,
)


GOVERNANCE_REPOSITORY = "markheck-solutions/governance"
GOVERNANCE_REPOSITORY_ID = 1280677092
LEGACY_AUTHORITY_MODE = "legacy.external_verifier.v1"


class CandidatePipelineError(ValueError):
    pass


def run_candidate_pipeline(
    *,
    target_root: Path,
    evaluator_root: Path,
    event_path: Path,
    config_path: Path,
    standard_path: Path,
    workflow_path: str,
    workflow_ref: str,
    workflow_commit_sha: str,
    evaluator_sha: str,
    run_id: int,
    run_attempt: int,
    toolchain_root: Path,
    output_dir: Path,
    authority_mode: str = LEGACY_AUTHORITY_MODE,
    workflow_repository: str | None = None,
) -> dict[str, Any]:
    native = authority_mode == NATIVE_AUTHORITY_MODE
    _validate_authority_inputs(
        authority_mode=authority_mode,
        workflow_repository=workflow_repository,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
        workflow_commit_sha=workflow_commit_sha,
        evaluator_sha=evaluator_sha,
    )
    target = target_root.resolve()
    evaluator = evaluator_root.resolve()
    event = _load_event(event_path)
    repository = _mapping(event.get("repository"), "repository")
    pull_request = _mapping(event.get("pull_request"), "pull request")
    docker = _executable("docker")
    workflow_root = evaluator if native else target
    workflow_file = _inside(workflow_root, workflow_root / workflow_path, "workflow")
    config_file = _inside(target, config_path, "configuration")
    standard_file = _inside(target, standard_path, "standard")
    manifest_file = _inside(target, target / MANIFEST_PATH, "adoption manifest")
    profile = _validate_configuration(
        config_file, standard_file, evaluator_sha, authority_mode=authority_mode
    )
    if native:
        evaluator_standard = _inside(
            evaluator,
            evaluator / "docs/reference/supportability-standard.md",
            "evaluator standard",
        )
        if sha256_file(standard_file) != sha256_file(evaluator_standard):
            raise CandidatePipelineError(
                "native adoption standard differs from exact Governance source"
            )
    discovery = discover_repository_profile(target)
    try:
        validate_profile_discovery(discovery, selected_profile=profile)
    except SQLiteSupportabilityError as exc:
        raise CandidatePipelineError(str(exc)) from exc
    adoption_manifest = _load_json(manifest_file, "adoption manifest")
    repository_id = repository.get("id")
    repository_name = repository.get("full_name")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
        or not isinstance(repository_name, str)
    ):
        raise CandidatePipelineError("repository identity is invalid")
    try:
        if native:
            validate_native_adoption_manifest(
                adoption_manifest,
                repository=repository_name,
                repository_id=repository_id,
                governance_sha=evaluator_sha,
                profile=profile,
            )
        else:
            verifier = _mapping(
                _load_json(config_file, "adoption configuration").get("verifier"),
                "verifier configuration",
            )
            app_id = verifier.get("app_id")
            assert isinstance(app_id, int) and not isinstance(app_id, bool)
            validate_adoption_manifest(
                adoption_manifest,
                repository=repository_name,
                repository_id=repository_id,
                governance_sha=evaluator_sha,
                verifier_app_id=app_id,
                profile=profile,
            )
    except AdoptionError as exc:
        raise CandidatePipelineError(str(exc)) from exc
    _validate_manifest_files(adoption_manifest, target, native=native)
    evaluator_repository = {
        "id": (NATIVE_GOVERNANCE_REPOSITORY_ID if native else GOVERNANCE_REPOSITORY_ID),
        "full_name": (
            NATIVE_GOVERNANCE_REPOSITORY if native else GOVERNANCE_REPOSITORY
        ),
    }
    receipt = bind_checkout(
        target_root=target,
        evaluator_root=evaluator,
        event=event,
        pull_request=pull_request,
        repository=repository,
        evaluator_repository=evaluator_repository,
        workflow_repository=evaluator_repository if native else None,
        workflow={
            "workflow_ref": workflow_ref,
            "workflow_sha": workflow_commit_sha,
            "evaluator_sha": evaluator_sha,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "server_url": "https://github.com",
            "api_url": "https://api.github.com",
            "observed_at": _observed_at(pull_request),
        },
        config_path=config_file,
        standard_path=standard_file,
        runtime={
            "docker_path": str(docker),
            "docker_sha256": sha256_file(docker),
            "docker_host": os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"),
        },
    )
    capability, adapter_id = profile_runner(profile)
    plan = compile_execution_plan_v2(
        receipt, capability=capability, adapter_id=adapter_id
    )
    result = execute_ruff_docker(
        plan=plan,
        receipt=receipt,
        target_root=target,
        evaluator_root=evaluator,
        toolchain_binary=toolchain_root.resolve(strict=True),
    )
    payloads = build_candidate_bundle(
        receipt=receipt,
        plan=plan,
        result=result,
        workflow_path=workflow_path,
        workflow_commit_sha=workflow_commit_sha,
        workflow_file_sha256=sha256_file(workflow_file),
        event_name="pull_request",
        ai_review={"status": "AI_REVIEW_UNAVAILABLE", "findings": []},
        profile=profile,
        profile_discovery=discovery,
        adoption_manifest_sha256=sha256_file(manifest_file),
        central_workflow=native,
    )
    write_candidate_bundle(output_dir, payloads, target_root=target)
    return json.loads(payloads["candidate-bundle.json"])


def _load_event(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidatePipelineError("GitHub event is malformed") from exc
    return _mapping(payload, "GitHub event")


def _validate_configuration(
    config_path: Path,
    standard_path: Path,
    evaluator_sha: str,
    *,
    authority_mode: str = LEGACY_AUTHORITY_MODE,
) -> str:
    config = _load_json(config_path, "adoption configuration")
    try:
        if authority_mode == NATIVE_AUTHORITY_MODE:
            validate_native_adoption_config(config, governance_sha=evaluator_sha)
        else:
            verifier = _mapping(config.get("verifier"), "verifier configuration")
            app_id = verifier.get("app_id")
            if not isinstance(app_id, int) or isinstance(app_id, bool) or app_id < 1:
                raise CandidatePipelineError("verifier App id must be positive")
            validate_adoption_config(
                config, governance_sha=evaluator_sha, verifier_app_id=app_id
            )
    except AdoptionError as exc:
        raise CandidatePipelineError(str(exc)) from exc
    standard = _mapping(config.get("standard"), "standard configuration")
    if standard.get("sha256") != sha256_file(standard_path):
        raise CandidatePipelineError("adoption standard hash mismatch")
    profile = config.get("profile")
    if not isinstance(profile, str):
        raise CandidatePipelineError("adoption profile is invalid")
    return profile


def _validate_manifest_files(
    manifest: Mapping[str, Any], target: Path, *, native: bool = False
) -> None:
    files = _mapping(manifest.get("files"), "adoption manifest files")
    expected = {
        CONFIG_PATH: target / CONFIG_PATH,
        STANDARD_PATH: target / STANDARD_PATH,
    }
    if not native:
        expected[WORKFLOW_PATH] = target / WORKFLOW_PATH
    if set(files) != set(expected):
        raise CandidatePipelineError("adoption manifest file set is invalid")
    for name, path in expected.items():
        file_path = _inside(target, path, f"adoption file {name}")
        receipt = _mapping(files[name], f"adoption file receipt {name}")
        if receipt != {
            "bytes": file_path.stat().st_size,
            "sha256": sha256_file(file_path),
        }:
            raise CandidatePipelineError("adoption manifest file binding mismatch")


def _validate_authority_inputs(
    *,
    authority_mode: str,
    workflow_repository: str | None,
    workflow_path: str,
    workflow_ref: str,
    workflow_commit_sha: str,
    evaluator_sha: str,
) -> None:
    if authority_mode == LEGACY_AUTHORITY_MODE:
        if workflow_repository is not None:
            raise CandidatePipelineError(
                "legacy candidate workflow repository must be target-owned"
            )
        return
    if authority_mode != NATIVE_AUTHORITY_MODE:
        raise CandidatePipelineError("workflow authority mode is unsupported")
    if (
        workflow_repository != NATIVE_GOVERNANCE_REPOSITORY
        or workflow_path != NATIVE_WORKFLOW_PATH
        or workflow_commit_sha != evaluator_sha
        or workflow_ref
        != f"{workflow_repository}/{workflow_path}@{workflow_commit_sha}"
    ):
        raise CandidatePipelineError("native required workflow identity is invalid")


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidatePipelineError(f"{label} is malformed") from exc
    return _mapping(payload, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidatePipelineError(f"{label} must be an object")
    return value


def _observed_at(pull_request: Mapping[str, Any]) -> str:
    value = pull_request.get("updated_at") or pull_request.get("created_at")
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CandidatePipelineError("pull request timestamp is unavailable")
    return value


def _inside(root: Path, path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CandidatePipelineError(f"{label} path escapes target checkout") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise CandidatePipelineError(f"{label} path is invalid")
    return resolved


def _executable(name: str) -> Path:
    discovered = shutil.which(name)
    if discovered is None:
        raise CandidatePipelineError(f"{name} executable is unavailable")
    path = Path(discovered).resolve()
    if not path.is_file():
        raise CandidatePipelineError(f"{name} executable is invalid")
    return path


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CandidatePipelineError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise CandidatePipelineError(f"unsupported JSON constant: {value}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run untrusted Governance candidate evaluation"
    )
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--evaluator-root", required=True, type=Path)
    parser.add_argument("--event-path", required=True, type=Path)
    parser.add_argument("--config-path", required=True, type=Path)
    parser.add_argument("--standard-path", required=True, type=Path)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-commit-sha", required=True)
    parser.add_argument("--evaluator-sha", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--authority-mode",
        choices=(LEGACY_AUTHORITY_MODE, NATIVE_AUTHORITY_MODE),
        default=LEGACY_AUTHORITY_MODE,
    )
    parser.add_argument("--workflow-repository")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    manifest = run_candidate_pipeline(**vars(arguments))
    print(json.dumps(manifest["decision"], sort_keys=True))
    if (
        arguments.authority_mode == NATIVE_AUTHORITY_MODE
        and manifest["decision"]["status"] != "PASS"
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
