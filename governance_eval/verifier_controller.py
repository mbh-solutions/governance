from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import quote

from governance_eval.artifact_verifier import REQUIRED_CONTEXT
from governance_eval.capability_catalog import PROFILE_ADAPTERS
from governance_eval.sqlite_policy import POLICY_SHA256
from governance_eval.verifier_pipeline import (
    WORKFLOW_PATH,
    GitHubAPIClient,
    VerificationTarget,
    publish_rejection,
    verify_and_publish,
)


MISSING_EVIDENCE_TIMEOUT = timedelta(minutes=15)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
_BASE_ENTRY_FIELDS = {
    "repository",
    "repository_id",
    "candidate_workflow_path",
    "governance_sha",
    "workflow_sha256",
    "configuration_sha256",
    "standard_sha256",
    "required_context",
    "verifier_app_id",
}
_OPTIONAL_ENTRY_FIELDS = {
    "profile",
    "adoption_manifest_sha256",
    "sqlite_policy_sha256",
}


class ControllerError(ValueError):
    pass


class ControllerAPI(Protocol):
    def get_json(self, path: str) -> Mapping[str, Any]: ...

    def get_list(self, path: str) -> list[Any]: ...

    def post_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def patch_json(
        self, path: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def download(self, path: str, destination: Path, limit: int) -> None: ...


@dataclass(frozen=True)
class Enrollment:
    repository: str
    repository_id: int
    candidate_workflow_path: str
    governance_sha: str
    workflow_sha256: str
    configuration_sha256: str
    standard_sha256: str
    required_context: str
    verifier_app_id: int
    profile: str = "python.standard.v1"
    adoption_manifest_sha256: str | None = None
    sqlite_policy_sha256: str | None = None


def load_registry(
    path: Path, *, governance_sha: str, verifier_app_id: int
) -> tuple[Enrollment, ...]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ControllerError("enrollment registry is unavailable")
    value = _load_json(path)
    if set(value) != {"schema_version", "repositories"}:
        raise ControllerError("enrollment registry fields are invalid")
    repositories = value.get("repositories")
    if value.get("schema_version") != "1.0" or not isinstance(repositories, list):
        raise ControllerError("enrollment registry contract is invalid")
    entries = tuple(
        _enrollment(item, governance_sha, verifier_app_id) for item in repositories
    )
    if len({item.repository for item in entries}) != len(entries):
        raise ControllerError("enrollment registry contains duplicate repositories")
    if len({item.repository_id for item in entries}) != len(entries):
        raise ControllerError("enrollment registry contains duplicate repository ids")
    return entries


def run_controller(
    *,
    api: ControllerAPI,
    enrollments: Sequence[Enrollment],
    output_directory: Path,
    repository: str | None = None,
    pull_request: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    output = _new_output(output_directory)
    selected = _selected(enrollments, repository, pull_request)
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    results: list[dict[str, Any]] = []
    for enrollment in selected:
        for pull in _open_pull_requests(api, enrollment, pull_request):
            results.append(_process_pull(api, enrollment, pull, output, observed))
    receipt = {
        "schema_version": "1.0",
        "status": "PASS",
        "repository_filter": repository,
        "pull_request_filter": pull_request,
        "results": results,
    }
    _write_json(output / "controller-receipt.json", receipt)
    return receipt


def _process_pull(
    api: ControllerAPI,
    enrollment: Enrollment,
    pull: Mapping[str, Any],
    output: Path,
    now: datetime,
) -> dict[str, Any]:
    number = _positive_integer(pull.get("number"), "pull request number")
    head_sha = _sha(_mapping(pull.get("head"), "pull request head").get("sha"))
    base_sha = _sha(_mapping(pull.get("base"), "pull request base").get("sha"))
    _validate_pull_repository(pull, enrollment)
    runs = _matching_runs(api, enrollment, number, base_sha, head_sha)
    directory = output / enrollment.repository.replace("/", "_") / f"pr-{number}"
    if not runs:
        if now - _timestamp(pull.get("updated_at")) < MISSING_EVIDENCE_TIMEOUT:
            return _result(enrollment, number, head_sha, "PENDING", None, None)
        result = publish_rejection(
            api=api,
            repository=enrollment.repository,
            repository_id=enrollment.repository_id,
            pull_request=number,
            head_sha=head_sha,
            verifier_app_id=enrollment.verifier_app_id,
            error="candidate evidence unavailable after bounded timeout",
            output_directory=directory,
        )
        return _result(
            enrollment, number, head_sha, result["result"], None, result["check_run_id"]
        )
    run = max(runs, key=lambda item: (item["run_attempt"], item["id"]))
    result = verify_and_publish(
        api=api,
        target=VerificationTarget(
            repository=enrollment.repository,
            pull_request=number,
            run_id=run["id"],
            run_attempt=run["run_attempt"],
            evaluator_sha=enrollment.governance_sha,
            verifier_app_id=enrollment.verifier_app_id,
            repository_id=enrollment.repository_id,
            workflow_sha256=enrollment.workflow_sha256,
            configuration_sha256=enrollment.configuration_sha256,
            standard_sha256=enrollment.standard_sha256,
            required_context=enrollment.required_context,
            profile=enrollment.profile,
            adoption_manifest_sha256=enrollment.adoption_manifest_sha256,
            sqlite_policy_sha256=enrollment.sqlite_policy_sha256,
        ),
        output_directory=directory,
    )
    return _result(
        enrollment,
        number,
        head_sha,
        result["result"],
        run["id"],
        result["check_run_id"],
    )


def _matching_runs(
    api: ControllerAPI,
    enrollment: Enrollment,
    pull_request: int,
    base_sha: str,
    head_sha: str,
) -> list[dict[str, int]]:
    path = quote(enrollment.candidate_workflow_path, safe="")
    runs: list[Any] = []
    for page in range(1, 101):
        payload = api.get_json(
            f"/repos/{enrollment.repository}/actions/workflows/{path}/runs"
            f"?event=pull_request&head_sha={head_sha}&status=completed&per_page=100&page={page}"
        )
        values = payload.get("workflow_runs")
        if not isinstance(values, list) or len(values) > 100:
            raise ControllerError("candidate workflow run listing is invalid")
        runs.extend(values)
        if len(values) < 100:
            break
    else:
        raise ControllerError("candidate workflow run pagination exceeded")
    return [
        {"id": item["id"], "run_attempt": item["run_attempt"]}
        for item in runs
        if _run_matches(item, enrollment, pull_request, base_sha, head_sha)
    ]


def _run_matches(
    value: Any,
    enrollment: Enrollment,
    pull_request: int,
    base_sha: str,
    head_sha: str,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    expected = {
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": head_sha,
        "path": enrollment.candidate_workflow_path,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        return False
    if not _positive_values(value.get("id"), value.get("run_attempt")):
        return False
    repository = value.get("repository")
    if (
        not isinstance(repository, Mapping)
        or repository.get("id") != enrollment.repository_id
    ):
        return False
    pulls = value.get("pull_requests")
    return isinstance(pulls, list) and any(
        _run_pull_matches(item, pull_request, base_sha, head_sha) for item in pulls
    )


def _run_pull_matches(value: Any, number: int, base_sha: str, head_sha: str) -> bool:
    if not isinstance(value, Mapping) or value.get("number") != number:
        return False
    base = value.get("base")
    head = value.get("head")
    return (
        isinstance(base, Mapping)
        and isinstance(head, Mapping)
        and base.get("sha") == base_sha
        and head.get("sha") == head_sha
    )


def _open_pull_requests(
    api: ControllerAPI,
    enrollment: Enrollment,
    pull_request: int | None,
) -> list[Mapping[str, Any]]:
    values: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        page_values = api.get_list(
            f"/repos/{enrollment.repository}/pulls"
            f"?state=open&sort=created&direction=asc&per_page=100&page={page}"
        )
        if len(page_values) > 100 or any(
            not isinstance(item, Mapping) for item in page_values
        ):
            raise ControllerError("open pull request listing is invalid")
        values.extend(page_values)
        if len(page_values) < 100:
            break
    else:
        raise ControllerError("open pull request pagination exceeded")
    if pull_request is not None:
        values = [item for item in values if item.get("number") == pull_request]
    return values


def _selected(
    enrollments: Sequence[Enrollment],
    repository: str | None,
    pull_request: int | None,
) -> tuple[Enrollment, ...]:
    if pull_request is not None and repository is None:
        raise ControllerError("pull request filter requires repository filter")
    if repository is None:
        return tuple(sorted(enrollments, key=lambda item: item.repository))
    matches = tuple(item for item in enrollments if item.repository == repository)
    if len(matches) != 1:
        raise ControllerError("repository filter is not enrolled")
    return matches


def _enrollment(value: Any, governance_sha: str, app_id: int) -> Enrollment:
    item = _mapping(value, "enrollment")
    if not _BASE_ENTRY_FIELDS.issubset(item) or not set(item).issubset(
        _BASE_ENTRY_FIELDS | _OPTIONAL_ENTRY_FIELDS
    ):
        raise ControllerError("enrollment fields are invalid")
    enrollment = Enrollment(**dict(item))
    if not _REPOSITORY_RE.fullmatch(enrollment.repository):
        raise ControllerError("enrollment repository is invalid")
    _positive_integer(enrollment.repository_id, "repository id")
    _positive_integer(enrollment.verifier_app_id, "verifier App id")
    if enrollment.candidate_workflow_path != WORKFLOW_PATH:
        raise ControllerError("candidate workflow path is invalid")
    if enrollment.governance_sha != governance_sha or not _SHA_RE.fullmatch(
        governance_sha
    ):
        raise ControllerError("enrollment Governance SHA is invalid")
    if enrollment.verifier_app_id != app_id:
        raise ControllerError("enrollment verifier App id is invalid")
    if enrollment.required_context != REQUIRED_CONTEXT:
        raise ControllerError("enrollment required context is invalid")
    _validate_enrollment_profile(enrollment)
    if any(
        not _HASH_RE.fullmatch(value)
        for value in (
            enrollment.workflow_sha256,
            enrollment.configuration_sha256,
            enrollment.standard_sha256,
            *(
                (enrollment.adoption_manifest_sha256,)
                if enrollment.adoption_manifest_sha256 is not None
                else ()
            ),
            *(
                (enrollment.sqlite_policy_sha256,)
                if enrollment.sqlite_policy_sha256 is not None
                else ()
            ),
        )
    ):
        raise ControllerError("enrollment content hash is invalid")
    return enrollment


def _validate_enrollment_profile(enrollment: Enrollment) -> None:
    if enrollment.profile not in PROFILE_ADAPTERS:
        raise ControllerError("enrollment profile is unsupported")
    if enrollment.profile == "python.sqlite.v1":
        if not enrollment.adoption_manifest_sha256:
            raise ControllerError("SQLite enrollment lacks adoption manifest binding")
        if enrollment.sqlite_policy_sha256 != POLICY_SHA256:
            raise ControllerError("SQLite enrollment policy hash is invalid")
    elif enrollment.sqlite_policy_sha256 is not None:
        raise ControllerError("standard enrollment has unexpected SQLite policy")


def _validate_pull_repository(pull: Mapping[str, Any], enrollment: Enrollment) -> None:
    if pull.get("state") != "open":
        raise ControllerError("pull request is not open")
    base = _mapping(pull.get("base"), "pull request base")
    repository = _mapping(base.get("repo"), "pull request base repository")
    if (
        repository.get("id") != enrollment.repository_id
        or repository.get("full_name") != enrollment.repository
    ):
        raise ControllerError("pull request repository binding is invalid")


def _result(
    enrollment: Enrollment,
    pull_request: int,
    head_sha: str,
    result: str,
    run_id: int | None,
    check_run_id: int | None,
) -> dict[str, Any]:
    return {
        "repository": enrollment.repository,
        "repository_id": enrollment.repository_id,
        "profile": enrollment.profile,
        "adoption_manifest_sha256": enrollment.adoption_manifest_sha256,
        "sqlite_policy_sha256": enrollment.sqlite_policy_sha256,
        "pull_request": pull_request,
        "head_sha": head_sha,
        "candidate_run_id": run_id,
        "check_run_id": check_run_id,
        "result": result,
    }


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerError("enrollment registry JSON is malformed") from exc
    return dict(_mapping(value, "enrollment registry"))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ControllerError(f"duplicate enrollment key: {key}")
        value[key] = item
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ControllerError(f"{label} must be an object")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ControllerError(f"{label} must be positive")
    return value


def _positive_values(*values: Any) -> bool:
    return all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in values
    )


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise ControllerError("GitHub SHA is invalid")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ControllerError("GitHub timestamp is invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError as exc:
        raise ControllerError("GitHub timestamp is invalid") from exc


def _new_output(path: Path) -> Path:
    output = path.resolve()
    if output.exists() and (
        output.is_symlink() or not output.is_dir() or any(output.iterdir())
    ):
        raise ControllerError("controller output must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    return output


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Process enrolled Governance repositories"
    )
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--governance-sha", required=True)
    parser.add_argument("--verifier-app-id", required=True, type=int)
    parser.add_argument("--repository")
    parser.add_argument("--pull-request", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    enrollments = load_registry(
        arguments.registry,
        governance_sha=arguments.governance_sha,
        verifier_app_id=arguments.verifier_app_id,
    )
    api = GitHubAPIClient(
        token=os.environ.get("GOVERNANCE_VERIFIER_TOKEN", ""),
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    result = run_controller(
        api=api,
        enrollments=enrollments,
        output_directory=arguments.output_directory,
        repository=arguments.repository,
        pull_request=arguments.pull_request,
    )
    print(
        json.dumps(
            {"status": result["status"], "processed": len(result["results"])},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
