from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import quote, urlparse

from governance_eval.adoption import (
    CONFIG_PATH,
    MANIFEST_PATH,
    STANDARD_PATH as ADOPTION_STANDARD_PATH,
    WORKFLOW_PATH as ADOPTION_WORKFLOW_PATH,
    validate_adoption_config,
    validate_adoption_manifest,
)
from governance_eval.artifact_verifier import (
    GITHUB_ACTIONS_APP_ID,
    MAX_ARCHIVE_BYTES,
    REQUIRED_CONTEXT,
    ArtifactVerificationError,
    VerifierContext,
    check_run_request,
    verify_candidate_artifact,
)
from governance_eval.candidate_bundle import artifact_name
from governance_eval.capability_catalog import PROFILE_ADAPTERS
from governance_eval.sqlite_policy import POLICY_SHA256
from governance_eval.candidate_pipeline import (
    GOVERNANCE_REPOSITORY,
    GOVERNANCE_REPOSITORY_ID,
)


WORKFLOW_PATH = ".github/workflows/governance-candidate.yml"
CONFIGURATION_PATH = ".github/governance/supportability.yml"
STANDARD_PATH = ".github/governance/supportability-standard.md"
API_VERSION = "2022-11-28"
MAX_JSON_BYTES = 4 * 1024 * 1024
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class VerifierPipelineError(RuntimeError):
    pass


class VerifierAPI(Protocol):
    def get_json(self, path: str) -> Mapping[str, Any]: ...

    def get_list(self, path: str) -> list[Any]: ...

    def post_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def patch_json(
        self, path: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def download(self, path: str, destination: Path, limit: int) -> None: ...


@dataclass(frozen=True)
class VerificationTarget:
    repository: str
    pull_request: int
    run_id: int
    run_attempt: int
    evaluator_sha: str
    verifier_app_id: int
    repository_id: int
    workflow_sha256: str
    configuration_sha256: str
    standard_sha256: str
    required_context: str
    profile: str = "python.standard.v1"
    adoption_manifest_sha256: str | None = None
    sqlite_policy_sha256: str | None = None


class GitHubAPIClient:
    def __init__(self, *, token: str, api_url: str = "https://api.github.com"):
        if not token or any(character.isspace() for character in token):
            raise VerifierPipelineError("verifier token is unavailable")
        if api_url != "https://api.github.com":
            raise VerifierPipelineError("GitHub API URL is not trusted")
        self.token = token
        self.api_url = api_url
        self.opener = urllib.request.build_opener(_SafeRedirectHandler())

    def get_json(self, path: str) -> Mapping[str, Any]:
        return _mapping(self._json_request(path, method="GET"), "GitHub API response")

    def get_list(self, path: str) -> list[Any]:
        value = self._json_request(path, method="GET")
        if not isinstance(value, list):
            raise VerifierPipelineError("GitHub API response must be an array")
        return value

    def post_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._json_request(
            path,
            method="POST",
            data=_canonical_json(payload),
        )

    def patch_json(self, path: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._json_request(
            path,
            method="PATCH",
            data=_canonical_json(payload),
        )

    def download(self, path: str, destination: Path, limit: int) -> None:
        request = self._request(path, method="GET")
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(limit + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise VerifierPipelineError("GitHub artifact download failed") from exc
        if len(data) > limit:
            raise VerifierPipelineError("GitHub artifact exceeds download limit")
        destination.write_bytes(data)

    def _json_request(
        self, path: str, *, method: str, data: bytes | None = None
    ) -> Any:
        request = self._request(path, method=method, data=data)
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
        except (OSError, urllib.error.URLError) as exc:
            raise VerifierPipelineError(f"GitHub API {method} failed") from exc
        if len(raw) > MAX_JSON_BYTES:
            raise VerifierPipelineError("GitHub API response exceeds size limit")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerifierPipelineError("GitHub API returned malformed JSON") from exc
        return value

    def _request(
        self, path: str, *, method: str, data: bytes | None = None
    ) -> urllib.request.Request:
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise VerifierPipelineError("GitHub API path is invalid")
        return urllib.request.Request(
            self.api_url + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "Content-Type": "application/json",
                "User-Agent": "governance-authoritative-verifier",
            },
        )


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: http.client.HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        if redirected is None:
            return None
        old = urlparse(request.full_url)
        new = urlparse(new_url)
        if new.scheme != "https":
            raise VerifierPipelineError("GitHub redirect is not HTTPS")
        if old.hostname != new.hostname:
            redirected.remove_header("Authorization")
        return redirected


def verify_and_publish(
    *,
    api: VerifierAPI,
    target: VerificationTarget,
    output_directory: Path,
    verified_at: str | None = None,
) -> dict[str, Any]:
    _validate_target(target)
    _prepare_output(output_directory)
    repository = _repository(api, target.repository)
    if repository["id"] != target.repository_id:
        raise VerifierPipelineError("enrolled repository id mismatch")
    pull_request = _pull_request(api, target, repository)
    initial_head = _sha(_nested(pull_request, "head").get("sha"), "PR head")
    request: Mapping[str, Any]
    try:
        archive = output_directory / "candidate-artifact.zip"
        context = _collect_context(
            api,
            target,
            repository,
            pull_request,
            archive,
            verified_at or _now(),
        )
        receipt = verify_candidate_artifact(archive, context)
        request = check_run_request(receipt)
    except (
        ArtifactVerificationError,
        VerifierPipelineError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        receipt = {"result": "REJECT", "errors": [str(exc)]}
        request = _rejection_request(initial_head, str(exc))
    latest = _pull_request(api, target, repository)
    latest_head = _sha(_nested(latest, "head").get("sha"), "current PR head")
    if latest_head != initial_head:
        request = _rejection_request(
            latest_head, "pull request head changed during verification"
        )
        receipt = {
            "result": "REJECT",
            "errors": ["pull request head changed during verification"],
        }
    started, response, check_id, request, identity_valid = _publish_check(
        api, target.repository, target.verifier_app_id, request
    )
    if not identity_valid:
        receipt = {
            "result": "REJECT",
            "errors": ["created check App or head identity mismatch"],
        }
    _write_json(output_directory / "verifier-receipt.json", receipt)
    _write_json(output_directory / "check-run-request.json", request)
    _write_json(output_directory / "check-run-created.json", started)
    _write_json(output_directory / "check-run-response.json", response)
    return {
        "result": receipt["result"],
        "head_sha": request["head_sha"],
        "check_run_id": check_id,
    }


def publish_rejection(
    *,
    api: VerifierAPI,
    repository: str,
    repository_id: int,
    pull_request: int,
    head_sha: str,
    verifier_app_id: int,
    error: str,
    output_directory: Path,
) -> dict[str, Any]:
    if not _REPOSITORY_RE.fullmatch(repository) or repository != repository.lower():
        raise VerifierPipelineError("target repository must use canonical owner/name")
    _positive_integer(repository_id, "repository id")
    _positive_integer(pull_request, "pull request")
    _positive_integer(verifier_app_id, "verifier App id")
    _sha(head_sha, "PR head")
    _prepare_output(output_directory)
    observed_repository = _repository(api, repository)
    if observed_repository["id"] != repository_id:
        raise VerifierPipelineError("enrolled repository id mismatch")
    pull = api.get_json(f"/repos/{_repository_path(repository)}/pulls/{pull_request}")
    if pull.get("state") != "open" or pull.get("number") != pull_request:
        raise VerifierPipelineError("pull request identity or state mismatch")
    current_head = _sha(_nested(pull, "head").get("sha"), "PR head")
    if current_head != head_sha:
        raise VerifierPipelineError("pull request head changed before rejection")
    request: Mapping[str, Any] = _rejection_request(head_sha, error)
    started, response, check_id, request, _identity_valid = _publish_check(
        api, repository, verifier_app_id, request
    )
    receipt = {"result": "REJECT", "errors": [error]}
    _write_json(output_directory / "verifier-receipt.json", receipt)
    _write_json(output_directory / "check-run-request.json", request)
    _write_json(output_directory / "check-run-created.json", started)
    _write_json(output_directory / "check-run-response.json", response)
    return {"result": "REJECT", "head_sha": head_sha, "check_run_id": check_id}


def _publish_check(
    api: VerifierAPI,
    repository: str,
    verifier_app_id: int,
    request: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any], int, Mapping[str, Any], bool]:
    check_path = f"/repos/{_repository_path(repository)}/check-runs"
    started = _existing_check(
        api, repository, verifier_app_id, str(request["head_sha"])
    )
    if started is None:
        started = api.post_json(check_path, _begin_check_request(request))
    check_id = _positive_integer(started.get("id"), "authoritative check run id")
    actual_app_id = _positive_integer(
        _nested(started, "app").get("id"), "created check App id"
    )
    identity_valid = (
        actual_app_id == verifier_app_id
        and started.get("name") == REQUIRED_CONTEXT
        and started.get("head_sha") == request["head_sha"]
    )
    final_request = (
        request
        if identity_valid
        else _rejection_request(
            str(request["head_sha"]), "created check App or head identity mismatch"
        )
    )
    response = api.patch_json(
        f"{check_path}/{check_id}", _check_update_request(final_request)
    )
    return started, response, check_id, final_request, identity_valid


def _existing_check(
    api: VerifierAPI, repository: str, verifier_app_id: int, head_sha: str
) -> Mapping[str, Any] | None:
    name = quote(REQUIRED_CONTEXT, safe="")
    base_path = (
        f"/repos/{_repository_path(repository)}/commits/{head_sha}/check-runs"
        f"?check_name={name}&per_page=100"
    )
    values: list[Any] = []
    for page in range(1, 101):
        path = base_path if page == 1 else f"{base_path}&page={page}"
        payload = api.get_json(path)
        page_values = payload.get("check_runs")
        if not isinstance(page_values, list) or len(page_values) > 100:
            raise VerifierPipelineError("authoritative check listing is invalid")
        values.extend(page_values)
        if len(page_values) < 100:
            break
    else:
        raise VerifierPipelineError("authoritative check pagination exceeded")
    matches = [
        item
        for item in values
        if isinstance(item, Mapping)
        and item.get("name") == REQUIRED_CONTEXT
        and isinstance(item.get("app"), Mapping)
        and item["app"].get("id") == verifier_app_id
        and item.get("head_sha") == head_sha
    ]
    if len(matches) > 1:
        raise VerifierPipelineError("authoritative check identity is ambiguous")
    return matches[0] if matches else None


def _collect_context(
    api: VerifierAPI,
    target: VerificationTarget,
    repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
    archive: Path,
    verified_at: str,
) -> VerifierContext:
    base = _nested(pull_request, "base")
    head = _nested(pull_request, "head")
    base_sha = _sha(base.get("sha"), "PR base")
    head_sha = _sha(head.get("sha"), "PR head")
    run = api.get_json(
        f"/repos/{_repository_path(target.repository)}/actions/runs/{target.run_id}"
    )
    run_app_id = _run_app_id(api, target.repository, run, head_sha)
    _validate_run(run, target, repository, base_sha, head_sha, run_app_id)
    artifact = _artifact(api, target, repository["id"], head_sha)
    artifact_id = _positive_integer(artifact.get("id"), "artifact id")
    api.download(
        f"/repos/{_repository_path(target.repository)}/actions/artifacts/{artifact_id}/zip",
        archive,
        MAX_ARCHIVE_BYTES,
    )
    evaluator = _repository(api, GOVERNANCE_REPOSITORY)
    if evaluator["id"] != GOVERNANCE_REPOSITORY_ID:
        raise VerifierPipelineError("Governance evaluator repository id mismatch")
    head_commit = _commit(api, target.repository, head_sha)
    evaluator_commit = _commit(api, GOVERNANCE_REPOSITORY, target.evaluator_sha)
    workflow_raw = _content(api, target.repository, WORKFLOW_PATH, head_sha)
    configuration_raw = _content(api, target.repository, CONFIGURATION_PATH, head_sha)
    standard_raw = _content(api, target.repository, STANDARD_PATH, head_sha)
    manifest_raw = _content(api, target.repository, MANIFEST_PATH, head_sha)
    workflow_sha256 = sha256(workflow_raw).hexdigest()
    configuration_sha256 = sha256(configuration_raw).hexdigest()
    standard_sha256 = sha256(standard_raw).hexdigest()
    adoption_manifest_sha256 = sha256(manifest_raw).hexdigest()
    if (
        workflow_sha256 != target.workflow_sha256
        or configuration_sha256 != target.configuration_sha256
        or standard_sha256 != target.standard_sha256
    ):
        raise VerifierPipelineError("enrolled workflow or configuration hash mismatch")
    if (
        target.adoption_manifest_sha256 is not None
        and adoption_manifest_sha256 != target.adoption_manifest_sha256
    ):
        raise VerifierPipelineError("enrolled adoption manifest hash mismatch")
    configuration = _json_content(configuration_raw, "adoption configuration")
    manifest = _json_content(manifest_raw, "adoption manifest")
    verifier = _nested(configuration, "verifier")
    app_id = _positive_integer(verifier.get("app_id"), "configuration App id")
    if app_id != target.verifier_app_id:
        raise VerifierPipelineError("configuration verifier App mismatch")
    validate_adoption_config(
        configuration,
        governance_sha=target.evaluator_sha,
        verifier_app_id=target.verifier_app_id,
        profile=target.profile,
    )
    validate_adoption_manifest(
        manifest,
        repository=target.repository,
        repository_id=target.repository_id,
        governance_sha=target.evaluator_sha,
        verifier_app_id=target.verifier_app_id,
        profile=target.profile,
    )
    if _nested(configuration, "standard").get("sha256") != standard_sha256:
        raise VerifierPipelineError("configuration standard content hash mismatch")
    _validate_manifest_files(
        manifest,
        {
            CONFIG_PATH: configuration_raw,
            ADOPTION_STANDARD_PATH: standard_raw,
            ADOPTION_WORKFLOW_PATH: workflow_raw,
        },
    )
    return VerifierContext(
        repository_id=repository["id"],
        repository_full_name=repository["full_name"],
        pull_request=target.pull_request,
        base_sha=base_sha,
        head_sha=head_sha,
        head_tree_sha=_tree_sha(head_commit),
        current_head_sha=head_sha,
        workflow_path=WORKFLOW_PATH,
        workflow_commit_sha=head_sha,
        workflow_file_sha256=workflow_sha256,
        evaluator_repository_id=evaluator["id"],
        evaluator_repository_full_name=evaluator["full_name"],
        evaluator_sha=target.evaluator_sha,
        evaluator_tree_sha=_tree_sha(evaluator_commit),
        configuration_sha256=configuration_sha256,
        standard_sha256=standard_sha256,
        run_id=target.run_id,
        run_attempt=target.run_attempt,
        run_event=str(run.get("event")),
        run_status=str(run.get("status")),
        run_conclusion=str(run.get("conclusion")),
        run_app_id=run_app_id,
        artifact_id=artifact_id,
        artifact_name=str(artifact.get("name")),
        artifact_digest=_digest(artifact.get("digest")),
        artifact_created_at=_timestamp(
            artifact.get("created_at"), "artifact created_at"
        ),
        verified_at=_timestamp(verified_at, "verified_at"),
        verifier_app_id=target.verifier_app_id,
        profile=target.profile,
        adoption_manifest_sha256=adoption_manifest_sha256,
        sqlite_policy_sha256=target.sqlite_policy_sha256 or "",
    )


def _repository(api: VerifierAPI, name: str) -> dict[str, Any]:
    payload = api.get_json(f"/repos/{_repository_path(name)}")
    repository_id = _positive_integer(payload.get("id"), "repository id")
    full_name = payload.get("full_name")
    if full_name != name:
        raise VerifierPipelineError("repository full name mismatch")
    return {"id": repository_id, "full_name": full_name}


def _pull_request(
    api: VerifierAPI,
    target: VerificationTarget,
    repository: Mapping[str, Any],
) -> Mapping[str, Any]:
    payload = api.get_json(
        f"/repos/{_repository_path(target.repository)}/pulls/{target.pull_request}"
    )
    if payload.get("number") != target.pull_request or payload.get("state") != "open":
        raise VerifierPipelineError("pull request identity or state mismatch")
    base_repository = _nested(_nested(payload, "base"), "repo")
    if base_repository.get("id") != repository["id"]:
        raise VerifierPipelineError("pull request base repository mismatch")
    return payload


def _validate_run(
    run: Mapping[str, Any],
    target: VerificationTarget,
    repository: Mapping[str, Any],
    base_sha: str,
    head_sha: str,
    run_app_id: int,
) -> None:
    expected = {
        "id": target.run_id,
        "run_attempt": target.run_attempt,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": head_sha,
        "path": WORKFLOW_PATH,
    }
    if any(run.get(field) != value for field, value in expected.items()):
        raise VerifierPipelineError("candidate workflow run identity mismatch")
    run_repository = _nested(run, "repository")
    if (
        run_repository.get("id") != repository["id"]
        or run_repository.get("full_name") != repository["full_name"]
    ):
        raise VerifierPipelineError("candidate workflow repository mismatch")
    if run_app_id != GITHUB_ACTIONS_APP_ID:
        raise VerifierPipelineError("candidate workflow producer mismatch")
    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list) or not any(
        _run_pull_request_matches(item, target.pull_request, base_sha, head_sha)
        for item in pull_requests
    ):
        raise VerifierPipelineError("candidate workflow pull request mismatch")


def _run_app_id(
    api: VerifierAPI,
    repository: str,
    run: Mapping[str, Any],
    head_sha: str,
) -> int:
    suite_id = _positive_integer(run.get("check_suite_id"), "run check suite id")
    suite = api.get_json(
        f"/repos/{_repository_path(repository)}/check-suites/{suite_id}"
    )
    if suite.get("id") != suite_id or suite.get("head_sha") != head_sha:
        raise VerifierPipelineError("candidate workflow check suite mismatch")
    return _positive_integer(_nested(suite, "app").get("id"), "run App id")


def _run_pull_request_matches(
    value: Any, number: int, base_sha: str, head_sha: str
) -> bool:
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


def _artifact(
    api: VerifierAPI,
    target: VerificationTarget,
    repository_id: int,
    head_sha: str,
) -> Mapping[str, Any]:
    base_path = (
        f"/repos/{_repository_path(target.repository)}/actions/runs/"
        f"{target.run_id}/artifacts?per_page=100"
    )
    artifacts: list[Any] = []
    for page in range(1, 101):
        path = base_path if page == 1 else f"{base_path}&page={page}"
        payload = api.get_json(path)
        page_values = payload.get("artifacts")
        if not isinstance(page_values, list) or len(page_values) > 100:
            raise VerifierPipelineError("candidate artifact listing is invalid")
        artifacts.extend(page_values)
        if len(page_values) < 100:
            break
    else:
        raise VerifierPipelineError("candidate artifact pagination exceeded")
    expected_name = artifact_name(target.run_id, target.run_attempt)
    matches = [
        item
        for item in artifacts
        if isinstance(item, Mapping) and item.get("name") == expected_name
    ]
    if len(matches) != 1:
        raise VerifierPipelineError("candidate artifact identity is ambiguous")
    artifact = matches[0]
    workflow_run = _nested(artifact, "workflow_run")
    if (
        artifact.get("expired") is not False
        or workflow_run.get("id") != target.run_id
        or workflow_run.get("repository_id") != repository_id
        or workflow_run.get("head_sha") != head_sha
    ):
        raise VerifierPipelineError("candidate artifact provenance is invalid")
    size = artifact.get("size_in_bytes")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= MAX_ARCHIVE_BYTES
    ):
        raise VerifierPipelineError("candidate artifact size is invalid")
    _digest(artifact.get("digest"))
    _timestamp(artifact.get("created_at"), "artifact created_at")
    return artifact


def _commit(api: VerifierAPI, repository: str, commit_sha: str) -> Mapping[str, Any]:
    payload = api.get_json(
        f"/repos/{_repository_path(repository)}/git/commits/{commit_sha}"
    )
    if payload.get("sha") != commit_sha:
        raise VerifierPipelineError("Git commit identity mismatch")
    return payload


def _tree_sha(commit: Mapping[str, Any]) -> str:
    return _sha(_nested(commit, "tree").get("sha"), "Git tree")


def _content(api: VerifierAPI, repository: str, path: str, commit_sha: str) -> bytes:
    payload = api.get_json(
        f"/repos/{_repository_path(repository)}/contents/{quote(path, safe='/')}?ref={commit_sha}"
    )
    if payload.get("type") != "file" or payload.get("encoding") != "base64":
        raise VerifierPipelineError("repository content identity is invalid")
    content = payload.get("content")
    if not isinstance(content, str):
        raise VerifierPipelineError("repository content is unavailable")
    try:
        raw = base64.b64decode("".join(content.split()), validate=True)
    except ValueError as exc:
        raise VerifierPipelineError("repository content encoding is invalid") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise VerifierPipelineError("repository content exceeds size limit")
    return raw


def _content_sha256(
    api: VerifierAPI, repository: str, path: str, commit_sha: str
) -> str:
    return sha256(_content(api, repository, path, commit_sha)).hexdigest()


def _json_content(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierPipelineError(f"{label} is malformed") from exc
    return _mapping(value, label)


def _validate_manifest_files(
    manifest: Mapping[str, Any], payloads: Mapping[str, bytes]
) -> None:
    files = _nested(manifest, "files")
    if set(files) != set(payloads):
        raise VerifierPipelineError("adoption manifest file set is invalid")
    for name, raw in payloads.items():
        receipt = _mapping(files.get(name), "adoption file receipt")
        if receipt != {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}:
            raise VerifierPipelineError("adoption manifest file binding mismatch")


def _validate_target(target: VerificationTarget) -> None:
    if not _REPOSITORY_RE.fullmatch(target.repository):
        raise VerifierPipelineError("target repository must be owner/name")
    if target.repository != target.repository.lower():
        raise VerifierPipelineError("target repository must use canonical lowercase")
    if target.pull_request < 1 or target.run_id < 1 or target.run_attempt < 1:
        raise VerifierPipelineError("target numeric identity must be positive")
    _positive_integer(target.verifier_app_id, "verifier App id")
    _positive_integer(target.repository_id, "repository id")
    _sha(target.evaluator_sha, "evaluator")
    if any(
        not _HASH_RE.fullmatch(value)
        for value in (
            target.workflow_sha256,
            target.configuration_sha256,
            target.standard_sha256,
        )
    ):
        raise VerifierPipelineError("enrolled content hash is invalid")
    if target.required_context != REQUIRED_CONTEXT:
        raise VerifierPipelineError("required context differs from Governance contract")
    if target.adoption_manifest_sha256 is not None and not _HASH_RE.fullmatch(
        target.adoption_manifest_sha256
    ):
        raise VerifierPipelineError("enrolled adoption manifest hash is invalid")
    _validate_target_profile(target)


def _validate_target_profile(target: VerificationTarget) -> None:
    if target.profile not in PROFILE_ADAPTERS:
        raise VerifierPipelineError("enrolled profile is unsupported")
    if target.profile == "python.sqlite.v1":
        if target.adoption_manifest_sha256 is None:
            raise VerifierPipelineError(
                "SQLite enrollment lacks adoption manifest binding"
            )
        if target.sqlite_policy_sha256 != POLICY_SHA256:
            raise VerifierPipelineError("SQLite enrollment policy hash is invalid")
    elif target.sqlite_policy_sha256 is not None:
        raise VerifierPipelineError("standard enrollment has unexpected SQLite policy")


def _prepare_output(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
            raise VerifierPipelineError("verifier output must be new or empty")
    path.mkdir(parents=True, exist_ok=True)


def _rejection_request(head_sha: str, error: str) -> dict[str, Any]:
    summary = error.strip()[:1000] or "verification failed closed"
    external_id = sha256(
        _canonical_json({"head_sha": head_sha, "error": summary})
    ).hexdigest()
    return {
        "name": REQUIRED_CONTEXT,
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": "failure",
        "external_id": external_id,
        "output": {"title": "Governance verifier: REJECT", "summary": summary},
    }


def _begin_check_request(final_request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": REQUIRED_CONTEXT,
        "head_sha": final_request["head_sha"],
        "status": "in_progress",
        "external_id": final_request["external_id"],
        "output": {
            "title": "Governance verifier: VERIFYING",
            "summary": "Validating fresh exact-head evidence.",
        },
    }


def _check_update_request(final_request: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: final_request[field]
        for field in ("name", "status", "conclusion", "external_id", "output")
    }


def _repository_path(value: str) -> str:
    if not _REPOSITORY_RE.fullmatch(value):
        raise VerifierPipelineError("repository path is invalid")
    return quote(value, safe="/")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VerifierPipelineError(f"{label} must be an object")
    return value


def _nested(value: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    return _mapping(value.get(field), field)


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise VerifierPipelineError(f"{label} must be positive")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise VerifierPipelineError(f"{label} SHA is invalid")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise VerifierPipelineError("artifact digest is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise VerifierPipelineError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise VerifierPipelineError(f"{label} is invalid") from exc
    if parsed.utcoffset() is None:
        raise VerifierPipelineError(f"{label} is invalid")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise VerifierPipelineError("GitHub API JSON contains duplicate keys")
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise VerifierPipelineError(f"unsupported JSON constant: {value}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify candidate evidence and publish the authoritative App check"
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--pull-request", required=True, type=int)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--evaluator-sha", required=True)
    parser.add_argument("--verifier-app-id", required=True, type=int)
    parser.add_argument("--workflow-sha256", required=True)
    parser.add_argument("--configuration-sha256", required=True)
    parser.add_argument("--standard-sha256", required=True)
    parser.add_argument("--required-context", required=True)
    parser.add_argument(
        "--profile", choices=tuple(PROFILE_ADAPTERS), default="python.standard.v1"
    )
    parser.add_argument("--adoption-manifest-sha256")
    parser.add_argument("--sqlite-policy-sha256")
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    api = GitHubAPIClient(
        token=os.environ.get("GOVERNANCE_VERIFIER_TOKEN", ""),
        api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    result = verify_and_publish(
        api=api,
        target=VerificationTarget(
            repository=arguments.repository,
            pull_request=arguments.pull_request,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            evaluator_sha=arguments.evaluator_sha,
            verifier_app_id=arguments.verifier_app_id,
            repository_id=arguments.repository_id,
            workflow_sha256=arguments.workflow_sha256,
            configuration_sha256=arguments.configuration_sha256,
            standard_sha256=arguments.standard_sha256,
            required_context=arguments.required_context,
            profile=arguments.profile,
            adoption_manifest_sha256=arguments.adoption_manifest_sha256,
            sqlite_policy_sha256=arguments.sqlite_policy_sha256,
        ),
        output_directory=arguments.output_directory,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
