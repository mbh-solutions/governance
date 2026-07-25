from __future__ import annotations

import re
import os
import shutil
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from governance_eval.hashing import sha256_file, sha256_json
from governance_eval.schema_validator import SchemaValidationError
from governance_eval.schemas import validate_packaged_named

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class CheckoutReceiptError(ValueError):
    pass


@dataclass(frozen=True)
class CheckoutReceipt:
    schema_version: str
    receipt_id: str
    repository: dict[str, Any]
    pull_request: dict[str, Any]
    evaluator: dict[str, Any]
    workflow: dict[str, Any]
    git_path: str
    git_sha256: str
    docker: dict[str, str]
    config_sha256: str
    standard_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "repository": self.repository,
            "pull_request": self.pull_request,
            "evaluator": self.evaluator,
            "workflow": self.workflow,
            "git_path": self.git_path,
            "git_sha256": self.git_sha256,
            "docker": self.docker,
            "config_sha256": self.config_sha256,
            "standard_sha256": self.standard_sha256,
        }


def bind_checkout(
    *,
    target_root: Path,
    evaluator_root: Path,
    event: Mapping[str, Any],
    pull_request: Mapping[str, Any],
    repository: Mapping[str, Any],
    evaluator_repository: Mapping[str, Any],
    workflow: Mapping[str, Any],
    config_path: Path,
    standard_path: Path,
    runtime: Mapping[str, Any],
    workflow_repository: Mapping[str, Any] | None = None,
) -> CheckoutReceipt:
    target_root = target_root.resolve()
    evaluator_root = evaluator_root.resolve()
    trusted_repository = _repository_identity(repository)
    trusted_evaluator_repository = _repository_identity(evaluator_repository)
    trusted_workflow_repository = (
        trusted_repository
        if workflow_repository is None
        else _repository_identity(workflow_repository)
    )
    _match_event(event, trusted_repository, pull_request)
    pr_identity = _pull_request_identity(pull_request)
    _validate_checkout(target_root, "target")
    _validate_checkout(evaluator_root, "evaluator")
    _match_target(target_root, trusted_repository, pr_identity)
    evaluator_identity = _match_evaluator(
        evaluator_root,
        trusted_evaluator_repository,
        trusted_workflow_repository,
        workflow,
    )
    config_path = _trusted_input(target_root, config_path, "config")
    standard_path = _trusted_input(target_root, standard_path, "standard")
    receipt = CheckoutReceipt(
        schema_version="1.0",
        receipt_id="",
        repository=trusted_repository,
        pull_request={
            **pr_identity,
            "base_tree_sha": _git(
                target_root, "rev-parse", f"{pr_identity['base_sha']}^{{tree}}"
            ),
            "head_tree_sha": _git(
                target_root, "rev-parse", f"{pr_identity['head_sha']}^{{tree}}"
            ),
        },
        evaluator=evaluator_identity,
        workflow=_workflow_identity(workflow),
        git_path=str(_git_executable()),
        git_sha256=sha256_file(_git_executable()),
        docker=_runtime_identity(runtime),
        config_sha256=sha256_file(config_path),
        standard_sha256=sha256_file(standard_path),
    )
    receipt = replace(receipt, receipt_id=sha256_json(_unsigned(receipt)))
    try:
        validate_packaged_named("checkout_receipt", receipt.to_json())
    except (KeyError, OSError, SchemaValidationError, ValueError) as exc:
        raise CheckoutReceiptError(
            f"checkout receipt schema is invalid: {exc}"
        ) from exc
    return receipt


def _repository_identity(repository: Mapping[str, Any]) -> dict[str, Any]:
    repository_id = repository.get("id")
    full_name = repository.get("full_name")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
    ):
        raise CheckoutReceiptError("repository id must be a positive integer")
    if not isinstance(full_name, str) or not _REPOSITORY_RE.fullmatch(full_name):
        raise CheckoutReceiptError("repository full_name must be owner/name")
    return {"id": repository_id, "full_name": full_name}


def _pull_request_identity(pull_request: Mapping[str, Any]) -> dict[str, Any]:
    number = pull_request.get("number")
    url = pull_request.get("html_url")
    base_sha = _nested_sha(pull_request, "base")
    head_sha = _nested_sha(pull_request, "head")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise CheckoutReceiptError("pull request number must be positive")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        raise CheckoutReceiptError("pull request URL is invalid")
    return {"number": number, "url": url, "base_sha": base_sha, "head_sha": head_sha}


def _nested_sha(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    sha = value.get("sha") if isinstance(value, Mapping) else None
    if not isinstance(sha, str) or not _SHA_RE.fullmatch(sha):
        raise CheckoutReceiptError(f"pull request {field} sha is invalid")
    return sha


def _match_event(
    event: Mapping[str, Any],
    repository: Mapping[str, Any],
    pull_request: Mapping[str, Any],
) -> None:
    event_repository = event.get("repository")
    if (
        not isinstance(event_repository, Mapping)
        or _repository_identity(event_repository) != repository
    ):
        raise CheckoutReceiptError(
            "repository id or name differs between event and API"
        )
    event_pr = event.get("pull_request")
    if not isinstance(event_pr, Mapping):
        raise CheckoutReceiptError("pull request is missing from event")
    expected = _pull_request_identity(pull_request)
    actual = _pull_request_identity(event_pr)
    for field in ("number", "url", "base_sha", "head_sha"):
        if actual[field] != expected[field]:
            label = field.replace("_", " ")
            raise CheckoutReceiptError(
                f"pull request {label} differs between event and API"
            )


def _validate_checkout(root: Path, label: str) -> None:
    if _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    ):
        raise CheckoutReceiptError(f"{label} checkout is dirty")
    for entry in _git(root, "ls-files", "--stage").splitlines():
        mode = entry.split(maxsplit=1)[0]
        if mode not in {"100644", "100755"}:
            raise CheckoutReceiptError(
                f"{label} checkout contains unsupported Git mode {mode}"
            )


def _match_target(
    root: Path, repository: Mapping[str, Any], pull_request: Mapping[str, Any]
) -> None:
    if _git(root, "rev-parse", "HEAD") != pull_request["head_sha"]:
        raise CheckoutReceiptError("target head does not match pull request head sha")
    _git(root, "cat-file", "-e", f"{pull_request['base_sha']}^{{commit}}")
    if _origin_repository(root) != repository["full_name"].lower():
        raise CheckoutReceiptError("repository origin does not match GitHub repository")


def _match_evaluator(
    root: Path,
    repository: Mapping[str, Any],
    workflow_repository: Mapping[str, Any],
    workflow: Mapping[str, Any],
) -> dict[str, Any]:
    sha_field = "evaluator_sha" if "evaluator_sha" in workflow else "workflow_sha"
    sha = _required_sha(workflow, sha_field)
    if _git(root, "rev-parse", "HEAD") != sha:
        raise CheckoutReceiptError("workflow sha does not match evaluator checkout")
    workflow_ref = workflow.get("workflow_ref")
    if not isinstance(workflow_ref, str) or not workflow_ref.startswith(
        f"{workflow_repository['full_name']}/.github/workflows/"
    ):
        raise CheckoutReceiptError("workflow ref does not match repository")
    if _origin_repository(root) != repository["full_name"].lower():
        raise CheckoutReceiptError("evaluator origin does not match GitHub repository")
    return {
        "repository_id": repository["id"],
        "repository_full_name": repository["full_name"],
        "commit_sha": sha,
        "tree_sha": _git(root, "rev-parse", f"{sha}^{{tree}}"),
    }


def _workflow_identity(workflow: Mapping[str, Any]) -> dict[str, Any]:
    required = (
        "workflow_ref",
        "run_id",
        "run_attempt",
        "server_url",
        "api_url",
        "observed_at",
    )
    if any(field not in workflow for field in required):
        raise CheckoutReceiptError("workflow identity is incomplete")
    try:
        timestamp = datetime.fromisoformat(
            str(workflow["observed_at"]).removesuffix("Z") + "+00:00"
        )
    except (TypeError, ValueError) as exc:
        raise CheckoutReceiptError("workflow observed_at is invalid") from exc
    if timestamp.utcoffset() is None:
        raise CheckoutReceiptError("workflow observed_at must include UTC offset")
    return {field: workflow[field] for field in required}


def _runtime_identity(runtime: Mapping[str, Any]) -> dict[str, str]:
    path_value = runtime.get("docker_path")
    digest = runtime.get("docker_sha256")
    host = runtime.get("docker_host")
    if not isinstance(path_value, str) or not path_value:
        raise CheckoutReceiptError("trusted Docker path is invalid")
    path = Path(path_value).resolve()
    if not path.is_file() or sha256_file(path) != digest:
        raise CheckoutReceiptError("trusted Docker digest is invalid")
    if host not in {
        "unix:///var/run/docker.sock",
        "npipe:////./pipe/docker_engine",
    }:
        raise CheckoutReceiptError("trusted Docker host is invalid")
    return {"path": str(path), "sha256": str(digest), "host": str(host)}


def _trusted_input(root: Path, path: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise CheckoutReceiptError(
            f"{label} path must be inside target checkout"
        ) from exc
    if not resolved.is_file():
        raise CheckoutReceiptError(f"{label} path must be a file")
    _git(root, "ls-files", "--error-unmatch", relative.as_posix())
    return resolved


def _origin_repository(root: Path) -> str:
    remote = _git(root, "remote", "get-url", "origin").removesuffix(".git")
    if remote.startswith("git@github.com:"):
        return remote.removeprefix("git@github.com:").lower()
    parsed = urlparse(remote)
    if parsed.hostname == "github.com" and parsed.path.strip("/"):
        return parsed.path.strip("/").lower()
    raise CheckoutReceiptError("repository origin is not GitHub")


def _required_sha(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise CheckoutReceiptError(f"{field.replace('_', ' ')} is invalid")
    return value


def _git(root: Path, *arguments: str) -> str:
    executable = _git_executable()
    try:
        completed = subprocess.run(
            [
                str(executable),
                f"--git-dir={root / '.git'}",
                f"--work-tree={root}",
                *arguments,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env=_git_environment(executable),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CheckoutReceiptError(
            f"git evidence unavailable: {' '.join(arguments)}"
        ) from exc
    return completed.stdout.strip()


def _git_executable() -> Path:
    configured = os.environ.get("GOVERNANCE_TRUSTED_GIT")
    discovered = configured or shutil.which("git")
    if discovered is None:
        raise CheckoutReceiptError("trusted Git executable is unavailable")
    path = Path(discovered).resolve()
    if not path.is_file():
        raise CheckoutReceiptError("trusted Git executable path is invalid")
    return path


def _git_environment(executable: Path) -> dict[str, str]:
    environment = {
        "PATH": str(executable.parent),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    }
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment


def _unsigned(receipt: CheckoutReceipt) -> dict[str, Any]:
    payload = receipt.to_json()
    payload.pop("receipt_id")
    return payload
