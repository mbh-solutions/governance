from __future__ import annotations

import base64
import binascii
import importlib.metadata
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

from governance_eval.checkout_receipt import CheckoutReceipt
from governance_eval.capability_catalog import (
    is_profile_runner,
    profile_adapters,
    runner_profile,
)
from governance_eval.execution_plan_v2 import (
    ExecutionPlanV2,
    _RUFF_SHA256,
    assess_execution_plan_v2,
)
from governance_eval.hashing import sha256_file, sha256_json

_DOCKER_HOSTS = {
    "unix:///var/run/docker.sock",
    "npipe:////./pipe/docker_engine",
}
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


class DockerRuntimeError(RuntimeError):
    pass


def docker_run_argv(
    *,
    docker: Path,
    docker_host: str,
    plan: ExecutionPlanV2,
    workspace: Path,
    toolchain_root: Path,
    container_name: str,
) -> list[str]:
    runtime = plan.runtime
    step = plan.step
    command = [
        str(docker),
        f"--host={docker_host}",
        "run",
        "--rm",
        f"--name={container_name}",
        "--read-only",
        f"--network={runtime['network']}",
        f"--user={runtime['user']}",
        f"--cap-drop={runtime['cap_drop'][0]}",
        "--security-opt=no-new-privileges:true",
        f"--pids-limit={runtime['pids_limit']}",
        f"--memory={runtime['memory_bytes']}",
        f"--cpus={runtime['cpus']}",
        "--env=HOME=/workspace/.home",
        "--env=TMPDIR=/workspace/.tmp",
        "--env=PYTHONNOUSERSITE=1",
        "--env=PYTHONDONTWRITEBYTECODE=1",
    ]
    if is_profile_runner(step["adapter_id"]):
        command.append("--env=PYTHONPATH=/opt/governance-toolchain/site-packages")
    return [
        *command,
        f"--workdir={step['working_directory']}",
        "--mount",
        f"type=bind,src={workspace},dst=/workspace",
        "--mount",
        f"type=bind,src={toolchain_root},dst=/opt/governance-toolchain,readonly",
        runtime["image"],
        *step["argv"],
    ]


def runtime_root_name(plan: ExecutionPlanV2) -> str:
    token = sha256_json(
        {"plan_id": plan.plan_id, "checkout_receipt_id": plan.checkout_receipt_id}
    )[:24]
    return f"governance-runtime-{token}"


def runtime_root_path(plan: ExecutionPlanV2) -> Path:
    return Path(tempfile.gettempdir()).resolve() / runtime_root_name(plan)


def execute_ruff_docker(
    *,
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt,
    target_root: Path,
    evaluator_root: Path,
    toolchain_binary: Path,
) -> dict[str, Any]:
    started = datetime.now(UTC)
    command: list[str] = []
    docker: Path | None = None
    outcome: dict[str, Any] | None = None
    errors: list[str] = []
    runtime_root: Path | None = None
    profile: list[dict[str, Any]] | None = None
    docker_host = str(plan.runtime.get("docker_host", "unknown"))
    try:
        _validate_plan_binding(plan, receipt)
        docker = _trusted_docker(
            Path(plan.runtime["docker_path"]),
            plan.runtime["docker_sha256"],
            docker_host,
        )
        git = _trusted_git(receipt)
        _validate_evaluator(evaluator_root, receipt.evaluator, git)
        _verify_image(docker, docker_host, plan.runtime["image"])
        candidate_root = runtime_root_path(plan)
        candidate_root.mkdir(mode=0o700)
        runtime_root = candidate_root
        workspace = runtime_root / "workspace"
        toolchain_root = runtime_root / "toolchain"
        _seal_toolchain(toolchain_binary, toolchain_root, plan, evaluator_root)
        _materialize_tree(target_root, plan.target, workspace, git)
        container_name = f"governance-{plan.plan_id[:12]}-{uuid.uuid4().hex[:8]}"
        command = docker_run_argv(
            docker=docker,
            docker_host=docker_host,
            plan=plan,
            workspace=workspace,
            toolchain_root=toolchain_root,
            container_name=container_name,
        )
        outcome = _run_bounded(
            command,
            docker=docker,
            docker_host=docker_host,
            container_name=container_name,
            timeout_seconds=plan.step["timeout_seconds"],
            output_limit=plan.step["output_limit_bytes"],
        )
        errors.extend(outcome["errors"])
        profile = _profile_payload(plan, outcome, workspace)
        if is_profile_runner(plan.step["adapter_id"]) and profile is None:
            errors.append("standard profile evidence is missing or malformed")
    except (DockerRuntimeError, OSError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    finally:
        cleanup_error = _remove_runtime_root(runtime_root)
        if cleanup_error is not None:
            errors.append(cleanup_error)
    return _result(
        plan,
        receipt,
        docker,
        docker_host,
        command,
        started,
        outcome=outcome,
        errors=errors,
        profile=profile,
    )


def _remove_runtime_root(runtime_root: Path | None) -> str | None:
    if runtime_root is None:
        return None
    try:
        shutil.rmtree(runtime_root)
    except OSError:
        return "disposable runtime root cleanup failed"
    return None


def _validate_plan_binding(plan: ExecutionPlanV2, receipt: CheckoutReceipt) -> None:
    if plan.checkout_receipt_id != receipt.receipt_id:
        raise DockerRuntimeError("execution plan checkout receipt mismatch")
    receipt_payload = receipt.to_json()
    receipt_id = receipt_payload.pop("receipt_id")
    if receipt_id != sha256_json(receipt_payload):
        raise DockerRuntimeError("checkout receipt integrity is invalid")
    plan_payload = plan.to_json()
    plan_id = plan_payload.pop("plan_id")
    if plan_id != sha256_json(plan_payload):
        raise DockerRuntimeError("execution plan integrity is invalid")
    assessment = assess_execution_plan_v2(plan.to_json(), receipt)
    if assessment["capability_status"] != "PASS":
        raise DockerRuntimeError("execution plan differs from evaluator-owned plan")


def _trusted_docker(path: Path, expected_sha256: str, host: str) -> Path:
    path = path.resolve()
    if not path.is_file():
        raise DockerRuntimeError("Docker CLI path is invalid")
    if sha256_file(path) != expected_sha256:
        raise DockerRuntimeError("Docker CLI digest mismatch")
    if host not in _DOCKER_HOSTS:
        raise DockerRuntimeError("Docker daemon endpoint is unsupported")
    return path


def _trusted_git(receipt: CheckoutReceipt) -> Path:
    path = Path(receipt.git_path).resolve()
    if not path.is_file():
        raise DockerRuntimeError("trusted Git executable is unavailable")
    if sha256_file(path) != receipt.git_sha256:
        raise DockerRuntimeError("trusted Git executable digest mismatch")
    return path


def _verify_image(docker: Path, docker_host: str, image: str) -> None:
    completed = _command(
        [
            str(docker),
            f"--host={docker_host}",
            "image",
            "inspect",
            "--format={{json .RepoDigests}}",
            image,
        ],
        timeout=30,
        env=_docker_environment(docker),
    )
    digest = image.split("@", 1)[1]
    if digest not in completed.stdout:
        raise DockerRuntimeError("Docker image digest mismatch")


def _validate_evaluator(root: Path, evaluator: dict[str, Any], git: Path) -> None:
    root = root.resolve()
    if _git(
        root,
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    ):
        raise DockerRuntimeError("evaluator checkout changed after receipt")
    if _git(root, git, "rev-parse", "HEAD") != evaluator["commit_sha"]:
        raise DockerRuntimeError("evaluator commit changed after receipt")
    if _git(root, git, "rev-parse", "HEAD^{tree}") != evaluator["tree_sha"]:
        raise DockerRuntimeError("evaluator tree changed after receipt")


def _seal_toolchain(
    source: Path,
    destination: Path,
    plan: ExecutionPlanV2,
    evaluator_root: Path,
) -> None:
    if is_profile_runner(plan.step["adapter_id"]):
        _seal_profile_toolchain(source, destination, plan, evaluator_root)
        return
    source = source.resolve()
    if not source.is_file():
        raise DockerRuntimeError("Ruff toolchain binary is unavailable")
    expected = plan.runtime["toolchain_sha256"]
    if sha256_file(source) != expected:
        raise DockerRuntimeError("Ruff toolchain digest mismatch")
    destination.mkdir()
    sealed = destination / "ruff"
    shutil.copyfile(source, sealed)
    if sha256_file(sealed) != expected:
        raise DockerRuntimeError("sealed Ruff toolchain digest mismatch")
    if os.name != "nt":
        sealed.chmod(0o555)


def _seal_profile_toolchain(
    source: Path,
    destination: Path,
    plan: ExecutionPlanV2,
    evaluator_root: Path,
) -> None:
    if source.is_symlink():
        raise DockerRuntimeError("standard profile toolchain root is invalid")
    source = source.resolve()
    if not source.is_dir():
        raise DockerRuntimeError("standard profile toolchain root is invalid")
    lock = evaluator_root.resolve() / "requirements-governance.lock"
    if not lock.is_file() or sha256_file(lock) != plan.runtime["toolchain_sha256"]:
        raise DockerRuntimeError("standard profile lock digest mismatch")
    site_packages = _site_packages(source)
    versions = _profile_package_versions(site_packages)
    expected = plan.step["toolchain"]
    if any(versions.get(name) != [version] for name, version in expected.items()):
        raise DockerRuntimeError("standard profile package versions mismatch")
    _verify_installed_evaluator(site_packages, evaluator_root)
    ruff = source / "bin" / "ruff"
    if ruff.is_symlink() or not ruff.is_file() or sha256_file(ruff) != _RUFF_SHA256:
        raise DockerRuntimeError("standard profile Ruff binary mismatch")
    _reject_links(site_packages)
    destination.mkdir()
    shutil.copyfile(ruff, destination / "ruff")
    shutil.copytree(
        site_packages,
        destination / "site-packages",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    _copy_profile_benchmark(evaluator_root, destination / "benchmark")
    if os.name != "nt":
        (destination / "ruff").chmod(0o555)


def _profile_package_versions(site_packages: Path) -> dict[str, list[str]]:
    versions: dict[str, list[str]] = {}
    for distribution in importlib.metadata.distributions(path=[str(site_packages)]):
        name = distribution.metadata["Name"]
        if name:
            normalized = str(name).lower().replace("_", "-")
            versions.setdefault(normalized, []).append(distribution.version)
    return versions


def _copy_profile_benchmark(evaluator_root: Path, benchmark: Path) -> None:
    benchmark.mkdir()
    for name in ("cases", "fixtures", "schemas", "target_packs", "targets"):
        source_path = evaluator_root / name
        _reject_links(source_path)
        shutil.copytree(source_path, benchmark / name)
    for name in ("AGENTS.md", "TASK.md", "requirements-governance.lock"):
        source_path = evaluator_root / name
        if not source_path.is_file() or source_path.is_symlink():
            raise DockerRuntimeError("standard profile benchmark asset is invalid")
        shutil.copyfile(source_path, benchmark / name)


def _site_packages(root: Path) -> Path:
    candidates = [
        *root.glob("lib/python*/site-packages"),
        root / "Lib" / "site-packages",
    ]
    matches = [path for path in candidates if path.is_dir()]
    if len(matches) != 1:
        raise DockerRuntimeError("standard profile site-packages is ambiguous")
    candidate = matches[0]
    current = root
    for part in candidate.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise DockerRuntimeError("standard profile site-packages contains a link")
    return candidate.resolve()


def _verify_installed_evaluator(site_packages: Path, evaluator_root: Path) -> None:
    source = evaluator_root.resolve() / "governance_eval"
    installed = site_packages / "governance_eval"
    if not source.is_dir() or not installed.is_dir():
        raise DockerRuntimeError("installed evaluator package is unavailable")
    _reject_links(source)
    _reject_links(installed)
    expected = {
        path.relative_to(source).as_posix(): sha256_file(path)
        for path in source.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and (path.suffix == ".py" or "schema_data" in path.parts)
        and "__pycache__" not in path.parts
    }
    observed = {
        path.relative_to(installed).as_posix(): sha256_file(path)
        for path in installed.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and (path.suffix == ".py" or "schema_data" in path.parts)
        and "__pycache__" not in path.parts
    }
    if not expected or observed != expected:
        raise DockerRuntimeError("installed evaluator package differs from checkout")


def _reject_links(root: Path) -> None:
    if root.is_symlink() or any(path.is_symlink() for path in root.rglob("*")):
        raise DockerRuntimeError("standard profile toolchain contains a link")


def _profile_payload(
    plan: ExecutionPlanV2,
    outcome: dict[str, Any],
    workspace: Path | None = None,
) -> list[dict[str, Any]] | None:
    if not is_profile_runner(plan.step["adapter_id"]):
        return None
    profile_id = runner_profile(plan.step["adapter_id"])
    expected_adapters = profile_adapters(profile_id)
    payload = _decode_profile_payload(outcome["stdout"], profile_id, workspace)
    if payload is None or set(payload) != {
        "schema_version",
        "profile",
        "status",
        "capabilities",
    }:
        return None
    capabilities = payload["capabilities"]
    if not isinstance(capabilities, list) or len(capabilities) != len(
        expected_adapters
    ):
        return None
    if not all(
        _valid_profile_capability(item, expected)
        for item, expected in zip(capabilities, expected_adapters, strict=True)
    ):
        return None
    expected_status = (
        "PASS"
        if all(item["status"] == "PASS" for item in capabilities)
        else "BLOCK_TECHNICAL"
    )
    if (
        payload["schema_version"] != "1.0"
        or payload["profile"] != profile_id
        or payload["status"] != expected_status
    ):
        return None
    return capabilities


def _decode_profile_payload(
    stream: dict[str, Any],
    profile: str = "python.standard.v1",
    workspace: Path | None = None,
) -> dict[str, Any] | None:
    if stream["truncated"]:
        return None
    try:
        raw = base64.b64decode(stream["captured_base64"], validate=True)
        text = raw.decode("utf-8")
        lines = text.splitlines()
        marker = (
            "__GOVERNANCE_SQLITE_PROFILE_V1__"
            if profile == "python.sqlite.v1"
            else "__GOVERNANCE_STANDARD_PROFILE_V1__"
        )
        if len(lines) != 1 or not lines[0].startswith(marker):
            return None
        payload = json.loads(lines[0].removeprefix(marker))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if profile == "python.sqlite.v1":
        return _load_sqlite_profile(payload, workspace)
    return payload


def _load_sqlite_profile(
    compact: dict[str, Any], workspace: Path | None
) -> dict[str, Any] | None:
    if workspace is None or set(compact) != {
        "schema_version",
        "profile",
        "status",
        "capabilities_path",
        "capabilities_sha256",
    }:
        return None
    if compact.get("capabilities_path") != ".governance-output/sqlite-profile.json":
        return None
    path = workspace / ".governance-output/sqlite-profile.json"
    try:
        raw = _read_regular_file(path, MAX_EVIDENCE_BYTES)
        if raw is None:
            return None
        if sha256(raw).hexdigest() != compact.get("capabilities_sha256"):
            return None
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if any(
        payload.get(key) != compact.get(key)
        for key in ("schema_version", "profile", "status")
    ):
        return None
    return payload


def _read_regular_file(path: Path, limit: int) -> bytes | None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > limit:
            return None
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        closed = os.fstat(descriptor)
        if os.read(descriptor, 1) or _file_identity(closed) != _file_identity(opened):
            return None
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _valid_profile_capability(item: Any, expected: tuple[str, str, str]) -> bool:
    if not isinstance(item, dict) or set(item) != {
        "capability",
        "adapter_id",
        "assurance_class",
        "status",
        "evidence",
    }:
        return False
    capability, adapter_id, assurance = expected
    return (
        item["capability"] == capability
        and item["adapter_id"] == adapter_id
        and item["assurance_class"] == assurance
        and item["status"] in {"PASS", "BLOCK_TECHNICAL"}
        and isinstance(item["evidence"], dict)
    )


def _materialize_tree(
    root: Path, target: dict[str, str], workspace: Path, git: Path
) -> None:
    root = root.resolve()
    if _git(
        root,
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    ):
        raise DockerRuntimeError("target checkout changed after receipt")
    if _git(root, git, "rev-parse", "HEAD") != target["commit_sha"]:
        raise DockerRuntimeError("target commit changed after receipt")
    if _git(root, git, "rev-parse", "HEAD^{tree}") != target["tree_sha"]:
        raise DockerRuntimeError("target tree changed after receipt")
    workspace.mkdir()
    entries = _git_bytes(
        root, git, "ls-tree", "-r", "-z", "--full-tree", target["commit_sha"]
    )
    for entry in entries.split(b"\0"):
        if entry:
            _materialize_entry(root, git, workspace, entry)
    (workspace / ".home").mkdir()
    (workspace / ".tmp").mkdir()
    _make_writable(workspace)


def _materialize_entry(root: Path, git: Path, workspace: Path, entry: bytes) -> None:
    try:
        header, raw_path = entry.split(b"\t", 1)
        mode, object_type, object_id = header.decode("ascii").split(" ")
        path_text = raw_path.decode("utf-8")
        relative = PurePosixPath(path_text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise DockerRuntimeError("target tree entry is malformed") from exc
    if object_type != "blob" or mode not in {"100644", "100755"}:
        raise DockerRuntimeError("target tree contains an unsupported entry")
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or not relative.parts
        or "\\" in path_text
        or any(":" in part for part in relative.parts)
    ):
        raise DockerRuntimeError("target tree path is unsafe")
    destination = workspace.joinpath(*relative.parts).resolve()
    try:
        destination.relative_to(workspace.resolve())
    except ValueError as exc:
        raise DockerRuntimeError("target tree path escapes workspace") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(_git_bytes(root, git, "cat-file", "blob", object_id))
    if mode == "100755" and os.name != "nt":
        destination.chmod(0o755)


def _make_writable(root: Path) -> None:
    if os.name == "nt":
        return
    for path in (root, *root.rglob("*")):
        path.chmod(0o777 if path.is_dir() else 0o666)


def _run_bounded(
    command: list[str],
    *,
    docker: Path,
    docker_host: str,
    container_name: str,
    timeout_seconds: int,
    output_limit: int,
) -> dict[str, Any]:
    command_started = datetime.now(UTC)
    command_started_monotonic = time.monotonic()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_docker_environment(docker),
    )
    output = _BoundedOutput(output_limit)
    threads = output.start(process)
    deadline = command_started_monotonic + timeout_seconds
    termination = _wait_reason(process, output, deadline)
    command_completed = datetime.now(UTC)
    if termination == "TIMED_OUT":
        command_completed = command_started + timedelta(seconds=timeout_seconds)
    if termination != "EXITED":
        _command(
            [str(docker), f"--host={docker_host}", "kill", container_name],
            timeout=10,
            check=False,
            env=_docker_environment(docker),
        )
    exit_code = process.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=5)
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            pipe.close()
    cleanup_errors = _cleanup_errors(docker, docker_host, container_name)
    return {
        "termination": termination,
        "exit_code": exit_code,
        "stdout": output.stream("stdout"),
        "stderr": output.stream("stderr"),
        "started_at": command_started,
        "completed_at": command_completed,
        "errors": cleanup_errors,
    }


def _cleanup_errors(docker: Path, docker_host: str, container_name: str) -> list[str]:
    environment = _docker_environment(docker)
    list_command = [
        str(docker),
        f"--host={docker_host}",
        "container",
        "ls",
        "--all",
        "--quiet",
        "--filter",
        f"name=^/{container_name}$",
    ]
    try:
        cleanup = _command(list_command, timeout=10, check=False, env=environment)
    except (OSError, subprocess.SubprocessError):
        return _remove_after_cleanup_error(
            docker, docker_host, container_name, environment
        )
    if cleanup.returncode != 0:
        return _remove_after_cleanup_error(
            docker, docker_host, container_name, environment
        )
    if not cleanup.stdout.strip():
        return []
    return _remove_after_cleanup_error(docker, docker_host, container_name, environment)


def _remove_after_cleanup_error(
    docker: Path, docker_host: str, container_name: str, environment: dict[str, str]
) -> list[str]:
    errors = ["Docker container cleanup failed"]
    try:
        removed = _command(
            [str(docker), f"--host={docker_host}", "rm", "-f", container_name],
            timeout=10,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        return [*errors, "Docker forced container removal failed"]
    if removed.returncode != 0:
        errors.append("Docker forced container removal failed")
    return errors


def _wait_reason(
    process: subprocess.Popen[bytes], output: _BoundedOutput, deadline: float
) -> str:
    while process.poll() is None:
        if output.exceeded.is_set():
            return "OUTPUT_LIMIT"
        if time.monotonic() >= deadline:
            return "TIMED_OUT"
        time.sleep(0.01)
    return "EXITED"


class _BoundedOutput:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.remaining = limit
        self.data = {"stdout": bytearray(), "stderr": bytearray()}
        self.truncated = {"stdout": False, "stderr": False}
        self.lock = threading.Lock()
        self.exceeded = threading.Event()

    def start(self, process: subprocess.Popen[bytes]) -> list[threading.Thread]:
        threads = [
            threading.Thread(target=self._drain, args=(name, pipe), daemon=True)
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr))
            if pipe is not None
        ]
        for thread in threads:
            thread.start()
        return threads

    def _drain(self, name: str, pipe: Any) -> None:
        while chunk := pipe.read(8192):
            with self.lock:
                keep = min(len(chunk), self.remaining)
                self.data[name].extend(chunk[:keep])
                self.remaining -= keep
                self.truncated[name] |= keep != len(chunk)
                if keep != len(chunk):
                    self.exceeded.set()

    def stream(self, name: str) -> dict[str, Any]:
        content = bytes(self.data[name])
        return {
            "captured_base64": base64.b64encode(content).decode("ascii"),
            "captured_bytes": len(content),
            "sha256": sha256(content).hexdigest(),
            "truncated": self.truncated[name],
        }


def _result(
    plan: ExecutionPlanV2,
    receipt: CheckoutReceipt,
    _docker: Path | None,
    docker_host: str,
    command: list[str],
    started: datetime,
    *,
    outcome: dict[str, Any] | None,
    errors: list[str],
    profile: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    completed = datetime.now(UTC)
    if outcome:
        started = outcome["started_at"]
        completed = outcome["completed_at"]
    empty = _empty_stream()
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "artifact_id": "",
        "plan_id": plan.plan_id,
        "checkout_receipt_id": receipt.receipt_id,
        "capability_status": "PASS"
        if outcome
        and outcome["termination"] == "EXITED"
        and outcome["exit_code"] == 0
        and not errors
        and (
            not is_profile_runner(plan.step["adapter_id"])
            or profile is not None
            and all(item["status"] == "PASS" for item in profile)
        )
        else "BLOCK_TECHNICAL",
        "runtime": {
            "image": plan.runtime["image"],
            "policy_id": plan.runtime["policy_id"],
            "docker_path": plan.runtime["docker_path"],
            "docker_sha256": plan.runtime["docker_sha256"],
            "toolchain": (
                plan.step["adapter_id"]
                if is_profile_runner(plan.step["adapter_id"])
                else "ruff==0.15.21"
            ),
            "toolchain_sha256": plan.runtime["toolchain_sha256"],
            "docker_host": docker_host,
        },
        "command": command,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": completed.isoformat().replace("+00:00", "Z"),
        "duration_seconds": round((completed - started).total_seconds(), 6),
        "timeout_seconds": plan.step["timeout_seconds"],
        "termination": outcome["termination"] if outcome else "NOT_STARTED",
        "exit_code": outcome["exit_code"] if outcome else None,
        "stdout": outcome["stdout"] if outcome else empty,
        "stderr": outcome["stderr"] if outcome else empty,
        "errors": errors,
    }
    if profile is not None:
        payload["capabilities"] = profile
    payload["artifact_id"] = sha256_json({**payload, "artifact_id": ""})
    return payload


def _empty_stream() -> dict[str, Any]:
    return {
        "captured_base64": "",
        "captured_bytes": 0,
        "sha256": sha256(b"").hexdigest(),
        "truncated": False,
    }


def _git(root: Path, executable: Path, *arguments: str) -> str:
    command = [
        str(executable),
        f"--git-dir={root / '.git'}",
        f"--work-tree={root}",
        *arguments,
    ]
    return _command(
        command, timeout=10, env=_git_environment(executable)
    ).stdout.strip()


def _git_bytes(root: Path, executable: Path, *arguments: str) -> bytes:
    command = [
        str(executable),
        f"--git-dir={root / '.git'}",
        f"--work-tree={root}",
        *arguments,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        timeout=10,
        env=_git_environment(executable),
    )
    if completed.returncode != 0:
        raise DockerRuntimeError(f"Git object command failed: {arguments[0]}")
    return completed.stdout


def _command(
    command: list[str],
    *,
    cwd: Path | None = None,
    timeout: int,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise DockerRuntimeError(
            f"command failed: {command[1] if len(command) > 1 else command[0]}: {detail}"
        )
    return completed


def _git_environment(executable: Path) -> dict[str, str]:
    environment = _base_environment(executable)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _docker_environment(executable: Path) -> dict[str, str]:
    return _base_environment(executable)


def _base_environment(executable: Path) -> dict[str, str]:
    environment = {"PATH": str(executable.parent), "LC_ALL": "C"}
    system_root = os.environ.get("SystemRoot")
    if system_root:
        environment["SystemRoot"] = system_root
    return environment
