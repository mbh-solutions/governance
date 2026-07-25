from __future__ import annotations

import argparse
import ast
import base64
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Sequence

from governance_eval.benchmark import BENCHMARK_PASS, run_benchmark
from governance_eval.capability_catalog import profile_adapters
from governance_eval.docker_runtime import _BoundedOutput
from governance_eval.hashing import sha256_file
from governance_eval.package_audit import MAX_ARCHIVE_BYTES, audit_candidate_wheel_bytes
from governance_eval.sqlite_supportability import (
    SQLITE_PROFILE,
    STANDARD_PROFILE,
    SQLiteSupportabilityError,
    discover_wheel_profile,
    packaged_source_snapshot,
    run_sqlite_supportability,
    validate_profile_discovery,
    wheel_source_binding_errors_from_snapshot,
)


PROFILE_MARKER = "__GOVERNANCE_STANDARD_PROFILE_V1__"
SQLITE_PROFILE_MARKER = "__GOVERNANCE_SQLITE_PROFILE_V1__"
OUTPUT_LIMIT = 65536
COMMAND_TIMEOUT = 120
SQLITE_ADAPTER_TIMEOUT = 120
_OUTPUT_DIR = ".governance-output"
_SQLITE_PROFILE_FILE = "sqlite-profile.json"


def run_standard_profile(
    workspace: Path,
    benchmark_root: Path,
    evaluator_sha: str,
    profile: str = STANDARD_PROFILE,
) -> dict[str, Any]:
    root = workspace.resolve(strict=True)
    benchmark = benchmark_root.resolve(strict=True)
    if root.as_posix() != "/workspace":
        raise ValueError("standard profile workspace is not fixed")
    if benchmark.as_posix() != "/opt/governance-toolchain/benchmark":
        raise ValueError("standard profile benchmark root is not fixed")
    if len(evaluator_sha) != 40 or any(
        character not in "0123456789abcdef" for character in evaluator_sha
    ):
        raise ValueError("standard profile evaluator SHA is invalid")
    if profile not in {STANDARD_PROFILE, SQLITE_PROFILE}:
        raise ValueError("Python Governance profile is unsupported")
    initial = _source_snapshot(root)
    package_sources: dict[str, bytes] | None = None
    package_source_errors: list[str] = []
    if profile == SQLITE_PROFILE:
        try:
            package_sources = packaged_source_snapshot(root)
        except (OSError, SQLiteSupportabilityError, UnicodeError, ValueError) as exc:
            package_source_errors.append(str(exc))
    python_files = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if _tracked_source(path, root)
    )
    output = root / _OUTPUT_DIR
    output.mkdir()
    build_source = output / "build-source"
    _stage_build_source(root, build_source, initial)
    commands = _fixed_commands(root, build_source, python_files, output)
    results = [_run_capability(root, *item) for item in commands[:4]]
    results.append(_architecture_result(root, python_files))
    results.append(_run_capability(root, *commands[4]))
    results.append(_run_capability(root, *commands[5]))
    wheel = _wheel_snapshot(output, results[-1])
    package_result = _package_result(root, wheel, results[-1])
    if wheel is not None and package_result["status"] == "PASS":
        _apply_wheel_closure(
            profile,
            wheel[1],
            package_result,
            package_sources,
            package_source_errors,
        )
    results.append(package_result)
    results.append(_benchmark_result(benchmark, output, evaluator_sha))
    results.append(_integrity_result(root, initial))
    if profile == SQLITE_PROFILE:
        results.append(
            _run_sqlite_bounded(
                wheel[0] if wheel else None,
                wheel[1] if wheel and package_result["status"] == "PASS" else None,
            )
        )
    expected = [item[0] for item in profile_adapters(profile)]
    if [item["capability"] for item in results] != expected:
        raise ValueError("standard profile capability order is invalid")
    status = (
        "PASS"
        if all(item["status"] == "PASS" for item in results)
        else "BLOCK_TECHNICAL"
    )
    _release_workspace_directories(root)
    return {
        "schema_version": "1.0",
        "profile": profile,
        "status": status,
        "capabilities": results,
    }


def _release_workspace_directories(root: Path, owner: int | None = None) -> None:
    if owner is None:
        getuid = getattr(os, "getuid", None)
        if not callable(getuid):
            raise RuntimeError("standard profile requires POSIX ownership")
        owner = int(getuid())
    for current, directories, _files in os.walk(root, topdown=True):
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink() and path.stat().st_uid == owner:
                path.chmod(0o777)


def _fixed_commands(
    root: Path, build_source: Path, python_files: list[str], output: Path
) -> list[tuple[str, str, str, list[str]]]:
    ruff = "/opt/governance-toolchain/ruff"
    python = sys.executable
    return [
        (
            "lint",
            "python.ruff-check.v1",
            "EVALUATOR_AUTHORITATIVE",
            [ruff, "check", "--isolated", "--no-cache", "--no-respect-gitignore", "."],
        ),
        (
            "format",
            "python.ruff-format-check.v1",
            "EVALUATOR_AUTHORITATIVE",
            [
                ruff,
                "format",
                "--check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                ".",
            ],
        ),
        (
            "typecheck",
            "python.mypy.v1",
            "EVALUATOR_AUTHORITATIVE",
            [
                python,
                "-P",
                "-s",
                "-m",
                "mypy",
                "--config-file=/dev/null",
                "--strict",
                "--no-incremental",
                "--cache-dir=/dev/null",
                *python_files,
            ],
        ),
        (
            "complexity",
            "python.ruff-c901.v1",
            "EVALUATOR_AUTHORITATIVE",
            [
                ruff,
                "check",
                "--isolated",
                "--no-cache",
                "--no-respect-gitignore",
                "--select",
                "C901",
                "--config",
                "lint.mccabe.max-complexity=10",
                ".",
            ],
        ),
        (
            "tests",
            "python.unittest.v1",
            "COOPERATIVE_DYNAMIC",
            [
                python,
                "-P",
                "-s",
                "-m",
                "governance_eval.unittest_runner",
                "--workspace",
                str(root),
            ],
        ),
        (
            "build",
            "python.wheel-build.v1",
            "CONTAINED_BUILD",
            [
                python,
                "-P",
                "-s",
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-index",
                "--no-build-isolation",
                str(build_source),
                "-w",
                str(output / "wheel"),
            ],
        ),
    ]


def _run_capability(
    root: Path,
    capability: str,
    adapter_id: str,
    assurance_class: str,
    command: list[str],
) -> dict[str, Any]:
    outcome = _bounded_command(command, root)
    status = (
        "PASS"
        if outcome["termination"] == "EXITED" and outcome["exit_code"] == 0
        else "BLOCK_TECHNICAL"
    )
    return {
        "capability": capability,
        "adapter_id": adapter_id,
        "assurance_class": assurance_class,
        "status": status,
        "evidence": outcome,
    }


def _architecture_result(root: Path, python_files: list[str]) -> dict[str, Any]:
    started = _now()
    errors = _import_cycle_errors(root, python_files)
    return {
        "capability": "architecture",
        "adapter_id": "python.architecture.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not errors else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "errors": errors,
            "files_scanned": len(python_files),
        },
    }


def _wheel_snapshot(
    output: Path, build_result: dict[str, Any]
) -> tuple[str, bytes] | None:
    wheels = sorted((output / "wheel").glob("*.whl"))
    if build_result["status"] != "PASS" or len(wheels) != 1:
        return None
    try:
        descriptor = os.open(wheels[0], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE_BYTES:
                return None
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    return None
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if os.read(descriptor, 1) or (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_ino,
            ) != (
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                info.st_ino,
            ):
                return None
        finally:
            os.close(descriptor)
    except OSError:
        return None
    return wheels[0].name, raw


def _package_result(
    root: Path,
    wheel: tuple[str, bytes] | None,
    build_result: dict[str, Any],
) -> dict[str, Any]:
    started = _now()
    errors: list[str] = []
    evidence: dict[str, Any] | None = None
    if build_result["status"] != "PASS" or wheel is None:
        errors.append("contained build did not produce exactly one wheel")
    else:
        evidence, wheel_errors = audit_candidate_wheel_bytes(root, *wheel)
        errors.extend(wheel_errors)
    return {
        "capability": "package_audit",
        "adapter_id": "python.package-audit.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not errors else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "wheel_sha256": sha256(wheel[1]).hexdigest() if wheel else None,
            "audit": evidence,
            "errors": errors,
        },
    }


def _apply_wheel_closure(
    profile: str,
    wheel_bytes: bytes,
    package_result: dict[str, Any],
    package_sources: dict[str, bytes] | None,
    source_errors: list[str],
) -> None:
    errors = package_result["evidence"]["errors"]
    discovery = discover_wheel_profile(wheel_bytes)
    try:
        validate_profile_discovery(discovery, selected_profile=profile)
    except ValueError as exc:
        errors.append(str(exc))
    if profile == SQLITE_PROFILE:
        errors.extend(source_errors)
        if not source_errors:
            errors.extend(
                wheel_source_binding_errors_from_snapshot(
                    package_sources or {}, wheel_bytes
                )
            )
    if errors:
        package_result["status"] = "BLOCK_TECHNICAL"


def _run_sqlite_bounded(
    wheel_name: str | None, wheel_bytes: bytes | None
) -> dict[str, Any]:
    if wheel_name is None or wheel_bytes is None:
        return run_sqlite_supportability(None)

    def timed_out(_signum: int, _frame: Any) -> None:
        raise TimeoutError("SQLite adapter timed out after 120 seconds")

    sigalrm = getattr(signal, "SIGALRM", None)
    alarm = getattr(signal, "alarm", None)
    if sigalrm is None or alarm is None:
        result = run_sqlite_supportability(None)
        result["evidence"]["errors"] = ["SQLite adapter hard timeout is unavailable"]
        return result
    previous = signal.signal(sigalrm, timed_out)
    alarm(SQLITE_ADAPTER_TIMEOUT)
    try:
        return run_sqlite_supportability(Path(wheel_name), wheel_bytes=wheel_bytes)
    except TimeoutError as exc:
        result = run_sqlite_supportability(None)
        result["evidence"]["errors"] = [str(exc)]
        return result
    finally:
        alarm(0)
        signal.signal(sigalrm, previous)


def _benchmark_result(
    benchmark_root: Path, output: Path, evaluator_sha: str
) -> dict[str, Any]:
    started = _now()
    errors: list[str] = []
    try:
        result = run_benchmark(
            benchmark_root,
            repeat=1,
            artifacts_dir=output / "phase1",
            evaluator_git_sha=evaluator_sha,
        )
        if result["phase1_decision"] != BENCHMARK_PASS:
            errors.extend(result["acceptance_errors"])
        digest = sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    except (OSError, KeyError, TypeError, ValueError) as exc:
        errors.append(str(exc))
        digest = None
    return {
        "capability": "benchmark",
        "adapter_id": "governance.phase1.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not errors else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "result_sha256": digest,
            "errors": errors,
        },
    }


def _integrity_result(root: Path, initial: dict[str, str]) -> dict[str, Any]:
    started = _now()
    current = _source_snapshot(root)
    changed = sorted(
        path
        for path in set(initial) | set(current)
        if current.get(path) != initial.get(path)
    )
    return {
        "capability": "integrity",
        "adapter_id": "git.diff-integrity.v1",
        "assurance_class": "EVALUATOR_AUTHORITATIVE",
        "status": "PASS" if not changed else "BLOCK_TECHNICAL",
        "evidence": {
            "started_at": started,
            "completed_at": _now(),
            "changed_files": changed,
            "tracked_files": len(initial),
        },
    }


def _bounded_command(command: list[str], cwd: Path) -> dict[str, Any]:
    started = datetime.now(UTC)
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_environment(),
        start_new_session=True,
    )
    output = _BoundedOutput(OUTPUT_LIMIT)
    threads = output.start(process)
    deadline = time.monotonic() + COMMAND_TIMEOUT
    termination = "EXITED"
    while process.poll() is None:
        if output.exceeded.is_set():
            termination = "OUTPUT_LIMIT"
            break
        if time.monotonic() >= deadline:
            termination = "TIMED_OUT"
            break
        time.sleep(0.01)
    if termination != "EXITED":
        _kill_process_group(process)
    exit_code = process.wait(timeout=10)
    _kill_process_group(process)
    for thread in threads:
        thread.join(timeout=5)
    completed = datetime.now(UTC)
    stdout = output.stream("stdout")
    stderr = output.stream("stderr")
    return {
        "argv": command,
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "completed_at": completed.isoformat().replace("+00:00", "Z"),
        "timeout_seconds": COMMAND_TIMEOUT,
        "termination": termination,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "summary": _summary(stdout, stderr),
    }


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    kill_group = getattr(os, "killpg", None)
    kill_signal = getattr(signal, "SIGKILL", signal.SIGTERM)
    try:
        if callable(kill_group):
            kill_group(process.pid, kill_signal)
        elif process.poll() is None:  # pragma: no cover - profile runtime is Linux
            process.kill()
    except ProcessLookupError:
        pass


def _environment() -> dict[str, str]:
    return {
        "HOME": "/workspace/.home",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": "/opt/governance-toolchain/site-packages",
        "PYTHONSAFEPATH": "1",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "TMPDIR": "/workspace/.tmp",
    }


def _summary(stdout: dict[str, Any], stderr: dict[str, Any]) -> str:
    raw = base64.b64decode(stdout["captured_base64"]) + base64.b64decode(
        stderr["captured_base64"]
    )
    return raw.decode("utf-8", errors="replace")[-2000:]


def _source_snapshot(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in root.rglob("*"):
        if not _tracked_source(path, root):
            continue
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = "SYMLINK"
        elif path.is_file():
            result[name] = sha256_file(path)
        elif not path.is_dir():
            result[name] = "SPECIAL"
    return result


def _stage_build_source(
    root: Path, destination: Path, snapshot: dict[str, str]
) -> None:
    destination.mkdir()
    for name in sorted(snapshot):
        source = root / name
        if snapshot[name] in {"SYMLINK", "SPECIAL"} or not source.is_file():
            raise ValueError(f"unsupported candidate source entry: {name}")
        target = destination.joinpath(*Path(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _tracked_source(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return relative.parts[0] not in {".home", ".tmp", _OUTPUT_DIR}


def _import_cycle_errors(root: Path, python_files: list[str]) -> list[str]:
    modules = {_module_name(path): path for path in python_files}
    graph: dict[str, set[str]] = {module: set() for module in modules}
    errors: list[str] = []
    for module, path in modules.items():
        try:
            tree = ast.parse((root / path).read_text(encoding="utf-8"), filename=path)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            errors.append(f"{path}: {exc}")
            continue
        for imported in _imports(tree, module):
            if imported in modules and imported != module:
                graph[module].add(imported)
    cycles = _cycles(graph)
    return [*errors, *("import cycle: " + " -> ".join(cycle) for cycle in cycles)]


def _module_name(path: str) -> str:
    value = path.removesuffix(".py").replace("/", ".")
    return value.removesuffix(".__init__")


def _imports(tree: ast.AST, module: str) -> set[str]:
    values: set[str] = set()
    package = module.rsplit(".", 1)[0] if "." in module else ""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = package.split(".")
            if node.level:
                prefix = prefix[: max(0, len(prefix) - node.level + 1)]
            base = ".".join((*prefix, node.module or "")).strip(".")
            values.add(base)
            values.update(
                ".".join((base, alias.name)).strip(".") for alias in node.names
            )
    return values


def _cycles(graph: dict[str, set[str]]) -> list[tuple[str, ...]]:
    found: set[tuple[str, ...]] = set()
    for start in sorted(graph):
        _walk_cycles(graph, start, start, [], set(), found)
    return sorted(found)


def _walk_cycles(
    graph: dict[str, set[str]],
    start: str,
    node: str,
    path: list[str],
    active: set[str],
    found: set[tuple[str, ...]],
) -> None:
    if node in active:
        if node == start:
            cycle = tuple(path[path.index(node) :])
            rotations = [cycle[index:] + cycle[:index] for index in range(len(cycle))]
            found.add(min(rotations))
        return
    active.add(node)
    path.append(node)
    for target in sorted(graph.get(node, ())):
        _walk_cycles(graph, start, target, path, active, found)
    path.pop()
    active.remove(node)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the fixed Python Governance profile"
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--benchmark-root", required=True, type=Path)
    parser.add_argument("--evaluator-sha", required=True)
    parser.add_argument(
        "--profile",
        choices=(STANDARD_PROFILE, SQLITE_PROFILE),
        default=STANDARD_PROFILE,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    result = run_standard_profile(
        arguments.workspace,
        arguments.benchmark_root,
        arguments.evaluator_sha,
        arguments.profile,
    )
    if arguments.profile == SQLITE_PROFILE:
        print(
            SQLITE_PROFILE_MARKER + _write_sqlite_profile(arguments.workspace, result)
        )
    else:
        print(
            PROFILE_MARKER + json.dumps(result, sort_keys=True, separators=(",", ":"))
        )
    return 0 if result["status"] == "PASS" else 1


def _write_sqlite_profile(workspace: Path, result: dict[str, Any]) -> str:
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    destination = workspace / _OUTPUT_DIR / _SQLITE_PROFILE_FILE
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        fchmod = getattr(os, "fchmod", None)
        if not callable(fchmod):
            raise RuntimeError("SQLite profile sidecar requires POSIX permissions")
        fchmod(stream.fileno(), 0o644)
    compact = {
        "schema_version": "1.0",
        "profile": SQLITE_PROFILE,
        "status": result["status"],
        "capabilities_path": f"{_OUTPUT_DIR}/{_SQLITE_PROFILE_FILE}",
        "capabilities_sha256": sha256(raw).hexdigest(),
    }
    return json.dumps(compact, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    raise SystemExit(main())
