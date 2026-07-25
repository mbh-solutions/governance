from __future__ import annotations

import base64
import configparser
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import re
import shutil
import stat
import tempfile
import tomllib
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from governance_eval.docker_runtime import (
    DockerRuntimeError,
    _run_bounded,
    _trusted_docker,
    _verify_image,
)
from governance_eval.execution_plan_v2 import _IMAGE
from governance_eval.hashing import sha256_file

SCHEMA_VERSION = "governance_package_audit.v1"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 5_000
MAX_MEMBER_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_METADATA_BYTES = 1024 * 1024
MAX_BUILD_OUTPUT_BYTES = 45 * 1024 * 1024
BUILD_TIMEOUT_SECONDS = 120
_WHEEL_MARKER = b"__GOVERNANCE_WHEEL_V1__"
_BUILD_SCRIPT = f"""
import base64
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys

source = pathlib.Path('/workspace/source')
shutil.copytree('/candidate', source)
for name in ('.home', '.tmp', 'dist'):
    (pathlib.Path('/workspace') / name).mkdir()
completed = subprocess.run([
    sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-index',
    '--no-build-isolation', '.', '-w', '/workspace/dist'
], cwd=source)
if completed.returncode:
    raise SystemExit(completed.returncode)
wheels = sorted(pathlib.Path('/workspace/dist').glob('*.whl'))
if len(wheels) != 1:
    raise SystemExit('contained build must produce exactly one wheel')
wheel = wheels[0]
descriptor = os.open(wheel, os.O_RDONLY | os.O_NOFOLLOW)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit('contained wheel output must be a regular file')
    if info.st_size > {MAX_ARCHIVE_BYTES}:
        raise SystemExit('contained wheel exceeds archive size limit')
    chunks = []
    remaining = info.st_size
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            raise SystemExit('contained wheel output is truncated')
        chunks.append(chunk)
        remaining -= len(chunk)
finally:
    os.close(descriptor)
payload = {{
    'name': wheel.name,
    'content_base64': base64.b64encode(b''.join(chunks)).decode('ascii'),
}}
print({_WHEEL_MARKER.decode("ascii")!r} + json.dumps(payload, separators=(',', ':')))
""".strip()
_COPY_EXCLUDED = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
}


class _EntryPointParser(configparser.ConfigParser):
    def optionxform(self, optionstr: str) -> str:
        return optionstr


def run_package_audit(
    repo_root: Path,
    artifacts_dir: Path,
    *,
    build_timeout_seconds: int = BUILD_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    root = repo_root.resolve()
    output = artifacts_dir.resolve()
    errors = _preflight_errors(root, output)
    if errors:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "FAIL",
            "repo_root": str(root),
            "build": _empty_build(build_timeout_seconds),
            "wheel": None,
            "errors": errors,
        }
    output.mkdir(parents=True, exist_ok=True)
    wheel_dir = output / "wheel"
    wheel_dir.mkdir(exist_ok=True)
    build = _empty_build(build_timeout_seconds)
    if not errors:
        try:
            build = _run_contained_build(root, wheel_dir, build_timeout_seconds)
        except (DockerRuntimeError, OSError, ValueError) as exc:
            errors.append(f"contained wheel build failed: {exc}")
    if build["termination"] == "TIMED_OUT":
        errors.append("contained wheel build timed out")
    elif build["termination"] == "OUTPUT_LIMIT":
        errors.append("contained wheel build exceeded output limit")
    elif build["exit_code"] not in (None, 0):
        errors.append(f"contained wheel build exited {build['exit_code']}")
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        errors.append(f"expected exactly one wheel, found {len(wheels)}")
    wheel_evidence: dict[str, Any] | None = None
    if len(wheels) == 1:
        wheel_evidence, wheel_errors = audit_wheel(root, wheels[0])
        errors.extend(wheel_errors)
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "PASS" if not errors else "FAIL",
        "repo_root": str(root),
        "build": build,
        "wheel": wheel_evidence,
        "errors": errors,
    }
    audit_path = output / "package-audit.json"
    audit_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest_lines = [f"{sha256_file(audit_path)}  {audit_path.name}"]
    if len(wheels) == 1:
        manifest_lines.append(f"{sha256_file(wheels[0])}  wheel/{wheels[0].name}")
    (output / "checksums.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="ascii"
    )
    return result


def _run_contained_build(
    root: Path, wheel_dir: Path, timeout_seconds: int
) -> dict[str, Any]:
    docker, docker_host, docker_sha256 = _docker_identity()
    _verify_image(docker, docker_host, _IMAGE)
    with tempfile.TemporaryDirectory(prefix="governance-package-build-") as directory:
        runtime_root = Path(directory).resolve()
        source = runtime_root / "source"
        toolchain = runtime_root / "toolchain"
        _stage_source(root, source)
        toolchain_sha256, setuptools_version = _stage_build_toolchain(toolchain)
        container_name = f"governance-package-{uuid.uuid4().hex[:16]}"
        command = _contained_build_argv(
            docker,
            docker_host,
            source,
            toolchain,
            container_name,
            timeout_seconds,
        )
        outcome = _run_bounded(
            command,
            docker=docker,
            docker_host=docker_host,
            container_name=container_name,
            timeout_seconds=timeout_seconds,
            output_limit=MAX_BUILD_OUTPUT_BYTES,
        )
        if outcome["errors"]:
            raise DockerRuntimeError("; ".join(outcome["errors"]))
        if outcome["termination"] == "EXITED" and outcome["exit_code"] == 0:
            name, content = _extract_contained_wheel(outcome["stdout"])
            (wheel_dir / name).write_bytes(content)
        return {
            "command": command,
            "image": _IMAGE,
            "docker_path": str(docker),
            "docker_host": docker_host,
            "docker_sha256": docker_sha256,
            "toolchain_sha256": toolchain_sha256,
            "setuptools_version": setuptools_version,
            "started_at": _format_time(outcome["started_at"]),
            "completed_at": _format_time(outcome["completed_at"]),
            "timeout_seconds": timeout_seconds,
            "output_limit_bytes": MAX_BUILD_OUTPUT_BYTES,
            "termination": outcome["termination"],
            "timed_out": outcome["termination"] == "TIMED_OUT",
            "exit_code": outcome["exit_code"],
            "stdout": outcome["stdout"],
            "stderr": outcome["stderr"],
        }


def _contained_build_argv(
    docker: Path,
    docker_host: str,
    source: Path,
    toolchain: Path,
    container_name: str,
    timeout_seconds: int,
) -> list[str]:
    return [
        str(docker),
        f"--host={docker_host}",
        "run",
        "--rm",
        f"--name={container_name}",
        "--read-only",
        "--network=none",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=128",
        "--memory=536870912",
        "--cpus=1.0",
        f"--ulimit=cpu={timeout_seconds}:{timeout_seconds}",
        "--tmpfs=/workspace:rw,nosuid,nodev,size=67108864,mode=1777",
        "--env=HOME=/workspace/.home",
        "--env=TMPDIR=/workspace/.tmp",
        "--env=PYTHONNOUSERSITE=1",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONPATH=/opt/governance-build-toolchain",
        "--workdir=/workspace",
        "--mount",
        f"type=bind,src={source},dst=/candidate,readonly",
        "--mount",
        f"type=bind,src={toolchain},dst=/opt/governance-build-toolchain,readonly",
        _IMAGE,
        "python",
        "-c",
        _BUILD_SCRIPT,
    ]


def _extract_contained_wheel(stream: dict[str, Any]) -> tuple[str, bytes]:
    captured = base64.b64decode(stream["captured_base64"], validate=True)
    payloads = [
        line.removeprefix(_WHEEL_MARKER)
        for line in captured.splitlines()
        if line.startswith(_WHEEL_MARKER)
    ]
    if len(payloads) != 1:
        raise DockerRuntimeError("contained wheel payload is missing or ambiguous")
    try:
        payload = json.loads(payloads[0])
        name = payload["name"]
        content = base64.b64decode(payload["content_base64"], validate=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DockerRuntimeError("contained wheel payload is malformed") from exc
    if (
        not isinstance(name, str)
        or Path(name).name != name
        or not name.endswith(".whl")
    ):
        raise DockerRuntimeError("contained wheel name is invalid")
    if len(content) > MAX_ARCHIVE_BYTES:
        raise DockerRuntimeError("contained wheel exceeds archive size limit")
    return name, content


def _docker_identity() -> tuple[Path, str, str]:
    configured = os.environ.get("GOVERNANCE_TRUSTED_DOCKER_PATH")
    discovered = configured or shutil.which("docker")
    if discovered is None:
        raise DockerRuntimeError("trusted Docker CLI is unavailable")
    path = Path(discovered).resolve()
    digest = os.environ.get("GOVERNANCE_TRUSTED_DOCKER_SHA256") or sha256_file(path)
    host = os.environ.get("GOVERNANCE_TRUSTED_DOCKER_HOST") or (
        "npipe:////./pipe/docker_engine"
        if os.name == "nt"
        else "unix:///var/run/docker.sock"
    )
    return _trusted_docker(path, digest, host), host, digest


def _stage_source(root: Path, workspace: Path) -> None:
    workspace.mkdir()
    for source in _build_inputs(root):
        _copy_build_input(root, workspace, source)


def _build_inputs(root: Path) -> list[Path]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    inputs = {root / "pyproject.toml", root / "governance_eval"}
    for name in ("setup.py", "setup.cfg", "MANIFEST.in"):
        if (root / name).is_file():
            inputs.add(root / name)
    build = project.get("build-system", {})
    backend = str(build.get("build-backend", "")).partition(":")[0]
    top_level = backend.partition(".")[0]
    for value in build.get("backend-path", []):
        relative = PurePosixPath(str(value))
        if relative.is_absolute() or ".." in relative.parts:
            raise DockerRuntimeError("candidate backend path is unsafe")
        backend_root = root.joinpath(*relative.parts)
        for candidate in (backend_root / top_level, backend_root / f"{top_level}.py"):
            if candidate.exists():
                inputs.add(candidate)
    return sorted(inputs)


def _copy_build_input(root: Path, workspace: Path, build_input: Path) -> None:
    if build_input.is_symlink():
        relative = build_input.relative_to(root)
        raise DockerRuntimeError(f"candidate source symlink forbidden: {relative}")
    sources = [build_input] if build_input.is_file() else sorted(build_input.rglob("*"))
    for source in sources:
        if source.is_dir():
            continue
        relative = source.relative_to(root)
        if any(_excluded(part) for part in relative.parts):
            continue
        if source.is_symlink():
            raise DockerRuntimeError(f"candidate source symlink forbidden: {relative}")
        if source.is_dir():
            continue
        if not source.is_file():
            raise DockerRuntimeError(f"candidate source form unsupported: {relative}")
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def _excluded(part: str) -> bool:
    return part in _COPY_EXCLUDED or part.endswith(".egg-info") or part.endswith(".pyc")


def _stage_build_toolchain(destination: Path) -> tuple[str, str]:
    distribution = importlib.metadata.distribution("setuptools")
    destination.mkdir()
    copied: list[tuple[str, str]] = []
    for relative in distribution.files or ():
        path = PurePosixPath(str(relative).replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or path.suffix == ".pyc":
            continue
        source = Path(str(distribution.locate_file(relative))).resolve()
        if not source.is_file():
            continue
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied.append((path.as_posix(), sha256_file(target)))
    if not copied:
        raise DockerRuntimeError("setuptools build toolchain is unavailable")
    manifest = "".join(f"{digest}  {path}\n" for path, digest in sorted(copied))
    return hashlib.sha256(manifest.encode("utf-8")).hexdigest(), distribution.version


def audit_wheel(repo_root: Path, wheel_path: Path) -> tuple[dict[str, Any], list[str]]:
    expected = _expected_package_files(repo_root)
    evidence = _empty_wheel_evidence(wheel_path, expected)
    if not wheel_path.is_file():
        return evidence, ["wheel archive missing"]
    if wheel_path.stat().st_size > MAX_ARCHIVE_BYTES:
        return evidence, [f"wheel archive size exceeds {MAX_ARCHIVE_BYTES}"]
    try:
        project = tomllib.loads(
            (repo_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        with zipfile.ZipFile(wheel_path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            evidence.update(
                {
                    "member_count": len(names),
                    "uncompressed_bytes": sum(item.file_size for item in infos),
                    "members": sorted(names),
                }
            )
            errors = _structural_errors(infos, expected)
            if errors:
                return evidence, errors
            by_name = {item.filename: item for item in infos}
            metadata_name = _required_suffix(names, ".dist-info/METADATA")
            entry_name = _required_suffix(names, ".dist-info/entry_points.txt")
            record_name = _required_suffix(names, ".dist-info/RECORD")
            errors.extend(
                _metadata_errors(
                    _read_member_bytes(archive, by_name[metadata_name]), project
                )
            )
            errors.extend(
                _entry_point_errors(
                    _read_member_bytes(archive, by_name[entry_name]).decode("utf-8"),
                    project,
                )
            )
            errors.extend(_record_errors(archive, by_name, record_name))
            return evidence, errors
    except (KeyError, OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        return evidence, [f"wheel archive malformed: {type(exc).__name__}"]


def audit_candidate_wheel(
    repo_root: Path, wheel_path: Path
) -> tuple[dict[str, Any], list[str]]:
    if not wheel_path.is_file() or wheel_path.is_symlink():
        return _candidate_evidence(wheel_path.name, None), [
            "wheel archive missing or linked"
        ]
    try:
        raw = wheel_path.read_bytes()
    except OSError:
        return _candidate_evidence(wheel_path.name, None), ["wheel archive unreadable"]
    return audit_candidate_wheel_bytes(repo_root, wheel_path.name, raw)


def audit_candidate_wheel_bytes(
    repo_root: Path, wheel_name: str, raw: bytes
) -> tuple[dict[str, Any], list[str]]:
    evidence = _candidate_evidence(wheel_name, hashlib.sha256(raw).hexdigest())
    if len(raw) > MAX_ARCHIVE_BYTES:
        return evidence, [f"wheel archive size exceeds {MAX_ARCHIVE_BYTES}"]
    try:
        project = tomllib.loads(
            (repo_root / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return _audit_candidate_archive(archive, project, evidence)
    except (KeyError, OSError, UnicodeError, ValueError, zipfile.BadZipFile) as exc:
        return evidence, [f"wheel archive malformed: {type(exc).__name__}"]


def _candidate_evidence(name: str, digest: str | None) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "name": name,
        "sha256": digest,
        "member_count": 0,
        "uncompressed_bytes": 0,
        "members": [],
        "metadata": None,
    }
    return evidence


def _audit_candidate_archive(
    archive: zipfile.ZipFile, project: dict[str, Any], evidence: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    infos = archive.infolist()
    names = [item.filename for item in infos]
    evidence.update(
        {
            "member_count": len(names),
            "uncompressed_bytes": sum(item.file_size for item in infos),
            "members": sorted(names),
        }
    )
    errors = _archive_errors(infos)
    if len(names) != len(set(name.casefold() for name in names)):
        errors.append("wheel contains case-insensitive duplicate members")
    suffix_errors: list[str] = []
    metadata_name = _one_suffix(names, ".dist-info/METADATA", suffix_errors)
    wheel_name = _one_suffix(names, ".dist-info/WHEEL", suffix_errors)
    record_name = _one_suffix(names, ".dist-info/RECORD", suffix_errors)
    entry_names = [
        name for name in names if name.endswith(".dist-info/entry_points.txt")
    ]
    if len(entry_names) > 1:
        suffix_errors.append(
            f"expected at most one .dist-info/entry_points.txt, found {len(entry_names)}"
        )
    errors.extend(suffix_errors)
    if errors or not metadata_name or not wheel_name or not record_name:
        return evidence, errors
    by_name = {item.filename: item for item in infos}
    metadata_bytes = _read_member_bytes(archive, by_name[metadata_name])
    metadata = BytesParser().parsebytes(metadata_bytes)
    observed_name = str(metadata.get("Name") or "")
    observed_version = str(metadata.get("Version") or "")
    evidence["metadata"] = {"name": observed_name, "version": observed_version}
    if _normalized_project_name(observed_name) != _normalized_project_name(
        str(project["name"])
    ):
        errors.append("wheel metadata project name mismatch")
    if observed_version != str(project["version"]):
        errors.append("wheel metadata version mismatch")
    errors.extend(_record_errors(archive, by_name, record_name))
    expected_scripts = project.get("scripts", {})
    if expected_scripts and not entry_names:
        errors.append("wheel console entry points are missing")
    elif entry_names:
        entry_text = _read_member_bytes(archive, by_name[entry_names[0]]).decode(
            "utf-8"
        )
        errors.extend(_candidate_entry_point_errors(entry_text, project))
    return evidence, errors


def _normalized_project_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _candidate_entry_point_errors(text: str, project: dict[str, Any]) -> list[str]:
    parser = _EntryPointParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.Error:
        return ["wheel entry points are malformed"]
    expected = project.get("scripts", {})
    observed = (
        dict(parser.items("console_scripts"))
        if parser.has_section("console_scripts")
        else {}
    )
    return [] if observed == expected else ["wheel console entry points mismatch"]


def _empty_wheel_evidence(wheel_path: Path, expected: set[str]) -> dict[str, Any]:
    return {
        "name": wheel_path.name,
        "sha256": sha256_file(wheel_path) if wheel_path.is_file() else None,
        "member_count": 0,
        "uncompressed_bytes": 0,
        "expected_package_files": sorted(expected),
        "members": [],
    }


def _structural_errors(infos: list[zipfile.ZipInfo], expected: set[str]) -> list[str]:
    errors = _archive_errors(infos)
    names = [item.filename for item in infos]
    package_names = {name for name in names if name.startswith("governance_eval/")}
    missing = sorted(expected - package_names)
    unexpected = sorted(package_names - expected)
    if missing:
        errors.append("missing package files: " + ", ".join(missing))
    if unexpected:
        errors.append("unexpected package files: " + ", ".join(unexpected))
    suffix_errors: list[str] = []
    metadata_name = _one_suffix(names, ".dist-info/METADATA", suffix_errors)
    _one_suffix(names, ".dist-info/entry_points.txt", suffix_errors)
    _one_suffix(names, ".dist-info/RECORD", suffix_errors)
    errors.extend(suffix_errors)
    if metadata_name:
        dist_info = metadata_name.removesuffix("METADATA")
        allowed = expected | {
            dist_info + name
            for name in (
                "METADATA",
                "RECORD",
                "WHEEL",
                "entry_points.txt",
                "top_level.txt",
            )
        }
        outside_allowlist = sorted(set(names) - allowed)
        if outside_allowlist:
            errors.append("unexpected wheel members: " + ", ".join(outside_allowlist))
    return errors


def _preflight_errors(root: Path, output: Path) -> list[str]:
    errors = []
    if not (root / "pyproject.toml").is_file():
        errors.append("pyproject.toml missing")
    if not (root / "governance_eval").is_dir():
        errors.append("governance_eval package missing")
    if output == root or root in output.parents:
        errors.append("artifacts directory must be outside repository")
    if any(output.glob("wheel/*.whl")):
        errors.append("artifacts wheel directory must not contain an existing wheel")
    return errors


def _expected_package_files(root: Path) -> set[str]:
    package = root / "governance_eval"
    return {
        path.relative_to(root).as_posix()
        for path in package.rglob("*")
        if path.is_file()
        and (path.suffix == ".py" or "schema_data" in path.parts)
        and "__pycache__" not in path.parts
    }


def _archive_errors(infos: list[zipfile.ZipInfo]) -> list[str]:
    errors: list[str] = []
    names = [item.filename for item in infos]
    if len(names) > MAX_MEMBERS:
        errors.append(f"wheel member count exceeds {MAX_MEMBERS}")
    if sum(item.file_size for item in infos) > MAX_UNCOMPRESSED_BYTES:
        errors.append(f"wheel uncompressed size exceeds {MAX_UNCOMPRESSED_BYTES}")
    if len(names) != len(set(names)):
        errors.append("wheel contains duplicate members")
    for item in infos:
        errors.extend(_member_structure_errors(item))
    return errors


def _member_structure_errors(item: zipfile.ZipInfo) -> list[str]:
    errors: list[str] = []
    path = PurePosixPath(item.filename)
    if (
        not item.filename
        or "\\" in item.filename
        or path.is_absolute()
        or ".." in path.parts
        or item.is_dir()
    ):
        errors.append(f"unsafe wheel member: {item.filename}")
    mode = item.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if stat.S_ISLNK(mode) or kind not in {0, stat.S_IFREG}:
        errors.append(f"wheel member form unsupported: {item.filename}")
    if item.flag_bits & 1 or item.compress_type not in {
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
    }:
        errors.append(f"wheel member encoding unsupported: {item.filename}")
    if item.file_size > MAX_MEMBER_UNCOMPRESSED_BYTES:
        errors.append(
            f"wheel member size exceeds {MAX_MEMBER_UNCOMPRESSED_BYTES}: {item.filename}"
        )
    if item.file_size and (
        item.compress_size == 0
        or item.file_size > item.compress_size * MAX_COMPRESSION_RATIO
    ):
        errors.append(
            f"wheel compression ratio exceeds {MAX_COMPRESSION_RATIO}: {item.filename}"
        )
    return errors


def _one_suffix(names: list[str], suffix: str, errors: list[str]) -> str | None:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        errors.append(f"expected one {suffix}, found {len(matches)}")
        return None
    return matches[0]


def _required_suffix(names: list[str], suffix: str) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(f"required wheel member missing: {suffix}")
    return matches[0]


def _metadata_errors(data: bytes, project: dict[str, Any]) -> list[str]:
    metadata = BytesParser().parsebytes(data)
    errors = []
    if metadata.get("Name") != project["project"]["name"]:
        errors.append("wheel metadata project name mismatch")
    if metadata.get("Version") != project["project"]["version"]:
        errors.append("wheel metadata version mismatch")
    return errors


def _entry_point_errors(text: str, project: dict[str, Any]) -> list[str]:
    parser = _EntryPointParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.Error:
        return ["wheel entry points are malformed"]
    expected = project["project"].get("scripts", {})
    observed = (
        dict(parser.items("console_scripts"))
        if parser.has_section("console_scripts")
        else {}
    )
    if parser.sections() != ["console_scripts"] or observed != expected:
        return ["wheel console entry points mismatch pyproject.toml"]
    return []


def _record_errors(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    record_name: str,
) -> list[str]:
    rows = list(
        csv.reader(
            io.StringIO(
                _read_member_bytes(archive, by_name[record_name]).decode("utf-8")
            )
        )
    )
    if any(len(row) != 3 for row in rows):
        return ["wheel RECORD row must contain three fields"]
    errors: list[str] = []
    record_names = [row[0] for row in rows]
    if sorted(record_names) != sorted(by_name):
        errors.append("wheel RECORD member set mismatch")
    for name, digest, size in rows:
        errors.extend(
            _record_row_errors(archive, by_name, record_name, name, digest, size)
        )
    return errors


def _record_row_errors(
    archive: zipfile.ZipFile,
    by_name: dict[str, zipfile.ZipInfo],
    record_name: str,
    name: str,
    digest: str,
    size: str,
) -> list[str]:
    if name == record_name:
        return (
            []
            if not digest and not size
            else ["wheel RECORD self-entry must omit hash and size"]
        )
    if name not in by_name:
        return []
    observed_digest, observed_size = _hash_member(archive, by_name[name])
    encoded = base64.urlsafe_b64encode(observed_digest).rstrip(b"=").decode("ascii")
    if digest != f"sha256={encoded}" or size != str(observed_size):
        return [f"wheel RECORD mismatch: {name}"]
    return []


def _read_member_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    limit = min(MAX_MEMBER_UNCOMPRESSED_BYTES, MAX_METADATA_BYTES)
    chunks: list[bytes] = []
    total = 0
    try:
        with archive.open(info, "r") as stream:
            while chunk := stream.read(min(64 * 1024, limit - total + 1)):
                total += len(chunk)
                if total > limit:
                    raise ValueError(
                        f"wheel member read exceeds {limit}: {info.filename}"
                    )
                chunks.append(chunk)
    except (EOFError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise ValueError(f"wheel member truncated: {info.filename}") from exc
    if total != info.file_size:
        raise ValueError(f"wheel member truncated: {info.filename}")
    return b"".join(chunks)


def _hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[bytes, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with archive.open(info, "r") as stream:
            while chunk := stream.read(64 * 1024):
                total += len(chunk)
                if total > MAX_MEMBER_UNCOMPRESSED_BYTES:
                    raise ValueError(
                        f"wheel member read exceeds {MAX_MEMBER_UNCOMPRESSED_BYTES}: {info.filename}"
                    )
                digest.update(chunk)
    except (EOFError, OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise ValueError(f"wheel member truncated: {info.filename}") from exc
    if total != info.file_size:
        raise ValueError(f"wheel member truncated: {info.filename}")
    return digest.digest(), total


def _empty_build(timeout_seconds: int) -> dict[str, Any]:
    return {
        "command": [],
        "image": _IMAGE,
        "started_at": _utc_now(),
        "completed_at": _utc_now(),
        "timeout_seconds": timeout_seconds,
        "output_limit_bytes": MAX_BUILD_OUTPUT_BYTES,
        "termination": "NOT_STARTED",
        "timed_out": False,
        "exit_code": None,
    }


def _format_time(value: Any) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
