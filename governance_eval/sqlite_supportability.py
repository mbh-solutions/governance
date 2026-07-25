from __future__ import annotations

import ast
import io
import re
import stat
import subprocess
import tomllib
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from governance_eval.hashing import sha256_json
from governance_eval.schemas import validate_packaged_named
from governance_eval.sqlite_ast_guard import (
    call_argument_mutation_names,
    call_arguments_prove_empty,
    comprehension_bound_names,
    comprehension_is_statically_empty,
    dynamic_sink_lookup_errors,
    function_binding_mutations as _function_binding_mutations,
    locally_shadowed,
    mapping_mutation_root,
    mutation_target_name as _mutation_target_name,
    namespace_subscript_name,
    target_names as _target_names,
    without_shadowed_bindings,
)
from governance_eval.sqlite_policy import (
    INITIALIZATION,
    LIMITS,
    MAX_VM_OPERATIONS,
    POLICY_ID,
    POLICY_SHA256,
    SQLitePolicyError,
    Statement,
    classify_statement,
    normalize_sql,
    prepare_statements,
    split_sql_script,
)


STANDARD_PROFILE = "python.standard.v1"
SQLITE_PROFILE = "python.sqlite.v1"
CAPABILITY = "sql_supportability"
ADAPTER_ID = "python.sqlite-supportability.v1"
ASSURANCE_CLASS = "EVALUATOR_AUTHORITATIVE"
MAX_FILES = 10_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_AST_NODES = 1_000_000
MAX_SINKS = 10_000
MAX_STATEMENTS = 10_000
MAX_SQL_BYTES = 1024 * 1024
_UNKNOWN_MAPPING_ALIAS = "<unknown-mapping-alias>"
_SINKS = frozenset({"execute", "executemany", "executescript"})
_MAPPING_MUTATORS = frozenset(
    {
        "__delitem__",
        "__ior__",
        "__setitem__",
        "clear",
        "pop",
        "popitem",
        "setdefault",
        "update",
    }
)
_SQL_PREFIX = re.compile(
    r"^\s*\ufeff?\s*(?:--[^\n]*\n|/\*.*?\*/\s*|;\s*)*"
    r"(?:ALTER|ANALYZE|ATTACH|BEGIN|COMMIT|CREATE|DELETE|DETACH|DROP|END|"
    r"EXPLAIN|INSERT|PRAGMA|REINDEX|RELEASE|REPLACE|ROLLBACK|SAVEPOINT|"
    r"SELECT|UPDATE|VACUUM|VALUES|WITH)\b",
    re.I | re.S,
)
_RESOURCE_SUFFIXES = frozenset({".ddl", ".sql", ".sqlite", ".tmpl"})
_EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".home",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "tests",
        "venv",
    }
)


class SQLiteSupportabilityError(ValueError):
    pass


@dataclass(frozen=True)
class _Choice:
    values: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _Module:
    path: str
    raw: bytes
    tree: ast.Module
    values: Mapping[str, Any]
    sqlite_aliases: frozenset[str]
    sqlite_symbols: frozenset[str]
    sqlite_types: frozenset[str]
    sqlite_returns: frozenset[str]
    function_mutations: Mapping[str, frozenset[str]]
    pathlib_aliases: frozenset[str]
    pathlib_symbols: frozenset[str]


@dataclass(frozen=True)
class _Surface:
    files: Mapping[str, bytes]
    resources: Mapping[str, bytes]
    tracked: frozenset[str] | None = None
    visible: frozenset[str] | None = None


def discover_repository_profile(repo_root: Path) -> dict[str, Any]:
    started = _now()
    root = repo_root.resolve(strict=True)
    errors: list[str] = []
    try:
        surface = _repository_surface(root)
        analysis = _analyze_surface(surface)
        errors.extend(analysis["errors"])
    except (OSError, SQLiteSupportabilityError, UnicodeError, ValueError) as exc:
        surface = _Surface({}, {})
        analysis = _empty_analysis()
        errors.append(str(exc))
    return _profile_discovery_payload(started, surface, analysis, errors)


def discover_wheel_profile(wheel_bytes: bytes) -> dict[str, Any]:
    started = _now()
    errors: list[str] = []
    try:
        surface = _wheel_surface_bytes(wheel_bytes)
        analysis = _analyze_surface(surface)
        errors.extend(analysis["errors"])
    except (
        OSError,
        SQLitePolicyError,
        SQLiteSupportabilityError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        surface = _Surface({}, {})
        analysis = _empty_analysis()
        errors.append(str(exc))
    return _profile_discovery_payload(started, surface, analysis, errors)


def wheel_source_binding_errors(repo_root: Path, wheel_bytes: bytes) -> list[str]:
    root = repo_root.resolve(strict=True)
    try:
        tracked = frozenset(_git_paths(root, "ls-files", "-z"))
        sources = _packaged_source_bytes(root, tracked)
    except (OSError, SQLiteSupportabilityError, ValueError, zipfile.BadZipFile) as exc:
        return [str(exc)]
    return wheel_source_binding_errors_from_snapshot(sources, wheel_bytes)


def packaged_source_snapshot(repo_root: Path) -> dict[str, bytes]:
    root = repo_root.resolve(strict=True)
    visible = frozenset(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    return _packaged_source_bytes(root, visible)


def wheel_source_binding_errors_from_snapshot(
    sources: Mapping[str, bytes], wheel_bytes: bytes
) -> list[str]:
    try:
        wheel = _wheel_surface_bytes(wheel_bytes)
    except (OSError, SQLiteSupportabilityError, ValueError, zipfile.BadZipFile) as exc:
        return [str(exc)]
    errors: list[str] = []
    for name, raw in sorted({**wheel.files, **wheel.resources}.items()):
        if name not in sources:
            errors.append(f"wheel runtime member is not committed source: {name}")
        elif not _source_member_matches(name, sources[name], raw):
            errors.append(f"wheel runtime member differs from committed source: {name}")
    return errors


def _source_member_matches(name: str, source: bytes, wheel: bytes) -> bool:
    if source == wheel:
        return True
    if PurePosixPath(name).suffix.lower() not in _RESOURCE_SUFFIXES:
        return False
    try:
        return normalize_sql(source.decode("utf-8")) == normalize_sql(
            wheel.decode("utf-8")
        )
    except UnicodeDecodeError:
        return False


def _packaged_source_bytes(root: Path, tracked: frozenset[str]) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    source_bytes = 0
    for package_root in _package_roots(root):
        for path in sorted(package_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            repository_name = path.relative_to(root).as_posix()
            if repository_name not in tracked:
                continue
            suffix = path.suffix.lower()
            if suffix != ".py" and suffix not in _RESOURCE_SUFFIXES:
                continue
            wheel_name = path.relative_to(package_root).as_posix()
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or len(sources) >= MAX_FILES:
                raise SQLiteSupportabilityError("packaged source exceeds fixed bounds")
            if source_bytes + size > MAX_SOURCE_BYTES:
                raise SQLiteSupportabilityError("source bytes exceeds 32 MiB")
            raw = path.read_bytes()
            if len(raw) != size:
                raise SQLiteSupportabilityError("packaged source changed while read")
            if wheel_name in sources and sources[wheel_name] != raw:
                raise SQLiteSupportabilityError(
                    f"packaged source path is ambiguous: {wheel_name}"
                )
            sources[wheel_name] = raw
            source_bytes += size
    return sources


def _profile_discovery_payload(
    started: str,
    surface: _Surface,
    analysis: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    sqlite_detected = bool(analysis["sinks"] or analysis["resources"])
    if analysis["unclassified_sql"]:
        errors.append("SQL-like source is not classified as SQLite")
    required = SQLITE_PROFILE if sqlite_detected else STANDARD_PROFILE
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "required_profile": required,
        "sqlite_detected": sqlite_detected,
        "files_scanned": len(surface.files),
        "resources": sorted(analysis["resources"]),
        "sinks": analysis["sinks"],
        "errors": sorted(set(errors)),
        "started_at": started,
        "completed_at": _now(),
        "receipt_sha256": "",
    }
    payload["receipt_sha256"] = sha256_json({**payload, "receipt_sha256": ""})
    validate_packaged_named("profile_discovery", payload)
    return payload


def validate_profile_discovery(
    value: Mapping[str, Any], *, selected_profile: str
) -> None:
    validate_packaged_named("profile_discovery", value)
    if set(value) != {
        "schema_version",
        "required_profile",
        "sqlite_detected",
        "files_scanned",
        "resources",
        "sinks",
        "errors",
        "started_at",
        "completed_at",
        "receipt_sha256",
    }:
        raise SQLiteSupportabilityError("profile discovery fields are invalid")
    expected = sha256_json({**dict(value), "receipt_sha256": ""})
    if value.get("receipt_sha256") != expected:
        raise SQLiteSupportabilityError("profile discovery receipt is invalid")
    try:
        started = _timestamp(str(value.get("started_at")))
        completed = _timestamp(str(value.get("completed_at")))
    except ValueError as exc:
        raise SQLiteSupportabilityError("profile discovery timing is invalid") from exc
    if completed < started:
        raise SQLiteSupportabilityError("profile discovery timestamps are out of order")
    required = value.get("required_profile")
    if required not in {STANDARD_PROFILE, SQLITE_PROFILE}:
        raise SQLiteSupportabilityError("profile discovery result is unsupported")
    detected = bool(value.get("sinks") or value.get("resources"))
    if value.get("sqlite_detected") is not detected or required != (
        SQLITE_PROFILE if detected else STANDARD_PROFILE
    ):
        raise SQLiteSupportabilityError("profile discovery semantics are contradictory")
    sinks = value.get("sinks", [])
    sink_paths = {item.get("path") for item in sinks if isinstance(item, Mapping)}
    resources = value.get("resources", [])
    if (
        len(sinks) != len({_sink_identity(item) for item in sinks})
        or len(resources) != len(set(resources))
        or any(not _safe_member_path(path) for path in (*sink_paths, *resources))
        or value.get("files_scanned", 0) < len(sink_paths)
    ):
        raise SQLiteSupportabilityError("profile discovery inventory is contradictory")
    if value.get("errors"):
        raise SQLiteSupportabilityError("profile discovery is blocking")
    if selected_profile != required:
        raise SQLiteSupportabilityError(
            f"profile discovery requires trusted opt-in to {required}"
        )


def run_sqlite_supportability(
    wheel_path: Path | None, *, wheel_bytes: bytes | None = None
) -> dict[str, Any]:
    started = _now()
    errors: list[str] = []
    analysis = _empty_analysis()
    identity: dict[str, Any] = {}
    preparations: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    wheel_sha256: str | None = None
    if wheel_path is None and wheel_bytes is None:
        errors.append("validated candidate wheel is unavailable")
    else:
        try:
            surface, wheel_sha256 = _wheel_input(wheel_path, wheel_bytes)
            files = _file_evidence(surface)
            analysis = _analyze_surface(surface)
            errors.extend(analysis["errors"])
            errors.extend(
                _execution_order_preparation_errors(analysis["order_sequences"])
            )
            preparations, policy_errors, identity = prepare_statements(
                _proved_statement_order(
                    analysis["order_sequences"], analysis["statements"]
                )
            )
            errors.extend(policy_errors)
        except (
            OSError,
            SQLitePolicyError,
            SQLiteSupportabilityError,
            UnicodeError,
            ValueError,
            zipfile.BadZipFile,
        ) as exc:
            errors.append(str(exc))
    repo_status = "PASS" if not analysis["errors"] and not errors else "FAIL"
    behavior_status = (
        "PASS"
        if preparations
        and len(preparations) == len(analysis["statements"])
        and all(item["status"] == "PASS" for item in preparations)
        else "FAIL"
    )
    evidence = {
        "schema_version": "1.0",
        "policy_id": POLICY_ID,
        "policy_sha256": POLICY_SHA256,
        "wheel_sha256": wheel_sha256,
        "gate_implementation": "PASS",
        "repo_sql_supportability": repo_status,
        "sql_behavior_proof": behavior_status,
        "files": files,
        "sinks": analysis["sinks"],
        "receiver_provenance": analysis["receiver_provenance"],
        "resources": sorted(analysis["resources"]),
        "preparations": preparations,
        "sqlite_identity": identity,
        "counts": analysis["counts"],
        "limits": _limit_evidence(),
        "started_at": started,
        "completed_at": _now(),
        "errors": sorted(set(errors)),
    }
    validate_packaged_named("sqlite_supportability_evidence", evidence)
    passed = all(
        evidence[name] == "PASS"
        for name in (
            "gate_implementation",
            "repo_sql_supportability",
            "sql_behavior_proof",
        )
    )
    return {
        "capability": CAPABILITY,
        "adapter_id": ADAPTER_ID,
        "assurance_class": ASSURANCE_CLASS,
        "status": "PASS" if passed else "BLOCK_TECHNICAL",
        "evidence": evidence,
    }


def _repository_surface(root: Path) -> _Surface:
    roots = _package_roots(root)
    files: dict[str, bytes] = {}
    resources: dict[str, bytes] = {}
    tracked = frozenset(_git_paths(root, "ls-files", "-z"))
    untracked = frozenset(
        _git_paths(root, "ls-files", "-z", "--others", "--exclude-standard")
    )
    visible = tracked | untracked
    source_bytes = 0
    for package_root in roots:
        for path in sorted(package_root.rglob("*")):
            member = _repository_member(path, package_root, root, visible)
            if member is None:
                continue
            name, raw = member
            if len(files) + len(resources) >= MAX_FILES:
                raise SQLiteSupportabilityError("packaged file count exceeds 10,000")
            if source_bytes + len(raw) > MAX_SOURCE_BYTES:
                raise SQLiteSupportabilityError("source bytes exceeds 32 MiB")
            _add_surface_file(files, resources, name, raw)
            source_bytes += len(raw)
    return _Surface(files, resources, tracked, visible)


def _repository_member(
    path: Path,
    package_root: Path,
    root: Path,
    visible: frozenset[str],
) -> tuple[str, bytes] | None:
    if not path.is_file() or path.is_symlink():
        return None
    package_relative = path.relative_to(package_root)
    if (
        package_root == root
        and package_relative.parts
        and package_relative.parts[0] in _EXCLUDED_PARTS
    ):
        return None
    name = path.relative_to(root).as_posix()
    suffix = path.suffix.lower()
    if suffix == ".pyc":
        raise SQLiteSupportabilityError(f"compiled Python is unsupported: {name}")
    if suffix != ".py" and suffix not in _RESOURCE_SUFFIXES:
        return None
    if name not in visible and suffix not in _RESOURCE_SUFFIXES:
        return None
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise SQLiteSupportabilityError(f"source file exceeds 2 MiB: {name}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise SQLiteSupportabilityError(f"source file changed while read: {name}")
    return name, raw


def _wheel_input(path: Path | None, wheel_bytes: bytes | None) -> tuple[_Surface, str]:
    if wheel_bytes is not None:
        if len(wheel_bytes) > MAX_SOURCE_BYTES:
            raise SQLiteSupportabilityError("candidate wheel is invalid or oversized")
        return _wheel_surface_bytes(wheel_bytes), sha256(wheel_bytes).hexdigest()
    assert path is not None
    wheel = path.resolve(strict=True)
    if (
        not wheel.is_file()
        or wheel.is_symlink()
        or wheel.stat().st_size > MAX_SOURCE_BYTES
    ):
        raise SQLiteSupportabilityError("candidate wheel is invalid or oversized")
    raw = wheel.read_bytes()
    return _wheel_surface_bytes(raw), sha256(raw).hexdigest()


def _wheel_surface_bytes(raw: bytes) -> _Surface:
    files: dict[str, bytes] = {}
    resources: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        _validate_members(infos)
        for info in sorted(infos, key=lambda item: item.filename):
            if ".dist-info/" in info.filename:
                continue
            _add_surface_file(
                files, resources, info.filename, _read_member(archive, info)
            )
    return _Surface(files, resources)


def _analyze_surface(surface: _Surface) -> dict[str, Any]:
    _validate_surface_bounds(surface)
    modules, errors, nodes = _parse_modules(surface.files)
    errors.extend(_static_mapping_mutation_errors(modules))
    statements: list[Statement] = []
    sinks: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []
    referenced: set[str] = set()
    order_sequences: list[tuple[str, tuple[Statement, ...]]] = []
    for module in modules:
        result = _analyze_module(module, surface.resources)
        statements.extend(result["statements"])
        sinks.extend(result["sinks"])
        provenance.extend(result["receiver_provenance"])
        referenced.update(result["resources"])
        order_sequences.extend(result["order_sequences"])
        errors.extend(result["errors"])
        if len(sinks) > MAX_SINKS:
            raise SQLiteSupportabilityError("sink count exceeds 10,000")
        if len(statements) > MAX_STATEMENTS:
            raise SQLiteSupportabilityError("statement count exceeds 10,000")
    if surface.tracked is not None:
        errors.extend(
            f"SQLite source is not committed: {path}"
            for path in sorted({str(item["path"]) for item in sinks})
            if path not in surface.tracked
        )
    errors.extend(_resource_errors(surface, referenced))
    unclassified = sorted(
        name
        for name, raw in surface.resources.items()
        if (_resource_is_sql(name, raw))
        and name not in referenced
        and (surface.visible is None or name in surface.visible)
    )
    errors.extend(
        f"SQL-like source is not classified as SQLite: {name}" for name in unclassified
    )
    _check_counts(surface, nodes, sinks, statements, errors)
    return {
        "statements": statements,
        "sinks": sinks,
        "receiver_provenance": provenance,
        "resources": referenced,
        "order_sequences": order_sequences,
        "unclassified_sql": unclassified,
        "errors": sorted(set(errors)),
        "counts": {
            "ast_nodes": nodes,
            "files": len(surface.files) + len(surface.resources),
            "sinks": len(sinks),
            "source_bytes": sum(
                map(len, (*surface.files.values(), *surface.resources.values()))
            ),
            "sql_statements": len(statements),
        },
    }


def _static_mapping_mutation_errors(modules: Sequence[_Module]) -> list[str]:
    owned = {module.path: _static_sql_mapping_names(module) for module in modules}
    exported = set().union(*owned.values()) if owned else set()
    errors: list[str] = []
    for module in modules:
        parents = {
            id(child): parent
            for parent in ast.walk(module.tree)
            for child in ast.iter_child_nodes(parent)
        }
        scope_bindings: dict[int, tuple[set[str], set[str]]] = {}
        monitored = set(owned[module.path])
        for statement in module.tree.body:
            if isinstance(statement, ast.ImportFrom):
                monitored.update(
                    item.asname or item.name
                    for item in statement.names
                    if item.name in exported
                )
            elif isinstance(statement, ast.Import):
                monitored.update(
                    f"{item.asname or item.name.split('.', 1)[0]}.{name}"
                    for item in statement.names
                    for name in exported
                )
        initializers = {
            id(node)
            for node in module.tree.body
            if _module_assignment(node)[0] in owned[module.path]
        }
        for node in ast.walk(module.tree):
            if id(node) in initializers:
                continue
            changed = sorted(
                reference
                for reference in _mutation_references(node) & monitored
                if not locally_shadowed(node, reference, parents, scope_bindings)
            )
            if changed:
                errors.append(
                    f"{module.path}:{getattr(node, 'lineno', 0)}: "
                    f"static SQL mapping is mutable: {', '.join(changed)}"
                )
    return errors


def _static_sql_mapping_names(module: _Module) -> set[str]:
    used = {
        name.id
        for node in ast.walk(module.tree)
        if _is_sink_call(node) and isinstance(node, ast.Call) and node.args
        for name in ast.walk(node.args[0])
        if isinstance(name, ast.Name)
        and _mutable_static_ids(module.values.get(name.id))
    }
    identities = {
        identity
        for name in used
        for identity in _mutable_static_ids(module.values[name])
    }
    return {
        name
        for name, value in module.values.items()
        if identities & _mutable_static_ids(value)
    }


def _mutation_references(node: ast.AST) -> set[str]:
    references = {
        name
        for target in _binding_targets(node)
        if (name := _mutation_reference(target)) is not None
    }
    if _is_mapping_mutation(node):
        assert isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        target = (
            node.args[0]
            if isinstance(node.func.value, ast.Name)
            and node.func.value.id == "dict"
            and node.args
            else node.func.value
        )
        if name := _mutation_reference(target):
            references.add(name)
        references.update(_namespace_mutation_names(node))
    return references


def _mutation_reference(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Subscript):
        return namespace_subscript_name(node) or _mutation_reference(node.value)
    if isinstance(node, ast.Attribute):
        return _expression_name(node) or None
    return None


def _namespace_mutation_names(node: ast.Call) -> set[str]:
    if not (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id in {"globals", "locals", "vars"}
    ):
        return set()
    names = {
        item.arg for item in node.keywords if isinstance(item.arg, str) and item.arg
    }
    if (
        node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        names.add(node.args[0].value)
    return names


def _analyze_module(module: _Module, resources: Mapping[str, bytes]) -> dict[str, Any]:
    statements: list[Statement] = []
    sinks: list[dict[str, Any]] = []
    provenance: list[dict[str, Any]] = []
    referenced: set[str] = set()
    errors = _dynamic_dispatch_errors(module)
    for scope in _scopes(module.tree):
        result = _analyze_scope(module, resources, scope)
        statements.extend(result["statements"])
        sinks.extend(result["sinks"])
        provenance.extend(result["receiver_provenance"])
        referenced.update(result["resources"])
        errors.extend(result["errors"])
    order_sequences, order_errors = _execution_order_sequences(module, statements)
    errors.extend(order_errors)
    return {
        "statements": statements,
        "sinks": sinks,
        "receiver_provenance": provenance,
        "resources": referenced,
        "order_sequences": order_sequences,
        "errors": errors,
    }


def _analyze_scope(
    module: _Module,
    resources: Mapping[str, bytes],
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "statements": [],
        "sinks": [],
        "receiver_provenance": [],
        "resources": set(),
        "errors": [],
    }
    known = _annotated_receivers(module, scope)
    values = {} if isinstance(scope, ast.Module) else dict(module.values)
    conditional = _conditional_nodes(scope)
    parents = {
        id(child): parent
        for parent in ast.walk(scope)
        for child in ast.iter_child_nodes(parent)
    }
    for node in _ordered_scope_nodes(scope):
        shadowed = comprehension_bound_names(node, parents)
        zero_iteration = comprehension_is_statically_empty(node, parents)
        _update_scope_bindings(
            node,
            module,
            known,
            values,
            conditional=id(node) in conditional,
            shadowed=shadowed,
            zero_iteration=zero_iteration,
        )
        if not _is_sink_call(node):
            continue
        sink_known = without_shadowed_bindings(known, shadowed)
        sink_values = without_shadowed_bindings(values, shadowed)
        _analyze_sink(module, resources, node, sink_known, sink_values, result)
        if len(result["sinks"]) > MAX_SINKS:
            raise SQLiteSupportabilityError("sink count exceeds 10,000")
        if len(result["statements"]) > MAX_STATEMENTS:
            raise SQLiteSupportabilityError("statement count exceeds 10,000")
    return result


def _update_scope_bindings(
    node: ast.AST,
    module: _Module,
    known: dict[str, str],
    values: dict[str, Any],
    *,
    conditional: bool,
    shadowed: set[str],
    zero_iteration: bool,
) -> None:
    for name in _scope_assignment_names(node):
        if name.split(".", 1)[0] in shadowed:
            continue
        known.pop(name, None)
        _drop_static_value(values, name)
    if _is_mapping_mutation(node):
        assert isinstance(node, ast.Call)
        if mapping_mutation_root(node) not in shadowed:
            _drop_static_value(values, _mapping_mutation_name(node))
        elif not zero_iteration:
            _drop_all_static_mappings(values)
    _invalidate_call_effects(node, module, known, values, shadowed, zero_iteration)
    target, value = _assignment(node)
    if not target or conditional:
        return
    if value is not None:
        try:
            values[target] = _static_value(value, values)
        except (KeyError, SQLiteSupportabilityError, TypeError, ValueError):
            pass
    proof = _receiver_proof(value, module, known) if value else None
    if proof:
        known[target] = proof


def _invalidate_call_effects(
    node: ast.AST,
    module: _Module,
    known: dict[str, str],
    values: dict[str, Any],
    shadowed: set[str],
    zero_iteration: bool,
) -> None:
    arguments = _mutable_call_arguments(node, values)
    if arguments & shadowed and not zero_iteration:
        _drop_all_static_mappings(values)
    for name in arguments - shadowed:
        if name not in shadowed:
            _drop_static_value(values, name)
    if not isinstance(node, ast.Call):
        return
    target = _local_call_target(node, frozenset(module.function_mutations))
    if target:
        for name in module.function_mutations[target]:
            if name == _UNKNOWN_MAPPING_ALIAS:
                if not call_arguments_prove_empty(node):
                    _drop_all_static_mappings(values)
            else:
                known.pop(name, None)
                _drop_static_value(values, name)


def _analyze_sink(
    module: _Module,
    resources: Mapping[str, bytes],
    node: ast.AST,
    known: Mapping[str, str],
    values: Mapping[str, Any],
    result: dict[str, Any],
) -> None:
    assert isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    receiver = _expression_name(node.func.value)
    if receiver not in known:
        result["errors"].extend(_unresolved_sink_errors(module, node))
        return
    sink = node.func.attr
    proof = known[receiver]
    result["receiver_provenance"].append(
        {
            "path": module.path,
            "line": node.lineno,
            "receiver": receiver,
            "proof": proof,
        }
    )
    try:
        resource = _resource_reference(node.args[0], module)
        resolved = _resolve_sql(
            node.args[0], module, resources, resource, values=values
        )
        found, names = _statements(module.path, node, sink, resolved, resource)
        result["statements"].extend(found)
        result["resources"].update(names)
    except (IndexError, SQLitePolicyError, SQLiteSupportabilityError) as exc:
        result["errors"].append(f"{module.path}:{node.lineno}: {exc}")
    result["sinks"].append({"path": module.path, "line": node.lineno, "sink": sink})


def _parse_modules(
    files: Mapping[str, bytes],
) -> tuple[list[_Module], list[str], int]:
    modules: list[_Module] = []
    errors: list[str] = []
    nodes = 0
    for path, raw in sorted(files.items()):
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"{path}: packaged Python is not parseable: {exc}")
            continue
        nodes += sum(1 for _ in ast.walk(tree))
        if nodes > MAX_AST_NODES:
            raise SQLiteSupportabilityError("AST nodes exceeds 1,000,000")
        aliases, symbols, types = _sqlite_imports(tree)
        pathlib_aliases, pathlib_symbols = _pathlib_imports(tree)
        modules.append(
            _Module(
                path,
                raw,
                tree,
                _module_values(tree),
                aliases,
                symbols,
                types,
                _sqlite_return_functions(tree, aliases, symbols, types),
                _function_mutations(tree),
                pathlib_aliases,
                pathlib_symbols,
            )
        )
    return modules, errors, nodes


def _sqlite_imports(
    tree: ast.Module,
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    aliases: set[str] = set()
    symbols: set[str] = set()
    types: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            aliases.update(
                item.asname or item.name
                for item in node.names
                if item.name == "sqlite3"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
            symbols.update(
                item.asname or item.name
                for item in node.names
                if item.name == "connect"
            )
            types.update(
                item.asname or item.name
                for item in node.names
                if item.name in {"Connection", "Cursor"}
            )
    return frozenset(aliases), frozenset(symbols), frozenset(types)


def _pathlib_imports(tree: ast.Module) -> tuple[frozenset[str], frozenset[str]]:
    aliases: set[str] = set()
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            aliases.update(
                item.asname or item.name
                for item in node.names
                if item.name == "pathlib"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "pathlib":
            symbols.update(
                item.asname or item.name for item in node.names if item.name == "Path"
            )
    return frozenset(aliases), frozenset(symbols)


def _annotated_receivers(
    module: _Module,
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    known: dict[str, str] = {}
    if isinstance(scope, ast.Module):
        return known
    for argument in (
        *scope.args.posonlyargs,
        *scope.args.args,
        *scope.args.kwonlyargs,
    ):
        if _sqlite_annotation(argument.annotation, module):
            known[argument.arg] = "sqlite annotation"
    return known


def _receiver_proof(
    node: ast.AST, module: _Module, known: Mapping[str, str]
) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    name = _expression_name(node.func)
    if _is_connect_call(name, module):
        if _custom_connect_factory(node):
            return None
        return "sqlite3.connect"
    if isinstance(node.func, ast.Attribute) and node.func.attr == "cursor":
        if _expression_name(node.func.value) in known and not (
            node.args or any(item.arg in {None, "factory"} for item in node.keywords)
        ):
            return "cursor derivation"
    short = (
        node.func.id
        if isinstance(node.func, ast.Name)
        else node.func.attr
        if isinstance(node.func, ast.Attribute)
        and _expression_name(node.func.value) in {"self", "cls"}
        else ""
    )
    if short in module.sqlite_returns:
        return f"statically resolved return: {short}"
    return None


def _resolve_sql(
    node: ast.AST,
    module: _Module,
    resources: Mapping[str, bytes],
    resource: str | None,
    *,
    values: Mapping[str, Any] | None = None,
) -> str | _Choice:
    static_values = module.values if values is None else values
    try:
        value = _static_value(node, static_values)
    except (KeyError, SQLiteSupportabilityError, TypeError, ValueError):
        choice = _mapping_choice(node, static_values)
        if choice is not None:
            return choice
        if resource is None:
            raise SQLiteSupportabilityError("SQL expression is not statically resolved")
        if resource not in resources:
            raise SQLiteSupportabilityError(
                f"packaged SQL resource is missing: {resource}"
            )
        try:
            return resources[resource].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SQLiteSupportabilityError(
                f"packaged SQL resource is not UTF-8: {resource}"
            ) from exc
    if not isinstance(value, str):
        raise SQLiteSupportabilityError("SQL expression does not resolve to text")
    return value


def _static_value(node: ast.AST, values: Mapping[str, Any]) -> Any:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return node.value
    if isinstance(node, ast.Name):
        return values[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _static_value(node.left, values) + _static_value(node.right, values)
    if isinstance(node, ast.Tuple):
        return tuple(_static_value(item, values) for item in node.elts)
    if isinstance(node, ast.Dict):
        return _static_dict(node, values)
    if isinstance(node, ast.Subscript):
        return _static_value(node.value, values)[_static_value(node.slice, values)]
    if _is_static_format(node):
        assert isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        template = _static_value(node.func.value, values)
        arguments = [_static_value(item, values) for item in node.args]
        keywords = {
            item.arg: _static_value(item.value, values)
            for item in node.keywords
            if item.arg is not None
        }
        return template.format(*arguments, **keywords)
    raise SQLiteSupportabilityError("unsupported static expression")


def _statements(
    path: str,
    node: ast.Call,
    sink: str,
    resolved: str | _Choice,
    resource: str | None = None,
) -> tuple[list[Statement], set[str]]:
    choices = resolved.values if isinstance(resolved, _Choice) else (("", resolved),)
    statements: list[Statement] = []
    resources: set[str] = set()
    if resource:
        resources.add(resource)
    for selector, value in choices:
        parts = (
            split_sql_script(value)
            if sink == "executescript"
            else [normalize_sql(value)]
        )
        for sql in parts:
            if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
                raise SQLiteSupportabilityError("normalized SQL exceeds 1 MiB")
            statements.append(
                Statement(
                    path=path,
                    line=node.lineno,
                    sink=sink,
                    selector=selector or None,
                    sql=sql,
                    sql_sha256=sha256(sql.encode("utf-8")).hexdigest(),
                )
            )
    return statements, resources


def _module_values(tree: ast.Module) -> dict[str, Any]:
    values: dict[str, Any] = {}
    bound: set[str] = set()
    unstable: set[str] = set()
    for node in tree.body:
        target, expression = _module_assignment(node)
        if target is not None:
            if target in bound:
                unstable.add(target)
            bound.add(target)
            _drop_static_value(values, target)
            if expression is not None and target not in unstable:
                try:
                    values[target] = _static_value(expression, values)
                except (KeyError, SQLiteSupportabilityError, TypeError, ValueError):
                    pass
            continue
        for name in _mutable_call_arguments(node, values):
            unstable.add(name)
            _drop_static_value(values, name)
        for name in _module_mutations(node):
            unstable.add(name)
            _drop_static_value(values, name)
    for name in unstable:
        _drop_static_value(values, name)
    return values


def _module_assignment(node: ast.stmt) -> tuple[str | None, ast.AST | None]:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        target = node.targets[0]
        return (target.id, node.value) if isinstance(target, ast.Name) else (None, None)
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id, node.value
    if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        return node.target.id, None
    return None, None


def _module_mutations(node: ast.stmt) -> set[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return set()
    names: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Delete):
            names.update(filter(None, map(_mutation_target_name, item.targets)))
        elif isinstance(item, ast.Assign):
            names.update(filter(None, map(_mutation_target_name, item.targets)))
        elif isinstance(item, (ast.AnnAssign, ast.AugAssign)):
            if name := _mutation_target_name(item.target):
                names.add(name)
        elif _is_mapping_mutation(item):
            assert isinstance(item, ast.Call)
            names.add(_mapping_mutation_name(item))
    return {name for name in names if name}


def _function_mutations(tree: ast.Module) -> dict[str, frozenset[str]]:
    return {
        function.name: frozenset(_function_mutation_names(function))
        for function in _functions(tree)
    }


def _function_mutation_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    nodes = _ordered_scope_nodes(function)
    parents = {
        id(child): parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }
    cache: dict[int, tuple[set[str], set[str]]] = {}
    globals_declared = {
        name for node in nodes if isinstance(node, ast.Global) for name in node.names
    }
    names: set[str] = set()
    for node in nodes:
        shadowed = comprehension_bound_names(node, parents)
        zero_iteration = comprehension_is_statically_empty(node, parents)
        names.update(_function_binding_mutations(node, globals_declared))
        if _is_mapping_mutation(node):
            assert isinstance(node, ast.Call)
            name = _mapping_mutation_name(node)
            root = mapping_mutation_root(node)
            if root in shadowed:
                if not zero_iteration:
                    names.add(_UNKNOWN_MAPPING_ALIAS)
            elif not root or not locally_shadowed(node, name, parents, cache):
                names.add(name)
        if isinstance(node, ast.Call) and not _is_sink_call(node):
            names.update(
                call_argument_mutation_names(
                    node,
                    parents,
                    cache,
                    shadowed,
                    zero_iteration,
                    _UNKNOWN_MAPPING_ALIAS,
                )
            )
    return names - {""}


def _is_mapping_mutation(node: ast.AST) -> bool:
    return bool(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _MAPPING_MUTATORS
    )


def _mapping_mutation_name(node: ast.Call) -> str:
    assert isinstance(node.func, ast.Attribute)
    if (
        isinstance(node.func.value, ast.Name)
        and node.func.value.id == "dict"
        and node.args
    ):
        return _mutation_target_name(node.args[0]) or ""
    return _mutation_target_name(node.func.value) or ""


def _mutable_call_arguments(node: ast.AST, values: Mapping[str, Any]) -> set[str]:
    if not isinstance(node, ast.Call) or _is_sink_call(node):
        return set()
    return {
        argument.id
        for argument in (*node.args, *(item.value for item in node.keywords))
        if isinstance(argument, ast.Name)
        and isinstance(values.get(argument.id), Mapping)
    }


def _drop_static_value(values: dict[str, Any], name: str) -> None:
    value = values.get(name)
    mutable_ids = _mutable_static_ids(value)
    aliases = [
        key
        for key, candidate in values.items()
        if candidate is value
        or mutable_ids
        and mutable_ids & _mutable_static_ids(candidate)
    ]
    for key in aliases or [name]:
        values.pop(key, None)


def _drop_all_static_mappings(values: dict[str, Any]) -> None:
    for name in tuple(values):
        if _mutable_static_ids(values.get(name)):
            _drop_static_value(values, name)


def _mutable_static_ids(value: Any) -> set[int]:
    if isinstance(value, Mapping):
        return {id(value)} | {
            identity
            for item in (*value.keys(), *value.values())
            for identity in _mutable_static_ids(item)
        }
    if isinstance(value, tuple):
        return {identity for item in value for identity in _mutable_static_ids(item)}
    return set()


def _mapping_choice(node: ast.AST, values: Mapping[str, Any]) -> _Choice | None:
    if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Name):
        return None
    mapping = values.get(node.value.id)
    if not isinstance(mapping, Mapping):
        return None
    if not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in mapping.items()
    ):
        return None
    return _Choice(tuple((str(key), str(mapping[key])) for key in sorted(mapping)))


def _resource_reference(node: ast.AST, module: _Module) -> str | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr not in {"read_text", "read_bytes"}:
        return None
    if not _safe_read_call(node):
        return None
    path_node = node.func.value
    name = _with_name_resource(path_node, module)
    if name is None:
        return None
    parent = PurePosixPath(module.path).parent
    return (parent / name).as_posix()


def _safe_read_call(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "read_text" or node.args:
        return False
    if not node.keywords:
        return True
    return bool(
        len(node.keywords) == 1
        and node.keywords[0].arg == "encoding"
        and isinstance(node.keywords[0].value, ast.Constant)
        and str(node.keywords[0].value.value).lower().replace("_", "-") == "utf-8"
    )


def _with_name_resource(node: ast.AST, module: _Module) -> str | None:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return None
    if node.func.attr != "with_name" or len(node.args) != 1 or node.keywords:
        return None
    argument = node.args[0]
    if not isinstance(argument, ast.Constant) or not isinstance(argument.value, str):
        return None
    name = argument.value
    if PurePosixPath(name).name != name or name in {"", ".", ".."}:
        return None
    constructor = node.func.value
    if not isinstance(constructor, ast.Call) or constructor.keywords:
        return None
    if len(constructor.args) != 1 or not isinstance(constructor.args[0], ast.Name):
        return None
    if constructor.args[0].id != "__file__":
        return None
    path_name = _expression_name(constructor.func)
    allowed = module.pathlib_symbols | frozenset(
        f"{alias}.Path" for alias in module.pathlib_aliases
    )
    return name if path_name in allowed else None


def _resource_errors(surface: _Surface, referenced: set[str]) -> list[str]:
    errors: list[str] = []
    for resource in sorted(referenced):
        if resource not in surface.resources:
            errors.append(f"referenced SQL resource is absent: {resource}")
        elif surface.tracked is not None and resource not in surface.tracked:
            errors.append(f"referenced SQL resource is not committed: {resource}")
    return errors


def _unsupported_sink_scope_errors(module: _Module) -> list[str]:
    errors: list[str] = []
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Lambda) and any(
            _is_sink_call(item) for item in ast.walk(node.body)
        ):
            errors.append(
                f"{module.path}:{node.lineno}: SQLite sink in lambda is unsupported"
            )
        if not isinstance(node, ast.ClassDef):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                errors.extend(_definition_sink_errors(module.path, node))
            continue
        errors.extend(_definition_sink_errors(module.path, node))
        for statement in node.body:
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if any(_is_sink_call(item) for item in ast.walk(statement)):
                errors.append(
                    f"{module.path}:{statement.lineno}: "
                    "SQLite sink in class body is unsupported"
                )
    return errors


def _definition_sink_errors(
    path: str, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
) -> list[str]:
    expressions: list[ast.AST] = [*node.decorator_list]
    if isinstance(node, ast.ClassDef):
        expressions.extend(node.bases)
        expressions.extend(item.value for item in node.keywords)
    else:
        expressions.extend(node.args.defaults)
        expressions.extend(item for item in node.args.kw_defaults if item is not None)
        expressions.extend(
            item.annotation
            for item in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if item.annotation is not None
        )
        if node.returns is not None:
            expressions.append(node.returns)
    return [
        f"{path}:{getattr(item, 'lineno', 0)}: "
        "SQLite sink in definition-time expression is unsupported"
        for expression in expressions
        for item in ast.walk(expression)
        if _is_sink_call(item)
    ]


def _shadowed_import_errors(module: _Module) -> list[str]:
    if not any(_is_sink_call(node) for node in ast.walk(module.tree)):
        return []
    trusted = (
        module.sqlite_aliases
        | module.sqlite_symbols
        | module.sqlite_types
        | module.sqlite_returns
        | module.pathlib_aliases
        | module.pathlib_symbols
    )
    if any(
        _is_sink_call(node)
        and isinstance(node, ast.Call)
        and node.args
        and any(
            isinstance(item, ast.Name) and item.id == "__file__"
            for item in ast.walk(node.args[0])
        )
        for node in ast.walk(module.tree)
    ):
        trusted |= frozenset({"__file__"})
    errors: list[str] = []
    for node in ast.walk(module.tree):
        names = _assigned_names(node) - _trusted_import_bindings(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.update(
                argument.arg
                for argument in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
            )
        if shadowed := sorted(names & trusted):
            errors.append(
                f"{module.path}:{getattr(node, 'lineno', 0)}: "
                f"trusted import is shadowed: {', '.join(shadowed)}"
            )
    for node in module.tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in trusted and not (
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in module.sqlite_returns
                and node.name
                not in (
                    module.sqlite_aliases
                    | module.sqlite_symbols
                    | module.sqlite_types
                    | module.pathlib_aliases
                    | module.pathlib_symbols
                )
            ):
                errors.append(
                    f"{module.path}:{node.lineno}: trusted import is shadowed: {node.name}"
                )
    return errors


def _metaprogramming_errors(module: _Module) -> list[str]:
    if not any(_is_sink_call(node) for node in ast.walk(module.tree)):
        return []
    trusted = (
        module.sqlite_aliases
        | module.sqlite_symbols
        | module.sqlite_types
        | module.sqlite_returns
        | module.pathlib_aliases
        | module.pathlib_symbols
    )
    errors: list[str] = []
    for node in ast.walk(module.tree):
        if isinstance(node, ast.ImportFrom) and any(
            item.name == "*" for item in node.names
        ):
            errors.append(
                f"{module.path}:{node.lineno}: wildcard import can shadow trusted imports"
            )
        if isinstance(node, ast.Call) and _mutates_trusted_bindings(node, trusted):
            errors.append(
                f"{module.path}:{node.lineno}: dynamic trusted import mutation is unsupported"
            )
    return errors


def _mutates_trusted_bindings(node: ast.Call, trusted: frozenset[str]) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == "exec":
        return True
    if (
        isinstance(node.func, ast.Name)
        and node.func.id == "setattr"
        and node.args
        and _expression_name(node.args[0]).split(".", 1)[0] in trusted
    ):
        return True
    return bool(
        isinstance(node.func, ast.Attribute)
        and node.func.attr in _MAPPING_MUTATORS
        and isinstance(node.func.value, ast.Call)
        and isinstance(node.func.value.func, ast.Name)
        and node.func.value.func.id in {"globals", "locals", "vars"}
    )


def _dynamic_dispatch_errors(module: _Module) -> list[str]:
    errors = _unsupported_sink_scope_errors(module)
    errors.extend(_shadowed_import_errors(module))
    errors.extend(_metaprogramming_errors(module))
    errors.extend(_unresolved_getattr_errors(module))
    errors.extend(_unresolved_mapping_helper_errors(module))
    errors.extend(_call_graph_scope_errors(module))
    errors.extend(_method_reference_errors(module))
    errors.extend(dynamic_sink_lookup_errors(module.path, module.tree, _SINKS))
    imported_aliases = _imported_sink_aliases(module.tree)
    function_names = frozenset(function.name for function in _functions(module.tree))
    imported_helpers = _imported_symbols(module.tree) - (
        module.sqlite_symbols | module.sqlite_types | module.pathlib_symbols
    )
    if not (
        module.sqlite_aliases
        or module.sqlite_symbols
        or module.sqlite_types
        or imported_aliases
    ):
        return errors
    for node in ast.walk(module.tree):
        errors.extend(
            _dispatch_node_errors(
                module, node, imported_aliases, imported_helpers, function_names
            )
        )
    return errors


def _method_reference_errors(module: _Module) -> list[str]:
    parents = {
        id(child): parent
        for parent in ast.walk(module.tree)
        for child in ast.iter_child_nodes(parent)
    }
    return [
        f"{module.path}:{node.lineno}: SQLite method reference is unsupported"
        for node in ast.walk(module.tree)
        if isinstance(node, ast.Attribute)
        and node.attr in _SINKS
        and not (
            isinstance(parent := parents.get(id(node)), ast.Call)
            and parent.func is node
        )
    ]


def _unresolved_getattr_errors(module: _Module) -> list[str]:
    return [
        f"{module.path}:{node.lineno}: dynamic SQLite dispatch"
        for node in ast.walk(module.tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and not _literal_non_sink_name(node)
    ]


def _unresolved_mapping_helper_errors(module: _Module) -> list[str]:
    untrusted_modules = {
        item.asname or item.name.split(".", 1)[0]
        for node in module.tree.body
        if isinstance(node, ast.Import)
        for item in node.names
        if item.name not in {"pathlib", "sqlite3"}
    }
    module_bound = {
        name
        for node in module.tree.body
        for name in (
            {node.name}
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            else _assigned_names(node)
        )
    }
    errors: list[str] = []
    for scope in _scopes(module.tree):
        nodes = _ordered_scope_nodes(scope)
        if not any(
            _is_sink_call(node)
            and isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Subscript)
            for node in nodes
        ):
            continue
        parameters = _scope_parameters(scope)
        bound = (
            module_bound
            | parameters
            | {name for node in nodes for name in _assigned_names(node)}
        )
        for node in nodes:
            if not isinstance(node, ast.Call) or _is_sink_call(node):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in parameters:
                errors.append(
                    f"{module.path}:{node.lineno}: unresolved helper call is unsupported"
                )
            if isinstance(node.func, ast.Attribute):
                root = _expression_name(node.func.value).split(".", 1)[0]
                if root and (
                    root not in bound or root in parameters or root in untrusted_modules
                ):
                    errors.append(
                        f"{module.path}:{node.lineno}: unresolved helper call is unsupported"
                    )
    return errors


def _scope_parameters(
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    if isinstance(scope, ast.Module):
        return set()
    return {
        argument.arg
        for argument in (
            *scope.args.posonlyargs,
            *scope.args.args,
            *scope.args.kwonlyargs,
        )
    }


def _call_graph_scope_errors(module: _Module) -> list[str]:
    functions = _functions(module.tree)
    names = frozenset(function.name for function in functions)
    parents = {
        id(child): parent
        for parent in ast.walk(module.tree)
        for child in ast.iter_child_nodes(parent)
    }
    errors: list[str] = []
    for function in functions:
        nodes = _ordered_scope_nodes(function)
        if _has_function_parent(function, parents) and any(
            _is_sink_call(node)
            or isinstance(node, ast.Call)
            and _local_call_target(node, names)
            for node in nodes
        ):
            errors.append(
                f"{module.path}:{function.lineno}: nested SQL call graph is unsupported"
            )
        methods = _owner_method_names(function, parents)
        errors.extend(
            f"{module.path}:{node.lineno}: cross-owner SQL call graph is unsupported"
            for node in nodes
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _expression_name(node.func.value) in {"self", "cls"}
            and node.func.attr in names
            and node.func.attr not in methods
        )
    return errors


def _has_function_parent(node: ast.AST, parents: Mapping[int, ast.AST]) -> bool:
    parent = parents.get(id(node))
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        parent = parents.get(id(parent))
    return False


def _owner_method_names(
    node: ast.AST, parents: Mapping[int, ast.AST]
) -> frozenset[str]:
    parent = parents.get(id(node))
    while parent is not None:
        if isinstance(parent, ast.ClassDef):
            return frozenset(
                item.name
                for item in parent.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        parent = parents.get(id(parent))
    return frozenset()


def _dispatch_node_errors(
    module: _Module,
    node: ast.AST,
    imported_aliases: frozenset[str],
    imported_helpers: frozenset[str],
    function_names: frozenset[str],
) -> list[str]:
    errors: list[str] = []
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        errors.extend(
            _named_call_errors(module, node, imported_aliases, imported_helpers)
        )
    if isinstance(node, ast.Call) and isinstance(
        node.func, (ast.Call, ast.Subscript, ast.Lambda)
    ):
        errors.append(
            f"{module.path}:{node.lineno}: dynamic helper dispatch is unsupported"
        )
    target, value = _assignment(node)
    if (
        target
        and isinstance(value, ast.Name)
        and value.id in (function_names | imported_helpers)
    ):
        errors.append(
            f"{module.path}:{getattr(node, 'lineno', 0)}: helper alias is unsupported"
        )
    return errors


def _named_call_errors(
    module: _Module,
    node: ast.Call,
    imported_aliases: frozenset[str],
    imported_helpers: frozenset[str],
) -> list[str]:
    assert isinstance(node.func, ast.Name)
    name = node.func.id
    if name == "getattr" and not _literal_non_sink_name(node):
        return [f"{module.path}:{node.lineno}: dynamic SQLite dispatch"]
    if (
        name in imported_aliases
        and node.args
        and _sql_expression(node.args[0], module.values)
    ):
        return [f"{module.path}:{node.lineno}: SQLite method alias is unsupported"]
    if name in imported_helpers:
        return [f"{module.path}:{node.lineno}: imported helper call is unsupported"]
    return []


def _imported_sink_aliases(tree: ast.Module) -> frozenset[str]:
    return frozenset(
        item.asname or item.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for item in node.names
        if item.name in _SINKS
    )


def _imported_symbols(tree: ast.Module) -> frozenset[str]:
    return frozenset(
        item.asname or item.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for item in node.names
        if item.name != "*"
    )


def _unresolved_sink_errors(module: _Module, node: ast.Call) -> list[str]:
    if not node.args:
        return [f"{module.path}:{node.lineno}: SQLite sink has no SQL argument"]
    if (
        module.sqlite_aliases
        or module.sqlite_symbols
        or _sql_expression(node.args[0], module.values)
    ):
        return [
            f"{module.path}:{node.lineno}: SQLite receiver provenance is unresolved"
        ]
    return []


def _sqlite_return_functions(
    tree: ast.Module,
    aliases: frozenset[str],
    symbols: frozenset[str],
    types: frozenset[str],
) -> frozenset[str]:
    names: set[str] = set()
    for function in _functions(tree):
        if function.decorator_list:
            continue
        annotation = _annotation_text(function.returns)
        if annotation in types or any(
            annotation == f"{alias}.{kind}"
            for alias in aliases
            for kind in ("Connection", "Cursor")
        ):
            names.add(function.name)
            continue
        returns = [
            node
            for node in _ordered_scope_nodes(function)
            if isinstance(node, ast.Return)
        ]
        if (
            len(returns) == 1
            and function.body
            and returns[0] is function.body[-1]
            and _return_is_connect(returns[0], aliases, symbols)
        ):
            names.add(function.name)
    return frozenset(names)


def _return_is_connect(
    node: ast.AST, aliases: frozenset[str], symbols: frozenset[str]
) -> bool:
    if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Call):
        return False
    name = _expression_name(node.value.func)
    return not _custom_connect_factory(node.value) and (
        name in symbols or any(name == f"{alias}.connect" for alias in aliases)
    )


def _sqlite_annotation(node: ast.AST | None, module: _Module) -> bool:
    text = _annotation_text(node)
    return bool(
        text in module.sqlite_types
        or any(
            text == f"{alias}.{kind}"
            for alias in module.sqlite_aliases
            for kind in ("Connection", "Cursor")
        )
    )


def _annotation_text(node: ast.AST | None) -> str:
    return "" if node is None else ast.unparse(node)


def _is_connect_call(name: str, module: _Module) -> bool:
    return name in module.sqlite_symbols or any(
        name == f"{alias}.connect" for alias in module.sqlite_aliases
    )


def _custom_connect_factory(node: ast.Call) -> bool:
    return len(node.args) >= 6 or any(
        item.arg in {None, "factory"} for item in node.keywords
    )


def _functions(
    tree: ast.Module,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return sorted(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )


def _scopes(
    tree: ast.Module,
) -> list[ast.Module | ast.FunctionDef | ast.AsyncFunctionDef]:
    return [tree, *_functions(tree)]


def _ordered_scope_nodes(
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    found: list[ast.AST] = []
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        found.append(node)
        pending.extend(ast.iter_child_nodes(node))
    return sorted(
        found,
        key=lambda node: (
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
            0 if isinstance(node, (ast.Assign, ast.AnnAssign)) else 1,
        ),
    )


def _execution_order_sequences(
    module: _Module, statements: Sequence[Statement]
) -> tuple[list[tuple[str, tuple[Statement, ...]]], list[str]]:
    functions = _functions(module.tree)
    names = [function.name for function in functions]
    seen: set[str] = set()
    duplicates: set[str] = set()
    for name in names:
        (duplicates if name in seen else seen).add(name)
    if duplicates:
        return [], [
            f"{module.path}: SQL call graph has ambiguous functions: "
            f"{', '.join(sorted(duplicates))}"
        ]
    scopes: dict[str, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef] = {
        "<module>": module.tree,
        **{function.name: function for function in functions},
    }
    statement_map: dict[tuple[int, str], list[Statement]] = {}
    for statement in statements:
        statement_map.setdefault((statement.line, statement.sink), []).append(statement)
    events = {
        name: _scope_flow(scope, frozenset(names), statement_map)
        for name, scope in scopes.items()
    }
    errors = _conditional_schema_errors(module.path, events)
    relevant = _sql_relevant_scopes(events)
    incoming = {
        name: sum(
            value == name
            for flow in events.values()
            for kind, value in flow
            if kind.endswith("call")
        )
        for name in scopes
    }
    roots = sorted(
        name
        for name in relevant
        if name == "<module>" or incoming[name] == 0 or not name.startswith("_")
    )
    counter = [0]
    sequences = [
        (
            f"{module.path}:{root}",
            tuple(_expand_flow(root, events, (), counter, errors)),
        )
        for root in roots
    ]
    covered = _reachable_scopes(roots, events)
    missing = sorted(relevant - covered)
    if missing:
        errors.append(
            f"{module.path}: SQL execution order is unproved: {', '.join(missing)}"
        )
    return [(name, sequence) for name, sequence in sequences if sequence], errors


def _scope_flow(
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
    function_names: frozenset[str],
    statements: Mapping[tuple[int, str], Sequence[Statement]],
) -> list[tuple[str, Any]]:
    events: list[tuple[str, Any]] = []
    conditional = _conditional_nodes(scope)
    for node in _ordered_scope_nodes(scope):
        if _is_sink_call(node):
            assert isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            found = tuple(statements.get((node.lineno, node.func.attr), ()))
            if found:
                events.append(
                    ("conditional_sql" if id(node) in conditional else "sql", found)
                )
            continue
        if isinstance(node, ast.Call):
            target = _local_call_target(node, function_names)
            if target:
                events.append(
                    (
                        "conditional_call" if id(node) in conditional else "call",
                        target,
                    )
                )
    return events


def _conditional_nodes(
    scope: ast.Module | ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(scope):
        if isinstance(node, (ast.Try, ast.TryStar)) and (
            not node.handlers or _safe_optional_fts_try(node)
        ):
            continue
        if isinstance(
            node,
            (
                ast.If,
                ast.IfExp,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Match,
                ast.Try,
                ast.TryStar,
                ast.BoolOp,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            for child in ast.iter_child_nodes(node):
                found.update(id(item) for item in ast.walk(child))
    return found


def _safe_optional_fts_try(node: ast.Try | ast.TryStar) -> bool:
    if len(node.handlers) != 1 or node.orelse or node.finalbody:
        return False
    handler = node.handlers[0]
    if _annotation_text(handler.type) not in {
        "OperationalError",
        "sqlite3.OperationalError",
    } or any(not isinstance(item, (ast.Pass, ast.Return)) for item in handler.body):
        return False
    calls = [
        item
        for statement in node.body
        for item in ast.walk(statement)
        if _is_sink_call(item)
    ]
    if not calls:
        return False
    for call in calls:
        assert isinstance(call, ast.Call)
        if not call.args:
            return False
        try:
            statement_class, module = classify_statement(
                str(_static_value(call.args[0], {}))
            )
        except (KeyError, SQLiteSupportabilityError, TypeError, ValueError):
            return False
        if statement_class != "CREATE_VIRTUAL_TABLE" or module != "fts5":
            return False
    return True


def _conditional_schema_errors(
    path: str, events: Mapping[str, Sequence[tuple[str, Any]]]
) -> list[str]:
    schema_scopes = {
        name
        for name, flow in events.items()
        if any(
            kind.endswith("sql")
            and any(
                classify_statement(statement.sql)[0].startswith("CREATE_")
                for statement in value
            )
            for kind, value in flow
        )
    }
    _extend_schema_scopes(schema_scopes, events)
    return [
        f"{path}:{name}: conditional schema execution order is unsupported"
        for name, flow in events.items()
        if any(
            _conditional_schema_event(kind, value, schema_scopes)
            for kind, value in flow
        )
    ]


def _extend_schema_scopes(
    schema_scopes: set[str], events: Mapping[str, Sequence[tuple[str, Any]]]
) -> None:
    changed = True
    while changed:
        changed = False
        for name, flow in events.items():
            if name not in schema_scopes and any(
                kind.endswith("call") and value in schema_scopes for kind, value in flow
            ):
                schema_scopes.add(name)
                changed = True


def _conditional_schema_event(kind: str, value: Any, scopes: set[str]) -> bool:
    if kind == "conditional_call":
        return value in scopes
    return bool(
        kind == "conditional_sql"
        and any(
            classify_statement(statement.sql)[0].startswith("CREATE_")
            for statement in value
        )
        or kind.endswith("sql")
        and any(
            statement.selector is not None
            and classify_statement(statement.sql)[0].startswith("CREATE_")
            for statement in value
        )
    )


def _local_call_target(node: ast.Call, names: frozenset[str]) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id if node.func.id in names else None
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in names:
        return None
    owner = _expression_name(node.func.value)
    return node.func.attr if owner in {"self", "cls"} else None


def _sql_relevant_scopes(events: Mapping[str, Sequence[tuple[str, Any]]]) -> set[str]:
    relevant = {
        name
        for name, flow in events.items()
        if any(kind.endswith("sql") for kind, _ in flow)
    }
    changed = True
    while changed:
        changed = False
        for name, flow in events.items():
            if name not in relevant and any(
                kind.endswith("call") and value in relevant for kind, value in flow
            ):
                relevant.add(name)
                changed = True
    return relevant


def _expand_flow(
    name: str,
    events: Mapping[str, Sequence[tuple[str, Any]]],
    stack: tuple[str, ...],
    counter: list[int],
    errors: list[str],
) -> list[Statement]:
    if name in stack:
        errors.append(
            f"SQL call graph cycle is unsupported: {' -> '.join((*stack, name))}"
        )
        return []
    result: list[Statement] = []
    for kind, value in events[name]:
        if kind.endswith("sql"):
            found = list(value)
            counter[0] += len(found)
            if counter[0] > MAX_STATEMENTS:
                errors.append("proved SQL execution routes exceed 10,000 statements")
                return result
        else:
            found = _expand_flow(value, events, (*stack, name), counter, errors)
        result.extend(found)
    return result


def _reachable_scopes(
    roots: Sequence[str], events: Mapping[str, Sequence[tuple[str, Any]]]
) -> set[str]:
    found: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        pending.extend(
            value
            for kind, value in events[name]
            if kind.endswith("call") and value not in found
        )
    return found


def _execution_order_preparation_errors(
    sequences: Sequence[tuple[str, Sequence[Statement]]],
) -> list[str]:
    errors: list[str] = []
    for name, statements in sequences:
        _evidence, route_errors, _identity = prepare_statements(statements)
        if route_errors:
            errors.append(
                f"SQL execution order is not proved for {name}: {route_errors[0]}"
            )
    return errors


def _proved_statement_order(
    sequences: Sequence[tuple[str, Sequence[Statement]]],
    statements: Sequence[Statement],
) -> list[Statement]:
    ordered = [statement for _name, route in sequences for statement in route]
    return list(dict.fromkeys((*ordered, *statements)))


def _assignment(node: ast.AST) -> tuple[str | None, ast.AST | None]:
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        return _expression_name(node.targets[0]), node.value
    if isinstance(node, ast.AnnAssign):
        return _expression_name(node.target), node.value
    return None, None


def _assigned_names(node: ast.AST) -> set[str]:
    named = _named_binding(node)
    if named is not None:
        return named
    targets = _binding_targets(node)
    return {name for target in targets for name in _target_names(target) if name}


def _scope_assignment_names(node: ast.AST) -> set[str]:
    named = _named_binding(node)
    if named is not None:
        return named
    return {
        name
        for target in _binding_targets(node)
        if not (
            isinstance(target, ast.Attribute)
            and target.attr not in (_SINKS | {"connect", "cursor"})
        )
        for name in _target_names(target)
        if name
    }


def _binding_targets(node: ast.AST) -> Sequence[ast.AST]:
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return (node.target,)
    if isinstance(node, ast.Delete):
        return node.targets
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return (node.target,)
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return tuple(
            item.optional_vars for item in node.items if item.optional_vars is not None
        )
    return ()


def _named_binding(node: ast.AST) -> set[str] | None:
    if isinstance(node, ast.ExceptHandler):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchAs):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchStar):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchMapping):
        return {node.rest} if node.rest else set()
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {
            item.asname or item.name.split(".", 1)[0]
            for item in node.names
            if item.name != "*"
        }
    return None


def _trusted_import_bindings(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Import):
        return {
            item.asname or item.name
            for item in node.names
            if item.name in {"sqlite3", "pathlib"}
        }
    if isinstance(node, ast.ImportFrom) and node.module in {"sqlite3", "pathlib"}:
        return {item.asname or item.name for item in node.names}
    return set()


def _expression_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _expression_name(node.value)
        return ".".join(filter(None, (prefix, node.attr)))
    return ""


def _is_sink_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _SINKS
    )


def _static_dict(node: ast.Dict, values: Mapping[str, Any]) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        if key is None:
            raise SQLiteSupportabilityError("dictionary unpacking is unsupported")
        result[_static_value(key, values)] = _static_value(value, values)
    return result


def _is_static_format(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def _literal_non_sink_name(node: ast.Call) -> bool:
    return (
        len(node.args) > 1
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
        and node.args[1].value not in _SINKS
    )


def _sql_expression(node: ast.AST, values: Mapping[str, Any]) -> bool:
    try:
        value = _static_value(node, values)
    except (KeyError, SQLiteSupportabilityError, TypeError, ValueError):
        return True
    return isinstance(value, str) and bool(_SQL_PREFIX.match(value))


def _safe_member_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


def _sink_identity(value: Any) -> tuple[Any, Any, Any]:
    if not isinstance(value, Mapping):
        return None, None, None
    return value.get("path"), value.get("line"), value.get("sink")


def _package_roots(root: Path) -> list[Path]:
    pyproject_path = root / "pyproject.toml"
    if not pyproject_path.is_file() or pyproject_path.is_symlink():
        raise SQLiteSupportabilityError("pyproject.toml is unavailable")
    project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    setuptools = project.get("tool", {}).get("setuptools", {})
    find = setuptools.get("packages", {}).get("find", {})
    where = find.get("where") or [setuptools.get("package-dir", {}).get("", ".")]
    roots: list[Path] = []
    for item in where:
        relative = PurePosixPath(str(item))
        if relative.is_absolute() or ".." in relative.parts:
            raise SQLiteSupportabilityError("packaged Python root escapes repository")
        candidate = root.joinpath(*relative.parts).resolve()
        if not candidate.is_relative_to(root):
            raise SQLiteSupportabilityError("packaged Python root escapes repository")
        roots.append(candidate)
    existing = [path for path in roots if path.is_dir() and not path.is_symlink()]
    if not existing:
        raise SQLiteSupportabilityError("packaged Python root is unavailable")
    return existing


def _git_paths(root: Path, *arguments: str) -> list[str]:
    try:
        completed = subprocess.run(
            ["git", *arguments], cwd=root, capture_output=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SQLiteSupportabilityError("Git file inventory is unavailable") from exc
    if completed.returncode != 0:
        raise SQLiteSupportabilityError("Git file inventory failed")
    try:
        return [
            value.decode("utf-8").replace("\\", "/")
            for value in completed.stdout.split(b"\0")
            if value
        ]
    except UnicodeDecodeError as exc:
        raise SQLiteSupportabilityError("Git file inventory is not UTF-8") from exc


def _add_surface_file(
    files: dict[str, bytes], resources: dict[str, bytes], name: str, raw: bytes
) -> None:
    if not _safe_member_path(name):
        raise SQLiteSupportabilityError(f"unsafe or overlong packaged path: {name}")
    if len(raw) > MAX_FILE_BYTES:
        raise SQLiteSupportabilityError(f"source file exceeds 2 MiB: {name}")
    suffix = PurePosixPath(name).suffix.lower()
    if suffix == ".pyc":
        raise SQLiteSupportabilityError(f"compiled Python is unsupported: {name}")
    if suffix == ".py":
        files[name] = raw
    elif suffix in _RESOURCE_SUFFIXES:
        resources[name] = raw


def _validate_members(infos: Sequence[zipfile.ZipInfo]) -> None:
    names = [item.filename for item in infos]
    if len(names) > MAX_FILES:
        raise SQLiteSupportabilityError("packaged file count exceeds 10,000")
    if sum(item.file_size for item in infos) > MAX_SOURCE_BYTES:
        raise SQLiteSupportabilityError("source bytes exceeds 32 MiB")
    if len(names) != len(set(names)) or len(names) != len(
        set(name.casefold() for name in names)
    ):
        raise SQLiteSupportabilityError("candidate wheel has duplicate members")
    for info in infos:
        _validate_member(info)


def _validate_member(info: zipfile.ZipInfo) -> None:
    mode = info.external_attr >> 16
    if (
        not _safe_member_path(info.filename)
        or info.is_dir()
        or stat.S_ISLNK(mode)
        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
    ):
        raise SQLiteSupportabilityError(f"unsafe wheel member: {info.filename}")
    if info.file_size > MAX_FILE_BYTES:
        raise SQLiteSupportabilityError(f"wheel member exceeds 2 MiB: {info.filename}")


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with archive.open(info) as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) != info.file_size or len(raw) > MAX_FILE_BYTES:
        raise SQLiteSupportabilityError(f"wheel member is truncated: {info.filename}")
    return raw


def _check_counts(
    surface: _Surface,
    nodes: int,
    sinks: Sequence[Mapping[str, Any]],
    statements: Sequence[Statement],
    errors: list[str],
) -> None:
    counts = {
        "file count": (len(surface.files) + len(surface.resources), MAX_FILES),
        "source bytes": (
            sum(map(len, (*surface.files.values(), *surface.resources.values()))),
            MAX_SOURCE_BYTES,
        ),
        "AST nodes": (nodes, MAX_AST_NODES),
        "sink count": (len(sinks), MAX_SINKS),
        "statement count": (len(statements), MAX_STATEMENTS),
    }
    errors.extend(
        f"{name} exceeds {maximum}"
        for name, (observed, maximum) in counts.items()
        if observed > maximum
    )


def _validate_surface_bounds(surface: _Surface) -> None:
    count = len(surface.files) + len(surface.resources)
    if count > MAX_FILES:
        raise SQLiteSupportabilityError("packaged file count exceeds 10,000")
    if any(
        not _safe_member_path(path)
        for path in (*surface.files.keys(), *surface.resources.keys())
    ):
        raise SQLiteSupportabilityError("packaged path is unsafe or overlong")
    size = sum(map(len, (*surface.files.values(), *surface.resources.values())))
    if size > MAX_SOURCE_BYTES:
        raise SQLiteSupportabilityError("source bytes exceeds 32 MiB")


def _file_evidence(surface: _Surface) -> list[dict[str, Any]]:
    return [
        {"path": path, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        for path, raw in sorted({**surface.files, **surface.resources}.items())
    ]


def _looks_like_sql(raw: bytes) -> bool:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(_SQL_PREFIX.match(text))


def _resource_is_sql(name: str, raw: bytes) -> bool:
    suffix = PurePosixPath(name).suffix.lower()
    return bool(raw.strip()) and (
        suffix in {".ddl", ".sql", ".sqlite"} or _looks_like_sql(raw)
    )


def _limit_evidence() -> dict[str, Any]:
    return {
        "files": MAX_FILES,
        "file_bytes": MAX_FILE_BYTES,
        "source_bytes": MAX_SOURCE_BYTES,
        "ast_nodes": MAX_AST_NODES,
        "sinks": MAX_SINKS,
        "statements": MAX_STATEMENTS,
        "sql_bytes": MAX_SQL_BYTES,
        "adapter_timeout_seconds": 120,
        "statement_timeout_seconds": 2,
        "statement_vm_operations": MAX_VM_OPERATIONS,
        "sqlite_limits": dict(LIMITS),
        "initialization": dict(INITIALIZATION),
    }


def _empty_analysis() -> dict[str, Any]:
    return {
        "statements": [],
        "sinks": [],
        "receiver_provenance": [],
        "resources": set(),
        "order_sequences": [],
        "unclassified_sql": [],
        "errors": [],
        "counts": {
            "ast_nodes": 0,
            "files": 0,
            "sinks": 0,
            "source_bytes": 0,
            "sql_statements": 0,
        },
    }


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("timestamp must use UTC Z suffix")
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
