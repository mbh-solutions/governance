from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping, Sequence


POLICY_ID = "sqlite-policy.v1"
MAX_VM_OPERATIONS = 10_000_000
CERTIFIED_SQLITE_IDENTITY = {
    "compile_options_sha256": "81ff1d58e1e36224109a46f61d60e58cf0add2f11e94ad7e864616142f7b2cb9",
    "enable_fts5": True,
    "version": "3.46.1",
}
ALLOWED_FUNCTIONS = frozenset(
    {"bm25", "coalesce", "highlight", "like", "match", "snippet"}
)
ALLOWED_PRAGMAS = frozenset({"foreign_keys", "foreign_key_check", "quick_check"})
ALLOWED_VIRTUAL_MODULES = frozenset({"fts5"})
_INTERNAL_RELATIONS = frozenset(
    {"sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema"}
)
SCHEMA_CLASSES = frozenset(
    {
        "CREATE_INDEX",
        "CREATE_TABLE",
        "CREATE_TRIGGER",
        "CREATE_VIEW",
        "CREATE_VIRTUAL_TABLE",
    }
)
PREPARED_CLASSES = frozenset({"DELETE", "INSERT", "PRAGMA", "SELECT", "UPDATE"})
LIMITS = {
    "SQLITE_LIMIT_ATTACHED": 0,
    "SQLITE_LIMIT_COLUMN": 2_000,
    "SQLITE_LIMIT_COMPOUND_SELECT": 500,
    "SQLITE_LIMIT_EXPR_DEPTH": 1_000,
    "SQLITE_LIMIT_FUNCTION_ARG": 127,
    "SQLITE_LIMIT_LENGTH": 2_097_152,
    "SQLITE_LIMIT_LIKE_PATTERN_LENGTH": 50_000,
    "SQLITE_LIMIT_SQL_LENGTH": 1_048_576,
    "SQLITE_LIMIT_TRIGGER_DEPTH": 100,
    "SQLITE_LIMIT_VARIABLE_NUMBER": 32_766,
    "SQLITE_LIMIT_VDBE_OP": 250_000,
    "SQLITE_LIMIT_WORKER_THREADS": 0,
}
INITIALIZATION = {
    "cache_size": -8192,
    "foreign_keys": "ON",
    "journal_mode": "MEMORY",
    "max_page_count": 16384,
    "recursive_triggers": "OFF",
    "temp_store": "MEMORY",
    "trusted_schema": "OFF",
}
POLICY = {
    "adapter_timeout_seconds": 120,
    "functions": sorted(ALLOWED_FUNCTIONS),
    "id": POLICY_ID,
    "initialization": INITIALIZATION,
    "limits": LIMITS,
    "pragmas": sorted(ALLOWED_PRAGMAS),
    "schema_classes": sorted(SCHEMA_CLASSES),
    "sqlite_identity": CERTIFIED_SQLITE_IDENTITY,
    "sqlite_max_exclusive": "4.0.0",
    "sqlite_minimum": "3.40.0",
    "statement_timeout_seconds": 2,
    "statement_vm_operations": MAX_VM_OPERATIONS,
    "virtual_modules": sorted(ALLOWED_VIRTUAL_MODULES),
}
POLICY_SHA256 = sha256(
    json.dumps(POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()

_LEADING_COMMENTS = re.compile(r"\A(?:\s+|--[^\n]*(?:\n|\Z)|/\*.*?\*/)*", re.S)
_PRAGMA = re.compile(r"^PRAGMA\s+([A-Za-z_][A-Za-z0-9_]*)", re.I)
_VIRTUAL_MODULE = re.compile(
    r"^CREATE\s+VIRTUAL\s+TABLE\b.*?\bUSING\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.I | re.S,
)
_BINDING_COUNT = re.compile(r"uses (\d+), and there (?:are|is) \d+ supplied")


class SQLitePolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Statement:
    path: str
    line: int
    sink: str
    sql: str
    sql_sha256: str
    selector: str | None = None


class _ProgressBound:
    def __init__(self) -> None:
        self.operations = 0
        self.deadline = time.monotonic()

    def reset(self) -> None:
        self.operations = 0
        self.deadline = time.monotonic() + 2

    def __call__(self) -> int:
        self.operations += 1_000
        return int(
            self.operations >= MAX_VM_OPERATIONS or time.monotonic() > self.deadline
        )


class _Authorizer:
    def __init__(self) -> None:
        self.functions: set[str] = set()
        self.sources: set[str] = set()
        self.internal_fts = False
        self.pending_relations: set[str] = set()
        self.allow_pending_reads = True
        self.relations = set(_INTERNAL_RELATIONS)

    def __call__(
        self,
        action: int,
        first: str | None,
        second: str | None,
        _database: str | None,
        _source: str | None,
    ) -> int:
        if _source:
            self.sources.add(_source)
        if action == sqlite3.SQLITE_FUNCTION:
            return self._function(second or first)
        if action == sqlite3.SQLITE_PRAGMA:
            return self._pragma(first)
        if action == sqlite3.SQLITE_CREATE_VTABLE:
            return self._virtual_module(second)
        if action == sqlite3.SQLITE_CREATE_TABLE:
            self.pending_relations.add((first or "").lower())
        if action == sqlite3.SQLITE_READ:
            return self._read(first)
        return (
            sqlite3.SQLITE_OK if action in _allowed_actions() else sqlite3.SQLITE_DENY
        )

    def _function(self, value: str | None) -> int:
        name = (value or "").lower()
        self.functions.add(name)
        return sqlite3.SQLITE_OK if name in ALLOWED_FUNCTIONS else sqlite3.SQLITE_DENY

    def _pragma(self, value: str | None) -> int:
        name = (value or "").lower()
        allowed = (
            name in ALLOWED_PRAGMAS or self.internal_fts and name == "data_version"
        )
        return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY

    def _virtual_module(self, value: str | None) -> int:
        return (
            sqlite3.SQLITE_OK
            if (value or "").lower() in ALLOWED_VIRTUAL_MODULES
            else sqlite3.SQLITE_DENY
        )

    def _read(self, value: str | None) -> int:
        name = (value or "").lower()
        return (
            sqlite3.SQLITE_OK
            if self.internal_fts
            or name in self.relations
            or self.allow_pending_reads
            and name in self.pending_relations
            else sqlite3.SQLITE_DENY
        )


def normalize_sql(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n").strip()


def split_sql_script(value: str) -> list[str]:
    statements: list[str] = []
    pending = ""
    for character in normalize_sql(value):
        pending += character
        if character == ";" and sqlite3.complete_statement(pending):
            statements.append(normalize_sql(pending))
            pending = ""
    if pending.strip():
        if not sqlite3.complete_statement(pending + ";"):
            raise SQLitePolicyError("executescript contains an incomplete statement")
        statements.append(normalize_sql(pending))
    return statements


def classify_statement(value: str) -> tuple[str, str | None]:
    sql = _without_comments(normalize_sql(value))
    upper = re.sub(r"\s+", " ", sql).upper()
    if _forbidden_prefix(upper):
        return "UNSUPPORTED", None
    if match := _VIRTUAL_MODULE.match(sql):
        return "CREATE_VIRTUAL_TABLE", match.group(1).lower()
    if re.match(r"^CREATE\s+(?:UNIQUE\s+)?INDEX\b", upper):
        return "CREATE_INDEX", None
    for name in ("TABLE", "VIEW", "TRIGGER"):
        if re.match(rf"^CREATE\s+{name}\b", upper):
            return f"CREATE_{name}", None
    if match := _PRAGMA.match(sql):
        return "PRAGMA", match.group(1).lower()
    for name in ("SELECT", "INSERT", "UPDATE", "DELETE"):
        if upper.startswith(name + " ") or upper == name:
            return _writable_schema_class(name, upper), None
    return "UNSUPPORTED", None


def sqlite_identity() -> dict[str, Any]:
    connection = sqlite3.connect(":memory:")
    try:
        options = sorted(
            str(row[0]) for row in connection.execute("PRAGMA compile_options")
        )
    finally:
        connection.close()
    encoded = "".join(f"{option}\n" for option in options).encode("utf-8")
    return {
        "version": sqlite3.sqlite_version,
        "compile_options_sha256": sha256(encoded).hexdigest(),
        "enable_fts5": "ENABLE_FTS5" in options,
    }


def prepare_statements(
    statements: Sequence[Statement],
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    identity = sqlite_identity()
    errors = _identity_errors(identity)
    identity["observed_functions"] = []
    if errors:
        return [], errors, identity
    authorizer = _Authorizer()
    progress = _ProgressBound()
    connection = _connection(authorizer, progress)
    evidence: list[dict[str, Any]] = []
    try:
        for statement in statements:
            error = _prepare_one(connection, authorizer, progress, statement)
            evidence.append(_statement_evidence(statement, error))
            if error:
                errors.append(error)
    finally:
        connection.close()
    identity["observed_functions"] = sorted(authorizer.functions)
    return evidence, errors, identity


def _connection(
    authorizer: _Authorizer, progress: _ProgressBound
) -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", cached_statements=0)
    connection.enable_load_extension(False)
    _set_limits(connection)
    for name, value in INITIALIZATION.items():
        connection.execute(f"PRAGMA {name}={value}").close()
    connection.set_progress_handler(progress, 1_000)
    connection.set_authorizer(authorizer)
    return connection


def _set_limits(connection: sqlite3.Connection) -> None:
    for name, value in LIMITS.items():
        category = getattr(sqlite3, name)
        connection.setlimit(category, value)
        if connection.getlimit(category) != value:
            raise SQLitePolicyError(f"SQLite limit did not bind: {name}")


def _prepare_one(
    connection: sqlite3.Connection,
    authorizer: _Authorizer,
    progress: _ProgressBound,
    statement: Statement,
) -> str | None:
    authorizer.relations = set(_schema_relation_names(connection))
    authorizer.pending_relations.clear()
    statement_class, detail = classify_statement(statement.sql)
    authorizer.allow_pending_reads = not (
        statement_class == "CREATE_TABLE" and _create_table_as_select(statement.sql)
    )
    if error := _classification_error(statement_class, detail):
        return error
    if statement_class == "CREATE_TABLE" and _has_deferred_default(statement.sql):
        return "function-bearing DEFAULT expressions cannot be authoritatively prepared"
    before = (
        _schema_objects(connection)
        if statement_class in SCHEMA_CLASSES
        else frozenset()
    )
    progress.reset()
    authorizer.internal_fts = statement_class == "CREATE_VIRTUAL_TABLE"
    try:
        if statement_class in SCHEMA_CLASSES:
            connection.execute(statement.sql).close()
            authorizer.relations = set(_schema_relation_names(connection))
            return _schema_validation_error(
                connection, authorizer, statement_class, before
            )
        else:
            _prepare_only(connection, statement.sql)
    except (sqlite3.DatabaseError, SQLitePolicyError) as exc:
        return f"{type(exc).__name__}: {exc}"
    finally:
        authorizer.internal_fts = False
        authorizer.pending_relations.clear()
        authorizer.allow_pending_reads = True
    return None


def _prepare_only(connection: sqlite3.Connection, sql: str) -> None:
    named = _validate_parameter_style(sql)
    if named:
        connection.execute("EXPLAIN " + sql, dict.fromkeys(named)).close()
        return
    try:
        connection.execute("EXPLAIN " + sql, ()).close()
    except sqlite3.ProgrammingError as exc:
        match = _BINDING_COUNT.search(str(exc))
        if match is None:
            raise
        count = int(match.group(1))
        if count > LIMITS["SQLITE_LIMIT_VARIABLE_NUMBER"]:
            raise SQLitePolicyError("SQL parameter count exceeds policy") from exc
        connection.execute("EXPLAIN " + sql, (None,) * count).close()


def _validate_parameter_style(sql: str) -> tuple[str, ...]:
    qmark, names, numbered = _parameter_tokens(sql)
    if numbered:
        raise SQLitePolicyError("numbered SQL parameters are unsupported")
    if qmark and names:
        raise SQLitePolicyError("mixed SQL parameter styles are unsupported")
    return tuple(sorted(names))


def _parameter_tokens(sql: str) -> tuple[bool, set[str], bool]:
    qmark = False
    names: set[str] = set()
    numbered = False
    index = 0
    while index < len(sql):
        skipped = _skip_noncode(sql, index)
        if skipped != index:
            index = skipped
            continue
        character = sql[index]
        if character == "?":
            qmark = True
            index += 1
            if index < len(sql) and sql[index].isdigit():
                numbered = True
            continue
        if character in ":@$":
            match = re.match(r"[^\W\d]\w*|[0-9]+", sql[index + 1 :])
            if match:
                token = match.group(0)
                numbered = numbered or token[0].isdigit()
                if not token[0].isdigit():
                    names.add(token)
                index += len(token) + 1
                continue
        index += 1
    return qmark, names, numbered


def _skip_noncode(sql: str, index: int) -> int:
    character = sql[index]
    if character in "'\"`":
        return _skip_quoted(sql, index, character)
    if character == "[":
        end = sql.find("]", index + 1)
        return len(sql) if end < 0 else end + 1
    if sql.startswith("--", index):
        end = sql.find("\n", index + 2)
        return len(sql) if end < 0 else end + 1
    if sql.startswith("/*", index):
        end = sql.find("*/", index + 2)
        return len(sql) if end < 0 else end + 2
    return index


def _skip_quoted(sql: str, index: int, quote: str) -> int:
    index += 1
    while index < len(sql):
        if sql[index] != quote:
            index += 1
            continue
        if index + 1 < len(sql) and sql[index + 1] == quote:
            index += 2
            continue
        return index + 1
    return len(sql)


def _has_deferred_default(sql: str) -> bool:
    code = _code_only(sql)
    return bool(
        re.search(r"\bDEFAULT\s*\(", code, re.I)
        or re.search(r"\bDEFAULT\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", code, re.I)
    )


def _create_table_as_select(sql: str) -> bool:
    depth = 0
    for token in re.findall(r"[A-Za-z_]+|[()]", _code_only(sql)):
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
        elif depth == 0 and token.upper() == "AS":
            return True
    return False


def _code_only(sql: str) -> str:
    characters = list(sql)
    index = 0
    while index < len(sql):
        skipped = _skip_noncode(sql, index)
        if skipped == index:
            index += 1
            continue
        characters[index:skipped] = " " * (skipped - index)
        index = skipped
    return "".join(characters)


def _classification_error(statement_class: str, detail: str | None) -> str | None:
    if statement_class == "PRAGMA" and detail not in ALLOWED_PRAGMAS:
        return f"PRAGMA is not allowed: {detail or 'unknown'}"
    if (
        statement_class == "CREATE_VIRTUAL_TABLE"
        and detail not in ALLOWED_VIRTUAL_MODULES
    ):
        return f"virtual-table module is not allowed: {detail or 'unknown'}"
    if statement_class not in SCHEMA_CLASSES | PREPARED_CLASSES:
        return "statement class is not allowed"
    return None


def _statement_evidence(statement: Statement, error: str | None) -> dict[str, Any]:
    return {
        "path": statement.path,
        "line": statement.line,
        "sink": statement.sink,
        "selector": statement.selector,
        "sql_sha256": statement.sql_sha256,
        "status": "PASS" if error is None else "BLOCK_TECHNICAL",
        "error": error,
    }


def _schema_objects(connection: sqlite3.Connection) -> frozenset[tuple[str, str, str]]:
    rows = connection.execute(
        "SELECT type, name, tbl_name FROM sqlite_schema "
        "WHERE type IN ('index', 'table', 'trigger', 'view')"
    )
    return frozenset((str(kind), str(name), str(table)) for kind, name, table in rows)


def _schema_relation_names(connection: sqlite3.Connection) -> frozenset[str]:
    return _INTERNAL_RELATIONS | frozenset(
        name.lower()
        for kind, name, _table in _schema_objects(connection)
        if kind in {"table", "view"}
    )


def _schema_validation_error(
    connection: sqlite3.Connection,
    authorizer: _Authorizer,
    statement_class: str,
    before: frozenset[tuple[str, str, str]],
) -> str | None:
    expected_type = {
        "CREATE_INDEX": "index",
        "CREATE_TABLE": "table",
        "CREATE_TRIGGER": "trigger",
        "CREATE_VIEW": "view",
        "CREATE_VIRTUAL_TABLE": "table",
    }[statement_class]
    created = sorted(
        item
        for item in _schema_objects(connection) - before
        if item[0] == expected_type
    )
    if not created:
        return "schema statement did not create a unique object"
    if statement_class == "CREATE_TABLE":
        return _table_validation_error(connection, authorizer, created[0][1])
    if statement_class == "CREATE_VIEW":
        return _view_validation_error(connection, created[0][1])
    if statement_class == "CREATE_TRIGGER":
        kind, trigger, target = created[0]
        assert kind == "trigger"
        return _trigger_validation_error(connection, authorizer, trigger, target)
    return None


def _table_validation_error(
    connection: sqlite3.Connection, authorizer: _Authorizer, table: str
) -> str | None:
    before = frozenset(authorizer.functions)
    error: str | None = None
    connection.execute("SAVEPOINT governance_schema_probe").close()
    try:
        connection.execute(f"INSERT INTO {_quote_identifier(table)} DEFAULT VALUES")
    except sqlite3.DatabaseError as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        connection.execute("ROLLBACK TO governance_schema_probe").close()
        connection.execute("RELEASE governance_schema_probe").close()
    return error if frozenset(authorizer.functions) - before else None


def _view_validation_error(connection: sqlite3.Connection, view: str) -> str | None:
    try:
        connection.execute(f"EXPLAIN SELECT * FROM {_quote_identifier(view)}").close()
    except sqlite3.DatabaseError as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def _trigger_validation_error(
    connection: sqlite3.Connection,
    authorizer: _Authorizer,
    trigger: str,
    target: str,
) -> str | None:
    quoted_target = _quote_identifier(target)
    try:
        cursor = connection.execute(f"SELECT * FROM {quoted_target} LIMIT 0")
        columns = tuple(str(item[0]) for item in cursor.description or ())
        cursor.close()
    except sqlite3.DatabaseError as exc:
        return f"{type(exc).__name__}: {exc}"
    update = ", ".join(
        f"{_quote_identifier(column)}={_quote_identifier(column)}" for column in columns
    )
    probes = [
        f"EXPLAIN INSERT INTO {quoted_target} DEFAULT VALUES",
        f"EXPLAIN DELETE FROM {quoted_target}",
    ]
    if update:
        probes.insert(1, f"EXPLAIN UPDATE {quoted_target} SET {update}")
    errors: list[str] = []
    for sql in probes:
        authorizer.sources.discard(trigger)
        try:
            connection.execute(sql).close()
        except sqlite3.DatabaseError as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        if trigger in authorizer.sources:
            return errors[-1] if errors else None
    return errors[-1] if errors else "trigger body cannot be prepared"


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _identity_errors(identity: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if not (3, 40, 0) <= sqlite3.sqlite_version_info < (4, 0, 0):
        errors.append(f"SQLite version is unsupported: {identity['version']}")
    if identity.get("enable_fts5") is not True:
        errors.append("SQLite compile option ENABLE_FTS5 is unavailable")
    if dict(identity) != CERTIFIED_SQLITE_IDENTITY:
        errors.append("SQLite identity differs from the certified toolchain")
    return errors


def _allowed_actions() -> frozenset[int]:
    names = {
        "SQLITE_CREATE_INDEX",
        "SQLITE_CREATE_TABLE",
        "SQLITE_CREATE_TRIGGER",
        "SQLITE_CREATE_VIEW",
        "SQLITE_CREATE_VTABLE",
        "SQLITE_DELETE",
        "SQLITE_FUNCTION",
        "SQLITE_INSERT",
        "SQLITE_PRAGMA",
        "SQLITE_READ",
        "SQLITE_REINDEX",
        "SQLITE_RECURSIVE",
        "SQLITE_SAVEPOINT",
        "SQLITE_SELECT",
        "SQLITE_TRANSACTION",
        "SQLITE_UPDATE",
    }
    return frozenset(
        value
        for name in names
        if isinstance(value := getattr(sqlite3, name, None), int)
    )


def _forbidden_prefix(upper: str) -> bool:
    return bool(
        re.match(
            r"^(?:ATTACH|DETACH|VACUUM|ALTER|DROP|REINDEX|ANALYZE|LOAD_EXTENSION)\b",
            upper,
        )
    )


def _writable_schema_class(name: str, upper: str) -> str:
    if name in {"INSERT", "UPDATE", "DELETE"} and re.search(
        r"\b(?:SQLITE_MASTER|SQLITE_SCHEMA)\b", upper
    ):
        return "UNSUPPORTED"
    return name


def _without_comments(value: str) -> str:
    match = _LEADING_COMMENTS.match(value)
    return value[match.end() if match else 0 :].lstrip()
