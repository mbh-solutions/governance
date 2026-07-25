from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from governance_eval.hashing import sha256_json
from governance_eval.sqlite_policy import CERTIFIED_SQLITE_IDENTITY, normalize_sql
from governance_eval.sqlite_supportability import (
    MAX_AST_NODES,
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_SINKS,
    MAX_SOURCE_BYTES,
    MAX_SQL_BYTES,
    MAX_STATEMENTS,
    SQLITE_PROFILE,
    STANDARD_PROFILE,
    SQLiteSupportabilityError,
    _Surface,
    _add_surface_file,
    _analyze_surface,
    _check_counts,
    _package_roots,
    _statements,
    discover_wheel_profile,
    discover_repository_profile,
    packaged_source_snapshot,
    run_sqlite_supportability,
    validate_profile_discovery,
    wheel_source_binding_errors,
    wheel_source_binding_errors_from_snapshot,
)


POSITIVE_SOURCE = b"""\
import sqlite3 as db
from pathlib import Path

SCHEMA = "CREATE TABLE docs(id INTEGER PRIMARY KEY, title TEXT);"
QUERIES = {"all": "SELECT coalesce(title, '') FROM docs", "one": "SELECT title FROM docs WHERE id = ?"}
TABLE = "docs"

def connect() -> db.Connection:
    return db.connect(":memory:")

def run(connection: db.Connection, selector: str) -> None:
    connection.executescript(SCHEMA)
    connection.execute("INSERT INTO docs(title) VALUES (?)", ("title",))
    connection.execute(QUERIES[selector], (1,))
    connection.execute("SELECT title FROM {table}".format(table=TABLE))
    connection.execute(Path(__file__).with_name("query.sql").read_text())
"""


class SQLiteSupportabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch(
            "governance_eval.sqlite_policy.sqlite_identity",
            side_effect=lambda: dict(CERTIFIED_SQLITE_IDENTITY),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_wheel_positive_controls_and_separate_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "fixture.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("package/database.py", POSITIVE_SOURCE)
                archive.writestr("package/query.sql", "SELECT title FROM docs;\r\n")

            result = run_sqlite_supportability(wheel)

        self.assertEqual(result["status"], "PASS")
        evidence = result["evidence"]
        self.assertEqual(evidence["gate_implementation"], "PASS")
        self.assertEqual(evidence["repo_sql_supportability"], "PASS")
        self.assertEqual(evidence["sql_behavior_proof"], "PASS")
        self.assertEqual(evidence["counts"]["sinks"], 5)
        self.assertEqual(evidence["counts"]["sql_statements"], 6)
        self.assertEqual(evidence["resources"], ["package/query.sql"])
        self.assertTrue(
            all(item["status"] == "PASS" for item in evidence["preparations"])
        )

    def test_static_analysis_blocks_unresolved_and_dynamic_sql(self) -> None:
        cases = {
            "f-string": b'import sqlite3\ndef run(c: sqlite3.Connection, table: str):\n c.execute(f"SELECT * FROM {table}")\n',
            "missing constant": b"import sqlite3\ndef run(c: sqlite3.Connection):\n c.execute(MISSING)\n",
            "runtime file": b"import sqlite3\nfrom pathlib import Path\ndef run(c: sqlite3.Connection, path: str):\n c.execute(Path(path).read_text())\n",
            "absent resource": b'import sqlite3\nfrom pathlib import Path\ndef run(c: sqlite3.Connection):\n c.execute(Path(__file__).with_name("missing.sql").read_text())\n',
            "unresolved receiver": b'def run(client):\n client.execute("SELECT 1")\n',
            "getattr": b'import sqlite3\ndef run(c: sqlite3.Connection):\n getattr(c, "execute")("SELECT 1")\n',
            "method alias": b'import sqlite3\ndef run(c: sqlite3.Connection):\n execute = c.execute\n execute("SELECT 1")\n',
            "imported method alias": b'from helper import execute\nexecute("SELECT 1")\n',
            "non-connect sqlite symbol": b'from sqlite3 import Binary\ndef run():\n c=Binary(b"x")\n c.execute("SELECT 1")\n',
            "fake return annotation": b'import sqlite3\ndef connect() -> FakeConnection:\n return object()\ndef run():\n c=connect()\n c.execute("SELECT 1")\n',
            "shadowed sqlite import": b'import sqlite3\nsqlite3 = object()\ndef run():\n c=sqlite3.connect(":memory:")\n c.execute("SELECT 1")\n',
            "shadowed Path import": b'import sqlite3\nfrom pathlib import Path\nPath = object()\ndef run(c: sqlite3.Connection):\n c.execute(Path(__file__).with_name("query.sql").read_text())\n',
            "function mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c: sqlite3.Connection, key):\n Q.update(runtime())\n c.execute(Q[key])\n',
            "conditional local constant": b'import sqlite3\ndef run(c: sqlite3.Connection, enabled):\n if enabled:\n  sql="SELECT 1"\n c.execute(sql)\n',
            "conditional receiver": b'import sqlite3\ndef run(enabled):\n if enabled:\n  c=sqlite3.connect(":memory:")\n c.execute("SELECT 1")\n',
            "class body": b'import sqlite3\nc=sqlite3.connect(":memory:")\nclass Bad:\n c.execute("SELECT 1")\n',
            "lambda": b'import sqlite3\nf=lambda c: c.execute("SELECT 1")\n',
            "stale module SQL": b'import sqlite3\nSQL="SELECT random()"\ndef run(c: sqlite3.Connection): c.execute(SQL)\nrun(sqlite3.connect(":memory:"))\nSQL="SELECT 1"\n',
            "subscript mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c: sqlite3.Connection, k):\n Q["x"]=runtime()\n c.execute(Q[k])\n',
            "helper mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate(): Q["x"]=runtime()\ndef run(c: sqlite3.Connection, k):\n mutate()\n c.execute(Q[k])\n',
            "helper alias mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate(): Q["x"]="SELECT random()"\ndef run(c: sqlite3.Connection):\n m=mutate\n m()\n c.execute(Q["x"])\n',
            "globals helper dispatch": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate(): Q["x"]="SELECT random()"\ndef run(c: sqlite3.Connection):\n globals()["mutate"]()\n c.execute(Q["x"])\n',
            "imported helper": b'import sqlite3\nfrom helper import mutate\ndef run(c: sqlite3.Connection):\n mutate()\n c.execute("SELECT 1")\n',
            "later sqlite import": b'import sqlite3\nimport fake as sqlite3\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "later Path import": b'import sqlite3\nfrom pathlib import Path\nimport fake as Path\ndef run(c: sqlite3.Connection): c.execute(Path(__file__).with_name("q.sql").read_text())\n',
            "shadowed module __file__": b'import sqlite3\nfrom pathlib import Path\n__file__="/tmp/evil.py"\ndef run(c: sqlite3.Connection): c.execute(Path(__file__).with_name("q.sql").read_text())\n',
            "shadowed argument __file__": b'import sqlite3\nfrom pathlib import Path\ndef run(c: sqlite3.Connection, __file__): c.execute(Path(__file__).with_name("q.sql").read_text())\n',
            "tuple method alias": b'import sqlite3\ndef run(c: sqlite3.Connection):\n (go,)=(c.execute,)\n go("SELECT 1")\n',
            "dunder dispatch": b'import sqlite3\ndef run(c: sqlite3.Connection): c.execute.__call__("SELECT 1")\n',
            "dynamic getattr": b'import sqlite3\nSINK="execute"\ndef run(c): getattr(c,SINK)("SELECT 1")\n',
            "forwarded method": b'import sqlite3\ndef run(c: sqlite3.Connection): forward(c.execute,"SELECT 1")\n',
            "mixed return receiver": b'import sqlite3\ndef make(enabled):\n if enabled: return sqlite3.connect(":memory:")\n return object()\ndef run():\n c=make(False)\n c.execute("SELECT 1")\n',
            "rebound return function": b'import sqlite3\ndef make(): return sqlite3.connect(":memory:")\nmake=fake\nc=make()\nc.execute("SELECT 1")\n',
            "connect factory": b'import sqlite3\ndef run():\n c=sqlite3.connect(":memory:", factory=Fake)\n c.execute("SELECT 1")\n',
            "cursor factory": b'import sqlite3\ndef run(c: sqlite3.Connection):\n q=c.cursor(factory=Fake)\n q.execute("SELECT 1")\n',
            "class decorator": b'import sqlite3\nc=sqlite3.connect(":memory:")\n@c.execute("SELECT 1")\nclass C: pass\n',
            "for shadow": b'import sqlite3\nfor sqlite3 in values: pass\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "with shadow": b'import sqlite3\nwith fake as sqlite3: pass\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "except shadow": b'import sqlite3\ntry: pass\nexcept Exception as sqlite3: pass\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "wildcard shadow": b'import sqlite3\nfrom evil import *\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "globals update": b'import sqlite3\nglobals().update(sqlite3=fake)\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "setattr connect": b'import sqlite3\nsetattr(sqlite3,"connect",fake)\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "exec shadow": b'import sqlite3\nexec("sqlite3=fake")\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "decorated receiver factory": b'import sqlite3\n@deco\ndef make()->sqlite3.Connection: return sqlite3.connect(":memory:")\nc=make()\nc.execute("SELECT 1")\n',
            "no-import getattr": b'getattr(client,"execute")("SELECT 1")\n',
            "unknown helper argument": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection,fn):\n fn()\n c.execute(Q["x"])\n',
            "unknown helper attribute": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection):\n helper.mutate()\n c.execute(Q["x"])\n',
            "imported helper attribute": b'import sqlite3\nimport helper\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection):\n helper.mutate()\n c.execute(Q["x"])\n',
            "nested schema owner": b'import sqlite3\ndef outer():\n def _schema(c:sqlite3.Connection): c.execute("CREATE TABLE t(x)")\ndef run(c:sqlite3.Connection):\n _schema(c)\n c.execute("SELECT * FROM t")\n',
            "cross-class schema owner": b'import sqlite3\nclass A:\n def _schema(self,c:sqlite3.Connection): c.execute("CREATE TABLE t(x)")\nclass B:\n def run(self,c:sqlite3.Connection):\n  self._schema(c)\n  c.execute("SELECT * FROM t")\n',
            "nested mapping alias mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\nA=(Q,)\ndef run(c:sqlite3.Connection):\n A[0]["x"]="SELECT random()"\n c.execute(Q["x"])\n',
            "unbound mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection):\n dict.__setitem__(Q,"x","SELECT random()")\n c.execute(Q["x"])\n',
            "vars shadow": b'import sqlite3\nvars()["sqlite3"]=fake\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\n',
            "globals nested mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\nglobals()["Q"]["x"]="SELECT random()"\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "vars nested mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\nvars()["Q"]["x"]="SELECT random()"\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "BOM SQL": 'def run(client): client.execute("\ufeffSELECT 1")\n'.encode(),
            "VALUES SQL": b'def run(client): client.execute("VALUES (1)")\n',
            "BEGIN SQL": b'def run(client): client.execute("BEGIN")\n',
            "leading empty SQL": b'def run(client): client.execute(";SELECT 1")\n',
            "bytes resource": b'import sqlite3\nfrom pathlib import Path\ndef run(c: sqlite3.Connection): c.execute(Path(__file__).with_name("q.sql").read_bytes())\n',
            "no-import wrapper": b'def call(fn, sql): fn(sql)\ndef run(c): call(c.execute, "SELECT random()")\n',
            "no-import method alias": b'def run(c):\n fn=c.execute\n fn("SELECT random()")\n',
            "no-import dunder dispatch": b'def run(c): c.execute.__call__("SELECT random()")\n',
            "mapping ior": b'import sqlite3\nQ={"x":"SELECT 1"}\nQ.__ior__({"x":"SELECT random()"})\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "unused helper ior": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate(): Q.__ior__({"x":"SELECT random()"})\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "module walrus": b'import sqlite3\nQ={"x":"SELECT 1"}\n(Q:={"x":"SELECT random()"})\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "globals pop mapping": b'import sqlite3\nQ={"x":"SELECT 1"}\nglobals().pop("Q")\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "globals setdefault mapping": b'import sqlite3\nQ={"x":"SELECT 1"}\nglobals().setdefault("Q", {"x":"SELECT random()"})\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "class mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\nclass Mutate:\n Q.update(x="SELECT random()")\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "decorator mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\n@Q.update({"x":"SELECT random()"})\ndef mutate(): pass\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "unused mapping mutator": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate(): Q.update(x="SELECT random()")\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "global mapping reassign": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate():\n global Q\n Q={"x":"SELECT random()"}\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
            "nested mapping mutation": b'import sqlite3\nQ={"x":"SELECT 1"}\nA={"q":Q}\ndef mutate(): Q.update(x="SELECT random()")\ndef run(c:sqlite3.Connection): c.execute(A["q"]["x"])\n',
            "type dict dispatch": b'def run(c): type(c).__dict__["execute"](c,"SELECT random()")\n',
            "getattribute dispatch": b'def run(c): c.__getattribute__("execute")("SELECT random()")\n',
            "vars type dispatch": b'def run(c): vars(type(c))["execute"](c,"SELECT random()")\n',
            "comprehension mapping shadow": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef mutate(items):\n [None for Q in items]\n Q.update(x="SELECT random()")\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
        }
        for label, source in cases.items():
            with self.subTest(label=label):
                analysis = _analyze_surface(
                    _Surface({"package/database.py": source}, {})
                )
                self.assertTrue(analysis["errors"])

    def test_module_and_async_sinks_are_scanned(self) -> None:
        source = b'import sqlite3\nc=sqlite3.connect(":memory:")\nc.execute("SELECT 1")\nasync def run(connection: sqlite3.Connection):\n connection.execute("SELECT 2")\n'

        analysis = _analyze_surface(_Surface({"package/database.py": source}, {}))

        self.assertEqual(analysis["errors"], [])
        self.assertEqual(analysis["counts"]["sinks"], 2)

        rogue = _analyze_surface(
            _Surface(
                {"package/database.py": source},
                {
                    "package/rogue.sql": b"WITH hidden AS (SELECT 1) SELECT * FROM hidden"
                },
            )
        )
        self.assertIn("package/rogue.sql", rogue["unclassified_sql"])

    def test_cross_function_and_conditional_schema_order_block(self) -> None:
        sources = (
            b'import sqlite3\ndef _schema(c: sqlite3.Connection):\n c.execute("CREATE TABLE docs(value TEXT)")\ndef _query(c: sqlite3.Connection):\n c.execute("SELECT value FROM docs")\ndef run(c: sqlite3.Connection):\n _query(c)\n _schema(c)\n',
            b'import sqlite3\ndef _schema(c: sqlite3.Connection):\n c.execute("CREATE TABLE docs(value TEXT)")\ndef _query(c: sqlite3.Connection):\n c.execute("SELECT value FROM docs")\ndef run(c: sqlite3.Connection, enabled):\n if enabled:\n  _schema(c)\n _query(c)\n',
            b'import sqlite3\ndef run(c: sqlite3.Connection, enabled):\n enabled and c.execute("CREATE TABLE docs(value TEXT)")\n c.execute("SELECT value FROM docs")\n',
            b'import sqlite3\ndef run(c: sqlite3.Connection):\n try: c.execute("CREATE TABLE docs(value TEXT)")\n except Exception: pass\n c.execute("SELECT value FROM docs")\n',
            b'import sqlite3\ndef run(c: sqlite3.Connection, items):\n [c.execute("CREATE TABLE docs(value TEXT)") for _ in items]\n c.execute("SELECT value FROM docs")\n',
            b'import sqlite3\ndef _schema(c: sqlite3.Connection): c.execute("CREATE TABLE docs(value TEXT)")\ndef _query(c: sqlite3.Connection): c.execute("SELECT value FROM docs")\ndef run(c: sqlite3.Connection, enabled):\n enabled and _schema(c)\n _query(c)\n',
            b'import sqlite3\nQ={"a":"CREATE TABLE a(value TEXT)","b":"CREATE TABLE b(value TEXT)"}\ndef run(c: sqlite3.Connection, key): c.execute(Q[key])\n',
        )
        for source in sources:
            with self.subTest(source=source):
                with tempfile.TemporaryDirectory() as directory:
                    wheel = Path(directory) / "fixture.whl"
                    with zipfile.ZipFile(wheel, "w") as archive:
                        archive.writestr("package/database.py", source)
                    result = run_sqlite_supportability(wheel)
                self.assertEqual(result["status"], "BLOCK_TECHNICAL")
                self.assertTrue(
                    any("order" in error for error in result["evidence"]["errors"])
                )

    def test_proved_cross_function_schema_order_passes(self) -> None:
        source = b'import sqlite3\ndef _query(c: sqlite3.Connection):\n c.execute("SELECT value FROM docs")\ndef _schema(c: sqlite3.Connection):\n c.execute("CREATE TABLE docs(value TEXT)")\ndef run(c: sqlite3.Connection):\n _schema(c)\n _query(c)\n'
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / "fixture.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("package/database.py", source)
            result = run_sqlite_supportability(wheel)

        self.assertEqual(result["status"], "PASS")

    def test_cross_module_static_mapping_mutation_blocks(self) -> None:
        surface = _Surface(
            {
                "package/a.py": b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n',
                "package/b.py": b'from package.a import Q\nQ.update(x="SELECT random()")\n',
            },
            {},
        )

        analysis = _analyze_surface(surface)

        self.assertTrue(
            any(
                "static SQL mapping is mutable" in error for error in analysis["errors"]
            )
        )

    def test_local_static_mapping_shadows_do_not_mutate_module_mapping(self) -> None:
        source = b'import sqlite3\nQ={"x":"SELECT 1"}\ndef local_assignment():\n Q={"x":"SELECT random()"}\n return Q\ndef local_parameter(Q): Q.update(x="SELECT random()")\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n'

        analysis = _analyze_surface(_Surface({"package/database.py": source}, {}))

        self.assertEqual(analysis["errors"], [])
        self.assertEqual([item.sql for item in analysis["statements"]], ["SELECT 1"])

    def test_comprehension_target_does_not_leak_into_outer_scope(self) -> None:
        source = b'import sqlite3\nQ={"x":"SELECT 1"}\ndef consume(items): [None for Q in items]\ndef run(c:sqlite3.Connection): c.execute(Q["x"])\n'

        analysis = _analyze_surface(_Surface({"package/database.py": source}, {}))

        self.assertEqual(analysis["errors"], [])
        self.assertEqual([item.sql for item in analysis["statements"]], ["SELECT 1"])

        first_iterator = b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection): [Q for Q in c.execute(Q["x"])]\n'
        first_iterator_analysis = _analyze_surface(
            _Surface({"package/database.py": first_iterator}, {})
        )
        self.assertEqual(first_iterator_analysis["errors"], [])
        self.assertEqual(
            [item.sql for item in first_iterator_analysis["statements"]], ["SELECT 1"]
        )

        local_mutation = b'import sqlite3\nQ={"x":"SELECT 1"}\ndef consume(value): pass\ndef shadow(items):\n [Q.update(x="SELECT random()") for Q in items]\n [consume(Q) for Q in items]\ndef run(c:sqlite3.Connection):\n shadow([])\n c.execute(Q["x"])\n'
        local_mutation_analysis = _analyze_surface(
            _Surface({"package/database.py": local_mutation}, {})
        )
        self.assertEqual(local_mutation_analysis["errors"], [])
        self.assertEqual(
            [item.sql for item in local_mutation_analysis["statements"]], ["SELECT 1"]
        )

        aliased_mutation = local_mutation.replace(b"shadow([])", b"shadow([Q])")
        aliased_analysis = _analyze_surface(
            _Surface({"package/database.py": aliased_mutation}, {})
        )
        self.assertTrue(aliased_analysis["errors"])

        shadowed_sink = b'import sqlite3\nQ={"x":"SELECT 1"}\ndef run(c:sqlite3.Connection, items): [c.execute(Q["x"]) for Q in items]\n'
        blocked = _analyze_surface(_Surface({"package/database.py": shadowed_sink}, {}))
        self.assertTrue(blocked["errors"])

    def test_discovery_requires_explicit_profile_and_committed_runtime_sql(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root, POSITIVE_SOURCE, "SELECT title FROM docs;\n")
            discovery = discover_repository_profile(root)
            self.assertEqual(discovery["required_profile"], SQLITE_PROFILE)
            validate_profile_discovery(discovery, selected_profile=SQLITE_PROFILE)
            with self.assertRaisesRegex(SQLiteSupportabilityError, "trusted opt-in"):
                validate_profile_discovery(discovery, selected_profile=STANDARD_PROFILE)

            subprocess.run(
                ["git", "rm", "--cached", "src/package/query.sql"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            (root / "src/package/query.sql").write_text(
                "SELECT changed FROM docs;\n", encoding="utf-8"
            )
            uncommitted = discover_repository_profile(root)
            self.assertIn(
                "referenced SQL resource is not committed: src/package/query.sql",
                uncommitted["errors"],
            )

    def test_untracked_sqlite_source_and_referenced_ignored_sql_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root, b"VALUE = 1\n", None)
            source = root / "src/package/database.py"
            subprocess.run(
                ["git", "rm", "--cached", "src/package/database.py"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            source.write_bytes(POSITIVE_SOURCE)
            discovery = discover_repository_profile(root)
            self.assertIn(
                "SQLite source is not committed: src/package/database.py",
                discovery["errors"],
            )

            subprocess.run(
                ["git", "add", "src/package/database.py"], cwd=root, check=True
            )
            subprocess.run(["git", "commit", "-qm", "source"], cwd=root, check=True)
            (root / ".gitignore").write_text("*.sql\n", encoding="utf-8")
            (root / "src/package/query.sql").write_text("SELECT 1;\n", encoding="utf-8")
            ignored = discover_repository_profile(root)
            self.assertIn(
                "referenced SQL resource is not committed: src/package/query.sql",
                ignored["errors"],
            )

    def test_receipt_mutation_and_all_hard_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root, b"VALUE = 1\n", None)
            discovery = discover_repository_profile(root)
            mutation = json.loads(json.dumps(discovery))
            mutation["required_profile"] = SQLITE_PROFILE
            with self.assertRaisesRegex(SQLiteSupportabilityError, "receipt"):
                validate_profile_discovery(mutation, selected_profile=SQLITE_PROFILE)

            contradiction = json.loads(json.dumps(discovery))
            contradiction.update(
                {
                    "sqlite_detected": True,
                    "sinks": [
                        {
                            "path": "src/package/database.py",
                            "line": 1,
                            "sink": "execute",
                        }
                    ],
                    "receipt_sha256": "",
                }
            )
            contradiction["receipt_sha256"] = sha256_json(contradiction)
            with self.assertRaisesRegex(SQLiteSupportabilityError, "contradictory"):
                validate_profile_discovery(
                    contradiction, selected_profile=STANDARD_PROFILE
                )

            for mutation in ("inventory", "timing"):
                hostile = json.loads(json.dumps(discovery))
                if mutation == "inventory":
                    hostile.update(
                        {
                            "required_profile": SQLITE_PROFILE,
                            "sqlite_detected": True,
                            "files_scanned": 0,
                            "sinks": [
                                {
                                    "path": "ghost.py",
                                    "line": 1,
                                    "sink": "execute",
                                }
                            ],
                        }
                    )
                else:
                    hostile["started_at"] = "2026-07-19T12:00:01Z"
                    hostile["completed_at"] = "2026-07-19T12:00:00Z"
                hostile["receipt_sha256"] = ""
                hostile["receipt_sha256"] = sha256_json(hostile)
                with self.assertRaises(SQLiteSupportabilityError):
                    validate_profile_discovery(
                        hostile, selected_profile=str(hostile["required_profile"])
                    )

        files: dict[str, bytes] = {}
        resources: dict[str, bytes] = {}
        _add_surface_file(files, resources, "at.py", b"x" * MAX_FILE_BYTES)
        with self.assertRaisesRegex(SQLiteSupportabilityError, "2 MiB"):
            _add_surface_file(files, resources, "over.py", b"x" * (MAX_FILE_BYTES + 1))

        errors: list[str] = []
        _check_counts(
            _Surface({str(index): b"" for index in range(MAX_FILES)}, {}),
            MAX_AST_NODES,
            [{}] * MAX_SINKS,
            [object()] * MAX_STATEMENTS,
            errors,
        )
        self.assertEqual(errors, [])
        for label, surface, nodes, sinks, statements in (
            (
                "file count",
                _Surface({str(i): b"" for i in range(MAX_FILES + 1)}, {}),
                0,
                [],
                [],
            ),
            (
                "source bytes",
                _Surface({"x": b"x" * (MAX_SOURCE_BYTES + 1)}, {}),
                0,
                [],
                [],
            ),
            ("AST nodes", _Surface({}, {}), MAX_AST_NODES + 1, [], []),
            ("sink count", _Surface({}, {}), 0, [{}] * (MAX_SINKS + 1), []),
            (
                "statement count",
                _Surface({}, {}),
                0,
                [],
                [object()] * (MAX_STATEMENTS + 1),
            ),
        ):
            with self.subTest(label=label):
                observed: list[str] = []
                _check_counts(surface, nodes, sinks, statements, observed)
                self.assertTrue(any(item.startswith(label) for item in observed))

        with self.assertRaisesRegex(SQLiteSupportabilityError, "file count"):
            _analyze_surface(
                _Surface({str(index): b"" for index in range(MAX_FILES + 1)}, {})
            )
        with self.assertRaisesRegex(SQLiteSupportabilityError, "source bytes"):
            _analyze_surface(_Surface({"x.py": b"x" * (MAX_SOURCE_BYTES + 1)}, {}))

        class _Node:
            lineno = 1
            args: list[object] = [object()]

        sql = "S" * MAX_SQL_BYTES
        statements, _resources = _statements("x.py", _Node(), "execute", sql)  # type: ignore[arg-type]
        self.assertEqual(len(statements[0].sql.encode()), MAX_SQL_BYTES)
        with self.assertRaisesRegex(SQLiteSupportabilityError, "1 MiB"):
            _statements("x.py", _Node(), "execute", sql + "S")  # type: ignore[arg-type]
        self.assertEqual(normalize_sql("SELECT\r\n1"), normalize_sql("SELECT\r1"))

    def test_nested_package_paths_and_wheel_source_binding_fail_closed(self) -> None:
        sqlite_source = (
            b'import sqlite3\ndef run(c: sqlite3.Connection):\n c.execute("SELECT 1")\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._repository(root, b"VALUE = 1\n", None)
            nested = root / "src/package/build/database.py"
            nested.parent.mkdir(parents=True)
            nested.write_bytes(sqlite_source)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "nested"], cwd=root, check=True)

            discovery = discover_repository_profile(root)
            self.assertEqual(discovery["required_profile"], SQLITE_PROFILE)
            self.assertTrue(discovery["sqlite_detected"])

            with tempfile.SpooledTemporaryFile() as wheel_buffer:
                with zipfile.ZipFile(wheel_buffer, "w") as archive:
                    archive.writestr("package/database.py", b"VALUE = 1\n")
                    archive.writestr("package/generated.py", sqlite_source)
                wheel_buffer.seek(0)
                wheel_bytes = wheel_buffer.read()
            self.assertEqual(
                discover_wheel_profile(wheel_bytes)["required_profile"], SQLITE_PROFILE
            )
            self.assertIn(
                "wheel runtime member is not committed source: package/generated.py",
                wheel_source_binding_errors(root, wheel_bytes),
            )

            with tempfile.SpooledTemporaryFile() as wheel_buffer:
                with zipfile.ZipFile(wheel_buffer, "w") as archive:
                    archive.writestr("package/query.sql", "SELECT 1\n")
                wheel_buffer.seek(0)
                normalized_wheel = wheel_buffer.read()
            self.assertEqual(
                wheel_source_binding_errors_from_snapshot(
                    {"package/query.sql": b"SELECT 1\r\n"}, normalized_wheel
                ),
                [],
            )

    def test_sealed_source_snapshot_needs_no_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "src/package"
            package.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nname="fixture"\nversion="0.0.1"\n'
                '[tool.setuptools.packages.find]\nwhere=["src"]\n',
                encoding="utf-8",
            )
            package.joinpath("database.py").write_bytes(POSITIVE_SOURCE)
            package.joinpath("query.sql").write_text("SELECT 1\r\n", encoding="utf-8")
            sources = packaged_source_snapshot(root)
            with tempfile.SpooledTemporaryFile() as wheel_buffer:
                with zipfile.ZipFile(wheel_buffer, "w") as archive:
                    archive.writestr("package/database.py", POSITIVE_SOURCE)
                    archive.writestr("package/query.sql", "SELECT 1\n")
                wheel_buffer.seek(0)
                wheel = wheel_buffer.read()

            self.assertEqual(
                wheel_source_binding_errors_from_snapshot(sources, wheel), []
            )

    def test_hostile_wheel_and_function_evidence_return_typed_block(self) -> None:
        cases = {
            "compiled Python": {"package/generated.pyc": b"compiled"},
            "operator function": {
                "package/database.py": b"import sqlite3\ndef run(c: sqlite3.Connection): c.execute(\"SELECT '{}' -> '$.x'\")\n"
            },
        }
        for label, members in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                wheel = Path(directory) / "fixture.whl"
                with zipfile.ZipFile(wheel, "w") as archive:
                    for name, content in members.items():
                        archive.writestr(name, content)
                result = run_sqlite_supportability(wheel)
                self.assertEqual(result["status"], "BLOCK_TECHNICAL")
                self.assertEqual(result["evidence"]["gate_implementation"], "PASS")

    def test_package_root_escape_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                '[project]\nname="fixture"\nversion="0.0.1"\n'
                '[tool.setuptools.packages.find]\nwhere=["../outside"]\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SQLiteSupportabilityError, "escapes"):
                _package_roots(root)

    def _repository(self, root: Path, source: bytes, sql: str | None) -> None:
        (root / "src/package").mkdir(parents=True)
        (root / "pyproject.toml").write_text(
            '[project]\nname="fixture"\nversion="0.0.1"\n'
            '[tool.setuptools.packages.find]\nwhere=["src"]\n',
            encoding="utf-8",
        )
        (root / "src/package/database.py").write_bytes(source)
        if sql is not None:
            (root / "src/package/query.sql").write_text(sql, encoding="utf-8")
        for command in (
            ("init", "-q"),
            ("config", "user.email", "governance@example.invalid"),
            ("config", "user.name", "Governance Test"),
            ("add", "."),
            ("commit", "-qm", "fixture"),
        ):
            subprocess.run(["git", *command], cwd=root, check=True, timeout=10)


if __name__ == "__main__":
    unittest.main()
