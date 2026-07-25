from __future__ import annotations

import sqlite3
import time
import unittest
from hashlib import sha256
from unittest import mock

from governance_eval.sqlite_policy import (
    CERTIFIED_SQLITE_IDENTITY,
    INITIALIZATION,
    LIMITS,
    MAX_VM_OPERATIONS,
    POLICY_SHA256,
    Statement,
    _Authorizer,
    _ProgressBound,
    _connection,
    classify_statement,
    normalize_sql,
    prepare_statements,
    split_sql_script,
)


def _statement(sql: str, line: int = 1, sink: str = "execute") -> Statement:
    normalized = normalize_sql(sql)
    return Statement(
        path="package/database.py",
        line=line,
        sink=sink,
        sql=normalized,
        sql_sha256=sha256(normalized.encode()).hexdigest(),
    )


class SQLitePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch(
            "governance_eval.sqlite_policy.sqlite_identity",
            side_effect=lambda: dict(CERTIFIED_SQLITE_IDENTITY),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_prepares_complete_allowed_surface_and_records_functions(self) -> None:
        statements = [
            _statement(
                "CREATE TABLE IF NOT EXISTS docs("
                "id TEXT PRIMARY KEY, title TEXT UNIQUE, body TEXT)"
            ),
            _statement("CREATE INDEX docs_title ON docs(title)", 2),
            _statement("CREATE VIEW doc_titles AS SELECT title FROM docs", 3),
            _statement(
                "CREATE TRIGGER docs_touch AFTER INSERT ON docs BEGIN "
                "UPDATE docs SET title = NEW.title WHERE id = NEW.id; END",
                4,
            ),
            _statement("CREATE VIRTUAL TABLE docs_fts USING fts5(title, body)", 5),
            _statement("INSERT INTO docs(title, body) VALUES (?, ?)", 6),
            _statement("UPDATE docs SET title = :title WHERE id = :id", 7),
            _statement("DELETE FROM docs WHERE id = ?", 8),
            _statement("SELECT coalesce(title, '') FROM docs WHERE title LIKE ?", 9),
            _statement(
                "SELECT bm25(docs_fts), highlight(docs_fts, 0, '[', ']'), "
                "snippet(docs_fts, 1, '[', ']', '...', 8) "
                "FROM docs_fts WHERE docs_fts MATCH ?",
                10,
            ),
            _statement("PRAGMA foreign_key_check", 11),
            _statement("PRAGMA quick_check", 12),
        ]

        evidence, errors, identity = prepare_statements(statements)

        self.assertEqual(errors, [])
        self.assertTrue(all(item["status"] == "PASS" for item in evidence))
        self.assertEqual(
            identity["observed_functions"],
            ["bm25", "coalesce", "highlight", "like", "match", "snippet"],
        )
        self.assertRegex(POLICY_SHA256, r"^[0-9a-f]{64}$")

    def test_default_deny_controls_block(self) -> None:
        cases = {
            "function": "SELECT abs(1)",
            "pragma": "PRAGMA journal_mode",
            "virtual table": "CREATE VIRTUAL TABLE spatial USING rtree(id, x1, x2)",
            "attach": "ATTACH DATABASE 'outside.db' AS outside",
            "detach": "DETACH DATABASE outside",
            "vacuum": "VACUUM",
            "alter": "ALTER TABLE docs ADD COLUMN extra TEXT",
            "drop": "DROP TABLE docs",
            "extension": "SELECT load_extension('outside')",
            "writable schema": "PRAGMA writable_schema=ON",
            "json_each eponymous table": "SELECT * FROM json_each('[1,2]')",
            "json_tree eponymous table": "SELECT * FROM json_tree('{}')",
            "pragma eponymous table": "SELECT * FROM pragma_database_list",
        }
        for label, sql in cases.items():
            with self.subTest(label=label):
                evidence, errors, _identity = prepare_statements([_statement(sql)])
                self.assertTrue(errors)
                self.assertEqual(evidence[0]["status"], "BLOCK_TECHNICAL")

    def test_schema_order_and_parameter_styles_fail_closed(self) -> None:
        order = [
            _statement("CREATE INDEX missing_index ON missing_table(value)"),
            _statement("CREATE TABLE missing_table(value TEXT)", 2),
        ]
        evidence, errors, _identity = prepare_statements(order)
        self.assertTrue(errors)
        self.assertEqual(evidence[0]["status"], "BLOCK_TECHNICAL")

        for sql in (
            "SELECT ?1",
            "SELECT '/*', ?1, '*/'",
            "SELECT ? + :named",
            "SELECT ? + :é",
            "SELECT FROM",
        ):
            with self.subTest(sql=sql):
                evidence, errors, _identity = prepare_statements([_statement(sql)])
                self.assertTrue(errors)
                self.assertEqual(evidence[0]["status"], "BLOCK_TECHNICAL")

    def test_schema_ddl_and_index_names_cannot_admit_eponymous_tables(self) -> None:
        cases = (
            [_statement("CREATE TABLE t AS SELECT * FROM json_each('[1]')")],
            [_statement("CREATE TABLE json_each AS SELECT * FROM json_each('[1]')")],
            [_statement("CREATE TABLE json_tree AS SELECT * FROM json_tree('{}')")],
            [
                _statement("CREATE TABLE docs(id INTEGER PRIMARY KEY)"),
                _statement("CREATE INDEX json_each ON docs(id)", 2),
                _statement("SELECT * FROM json_each('[1]')", 3),
            ],
        )
        for statements in cases:
            with self.subTest(sql=statements[-1].sql):
                evidence, errors, _identity = prepare_statements(statements)
                self.assertTrue(errors)
                self.assertEqual(evidence[-1]["status"], "BLOCK_TECHNICAL")

        allowed = [
            _statement("CREATE TABLE source(value TEXT)"),
            _statement("CREATE TABLE copied AS SELECT value FROM source", 2),
            _statement("SELECT value FROM copied", 3),
        ]
        evidence, errors, _identity = prepare_statements(allowed)
        self.assertEqual(errors, [])
        self.assertTrue(all(item["status"] == "PASS" for item in evidence))

    def test_deferred_schema_functions_and_duplicate_noops_fail_closed(self) -> None:
        cases = (
            [
                _statement("CREATE TABLE t(value TEXT DEFAULT(random()))"),
            ],
            [
                _statement("CREATE TABLE t(value TEXT)"),
                _statement("CREATE VIEW v AS SELECT random() FROM t", 2),
            ],
            [
                _statement("CREATE TABLE t(value TEXT)"),
                _statement(
                    "CREATE TRIGGER tr AFTER INSERT ON t BEGIN SELECT random(); END",
                    2,
                ),
            ],
            [
                _statement("CREATE TABLE IF NOT EXISTS t(value TEXT)"),
                _statement(
                    "CREATE TABLE IF NOT EXISTS t(value TEXT DEFAULT(random()))",
                    2,
                ),
            ],
        )
        for statements in cases:
            with self.subTest(sql=statements[-1].sql):
                evidence, errors, _identity = prepare_statements(statements)
                self.assertTrue(errors)
                self.assertEqual(evidence[-1]["status"], "BLOCK_TECHNICAL")

        allowed = [
            _statement("CREATE TABLE t(value TEXT)"),
            _statement("CREATE VIEW v AS SELECT coalesce(value, '') FROM t", 2),
            _statement(
                "CREATE TRIGGER tr AFTER INSERT ON t "
                "BEGIN SELECT coalesce(NEW.value, ''); END",
                3,
            ),
        ]
        evidence, errors, identity = prepare_statements(allowed)
        self.assertEqual(errors, [])
        self.assertTrue(all(item["status"] == "PASS" for item in evidence))
        self.assertEqual(identity["observed_functions"], ["coalesce"])

    def test_noncertified_sqlite_identity_blocks_before_preparation(self) -> None:
        hostile = {**CERTIFIED_SQLITE_IDENTITY, "version": "3.50.4"}
        with mock.patch(
            "governance_eval.sqlite_policy.sqlite_identity", return_value=hostile
        ):
            evidence, errors, identity = prepare_statements([_statement("SELECT 1")])

        self.assertEqual(evidence, [])
        self.assertEqual(identity, hostile)
        self.assertEqual(identity["observed_functions"], [])
        self.assertIn("SQLite identity differs from the certified toolchain", errors)

    def test_classifier_scripts_and_newline_hashes_are_deterministic(self) -> None:
        expected = {
            "CREATE TABLE t(value TEXT)": "CREATE_TABLE",
            "CREATE UNIQUE INDEX i ON t(value)": "CREATE_INDEX",
            "CREATE VIEW v AS SELECT value FROM t": "CREATE_VIEW",
            "CREATE TRIGGER x AFTER INSERT ON t BEGIN SELECT 1; END": "CREATE_TRIGGER",
            "CREATE VIRTUAL TABLE f USING fts5(value)": "CREATE_VIRTUAL_TABLE",
            "PRAGMA foreign_keys": "PRAGMA",
            "SELECT 1": "SELECT",
            "INSERT INTO t VALUES (?)": "INSERT",
            "UPDATE t SET value=?": "UPDATE",
            "DELETE FROM t": "DELETE",
        }
        self.assertEqual(
            {sql: classify_statement(sql)[0] for sql in expected},
            expected,
        )
        script = "CREATE TABLE t(value TEXT);\r\nINSERT INTO t VALUES ('x');\r"
        self.assertEqual(len(split_sql_script(script)), 2)
        self.assertEqual(split_sql_script("SELECT 1"), ["SELECT 1"])
        variants = ["SELECT\n1", "SELECT\r\n1", "SELECT\r1"]
        self.assertEqual(
            len({sha256(normalize_sql(v).encode()).hexdigest() for v in variants}), 1
        )

    def test_connection_binds_exact_limits_initialization_and_progress_bounds(
        self,
    ) -> None:
        authorizer = _Authorizer()
        progress = _ProgressBound()
        connection = _connection(authorizer, progress)
        try:
            connection.set_authorizer(None)
            for name, value in LIMITS.items():
                self.assertEqual(connection.getlimit(getattr(sqlite3, name)), value)
            expected = {
                "cache_size": -8192,
                "foreign_keys": 1,
                "journal_mode": "memory",
                "max_page_count": 16384,
                "recursive_triggers": 0,
                "temp_store": 2,
                "trusted_schema": 0,
            }
            self.assertEqual(
                {
                    name: connection.execute(f"PRAGMA {name}").fetchone()[0]
                    for name in INITIALIZATION
                },
                expected,
            )
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute("SELECT load_extension('outside')")
        finally:
            connection.close()

        progress.reset()
        for _ in range(MAX_VM_OPERATIONS // 1_000 - 1):
            self.assertEqual(progress(), 0)
        self.assertEqual(progress(), 1)
        progress.reset()
        progress.deadline = time.monotonic() - 1
        self.assertEqual(progress(), 1)


if __name__ == "__main__":
    unittest.main()
