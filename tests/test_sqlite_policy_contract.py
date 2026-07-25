from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import unittest
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/historical/twmn_sqlite_coalesce/statement.json"
POLICY_FUNCTIONS = frozenset(
    {"bm25", "coalesce", "highlight", "like", "match", "snippet"}
)


def _authorizer(
    observed: set[str],
) -> Callable[[int, str | None, str | None, str, str | None], int]:
    def authorize(
        action: int,
        first: str | None,
        second: str | None,
        _database: str,
        _source: str | None,
    ) -> int:
        if action != sqlite3.SQLITE_FUNCTION:
            return sqlite3.SQLITE_OK
        function = (second or first or "").lower()
        observed.add(function)
        return (
            sqlite3.SQLITE_OK if function in POLICY_FUNCTIONS else sqlite3.SQLITE_DENY
        )

    return authorize


class SQLitePolicyContractTests(unittest.TestCase):
    def test_pinned_twmn_coalesce_statement_prepares(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        statement = fixture["statement"]
        self.assertEqual(
            hashlib.sha256(statement.encode("utf-8")).hexdigest(),
            fixture["normalized_sql_sha256"],
        )
        self.assertEqual(
            fixture["commit_sha"],
            "47bf8823000ac98595ccb1013d3f8f6abdf90ebd",
        )
        connection = sqlite3.connect(":memory:")
        observed: set[str] = set()
        try:
            connection.execute(
                "CREATE TABLE products("
                "id TEXT PRIMARY KEY, title TEXT NOT NULL, source_url TEXT)"
            )
            connection.set_authorizer(_authorizer(observed))
            connection.execute(
                "EXPLAIN " + statement, ("id", "title", "source")
            ).close()
        finally:
            connection.close()
        self.assertEqual(observed, {"coalesce"})

    def test_unapproved_function_remains_blocked(self) -> None:
        connection = sqlite3.connect(":memory:")
        observed: set[str] = set()
        try:
            connection.set_authorizer(_authorizer(observed))
            with self.assertRaisesRegex(sqlite3.DatabaseError, "not authorized"):
                connection.execute("EXPLAIN SELECT abs(1)").close()
        finally:
            connection.close()
        self.assertEqual(observed, {"abs"})

    def test_contract_locations_have_one_exact_allowlist(self) -> None:
        expected = {
            "TASK.md": (
                "`bm25`, `coalesce`, `highlight`, `like`, `match`, and `snippet`"
            ),
            "docs/adr/0003-sqlite-supportability-profile.md": (
                "`bm25`, `coalesce`, `highlight`, `like`, `match`, `snippet`"
            ),
            "docs/reference/supportability-standard.md": (
                "`bm25`, `coalesce`, `highlight`, `like`, `match`, and `snippet`"
            ),
        }
        for relative, allowlist in expected.items():
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(re.sub(r"\s+", " ", text).count(allowlist), 1)


if __name__ == "__main__":
    unittest.main()
