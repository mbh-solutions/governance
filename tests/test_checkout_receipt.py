from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from governance_eval.checkout_receipt import CheckoutReceiptError, bind_checkout
from governance_eval.hashing import sha256_file
from governance_eval.schemas import validate_named


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def _repository(root: Path, remote: str, filename: str) -> tuple[str, str]:
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "governance@example.invalid")
    _git(root, "config", "user.name", "Governance Test")
    _git(root, "remote", "add", "origin", remote)
    (root / filename).write_text("base\n", encoding="utf-8")
    _git(root, "add", filename)
    _git(root, "commit", "-qm", "base")
    base = _git(root, "rev-parse", "HEAD")
    (root / filename).write_text("head\n", encoding="utf-8")
    _git(root, "commit", "-qam", "head")
    return base, _git(root, "rev-parse", "HEAD")


class CheckoutReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.target = self.root / "target"
        self.evaluator = self.root / "evaluator"
        self.base, self.head = _repository(
            self.target,
            "https://github.com/markheck-solutions/governance.git",
            "target.py",
        )
        _, self.evaluator_sha = _repository(
            self.evaluator,
            "git@github.com:markheck-solutions/governance.git",
            "judge.py",
        )
        self.config = self.target / "supportability.yml"
        self.standard = self.target / "SUPPORTABILITY.md"
        self.config.write_text("schema_version: '2.0'\n", encoding="utf-8")
        self.standard.write_text("# Standard\n", encoding="utf-8")
        _git(self.target, "add", self.config.name, self.standard.name)
        _git(self.target, "commit", "-qm", "governance inputs")
        self.head = _git(self.target, "rev-parse", "HEAD")
        self.repository = {
            "id": 123456,
            "full_name": "markheck-solutions/governance",
        }
        self.pull_request = {
            "number": 81,
            "html_url": "https://github.com/markheck-solutions/governance/pull/81",
            "base": {"sha": self.base},
            "head": {"sha": self.head},
        }
        self.event = {
            "repository": self.repository,
            "evaluator_repository": self.repository,
            "pull_request": self.pull_request,
        }
        self.workflow = {
            "workflow_ref": "markheck-solutions/governance/.github/workflows/governance.yml@refs/heads/main",
            "workflow_sha": self.evaluator_sha,
            "run_id": 999,
            "run_attempt": 2,
            "server_url": "https://github.com",
            "api_url": "https://api.github.com",
            "observed_at": "2026-07-19T12:00:00Z",
        }
        runtime_path = Path(shutil.which("git") or "missing-git").resolve()
        self.runtime = {
            "docker_path": str(runtime_path),
            "docker_sha256": sha256_file(runtime_path),
            "docker_host": "npipe:////./pipe/docker_engine",
        }

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _bind(self, **overrides: object):
        arguments = {
            "target_root": self.target,
            "evaluator_root": self.evaluator,
            "event": self.event,
            "pull_request": self.pull_request,
            "repository": self.repository,
            "evaluator_repository": self.repository,
            "workflow": self.workflow,
            "config_path": self.config,
            "standard_path": self.standard,
            "runtime": self.runtime,
        }
        arguments.update(overrides)
        return bind_checkout(**arguments)

    def test_binds_clean_exact_git_and_github_identity(self) -> None:
        receipt = self._bind()

        payload = receipt.to_json()
        validate_named("checkout_receipt", payload)
        self.assertEqual(payload["repository"], self.repository)
        self.assertEqual(payload["pull_request"]["head_sha"], self.head)
        self.assertEqual(
            payload["pull_request"]["head_tree_sha"],
            _git(self.target, "rev-parse", f"{self.head}^{{tree}}"),
        )
        self.assertEqual(
            payload["evaluator"]["tree_sha"],
            _git(self.evaluator, "rev-parse", f"{self.evaluator_sha}^{{tree}}"),
        )
        self.assertEqual(payload["config_sha256"], sha256_file(self.config))
        self.assertEqual(payload["standard_sha256"], sha256_file(self.standard))
        self.assertEqual(receipt.to_json(), self._bind().to_json())

    def test_target_working_directory_cannot_control_receipt_schema(self) -> None:
        original = Path.cwd()
        try:
            os.chdir(self.target)
            receipt = self._bind()
        finally:
            os.chdir(original)

        self.assertEqual(receipt.repository, self.repository)

    def test_rejects_event_api_and_workflow_identity_mismatches(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []
        event = deepcopy(self.event)
        event["repository"]["id"] = 9
        cases.append(("repository id", {"event": event}))
        pull_request = deepcopy(self.pull_request)
        pull_request["head"]["sha"] = "a" * 40
        cases.append(("head sha", {"pull_request": pull_request}))
        workflow = {**self.workflow, "workflow_sha": "b" * 40}
        cases.append(("workflow sha", {"workflow": workflow}))
        workflow = {**self.workflow, "observed_at": "not-a-date"}
        cases.append(("observed_at", {"workflow": workflow}))

        for expected, override in cases:
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(CheckoutReceiptError, expected):
                    self._bind(**override)

    def test_rejects_dirty_target_and_evaluator(self) -> None:
        for root, filename in (
            (self.target, "untracked.txt"),
            (self.evaluator, "judge.py"),
        ):
            with self.subTest(root=root.name):
                original = (
                    (root / filename).read_bytes()
                    if (root / filename).exists()
                    else None
                )
                (root / filename).write_text("dirty\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    CheckoutReceiptError, f"{root.name} checkout is dirty"
                ):
                    self._bind()
                if original is None:
                    (root / filename).unlink()
                else:
                    (root / filename).write_bytes(original)

    def test_rejects_ignored_target_content(self) -> None:
        (self.target / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        _git(self.target, "add", ".gitignore")
        _git(self.target, "commit", "-qm", "ignore rule")
        self.head = _git(self.target, "rev-parse", "HEAD")
        self.pull_request["head"]["sha"] = self.head
        (self.target / "ignored.txt").write_text("hidden\n", encoding="utf-8")

        with self.assertRaisesRegex(CheckoutReceiptError, "target checkout is dirty"):
            self._bind()

    def test_ignores_inherited_git_repository_redirects(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GIT_DIR": str(self.evaluator / ".git"),
                "GIT_WORK_TREE": str(self.evaluator),
                "GIT_CONFIG_GLOBAL": str(self.root / "hostile.gitconfig"),
            },
        ):
            receipt = self._bind()

        self.assertEqual(receipt.pull_request["head_sha"], self.head)
        self.assertEqual(
            receipt.pull_request["head_tree_sha"],
            _git(self.target, "rev-parse", "HEAD^{tree}"),
        )

    def test_rejects_local_head_origin_and_input_path_mismatches(self) -> None:
        (self.root / "outside.yml").write_text("x", encoding="utf-8")
        other_pr = {**self.pull_request, "head": {"sha": self.base}}
        other_event = {**self.event, "pull_request": other_pr}
        with self.assertRaisesRegex(CheckoutReceiptError, "target head"):
            self._bind(pull_request=other_pr, event=other_event)

        _git(
            self.target,
            "remote",
            "set-url",
            "origin",
            "https://github.com/other/repo.git",
        )
        with self.assertRaisesRegex(CheckoutReceiptError, "repository origin"):
            self._bind()
        _git(
            self.target,
            "remote",
            "set-url",
            "origin",
            "https://github.com/markheck-solutions/governance.git",
        )

        with self.assertRaisesRegex(CheckoutReceiptError, "config path"):
            self._bind(config_path=self.root / "outside.yml")

    def test_binds_evaluator_repository_independently_from_target(self) -> None:
        target_repository = {"id": 222, "full_name": "example/target"}
        target_pr = {
            **self.pull_request,
            "html_url": "https://github.com/example/target/pull/81",
        }
        target_event = {
            "repository": target_repository,
            "pull_request": target_pr,
        }
        _git(
            self.target,
            "remote",
            "set-url",
            "origin",
            "https://github.com/example/target.git",
        )

        receipt = self._bind(
            repository=target_repository,
            event=target_event,
            pull_request=target_pr,
            evaluator_repository=self.repository,
            workflow={
                **self.workflow,
                "workflow_ref": (
                    "example/target/.github/workflows/"
                    "governance-candidate.yml@refs/heads/main"
                ),
                "evaluator_sha": self.evaluator_sha,
            },
        )

        self.assertEqual(receipt.repository, target_repository)
        self.assertEqual(
            receipt.evaluator["repository_full_name"],
            "markheck-solutions/governance",
        )

        central = self._bind(
            repository=target_repository,
            event=target_event,
            pull_request=target_pr,
            evaluator_repository=self.repository,
            workflow_repository=self.repository,
            workflow={
                **self.workflow,
                "workflow_ref": (
                    "markheck-solutions/governance/.github/workflows/"
                    f"governance-required.yml@{self.evaluator_sha}"
                ),
                "evaluator_sha": self.evaluator_sha,
            },
        )
        self.assertEqual(
            central.workflow["workflow_ref"],
            "markheck-solutions/governance/.github/workflows/"
            f"governance-required.yml@{self.evaluator_sha}",
        )

    def test_rejects_non_github_hostname_containing_github_text(self) -> None:
        _git(
            self.target,
            "remote",
            "set-url",
            "origin",
            "https://notgithub.com/markheck-solutions/governance.git",
        )

        with self.assertRaisesRegex(CheckoutReceiptError, "origin is not GitHub"):
            self._bind()


if __name__ == "__main__":
    unittest.main()
