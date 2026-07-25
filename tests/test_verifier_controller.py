from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Mapping
from unittest import mock

from governance_eval.artifact_verifier import REQUIRED_CONTEXT
from governance_eval.sqlite_policy import POLICY_SHA256
from governance_eval.schema_validator import validate
from governance_eval.verifier_controller import (
    ControllerError,
    Enrollment,
    load_registry,
    run_controller,
)
from governance_eval.verifier_pipeline import WORKFLOW_PATH


class _API:
    def __init__(self, pull: Mapping[str, Any], runs: list[Mapping[str, Any]]):
        self.pull = pull
        self.runs = runs

    def get_list(self, _path: str) -> list[Any]:
        return [self.pull]

    def get_json(self, path: str) -> Mapping[str, Any]:
        if "/actions/workflows/" in path:
            return {"workflow_runs": self.runs}
        raise AssertionError(path)

    def post_json(self, _path: str, _payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise AssertionError("unexpected post")

    def patch_json(self, _path: str, _payload: Mapping[str, Any]) -> Mapping[str, Any]:
        raise AssertionError("unexpected patch")

    def download(self, _path: str, _destination: Path, _limit: int) -> None:
        raise AssertionError("unexpected download")


class VerifierControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.enrollment = Enrollment(
            repository="markheck-solutions/example",
            repository_id=101,
            candidate_workflow_path=WORKFLOW_PATH,
            governance_sha="a" * 40,
            workflow_sha256="b" * 64,
            configuration_sha256="c" * 64,
            standard_sha256="d" * 64,
            required_context=REQUIRED_CONTEXT,
            verifier_app_id=456,
        )
        self.base = "e" * 40
        self.head = "f" * 40

    def test_processes_exact_current_pr_run(self) -> None:
        pull = self._pull(7)
        run = self._run(7)
        api = _API(pull, [run])
        with TemporaryDirectory() as directory:
            with mock.patch(
                "governance_eval.verifier_controller.verify_and_publish",
                return_value={
                    "result": "PASS",
                    "head_sha": self.head,
                    "check_run_id": 999,
                },
            ) as verify:
                result = run_controller(
                    api=api,
                    enrollments=(self.enrollment,),
                    output_directory=Path(directory) / "proof",
                    now=datetime(2026, 7, 23, 20, 0, tzinfo=UTC),
                )

        target = verify.call_args.kwargs["target"]
        self.assertEqual(target.repository_id, 101)
        self.assertEqual(target.pull_request, 7)
        self.assertEqual(target.run_id, 123)
        self.assertEqual(target.workflow_sha256, "b" * 64)
        self.assertEqual(result["results"][0]["result"], "PASS")

    def test_same_head_different_pr_run_is_not_reused(self) -> None:
        pull = self._pull(8, updated_at="2026-07-23T19:00:00Z")
        api = _API(pull, [self._run(7)])
        with TemporaryDirectory() as directory:
            with (
                mock.patch(
                    "governance_eval.verifier_controller.verify_and_publish"
                ) as verify,
                mock.patch(
                    "governance_eval.verifier_controller.publish_rejection",
                    return_value={
                        "result": "REJECT",
                        "head_sha": self.head,
                        "check_run_id": 1000,
                    },
                ) as reject,
            ):
                result = run_controller(
                    api=api,
                    enrollments=(self.enrollment,),
                    output_directory=Path(directory) / "proof",
                    now=datetime(2026, 7, 23, 20, 0, tzinfo=UTC),
                )

        verify.assert_not_called()
        reject.assert_called_once()
        self.assertEqual(result["results"][0]["result"], "REJECT")

    def test_registry_rejects_command_or_argument_fields(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "enrollments.json"
            entry = self.enrollment.__dict__ | {"command": "python attacker.py"}
            path.write_text(
                json.dumps({"schema_version": "1.0", "repositories": [entry]}),
                encoding="utf-8",
            )
            with self.assertRaises(ControllerError):
                load_registry(
                    path,
                    governance_sha=self.enrollment.governance_sha,
                    verifier_app_id=self.enrollment.verifier_app_id,
                )

    def test_registry_defaults_legacy_standard_and_requires_sqlite_manifest(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "enrollments.json"
            legacy = {
                key: value
                for key, value in self.enrollment.__dict__.items()
                if key
                not in {
                    "profile",
                    "adoption_manifest_sha256",
                    "sqlite_policy_sha256",
                }
            }
            path.write_text(
                json.dumps({"schema_version": "1.0", "repositories": [legacy]}),
                encoding="utf-8",
            )
            loaded = load_registry(
                path,
                governance_sha=self.enrollment.governance_sha,
                verifier_app_id=self.enrollment.verifier_app_id,
            )
            self.assertEqual(loaded[0].profile, "python.standard.v1")

            legacy["sqlite_policy_sha256"] = ""
            path.write_text(
                json.dumps({"schema_version": "1.0", "repositories": [legacy]}),
                encoding="utf-8",
            )
            with self.assertRaises(ControllerError):
                load_registry(
                    path,
                    governance_sha=self.enrollment.governance_sha,
                    verifier_app_id=self.enrollment.verifier_app_id,
                )
            del legacy["sqlite_policy_sha256"]

            sqlite = {
                **legacy,
                "profile": "python.sqlite.v1",
                "adoption_manifest_sha256": "9" * 64,
                "sqlite_policy_sha256": POLICY_SHA256,
            }
            path.write_text(
                json.dumps({"schema_version": "1.0", "repositories": [sqlite]}),
                encoding="utf-8",
            )
            loaded = load_registry(
                path,
                governance_sha=self.enrollment.governance_sha,
                verifier_app_id=self.enrollment.verifier_app_id,
            )
            self.assertEqual(loaded[0].profile, "python.sqlite.v1")
            schema = json.loads(
                (
                    Path(__file__).resolve().parents[1]
                    / "schemas/v1/verifier_enrollment.schema.json"
                ).read_text(encoding="utf-8")
            )
            validate({"schema_version": "1.0", "repositories": [sqlite]}, schema)

            for policy in (None, "0" * 64):
                hostile = dict(sqlite)
                if policy is None:
                    hostile.pop("sqlite_policy_sha256")
                else:
                    hostile["sqlite_policy_sha256"] = policy
                path.write_text(
                    json.dumps({"schema_version": "1.0", "repositories": [hostile]}),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ControllerError, "policy"):
                    load_registry(
                        path,
                        governance_sha=self.enrollment.governance_sha,
                        verifier_app_id=self.enrollment.verifier_app_id,
                    )

            del sqlite["adoption_manifest_sha256"]
            path.write_text(
                json.dumps({"schema_version": "1.0", "repositories": [sqlite]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ControllerError, "manifest"):
                load_registry(
                    path,
                    governance_sha=self.enrollment.governance_sha,
                    verifier_app_id=self.enrollment.verifier_app_id,
                )

    def _pull(
        self, number: int, updated_at: str = "2026-07-23T19:59:00Z"
    ) -> dict[str, Any]:
        return {
            "number": number,
            "state": "open",
            "updated_at": updated_at,
            "base": {
                "sha": self.base,
                "repo": {"id": 101, "full_name": self.enrollment.repository},
            },
            "head": {"sha": self.head},
        }

    def _run(self, pull_request: int) -> dict[str, Any]:
        return {
            "id": 123,
            "run_attempt": 1,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "head_sha": self.head,
            "path": WORKFLOW_PATH,
            "repository": {"id": 101, "full_name": self.enrollment.repository},
            "pull_requests": [
                {
                    "number": pull_request,
                    "base": {"sha": self.base},
                    "head": {"sha": self.head},
                }
            ],
        }


if __name__ == "__main__":
    unittest.main()
