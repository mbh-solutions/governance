from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

from governance_eval.adoption import (
    NATIVE_AUTHORITY_MODE,
    NATIVE_GOVERNANCE_REPOSITORY,
    NATIVE_WORKFLOW_PATH,
    _configuration,
    _native_configuration,
)
from governance_eval.candidate_pipeline import (
    CandidatePipelineError,
    _validate_authority_inputs,
    _validate_configuration,
    main,
)
from governance_eval.hashing import sha256_file


class CandidatePipelineConfigurationTests(unittest.TestCase):
    def test_accepts_only_fixed_profile_bound_to_standard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard = root / "standard.md"
            standard.write_text("fixed standard\n", encoding="utf-8")
            config = root / "supportability.yml"
            payload = _configuration("a" * 40, 4378147, sha256_file(standard))
            config.write_text(json.dumps(payload), encoding="utf-8")

            _validate_configuration(config, standard, "a" * 40)

            for name, mutation in (
                ("command", {"command": "python attacker.py"}),
                ("arguments", {"arguments": ["--exit-zero"]}),
                ("environment", {"environment": {"TOKEN": "attacker"}}),
                ("threshold", {"max_complexity": 99}),
                ("root", {"evaluation_root": "../../outside"}),
            ):
                with self.subTest(name=name):
                    hostile = {**deepcopy(payload), **mutation}
                    config.write_text(json.dumps(hostile), encoding="utf-8")
                    with self.assertRaises(CandidatePipelineError):
                        _validate_configuration(config, standard, "a" * 40)

    def test_rejects_standard_content_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard = root / "standard.md"
            standard.write_text("fixed standard\n", encoding="utf-8")
            config = root / "supportability.yml"
            config.write_text(
                json.dumps(_configuration("a" * 40, 4378147, "b" * 64)),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                CandidatePipelineError, "standard hash mismatch"
            ):
                _validate_configuration(config, standard, "a" * 40)

    def test_selects_exact_sqlite_profile_and_rejects_adapter_omission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard = root / "standard.md"
            standard.write_text("fixed standard\n", encoding="utf-8")
            config = root / "supportability.yml"
            payload = _configuration(
                "a" * 40,
                4378147,
                sha256_file(standard),
                profile="python.sqlite.v1",
            )
            config.write_text(json.dumps(payload), encoding="utf-8")

            self.assertEqual(
                _validate_configuration(config, standard, "a" * 40),
                "python.sqlite.v1",
            )

            for label, hostile in (
                ("omission", {**payload, "adapters": payload["adapters"][:-1]}),
                ("substitution", {**payload, "profile": "python.standard.v1"}),
            ):
                with self.subTest(label=label):
                    config.write_text(json.dumps(hostile), encoding="utf-8")
                    with self.assertRaises(CandidatePipelineError):
                        _validate_configuration(config, standard, "a" * 40)

    def test_native_configuration_and_central_workflow_identity_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            standard = root / "standard.md"
            standard.write_text("fixed standard\n", encoding="utf-8")
            config = root / "supportability.yml"
            sha = "a" * 40
            config.write_text(
                json.dumps(_native_configuration(sha, sha256_file(standard))),
                encoding="utf-8",
            )

            self.assertEqual(
                _validate_configuration(
                    config,
                    standard,
                    sha,
                    authority_mode=NATIVE_AUTHORITY_MODE,
                ),
                "python.standard.v1",
            )
            identity = {
                "authority_mode": NATIVE_AUTHORITY_MODE,
                "workflow_repository": NATIVE_GOVERNANCE_REPOSITORY,
                "workflow_path": NATIVE_WORKFLOW_PATH,
                "workflow_ref": (
                    f"{NATIVE_GOVERNANCE_REPOSITORY}/{NATIVE_WORKFLOW_PATH}@{sha}"
                ),
                "workflow_commit_sha": sha,
                "evaluator_sha": sha,
            }
            _validate_authority_inputs(**identity)
            for field, value in (
                ("workflow_repository", "attacker/governance"),
                ("workflow_path", ".github/workflows/attacker.yml"),
                ("workflow_commit_sha", "b" * 40),
                ("evaluator_sha", "b" * 40),
            ):
                with (
                    self.subTest(field=field),
                    self.assertRaises(CandidatePipelineError),
                ):
                    _validate_authority_inputs(**{**identity, field: value})

    def test_native_cli_returns_nonzero_for_blocking_decision(self) -> None:
        arguments = [
            "--target-root",
            "target",
            "--evaluator-root",
            "evaluator",
            "--event-path",
            "event.json",
            "--config-path",
            "config.yml",
            "--standard-path",
            "standard.md",
            "--workflow-path",
            NATIVE_WORKFLOW_PATH,
            "--workflow-ref",
            "ref",
            "--workflow-commit-sha",
            "a" * 40,
            "--evaluator-sha",
            "a" * 40,
            "--run-id",
            "1",
            "--run-attempt",
            "1",
            "--toolchain-root",
            "runtime",
            "--output-dir",
            "evidence",
            "--authority-mode",
            NATIVE_AUTHORITY_MODE,
        ]
        with (
            mock.patch(
                "governance_eval.candidate_pipeline.run_candidate_pipeline",
                return_value={"decision": {"status": "BLOCK_TECHNICAL"}},
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(main(arguments), 1)


if __name__ == "__main__":
    unittest.main()
