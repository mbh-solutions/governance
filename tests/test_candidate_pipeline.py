from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from governance_eval.adoption import _configuration
from governance_eval.candidate_pipeline import (
    CandidatePipelineError,
    _validate_configuration,
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


if __name__ == "__main__":
    unittest.main()
