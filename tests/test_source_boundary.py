from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from governance_eval import protected_surface, supportability
from governance_eval.paths import repo_root
from governance_eval.workflow_contract import (
    permission_scope_errors,
    reusable_permission_closure_errors,
    source_workflow_contract_errors,
    standard_event_contract_errors,
    trusted_source_authority_errors,
)


class SourceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def _source_errors_after_replacements(
        self,
        replacements: tuple[tuple[str, str], ...],
        workflow_name: str = "source-qualification.yml",
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in ("source-candidate.yml", "source-qualification.yml"):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            target = workflow_root / workflow_name
            text = target.read_text(encoding="utf-8")
            for old, new in replacements:
                self.assertIn(old, text)
                text = text.replace(old, new, 1)
            target.write_text(text, encoding="utf-8")
            return source_workflow_contract_errors(root)

    def test_reusable_permission_closure_is_complete(self) -> None:
        self.assertEqual(reusable_permission_closure_errors(self.root), [])

    def test_reusable_permission_closure_rejects_missing_checks_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in (
                "supportability-enforcement.yml",
                "supportability-gate.yml",
                "delivery-receipt.yml",
            ):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace("  checks: read\n", "", 1),
                encoding="utf-8",
            )

            errors = reusable_permission_closure_errors(root)

        self.assertTrue(
            any(
                "delivery-receipt.yml requires checks: read" in error
                for error in errors
            )
        )

    def test_reusable_permission_closure_rejects_floating_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in (
                "supportability-enforcement.yml",
                "supportability-gate.yml",
                "delivery-receipt.yml",
            ):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace(
                    "@50a7c1c958fe06056206429d7e2f194e0288738c", "@main"
                ),
                encoding="utf-8",
            )

            errors = reusable_permission_closure_errors(
                root, "supportability-enforcement.yml"
            )

        self.assertTrue(any("is not immutable" in error for error in errors))
        self.assertFalse(any("called workflow is missing" in error for error in errors))

    def test_reusable_permission_closure_includes_yaml_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            (workflow_root / "added.yaml").write_text(
                "name: Added\n"
                "on: pull_request\n"
                "permissions: {}\n"
                "jobs:\n"
                "  call:\n"
                "    uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@main\n",
                encoding="utf-8",
            )

            errors = reusable_permission_closure_errors(root)

        self.assertTrue(any("is not immutable" in error for error in errors))

    def test_reusable_permission_closure_honors_job_level_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in (
                "supportability-enforcement.yml",
                "supportability-gate.yml",
                "delivery-receipt.yml",
            ):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace(
                    "  delivery-receipt:\n",
                    "  delivery-receipt:\n    permissions:\n      checks: none\n",
                    1,
                ),
                encoding="utf-8",
            )

            errors = reusable_permission_closure_errors(
                root, "supportability-enforcement.yml"
            )

        self.assertTrue(
            any(
                "delivery-receipt.yml requires checks: read" in error
                for error in errors
            )
        )

    def test_reusable_permission_closure_honors_inline_empty_job_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in (
                "supportability-enforcement.yml",
                "supportability-gate.yml",
                "delivery-receipt.yml",
            ):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace(
                    "  delivery-receipt:\n",
                    "  delivery-receipt:\n    permissions: {}\n",
                    1,
                ),
                encoding="utf-8",
            )

            errors = reusable_permission_closure_errors(
                root, "supportability-enforcement.yml"
            )

        self.assertTrue(
            any(
                "delivery-receipt.yml requires checks: read" in error
                for error in errors
            )
        )

    def test_standard_profile_event_contract_is_pull_request_only(self) -> None:
        self.assertEqual(standard_event_contract_errors(self.root), [])

    def test_standard_profile_ignores_comment_only_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            evaluator_root = root / "governance_eval"
            workflow_root.mkdir(parents=True)
            evaluator_root.mkdir(parents=True)
            for name in (
                "supportability-enforcement.yml",
                "supportability-gate.yml",
            ):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            for name in ("codex_connector_evidence.py", "toolchain_bootstrap.py"):
                shutil.copyfile(
                    self.root / "governance_eval" / name, evaluator_root / name
                )
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace(
                    "  pull_request_target:\n",
                    "  workflow_dispatch:\n  #  pull_request_target:\n",
                    1,
                ),
                encoding="utf-8",
            )

            errors = standard_event_contract_errors(root)

        self.assertTrue(
            any("standard caller events are invalid" in error for error in errors)
        )

    def test_standard_profile_rejects_missing_synchronize_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            evaluator_root = root / "governance_eval"
            workflow_root.mkdir(parents=True)
            evaluator_root.mkdir(parents=True)
            for name in ("supportability-enforcement.yml", "supportability-gate.yml"):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            for name in ("codex_connector_evidence.py", "toolchain_bootstrap.py"):
                shutil.copyfile(
                    self.root / "governance_eval" / name, evaluator_root / name
                )
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace(
                    "      - synchronize\n", "      - closed\n", 1
                ),
                encoding="utf-8",
            )

            errors = standard_event_contract_errors(root)

        self.assertTrue(any("action scope is invalid" in error for error in errors))

    def test_standard_profile_rejects_guard_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            evaluator_root = root / "governance_eval"
            workflow_root.mkdir(parents=True)
            evaluator_root.mkdir(parents=True)
            for name in ("supportability-enforcement.yml", "supportability-gate.yml"):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            for name in ("codex_connector_evidence.py", "toolchain_bootstrap.py"):
                shutil.copyfile(
                    self.root / "governance_eval" / name, evaluator_root / name
                )
            gate = workflow_root / "supportability-gate.yml"
            guard = '          if os.environ["REQUEST_EVENT_NAME"] != "pull_request_target":\n'
            gate.write_text(
                gate.read_text(encoding="utf-8").replace(
                    guard,
                    '          os.environ["REQUEST_EVENT_NAME"] = "pull_request_target"\n'
                    + guard,
                    1,
                ),
                encoding="utf-8",
            )

            errors = standard_event_contract_errors(root)

        self.assertTrue(any("trusted contract" in error for error in errors))

    def test_source_qualification_excludes_governance_product_authority(self) -> None:
        self.assertEqual(source_workflow_contract_errors(self.root), [])

    def test_source_qualification_rejects_comment_only_test_command(self) -> None:
        errors = self._source_errors_after_replacements(
            (
                (
                    "run: python -I -c ",
                    "run: echo skipped # python -I -c ",
                ),
            ),
            "source-candidate.yml",
        )

        self.assertTrue(any("exact allowlist" in error for error in errors))

    def test_source_qualification_rejects_branch_ignore_main(self) -> None:
        errors = self._source_errors_after_replacements(
            (("    branches:\n", "    branches-ignore:\n"),)
        )

        self.assertTrue(any("scope is not exact" in error for error in errors))

    def test_source_qualification_rejects_top_level_defaults(self) -> None:
        errors = self._source_errors_after_replacements(
            (
                (
                    "permissions:\n",
                    "defaults:\n  run:\n    shell: echo {0}\n\npermissions:\n",
                ),
            )
        )

        self.assertTrue(any("exact allowlist" in error for error in errors))

    def test_source_qualification_rejects_duplicate_required_context(self) -> None:
        job_blocks = (
            "  spoof:\n"
            "    name: Governance Source Qualification\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: true\n",
            "  spoof:\n"
            '    name: "Governance Source Qualification"\n'
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: true\n",
            "  spoof:\n"
            "    name: ${{ format('Governance Source {0}', 'Qualification') }}\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: true\n",
            "  spoof:\n"
            '    "name": Governance Source Qualification\n'
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - run: true\n",
            "  spoof: {name: Governance Source Qualification, "
            "runs-on: ubuntu-24.04, steps: [{run: true}]}\n",
            "   spoof:\n"
            "     name: Governance Source Qualification\n"
            "     runs-on: ubuntu-24.04\n"
            "     steps:\n"
            "       - run: true\n",
            "  spoof:\n"
            "     name: Governance Source Qualification\n"
            "     runs-on: ubuntu-24.04\n"
            "     steps:\n"
            "       - run: true\n",
        )
        for job_block in job_blocks:
            with (
                self.subTest(job_block=job_block),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                workflow_root = root / ".github" / "workflows"
                workflow_root.mkdir(parents=True)
                for name in ("source-candidate.yml", "source-qualification.yml"):
                    shutil.copyfile(
                        self.root / ".github" / "workflows" / name,
                        workflow_root / name,
                    )
                (workflow_root / "spoof.yml").write_text(
                    "name: Spoof\n"
                    "on: pull_request\n"
                    "permissions: {}\n"
                    "jobs:\n" + job_block,
                    encoding="utf-8",
                )

                errors = source_workflow_contract_errors(root)

            self.assertNotEqual(errors, [])

    def test_source_qualification_rejects_duplicate_top_level_keys(self) -> None:
        for declaration in ("name: Override\n", "on: push\n"):
            with (
                self.subTest(declaration=declaration),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                workflow_root = root / ".github" / "workflows"
                shutil.copytree(self.root / ".github" / "workflows", workflow_root)
                workflow = workflow_root / "supportability-enforcement.yml"
                workflow.write_text(
                    workflow.read_text(encoding="utf-8").replace(
                        "\npermissions:\n", f"\n{declaration}permissions:\n", 1
                    ),
                    encoding="utf-8",
                )

                errors = source_workflow_contract_errors(root)

            self.assertTrue(
                any("top-level declaration is duplicated" in error for error in errors),
                errors,
            )

    def test_source_qualification_rejects_extra_nameless_steps(self) -> None:
        for inserted in (
            "      - uses: attacker/example@main\n",
            "      - run: echo arbitrary\n",
        ):
            with self.subTest(inserted=inserted):
                errors = self._source_errors_after_replacements(
                    (("    steps:\n", "    steps:\n" + inserted),)
                )
                self.assertTrue(any("exact allowlist" in error for error in errors))

    def test_source_qualification_rejects_unpinned_actions_in_added_workflow(
        self,
    ) -> None:
        for action_step in (
            "      - uses: attacker/example@main\n",
            '      - "uses": attacker/example@main\n',
            '      - "\\u0075ses": attacker/example@main\n',
            "      - {uses: attacker/example@main}\n",
            "      - ? uses\n        : attacker/example@main\n",
        ):
            with (
                self.subTest(action_step=action_step),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                workflow_root = root / ".github" / "workflows"
                workflow_root.mkdir(parents=True)
                for name in ("source-candidate.yml", "source-qualification.yml"):
                    shutil.copyfile(
                        self.root / ".github" / "workflows" / name,
                        workflow_root / name,
                    )
                (workflow_root / "added.yml").write_text(
                    "name: Added\n"
                    "on: pull_request\n"
                    "permissions: {}\n"
                    "jobs:\n"
                    "  check:\n"
                    "    runs-on: ubuntu-24.04\n"
                    "    steps:\n" + action_step,
                    encoding="utf-8",
                )

                errors = source_workflow_contract_errors(root)

            self.assertTrue(
                any(
                    "workflow action use" in error
                    or "workflow YAML key syntax" in error
                    for error in errors
                )
            )

    def test_source_qualification_rejects_unpinned_composite_action(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in ("source-candidate.yml", "source-qualification.yml"):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            action = root / ".github/actions/example/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: Example\n"
                "runs:\n"
                "  using: composite\n"
                "  steps:\n"
                "    - uses: attacker/example@main\n",
                encoding="utf-8",
            )

            errors = source_workflow_contract_errors(root)

        self.assertTrue(any("workflow action use" in error for error in errors))

    def test_source_qualification_rejects_unapproved_immutable_pins(self) -> None:
        substitutions = (
            (
                "supportability-enforcement.yml",
                "50a7c1c958fe06056206429d7e2f194e0288738c",
                "1234567890abcdef1234567890abcdef12345678",
            ),
            (
                "governance-shadow.yml",
                "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
                "attacker/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
            ),
        )
        for workflow_name, original, replacement in substitutions:
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                workflow_root = root / ".github" / "workflows"
                shutil.copytree(self.root / ".github" / "workflows", workflow_root)
                workflow = workflow_root / workflow_name
                workflow.write_text(
                    workflow.read_text(encoding="utf-8").replace(
                        original, replacement, 1
                    ),
                    encoding="utf-8",
                )

                errors = source_workflow_contract_errors(root)

            self.assertTrue(
                any("trusted allowlist" in error for error in errors), errors
            )

    def test_source_qualification_rejects_local_action_outside_authority(self) -> None:
        for local_action in (
            "./tools/evil",
            "./.github/actions/../workflows/evil",
            "./governance/.github/actions/evil",
        ):
            with self.subTest(local_action=local_action):
                errors = self._source_errors_after_replacements(
                    (
                        (
                            "uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
                            f"uses: {local_action}",
                        ),
                    ),
                    "source-candidate.yml",
                )

                self.assertTrue(any("workflow action use" in error for error in errors))

    def test_source_qualification_rejects_symlinked_local_action_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in ("source-candidate.yml", "source-qualification.yml"):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            (workflow_root / "local-action.yml").write_text(
                "name: Local action\n"
                "on: pull_request\n"
                "permissions: {}\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - uses: ./.github/actions/link\n",
                encoding="utf-8",
            )
            action = root / ".github/actions/link/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: Link\nruns:\n  using: composite\n  steps: []\n",
                encoding="utf-8",
            )
            real_is_symlink = Path.is_symlink

            def fake_is_symlink(path: Path) -> bool:
                return path == action.parent or real_is_symlink(path)

            with patch.object(Path, "is_symlink", fake_is_symlink):
                errors = source_workflow_contract_errors(root)

        self.assertTrue(any("contains a symlink" in error for error in errors))

    def test_source_qualification_rejects_anchor_alias_action_key(self) -> None:
        for anchor_name in ("action_key", "1"):
            with (
                self.subTest(anchor_name=anchor_name),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                workflow_root = root / ".github" / "workflows"
                workflow_root.mkdir(parents=True)
                for name in ("source-candidate.yml", "source-qualification.yml"):
                    shutil.copyfile(
                        self.root / ".github" / "workflows" / name,
                        workflow_root / name,
                    )
                (workflow_root / "anchor.yml").write_text(
                    f"name: &{anchor_name} uses\n"
                    "on: pull_request\n"
                    "permissions: {}\n"
                    "jobs:\n"
                    "  check:\n"
                    "    runs-on: ubuntu-24.04\n"
                    "    steps:\n"
                    f"      - *{anchor_name}: attacker/example@main\n",
                    encoding="utf-8",
                )

                errors = source_workflow_contract_errors(root)

            self.assertTrue(
                any("workflow YAML key syntax" in error for error in errors)
            )

    def test_source_qualification_ignores_uses_text_in_run_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            for name in ("source-candidate.yml", "source-qualification.yml"):
                shutil.copyfile(
                    self.root / ".github" / "workflows" / name,
                    workflow_root / name,
                )
            (workflow_root / "script.yml").write_text(
                "name: Script\n"
                "on: pull_request\n"
                "permissions: {}\n"
                "jobs:\n"
                "  check:\n"
                "    name: Script check\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - name: Explain syntax\n"
                "        run: |2\n"
                "          echo 'uses: documentation'\n",
                encoding="utf-8",
            )

            errors = source_workflow_contract_errors(root)

        self.assertFalse(any("workflow action use" in error for error in errors))
        self.assertFalse(any("workflow YAML key syntax" in error for error in errors))

    def test_source_qualification_rejects_runner_or_timeout_drift(self) -> None:
        for old, new in (
            ("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-latest\n"),
            ("    timeout-minutes: 10\n", ""),
        ):
            with self.subTest(old=old):
                errors = self._source_errors_after_replacements(((old, new),))
                self.assertTrue(any("exact allowlist" in error for error in errors))

    def test_isolated_tool_invocation_rejects_candidate_module_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp)
            (candidate / "ruff.py").write_text(
                "raise SystemExit('SHADOW_RUFF')\n", encoding="utf-8"
            )

            result = subprocess.run(
                [sys.executable, "-I", "-m", "ruff", "--version"],
                cwd=candidate,
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SHADOW_RUFF", result.stdout + result.stderr)

    def test_trusted_source_authority_rejects_candidate_self_update(self) -> None:
        paths = (
            ".github/workflows/source-candidate.yml",
            ".github/workflows/source-qualification.yml",
            "governance_eval/source_qualification.py",
            "governance_eval/workflow_contract.py",
            "pyproject.toml",
            "requirements-governance.lock",
        )
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp)
            for relative_path in paths:
                target = candidate / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.root / relative_path, target)
            authority = candidate / "governance_eval/source_qualification.py"
            authority.write_text(
                authority.read_text(encoding="utf-8") + "\n# candidate drift\n",
                encoding="utf-8",
            )

            errors = trusted_source_authority_errors(candidate)

        self.assertTrue(any("source_qualification.py" in error for error in errors))

    def test_trusted_source_authority_freezes_local_action_tree(self) -> None:
        paths = (
            ".github/workflows/source-candidate.yml",
            ".github/workflows/source-qualification.yml",
            "governance_eval/source_qualification.py",
            "governance_eval/workflow_contract.py",
            "pyproject.toml",
            "requirements-governance.lock",
        )
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp)
            for relative_path in paths:
                target = candidate / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.root / relative_path, target)
            shutil.copytree(
                self.root / ".github/actions", candidate / ".github/actions"
            )
            action = candidate / ".github/actions/setup-governance-toolchain/action.yml"
            action.write_text(
                action.read_text(encoding="utf-8") + "\n# candidate drift\n",
                encoding="utf-8",
            )

            errors = trusted_source_authority_errors(candidate)

        self.assertTrue(any("setup-governance-toolchain" in error for error in errors))

    def test_trusted_source_authority_rejects_symlinked_path_component(self) -> None:
        paths = (
            ".github/workflows/source-candidate.yml",
            ".github/workflows/source-qualification.yml",
            "governance_eval/source_qualification.py",
            "governance_eval/workflow_contract.py",
            "pyproject.toml",
            "requirements-governance.lock",
        )
        with tempfile.TemporaryDirectory() as tmp:
            candidate = Path(tmp)
            for relative_path in paths:
                target = candidate / relative_path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.root / relative_path, target)
            real_is_symlink = Path.is_symlink

            def fake_is_symlink(path: Path) -> bool:
                return path == candidate / ".github" or real_is_symlink(path)

            with patch.object(Path, "is_symlink", fake_is_symlink):
                errors = trusted_source_authority_errors(candidate)

        self.assertTrue(any("contains a symlink" in error for error in errors))

    def test_new_authority_module_and_all_authority_roots_are_protected(self) -> None:
        changed = [
            "governance_eval/future_authority_module.py",
            "schemas/v9/future.schema.json",
            ".github/actions/future/action.yml",
            ".github/workflows/future.yml",
            ".github/governance/future.yml",
            "requirements-governance.lock",
            "pyproject.toml",
            "AGENTS.md",
            "TASK.md",
            "docs/ordinary.md",
        ]

        protected = protected_surface.protected_authority_paths(changed)

        self.assertEqual(protected, sorted(changed[:-1]))
        for path in changed[:-1]:
            with self.subTest(enforced_path=path), tempfile.TemporaryDirectory() as tmp:
                errors = supportability._architecture_governance_change_errors(
                    Path(tmp), [path], "a" * 40, Path(tmp) / "supportability.yml"
                )
                self.assertTrue(
                    any(
                        "protected " in error and " change " in error
                        for error in errors
                    )
                )

    def test_source_adopter_contract_is_explicit(self) -> None:
        agents = (self.root / "AGENTS.md").read_text(encoding="utf-8")
        task = (self.root / "TASK.md").read_text(encoding="utf-8")
        readme = (self.root / "README.md").read_text(encoding="utf-8")
        adr = (
            self.root / "docs" / "adr" / "0004-native-organization-required-workflow.md"
        ).read_text(encoding="utf-8")

        for document in (task, readme, adr):
            self.assertIn("Governance source", document)
            self.assertIn("external verifier", document.lower())
            self.assertIn("legacy", document.lower())
        self.assertIn("diagnostic, never required", agents)
        self.assertIn("organization required workflow", task)
        self.assertIn("stable final job", readme)
        self.assertIn("supersedes", adr.lower())

    def test_active_contract_does_not_restore_self_referential_requirements(
        self,
    ) -> None:
        active_contracts = (
            "AGENTS.md",
            "TASK.md",
            "README.md",
            "docs/adr/0002-source-adopter-authority.md",
            "docs/self-enforcement-canary.md",
            "docs/supportability-github-enforcement.md",
        )
        forbidden = (
            "all four required contexts are GREEN",
            "Protect `main` with the existing four check contexts",
            "Governance changes must pass the same protected pull-request path",
        )
        for relative_path in active_contracts:
            text = (self.root / relative_path).read_text(encoding="utf-8")
            for phrase in forbidden:
                with self.subTest(path=relative_path, phrase=phrase):
                    self.assertNotIn(phrase, text)


class PermissionScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_workflow_permissions_reject_privilege_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            shutil.copytree(self.root / ".github" / "workflows", workflow_root)
            caller = workflow_root / "supportability-enforcement.yml"
            caller.write_text(
                caller.read_text(encoding="utf-8").replace(
                    "  checks: read\n", "  checks: read\n  id-token: write\n", 1
                ),
                encoding="utf-8",
            )

            errors = permission_scope_errors(root)

        self.assertTrue(any("authority ceiling" in error for error in errors))

    def test_workflow_permissions_require_explicit_top_level_map(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            (workflow_root / "implicit.yml").write_text(
                "name: Implicit\n"
                "on: pull_request_target\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
                encoding="utf-8",
            )

            errors = permission_scope_errors(root)

        self.assertTrue(any("declaration is missing" in error for error in errors))

    def test_workflow_permissions_reject_bare_null_map(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            workflow_root.mkdir(parents=True)
            (workflow_root / "null.yml").write_text(
                "name: Null\n"
                "on: pull_request_target\n"
                "permissions:\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-24.04\n"
                "    steps:\n"
                "      - run: true\n",
                encoding="utf-8",
            )

            errors = permission_scope_errors(root)

        self.assertTrue(any("declaration is malformed" in error for error in errors))

    def test_workflow_permissions_reject_duplicate_keys(self) -> None:
        cases = {
            "workflow-block": (
                "permissions:\n"
                "  contents: write\n"
                "  contents: read\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-24.04\n"
            ),
            "workflow-inline": (
                "permissions: {contents: write, contents: read}\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-24.04\n"
            ),
            "job-inline": (
                "permissions: {}\n"
                "jobs:\n"
                "  check:\n"
                "    permissions: {contents: write, contents: read}\n"
                "    runs-on: ubuntu-24.04\n"
            ),
        }
        for name, body in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                workflow_root = root / ".github" / "workflows"
                workflow_root.mkdir(parents=True)
                (workflow_root / "duplicate.yml").write_text(
                    f"name: Duplicate\non: pull_request_target\n{body}",
                    encoding="utf-8",
                )

                errors = permission_scope_errors(root)

                self.assertTrue(
                    any("declaration is malformed" in error for error in errors),
                    errors,
                )

    def test_workflow_permissions_reject_write_all_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow_root = root / ".github" / "workflows"
            shutil.copytree(self.root / ".github" / "workflows", workflow_root)
            workflow = workflow_root / "governance-shadow.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    "permissions:\n  contents: read", "permissions: write-all", 1
                ),
                encoding="utf-8",
            )

            errors = permission_scope_errors(root)

        self.assertTrue(any("malformed" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
