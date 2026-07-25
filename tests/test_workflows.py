from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

from governance_eval.architecture_policy import architecture_command_lines
from governance_eval.paths import repo_root


def _legacy_startup_receipt_strings() -> tuple[str, ...]:
    boot = "boot"
    strap = "strap"
    return (
        boot + strap + "-receipt",
        "baseline protected workflow missing " + "on main",
        "Baseline " + boot.capitalize() + strap + " Receipt Required",
        "Confirm " + boot + strap + " is still required",
        boot.capitalize() + strap + " reason",
        "remove " + boot + strap + " mode",
    )


def _workflow_input_validation_script(workflow: str) -> str:
    block = workflow.split("      - name: Validate workflow inputs", 1)[1].split(
        "      - name: Bind validated AI-review supportability config", 1
    )[0]
    script = block.split("          python - <<'PY'\n", 1)[1].split(
        "\n          PY", 1
    )[0]
    return textwrap.dedent(script)


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_shadow_verification_consumes_pinned_toolchain(self) -> None:
        workflow = (self.root / ".github/workflows/governance-shadow.yml").read_text(
            encoding="utf-8"
        )
        action = (
            self.root / ".github/actions/setup-governance-toolchain/action.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('python-version: "3.12.13"', workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("context-kind: PHASE1_SHADOW", workflow)
        self.assertIn("expected-artifact-name: governance-benchmark-json", workflow)
        self.assertIn('"${{ steps.toolchain.outputs.python-path }}"', workflow)
        verification = workflow.split("      - name: Run Phase 1 verification", 1)[
            1
        ].split("      - name: Validate and preserve shadow toolchain receipt", 1)[0]
        self.assertNotIn("run: python ", verification)
        self.assertIn('bootstrap["validate_receipt"]', workflow)
        self.assertIn('bootstrap["validate_live_receipt"]', workflow)
        self.assertIn("Run authenticated Docker boundary controls", workflow)
        self.assertIn("Bind trusted runner Docker CLI identity", workflow)
        self.assertIn("Provision pinned Docker image", workflow)
        self.assertIn(
            "python@sha256:72d3d75f2639ab82b34b29390ad3d6e0827c775befee94edda8e9976818f488d",
            workflow,
        )
        self.assertIn('GOVERNANCE_LIVE_DOCKER: "1"', workflow)
        self.assertIn(
            "GOVERNANCE_RUFF_LINUX_BINARY: ${{ steps.toolchain.outputs.bin-path }}/ruff",
            workflow,
        )
        self.assertIn(
            "GOVERNANCE_TRUSTED_DOCKER_PATH: ${{ steps.docker-runtime.outputs.path }}",
            workflow,
        )
        self.assertIn(
            "GOVERNANCE_TRUSTED_DOCKER_SHA256: ${{ steps.docker-runtime.outputs.sha256 }}",
            workflow,
        )
        self.assertIn(
            "GOVERNANCE_TRUSTED_DOCKER_HOST: ${{ steps.docker-runtime.outputs.host }}",
            workflow,
        )
        self.assertIn('-p "test_ruff_docker_live.py"', workflow)
        self.assertIn("hmac.compare_digest(actual, expected)", workflow)
        self.assertIn("governance-toolchain-receipt.json", workflow)
        self.assertIn("steps.receipt.outcome != 'success'", workflow)
        shadow_job = workflow.split("  shadow:", 1)[1].split("    steps:", 1)[0]
        self.assertIn("timeout-minutes: 10", shadow_job)
        self.assertNotIn("continue-on-error:", shadow_job)
        receipt_step = workflow.split(
            "      - name: Validate and preserve shadow toolchain receipt", 1
        )[1].split("      - name: Read benchmark summary", 1)[0]
        self.assertIn("continue-on-error: true", receipt_step)
        self.assertIn("PHASE1_SHADOW", action)
        self.assertNotIn("GITHUB_PATH", action)

    def test_native_required_workflow_is_central_read_only_and_fail_closed(
        self,
    ) -> None:
        workflow = (self.root / ".github/workflows/governance-required.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("on:\n  pull_request:\n", workflow)
        for forbidden in (
            "pull_request_target",
            "merge_group:",
            "workflow_dispatch:",
            "schedule:",
            "branches:",
            "paths:",
            "types:",
            "secrets.",
            "private-key",
            "checks: write",
            "statuses: write",
            "needs:",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        self.assertEqual(workflow.count("permissions:"), 1)
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertEqual(workflow.count("timeout-minutes: 10"), 1)
        self.assertEqual(workflow.count("persist-credentials: false"), 2)
        actions = {
            "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10": 2,
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1": 1,
            "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f": 1,
        }
        self.assertEqual(workflow.count("uses:"), sum(actions.values()))
        for action, count in actions.items():
            with self.subTest(action=action):
                self.assertEqual(workflow.count(f"uses: {action}"), count)
        for binding in (
            'test "$repository" = "mbh-solutions/governance"',
            "${{ github.event.pull_request.head.sha }}",
            'test "$GITHUB_WORKFLOW_REF" =',
            '--authority-mode "github.organization_required_workflow.v1"',
            '--workflow-commit-sha "${GITHUB_WORKFLOW_SHA}"',
            "continue-on-error: true",
            "if: ${{ always() }}",
            'test "$EVALUATION_OUTCOME" = "success"',
            'raise SystemExit(decision.get("status") != "PASS")',
        ):
            with self.subTest(binding=binding):
                self.assertIn(binding, workflow)

    def test_shadow_workflow_runs_on_merge_group_sha(self) -> None:
        workflow = (self.root / ".github/workflows/governance-shadow.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("  merge_group:\n    types:\n      - checks_requested", workflow)
        self.assertIn("github.event.merge_group.head_sha", workflow)
        self.assertIn("github.event.merge_group.base_sha", workflow)

    def test_reusable_gate_consumes_pinned_toolchain_interpreter(self) -> None:
        workflow = (self.root / ".github/workflows/supportability-gate.yml").read_text(
            encoding="utf-8"
        )
        action = (
            self.root / ".github/actions/setup-governance-toolchain/action.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('python-version: "3.12.13"', workflow)
        self.assertIn("id: setup-python", workflow)
        self.assertIn(
            "uses: markheck-solutions/governance/.github/actions/"
            "setup-governance-toolchain@50a7c1c958fe06056206429d7e2f194e0288738c",
            workflow,
        )
        self.assertNotIn(
            "uses: ./.github/actions/setup-governance-toolchain",
            workflow.split("name: Supportability Gate", 1)[1],
        )
        provision = workflow.index(
            "      - name: Provision pinned governance toolchain"
        )
        self.assertGreater(
            provision, workflow.index("      - name: Validate workflow inputs")
        )
        self.assertLess(
            provision,
            workflow.index("      - name: Run configured supportability gates"),
        )
        post_provision = workflow[provision:]
        pinned_invocation = '"${{ steps.toolchain.outputs.python-path }}"'
        self.assertEqual(post_provision.count(pinned_invocation), 6)
        architecture_block = post_provision.split(
            "      - name: Run approved architecture fitness gate", 1
        )[1].split("      - name: Reconcile Codex review evidence", 1)[0]
        self.assertIn(
            "python -m governance_eval architecture-gate",
            architecture_block,
        )
        self.assertEqual(
            architecture_command_lines(workflow),
            [
                "python -m governance_eval architecture-gate \\",
            ],
        )
        non_architecture_post_provision = post_provision.replace(architecture_block, "")
        self.assertNotRegex(non_architecture_post_provision, r"(?m)^\s+python(?:\s|$)")
        self.assertNotIn("GITHUB_PATH", post_provision)
        self.assertNotRegex(post_provision, r"(?m)^\s+(?:export\s+)?PATH=")
        for binding in (
            "context-kind: SUPPORTABILITY_EVALUATION",
            "base-sha: ${{ inputs.governance-ref }}",
            "evaluator-sha: ${{ inputs.governance-ref }}",
            "target-base-sha: ${{ inputs.target-base-sha }}",
            "target-head-sha: ${{ inputs.target-head-sha }}",
            "head-repository-id: ${{ inputs.target-head-repository-id || github.event.pull_request.head.repo.id }}",
            "event-name: ${{ github.event_name }}",
            "event-action: ${{ github.event.action }}",
            "run-attempt: ${{ github.run_attempt }}",
            "expected-artifact-name: ${{ inputs.artifact-name }}",
        ):
            with self.subTest(binding=binding):
                self.assertIn(binding, workflow)
        gate_block = workflow.split(
            "      - name: Run configured supportability gates", 1
        )[1].split("      - name: Run approved architecture fitness gate", 1)[0]
        for output in (
            "GOVERNANCE_TOOLCHAIN_PYTHON_PATH",
            "GOVERNANCE_TOOLCHAIN_BIN_PATH",
            "GOVERNANCE_TOOLCHAIN_RECEIPT_PATH",
            "GOVERNANCE_TOOLCHAIN_LOCK_SHA256",
            "GOVERNANCE_TOOLCHAIN_RECEIPT_FILE_SHA256",
        ):
            self.assertIn(output, gate_block)
        self.assertNotIn("GITHUB_PATH", action)
        self.assertIn("default: PUBLICATION", action)
        self.assertIn('--context-kind "${CONTEXT_KIND:?}"', action)
        self.assertNotIn("governance-toolchain-receipt.json", workflow)
        self.assertNotIn("shutil.copyfile", workflow)
        self.assertIn("path: target/artifacts/supportability/*", workflow)
        summary_block = workflow.split("      - name: Read supportability summary", 1)[
            1
        ].split("      - name: Upload supportability evidence", 1)[0]
        self.assertIn(
            'summary_python="${{ steps.toolchain.outputs.python-path }}"',
            summary_block,
        )
        self.assertIn(
            'summary_python="${{ steps.setup-python.outputs.python-path }}"',
            summary_block,
        )

    def test_toolchain_publication_is_bounded_pinned_and_inert(self) -> None:
        workflow = (
            self.root / ".github/workflows/toolchain-publication.yml"
        ).read_text(encoding="utf-8")
        action = (
            self.root / ".github/actions/setup-governance-toolchain/action.yml"
        ).read_text(encoding="utf-8")
        bootstrap = (self.root / "governance_eval/toolchain_bootstrap.py").read_text(
            encoding="utf-8"
        )
        lock = (self.root / "requirements-governance.lock").read_text(encoding="utf-8")

        self.assertIn('python-version: "3.12.13"', workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("pull_request: {}", workflow)
        self.assertNotIn("paths:", workflow.split("permissions:", 1)[0])
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertNotIn("continue-on-error:", workflow)
        self.assertIn("uses: ./.github/actions/setup-governance-toolchain", workflow)
        self.assertLess(
            workflow.index("uses: ./.github/actions/setup-governance-toolchain"),
            workflow.index("-m governance_eval verify"),
        )
        self.assertIn(
            "python-path: ${{ steps.setup-python.outputs.python-path }}", workflow
        )
        self.assertIn('"${{ steps.toolchain.outputs.python-path }}"', workflow)
        self.assertIn("steps.toolchain.outputs.receipt-file-sha256", workflow)
        self.assertIn(
            "base-sha: ${{ github.event.pull_request.base.sha }}",
            workflow,
        )
        self.assertIn("if: always()", workflow)
        self.assertIn('bootstrap["validate_live_receipt"](', workflow)
        self.assertIn("governance_root, receipt, expected_context", workflow)
        self.assertIn("hmac.compare_digest(actual, expected)", workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 1)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn(
            "governance-toolchain-publication-${{ github.run_id }}-${{ github.run_attempt }}",
            workflow,
        )
        self.assertIn("id: upload", workflow)
        self.assertIn("steps.upload.outputs.artifact-id", workflow)
        self.assertIn("steps.upload.outputs.artifact-digest", workflow)
        self.assertIn('bootstrap["create_artifact_binding"](', workflow)
        self.assertIn("governance-toolchain-artifact-binding.json", workflow)
        self.assertIn("id: binding_upload", workflow)
        self.assertIn("steps.binding_upload.outputs.artifact-id", workflow)
        self.assertIn("steps.binding_upload.outputs.artifact-digest", workflow)
        for context_key in (
            "repository-id:",
            "head-repository-id:",
            "event-name:",
            "pull-request-number:",
            "workflow-ref:",
            "workflow-sha:",
            "run-id:",
            "run-attempt:",
            "expected-artifact-name:",
        ):
            self.assertIn(context_key, workflow)
        for required in (
            "--require-hashes",
            "--only-binary=:all:",
            "--no-deps",
            'venv.EnvBuilder(with_pip=False, clear=False, symlinks=os.name != "nt")',
            '"ensurepip"',
            "command_evidence",
        ):
            self.assertIn(required, bootstrap)
        for required in (
            'GH_TOKEN: ""',
            'GITHUB_TOKEN: ""',
            '"$base_python" -I',
            "receipt-path",
            "receipt-file-sha256",
            '--failure-receipt "$receipt_path"',
            '--github-output "${GITHUB_OUTPUT:?}"',
            '--repository "${REPOSITORY:?}"',
            '--run-attempt "${RUN_ATTEMPT:?}"',
            '--expected-artifact-name "${EXPECTED_ARTIFACT_NAME:?}"',
        ):
            self.assertIn(required, action)
        run_script = action.split("      run: |", 1)[1]
        self.assertNotIn("${{ inputs.", run_script)
        self.assertNotIn("/bin/python", action)
        self.assertNotIn("runtime_root}/bin", action)
        self.assertEqual(lock.count("ruff==0.15.21"), 1)
        self.assertIn(
            "bab0905d2f29e0d9fbc3c373ed23db0095edaa3f71f1f4f519ec15134d9e85c8",
            lock,
        )
        self.assertIn(
            "d4b8d9a2f0f12b816b50447f6eccb9f4bb01a6b82c86b50fb3b5354b458dc6d3",
            lock,
        )

    def test_required_governance_text_uses_no_banned_condition_word(self) -> None:
        banned = "un" + "less"
        checked_suffixes = {".md", ".py", ".json", ".yml", ".yaml"}
        checked_roots = ("docs", "schemas", "tests", "governance_eval", ".github")
        violations: list[str] = []
        for root_name in checked_roots:
            root = self.root / root_name
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.suffix not in checked_suffixes:
                    continue
                if root_name == "docs" and path.name in {
                    "GOAL.md",
                    "02_GOAL.md",
                    "03_GOAL.md",
                }:
                    continue
                text = path.read_text(encoding="utf-8")
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if banned in line.lower():
                        violations.append(
                            f"{path.relative_to(self.root).as_posix()}:{line_number}:{line.strip()}"
                        )
        self.assertEqual(violations, [])

    def test_governance_workflows_are_read_only_nonblocking_and_retained(self) -> None:
        workflows = {
            path.name: path.read_text(encoding="utf-8")
            for path in (self.root / ".github/workflows").glob("*.yml")
        }
        self.assertIn("governance-shadow.yml", workflows)
        self.assertIn("governance-evaluate.yml", workflows)
        self.assertIn("supportability-gate.yml", workflows)
        self.assertIn("delivery-receipt.yml", workflows)
        self.assertIn("supportability-enforcement.yml", workflows)
        self.assertIn("source-candidate.yml", workflows)
        self.assertIn("source-qualification.yml", workflows)
        for name, text in workflows.items():
            if name in {
                "supportability-enforcement.yml",
                "source-qualification.yml",
            }:
                self.assertIn("pull_request_target:", text)
            else:
                self.assertNotRegex(text, r"(?m)^  pull_request_target:\s*$")
            self.assertIn("contents: read", text)
            self.assertNotIn("secrets: inherit", text)
        for name in (
            "governance-shadow.yml",
            "governance-evaluate.yml",
            "supportability-gate.yml",
            "delivery-receipt.yml",
        ):
            self.assertIn("retention-days: 90", workflows[name])
        self.assertIn("workflow_call:", workflows["governance-evaluate.yml"])
        self.assertIn("governance-ref:", workflows["governance-evaluate.yml"])
        self.assertIn("revision-mode:", workflows["governance-evaluate.yml"])
        self.assertIn("target-pr-number:", workflows["governance-evaluate.yml"])
        self.assertIn("GOVERNANCE_CHECKOUT_REF", workflows["governance-evaluate.yml"])
        self.assertIn("validate-target-request", workflows["governance-evaluate.yml"])
        self.assertNotIn("allowed = {", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-digest", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-id", workflows["governance-evaluate.yml"])
        self.assertIn("artifact-id", workflows["governance-shadow.yml"])
        self.assertIn(
            "github.event.merge_group.head_sha || github.sha",
            workflows["governance-shadow.yml"],
        )
        self.assertIn("workflow_call:", workflows["supportability-gate.yml"])
        self.assertIn(
            "TARGET_PR_HEAD_SHA: ${{ inputs.target-pr-head-sha || inputs.target-head-sha }}",
            workflows["supportability-gate.yml"],
        )
        self.assertIn(
            "TARGET_PR_HEAD_SHA: ${{ inputs.target-pr-head-sha || inputs.target-head-sha }}",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn("Supportability Gate", workflows["supportability-gate.yml"])
        self.assertIn("supportability-config", workflows["supportability-gate.yml"])
        self.assertIn(
            "Validate supportability config", workflows["supportability-gate.yml"]
        )
        self.assertIn("continue-on-error: true", workflows["supportability-gate.yml"])
        self.assertIn("supportability-gate", workflows["supportability-gate.yml"])
        self.assertIn(
            "Run approved architecture fitness gate",
            workflows["supportability-gate.yml"],
        )
        self.assertIn(
            "python -m governance_eval architecture-gate",
            workflows["supportability-gate.yml"],
        )
        self.assertIn(
            "architecture-gate-result.json", workflows["supportability-gate.yml"]
        )
        self.assertIn(
            "architecture-gate-result.md", workflows["supportability-gate.yml"]
        )
        self.assertIn(
            "governance_eval.codex_review_gate", workflows["supportability-gate.yml"]
        )
        self.assertRegex(
            workflows["supportability-gate.yml"],
            r'(?s)- name: Reconcile Codex review evidence.*?env:\s+GITHUB_TOKEN: \$\{\{ github\.token \}\}.*?"\$\{\{ steps\.toolchain\.outputs\.python-path \}\}" -m governance_eval\.codex_review_gate',
        )
        self.assertIn(
            "ai-review-gate-result.json", workflows["supportability-gate.yml"]
        )
        self.assertNotIn("copilot-review-gate", workflows["supportability-gate.yml"])
        self.assertRegex(
            workflows["supportability-gate.yml"],
            r'(?s)- name: Run configured supportability gates.*?env:\s+GH_TOKEN: "".*?"\$\{\{ steps\.toolchain\.outputs\.python-path \}\}" -m governance_eval supportability-gate',
        )
        self.assertIn(
            'replace("\\r", " ").replace("\\n", " ")',
            workflows["supportability-gate.yml"],
        )
        self.assertIn("pull-requests: read", workflows["supportability-gate.yml"])
        self.assertIn("artifact-digest", workflows["supportability-gate.yml"])
        self.assertIn(
            "artifact-digest: ${{ steps.upload.outputs.artifact-digest }}",
            workflows["supportability-gate.yml"],
        )
        self.assertNotIn(
            "steps.upload.outputs.digest", workflows["supportability-gate.yml"]
        )
        self.assertIn(
            "Fail closed on RED supportability evidence",
            workflows["supportability-gate.yml"],
        )
        enforcement = workflows["supportability-enforcement.yml"]
        self.assertIn("pull_request_target:", enforcement)
        self.assertNotIn("pull_request_review:", enforcement)
        self.assertNotIn("issue_comment:", enforcement)
        top_permissions = enforcement.split("jobs:", 1)[0].split("permissions:", 1)[1]
        self.assertIn("checks: read", top_permissions)
        self.assertNotIn("issues: read", top_permissions)
        self.assertNotIn("actions: write", enforcement)
        self.assertNotIn("rerun", enforcement.lower())
        self.assertIn("request-codex-review:", enforcement)
        self.assertIn("@codex review", enforcement)
        self.assertIn("Governance review request for exact head", enforcement)
        self.assertIn("issues: write", enforcement)
        self.assertIn("Codex review request transport unavailable", enforcement)
        self.assertIn("AI_REVIEW_UNAVAILABLE", enforcement)
        self.assertIn("needs: request-codex-review", enforcement)
        self.assertIn("baseline-supportability:", enforcement)
        self.assertIn("candidate-supportability:", enforcement)
        self.assertIn("Baseline Protected Supportability Gate", enforcement)
        enforcement_docs = (
            self.root / "docs/supportability-github-enforcement.md"
        ).read_text(encoding="utf-8")
        for blocked_text in _legacy_startup_receipt_strings():
            for name in ("supportability-enforcement.yml", "delivery-receipt.yml"):
                self.assertNotIn(blocked_text, workflows[name])
            self.assertNotIn(blocked_text, Path(__file__).read_text(encoding="utf-8"))
            self.assertNotIn(blocked_text, enforcement_docs)
        protected_refs = re.findall(
            r"(?m)^    uses: markheck-solutions/governance/\.github/workflows/(supportability-gate|delivery-receipt)\.yml@([0-9a-f]{40})$",
            workflows["supportability-enforcement.yml"],
        )
        self.assertEqual(
            protected_refs,
            [
                ("supportability-gate", "50a7c1c958fe06056206429d7e2f194e0288738c"),
                ("supportability-gate", "50a7c1c958fe06056206429d7e2f194e0288738c"),
                ("delivery-receipt", "50a7c1c958fe06056206429d7e2f194e0288738c"),
            ],
        )
        self.assertNotIn(
            "uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@main",
            workflows["supportability-enforcement.yml"],
        )
        self.assertNotIn(
            "uses: ./.github/workflows/supportability-gate.yml",
            workflows["supportability-enforcement.yml"],
        )
        self.assertNotIn(
            "uses: ./.github/workflows/delivery-receipt.yml",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "artifact-name: baseline-supportability-gate-evidence",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "supportability-artifact-name: baseline-supportability-gate-evidence",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "needs['baseline-supportability'].outputs['artifact-id']",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "needs['baseline-supportability'].outputs['artifact-digest']",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "needs['candidate-supportability'].outputs['artifact-id']",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "needs['candidate-supportability'].outputs['artifact-digest']",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "missing-baseline-supportability-artifact-id",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "missing-baseline-supportability-artifact-digest",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "missing-candidate-supportability-artifact-id",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "missing-candidate-supportability-artifact-digest",
            workflows["supportability-enforcement.yml"],
        )
        baseline_block, candidate_block = workflows[
            "supportability-enforcement.yml"
        ].split("  candidate-supportability:", 1)
        candidate_block, delivery_block = candidate_block.split(
            "  delivery-receipt:", 1
        )
        self.assertIn(
            "uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@50a7c1c958fe06056206429d7e2f194e0288738c",
            baseline_block,
        )
        self.assertIn(
            "target-base-sha: ${{ github.event.pull_request.base.sha }}", baseline_block
        )
        self.assertIn(
            "target-head-sha: ${{ github.event.pull_request.head.sha }}", baseline_block
        )
        self.assertIn(
            "governance-ref: 50a7c1c958fe06056206429d7e2f194e0288738c", baseline_block
        )
        self.assertIn(
            "uses: markheck-solutions/governance/.github/workflows/supportability-gate.yml@50a7c1c958fe06056206429d7e2f194e0288738c",
            candidate_block,
        )
        self.assertIn(
            "target-head-sha: ${{ github.event.pull_request.head.sha }}",
            candidate_block,
        )
        self.assertIn(
            "governance-ref: 50a7c1c958fe06056206429d7e2f194e0288738c", candidate_block
        )
        self.assertNotIn(
            "governance-ref: ${{ github.event.pull_request.head.sha }}", enforcement
        )
        self.assertIn("supportability-artifact-id", delivery_block)
        self.assertIn("supportability-artifact-digest", delivery_block)
        self.assertIn("candidate-supportability-artifact-id", delivery_block)
        self.assertIn("candidate-supportability-artifact-digest", delivery_block)
        self.assertIn(
            "governance-ref: 50a7c1c958fe06056206429d7e2f194e0288738c", delivery_block
        )
        self.assertIn(
            "if: ${{ github.event.pull_request.base.ref == 'main' }}",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn(
            "if: ${{ always() && github.event.pull_request.base.ref == 'main' }}",
            workflows["supportability-enforcement.yml"],
        )

    def test_source_qualification_separates_candidate_and_authority(self) -> None:
        workflow_root = self.root / ".github/workflows"
        source_candidate = (workflow_root / "source-candidate.yml").read_text(
            encoding="utf-8"
        )
        source_qualifier = (workflow_root / "source-qualification.yml").read_text(
            encoding="utf-8"
        )

        self.assertRegex(source_candidate, r"(?m)^  pull_request:\s*$")
        self.assertNotIn("pull_request_target:", source_candidate)
        self.assertIn("Checkout exact candidate without execution", source_qualifier)
        self.assertIn(
            "python -m governance_eval.workflow_contract ../candidate",
            source_qualifier,
        )
        self.assertNotIn("working-directory: candidate", source_qualifier)
        self.assertIn(
            "python -m governance_eval.source_qualification", source_qualifier
        )
        self.assertIn(
            "SOURCE_EVENT_UPDATED_AT: ${{ github.event.pull_request.updated_at }}",
            source_qualifier,
        )

    def test_codex_reconciliation_uses_pre_execution_bound_config_without_architecture_drift(
        self,
    ) -> None:
        workflow = (self.root / ".github/workflows/supportability-gate.yml").read_text(
            encoding="utf-8"
        )
        binding_name = "      - name: Bind validated AI-review supportability config"
        binding_block = workflow.split(binding_name, 1)[1].split(
            "      - name: Validate supportability config", 1
        )[0]
        self.assertIn("id: bind_ai_config", binding_block)
        self.assertNotIn("continue-on-error", binding_block)
        self.assertIn("bind_supportability_config", binding_block)
        self.assertIn('["git", "rev-parse", "HEAD"]', binding_block)
        self.assertIn('"ls-files",', binding_block)
        self.assertIn('os.environ["CONFIG_PATH"],', binding_block)
        self.assertIn(
            "print(f\"bound-config-path={binding['bound_config_path']}\")",
            binding_block,
        )
        self.assertIn(
            "print(f\"binding-sha256={binding['binding_sha256']}\")",
            binding_block,
        )
        self.assertLess(
            workflow.index(binding_name),
            workflow.index("      - name: Run configured supportability gates"),
        )
        codex_block = workflow.split(
            "      - name: Reconcile Codex review evidence", 1
        )[1].split("      - name: Read supportability summary", 1)[0]
        self.assertNotIn("../target/${CONFIG_PATH}", codex_block)
        self.assertIn(
            '"${{ steps.toolchain.outputs.python-path }}" -m governance_eval.codex_review_gate \\\n'
            '            --config "${{ steps.bind_ai_config.outputs.bound-config-path }}" \\\n'
            '            --config-source-path "$CONFIG_PATH" \\\n'
            '            --config-binding-digest "${{ steps.bind_ai_config.outputs.binding-sha256 }}" \\\n',
            codex_block,
        )
        architecture_block = workflow.split(
            "      - name: Run approved architecture fitness gate", 1
        )[1].split("      - name: Reconcile Codex review evidence", 1)[0]
        self.assertIn(
            "python -m governance_eval architecture-gate \\\n"
            '            --config "../target/${CONFIG_PATH}" \\\n'
            "            --target-repo ../target \\\n",
            architecture_block,
        )


class ReusableWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = repo_root(Path(__file__).resolve())

    def test_reusable_gate_binds_automatic_request_receipt(self) -> None:
        workflow = (self.root / ".github/workflows/supportability-gate.yml").read_text(
            encoding="utf-8"
        )
        call_inputs = workflow.split("  workflow_call:", 1)[1].split("    outputs:", 1)[
            0
        ]
        for name in (
            "request-outcome",
            "request-transport-command-json",
            "request-transport-started-at",
            "request-transport-completed-at",
            "request-transport-timeout-seconds",
            "request-transport-timed-out",
            "request-transport-exit-code",
        ):
            with self.subTest(required_input=name):
                self.assertRegex(
                    call_inputs,
                    rf"(?m)^      {re.escape(name)}:\n"
                    r"        required: true\n"
                    r"        type: string$",
                )
        for name in (
            "request-transport-error-sha256",
            "request-response-validation-error-sha256",
            "request-comment-id",
            "request-comment-created-at",
        ):
            with self.subTest(optional_input=name):
                self.assertRegex(
                    call_inputs,
                    rf"(?m)^      {re.escape(name)}:\n"
                    r"        required: false\n"
                    r"        type: string\n"
                    r'        default: ""$',
                )

        env_bindings = {
            "REQUEST_WORKFLOW_REF": "${{ github.workflow_ref }}",
            "REQUEST_WORKFLOW_SHA": "${{ github.workflow_sha }}",
            "REQUEST_EVENT_NAME": "${{ github.event_name }}",
            "REQUEST_EVENT_ACTION": "${{ github.event.action }}",
            "REQUEST_RUN_ID": "${{ github.run_id }}",
            "REQUEST_RUN_ATTEMPT": "${{ github.run_attempt }}",
            "REQUEST_REPOSITORY_ID": "${{ github.repository_id }}",
            "REQUEST_OUTCOME": "${{ inputs.request-outcome }}",
            "REQUEST_TRANSPORT_COMMAND_JSON": (
                "${{ inputs.request-transport-command-json }}"
            ),
            "REQUEST_TRANSPORT_STARTED_AT": (
                "${{ inputs.request-transport-started-at }}"
            ),
            "REQUEST_TRANSPORT_COMPLETED_AT": (
                "${{ inputs.request-transport-completed-at }}"
            ),
            "REQUEST_TRANSPORT_TIMEOUT_SECONDS": (
                "${{ inputs.request-transport-timeout-seconds }}"
            ),
            "REQUEST_TRANSPORT_TIMED_OUT": (
                "${{ inputs.request-transport-timed-out }}"
            ),
            "REQUEST_TRANSPORT_EXIT_CODE": (
                "${{ inputs.request-transport-exit-code }}"
            ),
            "REQUEST_TRANSPORT_ERROR_SHA256": (
                "${{ inputs.request-transport-error-sha256 }}"
            ),
            "REQUEST_RESPONSE_VALIDATION_ERROR_SHA256": (
                "${{ inputs.request-response-validation-error-sha256 }}"
            ),
            "REQUEST_COMMENT_ID": "${{ inputs.request-comment-id }}",
            "REQUEST_COMMENT_CREATED_AT": ("${{ inputs.request-comment-created-at }}"),
        }
        for name, value in env_bindings.items():
            with self.subTest(env=name):
                self.assertIn(f"      {name}: {value}", workflow)

        validation_block = workflow.split("      - name: Validate workflow inputs", 1)[
            1
        ].split("      - name: Bind validated AI-review supportability config", 1)[0]
        for token in (
            "f\"{os.environ['TARGET_REPOSITORY']}/.github/workflows/\"",
            '"supportability-enforcement.yml@refs/heads/main"',
            'os.environ["REQUEST_WORKFLOW_SHA"]',
            'os.environ["REQUEST_EVENT_NAME"] != "pull_request_target"',
            '"opened", "reopened", "synchronize", "ready_for_review"',
            'os.environ["REQUEST_RUN_ATTEMPT"] != "1"',
            'os.environ["REQUEST_OUTCOME"]',
            'os.environ["REQUEST_TRANSPORT_COMMAND_JSON"]',
            'os.environ["REQUEST_TRANSPORT_STARTED_AT"]',
            'os.environ["REQUEST_TRANSPORT_COMPLETED_AT"]',
            'os.environ["REQUEST_TRANSPORT_TIMEOUT_SECONDS"]',
            'os.environ["REQUEST_TRANSPORT_TIMED_OUT"]',
            'os.environ["REQUEST_TRANSPORT_EXIT_CODE"]',
            'os.environ["REQUEST_TRANSPORT_ERROR_SHA256"]',
            '"REQUEST_RESPONSE_VALIDATION_ERROR_SHA256"',
            'os.environ["REQUEST_COMMENT_ID"]',
            'os.environ["REQUEST_COMMENT_CREATED_AT"]',
        ):
            with self.subTest(validation=token):
                self.assertIn(token, validation_block)
        self.assertNotIn('"pull_request_target", "merge_group"', validation_block)

        codex_block = workflow.split(
            "      - name: Reconcile Codex review evidence", 1
        )[1].split("      - name: Read supportability summary", 1)[0]
        self.assertIn("receipt_args=(", codex_block)
        required_cli = {
            "--request-workflow-ref": "REQUEST_WORKFLOW_REF",
            "--request-workflow-sha": "REQUEST_WORKFLOW_SHA",
            "--request-event-name": "REQUEST_EVENT_NAME",
            "--request-event-action": "REQUEST_EVENT_ACTION",
            "--request-run-id": "REQUEST_RUN_ID",
            "--request-run-attempt": "REQUEST_RUN_ATTEMPT",
            "--request-repository-id": "REQUEST_REPOSITORY_ID",
            "--request-outcome": "REQUEST_OUTCOME",
            "--request-transport-command-json": "REQUEST_TRANSPORT_COMMAND_JSON",
            "--request-transport-started-at": "REQUEST_TRANSPORT_STARTED_AT",
            "--request-transport-completed-at": "REQUEST_TRANSPORT_COMPLETED_AT",
            "--request-transport-timeout-seconds": (
                "REQUEST_TRANSPORT_TIMEOUT_SECONDS"
            ),
            "--request-transport-timed-out": "REQUEST_TRANSPORT_TIMED_OUT",
            "--request-transport-exit-code": "REQUEST_TRANSPORT_EXIT_CODE",
        }
        for argument, variable in required_cli.items():
            with self.subTest(cli=argument):
                self.assertIn(f'{argument} "${variable}"', codex_block)
        self.assertIn('--request-comment-id "$REQUEST_COMMENT_ID"', codex_block)
        self.assertIn(
            '--request-comment-created-at "$REQUEST_COMMENT_CREATED_AT"',
            codex_block,
        )
        self.assertIn(
            '--request-transport-error-sha256 "$REQUEST_TRANSPORT_ERROR_SHA256"',
            codex_block,
        )
        self.assertIn(
            "--request-response-validation-error-sha256 "
            '"$REQUEST_RESPONSE_VALIDATION_ERROR_SHA256"',
            codex_block,
        )
        self.assertIn('"${receipt_args[@]}"', codex_block)
        self.assertNotIn("eval ", codex_block)
        self.assertNotIn("${{ inputs.request-", codex_block)

    def test_reusable_gate_request_receipt_validation_controls(self) -> None:
        workflow = (self.root / ".github/workflows/supportability-gate.yml").read_text(
            encoding="utf-8"
        )
        script = _workflow_input_validation_script(workflow)
        body = (
            f"@codex review\n\nGovernance review request for exact head `{'b' * 40}`."
        )
        command = [
            "gh",
            "api",
            "--method",
            "POST",
            "repos/markheck-solutions/governance/issues/57/comments",
            "-f",
            f"body={body}",
        ]
        base = {
            "TARGET_REPOSITORY": "markheck-solutions/governance",
            "TARGET_BASE_SHA": "a" * 40,
            "TARGET_HEAD_SHA": "b" * 40,
            "TARGET_PR_HEAD_SHA": "b" * 40,
            "TARGET_PR_BASE_SHA": "a" * 40,
            "MERGE_GROUP_REF": "",
            "MERGE_GROUP_SHA": "",
            "MERGE_GROUP_EVENT_ID": "",
            "EVENT_CREATED_AT": "2026-07-17T13:32:56Z",
            "GOVERNANCE_REF": "c" * 40,
            "TARGET_PR_NUMBER": "57",
            "ARTIFACT_NAME": "candidate-supportability-gate-evidence",
            "CONFIG_PATH": ".github/governance/supportability.yml",
            "REQUEST_WORKFLOW_REF": (
                "markheck-solutions/governance/.github/workflows/"
                "supportability-enforcement.yml@refs/heads/main"
            ),
            "REQUEST_WORKFLOW_SHA": "d" * 40,
            "REQUEST_EVENT_NAME": "pull_request_target",
            "REQUEST_EVENT_ACTION": "opened",
            "REQUEST_RUN_ID": "29583977309",
            "REQUEST_RUN_ATTEMPT": "1",
            "REQUEST_REPOSITORY_ID": "1280677092",
            "REQUEST_OUTCOME": "POSTED",
            "REQUEST_TRANSPORT_COMMAND_JSON": json.dumps(
                command, separators=(",", ":")
            ),
            "REQUEST_TRANSPORT_STARTED_AT": "2026-07-17T13:32:56Z",
            "REQUEST_TRANSPORT_COMPLETED_AT": "2026-07-17T13:32:58Z",
            "REQUEST_TRANSPORT_TIMEOUT_SECONDS": "30",
            "REQUEST_TRANSPORT_TIMED_OUT": "false",
            "REQUEST_TRANSPORT_EXIT_CODE": "0",
            "REQUEST_TRANSPORT_ERROR_SHA256": "",
            "REQUEST_RESPONSE_VALIDATION_ERROR_SHA256": "",
            "REQUEST_COMMENT_ID": "5003756722",
            "REQUEST_COMMENT_CREATED_AT": "2026-07-17T13:32:58Z",
        }

        cases = {
            "posted": ({}, 0),
            "transport_unavailable": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_EXIT_CODE": "1",
                    "REQUEST_TRANSPORT_TIMED_OUT": "false",
                    "REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64,
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                0,
            ),
            "transport_timeout": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_TIMED_OUT": "true",
                    "REQUEST_TRANSPORT_EXIT_CODE": "124",
                    "REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64,
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                0,
            ),
            "transport_exit_124_without_timeout": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_TIMED_OUT": "false",
                    "REQUEST_TRANSPORT_EXIT_CODE": "124",
                    "REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64,
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                0,
            ),
            "transport_launch_failure": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_TIMED_OUT": "false",
                    "REQUEST_TRANSPORT_EXIT_CODE": "",
                    "REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64,
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                0,
            ),
            "response_invalid": (
                {
                    "REQUEST_OUTCOME": "RESPONSE_INVALID",
                    "REQUEST_TRANSPORT_EXIT_CODE": "0",
                    "REQUEST_RESPONSE_VALIDATION_ERROR_SHA256": ("sha256:" + "f" * 64),
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                0,
            ),
            "rerun": ({"REQUEST_RUN_ATTEMPT": "2"}, 64),
            "wrong_workflow": ({"REQUEST_WORKFLOW_REF": "main"}, 64),
            "unsupported_action": ({"REQUEST_EVENT_ACTION": "closed"}, 64),
            "partial_posted": ({"REQUEST_COMMENT_ID": ""}, 64),
            "posted_missing_exit_code": ({"REQUEST_TRANSPORT_EXIT_CODE": ""}, 64),
            "contradictory_posted": (
                {"REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64},
                64,
            ),
            "posted_response_error": (
                {"REQUEST_RESPONSE_VALIDATION_ERROR_SHA256": "sha256:" + "f" * 64},
                64,
            ),
            "partial_unavailable": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_EXIT_CODE": "1",
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                64,
            ),
            "partial_response_invalid": (
                {
                    "REQUEST_OUTCOME": "RESPONSE_INVALID",
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                64,
            ),
            "response_invalid_missing_exit_code": (
                {
                    "REQUEST_OUTCOME": "RESPONSE_INVALID",
                    "REQUEST_TRANSPORT_EXIT_CODE": "",
                    "REQUEST_RESPONSE_VALIDATION_ERROR_SHA256": ("sha256:" + "f" * 64),
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                64,
            ),
            "exit_code_out_of_range": (
                {"REQUEST_TRANSPORT_EXIT_CODE": "256"},
                64,
            ),
            "malformed_missing_exit_code": (
                {"REQUEST_TRANSPORT_EXIT_CODE": "NONE"},
                64,
            ),
            "metacharacter_comment_id": ({"REQUEST_COMMENT_ID": "1\n2"}, 64),
            "invalid_timestamp": (
                {"REQUEST_COMMENT_CREATED_AT": "2026-02-30T13:32:58Z"},
                64,
            ),
            "malformed_command": (
                {"REQUEST_TRANSPORT_COMMAND_JSON": "not-json"},
                64,
            ),
            "mutated_command": (
                {
                    "REQUEST_TRANSPORT_COMMAND_JSON": json.dumps(
                        [*command[:-1], "body=@codex review"], separators=(",", ":")
                    )
                },
                64,
            ),
            "reversed_transport_times": (
                {"REQUEST_TRANSPORT_COMPLETED_AT": "2026-07-17T13:32:55Z"},
                64,
            ),
            "wrong_timeout": ({"REQUEST_TRANSPORT_TIMEOUT_SECONDS": "31"}, 64),
            "contradictory_timeout": ({"REQUEST_TRANSPORT_TIMED_OUT": "true"}, 64),
            "timeout_with_non_timeout_exit": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_TIMED_OUT": "true",
                    "REQUEST_TRANSPORT_EXIT_CODE": "1",
                    "REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64,
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                64,
            ),
            "launch_failure_claims_timeout": (
                {
                    "REQUEST_OUTCOME": "TRANSPORT_UNAVAILABLE",
                    "REQUEST_TRANSPORT_TIMED_OUT": "true",
                    "REQUEST_TRANSPORT_EXIT_CODE": "",
                    "REQUEST_TRANSPORT_ERROR_SHA256": "sha256:" + "e" * 64,
                    "REQUEST_COMMENT_ID": "",
                    "REQUEST_COMMENT_CREATED_AT": "",
                },
                64,
            ),
        }
        for name, (changes, expected) in cases.items():
            with self.subTest(case=name):
                env = os.environ.copy()
                env.update(base)
                env.update(changes)
                completed = subprocess.run(
                    [sys.executable, "-c", script],
                    check=False,
                    capture_output=True,
                    env=env,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(completed.returncode, expected, completed.stderr)

    def test_enforcement_jobs_use_pull_request_target_conditions(self) -> None:
        enforcement = (
            self.root / ".github/workflows/supportability-enforcement.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(
            enforcement.count(
                "if: ${{ github.event.pull_request.base.ref == 'main' }}"
            ),
            3,
        )
        self.assertIn(
            "if: ${{ always() && github.event.pull_request.base.ref == 'main' }}",
            enforcement,
        )

    def test_delivery_receipt_workflow_is_bound_and_fail_closed(self) -> None:
        workflows = {
            path.name: path.read_text(encoding="utf-8")
            for path in (self.root / ".github/workflows").glob("*.yml")
        }
        self.assertIn(
            "architecture_violation_count", workflows["supportability-gate.yml"]
        )
        self.assertIn(
            "architecture_known_debt_applied_count",
            workflows["supportability-gate.yml"],
        )
        self.assertIn(
            "architecture_expired_known_debt_count",
            workflows["supportability-gate.yml"],
        )
        self.assertIn("ai_review_evidence_status", workflows["supportability-gate.yml"])
        self.assertNotIn("Copilot review request", workflows["supportability-gate.yml"])
        self.assertIn("workflow_call:", workflows["delivery-receipt.yml"])
        self.assertIn("Delivery Receipt", workflows["delivery-receipt.yml"])
        self.assertIn(
            '== "Baseline Protected Delivery Receipt / Delivery Receipt"',
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            'gh api "repos/${TARGET_REPOSITORY}/actions/artifacts/${SUPPORTABILITY_ARTIFACT_ID}/zip"',
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            'replace("\\r", " ").replace("\\n", " ")', workflows["delivery-receipt.yml"]
        )
        self.assertIn(
            "Record supportability artifact metadata", workflows["delivery-receipt.yml"]
        )
        self.assertIn("id: supportability_artifact", workflows["delivery-receipt.yml"])
        self.assertIn("SUPPORTABILITY_ARTIFACT_ID", workflows["delivery-receipt.yml"])
        self.assertIn(
            "SUPPORTABILITY_ARTIFACT_DIGEST", workflows["delivery-receipt.yml"]
        )
        self.assertIn(
            "CANDIDATE_SUPPORTABILITY_ARTIFACT_ID", workflows["delivery-receipt.yml"]
        )
        self.assertIn(
            "CANDIDATE_SUPPORTABILITY_ARTIFACT_NAME", workflows["delivery-receipt.yml"]
        )
        self.assertIn(
            "Download candidate supportability evidence",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            "/actions/artifacts/${SUPPORTABILITY_ARTIFACT_ID}/zip",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            "/actions/artifacts/${CANDIDATE_SUPPORTABILITY_ARTIFACT_ID}/zip",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            "repos/{os.environ['TARGET_REPOSITORY']}/actions/artifacts/{artifact_id}",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn("evidence_present(root)", workflows["delivery-receipt.yml"])
        self.assertIn(
            'str(run.get("id") or "") == os.environ["GITHUB_RUN_ID"]',
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            "archive_digest(archive_path) == expected_digest",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn("proof_flags=()", workflows["delivery-receipt.yml"])
        self.assertIn(
            "proof_flags+=(--protected-baseline-judge-ran --baseline-receipt-produced)",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn(
            "proof_flags+=(--candidate-judge-ran --candidate-receipt-produced)",
            workflows["delivery-receipt.yml"],
        )
        self.assertIn('"${proof_flags[@]}"', workflows["delivery-receipt.yml"])
        self.assertIn(
            "candidate-supportability-gate-evidence",
            workflows["supportability-enforcement.yml"],
        )
        self.assertIn('digest="sha256:${digest}"', workflows["delivery-receipt.yml"])
        self.assertIn("if: always()", workflows["delivery-receipt.yml"])
        self.assertNotIn(
            "actions/runs/{run_id}/artifacts", workflows["delivery-receipt.yml"]
        )
        self.assertIn("delivery-receipt", workflows["delivery-receipt.yml"])
        self.assertIn("--architecture-result", workflows["delivery-receipt.yml"])
        self.assertIn(
            "architecture-gate-result.json", workflows["delivery-receipt.yml"]
        )
        self.assertIn("verify-receipt", workflows["delivery-receipt.yml"])
        self.assertIn("artifact-digest", workflows["delivery-receipt.yml"])
        self.assertIn(
            "artifact-digest: ${{ steps.upload.outputs.artifact-digest }}",
            workflows["delivery-receipt.yml"],
        )
        self.assertNotIn(
            "steps.upload.outputs.digest", workflows["delivery-receipt.yml"]
        )
        docs = (self.root / "docs/supportability-github-enforcement.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("trusted base config", docs)
        self.assertIn("AI_REVIEW_UNAVAILABLE", docs)
        self.assertIn("Codex is evidence, not approval", docs)
        self.assertNotIn("governance-review-evidence:v1", docs)

    def test_private_repository_receipt_auth_is_active_and_fail_closed(self) -> None:
        receipt_workflow = (
            self.root / ".github/workflows/delivery-receipt.yml"
        ).read_text(encoding="utf-8")
        auth_command = "gh auth setup-git --force --hostname github.com"
        receipt_job = receipt_workflow.split("  receipt:\n", 1)[1]
        receipt_job_env = receipt_job.split("    env:\n", 1)[1].split(
            "    steps:\n", 1
        )[0]
        checkout_block = receipt_workflow.split(
            "      - name: Checkout governance evaluator", 1
        )[1].split("      - name: Set up Python", 1)[0]
        verify_block = receipt_workflow.split(
            "      - name: Verify delivery receipt", 1
        )[1].split("      - name: Read delivery summary", 1)[0]
        verify_script = verify_block.split("        run: |\n", 1)[1]
        verify_commands = [
            line[10:]
            for line in verify_script.splitlines()
            if line.startswith("          ") and line.strip()
        ]
        self.assertEqual(
            verify_commands[:3],
            [
                auth_command,
                "cd governance",
                "python -m governance_eval verify-receipt \\",
            ],
        )
        self.assertNotIn("|| true", verify_block)
        self.assertIn("\n      GH_TOKEN: ${{ github.token }}\n", receipt_job_env)
        self.assertIn(
            'expected_url = f"https://github.com/{repository}.git"', receipt_workflow
        )
        self.assertIn(
            'os.environ["TARGET_REPOSITORY_URL"] != expected_url', receipt_workflow
        )
        self.assertNotIn("x-access-token", receipt_workflow)
        self.assertIn("\n          persist-credentials: false\n", checkout_block)
        self.assertNotIn("persist-credentials: true", receipt_workflow)
        self.assertNotIn("secrets: inherit", receipt_workflow)
        self.assertNotIn("--skip-live", receipt_workflow)

        fail_closed_block = receipt_workflow.split(
            "      - name: Fail closed on RED delivery receipt", 1
        )[1]
        fail_closed_header, fail_closed_script = fail_closed_block.split(
            "        run: |\n", 1
        )
        fail_closed_commands = [
            line[10:]
            for line in fail_closed_script.splitlines()
            if line.startswith("          ") and line.strip()
        ]
        self.assertIn(
            "\n        if: always() && steps.summary.outputs.owner_status != 'GREEN'\n",
            fail_closed_header,
        )
        self.assertEqual(
            fail_closed_commands,
            ['echo "Delivery receipt is RED"', "exit 1"],
        )


if __name__ == "__main__":
    unittest.main()
