from __future__ import annotations

import io
import json
import shutil
import subprocess
import unittest
import os
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from unittest import mock

from governance_eval.docker_runtime import (
    docker_run_argv,
    execute_ruff_docker,
    runtime_root_path,
)
from governance_eval.artifact_verifier import MAX_ENTRY_BYTES
import governance_eval.docker_runtime as docker_runtime
from governance_eval.execution_plan_v2 import compile_execution_plan_v2
from governance_eval.execution_result_v2 import validate_execution_result_v2
from governance_eval.schemas import validate_named
from test_execution_plan_v2 import _receipt


class DockerRuntimePolicyTests(unittest.TestCase):
    def test_sqlite_profile_reader_uses_artifact_entry_limit(self) -> None:
        payload = {
            "schema_version": "1.0",
            "profile": "python.sqlite.v1",
            "status": "PASS",
        }
        raw = json.dumps(payload).encode("utf-8")
        compact = {
            **payload,
            "capabilities_path": ".governance-output/sqlite-profile.json",
            "capabilities_sha256": sha256(raw).hexdigest(),
        }
        workspace = Path("C:/workspace")

        with mock.patch(
            "governance_eval.docker_runtime._read_regular_file", return_value=raw
        ) as reader:
            self.assertEqual(
                docker_runtime._load_sqlite_profile(compact, workspace), payload
            )

        reader.assert_called_once_with(
            workspace / ".governance-output/sqlite-profile.json", MAX_ENTRY_BYTES
        )

    def test_sqlite_profile_file_open_is_nonblocking_and_regular_only(self) -> None:
        compact = {
            "schema_version": "1.0",
            "profile": "python.sqlite.v1",
            "status": "PASS",
            "capabilities_path": ".governance-output/sqlite-profile.json",
            "capabilities_sha256": "0" * 64,
        }
        with TemporaryDirectory() as directory:
            workspace = Path(directory)
            path = workspace / compact["capabilities_path"]
            path.parent.mkdir()
            path.write_text("{}", encoding="utf-8")
            hostile = SimpleNamespace(
                st_mode=stat.S_IFIFO,
                st_size=2,
                st_dev=1,
                st_ino=1,
                st_mtime_ns=1,
                st_ctime_ns=1,
            )
            with mock.patch(
                "governance_eval.docker_runtime.os.fstat", return_value=hostile
            ) as fstat:
                self.assertIsNone(
                    docker_runtime._load_sqlite_profile(compact, workspace)
                )
            self.assertEqual(fstat.call_count, 1)

        with mock.patch(
            "governance_eval.docker_runtime.os.open", side_effect=OSError
        ) as opened:
            self.assertIsNone(
                docker_runtime._load_sqlite_profile(compact, Path("unused"))
            )
        flags = opened.call_args.args[1]
        self.assertEqual(
            flags & getattr(os, "O_NONBLOCK", 0), getattr(os, "O_NONBLOCK", 0)
        )

    def test_subprocess_environments_drop_host_injection_variables(self) -> None:
        executable = Path("C:/trusted/tool.exe")
        with mock.patch.dict(
            os.environ,
            {
                "DOCKER_HOST": "tcp://attacker.invalid:2375",
                "DOCKER_CONTEXT": "attacker",
                "DOCKER_CONFIG": "C:/attacker",
                "GIT_DIR": "C:/attacker/.git",
                "GIT_WORK_TREE": "C:/attacker/worktree",
            },
        ):
            docker_environment = docker_runtime._docker_environment(executable)
            git_environment = docker_runtime._git_environment(executable)

        self.assertNotIn("DOCKER_HOST", docker_environment)
        self.assertNotIn("DOCKER_CONTEXT", docker_environment)
        self.assertNotIn("DOCKER_CONFIG", docker_environment)
        self.assertNotIn("GIT_DIR", git_environment)
        self.assertNotIn("GIT_WORK_TREE", git_environment)

    def test_run_command_has_exact_lockdown_and_only_disposable_mounts(self) -> None:
        plan = compile_execution_plan_v2(
            _receipt(), capability="lint", adapter_id="python.ruff-check.v1"
        )
        workspace = Path("C:/temp/disposable-target")
        docker = Path("C:/Program Files/Docker/docker.exe")
        toolchain_root = Path("C:/temp/sealed-toolchain")

        argv = docker_run_argv(
            docker=docker,
            docker_host="npipe:////./pipe/docker_engine",
            plan=plan,
            workspace=workspace,
            toolchain_root=toolchain_root,
            container_name="governance-test-container",
        )

        self.assertEqual(argv[0], str(docker))
        self.assertEqual(argv[1], "--host=npipe:////./pipe/docker_engine")
        for required in (
            "--read-only",
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=128",
            "--memory=536870912",
            "--cpus=1.0",
            "--user=65532:65532",
        ):
            self.assertIn(required, argv)
        self.assertIn(
            f"type=bind,src={workspace},dst=/workspace",
            argv,
        )
        self.assertIn(
            f"type=bind,src={toolchain_root},dst=/opt/governance-toolchain,readonly",
            argv,
        )
        self.assertNotIn("-v", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("sh", argv)
        self.assertNotIn("bash", argv)
        self.assertEqual(argv[-6:], plan.step["argv"])

    def test_missing_docker_emits_schema_valid_block(self) -> None:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )

        result = execute_ruff_docker(
            plan=plan,
            receipt=receipt,
            target_root=Path("C:/not-used"),
            evaluator_root=Path("C:/not-used"),
            toolchain_binary=Path("C:/not-used/ruff"),
        )

        validate_named("execution_result_v2", result)
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(result["termination"], "NOT_STARTED")
        self.assertEqual(result["errors"], ["Docker CLI path is invalid"])
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

    def test_rehashed_mutated_plan_blocks_before_docker_resolution(self) -> None:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )
        runtime = {**plan.runtime, "network": "bridge"}
        hostile = replace(plan, runtime=runtime, plan_id="")
        payload = hostile.to_json()
        payload.pop("plan_id")
        from governance_eval.hashing import sha256_json

        hostile = replace(hostile, plan_id=sha256_json(payload))

        with mock.patch(
            "governance_eval.docker_runtime._trusted_docker"
        ) as docker_resolution:
            result = execute_ruff_docker(
                plan=hostile,
                receipt=receipt,
                target_root=Path("C:/not-used"),
                evaluator_root=Path("C:/not-used"),
                toolchain_binary=Path("C:/not-used/ruff"),
            )

        docker_resolution.assert_not_called()
        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            result["errors"],
            ["execution plan differs from evaluator-owned plan"],
        )

    def test_non_exited_zero_code_cannot_pass(self) -> None:
        result, plan, receipt = self._host_result(
            termination="TIMED_OUT", exit_code=0, duration=120, errors=[]
        )

        self.assertEqual(result["capability_status"], "BLOCK_TECHNICAL")
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

    def test_cleanup_error_preserves_launched_outcome(self) -> None:
        result, plan, receipt = self._host_result(
            termination="EXITED",
            exit_code=0,
            duration=1,
            errors=["Docker container cleanup failed"],
        )

        self.assertEqual(result["termination"], "EXITED")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["errors"], ["Docker container cleanup failed"])
        self.assertEqual(
            validate_execution_result_v2(result, plan, receipt)["integrity_status"],
            "INTEGRITY_VALID",
        )

    def test_run_boundary_captures_cleanup_timeout(self) -> None:
        process = mock.Mock()
        process.stdout = io.BytesIO(b"captured stdout")
        process.stderr = io.BytesIO(b"")
        process.poll.return_value = 0
        process.wait.return_value = 0
        with (
            mock.patch("subprocess.Popen", return_value=process),
            mock.patch(
                "governance_eval.docker_runtime._command",
                side_effect=(
                    subprocess.TimeoutExpired("docker inspect", 10),
                    SimpleNamespace(returncode=0),
                ),
            ),
        ):
            outcome = docker_runtime._run_bounded(
                ["docker", "run"],
                docker=Path("C:/trusted/docker.exe"),
                docker_host="npipe:////./pipe/docker_engine",
                container_name="governance-test-container",
                timeout_seconds=120,
                output_limit=65536,
            )

        self.assertEqual(outcome["termination"], "EXITED")
        self.assertEqual(outcome["exit_code"], 0)
        self.assertEqual(outcome["errors"], ["Docker container cleanup failed"])
        self.assertGreater(outcome["stdout"]["captured_bytes"], 0)

    def test_cleanup_listing_transport_failure_blocks(self) -> None:
        with mock.patch(
            "governance_eval.docker_runtime._command",
            side_effect=(
                SimpleNamespace(returncode=1, stdout="", stderr="daemon unavailable"),
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ),
        ):
            errors = docker_runtime._cleanup_errors(
                Path("C:/trusted/docker.exe"),
                "npipe:////./pipe/docker_engine",
                "governance-test-container",
            )

        self.assertEqual(errors, ["Docker container cleanup failed"])

    def test_materialization_ignores_export_ignore_attributes(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "target"
            workspace = Path(directory) / "workspace"
            root.mkdir()
            commands = (
                ("init", "-q"),
                ("config", "user.email", "governance@example.invalid"),
                ("config", "user.name", "Governance Test"),
            )
            for arguments in commands:
                subprocess.run(["git", *arguments], cwd=root, check=True, timeout=10)
            (root / ".gitattributes").write_text(
                "hidden.py export-ignore\n", encoding="utf-8"
            )
            (root / "hidden.py").write_text("import os\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True, timeout=10)
            subprocess.run(
                ["git", "commit", "-qm", "tree"],
                cwd=root,
                check=True,
                timeout=10,
            )
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            git = Path(shutil.which("git") or "missing-git").resolve()

            docker_runtime._materialize_tree(
                root,
                {"commit_sha": commit, "tree_sha": tree},
                workspace,
                git,
            )

            self.assertEqual(
                (workspace / "hidden.py").read_text(encoding="utf-8"),
                "import os\n",
            )

    def test_materialization_rejects_windows_path_escapes(self) -> None:
        for path in (r"..\escaped.py", r"C:\attacker\owned.py"):
            with self.subTest(path=path), TemporaryDirectory() as directory:
                workspace = Path(directory) / "workspace"
                workspace.mkdir()
                entry = f"100644 blob {'a' * 40}\t{path}".encode("utf-8")

                with self.assertRaisesRegex(
                    docker_runtime.DockerRuntimeError, "path is unsafe"
                ):
                    docker_runtime._materialize_entry(
                        Path(directory),
                        Path("C:/trusted/git.exe"),
                        workspace,
                        entry,
                    )

    def _host_result(
        self,
        *,
        termination: str,
        exit_code: int,
        duration: int,
        errors: list[str],
    ) -> tuple[dict[str, object], object, object]:
        receipt = _receipt()
        plan = compile_execution_plan_v2(
            receipt, capability="lint", adapter_id="python.ruff-check.v1"
        )
        started = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
        runtime_root = runtime_root_path(plan)
        workspace = runtime_root / "workspace"
        toolchain = runtime_root / "toolchain"
        command = docker_run_argv(
            docker=Path(plan.runtime["docker_path"]),
            docker_host=plan.runtime["docker_host"],
            plan=plan,
            workspace=workspace,
            toolchain_root=toolchain,
            container_name="governance-test-container",
        )
        outcome = {
            "termination": termination,
            "exit_code": exit_code,
            "stdout": docker_runtime._empty_stream(),
            "stderr": docker_runtime._empty_stream(),
            "started_at": started,
            "completed_at": started + timedelta(seconds=duration),
        }
        result = docker_runtime._result(
            plan,
            receipt,
            None,
            plan.runtime["docker_host"],
            command,
            started,
            outcome=outcome,
            errors=errors,
        )
        return result, plan, receipt


if __name__ == "__main__":
    unittest.main()
