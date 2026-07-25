from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from governance_eval.benchmark import BENCHMARK_PASS
from governance_eval.benchmark import run_benchmark
from governance_eval.cases import load_cases
from governance_eval.decision import decide
from governance_eval.detectors import run_detectors
from governance_eval.architecture_gate import main as architecture_gate_main
from governance_eval.adoption import bundle_main as adoption_bundle_main
from governance_eval.adoption import proof_main as adoption_proof_main
from governance_eval.lock import write_spaghetti_lock
from governance_eval.package_audit import run_package_audit
from governance_eval.paths import repo_root
from governance_eval.supportability import main as supportability_main
from governance_eval.target_eval import evaluate_target
from governance_eval.target_pack import validate_target_request


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    routed = _product_command(argv)
    if routed is not None:
        return routed
    parser = argparse.ArgumentParser(prog="governance-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)

    lock_parser = subparsers.add_parser(
        "lock", help="write the pinned Spaghetti lock file"
    )
    lock_parser.add_argument("--root", type=Path, default=None)

    run_parser = subparsers.add_parser("run-case", help="run one evaluation case")
    run_parser.add_argument("case_id")
    run_parser.add_argument("--root", type=Path, default=None)

    bench_parser = subparsers.add_parser("benchmark", help="run the complete benchmark")
    bench_parser.add_argument("--root", type=Path, default=None)
    bench_parser.add_argument("--repeat", type=int, default=3)
    bench_parser.add_argument(
        "--artifacts-dir", type=Path, default=Path("artifacts/phase1")
    )

    verify_parser = subparsers.add_parser(
        "verify", help="run tests and Phase 1 benchmark"
    )
    verify_parser.add_argument("--root", type=Path, default=None)
    verify_parser.add_argument("--repeat", type=int, default=3)
    verify_parser.add_argument(
        "--artifacts-dir", type=Path, default=Path("artifacts/phase1")
    )

    package_parser = subparsers.add_parser(
        "package-audit", help="build and audit the Governance wheel"
    )
    package_parser.add_argument("--repo-root", type=Path, required=True)
    package_parser.add_argument("--artifacts-dir", type=Path, required=True)

    target_parser = subparsers.add_parser(
        "evaluate-target", help="run a non-blocking target shadow evaluation"
    )
    target_parser.add_argument("--pack", type=Path, required=True)
    target_parser.add_argument("--base-sha", required=True)
    target_parser.add_argument("--head-sha", required=True)
    target_parser.add_argument("--merge-sha", default=None)
    target_parser.add_argument("--repository-url", default=None)
    target_parser.add_argument(
        "--revision-mode",
        choices=["HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC"],
        default=None,
    )
    target_parser.add_argument("--target-pr-number", type=int, default=None)
    target_parser.add_argument("--governance-owned-pack", action="store_true")
    target_parser.add_argument(
        "--review-gate",
        choices=[
            "GITHUB_CODEX_FINAL_REVIEW",
            "NOT_APPLICABLE",
        ],
        default=None,
    )
    target_parser.add_argument(
        "--github-review-state",
        choices=[
            "CLEAN",
            "STALE",
            "UNAVAILABLE",
            "BLOCKING_FINDINGS_PRESENT",
            "NOT_APPLICABLE",
        ],
        default=None,
    )
    target_parser.add_argument(
        "--artifacts-dir", type=Path, default=Path("artifacts/target")
    )

    validate_target_parser = subparsers.add_parser(
        "validate-target-request", help="validate target pack and revision inputs"
    )
    validate_target_parser.add_argument("--pack", type=Path, required=True)
    validate_target_parser.add_argument("--repository-url", required=True)
    validate_target_parser.add_argument("--base-sha", required=True)
    validate_target_parser.add_argument("--head-sha", required=True)
    validate_target_parser.add_argument("--merge-sha", default=None)
    validate_target_parser.add_argument(
        "--revision-mode",
        choices=["HISTORICAL_FIXED", "SAFE_FIXED", "CANDIDATE_DYNAMIC"],
        required=True,
    )

    args = parser.parse_args(argv)
    root = repo_root(getattr(args, "root", None))

    if args.command == "lock":
        lock = write_spaghetti_lock(root / "targets" / "spaghetti.lock.toml")
        print(json.dumps(lock.to_json(), indent=2, sort_keys=True))
        return 0
    if args.command == "run-case":
        return _run_case(args.case_id, root)
    if args.command == "benchmark":
        artifacts_dir = root / args.artifacts_dir
        result = run_benchmark(
            root=root,
            repeat=args.repeat,
            artifacts_dir=artifacts_dir,
            exact_commands=[
                _artifact_command("benchmark", args.repeat, args.artifacts_dir)
            ],
        )
        print(json.dumps(_summary(result), indent=2, sort_keys=True))
        return 0 if result["phase1_decision"] == BENCHMARK_PASS else 1
    if args.command == "verify":
        return _verify(root, args.repeat, root / args.artifacts_dir, args.artifacts_dir)
    if args.command == "package-audit":
        result = run_package_audit(args.repo_root, args.artifacts_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "PASS" else 1
    if args.command == "evaluate-target":
        result = evaluate_target(
            root / args.pack if not args.pack.is_absolute() else args.pack,
            args.base_sha,
            args.head_sha,
            root / args.artifacts_dir
            if not args.artifacts_dir.is_absolute()
            else args.artifacts_dir,
            args.merge_sha or None,
            args.repository_url,
            args.revision_mode,
            args.target_pr_number,
            args.governance_owned_pack,
            args.review_gate,
            args.github_review_state,
        )
        print(json.dumps(_target_summary(result), indent=2, sort_keys=True))
        return 0
    if args.command == "validate-target-request":
        pack = validate_target_request(
            root / args.pack if not args.pack.is_absolute() else args.pack,
            args.repository_url,
            args.base_sha,
            args.head_sha,
            args.merge_sha or None,
            args.revision_mode,
            root,
        )
        print(
            json.dumps(
                {"status": "PASS", "target_pack_id": pack["id"]},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    raise AssertionError("unreachable command")


def _product_command(argv: list[str]) -> int | None:
    if not argv:
        return None
    command = argv[0]
    direct = {
        "adoption-bundle": adoption_bundle_main,
        "adoption-proof": adoption_proof_main,
    }
    if command in direct:
        return direct[command](argv[1:])
    if command == "verify-candidate":
        from governance_eval.verifier_pipeline import main as verifier_main

        return verifier_main(argv[1:])
    if command == "architecture-gate":
        return architecture_gate_main(argv)
    if command in {
        "supportability-config",
        "supportability-gate",
        "delivery-receipt",
        "bootstrap-receipt",
        "verify-receipt",
    }:
        return supportability_main(argv)
    return None


def _run_case(case_id: str, root: Path) -> int:
    cases = {case["id"]: case for case in load_cases(root)}
    if case_id not in cases:
        print(f"unknown case id: {case_id}", file=sys.stderr)
        return 2
    case = cases[case_id]
    evidence = run_detectors(case, root)
    decision = decide(case, evidence)
    print(
        json.dumps(
            {
                "decision": decision.to_json(),
                "evidence": [item.to_json() for item in evidence],
            },
            indent=2,
        )
    )
    return 0 if decision.decision.value == case["expected_decision"] else 1


def _verify(
    root: Path, repeat: int, artifacts_dir: Path, command_artifacts_dir: Path
) -> int:
    test_command = [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-p",
        "test_*.py",
    ]
    tests = subprocess.run(test_command, cwd=root)
    if tests.returncode != 0:
        return tests.returncode
    result = run_benchmark(
        root=root,
        repeat=repeat,
        artifacts_dir=artifacts_dir,
        exact_commands=[_artifact_command("verify", repeat, command_artifacts_dir)],
    )
    print(json.dumps(_summary(result), indent=2, sort_keys=True))
    return 0 if result["phase1_decision"] == BENCHMARK_PASS else 1


def _artifact_command(command: str, repeat: int, artifacts_dir: Path) -> str:
    parts = ["python -m governance_eval", command]
    if repeat != 3:
        parts.extend(["--repeat", str(repeat)])
    parts.extend(["--artifacts-dir", artifacts_dir.as_posix()])
    return " ".join(parts)


def _summary(result: dict) -> dict:
    return {
        "phase1_decision": result["phase1_decision"],
        "acceptance_errors": result["acceptance_errors"],
        "metrics": result["metrics"],
        "artifact_path": result.get("artifact_path"),
    }


def _target_summary(result: dict) -> dict:
    return {
        "real_target_shadow_decision": result["real_target_shadow_decision"],
        "enforcement_mode": result["enforcement_mode"],
        "acceptance_errors": result["acceptance_errors"],
        "case_counts": result["case_counts"],
        "revision_mode": result["revision_mode"],
        "review_gate": result["review_gate"],
        "github_review_state": result["github_review_state"],
        "target_pr_number": result["target_pr_number"],
        "unknown_required_measurements": result["structural_measurements"][
            "unknown_required_count"
        ],
        "unknown_advisory_measurements": result["structural_measurements"][
            "unknown_advisory_count"
        ],
        "artifact_content_hash": result["artifact_content_hash"],
        "artifact_path": result.get("artifact_path"),
    }


if __name__ == "__main__":
    raise SystemExit(main())
