from __future__ import annotations

from dataclasses import dataclass


STANDARD_PROFILE_ADAPTERS = (
    ("lint", "python.ruff-check.v1", "EVALUATOR_AUTHORITATIVE"),
    ("format", "python.ruff-format-check.v1", "EVALUATOR_AUTHORITATIVE"),
    ("typecheck", "python.mypy.v1", "EVALUATOR_AUTHORITATIVE"),
    ("complexity", "python.ruff-c901.v1", "EVALUATOR_AUTHORITATIVE"),
    ("architecture", "python.architecture.v1", "EVALUATOR_AUTHORITATIVE"),
    ("tests", "python.unittest.v1", "COOPERATIVE_DYNAMIC"),
    ("build", "python.wheel-build.v1", "CONTAINED_BUILD"),
    ("package_audit", "python.package-audit.v1", "EVALUATOR_AUTHORITATIVE"),
    ("benchmark", "governance.phase1.v1", "EVALUATOR_AUTHORITATIVE"),
    ("integrity", "git.diff-integrity.v1", "EVALUATOR_AUTHORITATIVE"),
)
SQLITE_PROFILE_ADAPTERS = (
    *STANDARD_PROFILE_ADAPTERS,
    (
        "sql_supportability",
        "python.sqlite-supportability.v1",
        "EVALUATOR_AUTHORITATIVE",
    ),
)
PROFILE_ADAPTERS = {
    "python.standard.v1": STANDARD_PROFILE_ADAPTERS,
    "python.sqlite.v1": SQLITE_PROFILE_ADAPTERS,
}
PROFILE_RUNNERS = {
    "python.standard.v1": ("standard_profile", "python.standard-profile.v1"),
    "python.sqlite.v1": ("standard_profile", "python.sqlite-profile.v1"),
}


@dataclass(frozen=True)
class CapabilityAdapter:
    capability: str
    adapter_id: str
    assurance_class: str
    runtime_id: str
    module: str
    arguments: tuple[str, ...]
    working_directory: str
    timeout_seconds: int
    output_limit_bytes: int


_ADAPTERS = {
    ("lint", "python.ruff-check.v1"): CapabilityAdapter(
        capability="lint",
        adapter_id="python.ruff-check.v1",
        assurance_class="EVALUATOR_AUTHORITATIVE",
        runtime_id="evaluator.python-isolated.v1",
        module="ruff",
        arguments=("check", "--isolated", "--no-cache", "--no-respect-gitignore", "."),
        working_directory=".",
        timeout_seconds=120,
        output_limit_bytes=65536,
    ),
    ("standard_profile", "python.standard-profile.v1"): CapabilityAdapter(
        capability="standard_profile",
        adapter_id="python.standard-profile.v1",
        assurance_class="COOPERATIVE_DYNAMIC",
        runtime_id="evaluator.python-isolated.v1",
        module="governance_eval.standard_profile",
        arguments=(
            "-P",
            "-s",
            "-m",
            "governance_eval.standard_profile",
            "--workspace",
            "/workspace",
            "--benchmark-root",
            "/opt/governance-toolchain/benchmark",
        ),
        working_directory="/workspace",
        timeout_seconds=300,
        output_limit_bytes=65536,
    ),
    ("standard_profile", "python.sqlite-profile.v1"): CapabilityAdapter(
        capability="standard_profile",
        adapter_id="python.sqlite-profile.v1",
        assurance_class="COOPERATIVE_DYNAMIC",
        runtime_id="evaluator.python-isolated.v1",
        module="governance_eval.standard_profile",
        arguments=(
            "-P",
            "-s",
            "-m",
            "governance_eval.standard_profile",
            "--workspace",
            "/workspace",
            "--benchmark-root",
            "/opt/governance-toolchain/benchmark",
            "--profile",
            "python.sqlite.v1",
        ),
        working_directory="/workspace",
        timeout_seconds=300,
        output_limit_bytes=65536,
    ),
}


def get_capability_adapter(capability: str, adapter_id: str) -> CapabilityAdapter:
    return _ADAPTERS[(capability, adapter_id)]


def profile_adapters(profile: str) -> tuple[tuple[str, str, str], ...]:
    return PROFILE_ADAPTERS[profile]


def profile_runner(profile: str) -> tuple[str, str]:
    return PROFILE_RUNNERS[profile]


def runner_profile(adapter_id: str) -> str:
    for profile, (_capability, runner) in PROFILE_RUNNERS.items():
        if runner == adapter_id:
            return profile
    raise KeyError(adapter_id)


def is_profile_runner(adapter_id: str) -> bool:
    return any(runner == adapter_id for _capability, runner in PROFILE_RUNNERS.values())
