# Governance

Governance is a Python 3.12 governance product for evidence-backed pull-request decisions. Governance source development and Governance adopter enforcement are separate trust boundaries.

## Authority boundary

- Governance source uses the independent `Governance Source Qualification` check.
- Source lint, type, tests, and build run without secrets or write authority in an exact-hash `pull_request` workflow. A base-controlled qualifier executes no candidate code and reconciles that exact PR/head/run/job result before writing the source check.
- Qualifier code, its workflow pair, the pinned lock, and package contract are byte-frozen to the trusted base; intentional updates use the pull-request-only maintainer lane.
- Governance product checks may run on Governance source as diagnostics; they are never required there.
- The owner has one auditable, pull-request-only maintainer editing lane. Direct push, force push, and deletion remain blocked.
- An adopter explicitly installs an exact certified Governance SHA in typed configuration. An organization ruleset requires the central workflow at that exact SHA.
- The central `pull_request` workflow evaluates the exact target head from protected Governance source with no secrets or write authority. Its stable final job is the GitHub-native merge authority; a target-local same-name workflow cannot replace it.
- Merge queue is optional. The standard profile is pull-request-only until repository eligibility and event bindings are proved.

AI availability is not merge authority. Missing, late, quota-limited, or unavailable AI evidence records `AI_REVIEW_UNAVAILABLE` after the bounded cutoff; valid exact-head P0-P2 findings remain blocking.

## Source development

Run the independent source checks:

```text
python -m governance_eval.workflow_contract
python -m ruff check .
python -m ruff format --check .
python -m ruff check --select C901 --config "lint.mccabe.max-complexity=10" governance_eval
python -m mypy governance_eval
python -m unittest discover -s tests -p "test_*.py"
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

The Phase 1 benchmark remains a product regression, not source merge authority:

```text
python -m governance_eval verify --artifacts-dir artifacts/phase1
```

## Release and adoption

The controlled sequence is source boundary → native product publication → exact publication-merge qualification → guarded organization-ruleset activation → configuration-only migration → disposable canaries → immutable release. Keep one active implementation PR at a time. Multiple finite local repair iterations are allowed until the frozen suite passes.

`python.standard.v1` remains the default non-SQL profile. A trusted operator may opt a repository with statically resolvable packaged SQLite into the only database profile in this release:

```text
python -m governance_eval.cli adoption-bundle ... --profile python.sqlite.v1
```

Native bundles contain typed configuration, the pinned Supportability Standard, and an exact-SHA adoption manifest. They do not install a target-local Governance caller or require a verifier App ID. The external verifier implementation remains available only for legacy installations and historical receipts; it is not the default path or a native release prerequisite.

The generator first performs read-only profile discovery. SQLite under the standard profile, uncommitted required SQL, dynamic SQL, unsupported statements, or any profile/configuration/manifest/enrollment mismatch blocks. The SQLite profile appends evaluator-owned `python.sqlite-supportability.v1`; its evidence reports gate implementation, repository SQL supportability, and SQL behavior proof separately. PostgreSQL, Snowflake, ORM abstraction, arbitrary SQL commands, and configurable allowlists are unsupported.

Source-control settings changes require guarded scripts, before-and-after API snapshots and hashes, fresh verification, and rollback only for an incomplete transaction. The previous self-referential required-check profile is not the desired baseline.

See [ADR 0004](docs/adr/0004-native-organization-required-workflow.md) for the current adopter-authority decision and `TASK.md` for completion evidence. ADR 0002 remains the source-authority and legacy-verifier history.
