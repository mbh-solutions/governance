# Task: Practical Tamper-Resistant Governance v1

Implement, activate, and prove a reusable GitHub governance framework with independent Governance source qualification and explicit adopter enforcement.

## Goal

Governance is a target-neutral evaluator and GitHub enforcement framework for solo, AI-directed software development. It must:

- preserve the completed Phase 1 offline benchmark as a mandatory regression suite;
- judge changes with deterministic code, not narrative approval;
- execute target-specific capabilities through typed, versioned adapters;
- separate candidate execution from the trusted verifier and authoritative merge decision;
- protect evaluator authority, credentials, evidence, scope, thresholds, and required-check identity from candidate control;
- release through protected pull requests without making Governance application checks authoritative over Governance source edits;
- prove clean, defective, and stale-evidence canaries before any target rollout.

Governance v1 supports the Python 3.12 ecosystem only. `python.standard.v1`
remains the unchanged profile for non-SQL adopters. `python.sqlite.v1` is the
only opt-in database profile in this release.

Spaghetti remains one registered historical target pack and benchmark source. It is not the framework identity, default target, or special case in the core evaluator. TWMN remains out of scope until the SQLite publication is qualified and the existing disposable adopter passes every required canary; TWMN is then the first real SQLite adopter.

## Authority and evidence

- `AGENTS.md` remains the repository contract.
- External repository evidence must use exact immutable commit SHAs.
- Evaluated target remotes are never mutated. Declared untrusted execution may write only to disposable target copies; those mutations may never be pushed, persisted, or represented as target-repository changes. Historical source evidence is pinned to exact SHAs and digests. Generated evidence artifacts may be persisted only with required identity and digest bindings. Live GitHub state is freshly queried and treated as mutable evidence.
- Missing, malformed, stale, unsupported, unresolved, or unverifiable required evidence or capability is `BLOCK_TECHNICAL`.
- Only deterministic code computes `MERGE`, `BLOCK_TECHNICAL`, or `ASK_BUSINESS`.
- `ASK_BUSINESS` is reserved for genuine owner-scoped behavior ambiguity.
- Human approval, AI approval, waiver, allowlist, CODEOWNER approval, baseline debt, or known-debt metadata never converts RED to GREEN.
- Deterministic GitHub Actions own merge decisions. External AI evidence can add blocking findings but cannot be the availability dependency that authorizes deterministic checks.

## Revised threat model

Governance v1 protects these assets from candidate control:

- base-branch evaluator and verifier code;
- reusable and caller workflows;
- action and dependency pins;
- configuration and Supportability Standard hashes;
- toolchain and image identities;
- the authoritative result artifact directory and its evidence bindings;
- the GitHub required-check app and workflow identity;
- branch protection and rulesets.

Candidate-controlled repository content may be malicious. It may attempt command injection, arbitrary configuration, file writes, network or secret access, result replacement, artifact replay, workflow spoofing, evaluator modification, process escape, or resource exhaustion.

Governance prevents candidate control of protected assets and authoritative merge decisions. It does not claim Byzantine proof that arbitrary malicious code loaded into an in-process dynamic test runner truthfully executed assertions. That narrow non-guarantee does not weaken command, filesystem, credential, artifact, scope, threshold, workflow, replay, process, or resource-abuse controls. `docs/adr/0001-governance-v1-threat-model.md` records the complete decision.

## Preserved Phase 1 benchmark

The Phase 1 benchmark remains mandatory and must continue to provide:

1. Versioned schemas for cases, detector evidence, review findings, benchmark results, and decisions.
2. The executable Spaghetti PR #141 partial-metadata interleaving reproducer. Review prose alone is not evidence.
3. Paired clean and defective controls for:
   - private helper re-export;
   - test dependency on private production internals;
   - import cycle;
   - untyped public dictionary boundary;
   - narrowed validation-gate scope;
   - weakened validation threshold.
4. Clean, defective, and evasion or mutation controls for every blocking rule.
5. Machine-readable benchmark artifacts.
6. A complete local verification command:

   ```text
   python -m governance_eval verify --artifacts-dir artifacts/phase1
   ```

Phase 1 acceptance remains:

- critical-defect recall: 100%;
- negative-control recall: 100%;
- false-block rate: 0% for the verified-safe controls;
- repeated deterministic decisions: identical;
- deterministic flake rate: 0%;
- benchmark JSON: schema-valid;
- execution duration: recorded;
- complete verification: nonzero exit on any failed criterion.

These thresholds may not be weakened, narrowed, waived, or replaced by narrative evidence.

## Framework contract

### Source and adopter authority

- Governance source development and Governance adopter enforcement are different trust boundaries.
- Governance application contexts are diagnostic on Governance source and are required only by adopter repositories that explicitly install Governance.
- Governance source uses the independent `Governance Source Qualification` check. Its permanent maintainer lane is auditable and pull-request-only; direct push, force push, and deletion remain prohibited.
- Source candidate execution is confined to the exact-hash `pull_request` workflow with read-only contents access. The base-controlled qualifier executes no candidate content; it validates the frozen source workflow pair and unique check producer, then accepts only the exact repository, PR, head, first-attempt run, and complete successful job set.
- The source qualifier modules, workflow pair, pinned lock, and package contract must remain byte-identical to the trusted base during ordinary qualification. Intentional authority updates use the auditable pull-request-only maintainer lane.
- Source-control settings changes require exact-repository guards, before-and-after API snapshots and hashes, fresh verification, and rollback only for an incomplete transaction. The previous self-referential required-check profile is not the desired baseline.
- Adopters pin an exact certified Governance SHA. Candidate execution is untrusted and non-authoritative; an external verifier validates hostile evidence and emits the one stable required check through a dedicated verifier GitHub App.
- `AI_REVIEW_UNAVAILABLE` is non-blocking after the deterministic cutoff. Valid exact-head, in-window findings at configured blocking severity remain RED.
- The standard profile supports pull requests. Merge queue is optional and may be enabled only where current GitHub eligibility and event bindings are proved.
- Work may use multiple finite local repair iterations until the frozen acceptance suite passes. Keep one active implementation pull request at a time.

### Deterministic core

The core owns schemas, target-pack validation, typed execution-plan generation, evidence validation, deterministic decisions, and delivery-receipt verification. Core behavior must not depend on a named target repository.

### Target packs

Repository-specific cases, fixtures, typed capability declarations, bounded adapter inputs, expected capabilities, and immutable evidence belong in versioned target packs. Target packs may not provide executable names, shell text, or arbitrary argument vectors. Evaluator-owned adapters generate every executable argument vector. Removing a target pack must not break the target-neutral core; removing a required registered pack must make complete verification RED.

### Typed capabilities and adapters

- Configuration selects supported typed capability and adapter identifiers, not arbitrary shell commands.
- Each adapter is versioned, has positive and negative controls, and generates an immutable execution plan.
- The evaluator assigns and the trusted verifier recomputes each adapter's assurance class. Candidate configuration cannot select or alter assurance.
- `EVALUATOR_AUTHORITATIVE`: Ruff lint, Ruff format, Ruff C901 at threshold 10, mypy, architecture, Phase 1 benchmark, Git diff integrity, and evaluator-owned package and artifact verification.
- `CONTAINED_BUILD`: candidate wheel build and other candidate build processes whose effects are contained and whose outputs are host-captured.
- `COOPERATIVE_DYNAMIC`: `python.unittest.v1` and any dynamic runner that imports candidate code. Its fixed command, scope, nonzero and not-all-skipped test requirements, timeout, output bounds, cleanup, host-owned result, and exact bindings remain enforced; assertion truth is not independently attributable.
- `EXTERNAL_ORACLE`: reserved for a future repository-specific stable external interface; not implemented or required for Governance v1.
- Unsupported adapters, capability versions, or options fail closed.
- The framework does not claim universal language support. A repository is governable only when all required capabilities have supported adapters.
- Candidate configuration cannot choose, replace, or modify the protected baseline judge or delivery-receipt verifier.

`python.sqlite.v1` extends, and does not alter, `python.standard.v1`. It appends
the evaluator-owned `sql_supportability` capability through
`python.sqlite-supportability.v1`, classified `EVALUATOR_AUTHORITATIVE`. A
trusted operator opts in only through the evaluator-owned adoption generator's
typed profile argument. The generator writes `profile: python.sqlite.v1` into
the configuration and binds the same value into the adoption manifest and
verifier enrollment. Source discovery never silently changes the selected
profile. The candidate pipeline derives the exact adapter tuple from the
authenticated configuration; the external verifier derives it independently
from the enrollment plus authenticated configuration and manifest. All values
and orders must match. Candidate-provided commands, exclusions, profile
substitution, capability omission, or order changes are invalid.

Every adoption preflight and candidate run performs evaluator-owned profile
discovery before profile execution. A packaged Python `sqlite3` import plus a
resolved connection/cursor/sink, or a packaged `.sql` resource referenced by
that flow, requires `python.sqlite.v1`. The same evidence under
`python.standard.v1` is `BLOCK_TECHNICAL`; discovery reports the required trusted
opt-in but never changes the profile. Unclassified SQL-like sources also block
rather than selecting an engine. The external verifier requires the bound
discovery receipt, recomputes the expected profile from it, and rejects any
config, manifest, enrollment, capability-order, or discovery mismatch.

For this contract, `python.standard.v1` byte compatibility means its adapter
identifiers, assurance classes, order, execution-plan step definitions, profile
marker framing, canonical profile payload serialization, and deterministic
decision remain byte-identical for identical non-SQL inputs. Publication tests
must compare those surfaces with evaluator-owned golden bytes and SHA-256
digests generated from rollback SHA
`c07b2ecf831fa2e3c68481a782a7e9e50d9dbc86`. Release identity, timestamps,
standard-document hash, and artifact identity bindings are intentionally outside
that comparison.

### Bounded SQLite contract

- Only Python standard-library `ast`, `sqlite3`, hashing, and existing safe package-audit helpers may implement SQLite governance.
- The evaluator scans the host-validated packaged Python and resource surface, not tests, environments, caches, or arbitrary ignored directories.
- Adoption preflight also inspects tracked files, untracked nonignored files, and ignored SQL resources referenced by production code. Required runtime SQL absent from the committed pull-request head blocks.
- Static extraction supports string literals, constant concatenation, static dictionaries, and statically selected dictionary entries. F-strings, runtime-built SQL, missing constants, runtime-loaded external SQL, unsupported sinks, unresolved packaged resources, and any other unresolved SQL block.
- Sink discovery proves receiver provenance across the packaged Python graph through `sqlite3` import aliases, `connect` calls, connection/cursor annotations, cursor derivation, and statically resolved function returns. An unresolved `execute`, `executemany`, or `executescript` receiver participating in SQLite or SQL flow blocks. Unresolved `getattr`, method aliases, wrapper forwarding, and dynamic dispatch block; unrelated methods may be ignored only when their non-SQL type is proved.
- Before parsing, evaluator-owned hard maxima are 10,000 files, 2 MiB per file, 32 MiB total source bytes, 1,000,000 Python AST nodes, 10,000 sinks, 10,000 SQL statements, and 1 MiB per normalized statement. Each boundary has passing-at-limit and blocking-over-limit controls.
- The adapter validates `execute`, `executemany`, and `executescript`. It builds schema statements only in statically proved sink and statement order in an isolated in-memory SQLite database and prepares remaining statements with bounded qmark or named dummy bindings without importing candidate code. Unproved cross-function/resource ordering blocks; the evaluator never reorders SQL to make it pass.
- Extension loading stays disabled. Evaluator-owned `sqlite-policy.v1` uses a default-deny authorizer and statement classifier; permits schema execution only for `CREATE TABLE`, `CREATE INDEX`, `CREATE VIEW`, `CREATE TRIGGER`, and `CREATE VIRTUAL TABLE ... USING fts5`; permits candidate PRAGMAs only for `foreign_keys`, `foreign_key_check`, and `quick_check`; and permits SQL functions only `bm25`, `coalesce`, `highlight`, `like`, `match`, and `snippet`. It rejects `ATTACH`, `DETACH`, `VACUUM`, file-backed databases, `load_extension`, writable-schema operations, every other PRAGMA/function/virtual-table module, and any filesystem escape.
- `sqlite-policy.v1` requires SQLite `>=3.40.0,<4.0.0` with `ENABLE_FTS5`. It sets `SQLITE_LIMIT_LENGTH=2097152`, `SQLITE_LIMIT_SQL_LENGTH=1048576`, `SQLITE_LIMIT_COLUMN=2000`, `SQLITE_LIMIT_EXPR_DEPTH=1000`, `SQLITE_LIMIT_COMPOUND_SELECT=500`, `SQLITE_LIMIT_VDBE_OP=250000`, `SQLITE_LIMIT_FUNCTION_ARG=127`, `SQLITE_LIMIT_ATTACHED=0`, `SQLITE_LIMIT_LIKE_PATTERN_LENGTH=50000`, `SQLITE_LIMIT_VARIABLE_NUMBER=32766`, `SQLITE_LIMIT_TRIGGER_DEPTH=100`, and `SQLITE_LIMIT_WORKER_THREADS=0`. It initializes `trusted_schema=OFF`, `temp_store=MEMORY`, `journal_mode=MEMORY`, `foreign_keys=ON`, `recursive_triggers=OFF`, `max_page_count=16384`, and `cache_size=-8192`; caps each statement at 10,000,000 virtual-machine operations and two seconds; and retains the existing 120-second adapter plus process memory/output limits.
- SQL canonicalization normalizes `CRLF`, `CR`, and `LF` before hashing.
- Evidence records paths, line numbers, normalized hashes, discovered sinks, receiver provenance, exact SQLite version/compile-option digest, `sqlite-policy.v1` canonical SHA-256, preparation results, errors, timestamps, limits, and bounded counts. Candidate execution and the external verifier independently recompute and require the policy hash and certified toolchain SQLite identity.
- `Gate implementation: PASS` means the exact adapter, schemas, bindings, and limit controls are registered and covered. `Repo SQL supportability: PASS` means every in-scope source, resource, sink, and dependency is resolved and validated. `SQL behavior proof: PASS` means evaluator-owned controls pass, schema statements build in statically proved order, remaining statements compile against that schema with bounded qmark or named dummy bindings, and required SQLite features exist. It does not claim application result rows, migration correctness, transaction semantics, or business behavior.
- SQL evidence reports those three statuses separately. Missing, malformed, unsupported, contradictory, or unverifiable evidence produces `BLOCK_TECHNICAL`.
- TWMN acceptance patterns are pinned to `markheck-solutions/twmn@47bf8823000ac98595ccb1013d3f8f6abdf90ebd` (tree `45b985ed6944cf9cc48ffe56e9954df5060b2a6a`). `src/twmn_corpus/database.py` has SHA-256 `bf8197920fe4821b7f8dc00e994db8f737c73863f40ecbaaa34069286a9cd66b`; candidate-owned `scripts/sql_gate.py` has SHA-256 `164e014d7f8c03d7393e765e0479524d149159bff281142879b4981640eb6363` and is behavior reference only, never executed or reused.
- PostgreSQL, Snowflake, arbitrary candidate SQL commands, configurable escape hatches, and multi-engine abstraction remain out of scope.

Practical Tamper-Resistant Governance v1 is the product release. Its typed configuration remains the separately versioned `schema_version: "2.0"` contract.

### Untrusted execution and trusted verification

- Candidate execution runs only in a `pull_request` workflow with `contents: read`, every unnecessary permission set to `none`, no secrets, no write token, exact action and evaluator pins, and no authoritative check identity.
- Provisioning is separate from offline gate execution. Candidate processes run non-root with a read-only root filesystem, dropped capabilities, no privilege escalation, bounded CPU, memory, PIDs, output, step time, and total time, and only a disposable target copy writable.
- Candidate code cannot access the Docker socket, evaluator checkout, toolchain source, or authoritative artifact directory.
- A host wrapper outside the target checkout owns result paths and records exact identities, timing, timeout and termination, exit status, bounded stream counts and digests, truncation, cleanup, and artifact name and content digest.
- The external verifier authenticates the adopter's `pull_request` workflow path and file hash against the certified Governance release. If the head changes that caller, its pinned wrapper, permissions, conditions, dependencies, or result-upload path, artifacts from that run are non-authoritative and cannot authorize the change.
- No adopter-controlled `pull_request_target` workflow is trusted authority. Candidate execution produces evidence without secrets or write authority; the external verifier never checks out or executes candidate code.
- The external verifier downloads artifacts as hostile data, safely inspects archive structure and bounds before extraction, validates schemas, recomputes digests and decisions, rejects identity mismatch or replay, reconciles the unchanged exact head and current protection, and alone emits the authoritative required context through its dedicated GitHub App.
- Execution plans bind repository, pull request, base SHA and tree, head SHA and tree, evaluator and workflow identities, adapter version and assurance, configuration and standard hashes, toolchain and image identities, working directory, and bounded steps.

### GitHub enforcement

The framework must produce and verify this status split:

```text
Repo config: PASS|FAIL
Caller workflow: PASS|FAIL
Protected branch/ruleset: PASS|FAIL
Required checks: PASS|FAIL
Canary PR: PASS|FAIL
Repo GitHub governance: PASS|FAIL
```

`Repo GitHub governance: PASS` requires current live evidence for all fields. Offline benchmark success is necessary but not sufficient.

Required enforcement properties:

- reusable workflows pinned to exact immutable SHAs;
- protected baseline and delivery receipt independent from candidate judgment;
- stable final required-check names with no ghost or skipped-success path;
- artifacts bound to exact repository, pull request, base, head, run, ID, name, and digest;
- exact approved AI reviewer identities and latest-head binding for any AI evidence that is received before the bounded cutoff;
- unresolved reproduced P0-P2 findings block;
- A Codex request is attempted automatically for every new head SHA. GitHub-blocked bot-to-bot request transport is recorded but does not skip deterministic evaluation and does not require a PAT or Copilot fallback. Each head gets a five-minute cutoff derived from GitHub server time. Evidence whose authoritative GitHub creation or submission timestamp is at or before the cutoff is in-window even if observed later. GREEN is prohibited until a fully paginated collection begins after the cutoff and reconciles an unchanged head. Missing, late, quota-limited, or unavailable evidence then records `AI_REVIEW_UNAVAILABLE`, never approval, and does not block deterministic governance;
- Copilot is not a required gate, reviewer, receipt dependency, or fallback;
- manual Actions approval, manual API rerun, or owner-copied review evidence can never satisfy a required check, receipt, canary, or completion proof; automatic exact-head reconciliation is allowed.

Adopter protection is read-only until an explicit installation. Governance source settings may change only through the evidence-backed source-protection transaction defined above; unrelated protection weakening remains out of scope.

### Protected four-PR release

1. **Source boundary:** land the source/adopter contract, independent source qualification, permission closure, standard-event validation, and structural source regressions.
2. **Publication:** merge the complete evaluator, adapters, schemas, workflows, evidence contracts, verifier, and adoption tooling without changing live adopter pins or configuration. Use merge-commit strategy and record publication merge `M`; require `tree(M) == tree(C)` for the frozen qualified candidate `C`.
3. **Exact-`M` qualification:** rerun complete qualification against the publication merge while the prior adopter pin remains active. A failure requires a replacement publication pull request, not weakened criteria.
4. **Pin-only activation:** change only exact reusable workflow or action pins, `governance-ref` values, and literal pin fixtures. Verify every live adopter pin equals `M` after merge.
5. **Config-only migration:** change only `.github/governance/supportability.yml` and exact migration fixtures from known v1 to typed v2. Require the external verifier context GREEN.
6. Keep `main` frozen from publication-candidate freeze through activation and config migration. Preserve source protection and the adopter required-context identity throughout.

### SQLite release sequence

1. Merge this contract through the existing required `Governance Source Qualification`.
2. Merge one publication pull request containing the adapter, schemas, verifier logic, adoption generator, documentation, and tests. Do not modify the frozen source qualifier modules, source workflow pair, dependency lock, or package contract.
3. Use a merge commit, record publication merge `M`, and prove `tree(M) == tree(qualified candidate)`.
4. Run exact-`M` qualification while the verifier remains pinned to `c07b2ecf831fa2e3c68481a782a7e9e50d9dbc86`.
5. Merge a pin-only `governance-verifier` pull request changing only Governance SHA literals to `M`.
6. Migrate the existing disposable runtime repository to `python.sqlite.v1`; do not create another permanent repository.
7. Prove clean, defective, replay, hostile-artifact, stale-head, spoofed-context, and AI-unavailable canaries. Defective pull requests close unmerged.
8. Publish an immutable release only after every canary passes; record `c07b2ecf831fa2e3c68481a782a7e9e50d9dbc86` as rollback.
9. Generate TWMN's bundle at the certified SHA from a separate clean worktree. Preserve its existing dirty checkout and unrelated pull requests.
10. Enroll TWMN in the verifier App, replace obsolete Actions contexts with `Governance / Authoritative Decision` through before-and-after ruleset snapshots plus a tested restore path, and merge the adoption pull request.
11. Run a harmless TWMN canary and report the complete live GitHub governance status split.

The publication candidate must pass these exact local source gates:

```text
python -I -m ruff check --isolated --target-version py312 .
python -I -m ruff format --check --isolated --target-version py312 .
python -I -m ruff check --isolated --select C901 --config "lint.mccabe.max-complexity=10" --target-version py312 governance_eval
python -I -m mypy governance_eval
python -I -m unittest discover -s tests -p "test_*.py"
python -I -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
python -m governance_eval.cli verify --repeat 3 --artifacts-dir artifacts/phase1
```

### Execution service levels

- Every subprocess uses an enforced hard timeout and records command, start/end time, timeout state, and exit code in schema-valid evidence.
- Focused verification command: at most 2 minutes.
- Complete local verification: at most 5 minutes; all local verification for the slice: at most 10 minutes.
- Codex evidence cutoff: 5 minutes from GitHub server time.
- GitHub workflows set `timeout-minutes` at or below 10. Protected-pull-request deadlines use GitHub server time.
- GitHub deterministic workflow: at most 10 minutes; protected pull request: at most 15 minutes.
- Local development may use multiple finite, bounded repair attempts until the acceptance suite passes. This does not authorize an autonomous repair loop.
- After a qualified head opens a pull request, permit at most one repair push for a live-only finding. A failed pull request ends that pull request, not the assignment; close or replace it from the last qualified checkpoint. Never repeat the same pull request, polling, or verification loop.

## Required implementation

1. Preserve every Phase 1 acceptance criterion and registered benchmark case.
2. Remove target-specific assumptions from the evaluator core while retaining named target packs.
3. Replace arbitrary command configuration with typed, versioned capability adapters and bounded execution plans.
4. Provide separate untrusted execution and trusted verification planes with a safe, deterministic, replay-resistant process for updating protected evaluator and workflow surfaces without same-PR self-authorization.
5. Validate both protected baseline evidence and candidate evidence contents before issuing a GREEN receipt.
6. Replace placeholder or duplicated gates with real lint, format, type, complexity, architecture, test, build, and package-audit capabilities. Applicability is computed deterministically from registered source and runtime evidence; a required capability without a supported adapter or executable evidence is `BLOCK_TECHNICAL`, never omitted.
7. Prove changed-file and highest-risk-file gate coverage without exclusions, threshold weakening, or scope narrowing.
8. Normalize received Codex review evidence from exact approved bot identities, bind it to the latest head SHA, and remove Copilot as a required provider.
9. Make received-review reconciliation deterministic and automatic without bot-comment approval deadlocks or manual rescue. Record bounded unavailability without converting it to approval or blocking deterministic governance indefinitely.
10. Keep required final contexts stable and fail closed on missing, skipped, malformed, or stale dependencies.
11. Produce machine-readable baseline, candidate, architecture, review, benchmark, and delivery-receipt artifacts.
12. Replace manual protected-path filename lists with structural protection for all evaluator Python, schemas, workflows, actions, dependency locks, package metadata, architecture and supportability configuration, adapter command logic, evidence validation, and final decisions.
13. Generate byte-stable, read-only adoption bundles and proofs without applying changes, opening pull requests, mutating protection, enumerating repositories, or modifying targets.
14. Prove the framework through clean, defective, replay, stale-review, protected-context-spoof, hostile-artifact, and AI-unavailable canaries.
15. Implement `python.sqlite.v1` without changing `python.standard.v1`, and bind its SQL evidence through typed execution plans, results, adoption manifests, and external-verifier validation.
16. Fail adoption preflight when required SQLite source or resource content would be absent from the committed pull-request head.

## Required controls

Positive, negative, and evasion controls must cover at least:

- clean target evaluation;
- every preserved Phase 1 defect;
- hostile target attempt to modify or replace its judge;
- config plus companion-file migration;
- missing or unsupported adapter;
- arbitrary command or shell syntax;
- execution-plan mutation or artifact replay;
- candidate writes or races the result path, reads secrets, reaches the network during offline execution, writes outside the disposable target, accesses the Docker socket, leaves child processes, exhausts PIDs, times out, or floods output;
- archive traversal, links, duplicate entries, unexpected entries, decompression abuse, oversized content, malformed JSON, or digest and identity mismatch;
- narrowed gate scope or weakened threshold;
- duplicate command used as multiple semantic capabilities;
- missing or malformed candidate artifact;
- candidate-only GREEN with protected baseline RED;
- wildcard, similar-looking, or stale-head AI reviewer evidence;
- workflow pin substitution, floating ref, disabled job, changed condition, removed dependency, broadened permissions, or renamed required context;
- candidate modification of the `pull_request` caller or upload wrapper cannot make that run's artifact authoritative, including during publication or pin activation;
- protected-context spoof attempt from candidate-controlled workflow;
- replay or mutation of a previously authorized protected-workflow update.
- SQLite literals, constant concatenation, static dictionary selection, parameterized queries, schema creation, PRAGMA, FTS, packaged `.sql` resources, and LF/CRLF canonical-hash equality;
- malformed SQL, missing constants, f-strings, dynamic identifiers, runtime file loading, absent resources, schema-order failure, SQLite evidence mutation, adapter omission, profile substitution, profile/config hash mismatch, and archive abuse.

## Required workflow

Before each implementation slice:

1. A read-only specification analyst defines acceptance and ambiguity.
2. The primary agent implements the smallest dependency-complete slice.
3. Local verification runs with changed-file and high-risk-file gate coverage.
4. A fresh read-only adversarial reviewer inspects the exact final diff and evidence.
5. Every reproduced P0-P2 finding is repaired before push.
6. The pull request requests Codex automatically, records its bounded evidence status, and receives all deterministic required checks.
7. Merge occurs only through the protected pull-request path. The exact owner may use the permanent pull-request-only source maintainer lane; no direct-push, force-push, deletion, or adopter-authority bypass is authorized.

## Explicitly out of scope

- Modifying evaluated application repositories.
- TWMN or other target-repository adoption before Governance self-canaries pass.
- Auto-merge.
- Autonomous repair loops or planner/builder factories.
- Production application refactoring.
- Global governance-skill modification.
- Unscoped branch-protection, ruleset, required-context, default-branch, permission, or administrative-bypass mutation outside the owner-authorized Governance source transaction.
- Node, PowerShell, PostgreSQL, Snowflake, arbitrary SQL-command, multi-engine, or additional language/database adapters in Governance v1.
- A custom hosted execution service, black-box assertion RPC framework, or `EXTERNAL_ORACLE` implementation in Governance v1.
- Universal hostile-code truth proof for in-process dynamic assertions.
- Claiming support for an adapter or ecosystem without executable positive, negative, and evasion controls.

## Completion

Completion is `FAIL` unless all are true:

- Phase 1 complete verification exits 0 and writes schema-valid artifacts.
- Every registered historical, clean, defective, and evasion control produces its expected deterministic result.
- All reproduced P0-P2 findings are resolved.
- Real lint, format, type, C901, architecture, tests, build, package audit, and benchmark gates pass for their complete registered scope.
- No changed or highest-risk production file is excluded from applicable gates.
- No gate threshold or scope was weakened.
- No evaluated target repository was modified.
- Governance configuration validates and uses supported typed adapters only.
- `python.unittest.v1` is documented and evidenced as `COOPERATIVE_DYNAMIC`; no completion document claims otherwise.
- The trusted verifier never executes or imports candidate code or executes artifact contents.
- Untrusted execution has no secrets or write token; authoritative artifacts are host-owned and exact-identity bound.
- Replay, mutation, malformed archives, scope narrowing, threshold weakening, and required-check spoofing deterministically block.
- Protected baseline and candidate artifacts are independently schema-valid and bound to the exact pull-request head.
- Delivery receipt validates both evidence chains and remote GitHub state.
- Governance source requires only independent source qualification; Governance application contexts may run diagnostically but are not required on Governance itself.
- Each adopter requires one stable external-verifier context bound to the dedicated verifier GitHub App ID; a candidate-created same-name check cannot satisfy it.
- Clean canary merges through the protected path.
- Defective canary remains RED and closes unmerged.
- Stale-review canary proves stale AI evidence cannot block or authorize the current head; a current exact-head received P0-P2 finding remains RED until resolved.
- Protected-context-spoof canary cannot bypass the real protected result.
- Codex request transport is attempted automatically and cannot skip deterministic evaluation; exact-head received evidence is classified; missing or unavailable evidence records `AI_REVIEW_UNAVAILABLE`; no PAT or Copilot evidence is required.
- A deterministic adoption command generates repo config and a caller pinned to the exact Governance SHA, validates config hash and required-context mapping, documents protection setup, and proves disposable clean and defective adoption canaries without modifying any target repository.
- The active evaluator and adoption pin equal publication merge `M`; live typed config is v2; arbitrary v1 command execution is unreachable; `main` contains no unactivated evaluator backlog.
- Protection and rulesets equal the verified intended delta from the saved before snapshot; the obsolete self-referential source contexts are not restored.
- A schema-valid `governance_completion_receipt.v1` binds every release pull request, SHA, run, artifact, digest, command, exit, canary, live-protection proof, and remaining unknown.
- Fresh adversarial review reports zero unresolved P0-P2 findings.
- Final report lists exact commands, exit codes, artifacts, hashes, commit SHAs, live GitHub proof, and unresolved unknowns.
- `python.standard.v1` named deterministic surfaces match rollback-SHA golden bytes and digests, and both pipelines independently select and validate `python.sqlite.v1` plus its exact capability order for SQLite adopters.
- SQLite positive and negative controls pass, including TWMN-style static SQL, resource discovery, newline-normalized hashing, unsupported dynamic SQL, evidence mutation, and profile/config substitution.
- SQLite evidence reports `Gate implementation: PASS`, `Repo SQL supportability: PASS`, and `SQL behavior proof: PASS` separately.
- Exact publication-merge qualification, verifier activation, disposable canaries, immutable release, and live TWMN config, caller, ruleset, required-check, artifact, receipt, and harmless-canary proof all pass.

Do not weaken any criterion to finish. Report `BLOCK_TECHNICAL` when required proof is unavailable.
