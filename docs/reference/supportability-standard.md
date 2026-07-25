---
title: "Supportability Standard"
owner: "Mark Heck"
created_by: "Mark Heck"
created: "2026-06-15"
last_reviewed: "2026-07-24"
status: "active"
---

# Supportability Standard for AI Coding Agents

| Document Owner | Created By | Created | Last Reviewed | Status |
|---|---|---:|---:|---|
| Mark Heck | Mark Heck | 2026-06-15 | 2026-07-24 | Active |

## Purpose

Use this standard when asking an AI coding agent to build, refactor, clean up, package, or productionize code.

The goal is not to make the repo look cleaner cosmetically. The goal is to make the code easier to reason about, safer to change, easier to test, and easier for another engineer to review.

A clean repo is created by responsibility boundaries first. The folder tree is only the visible result.

## Strict Interpretation

The AI must treat this standard as a pass/fail supportability standard.

The AI must not use feasibility language as an escape hatch.

If a required item is not completed, the AI must mark that item as failed or incomplete.

The AI must not convert a required item into an optional recommendation.

The AI must not claim completion when required evidence is missing.

---

## When to Use This

Use this standard for:

* New features
* Refactoring
* Legacy code cleanup
* Package/runtime changes
* CLI or wrapper changes
* Architecture cleanup
* Test hardening
* Repo maintainability work
* AI-generated code review

Do not use the full standard for very small tasks such as:

* Renaming one variable
* Fixing a typo
* Explaining an error message
* Adding one log line
* Making a small documentation edit

For small tasks, use this shorter instruction:

> Follow the Supportability Standard where relevant. Keep the change small, preserve behavior, avoid vague helpers, and validate the result.

---

## Core Principle

Do not accept “the code runs” as the only success condition.

A good AI-generated change must also be:

* understandable
* modular
* testable
* reviewable
* behavior-preserving
* low-risk
* validated

The minimum standard is:

```text
C901 improvement + boundary improvement + behavior proof
```

Additional required proof:

```text
gate coverage proof
```

The AI must prove that the validation gates cover the files that were changed and the highest-risk production files in the repo.

Not:

```text
C901 improvement by itself
```

Lowering complexity alone is not enough. An AI agent can pass C901 by chopping one messy function into several badly named helper functions. That lowers the metric while leaving the repo just as messy.

---

# The Supportability Standard Stack

## 1. Cyclomatic / McCabe Complexity Control

### What it means

Cyclomatic complexity, also called McCabe complexity, measures how many decision paths exist inside a function.

C901 is the Ruff/Flake8 rule that reports functions that exceed the allowed complexity ceiling.

### What it prevents

It prevents individual functions from becoming mazes.

### AI instruction

Keep McCabe/cyclomatic complexity under 10 per touched production function.

Do not reduce complexity by creating vague helper functions.

For legacy code that starts above 10, use progressive tightening:

* No new or extracted production function may exceed 10.
* Touched legacy functions must move lower than their starting complexity.
* A temporary ceiling must be labeled as temporary.
* New modules must be designed for the final ceiling of 10, not for a temporary ceiling.
* Do not weaken global gate settings to make the change pass.
* The completion report must show starting complexity, ending complexity, remaining gap, and next target.

Bad examples:

```text
process_part_1()
process_part_2()
handle_stuff()
do_misc()
helper_final()
```

Good examples:

```text
validate_input_rows()
normalize_customer_records()
calculate_route_order()
write_output_workbook()
load_runtime_config()
```

### Acceptance test

The touched function should be easier to read, easier to test, and easier to name after the refactor.

For legacy functions that remain above 10 after a pass, the AI must report the exact remaining functions, current complexity values, why they remain, and the next extraction target. The AI must not describe the complexity gate as satisfied until the configured gate covers the relevant files and the reported values meet the active target.

---

## 2. Separation of Concerns / Single Responsibility Principle

### What it means

Each function, file, or module should have one clear job.

Parsing, validation, business rules, file access, logging, CLI output, and packaging behavior should not all be tangled together.

### What it prevents

It prevents one file from doing five unrelated jobs.

### AI instruction

Split code along real responsibility boundaries:

* parsing
* validation
* business rules
* orchestration
* transformation
* persistence
* external API calls
* configuration
* error handling
* logging
* CLI/UI presentation
* tests

### Acceptance test

Another engineer should be able to answer:

```text
What is this file responsible for?
What does this function own?
What does this module not own?
```

If the answer is unclear, the boundary is still weak.

### Frontend and component code

For frontend codebases, apply the same supportability rules.

A large React, Vue, Svelte, Angular, or route/page component is the same supportability problem as a large backend script.

Frontend code must separate:

* route/page composition
* data loading
* query parsing
* state management
* rendering
* form handling
* validation
* domain/business rules
* reusable UI components
* API/client calls

Do not leave giant dashboard, route, page, or component files that mix these responsibilities.

Frontend validation must use the stack's own gates, such as eslint, prettier, tsc or framework typecheck, vitest/jest, playwright/cypress, build, and import-boundary or dependency checks.

---

## 3. Layered Architecture / Clean Dependency Direction / Acyclic Imports

### What it means

Code should depend in predictable directions.

A typical direction is:

```text
CLI / UI / API
    ↓
Application / workflow orchestration
    ↓
Domain / business rules
    ↓
Infrastructure / files / database / external services
```

### What it prevents

It prevents random cross-imports, circular dependencies, and business logic depending directly on UI, CLI, database, package, or framework glue.

### AI instruction

Do not introduce circular imports.

Do not make domain or business logic depend directly on CLI code, UI code, framework glue, package runtime details, database clients, or external service clients. Existing architecture debt must remain visible as debt, not a GREEN result.

Keep dependency direction predictable.

### Acceptance test

The AI must explain whether dependency direction was preserved or improved.

---

## 4. Domain-Driven Modularization / High Cohesion / Low Coupling

### What it means

Related code should live together. Unrelated code should not be forced together.

High cohesion means a module contains things that belong together.

Low coupling means one part of the repo does not casually depend on many unrelated parts.

### What it prevents

It prevents a repo from becoming a junk drawer full of `utils`, `helpers`, `common`, `misc`, and random shared files.

### AI instruction

Prefer domain-based or responsibility-based modules.

Avoid vague dumping-ground folders and files.

Before creating a new package, folder tree, or module location, check whether an existing governed package already owns the domain.

Prefer extending an existing typed, linted, tested, and documented package over creating a parallel package.

A new package or top-level module is acceptable only when all of the following are true:

* the responsibility does not belong in an existing governed package
* the new location is covered by lint
* the new location is covered by type-checking
* the new location is covered by tests
* the new location is covered by complexity checks
* the new location is covered by architecture or import-boundary checks
* the dependency direction is clear
* the completion report explains why the new location is justified

A second package means a second set of gate scopes to maintain.

Weak examples:

```text
utils/
helpers/
common/
misc/
stuff/
```

Better examples:

```text
cli/
workflow/
domain/
validation/
runtime/
packaging/
reporting/
tests/
```

Or, when the repo is domain-heavy:

```text
orders/
customers/
billing/
inventory/
notifications/
```

### Acceptance test

The AI must explain why the new module or folder boundary reflects a real responsibility or domain concept.

---

## 5. Characterization / Golden-Master Tests

### What it means

Before changing legacy or complex code, capture what the current behavior does.

This does not mean the current behavior is perfect. It means the current behavior is known before it is changed.

### What it prevents

It prevents refactoring from accidentally changing behavior.

### AI instruction

Before changing legacy, wrapper, orchestration, package, or runtime-sensitive code, characterize current behavior.

Use tests, sample inputs/outputs, snapshots, golden files, CLI output captures, or focused regression tests.

### Acceptance test

The AI must show what behavior was captured before the refactor and which validation proves compatibility afterward.

---

## 6. Incremental Strangler-Style Refactoring

### What it means

Replace messy code gradually instead of rewriting everything at once.

Choose one small target, create a safer boundary, validate it, then continue.

### What it prevents

It prevents big-bang rewrites, excessive churn, and changes that become too large to review safely.

### AI instruction

Prefer incremental strangler-style cleanup over big-bang rewrites.

Pick one small high-value target first.

Keep each logical step small and runnable.

Do not attempt repo-wide cleanup without explicit owner scope.

### Acceptance test

The change should be reviewable as a focused improvement, not a sprawling rewrite.

---

## 7. Quality Gates

### What it means

Quality gates are automated checks that prove the repo still meets basic standards after the change.

### What it prevents

It prevents fake completion.

### AI instruction

Run the relevant validation commands before claiming completion.

Quality gates must cover the files that matter.

The AI must verify and report:

1. Which files were changed
2. Which gates apply to each changed file
3. Which high-risk production files are excluded from any gate
4. Whether any gate threshold was changed
5. Whether any gate scope was narrowed
6. Whether any production file was excluded from lint, type-check, complexity, tests, or architecture checks

If lint, type-check, complexity, architecture, or test gates exclude production code, changed files, large files, legacy wrappers, generated-looking source, or files carrying the most risk, the AI must report that exclusion as a supportability failure.

The AI must not claim quality gates passed before proving the relevant gates cover the changed files and the highest-risk production files.

The AI must not weaken thresholds, exclude files, rename files to avoid checks, move files outside checked paths, or narrow gate scope to make validation pass.

Examples:

```text
ruff check
ruff format --check
C901 complexity check
mypy
pytest
python -m compileall
architecture/import-boundary checks
package build
package audit
PowerShell parser check
git diff whitespace check
```

Use the repo’s actual commands when available.

### SQLite supportability contract

For a Python repository whose generated adoption configuration selects
`python.sqlite.v1`, SQLite is a blocking supportability capability, not an
advisory command. The evaluator owns `python.sqlite-supportability.v1`. A trusted
operator opts in through the evaluator-owned generator's typed profile argument.
The generated configuration, adoption
manifest, and verifier enrollment must all bind `python.sqlite.v1`; source
discovery does not auto-select it. Candidate configuration cannot provide SQL
commands, exclusions, alternate adapters, profile changes, or escape hatches.
Packaged `sqlite3` connection/cursor/sink evidence, or a packaged `.sql` resource
referenced by that flow, under `python.standard.v1` is `BLOCK_TECHNICAL` until a
trusted adoption generation selects `python.sqlite.v1`. Unclassified SQL-like
sources also block; discovery never guesses an engine.

The gate must:

* scan the host-validated packaged Python and resource surface;
* inspect tracked files, untracked nonignored files, and ignored SQL only when
  production code references it during adoption preflight;
* resolve only literals, constant concatenation, static dictionaries, and
  statically selected dictionary values;
* prove SQLite connection/cursor receiver provenance across packaged modules and
  block unresolved aliases, wrappers, or dynamic dispatch;
* enforce 10,000 files, 2 MiB per file, 32 MiB total source, 1,000,000 AST nodes,
  10,000 sinks, 10,000 statements, and 1 MiB per normalized statement;
* validate `execute`, `executemany`, and `executescript` with a memory-only
  SQLite database without importing candidate code;
* disable extension loading and use a default-deny authorizer, allowlisted
  PRAGMAs/functions, fixed SQLite limits, and progress/time bounds exactly as
  `sqlite-policy.v1` in ADR 0003 defines;
* normalize `CRLF`, `CR`, and `LF` before canonical SQL hashing; and
* bind paths, lines, hashes, sinks, receiver provenance, SQLite identity,
  preparation results, errors, timestamps, limits, and bounded counts into typed
  evidence.

Tests, environments, caches, and arbitrary ignored directories are outside the
packaged scan surface. An ignored SQL resource referenced by production code is
inside adoption preflight and must exist in the committed pull-request head.

F-strings, runtime-built SQL, missing constants, dynamic identifiers,
runtime-loaded external SQL, unsupported sinks, malformed SQL, absent packaged
resources, profile substitution, capability omission, evidence mutation,
`ATTACH`, `DETACH`, `VACUUM`, file-backed databases, extension loading,
writable-schema operations, non-allowlisted PRAGMAs/functions, and contradictory
evidence fail closed.

`sqlite-policy.v1` permits candidate PRAGMAs only `foreign_keys`,
`foreign_key_check`, and `quick_check`; functions only `bm25`, `coalesce`,
`highlight`, `like`, `match`, and `snippet`; and virtual-table module only
`fts5`. It requires
SQLite `>=3.40.0,<4.0.0` with `ENABLE_FTS5`, binds the exact certified SQLite
version plus compile-option digest, and binds the canonical policy SHA-256 in
plans, results, manifests, and verifier enrollment. The exact `setlimit`,
connection initialization, statement-progress, and adapter bounds in ADR 0003
are mandatory, not implementation defaults.

Report these statuses separately:

```text
Gate implementation: PASS|FAIL
Repo SQL supportability: PASS|FAIL
SQL behavior proof: PASS|FAIL
```

`SQL behavior proof: PASS` means evaluator-owned controls pass, schema statements
build only in statically proved sink and statement order, remaining statements
compile with bounded qmark or named dummy bindings, and required SQLite features exist. Unproved
cross-function/resource order blocks; the evaluator never reorders SQL to make
it pass. This does not prove result rows,
migration correctness, transaction semantics, or application business behavior.

Any required status other than `PASS` makes the repository supportability result
RED. PostgreSQL, Snowflake, arbitrary SQL commands, configurable exclusions, and
multi-engine abstraction are not supported by this contract.

### Acceptance test

The AI must report exactly which validation commands ran, which passed, which failed, and what was not tested.

The AI must also report gate coverage. The report must include changed files, gate names, gate scope, excluded production files, threshold changes, and scope changes. Missing gate coverage proof means validation is incomplete.

---

## 8. Review Handoff / ADR-Style Reporting

### What it means

The AI must explain the change in a way another engineer could review.

ADR means Architectural Decision Record. For AI work, this can be lighter than a formal ADR, but the agent still needs to explain the decision.

### What it prevents

It prevents vague “done” responses and makes the change reviewable.

### AI instruction

After the change, provide a completion report explaining:

1. What changed
2. Which responsibilities were separated
3. Which functions were simplified
4. Any McCabe/C901 improvements
5. Why the new boundary is cleaner
6. Which validation commands ran
7. Risks, gaps, or follow-up work
8. Gate coverage proof, including changed files, gates applied, excluded production files, threshold changes, and scope changes

### Acceptance test

The completion report should make it clear whether the change improved architecture or merely rearranged code.

---

# The AI Build Blueprint

When asking AI to build or refactor, use this workflow:

## Step 1: Find Mixed Responsibilities

Ask the AI to inspect the target area and identify where responsibilities are tangled.

Examples:

```text
This function parses input, validates records, applies business rules, writes files, and logs user messages.
```

```text
This wrapper module mixes CLI presentation, package runtime detection, filesystem access, and orchestration.
```

---

## Step 2: Characterize Current Behavior

Before changing risky code, ask the AI to prove what the code currently does.

Examples:

```text
Capture current CLI behavior before refactoring.
```

```text
Create golden-master tests for the existing output.
```

```text
Add regression tests around current package/runtime behavior.
```

---

## Step 3: Choose One Small Target

Do not let the AI clean up the whole repo at once.

Examples:

```text
Pick one small high-value refactoring target.
```

```text
Do not perform repo-wide cleanup.
```

```text
Move files only when the move improves a real responsibility or dependency boundary.
```

---

## Step 4: Separate Responsibilities

Ask the AI to split by responsibility, not by line count.

Good split:

```text
parse_args()
validate_config()
load_input_rows()
normalize_rows()
write_report()
```

Bad split:

```text
main_part_1()
main_part_2()
main_helper()
final_processing()
```

---

## Step 5: Keep Complexity Under Control

Use McCabe/C901 as a hard guardrail, but not as the only goal.

Instruction:

```text
Keep touched production functions under McCabe/cyclomatic complexity 10.
```

---

## Step 6: Maintain Dependency Direction

Ask the AI to preserve or improve dependency direction.

Instruction:

```text
Do not introduce circular imports or dependency inversions. Keep domain/business logic independent from CLI, UI, framework, package, database, or external-service glue. Existing architecture debt remains RED until removed.
```

---

## Step 7: Run Validation

The AI must run the repo’s relevant checks.

Instruction:

```text
Run lint, format check, C901, type checks, tests, compile/package validation, and any repo-specific audit commands before claiming completion.
```

---

## Step 8: Explain the Boundary Improvement

The AI must explain what got better.

Instruction:

```text
Do not only say tests passed. Explain which responsibility boundary improved, why the new names are better, what behavior was preserved, and what risks remain.
```

---

# Default Prompt to Use With AI Coding Agents

Use this when starting a build, refactor, or cleanup mission:

```markdown
Apply the Supportability Standard.

Goal: improve clarity, modularity, maintainability, testability, and peer-review quality without changing intended behavior.

This is not a cosmetic folder shuffle. Improve real code boundaries.

Before editing code, inspect the repo and produce a short plan covering:

1. Code that is too complex or poorly organized
2. Functions exceeding or approaching McCabe/cyclomatic complexity 10
3. Mixed responsibilities
4. The smallest safe target for this change
5. Files intended to change
6. Files explicitly not touched
7. Tests and validation commands to run
8. Gate coverage: which validation gates cover the files intended to change and the highest-risk production files

Do not edit code until the plan is complete.

Rules:

- Keep touched production functions under McCabe/cyclomatic complexity 10.
- For legacy functions already above 10, no new or extracted production function may exceed 10, and touched legacy functions must move lower than their starting complexity.
- Do not game C901 by creating vague helper functions.
- Extract only responsibility-named functions or modules.
- Split along real boundaries: parsing, validation, business rules, orchestration, transformation, persistence, external APIs, config, error handling, logging, CLI/UI presentation, and tests.
- Avoid vague dumping grounds such as `utils`, `helpers`, `common`, `misc`, or `stuff`.
- Before creating a new package or top-level module, check whether an existing governed package already owns the domain. Extend the existing governed package when it owns the domain.
- Keep dependency direction predictable.
- Do not introduce circular imports or dependency inversions.
- Characterize current behavior before changing complex or legacy code.
- Prefer incremental strangler-style cleanup over big-bang rewrites.
- Keep each logical step small and runnable.
- Preserve intended behavior. Explicit behavior changes require owner scope and proof.

Validation:

Run the repo’s relevant checks before claiming completion, including lint, format check, C901, type checks, architecture/import-boundary checks, tests, compile/package validation, and any repo-specific audit commands.

Also verify and report gate coverage. The validation report must identify which changed files and high-risk production files are covered by lint, type-check, complexity, tests, and architecture/import-boundary checks. Do not claim validation is complete when changed files or high-risk production files are outside the gate scope.

Completion report:

After editing, explain:

1. What changed
2. Which responsibilities were separated
3. Which functions were simplified
4. Any McCabe/C901 improvements
5. Why the new boundary is cleaner
6. Validation commands run and results
7. Risks, gaps, or follow-up work
8. Gate coverage proof, including changed files, gates applied, excluded production files, threshold changes, and scope changes
```

---

# Short Version for Small Tasks

Use this when the task is narrow:

```markdown
Follow the Supportability Standard where relevant.

Keep the change small. Preserve behavior. Avoid vague helpers. Do not introduce circular imports or dependency inversions. Validate the result. If you refactor, explain which responsibility boundary improved.
```

---

# How to Judge AI Output

Do not judge the AI only by whether the code runs.

Ask these questions:

1. Did it preserve behavior?
2. Did it reduce complexity without creating vague helpers?
3. Did it separate real responsibilities?
4. Did it improve or preserve dependency direction?
5. Did it avoid dumping-ground modules?
6. Did it add or preserve useful tests?
7. Did it run validation?
8. Did it verify that quality gates actually cover the changed files and the highest-risk production files?
9. Did it avoid weakening thresholds, excluding files, narrowing gate scope, or moving files outside checked paths to make validation pass?
10. Did it explain the architectural improvement clearly?

If the answer is mostly no, the AI did not clean the repo. It rearranged the mess.
