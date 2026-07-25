# ADR 0003: Add a bounded SQLite supportability profile

Status: accepted

## Context

`python.standard.v1` governs Python repositories but cannot produce authoritative
evidence for SQLite embedded in Python or packaged resources. Allowing adopter
commands or exclusions would move the trust boundary into candidate-controlled
configuration. Building a general SQL framework would add engines and extension
points without a proved adopter need.

TWMN is the first real adopter candidate. Acceptance evidence is pinned to
`markheck-solutions/twmn@47bf8823000ac98595ccb1013d3f8f6abdf90ebd`
(tree `45b985ed6944cf9cc48ffe56e9954df5060b2a6a`). Its required patterns are
bounded: literal SQL, constant concatenation, static dictionaries, parameter
binding, schema creation, PRAGMA, FTS, and packaged `.sql` resources.

## Decision

1. Add opt-in profile `python.sqlite.v1`. It extends the exact
   `python.standard.v1` capability sequence with `sql_supportability` using
   evaluator-owned adapter `python.sqlite-supportability.v1`.
2. Classify the adapter `EVALUATOR_AUTHORITATIVE`. Candidate configuration may
   not provide commands, exclusions, adapter choices, or escape hatches.
3. Keep `python.standard.v1` byte-compatible for every non-SQL adopter. The
   measured byte surfaces are adapter identifiers, assurance classes, order,
   execution-plan steps, profile marker framing, canonical payload
   serialization, and deterministic decision for identical inputs. Golden bytes
   and SHA-256 digests come from rollback SHA
   `c07b2ecf831fa2e3c68481a782a7e9e50d9dbc86`; release identity, timestamps,
   standard-document hash, and artifact bindings are excluded.
4. Opt in only through the evaluator-owned adoption generator's typed profile
   argument. It writes `profile: python.sqlite.v1` and binds that value into the
   manifest and verifier enrollment. Source discovery does not auto-select a
   profile. Candidate execution derives the adapter tuple from authenticated
   configuration; the verifier derives it independently from enrollment plus
   authenticated configuration and manifest. Any mismatch blocks.
   Before execution, discovery requires this profile when packaged Python has a
   `sqlite3` import plus a resolved connection/cursor/sink, or when that flow
   references a packaged `.sql` resource. SQLite evidence under
   `python.standard.v1` blocks without auto-switching. Unclassified SQL-like
   sources also block.
5. Scan only the host-validated packaged Python/resource surface. Exclude tests,
   environments, caches, and arbitrary ignored directories. Adoption preflight
   additionally checks tracked files, untracked nonignored files, and ignored
   SQL only when production code references it; a required resource absent from
   the committed pull-request head blocks.
6. Resolve only string literals, constant concatenation, static dictionaries,
   and statically selected dictionary values. Fail closed on f-strings,
   runtime-built SQL, missing constants, dynamic identifiers, runtime-loaded
   external SQL, unsupported sinks, malformed SQL, or unresolved resources.
7. Recognize only `execute`, `executemany`, and `executescript` sinks. Prove
   receiver provenance through `sqlite3` import aliases, `connect`,
   connection/cursor annotations, cursor derivation, and statically resolved
   returns across the packaged graph. An unresolved receiver participating in
   SQLite or SQL flow blocks. Unresolved dynamic dispatch, `getattr`, method
   aliases, and wrapper forwarding block; ignore an unrelated same-named
   method only when its non-SQL type is proved.
8. Enforce evaluator-owned maxima before parsing: 10,000 files, 2 MiB per file,
   32 MiB total, 1,000,000 Python AST nodes, 10,000 sinks, 10,000 SQL statements,
   and 1 MiB per normalized statement. Positive-at-limit and negative-over-limit
   controls are required.
9. Use Python standard-library `ast` and `sqlite3`. Build schema statements only
   in statically proved sink and statement order in an isolated in-memory
   database, then prepare remaining statements with bounded qmark or named dummy
   bindings without importing or executing candidate Python code. Unproved
   cross-function/resource order blocks; never reorder SQL to make it pass.
10. Apply evaluator-owned `sqlite-policy.v1` exactly as specified below. Keep
    extension loading disabled; use a default-deny authorizer and statement
    classifier; and retain the existing process memory/output bounds.
11. Normalize `CRLF`, `CR`, and `LF` before canonical SQL hashing. Bind source
   paths, line numbers, normalized hashes, sink identities, preparation results,
   receiver provenance, exact SQLite version/compile-option digest, canonical
   policy SHA-256, errors, timestamps, applied limits, and bounded counts into
   typed plan and result evidence.
12. Report `Gate implementation`, `Repo SQL supportability`, and
   `SQL behavior proof` separately. `SQL behavior proof` means adapter controls
   pass, schema builds in statically proved order, remaining SQL compiles with
   bounded qmark or named dummy bindings, and required SQLite features exist. It does not assert query
   result rows, migration correctness, transaction semantics, or business
   behavior. Missing, malformed, unsupported,
   contradictory, mutated, replayed, or unverifiable evidence is
   `BLOCK_TECHNICAL`.
13. Use only Python standard library plus existing safe package-audit helpers.
    Do not reuse or execute TWMN's candidate-owned `scripts/sql_gate.py`; it may
    inform evaluator-owned controls only. The pinned TWMN database module has
    SHA-256 `bf8197920fe4821b7f8dc00e994db8f737c73863f40ecbaaa34069286a9cd66b`;
    its SQL gate has SHA-256
    `164e014d7f8c03d7393e765e0479524d149159bff281142879b4981640eb6363`.

## SQLite policy v1

`sqlite-policy.v1` is evaluator-owned and canonical. Candidate execution and the
external verifier independently compute its canonical JSON SHA-256 and require
the same policy hash in plans, results, manifests, and enrollment evidence.

| Control | Exact value |
|---|---|
| SQLite version | `>=3.40.0,<4.0.0`; exact certified version and compile-option digest bound to toolchain evidence |
| Required compile option | `ENABLE_FTS5` |
| Executed schema statements | `CREATE TABLE`, `CREATE INDEX`, `CREATE VIEW`, `CREATE TRIGGER`, `CREATE VIRTUAL TABLE ... USING fts5` |
| Candidate PRAGMA allowlist | `foreign_keys`, `foreign_key_check`, `quick_check` |
| SQL function allowlist | `bm25`, `coalesce`, `highlight`, `like`, `match`, `snippet` |
| Virtual-table module allowlist | `fts5` |
| Always denied | `ATTACH`, `DETACH`, `VACUUM`, file-backed databases, `load_extension`, writable schema, every unlisted PRAGMA/function/module, filesystem escape |
| Progress bound | `10,000,000` virtual-machine operations and `2` seconds per statement |
| Adapter bound | `120` seconds plus existing process memory/output limits |

The connection is `:memory:` only and initializes `trusted_schema=OFF`,
`temp_store=MEMORY`, `journal_mode=MEMORY`, `foreign_keys=ON`,
`recursive_triggers=OFF`, `max_page_count=16384`, and `cache_size=-8192`.

| `sqlite3.setlimit` category | Exact value |
|---|---:|
| `SQLITE_LIMIT_LENGTH` | `2097152` |
| `SQLITE_LIMIT_SQL_LENGTH` | `1048576` |
| `SQLITE_LIMIT_COLUMN` | `2000` |
| `SQLITE_LIMIT_EXPR_DEPTH` | `1000` |
| `SQLITE_LIMIT_COMPOUND_SELECT` | `500` |
| `SQLITE_LIMIT_VDBE_OP` | `250000` |
| `SQLITE_LIMIT_FUNCTION_ARG` | `127` |
| `SQLITE_LIMIT_ATTACHED` | `0` |
| `SQLITE_LIMIT_LIKE_PATTERN_LENGTH` | `50000` |
| `SQLITE_LIMIT_VARIABLE_NUMBER` | `32766` |
| `SQLITE_LIMIT_TRIGGER_DEPTH` | `100` |
| `SQLITE_LIMIT_WORKER_THREADS` | `0` |

The publication suite must prove every allowlist item, every explicit denial,
every at-limit/over-limit pair, the policy digest binding, an SQLite version or
compile-option mismatch, and candidate/verifier recomputation disagreement.

## Release boundary

The contract lands first through `Governance Source Qualification`. One later
publication pull request may add adapter code, schemas, verifier validation,
adoption generation, documentation, and tests, but may not change frozen source
qualifier modules, the source workflow pair, dependency lock, or package
contract. Publication uses a merge commit and exact-merge qualification before a
pin-only verifier activation.

The existing disposable runtime repository must prove clean, defective, replay,
hostile-artifact, stale-head, spoofed-context, and AI-unavailable canaries before
release. Only then may an immutable release be published and TWMN be enrolled as
the first real adopter from a separate clean worktree.

## Consequences

SQLite gains deterministic, fail-closed support without changing non-SQL
adopters or creating a multi-engine abstraction. Unsupported dynamic SQL blocks
instead of receiving a waiver. PostgreSQL, Snowflake, arbitrary SQL commands,
and additional databases remain out of scope.
