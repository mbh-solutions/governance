# ADR 0004: Use an organization required workflow for adopter authority

Status: accepted

## Context

The external verifier and dedicated GitHub App separated hostile candidate evidence from adopter merge authority, but added artifact relay, scheduled transport, App enrollment, and a second repository to every adoption. Live capability proof established that the organization can require a workflow stored in a central repository, that GitHub runs it automatically on target pull requests from the selected central SHA, that a deterministic defect fails it, and that a target-local similarly named workflow cannot replace it.

Governance source qualification is already independent and remains a separate trust boundary.

## Decision

1. The default adopter authority is an organization ruleset requiring `.github/workflows/governance-required.yml` from an exact certified SHA in `mbh-solutions/governance`.
2. The central workflow uses unfiltered `pull_request`, explicit read-only permissions, exact action pins, no secrets, no App private key, no write-capable target token, and no persisted checkout credentials.
3. GitHub-supplied workflow repository, ref, and SHA identify the protected evaluator source. The workflow binds those values to the exact target repository, pull request, base, and head before evaluation.
4. The existing evaluator, typed profiles, containment, resource bounds, deterministic decision, and fail-closed input validation remain unchanged. `python.standard.v1` and `python.sqlite.v1` are the only supported profiles.
5. One stable final job returns nonzero for every blocked decision. The GitHub required-workflow rule and that job are merge authority. Diagnostic artifacts are not a second authority.
6. Native adoption bundles contain typed configuration, the Supportability Standard, and an exact-SHA manifest. They contain no target-local Governance caller, verifier enrollment, App ID dependency, or App-backed required context.
7. Merge queue remains optional and is added only after live repository eligibility and event-authority proof.
8. The external verifier implementation, repository history, artifacts, and receipts remain available for legacy installations until the native release is proven. They are not the default architecture or a native release prerequisite.

## Consequences

Adopter merge enforcement becomes event-driven and GitHub-native. A target candidate cannot edit the centrally required workflow or satisfy the rule with a local lookalike. Adoption and rollback bind one exact Governance SHA instead of coordinating a target caller, artifact relay, verifier service, App enrollment, and App-backed context.

This ADR supersedes ADR 0002 decisions 8-9 and its adopter-authority consequence for native installations. ADR 0002's independent Governance source authority remains in force. It also supersedes ADR 0003's verifier-enrollment and external-verifier recomputation wording for native installations; every SQLite extraction, policy, profile, evidence, limit, and supportability control in ADR 0003 remains unchanged. The legacy verifier path continues to follow the earlier ADRs while it remains installed.
