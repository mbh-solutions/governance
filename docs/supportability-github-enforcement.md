# GitHub supportability enforcement

This repository publishes repo-agnostic Governance components. Adopter repositories supply typed configuration and pin an exact certified Governance SHA. Governance source uses separate source qualification; every Governance product workflow on Governance source is diagnostic.

## Native merge decision

GREEN requires:

- configured deterministic gates pass;
- architecture implementation and behavior proof pass;
- the exact target, pull request, base, head, central workflow repository, and central workflow SHA are bound;
- the typed configuration, adoption manifest, Supportability Standard, evaluator, toolchain, and runtime identities match;
- the evaluator-owned profile completes with no blocking deterministic result;
- the stable final decision job succeeds.

Codex is evidence, not approval. `AI_REVIEW_UNAVAILABLE` never skips deterministic evaluation. Copilot is not a required reviewer, gate, receipt input, or dependency.

## Target configuration

```yaml
ai_review:
  provider: codex_connector
  adapter: codex_connector_pr_signal_v2
  review_window_seconds: 300
  unavailable_after_cutoff: non_blocking
  unresolved_p0_p1_p2_blocks: true
```

These values are fixed by schema. Target repositories cannot substitute reviewer identities, shorten the window, or turn blocking findings into advisory output.

## Event model

The organization-required central workflow uses unfiltered `pull_request`. GitHub supplies the target event identity plus the required workflow repository, ref, and SHA. The workflow checks out the exact target head without persisted credentials and obtains the evaluator from that exact protected central SHA.

The target has no Governance caller to modify. Candidate content remains untrusted and runs only inside the existing bounded containment model. Merge-group support is a later optional profile and requires live eligibility and event-authority proof.

## Required checks

On Governance source, require only `Governance Source Qualification`; product contexts are diagnostic. On an adopter, an organization ruleset requires the exact central workflow at the certified Governance SHA. Its stable final job is authoritative because GitHub binds it to the required-workflow rule; a local similarly named workflow is not a substitute. Apply protection only through the guarded procedure in `TASK.md`.

## Evidence artifacts

The native workflow records checkout, plan, execution, and final candidate-bundle receipts. Artifact upload is diagnostic only: no relay, poller, App, or copied status consumes it to authorize merge. The final job reads the host-owned local receipt and fails for a missing receipt or any decision other than `PASS`.

## Adoption boundary

Do not roll this framework into application repositories until exact publication qualification, organization-ruleset binding, rollback proof, and every disposable positive/negative canary pass. Target repositories remain read-only until an explicit installation. The external verifier is a legacy optional path retained for historical installations and receipts; it is not a native release dependency.
