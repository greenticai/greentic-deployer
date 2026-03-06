# PR-08 — Wizard-backed deployment-pack examples, replay fixtures, and CI

## Goal
Ensure new deployment-pack examples and extension packs are created with the existing wizards and replay files, not handcrafted ad hoc.

## Tasks

### 1. Wizard-created example assets
Use:
- `greentic-pack wizard`
- `greentic-flow wizard`
- `greentic-component wizard`

to scaffold:
- a deployment-pack example
- a sample flow set for `generate/plan/apply/destroy/status/rollback`
- any helper components needed for deployer demo/testing

### 2. Commit replay answers
Add answer documents under:
- `testdata/answers/**`
- `examples/answers/**`

### 3. Replay CI
Add smoke tests that:
- replay answers
- verify scaffold is stable
- compare against golden snapshots where appropriate

### 4. Documentation
Document how to regenerate examples from replay files.

## Boundary rule
These examples must live as deployment packs and related fixtures. They must not reintroduce a deployer CLI surface or handcrafted provider logic into the core runtime.

## Important
If the wizard JSON schema becomes available later, update examples to validate answer documents against the schema before replay.

## Implemented shape
This repo now includes replay-backed example assets under:

- `examples/answers/deployment-packs/*.json`
- `testdata/answers/deployment-packs/replay-index.json`
- `docs/replay-examples.md`

Delivered coverage includes:
- replay answer documents for all current deployment-pack fixtures
- real `greentic-pack wizard` scaffold answers for each deployer fixture
- replay index validation
- fixture/reference smoke tests in `tests/pr08_replay_examples.rs`
- scaffold replay via `cargo run --bin replay_deployer_scaffolds`
- CI-style replay smoke entry via `scripts/ci-smoke.sh`
- regeneration documentation aligned with the current library-only boundary

This was implemented as replay fixtures and smoke tests for deployment-pack examples, plus real wizard-backed scaffold answers under `examples/answers/deployer-scaffolds/*.json`. The scaffold replay uses `greentic-pack wizard apply` and overlays provider-specific fixture assets. It does not reintroduce a deployer CLI surface or handcrafted provider logic into the core runtime.
