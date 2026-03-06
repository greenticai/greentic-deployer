# DEP-PR-01 — Deterministic smoke harness + fixtures (plan -> runner -> output)

## Goal
Create a **reproducible**, **deterministic** test harness proving that `greentic-deployer` can:
1) load/build a minimal `DeploymentPlan` from a fixture app pack (or fixture plan JSON),
2) select a deployment provider pack + flow (initially placeholders),
3) invoke `greentic-runner`,
4) and produce output under `deploy/<provider>/<tenant>/<environment>/`.

This PR is intentionally *first* to stop guessing: every subsequent fix is validated against this harness.

## Non-goals
- No schema invention.
- No provider-extension migration yet.
- No real cloud API calls (use mock/emit-only placeholders).

## Additions
### 1) New `tests/fixtures/`
Pick ONE approach (prefer A if deployer already reads app packs):
- **A: Fixture app pack**: `tests/fixtures/app-pack/` that deployer can plan from.
- **B: Fixture plan JSON**: `tests/fixtures/plan.json` + a `deployer emit --plan <path>` command.

Include:
- tenant: `acme`
- environment: `dev`
- provider: `local` (first green target)
- strategy: open-ended string (e.g. `placeholder`)

### 2) Smoke runner script (local + CI)
Add `ci/smoke_deployer.sh` that:
- builds deployer (or uses target/debug in dev-mode)
- builds/locates placeholder provider packs
- runs:
  - `greentic-deployer plan ...` (or uses plan fixture)
  - `greentic-deployer emit --provider local --strategy placeholder --tenant acme --environment dev ...`
- asserts output exists:
  - `deploy/local/acme/dev/README.md` (or `main.tf`, `Chart.yaml`, etc.)

Make it print:
- selected pack_id + flow_id
- runner command line
- resolved output dir

### 3) Rust integration test (preferred)
Add `tests/smoke_placeholder_local.rs` that executes the CLI (or calls internal API):
- run deployer in a temp workdir
- assert output files exist
- capture stdout/stderr on failure

If CLI-based tests are hard, keep shell smoke script and run it from CI.

## Code changes (greentic-deployer)
- Add `--workdir` or ensure tests can run in temp dirs (if not already)
- Add `--print-runner-cmd` (or always log it at INFO)
- Ensure deployer returns non-zero exit code with actionable error when selection fails

## Acceptance criteria
- ✅ `./ci/smoke_deployer.sh` succeeds locally for provider `local`
- ✅ CI runs smoke and fails with clear logs if broken
- ✅ Output path contract is validated

## Files
- `ci/smoke_deployer.sh`
- `tests/fixtures/...`
- `tests/smoke_placeholder_local.rs` (optional)
- Minimal doc update: `docs/testing.md` or README section
