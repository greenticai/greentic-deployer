# DEP-PR-03 — Standardize runner invocation contract (mount plan + output, persist command)

## Goal
Fix runner invocation mismatch:
- pass DeploymentPlan deterministically
- mount/create output directory
- persist runner command and resolved paths for debugging

## Implementation plan
### 1) Stable invocation payload (no new schema)
Write:
- `state/runtime/<tenant>/<environment>/plan.json`
- `state/runtime/<tenant>/<environment>/invoke.json` containing:
  - provider, strategy, tenant, environment, output_dir, plan_path

Pass invoke.json as runner input (or plan.json if runner expects plan-only).

### 2) Output dir
Ensure `deploy/<provider>/<tenant>/<environment>/` exists before execution and is writable.

### 3) Persist diagnostics
Create in output dir:
- `._deployer_invocation.json`
- `._runner_cmd.txt`
Include pack_id, flow_id, pack path, output dir, runner argv, env.

### 4) Compatibility
If packs expect plan at a fixed mount location, mount plan there too (temporary bridge).

### 5) Smoke assertions
Smoke asserts output + diagnostics exist.

## Acceptance criteria
- ✅ Runner command is deterministic and printed/logged
- ✅ Output directory is created and writable
- ✅ Diagnostics files exist for every run

## Files
- `src/invoke_runner.rs` (new) or refactor existing
- `src/deployment.rs`
- smoke/tests updated
