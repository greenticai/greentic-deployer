# DEP-PR-02 — Make placeholder dispatch runnable (pack discovery, env overrides, better errors)

## Context
Default dispatch map covers providers: aws, local, azure, gcp, k8s, generic.
Each routes to placeholder `(pack_id, flow_id)` entries like:
- `greentic.demo.deploy.aws` + `deploy_aws_iac`
- `greentic.demo.deploy.local` + `deploy_local_iac`
...etc.

Overrides exist via:
- `DEPLOY_TARGET_<PROVIDER>_<STRATEGY>_PACK_ID`
- `DEPLOY_TARGET_<PROVIDER>_<STRATEGY>_FLOW_ID`

But none of the providers are currently working.

## Goal
Make the placeholder dispatch path runnable and debuggable:
- Ensure deployer can find placeholder packs (local path first)
- Ensure flow IDs exist (or print available flows)
- Ensure override env vars are parsed robustly
- Improve error messages: show discovered packs, selected pack/flow, missing items.

## Implementation plan
### 1) Pack discovery sources
Deterministic search order:
1) `--providers-dir <path>` (default: `./providers/deployer` or `./providers`)
2) `--packs-dir <path>` (default: `./packs`)
3) `./dist` or `./examples` as fallback (only if already used)

Support a direct override:
- `--provider-pack <path.gtpack>` (debug)

### 2) Better selection diagnostics
When selection fails, print:
- requested provider + strategy
- whether override env vars were set and their values
- selected pack_id + flow_id (or default candidate)
- list discovered pack_ids (and origin paths)
- if pack found but flow missing: list available flows

### 3) Normalize env var parsing
Provider normalization for env lookup:
- provider `k8s` / `K8S` treated same
- strategy is open-ended; normalize to uppercase for env key only.

Also allow fallback overrides:
- `DEPLOY_TARGET_<PROVIDER>_PACK_ID`
- `DEPLOY_TARGET_<PROVIDER>_FLOW_ID`
used only if strategy-specific keys missing.

### 4) Wire into DEP-PR-01 smoke
Update smoke harness to verify:
- default selection works (local)
- env override works (set override and see selection change)

## Acceptance criteria
- ✅ Missing pack errors show search locations and how to fix
- ✅ Missing flow errors list available flows
- ✅ Smoke consistently reaches “runner invoked”
- ✅ Env override works and is tested

## Files
- `src/deployment.rs` (selection + env parsing + errors)
- `src/cli.rs` (new flags)
- `ci/smoke_deployer.sh`
- tests updated
