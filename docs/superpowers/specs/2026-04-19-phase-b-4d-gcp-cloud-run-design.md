# Phase B #4d — GCP Cloud Run Deploy Extension

- **Date:** 2026-04-19
- **Status:** Draft, pending user review
- **Branch:** `spec/phase-b-4d-gcp-cloud-run`
- **Owner:** TBD
- **Related:**
  - Parent: `memory/deploy-extension-next-steps.md` (Phase B #4d — clouds)
  - Phase B #4a (MERGED): `docs/superpowers/specs/2026-04-19-phase-b-4a-deployer-cli-wiring-design.md`
  - Phase B #4b+#4c (MERGED 2026-04-19): `docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`
  - Reused pack fixture: `greentic-deployer/fixtures/packs/terraform/` (`greentic.deploy.gcp` — cloud-aware, same pack serves aws/gcp/azure)
  - Ref exts repo: `greentic-biz/greentic-deployer-extensions` (ships `deploy-desktop@0.2.0`, `deploy-single-vm@0.1.0`, `deploy-aws@0.1.0`, will ship `deploy-gcp@0.1.0`)

## 1. Context & motivation

### Current state after Phase B #4b+#4c (merged 2026-04-19)

`ext apply --target X` routes via `src/ext/backend_adapter.rs` to Desktop, SingleVm, and Aws backends. Gcp/Azure/Terraform/etc. return `AdapterNotImplemented` with message listing Desktop/SingleVm/Aws as supported.

### Goal

Make `greentic-deployer ext apply --target gcp-cloud-run-local ...` deploy to GCP Cloud Run via the existing `greentic.deploy.gcp` pack (which wraps the `fixtures/packs/terraform/modules/operator-gcp/` module). Ship a new `deploy-gcp@0.1.0.gtxpack` ref ext. Mirror AWS pattern end-to-end; validate cross-cloud consistency.

Two paired PRs (same strategy as #4b+#4c):
- **Phase A** — `greentic-deployer`: GCP match arms in `backend_adapter`, new `gcp::apply_from_ext` / `destroy_from_ext` entry points.
- **Phase B** — `greentic-biz/greentic-deployer-extensions`: new `reference-extensions/deploy-gcp/` crate.

### Hard non-negotiable constraint (same as #4b)

**Existing `greentic-deployer` cloud paths must remain bit-for-bit untouched.** No changes to:
- `src/gcp.rs` existing pub fns (`resolve_config`, `ensure_gcp_config`, `run`, `run_config`, `run_with_plan`, `run_config_with_plan`)
- `src/main.rs` clap `run_gcp` path
- `src/apply.rs`, `src/aws.rs`, `src/azure.rs`, and all other cloud backends
- `src/deployment.rs` dispatch table (`greentic.deploy.gcp` already mapped)
- `fixtures/packs/terraform/` (reused as `greentic.deploy.gcp` pack)

### Non-goals

- No Mode B (Phase B #2)
- No `host::http`/`host::secrets`/`host::storage` (Phase B #2)
- No secret URI resolution — secrets via ambient Google Application Default Credentials (ADC) chain
- No new pack authoring — reuse existing `greentic.deploy.gcp` pack
- No Azure ref ext — follows separately (Phase B #4d Azure split-out)
- No GKE/Cloud Functions targets — single target `gcp-cloud-run-local`, expand later if demand
- No preview/dry-run flag on `ext apply` path — use built-in `greentic-deployer gcp plan`

## 2. Design decisions (from brainstorming)

| # | Question | Decision | Reason |
|---|---|---|---|
| Q1 | Target identifier | `gcp-cloud-run-local` | Symmetric with `aws-ecs-fargate-local`; kebab-case matches deployer convention |
| Q2 | Required config fields | `projectId, region, environment, operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend` (7 fields — 6 shared with AWS + `projectId`) | Parity with AWS; `projectId` is GCP-specific required; optional fields same as AWS |
| Q3 | AWS precedent decisions carry over | Yes — Q1/Q2/Q3/Q4/Q5 from #4b+#4c apply verbatim with cloud swap | Pattern proven end-to-end; YAGNI to re-debate |

Carried forward from #4b+#4c without re-litigation:
- Ambient credentials (Google ADC via `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS`)
- Narrow Rust wrapper `GcpCloudRunExtConfig` (not full pack input schema)
- Thin adapter delegating to existing `resolve_config` + `apply::run`
- Async isolated via internal `tokio::runtime::Runtime::new().block_on()`
- Single target, expand in 0.2.0 if demand
- Reuse existing `greentic.deploy.gcp` pack (multi-cloud-aware via `cloud: gcp`)

## 3. Architecture

```
┌─ Existing Phase B #4a + #4b (UNCHANGED) ──────────────────────────────┐
│   ext::cli::run_apply → dispatch_extension → backend_adapter::run    │
│   Desktop/SingleVm/Aws arms — all untouched                          │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ src/ext/backend_adapter.rs (EXTENDED) ──────────────────────────────┐
│   match (backend, action) {                                          │
│     ... existing arms (Desktop/SingleVm/Aws) UNCHANGED ...           │
│     (Gcp, Apply)   => gcp::apply_from_ext(json, creds, pack_path)    │  ← NEW
│     (Gcp, Destroy) => gcp::destroy_from_ext(json, creds, pack_path)  │  ← NEW
│     _ => AdapterNotImplemented                                       │
│   }                                                                  │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ src/gcp.rs (ADDITIVE ONLY) ─────────────────────────────────────────┐
│   existing: resolve_config, ensure_gcp_config, run, run_config, etc. │
│   NEW:      pub struct GcpCloudRunExtConfig                          │
│   NEW:      fn build_gcp_request_from_ext                            │
│   NEW:      pub fn apply_from_ext (tokio::block_on)                  │
│   NEW:      pub fn destroy_from_ext (tokio::block_on)                │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ Existing deploy pipeline (ENTIRELY UNCHANGED) ──────────────────────┐
│   apply::run → terraform plan/apply via provider                     │
│   pack discovery → greentic.deploy.gcp (reuses fixtures/packs/...)   │
└──────────────────────────────────────────────────────────────────────┘
```

**Async isolation:** Adapter and CLI layers are sync. GCP deploy is async. `gcp::apply_from_ext` creates its own tokio runtime and `block_on`s internally (mirror of AWS).

## 4. Components & files

### 4.1 `greentic-deployer` — `src/gcp.rs` additions (~100 impl + ~60 tests)

New Deserialize struct (placed after existing request types, before `impl GcpRequest`):

```rust
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudRunExtConfig {
    pub project_id: String,
    pub region: String,
    pub environment: String,
    pub operator_image_digest: String,
    pub bundle_source: String,
    pub bundle_digest: String,
    pub remote_state_backend: String,
    pub dns_name: Option<String>,
    pub public_base_url: Option<String>,
    pub repo_registry_base: Option<String>,
    pub store_registry_base: Option<String>,
    pub admin_allowed_clients: Option<String>,
    #[serde(default = "default_ext_tenant")]
    pub tenant: String,
}

fn default_ext_tenant() -> String {
    "default".to_string()
}
```

Private helper (dedupes GcpRequest construction):

```rust
fn build_gcp_request_from_ext(
    capability: DeployerCapability,
    cfg: &GcpCloudRunExtConfig,
    pack_path: Option<&Path>,
) -> GcpRequest {
    GcpRequest {
        capability,
        tenant: cfg.tenant.clone(),
        pack_path: pack_path.map(Path::to_path_buf).unwrap_or_default(),
        bundle_source: Some(cfg.bundle_source.clone()),
        bundle_digest: Some(cfg.bundle_digest.clone()),
        repo_registry_base: cfg.repo_registry_base.clone(),
        store_registry_base: cfg.store_registry_base.clone(),
        provider_pack: None,
        deploy_pack_id_override: None,
        deploy_flow_id_override: None,
        environment: Some(cfg.environment.clone()),
        pack_id: None,
        pack_version: None,
        pack_digest: None,
        distributor_url: None,
        distributor_token: None,
        preview: false,
        dry_run: false,
        execute_local: true,
        output: crate::config::OutputFormat::Text,
        config_path: None,
        allow_remote_in_offline: false,
        providers_dir: PathBuf::from("providers/deployer"),
        packs_dir: PathBuf::from("packs"),
    }
}
```

**Note on `project_id`:** `GcpRequest` struct doesn't have a `project_id` field (it's a terraform variable consumed by the pack). Same situation as AWS `region`. Value is validated at the extension layer (Rust struct + JSON schema), and pack-level plumbing (bundle config → `TF_VAR_gcp_project_id`) is pack responsibility. If pack doesn't currently consume it automatically, that's a separate bug tracked outside this PR.

Public entry points:

```rust
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: GcpCloudRunExtConfig = serde_json::from_str(config_json)
        .context("parse gcp cloud-run config JSON")?;
    let request = build_gcp_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve GCP deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for GCP deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run GCP deployment pipeline")?;
    Ok(())
}

pub fn destroy_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: GcpCloudRunExtConfig = serde_json::from_str(config_json)
        .context("parse gcp cloud-run config JSON")?;
    let request = build_gcp_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve GCP deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for GCP destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run GCP destroy pipeline")?;
    Ok(())
}
```

6 unit tests (listed in §7.1).

### 4.2 `greentic-deployer` — `src/ext/backend_adapter.rs` additions (~25 LoC)

Add 2 match arms (mirror of Aws arms) BEFORE `_ =>`:

```rust
(BuiltinBackendId::Gcp, ExtAction::Apply) => {
    crate::gcp::apply_from_ext(config_json, creds_json, pack_path).map_err(|e| {
        ExtensionError::BackendExecutionFailed {
            backend,
            source: e,
        }
    })
}
(BuiltinBackendId::Gcp, ExtAction::Destroy) => {
    crate::gcp::destroy_from_ext(config_json, creds_json, pack_path).map_err(|e| {
        ExtensionError::BackendExecutionFailed {
            backend,
            source: e,
        }
    })
}
```

Add 2 new tests + update existing 2 tests to use `Azure` instead of `Gcp` as "unsupported" example (Gcp is now wired).

### 4.3 `greentic-deployer` — `src/ext/errors.rs` (~3 LoC)

Update `AdapterNotImplemented` message:

```rust
#[error(
    "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws, Gcp)"
)]
AdapterNotImplemented { backend: BuiltinBackendId },
```

Update existing test `adapter_not_implemented_displays_backend` — use `Azure` as unsupported example; assertions include Gcp.

### 4.4 `greentic-deployer` — `tests/ext_apply_integration.rs` additions (~30 LoC)

1 new `#[ignore]` placeholder test `ext_apply_gcp_target_requires_required_config_fields`. Unignore when `testdata/ext/greentic.deploy-gcp-stub/` lands after #4d ref ext publishes.

### 4.5 `greentic-biz/greentic-deployer-extensions` — new `deploy-gcp/` ref ext crate

Mirror `reference-extensions/deploy-aws/` structure exactly. Key content:

**`describe.json`:**

```json
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": {
    "id": "greentic.deploy-gcp",
    "name": "GCP Deploy",
    "version": "0.1.0",
    "summary": "GCP Cloud Run deployment via Terraform",
    "author": { "name": "Greentic", "email": "team@greentic.ai" },
    "license": "MIT"
  },
  "engine": { "greenticDesigner": "*", "extRuntime": "^0.1.0" },
  "capabilities": {
    "offered": [{ "id": "greentic:deploy/gcp-cloud-run", "version": "0.1.0" }],
    "required": []
  },
  "runtime": {
    "component": "extension.wasm",
    "memoryLimitMB": 32,
    "permissions": { "network": [], "secrets": [], "callExtensionKinds": [] }
  },
  "contributions": {
    "targets": [{
      "id": "gcp-cloud-run-local",
      "displayName": "GCP Cloud Run (local Terraform)",
      "description": "Deploy to GCP Cloud Run via Terraform using ambient Google credentials",
      "execution": { "backend": "gcp", "handler": null, "kind": "builtin" },
      "supportsRollback": true
    }]
  }
}
```

**`schemas/gcp-cloud-run.credentials.schema.json`** — empty object (ambient ADC).

**`schemas/gcp-cloud-run.config.schema.json`** — mirror `GcpCloudRunExtConfig`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "GCP Cloud Run deployment config",
  "type": "object",
  "required": [
    "projectId", "region", "environment", "operatorImageDigest",
    "bundleSource", "bundleDigest", "remoteStateBackend"
  ],
  "properties": {
    "projectId":           { "type": "string", "minLength": 1, "description": "GCP project ID" },
    "region":              { "type": "string", "minLength": 1, "description": "GCP region (e.g., us-central1)" },
    "environment":         { "type": "string", "minLength": 1 },
    "operatorImageDigest": { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
    "bundleSource":        { "type": "string", "minLength": 1 },
    "bundleDigest":        { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
    "remoteStateBackend":  { "type": "string", "minLength": 1, "description": "Terraform remote state (e.g., gs://bucket/path)" },
    "dnsName":             { "type": "string" },
    "publicBaseUrl":       { "type": "string" },
    "repoRegistryBase":    { "type": "string" },
    "storeRegistryBase":   { "type": "string" },
    "adminAllowedClients": { "type": "string" },
    "tenant":              { "type": "string" }
  },
  "additionalProperties": false
}
```

**`src/lib.rs`** — mirror `deploy-aws/src/lib.rs`:
- `const TARGET_GCP_CLOUD_RUN: &str = "gcp-cloud-run-local";`
- Mode A implementation; deploy/poll/rollback return `Internal` error pointing at `backend=gcp` routing
- Manifest identity: `id: "greentic.deploy-gcp"`, `version: "0.1.0"`
- Offered capability: `greentic:deploy/gcp-cloud-run @ 0.1.0`

**`Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `build.sh`, `wit/world.wit`** — copy from `deploy-aws/` with name substitutions. **CRITICAL:** `.gitignore` must only exclude `src/bindings.rs` (not Cargo.lock or /wit — lesson learned from PR #4 CI failure).

**`ci/local_check.sh`:** extend to build+validate deploy-gcp after deploy-aws.

### 4.6 Delta summary

| Repo / file | LoC delta |
|---|---|
| `greentic-deployer/src/gcp.rs` | +~160 |
| `greentic-deployer/src/ext/backend_adapter.rs` | +~25 |
| `greentic-deployer/src/ext/errors.rs` | ~3 |
| `greentic-deployer/tests/ext_apply_integration.rs` | +~30 |
| **Deployer PR total** | **~220** |
| `greentic-deployer-extensions/reference-extensions/deploy-gcp/` (NEW) | +~350 |
| `greentic-deployer-extensions/ci/local_check.sh` | +4 |
| **Total across 2 PRs** | **~575** |

### 4.7 Files EXPLICITLY unchanged

- `src/gcp.rs` existing pub fns
- `src/main.rs::run_gcp` and all clap paths
- `src/apply.rs`, `src/aws.rs`, `src/azure.rs`, `src/terraform.rs`, and all other backends
- `src/deployment.rs` dispatch table
- `fixtures/packs/terraform/` — reused
- `src/desktop.rs`, `src/single_vm.rs`
- `src/ext/dispatcher.rs`, `src/ext/cli.rs`, `src/ext/wasm.rs`, `src/ext/loader.rs`, `src/ext/registry.rs`, `src/ext/builtin_bridge.rs`
- All existing tests

## 5. Data flow

### 5.1 Happy path (apply)

User prerequisites (outside our tool):
1. `gcloud auth application-default login` (or `GOOGLE_APPLICATION_CREDENTIALS`)
2. `terraform` binary on PATH
3. `deploy-gcp-0.1.0.gtxpack` installed in `~/.greentic/extensions/deploy/`
4. `greentic.deploy.gcp.gtpack` in `./packs/` or `./providers/deployer/`

```bash
greentic-deployer ext apply \
  --target gcp-cloud-run-local \
  --creds creds.json \
  --config config.json \
  --ext-dir ~/.greentic/extensions/deploy
```

`creds.json`: `{}`

`config.json`:

```json
{
  "projectId": "my-gcp-project-12345",
  "region": "us-central1",
  "environment": "staging",
  "operatorImageDigest": "sha256:abcd...64hex",
  "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:...",
  "bundleDigest": "sha256:ef01...64hex",
  "remoteStateBackend": "gs://my-tf-state-bucket/greentic/staging"
}
```

### 5.2 Sequence

Structurally identical to Phase B #4b (AWS) with Gcp substitution. See Phase B #4b spec §5.2 for full detail. Key steps:

1. clap → `TopLevelCommand::Ext(cmd)` → `ext::cli::run_apply(&dir, args)`
2. Read creds/config files → scan + registry + WasmtimeInvoker
3. `dispatch_extension` → validates schemas → `DispatchAction::Builtin(BridgeResolved{backend: Gcp, handler: None})`
4. `backend_adapter::run(Gcp, None, Apply, creds, config, pack_path)` → `gcp::apply_from_ext(...)`
5. Parse → build request → `gcp::resolve_config` → new tokio runtime → `apply::run(config)`
6. Drop `OperationResult`, return `Ok(())`

### 5.3 Destroy flow

Identical with `ExtAction::Destroy` → `destroy_from_ext` → `DeployerCapability::Destroy`.

### 5.4 Pack discovery

Existing `find_pack_for_dispatch`:
1. `--pack` CLI arg (→ `provider_pack`)
2. `providers_dir` (default `providers/deployer/`)
3. `packs_dir` (default `packs/`)
4. `dist/`, `examples/`

User needs `greentic.deploy.gcp.gtpack` in one of these paths.

### 5.5 How `projectId` reaches terraform

Same pattern as AWS `region` — pack-layer responsibility:
1. User provides `projectId` in `config.json` → parsed into `GcpCloudRunExtConfig.project_id`
2. Not forwarded to `GcpRequest` (no slot for it)
3. Pack flow consumes `bundle_source` + `bundle_digest` + `environment` via `GcpRequest`
4. Terraform receives `TF_VAR_gcp_project_id` through pack's flow context

If current pack flow doesn't populate `gcp_project_id` from request bundle data, terraform apply will fail. Surfaced as separate bug outside Phase B #4d scope — spec commits to the user-facing contract (Rust struct + schema), pack plumbing is pack repo territory.

### 5.6 Non-goals in flow

- No preview/dry-run from ext path
- No output format flag
- No secret URI resolution (Phase B #2)
- No Mode B

## 6. Error handling

No new error variants — reuse Phase B #4a variants.

### 6.1 Error matrix

| Layer | Scenario | Variant |
|---|---|---|
| CLI | Creds/config file missing | `CredsReadError` / `ConfigReadError` |
| Dispatcher | Target not in registry | `TargetNotFound` |
| Dispatcher | Config schema violation | `ValidationFailed` |
| Dispatcher | Mode B target | `ModeBNotImplemented` |
| Adapter | JSON parse error | `BackendExecutionFailed { backend: Gcp, source }` |
| Adapter | Missing required field | `BackendExecutionFailed { backend: Gcp, source }` (serde via `anyhow::Error::from`) |
| Adapter | Pack not found | `BackendExecutionFailed { backend: Gcp, source }` (wraps `DeployerError`) |
| Adapter | Tokio runtime creation fails | `BackendExecutionFailed { backend: Gcp, source }` (via `.context()`) |
| Adapter | Terraform failure | `BackendExecutionFailed { backend: Gcp, source }` |
| Adapter | Ambient Google creds missing | Propagated from terraform, in source chain |

### 6.2 Example error output

```
Error: backend 'Gcp' execution failed: pack 'greentic.deploy.gcp' not found; searched providers-dir (providers/deployer), packs-dir (packs), dist, examples (candidates: none)
```

```
Error: backend 'Gcp' execution failed: parse gcp cloud-run config JSON: missing field `projectId` at line 2 column 3
```

```
Error: backend 'Gcp' execution failed: run GCP deployment pipeline: terraform apply: Error: google: could not find default credentials. See https://cloud.google.com/docs/authentication/external/set-up-adc
```

### 6.3 Non-goals

Same as #4b: no retry, no structured codes, no rollback from adapter.

## 7. Testing

### 7.1 Unit tests — `src/gcp.rs` (6 new)

Mirror `src/aws.rs` tests structure. Test names:
- `ext_config_parses_minimum_fields`
- `ext_config_accepts_all_optionals`
- `ext_config_rejects_missing_project_id` (GCP-specific — tests `projectId` required)
- `apply_from_ext_rejects_invalid_json`
- `apply_from_ext_rejects_missing_required_field`
- `destroy_from_ext_rejects_invalid_json`

### 7.2 Unit tests — `src/ext/backend_adapter.rs` (2 new + 1 updated)

2 new:
- `gcp_invalid_config_surfaces_as_backend_execution_failed`
- `gcp_destroy_invalid_config_surfaces_as_backend_execution_failed`

Update existing: swap `unsupported_backend_returns_adapter_not_implemented_apply` from `Gcp` → `Azure`. Same for Destroy variant (already uses Gcp from #4b — update to `Azure`).

### 7.3 Unit tests — `src/ext/errors.rs` (1 updated)

`adapter_not_implemented_displays_backend` — use `Azure` as unsupported; assertions include `Gcp` now supported.

### 7.4 Integration tests — 1 new, ignored

`tests/ext_apply_integration.rs` gains `ext_apply_gcp_target_requires_required_config_fields` with `#[ignore]` scoped for future `deploy-gcp` stub fixture.

### 7.5 Existing integration suite — relied upon

`tests/gcp_cli.rs` (verified to exist) covers built-in `greentic-deployer gcp apply/plan/generate` via fake terraform bin. `apply_from_ext` delegates to same path → existing coverage transitively covers core flow.

### 7.6 Zero-touch checkpoint

Task 3 runs `cargo test --test gcp_cli --features extensions` explicitly before PR — verifies zero regression.

### 7.7 Ref ext repo tests

No crate-level tests; validation via `ci/local_check.sh` + `ci/validate-gtxpack.sh`. Same pattern as deploy-desktop/single-vm/aws.

### 7.8 CLI smoke tests

No new smoke tests — GCP-specific surface goes through JSON config, no new flags. Existing `ext apply --help` coverage is backend-agnostic.

### 7.9 Explicit out-of-scope

- Real GCP deploy in CI
- Cross-cloud tests (AWS + GCP together)
- Performance/load
- Multi-tenant state conflict testing

## 8. Acceptance criteria

Ship paired PRs when all hold:

1. `greentic-deployer ext apply --target gcp-cloud-run-local --creds creds.json --config config.json` dispatches to `gcp::apply_from_ext` (verified via terraform CLI invocation in logs).
2. Invalid JSON → non-zero exit, stderr shows "parse gcp cloud-run config JSON".
3. Missing required field → non-zero exit, stderr surfaces the field name.
4. No pack on disk → non-zero exit, stderr shows "pack 'greentic.deploy.gcp' not found".
5. `ext apply --target <unknown-gcp-variant>` → `TargetNotFound`.
6. Existing `greentic-deployer gcp apply/plan/generate` clap CLI path produces bit-for-bit identical output (`cargo test --test gcp_cli` passes).
7. All existing tests pass (`cargo test` with and without `--features extensions`).
8. `cargo fmt --check` + `cargo clippy -D warnings` green.
9. `cargo build --no-default-features` baseline green.
10. `ci/local_check.sh` all 9 gates pass.
11. Ref ext repo (`deploy-gcp@0.1.0`) CI green — builds, signs, produces .gtxpack.

## 9. Rollout & risk

### 9.1 Risk matrix

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Pack doesn't consume `projectId` from bundle config | Medium | High | Verify during Task 2 via `gcp_cli.rs` test or pack dry-run. If gap exists, document + file pack-repo bug; spec commits only to user-facing contract. |
| `GcpRequest` field shape diverges | Low | Medium | Plan Task 2 verifies field-by-field (confirmed during brainstorming: identical 25 fields as AwsRequest). Compiler catches mismatches. |
| `.gitignore` Cargo.lock trap (from #4c hotfix) | Low | Low | Copy `.gitignore` from `deploy-aws/` after PR #4 fix — contains only `src/bindings.rs`. Commit Cargo.lock. |
| Tokio runtime conflict | Low | Medium | Adapter is sync; block_on safe. Pattern proven by #4b. |
| Signing key rotation mid-stream | Low | Low | Same GH org secret applies. |

### 9.2 Out-of-scope follow-ups

- Azure ref ext (`deploy-azure@0.1.0` for Container Apps) — next iteration of #4d
- GKE + Cloud Functions as additional GCP targets
- Bundle `greentic.deploy.gcp.gtpack` alongside ref ext
- Unignore integration test after `deploy-gcp` stub fixture lands in deployer repo

## 10. References

- Phase B #4a spec: `docs/superpowers/specs/2026-04-19-phase-b-4a-deployer-cli-wiring-design.md` (MERGED)
- Phase B #4b+#4c spec: `docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md` (MERGED)
- Phase B #4b+#4c plan: `docs/superpowers/plans/2026-04-19-phase-b-4b-4c-aws-ecs-fargate.md`
- Memory: `deploy-extension-migration.md`, `deploy-extension-next-steps.md`, `phase-b-4a-cli-wiring.md`, `phase-b-4b-4c-aws-ecs-fargate.md`
- Existing pack fixture: `fixtures/packs/terraform/modules/operator-gcp/`
- Existing GCP integration suite: `tests/gcp_cli.rs`
- Ref ext precedent: `greentic-biz/greentic-deployer-extensions/reference-extensions/deploy-aws@0.1.0` (MERGED 2026-04-19)
