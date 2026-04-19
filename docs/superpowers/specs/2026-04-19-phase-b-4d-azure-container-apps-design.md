# Phase B #4d (Azure) — Azure Container Apps Deploy Extension

- **Date:** 2026-04-19
- **Status:** Draft, pending user review
- **Branch:** `spec/phase-b-4d-azure-container-apps`
- **Related:**
  - Parent: `memory/deploy-extension-next-steps.md` (Phase B #4d — Azure track)
  - Phase B #4a (MERGED): deployer CLI wiring
  - Phase B #4b+#4c (MERGED): AWS ECS Fargate
  - Phase B #4d GCP (MERGED 2026-04-19): GCP Cloud Run
  - Reused pack fixture: `greentic-deployer/fixtures/packs/terraform/` (`greentic.deploy.azure` — cloud-aware, same pack serves aws/gcp/azure)
  - Ref exts repo: `greentic-biz/greentic-deployer-extensions` — ships `deploy-desktop@0.2.0`, `deploy-single-vm@0.1.0`, `deploy-aws@0.1.0`, `deploy-gcp@0.1.0`, will ship `deploy-azure@0.1.0`

## 1. Context & motivation

### Current state after Phase B #4d GCP (merged 2026-04-19)

`ext apply --target X` routes to Desktop, SingleVm, Aws, and Gcp backends. Azure/Terraform/K8sRaw/etc. return `AdapterNotImplemented`. This phase completes the 3-cloud story by wiring Azure Container Apps.

### Goal

Make `greentic-deployer ext apply --target azure-container-apps-local ...` deploy to Azure Container Apps via the existing `greentic.deploy.azure` pack (wraps `fixtures/packs/terraform/modules/operator-azure/`). Ship `deploy-azure@0.1.0.gtxpack` ref ext. Complete cross-cloud consistency — AWS + GCP + Azure all end-to-end.

Two paired PRs (same strategy as #4b/#4c and #4d GCP):
- **Phase A** — `greentic-deployer`: Azure match arms + `azure::apply_from_ext` / `destroy_from_ext`.
- **Phase B** — `greentic-biz/greentic-deployer-extensions`: new `deploy-azure/` ref ext crate.

### Hard non-negotiable constraint

**Existing `greentic-deployer` cloud paths remain untouched.** No changes to:
- `src/azure.rs` existing pub fns (`resolve_config`, `ensure_azure_config`, `run`, `run_config`, `run_with_plan`, `run_config_with_plan`)
- `src/main.rs` clap `run_azure` path
- `src/apply.rs`, other cloud backends
- `src/deployment.rs` dispatch table (`greentic.deploy.azure` already mapped)
- `fixtures/packs/terraform/` reused as-is

### Non-goals

- No Mode B (Phase B #2)
- No host interfaces
- No secret URI resolution — credentials via ambient Azure auth chain (`az login`, `AZURE_*` env vars, managed identity)
- No new pack authoring — reuse existing `greentic.deploy.azure` pack
- No AKS / Azure Functions targets — single target `azure-container-apps-local`
- No preview/dry-run via ext path

## 2. Design decisions

Pattern decisions carry over from #4b+#4c+#4d GCP verbatim. Azure-specific:

| Q | Decision | Reason |
|---|---|---|
| Target identifier | `azure-container-apps-local` | Symmetric with `aws-ecs-fargate-local` / `gcp-cloud-run-local` |
| Required config fields | 8 fields: `location, keyVaultUri, keyVaultId, environment, operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend` | Terraform module declares key vault vars without defaults — fail at Rust layer with clear missing-field error, not cryptic tf error later |
| Subscription/resourceGroup | NOT in config | Azure provider derives from ambient `az login` / `AZURE_SUBSCRIPTION_ID` (symmetric with AWS `region` pattern) |

## 3. Architecture

```
┌─ Existing Phase B #4a+#4b+#4d GCP (UNCHANGED) ────────────────────────┐
│   ext::cli::run_apply → dispatch_extension → backend_adapter::run    │
│   Desktop/SingleVm/Aws/Gcp arms — all untouched                      │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ src/ext/backend_adapter.rs (EXTENDED) ──────────────────────────────┐
│   match (backend, action) {                                          │
│     ... existing arms (Desktop/SingleVm/Aws/Gcp) UNCHANGED ...       │
│     (Azure, Apply)   => azure::apply_from_ext(...)                   │  ← NEW
│     (Azure, Destroy) => azure::destroy_from_ext(...)                 │  ← NEW
│     _ => AdapterNotImplemented                                       │
│   }                                                                  │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ src/azure.rs (ADDITIVE ONLY) ───────────────────────────────────────┐
│   existing: resolve_config, ensure_azure_config, run, run_config     │
│   NEW: pub struct AzureContainerAppsExtConfig                        │
│   NEW: fn build_azure_request_from_ext                               │
│   NEW: pub fn apply_from_ext (tokio::block_on)                       │
│   NEW: pub fn destroy_from_ext (tokio::block_on)                     │
└──────────────────────────────────────────────────────────────────────┘
```

## 4. Components & files

### 4.1 `greentic-deployer` (~220 LoC)

**`src/azure.rs`** (+~160 LoC, ADDITIVE):

```rust
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureContainerAppsExtConfig {
    pub location: String,
    pub key_vault_uri: String,
    pub key_vault_id: String,
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

fn default_ext_tenant() -> String { "default".to_string() }
```

Plus `build_azure_request_from_ext`, `apply_from_ext`, `destroy_from_ext` — exact mirror of `src/gcp.rs` pattern with Azure names and context strings ("parse azure container-apps config JSON", "resolve Azure deployer config", "create tokio runtime for Azure deploy/destroy", "run Azure deployment/destroy pipeline").

6 unit tests (see §7.1).

**`src/ext/backend_adapter.rs`** (+~25 LoC): 2 new match arms for `BuiltinBackendId::Azure`, 2 new tests (`azure_invalid_config_surfaces_as_backend_execution_failed`, `azure_destroy_invalid_config_surfaces_as_backend_execution_failed`). **Update 2 existing tests** (`unsupported_backend_returns_adapter_not_implemented_{apply,destroy}`): both currently use `Azure` — swap to `BuiltinBackendId::Terraform` (all 3 clouds now supported; Terraform is a builtin backend, not cloud, and remains unwired for ext path).

**`src/ext/errors.rs`** (~3 LoC): update `AdapterNotImplemented` message to `"supported: Desktop, SingleVm, Aws, Gcp, Azure"`. Update test to use `Terraform` as unsupported example.

**`tests/ext_apply_integration.rs`** (+~30 LoC): 1 ignored placeholder `ext_apply_azure_target_requires_required_config_fields`.

### 4.2 `greentic-deployer-extensions` (new `deploy-azure/` crate, ~350 LoC)

Mirror `deploy-gcp/` exactly. Key differences:

**`describe.json`** target:
```json
{
  "id": "azure-container-apps-local",
  "displayName": "Azure Container Apps (local Terraform)",
  "description": "Deploy to Azure Container Apps via Terraform using ambient Azure credentials",
  "execution": { "backend": "azure", "handler": null, "kind": "builtin" },
  "supportsRollback": true
}
```

Metadata id `greentic.deploy-azure`, version `0.1.0`, capability `greentic:deploy/azure-container-apps@0.1.0`.

**`config.schema.json`** required fields: `location, keyVaultUri, keyVaultId, environment, operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend` (8 required).

**`src/lib.rs`** mirrors deploy-gcp: `TARGET_AZURE_CONTAINER_APPS = "azure-container-apps-local"`, Mode A.

**`wit/world.wit`**: package `greentic:deploy-azure-extension`.

**`Cargo.toml`, `Cargo.lock` (COMMITTED from day 1), `rust-toolchain.toml`, `.gitignore` (ONLY `src/bindings.rs`), `build.sh`** — copied from deploy-gcp with name substitutions.

**`ci/local_check.sh`** +4 LoC.

### 4.3 Delta summary

| Repo | LoC |
|---|---|
| deployer | ~220 |
| deployer-extensions | ~354 |
| **Total** | **~574** |

### 4.4 Unchanged

- `src/azure.rs` existing pub fns
- `src/main.rs::run_azure` and all clap paths
- `src/apply.rs`, `src/aws.rs`, `src/gcp.rs`, all other backends
- `src/deployment.rs` dispatch table
- `fixtures/packs/terraform/` reused
- All existing tests

## 5. Data flow

### 5.1 Happy path

Prerequisites:
1. `az login` (or `AZURE_*` env vars for service principal)
2. `terraform` on PATH
3. `deploy-azure-0.1.0.gtxpack` installed
4. `greentic.deploy.azure.gtpack` on disk

```bash
greentic-deployer ext apply \
  --target azure-container-apps-local \
  --creds creds.json \
  --config config.json \
  --ext-dir ~/.greentic/extensions/deploy
```

`config.json`:
```json
{
  "location": "eastus",
  "keyVaultUri": "https://my-vault.vault.azure.net/",
  "keyVaultId": "/subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/my-vault",
  "environment": "staging",
  "operatorImageDigest": "sha256:...",
  "bundleSource": "oci://...",
  "bundleDigest": "sha256:...",
  "remoteStateBackend": "azurerm://storage-account/container/key"
}
```

### 5.2 Sequence

Identical to #4d GCP §5.2 with Azure substitution:
1. clap → ext::cli → run_apply
2. Read creds/config → scan → registry → WasmtimeInvoker
3. dispatch_extension → `DispatchAction::Builtin(BridgeResolved{backend: Azure, handler: None})`
4. backend_adapter::run(Azure, None, Apply, ...) → azure::apply_from_ext
5. Parse → build_azure_request_from_ext → resolve_config → tokio block_on(apply::run)
6. Exit 0

### 5.3 How keyVault values reach terraform

`AzureRequest` struct doesn't have `key_vault_uri` / `key_vault_id` fields. Values stay in `AzureContainerAppsExtConfig` only. Pack flow responsibility to route through `TF_VAR_azure_key_vault_uri` / `TF_VAR_azure_key_vault_id`. Same pattern as GCP's `projectId`.

**Risk:** if pack flow doesn't currently populate these, terraform will fail. Tracked as out-of-scope pack-repo bug; Rust layer commits only to user-facing contract.

## 6. Error handling

No new variants. All errors flow through `BackendExecutionFailed { backend: Azure, source }`.

Example:
```
Error: backend 'Azure' execution failed: parse azure container-apps config JSON: missing field `keyVaultUri` at line 3 column 3
```

## 7. Testing

### 7.1 Unit tests in `src/azure.rs` (6 new)

- `ext_config_parses_minimum_fields`
- `ext_config_accepts_all_optionals`
- `ext_config_rejects_missing_location`
- `apply_from_ext_rejects_invalid_json`
- `apply_from_ext_rejects_missing_required_field`
- `destroy_from_ext_rejects_invalid_json`

### 7.2 Unit tests in `src/ext/backend_adapter.rs` (2 new + 2 updated)

- NEW: `azure_invalid_config_surfaces_as_backend_execution_failed`
- NEW: `azure_destroy_invalid_config_surfaces_as_backend_execution_failed`
- UPDATE: `unsupported_backend_returns_adapter_not_implemented_{apply,destroy}` — swap `Azure` → `Terraform`

### 7.3 Unit test in `src/ext/errors.rs` (1 updated)

`adapter_not_implemented_displays_backend` — swap `Azure` → `Terraform`; assertions include Azure.

### 7.4 Integration test (1 new, ignored)

`ext_apply_azure_target_requires_required_config_fields` — `#[ignore]` placeholder for future fixture.

### 7.5 Zero-touch checkpoint

Task 3: `cargo test --test azure_cli --features extensions` — `tests/azure_cli.rs` exists (123 lines).

### 7.6 Ref ext repo

`ci/local_check.sh` extended to build+validate deploy-azure.

## 8. Acceptance criteria

1. `ext apply --target azure-container-apps-local ...` dispatches to `azure::apply_from_ext`
2. Invalid JSON → "parse azure container-apps config JSON"
3. Missing required field → surfaces field name
4. No pack → "pack 'greentic.deploy.azure' not found"
5. Existing `azure_cli` clap path unchanged (cargo test --test azure_cli passes)
6. All existing tests pass
7. fmt+clippy green, no-default baseline green, ci/local_check.sh all 9 gates green
8. Ref ext `deploy-azure@0.1.0` CI green — builds, signs, produces .gtxpack

## 9. Risk & rollout

| Risk | Mitigation |
|---|---|
| Pack doesn't consume keyVault fields | Verified during Task 3 via `azure_cli.rs` — separate pack-repo bug if present |
| `AzureRequest` field mismatch | Verified during exploration: 25 fields same as AwsRequest/GcpRequest |
| `.gitignore` Cargo.lock trap | Task 9 explicit warning; mirror deploy-gcp (ONLY `src/bindings.rs`) |

## 10. References

- Phase B #4a-#4d GCP specs in `docs/superpowers/specs/2026-04-19-phase-b-*.md`
- Memory: `phase-b-4a-cli-wiring.md`, `phase-b-4b-4c-aws-ecs-fargate.md`, `phase-b-4d-gcp-cloud-run.md`
- Existing Azure integration: `tests/azure_cli.rs`
- Terraform module: `fixtures/packs/terraform/terraform/modules/operator-azure/`
- Ref ext precedent: `deploy-gcp@0.1.0` (MERGED 2026-04-19)
