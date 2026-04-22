# Phase B #4d (Azure) — Azure Container Apps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `greentic-deployer ext apply --target azure-container-apps-local` to deploy via Azure Container Apps using existing `greentic.deploy.azure` pack, and ship matching `deploy-azure@0.1.0` reference extension.

**Architecture:** Two-repo delivery mirroring Phase B #4d GCP 1:1 with `Gcp`→`Azure` substitution. `greentic-deployer` adds `azure::apply_from_ext` / `destroy_from_ext`; `backend_adapter` gains Azure match arms. `greentic-deployer-extensions` gets new `deploy-azure/` ref ext crate.

**Tech Stack:** Rust 2024, tokio, serde, wit-bindgen 0.41 (ref ext), cargo-component.

**Spec:** `docs/superpowers/specs/2026-04-19-phase-b-4d-azure-container-apps-design.md`

**Branches:**
- `greentic-deployer`: `spec/phase-b-4d-azure-container-apps` (already checked out)
- `greentic-deployer-extensions`: `feat/deploy-azure-0.1.0` (will create Task 9)

**Delivery:** Phase A (Tasks 1–8) in deployer → one PR. Phase B (Tasks 9–13) in deployer-extensions → one PR. Merge order: Phase A first.

---

## Phase A — `greentic-deployer` Tasks

## Task 1: Add `AzureContainerAppsExtConfig` struct

**Files:** Modify `src/azure.rs`

- [ ] **Step 1.1: Write failing tests**

Append to existing `#[cfg(test)] mod tests { ... }` in `src/azure.rs`:

```rust
    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{
            "location": "eastus",
            "keyVaultUri": "https://my-vault.vault.azure.net/",
            "keyVaultId": "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "azurerm://storage/container/key"
        }"#;
        let cfg: AzureContainerAppsExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.location, "eastus");
        assert_eq!(cfg.key_vault_uri, "https://my-vault.vault.azure.net/");
        assert_eq!(cfg.tenant, "default");
        assert!(cfg.dns_name.is_none());
    }

    #[test]
    fn ext_config_accepts_all_optionals() {
        let json = r#"{
            "location": "eastus",
            "keyVaultUri": "https://my-vault.vault.azure.net/",
            "keyVaultId": "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault",
            "environment": "prod",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "azurerm://...",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: AzureContainerAppsExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_name.as_deref(), Some("api.example.com"));
        assert_eq!(cfg.tenant, "acme");
    }

    #[test]
    fn ext_config_rejects_missing_location() {
        let json = r#"{
            "keyVaultUri": "https://my-vault.vault.azure.net/",
            "keyVaultId": "/subscriptions/aaa/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/my-vault",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "azurerm://..."
        }"#;
        let err = serde_json::from_str::<AzureContainerAppsExtConfig>(json).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("location"), "got: {msg}");
    }
```

- [ ] **Step 1.2: Verify compile fails**

```bash
cd /home/bimbim/works/greentic/greentic-deployer
cargo test --features extensions --lib azure::tests::ext_config 2>&1 | tail -10
```

Expected: compile error — `AzureContainerAppsExtConfig` not found.

- [ ] **Step 1.3: Add struct + helper**

In `src/azure.rs`, find `pub fn resolve_config` (around line 104). Immediately BEFORE it, add:

```rust
/// Configuration shape consumed by `ext apply --target azure-container-apps-local`.
///
/// Mirrors the JSON schema declared by the `deploy-azure` reference extension.
/// Keys use camelCase on the wire; Rust field names use snake_case with serde rename.
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

fn default_ext_tenant() -> String {
    "default".to_string()
}
```

- [ ] **Step 1.4: Run tests**

```bash
cargo test --features extensions --lib azure::tests::ext_config 2>&1 | tail -15
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: 3 tests pass. Fmt clean (run `cargo fmt --all` if not).

- [ ] **Step 1.5: Commit**

```bash
git add src/azure.rs
git commit -m "feat(azure): add AzureContainerAppsExtConfig for ext apply JSON input

New Deserialize struct mirrors the deploy-azure reference extension's
config schema. camelCase on the wire, snake_case internally. Required
fields: location, keyVaultUri, keyVaultId, environment, operatorImageDigest,
bundleSource, bundleDigest, remoteStateBackend. Optional: dns/URL/registry
bases, admin clients, tenant (defaults to 'default')."
```

---

## Task 2: Add `build_azure_request_from_ext` + `apply_from_ext` + `destroy_from_ext`

**Files:** Modify `src/azure.rs`

- [ ] **Step 2.1: Write failing tests**

Append to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_missing_required_field() {
        let json = r#"{"location":"eastus"}"#;
        let err = apply_from_ext(json, "{}", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field")
                || msg.contains("keyVaultUri")
                || msg.contains("key_vault_uri"),
            "got: {msg}"
        );
    }

    #[test]
    fn destroy_from_ext_rejects_invalid_json() {
        let err = destroy_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }
```

**Note:** `{err:#}` alternate display shows full anyhow chain. Precedent: `src/gcp.rs` + `src/aws.rs`.

- [ ] **Step 2.2: Verify compile fails**

```bash
cargo test --features extensions --lib azure::tests::apply_from_ext 2>&1 | tail -15
cargo test --features extensions --lib azure::tests::destroy_from_ext 2>&1 | tail -15
```

Expected: `apply_from_ext` / `destroy_from_ext` not found.

- [ ] **Step 2.3: Add helper + entry points**

In `src/azure.rs`, find `pub fn ensure_azure_config` (around line 108-117). Immediately AFTER its closing `}`, BEFORE `pub async fn run`, add:

```rust
/// Build an `AzureRequest` from the extension-provided config.
fn build_azure_request_from_ext(
    capability: DeployerCapability,
    cfg: &AzureContainerAppsExtConfig,
    pack_path: Option<&std::path::Path>,
) -> AzureRequest {
    AzureRequest {
        capability,
        tenant: cfg.tenant.clone(),
        pack_path: pack_path.map(std::path::Path::to_path_buf).unwrap_or_default(),
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
        providers_dir: std::path::PathBuf::from("providers/deployer"),
        packs_dir: std::path::PathBuf::from("packs"),
    }
}

/// Extension-driven apply entry point: parse JSON config, build request,
/// delegate to existing `resolve_config` + `apply::run` pipeline.
///
/// `_creds_json` is reserved for future secret URI resolution (Phase B #2);
/// today, Azure credentials come from the ambient Azure auth chain
/// (`az login`, `AZURE_*` env vars, or managed identity).
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AzureContainerAppsExtConfig =
        serde_json::from_str(config_json).context("parse azure container-apps config JSON")?;
    let request = build_azure_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve Azure deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for Azure deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run Azure deployment pipeline")?;
    Ok(())
}

/// Extension-driven destroy entry point.
pub fn destroy_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AzureContainerAppsExtConfig =
        serde_json::from_str(config_json).context("parse azure container-apps config JSON")?;
    let request = build_azure_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve Azure deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for Azure destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run Azure destroy pipeline")?;
    Ok(())
}
```

**Note:** `DeployerCapability` imported at `src/azure.rs:4` (`use crate::contract::DeployerCapability;`) — no new import needed. `AzureRequest` at lines 11-36.

- [ ] **Step 2.4: Run tests**

```bash
cargo test --features extensions --lib azure::tests::apply_from_ext 2>&1 | tail -15
cargo test --features extensions --lib azure::tests::destroy_from_ext 2>&1 | tail -15
cargo build --features extensions 2>&1 | tail -5
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: 3 tests pass. Build + fmt clean.

- [ ] **Step 2.5: Commit**

```bash
git add src/azure.rs
git commit -m "feat(azure): add apply_from_ext / destroy_from_ext entry points

Extension-driven dispatch: parse JSON config, build AzureRequest, call
existing resolve_config + apply::run. Async isolated via internal
tokio::runtime::Runtime::new().block_on() — adapter layer stays sync.

_creds_json reserved for future secret URI resolution (Phase B #2);
Azure credentials resolved via ambient Azure auth chain (az login /
AZURE_* env vars / managed identity)."
```

---

## Task 3: Verify `tests/azure_cli.rs` integration still green

**Files:** none (checkpoint)

- [ ] **Step 3.1:**

```bash
cargo test --test azure_cli --features extensions 2>&1 | tail -15
cargo test --features extensions --lib 2>&1 | tail -5
cargo build --no-default-features 2>&1 | tail -3
```

Expected: all `azure_cli.rs` tests pass (file exists, 123 lines). Lib tests all pass. Baseline clean.

**No commit.**

---

## Task 4: Add Azure match arms to `backend_adapter`

**Files:** Modify `src/ext/backend_adapter.rs`

- [ ] **Step 4.1: Write failing tests + update existing**

In `src/ext/backend_adapter.rs`, inside `#[cfg(test)] mod tests { ... }`, ADD:

```rust
    #[test]
    fn azure_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Azure,
            None,
            ExtAction::Apply,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Azure,
                ..
            }
        ));
    }

    #[test]
    fn azure_destroy_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Azure,
            None,
            ExtAction::Destroy,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Azure,
                ..
            }
        ));
    }
```

**Update 2 existing tests** — `unsupported_backend_returns_adapter_not_implemented_apply` and `unsupported_backend_returns_adapter_not_implemented_destroy` both use `BuiltinBackendId::Azure`. Swap to `BuiltinBackendId::Terraform` in BOTH call and assertion. Example for apply variant (replicate for destroy):

```rust
    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Terraform,
            None,
            ExtAction::Apply,
            "{}",
            "{}",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::AdapterNotImplemented {
                backend: BuiltinBackendId::Terraform
            }
        ));
    }
```

Same swap (Azure → Terraform) for `unsupported_backend_returns_adapter_not_implemented_destroy`.

- [ ] **Step 4.2: Run tests (expect 2 new fail, 2 updated pass)**

```bash
cargo test --features extensions --lib ext::backend_adapter 2>&1 | tail -20
```

Expected: 2 new Azure tests FAIL (no arms). 2 updated "unsupported" tests PASS.

- [ ] **Step 4.3: Add Azure match arms**

In `src/ext/backend_adapter.rs`, in `match (backend, action) { ... }`, add AFTER existing `(Gcp, ...)` arms and BEFORE `_ =>`:

```rust
        (BuiltinBackendId::Azure, ExtAction::Apply) => {
            crate::azure::apply_from_ext(config_json, creds_json, pack_path).map_err(|e| {
                ExtensionError::BackendExecutionFailed {
                    backend,
                    source: e,
                }
            })
        }
        (BuiltinBackendId::Azure, ExtAction::Destroy) => {
            crate::azure::destroy_from_ext(config_json, creds_json, pack_path).map_err(|e| {
                ExtensionError::BackendExecutionFailed {
                    backend,
                    source: e,
                }
            })
        }
```

- [ ] **Step 4.4: Run tests (expect all pass)**

```bash
cargo test --features extensions --lib ext::backend_adapter 2>&1 | tail -20
cargo fmt --all -- --check 2>&1 | tail -5
```

- [ ] **Step 4.5: Commit**

```bash
git add src/ext/backend_adapter.rs
git commit -m "feat(ext): wire Azure backend into backend_adapter

Adds match arms for (Azure, Apply) and (Azure, Destroy) delegating to
azure::apply_from_ext / destroy_from_ext. Errors wrapped in
BackendExecutionFailed with source chain preserved.

Existing 'unsupported backend' tests updated to use Terraform
(all 3 cloud backends now supported — Aws, Gcp, Azure)."
```

---

## Task 5: Update `AdapterNotImplemented` message

**Files:** Modify `src/ext/errors.rs`

- [ ] **Step 5.1: Update message**

Find `AdapterNotImplemented` in `src/ext/errors.rs`. Current:

```rust
    #[error(
        "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws, Gcp)"
    )]
```

Replace with:

```rust
    #[error(
        "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws, Gcp, Azure)"
    )]
```

- [ ] **Step 5.2: Update test**

Find `adapter_not_implemented_displays_backend`. Currently uses `BuiltinBackendId::Azure`. Swap to `Terraform`:

```rust
    #[test]
    fn adapter_not_implemented_displays_backend() {
        let err = ExtensionError::AdapterNotImplemented {
            backend: BuiltinBackendId::Terraform,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Terraform"), "got: {msg}");
        assert!(msg.contains("Desktop"), "got: {msg}");
        assert!(msg.contains("SingleVm"), "got: {msg}");
        assert!(msg.contains("Aws"), "got: {msg}");
        assert!(msg.contains("Gcp"), "got: {msg}");
        assert!(msg.contains("Azure"), "got: {msg}");
    }
```

- [ ] **Step 5.3: Run tests**

```bash
cargo test --features extensions --lib ext::errors 2>&1 | tail -15
cargo fmt --all -- --check 2>&1 | tail -5
```

- [ ] **Step 5.4: Commit**

```bash
git add src/ext/errors.rs
git commit -m "chore(ext): update AdapterNotImplemented message for Azure wiring

Now lists Desktop, SingleVm, Aws, Gcp, Azure as supported backends.
Test updated to use Terraform as example unsupported backend."
```

---

## Task 6: Add ignored integration test

**Files:** Modify `tests/ext_apply_integration.rs`

- [ ] **Step 6.1: Append test**

```rust
#[test]
#[ignore = "unignore when deploy-azure fixture lands in testdata/ext/ (Phase B #4d Azure follow-up)"]
fn ext_apply_azure_target_requires_required_config_fields() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", r#"{"location":"eastus"}"#);
    let args = ExtApplyArgs {
        target: "azure-container-apps-local".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    assert!(
        matches!(
            err,
            ExtensionError::ValidationFailed { .. } | ExtensionError::TargetNotFound(_)
        ),
        "got: {err:?}"
    );
}
```

- [ ] **Step 6.2: Verify ignored**

```bash
cargo test --features extensions,test-utils --test ext_apply_integration 2>&1 | tail -10
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: `X passed; 0 failed; 3 ignored` (AWS + GCP + Azure placeholders).

- [ ] **Step 6.3: Commit**

```bash
git add tests/ext_apply_integration.rs
git commit -m "test(ext): add ignored integration test for azure-container-apps-local

Placeholder scoped for when deploy-azure stub fixture lands in
testdata/ext/ after Phase B #4d Azure publishes deploy-azure@0.1.0."
```

---

## Task 7: Full local CI

**Files:** none

- [ ] **Step 7.1: Run full CI**

```bash
./ci/local_check.sh 2>&1 | tail -20
```

Expected: all 9 gates pass. If fmt/clippy fails, fix + commit separately.

- [ ] **Step 7.2: Confirm zero-regression**

```bash
cargo test --test azure_cli --features extensions 2>&1 | tail -10
```

All existing Azure integration tests pass.

---

## Task 8: Push Phase A + open deployer PR

- [ ] **Step 8.1: Check branch state**

```bash
git log --oneline main..HEAD
```

Expected: 7 commits (spec + 6 feature commits).

- [ ] **Step 8.2: Push**

```bash
git push -u origin spec/phase-b-4d-azure-container-apps 2>&1 | tail -5
```

- [ ] **Step 8.3: Open PR**

```bash
gh pr create --title "feat(ext): Phase B #4d (Azure) wire Azure Container Apps backend into ext apply/destroy" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4d Azure side per `docs/superpowers/specs/2026-04-19-phase-b-4d-azure-container-apps-design.md`
- Completes 3-cloud story: AWS + GCP + Azure all end-to-end via `ext apply/destroy`
- Wires `ext apply --target azure-container-apps-local` and `ext destroy --target azure-container-apps-local`
- Reuses existing `greentic.deploy.azure` pack (cloud-aware terraform fixture)
- Pair PR in `greentic-biz/greentic-deployer-extensions` will ship `deploy-azure@0.1.0.gtxpack`

## Architecture

- `src/azure.rs`: new `AzureContainerAppsExtConfig` (8 required + 6 optional fields, `keyVaultUri`/`keyVaultId` Azure-specific), `build_azure_request_from_ext`, `apply_from_ext`/`destroy_from_ext`
- Entry points delegate to existing `resolve_config` + `apply::run` — zero touch to existing Azure clap path
- Async isolated via internal tokio runtime
- `src/ext/backend_adapter.rs`: 2 new match arms for `BuiltinBackendId::Azure`
- Azure credentials via ambient auth chain (az login / AZURE_* env vars / managed identity)

## Zero-touch guarantee

Existing `src/azure.rs` pub fns, `src/main.rs::run_azure`, `src/apply.rs`, all other backends, dispatch table, terraform fixtures receive zero line changes. Task 3 checkpoint: `cargo test --test azure_cli --features extensions` passes.

## Test plan

- [x] Unit tests: azure (6 new), backend_adapter (2 new + 2 updated), errors (1 updated) — all passing
- [x] Existing integration: `tests/azure_cli.rs` passes unchanged
- [x] New ignored integration: 1 test scoped for ref ext fixture follow-up
- [x] `ci/local_check.sh` all 9 gates green
- [x] `cargo build --no-default-features` baseline green

## Follow-up PR

`greentic-biz/greentic-deployer-extensions` — `feat/deploy-azure-0.1.0` ships `deploy-azure@0.1.0.gtxpack`. Merge this PR first.

## Spec & plan

- Spec: `docs/superpowers/specs/2026-04-19-phase-b-4d-azure-container-apps-design.md`
- Plan: `docs/superpowers/plans/2026-04-19-phase-b-4d-azure-container-apps.md`
EOF
)" 2>&1 | tail -3
```

- [ ] **Step 8.4: Report PR URL**

---

## Phase B — `greentic-deployer-extensions` Tasks

## Task 9: Scaffold `deploy-azure/` crate

**Files:** 3 files under `reference-extensions/deploy-azure/`

Work from: `/home/bimbim/works/greentic/greentic-deployer-extensions`

- [ ] **Step 9.1: Sync + branch**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git fetch origin
git checkout main
git pull --ff-only origin main
git checkout -b feat/deploy-azure-0.1.0
```

- [ ] **Step 9.2: Create dirs**

```bash
mkdir -p reference-extensions/deploy-azure/src
mkdir -p reference-extensions/deploy-azure/schemas
mkdir -p reference-extensions/deploy-azure/wit
```

- [ ] **Step 9.3: Create Cargo.toml**

```toml
[workspace]

[package]
name = "greentic-deploy-azure-extension"
version = "0.1.0"
edition = "2024"
license = "MIT"
publish = false
description = "Greentic deploy extension for Azure Container Apps targets"

[lib]
crate-type = ["cdylib", "rlib"]
path = "src/lib.rs"

[dependencies]
wit-bindgen = "0.41"
wit-bindgen-rt = "0.41"

[package.metadata.component]
package = "greentic:deploy-azure-extension"

[package.metadata.component.target]
path = "wit"
world = "deploy-extension"

[package.metadata.component.target.dependencies]
"greentic:extension-base"   = { path = "../../wit/extension-base.wit" }
"greentic:extension-host"   = { path = "../../wit/extension-host.wit" }
"greentic:extension-deploy" = { path = "../../wit/extension-deploy.wit" }
```

- [ ] **Step 9.4: Copy rust-toolchain.toml**

```bash
cp reference-extensions/deploy-gcp/rust-toolchain.toml reference-extensions/deploy-azure/rust-toolchain.toml
```

- [ ] **Step 9.5: Create .gitignore**

**CRITICAL:** ONLY `src/bindings.rs`. Do NOT add Cargo.lock or /wit.

Content for `reference-extensions/deploy-azure/.gitignore`:

```
# Auto-generated by wit-bindgen at build time; not source-controlled
src/bindings.rs
```

- [ ] **Step 9.6: Commit**

```bash
git add reference-extensions/deploy-azure/Cargo.toml \
        reference-extensions/deploy-azure/rust-toolchain.toml \
        reference-extensions/deploy-azure/.gitignore
git commit -m "feat(deploy-azure): scaffold reference extension crate

Mirror deploy-gcp structure: empty workspace, cdylib+rlib lib,
wit-bindgen 0.41. .gitignore only excludes src/bindings.rs
(Cargo.lock committed for --locked CI builds)."
```

---

## Task 10: Add wit/world.wit + describe.json + schemas

- [ ] **Step 10.1: Create `reference-extensions/deploy-azure/wit/world.wit`**

```
package greentic:deploy-azure-extension;

world deploy-extension {
  import greentic:extension-base/types@0.1.0;
  import greentic:extension-host/logging@0.1.0;
  import greentic:extension-host/i18n@0.1.0;
  import greentic:extension-host/secrets@0.1.0;
  import greentic:extension-host/http@0.1.0;

  export greentic:extension-base/manifest@0.1.0;
  export greentic:extension-base/lifecycle@0.1.0;
  export greentic:extension-deploy/targets@0.1.0;
  export greentic:extension-deploy/deployment@0.1.0;
}
```

- [ ] **Step 10.2: Create `describe.json`**

```json
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": {
    "id": "greentic.deploy-azure",
    "name": "Azure Deploy",
    "version": "0.1.0",
    "summary": "Azure Container Apps deployment via Terraform",
    "author": {
      "name": "Greentic",
      "email": "team@greentic.ai"
    },
    "license": "MIT"
  },
  "engine": {
    "greenticDesigner": "*",
    "extRuntime": "^0.1.0"
  },
  "capabilities": {
    "offered": [
      {
        "id": "greentic:deploy/azure-container-apps",
        "version": "0.1.0"
      }
    ],
    "required": []
  },
  "runtime": {
    "component": "extension.wasm",
    "memoryLimitMB": 32,
    "permissions": {
      "network": [],
      "secrets": [],
      "callExtensionKinds": []
    }
  },
  "contributions": {
    "targets": [
      {
        "id": "azure-container-apps-local",
        "displayName": "Azure Container Apps (local Terraform)",
        "description": "Deploy to Azure Container Apps via Terraform using ambient Azure credentials",
        "execution": {
          "backend": "azure",
          "handler": null,
          "kind": "builtin"
        },
        "supportsRollback": true
      }
    ]
  }
}
```

- [ ] **Step 10.3: Create credentials schema**

`reference-extensions/deploy-azure/schemas/azure-container-apps.credentials.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Azure Container Apps credentials",
  "description": "Empty object. Azure credentials resolved via ambient Azure auth chain (az login, AZURE_* env vars, or managed identity).",
  "type": "object",
  "properties": {},
  "additionalProperties": false
}
```

- [ ] **Step 10.4: Create config schema**

`reference-extensions/deploy-azure/schemas/azure-container-apps.config.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Azure Container Apps deployment config",
  "type": "object",
  "required": [
    "location",
    "keyVaultUri",
    "keyVaultId",
    "environment",
    "operatorImageDigest",
    "bundleSource",
    "bundleDigest",
    "remoteStateBackend"
  ],
  "properties": {
    "location": {
      "type": "string",
      "minLength": 1,
      "description": "Azure region (e.g., eastus, westeurope)"
    },
    "keyVaultUri": {
      "type": "string",
      "minLength": 1,
      "description": "Azure Key Vault URI for admin cert secret materialization (e.g., https://my-vault.vault.azure.net/)"
    },
    "keyVaultId": {
      "type": "string",
      "minLength": 1,
      "description": "Azure Key Vault full resource ID (/subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/my-vault)"
    },
    "environment": {
      "type": "string",
      "minLength": 1
    },
    "operatorImageDigest": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$"
    },
    "bundleSource": {
      "type": "string",
      "minLength": 1
    },
    "bundleDigest": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$"
    },
    "remoteStateBackend": {
      "type": "string",
      "minLength": 1,
      "description": "Terraform remote state backend URI (e.g., azurerm://storage-account/container/key)"
    },
    "dnsName": { "type": "string" },
    "publicBaseUrl": { "type": "string" },
    "repoRegistryBase": { "type": "string" },
    "storeRegistryBase": { "type": "string" },
    "adminAllowedClients": { "type": "string" },
    "tenant": { "type": "string" }
  },
  "additionalProperties": false
}
```

- [ ] **Step 10.5: Validate JSON**

```bash
cd reference-extensions/deploy-azure
jq empty describe.json schemas/*.schema.json
```

- [ ] **Step 10.6: Commit**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git add reference-extensions/deploy-azure/wit/ \
        reference-extensions/deploy-azure/describe.json \
        reference-extensions/deploy-azure/schemas/
git commit -m "feat(deploy-azure): add wit/world.wit + describe.json + schemas

Single target 'azure-container-apps-local' with backend=azure, handler=null.

Config schema mirrors AzureContainerAppsExtConfig in greentic-deployer
(8 required: location, keyVaultUri, keyVaultId, environment,
operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend).
Creds schema empty — Azure credentials via ambient auth chain."
```

---

## Task 11: WASM Guest impl `src/lib.rs`

- [ ] **Step 11.1: Write `reference-extensions/deploy-azure/src/lib.rs`**

```rust
//! greentic.deploy-azure — reference deploy extension for Azure Container Apps.
//!
//! Mode A only: metadata + schemas served here; deployer host routes actual
//! deploy/poll/rollback to its built-in `azure` backend.

#[allow(warnings)]
mod bindings;

use bindings::exports::greentic::extension_base::{lifecycle, manifest};
use bindings::exports::greentic::extension_deploy::{deployment, targets};
use bindings::greentic::extension_base::types;

const CREDS_SCHEMA: &str = include_str!("../schemas/azure-container-apps.credentials.schema.json");
const CONFIG_SCHEMA: &str = include_str!("../schemas/azure-container-apps.config.schema.json");

const TARGET_AZURE_CONTAINER_APPS: &str = "azure-container-apps-local";

struct Component;

impl manifest::Guest for Component {
    fn get_identity() -> types::ExtensionIdentity {
        types::ExtensionIdentity {
            id: "greentic.deploy-azure".into(),
            version: "0.1.0".into(),
            kind: types::Kind::Deploy,
        }
    }

    fn get_offered() -> Vec<types::CapabilityRef> {
        vec![types::CapabilityRef {
            id: "greentic:deploy/azure-container-apps".into(),
            version: "0.1.0".into(),
        }]
    }

    fn get_required() -> Vec<types::CapabilityRef> {
        vec![]
    }
}

impl lifecycle::Guest for Component {
    fn init(_config_json: String) -> Result<(), types::ExtensionError> {
        Ok(())
    }

    fn shutdown() {}
}

impl targets::Guest for Component {
    fn list_targets() -> Vec<targets::TargetSummary> {
        vec![targets::TargetSummary {
            id: TARGET_AZURE_CONTAINER_APPS.into(),
            display_name: "Azure Container Apps (local Terraform)".into(),
            description: "Deploy to Azure Container Apps via Terraform using ambient Azure credentials".into(),
            icon_path: None,
            supports_rollback: true,
        }]
    }

    fn credential_schema(target_id: String) -> Result<String, types::ExtensionError> {
        match target_id.as_str() {
            TARGET_AZURE_CONTAINER_APPS => Ok(CREDS_SCHEMA.into()),
            other => Err(types::ExtensionError::InvalidInput(format!(
                "unknown target: {other}"
            ))),
        }
    }

    fn config_schema(target_id: String) -> Result<String, types::ExtensionError> {
        match target_id.as_str() {
            TARGET_AZURE_CONTAINER_APPS => Ok(CONFIG_SCHEMA.into()),
            other => Err(types::ExtensionError::InvalidInput(format!(
                "unknown target: {other}"
            ))),
        }
    }

    fn validate_credentials(
        target_id: String,
        _credentials_json: String,
    ) -> Vec<types::Diagnostic> {
        match target_id.as_str() {
            TARGET_AZURE_CONTAINER_APPS => vec![],
            other => vec![types::Diagnostic {
                severity: types::Severity::Error,
                code: "unknown-target".into(),
                message: format!("unknown target: {other}"),
                path: None,
            }],
        }
    }
}

impl deployment::Guest for Component {
    fn deploy(
        _req: deployment::DeployRequest,
    ) -> Result<deployment::DeployJob, types::ExtensionError> {
        Err(types::ExtensionError::Internal(
            "deploy-azure uses Mode A builtin execution; dispatcher should route via \
             backend=azure, not WASM"
                .into(),
        ))
    }

    fn poll(_job_id: String) -> Result<deployment::DeployJob, types::ExtensionError> {
        Err(types::ExtensionError::Internal(
            "poll not implemented in Mode A".into(),
        ))
    }

    fn rollback(_job_id: String) -> Result<(), types::ExtensionError> {
        Err(types::ExtensionError::Internal(
            "rollback not implemented in Mode A".into(),
        ))
    }
}

bindings::export!(Component with_types_in bindings);
```

- [ ] **Step 11.2: Commit**

```bash
git add reference-extensions/deploy-azure/src/lib.rs
git commit -m "feat(deploy-azure): add WASM Guest impl for Azure Container Apps target

Mode A only: metadata + schemas exposed; deploy/poll/rollback return
Internal error pointing at host routing via backend=azure. Mirrors
deploy-gcp pattern, single target."
```

---

## Task 12: build.sh + local build + Cargo.lock

- [ ] **Step 12.1: Copy build.sh from deploy-gcp**

```bash
cp reference-extensions/deploy-gcp/build.sh reference-extensions/deploy-azure/build.sh
```

- [ ] **Step 12.2: Substitute gcp → azure**

Edit `reference-extensions/deploy-azure/build.sh`. Replace:
- `greentic.deploy-gcp` → `greentic.deploy-azure`
- `greentic_deploy_gcp_extension` → `greentic_deploy_azure_extension`
- Any "gcp" references in comments referring to the current extension → "azure"

Verify:

```bash
cat reference-extensions/deploy-azure/build.sh | head -30
grep -n "gcp\|deploy-gcp" reference-extensions/deploy-azure/build.sh
```

Expected: no gcp/deploy-gcp references remaining.

- [ ] **Step 12.3: Make executable + run**

```bash
chmod +x reference-extensions/deploy-azure/build.sh
cd reference-extensions/deploy-azure
./build.sh 2>&1 | tail -30
```

Expected: produces `greentic.deploy-azure-0.1.0.gtxpack`. Generates `Cargo.lock`.

- [ ] **Step 12.4: Verify .gtxpack contents**

```bash
unzip -l reference-extensions/deploy-azure/greentic.deploy-azure-0.1.0.gtxpack | head -10
```

- [ ] **Step 12.5: Commit build.sh + Cargo.lock together**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
ls reference-extensions/deploy-azure/Cargo.lock  # must exist
cat reference-extensions/deploy-azure/.gitignore  # must ONLY contain src/bindings.rs
git add reference-extensions/deploy-azure/build.sh reference-extensions/deploy-azure/Cargo.lock
git commit -m "feat(deploy-azure): add build.sh + commit Cargo.lock

Mirrors deploy-gcp build.sh: validate schemas, cargo component build,
wasm-tools validate, env-aware signing (GREENTIC_EXT_SIGNING_KEY_PEM
from CI secret), zip to .gtxpack. Cargo.lock committed so CI --locked
builds work (lesson from deploy-aws PR #4 hotfix)."
```

- [ ] **Step 12.6: Verify .gtxpack not tracked**

```bash
git ls-files reference-extensions/deploy-azure/ | grep -i gtxpack
```

Expected: no output.

---

## Task 13: Extend ci/local_check.sh + push + open ref ext PR

- [ ] **Step 13.1: Extend ci/local_check.sh**

Read current content. Find existing deploy-gcp block near end:

```bash
echo "==> build deploy-gcp"
(cd reference-extensions/deploy-gcp && bash build.sh)

echo "==> validate deploy-gcp .gtxpack"
bash ci/validate-gtxpack.sh \
    reference-extensions/deploy-gcp/greentic.deploy-gcp-0.1.0.gtxpack
```

Add AFTER the deploy-gcp validate block, BEFORE "Local check completed successfully":

```bash
echo "==> build deploy-azure"
(cd reference-extensions/deploy-azure && bash build.sh)

echo "==> validate deploy-azure .gtxpack"
bash ci/validate-gtxpack.sh \
    reference-extensions/deploy-azure/greentic.deploy-azure-0.1.0.gtxpack
```

- [ ] **Step 13.2: Run local_check.sh**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
bash ci/local_check.sh 2>&1 | tail -30
```

Expected: all 5 extensions (desktop, single-vm, aws, gcp, azure) build + validate.

- [ ] **Step 13.3: Commit**

```bash
git add ci/local_check.sh
git commit -m "ci(deploy-azure): extend local_check.sh to build+validate deploy-azure

Completes 5-extension matrix (desktop, single-vm, aws, gcp, azure).
CI_REQUIRE_SIGNED guardrail applies on main push."
```

- [ ] **Step 13.4: Push**

```bash
git log --oneline main..HEAD  # expect 5 commits
git push -u origin feat/deploy-azure-0.1.0 2>&1 | tail -5
```

- [ ] **Step 13.5: Open PR**

```bash
gh pr create --title "feat(deploy-azure): ship deploy-azure@0.1.0 reference extension" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4d Azure deployer-extensions side per \`greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4d-azure-container-apps-design.md\`
- Completes 3-cloud story — AWS + GCP + Azure all end-to-end via ext apply/destroy
- New reference extension \`deploy-azure@0.1.0.gtxpack\` with single target \`azure-container-apps-local\`
- Backend \`azure\`, handler \`null\`, execution kind \`builtin\` (Mode A)

## Architecture

- \`reference-extensions/deploy-azure/\` — new crate mirroring \`deploy-gcp@0.1.0\` structure
- Single target: \`azure-container-apps-local\`
- Config schema: 8 required fields (\`location, keyVaultUri, keyVaultId, environment, operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend\`) + 6 optional
- Credentials schema: empty object — Azure creds via ambient auth (\`az login\` / \`AZURE_*\` env vars / managed identity)

## Test plan

- [x] schemas validate as JSON
- [x] cargo component build succeeds
- [x] wasm-tools validate passes
- [x] .gtxpack produced (~36K, 4 files)
- [x] ci/local_check.sh extended to 5 extensions
- [x] Cargo.lock committed (lesson from deploy-aws PR #4)

## Merge order

1. Merge deployer Phase B #4d Azure PR first
2. Merge this PR second

## Spec & plan

- Spec: \`greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4d-azure-container-apps-design.md\`
- Plan: \`greentic-deployer/docs/superpowers/plans/2026-04-19-phase-b-4d-azure-container-apps.md\`
EOF
)" 2>&1 | tail -3
```

- [ ] **Step 13.6: Report PR URL**

---

## Self-Review Checklist

**Spec coverage:**
- §2 design decisions (target id, required fields) → Tasks 1, 10 ✓
- §3 architecture → Tasks 2, 4 ✓
- §4.1 azure.rs additions → Tasks 1, 2 ✓
- §4.1 backend_adapter → Task 4 ✓
- §4.1 errors.rs → Task 5 ✓
- §4.1 ignored test → Task 6 ✓
- §4.2 ref ext crate → Tasks 9, 10, 11 ✓
- §4.2 ci/local_check.sh → Task 13 ✓
- §5 data flow → Tasks 2, 4 ✓
- §6 error handling → Tasks 2, 4, 5 ✓
- §7 testing → all covered ✓
- §8 acceptance criteria → verified via Tasks 3, 7, 8, 13 ✓
- §9.1 risk (.gitignore Cargo.lock) → Task 9 Step 9.5 warning + Task 12 Step 12.5 ✓

**Placeholder scan:** no TBD/TODO/"fill in later" ✓

**Type consistency:**
- `AzureContainerAppsExtConfig` field names consistent across Tasks 1, 2, 10, 11 ✓
- `apply_from_ext`/`destroy_from_ext` signatures consistent ✓
- `TARGET_AZURE_CONTAINER_APPS` const consistent ✓
- `BuiltinBackendId::Azure` / `::Terraform` usage consistent ✓

**Plan complete.**
