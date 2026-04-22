# Phase B #4d — GCP Cloud Run Deploy Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `greentic-deployer ext apply --target gcp-cloud-run-local` to actually deploy via GCP Cloud Run using existing `greentic.deploy.gcp` pack, and ship matching `deploy-gcp@0.1.0` reference extension.

**Architecture:** Two-repo delivery mirroring Phase B #4b+#4c (AWS) pattern 1:1 with `Aws`→`Gcp` substitution. `greentic-deployer` adds `gcp::apply_from_ext` / `destroy_from_ext` entry points; `backend_adapter` gains AWS→GCP match arms. `greentic-deployer-extensions` gets new `deploy-gcp/` ref ext crate.

**Tech Stack:** Rust 2024, tokio (existing dep), serde, thiserror, anyhow, wit-bindgen 0.41 (ref ext), cargo-component (ref ext build).

**Spec:** `docs/superpowers/specs/2026-04-19-phase-b-4d-gcp-cloud-run-design.md`

**Branches:**
- `greentic-deployer`: `spec/phase-b-4d-gcp-cloud-run` (already checked out)
- `greentic-deployer-extensions`: `feat/deploy-gcp-0.1.0` (will create in Phase C)

**Delivery structure:**
- **Phase A** — `greentic-deployer` changes (Tasks 1–8) → one PR
- **Phase B** — `greentic-deployer-extensions` changes (Tasks 9–13) → one PR in sibling repo
- Merge order: Phase A first, Phase B second

---

## File Structure

### Phase A — `greentic-deployer` repo

| Path | New/Modified | Responsibility |
|------|--------------|----------------|
| `src/gcp.rs` | Modified (+~160 LoC) | New: `GcpCloudRunExtConfig` struct, `build_gcp_request_from_ext` helper, `apply_from_ext`, `destroy_from_ext`. Unchanged: existing `resolve_config`, `ensure_gcp_config`, `run`, `run_config`, `run_with_plan`. |
| `src/ext/backend_adapter.rs` | Modified (+~25 LoC) | Add 2 match arms for `BuiltinBackendId::Gcp`. Update 2 existing tests to use `Azure` instead of `Gcp` as "unsupported" example. |
| `src/ext/errors.rs` | Modified (~3 LoC) | Update `AdapterNotImplemented` error message: list Desktop/SingleVm/Aws/Gcp as supported. |
| `tests/ext_apply_integration.rs` | Modified (+~30 LoC) | One new `#[ignore]` integration test scoped for future `deploy-gcp` fixture. |

### Phase B — `greentic-deployer-extensions` repo

| Path | New/Modified | Responsibility |
|------|--------------|----------------|
| `reference-extensions/deploy-gcp/Cargo.toml` | New | Crate metadata, wit-bindgen deps. |
| `reference-extensions/deploy-gcp/Cargo.lock` | New (COMMITTED) | Required for `--locked` builds (lesson from PR #4 hotfix). |
| `reference-extensions/deploy-gcp/rust-toolchain.toml` | New | Pin toolchain (copy from deploy-aws). |
| `reference-extensions/deploy-gcp/.gitignore` | New | ONLY excludes `src/bindings.rs` (not Cargo.lock, not /wit — lesson from PR #4). |
| `reference-extensions/deploy-gcp/src/lib.rs` | New | Minimal WASM Guest impl — schemas + validate_credentials. Mode A only. |
| `reference-extensions/deploy-gcp/wit/world.wit` | New | cargo-component build input. |
| `reference-extensions/deploy-gcp/describe.json` | New | Metadata + target contribution (`gcp-cloud-run-local`, backend=gcp). |
| `reference-extensions/deploy-gcp/schemas/gcp-cloud-run.credentials.schema.json` | New | Empty object (ambient Google ADC). |
| `reference-extensions/deploy-gcp/schemas/gcp-cloud-run.config.schema.json` | New | Mirrors `GcpCloudRunExtConfig`. |
| `reference-extensions/deploy-gcp/build.sh` | New | cargo-component build + wasm-tools validate + env-aware sign + zip. |
| `ci/local_check.sh` | Modified (+4 LoC) | Add deploy-gcp build+validate after deploy-aws. |

### Files explicitly UNCHANGED (verify no regression)

- `src/main.rs` — all clap paths including `run_gcp`
- `src/apply.rs` — `apply::run` entry
- `src/gcp.rs` existing pub fns: `resolve_config`, `ensure_gcp_config`, `run`, `run_config`, `run_with_plan`, `run_config_with_plan`
- `src/aws.rs`, `src/azure.rs`, `src/terraform.rs`, `src/helm.rs`, `src/k8s_raw.rs`, `src/juju_k8s.rs`, `src/juju_machine.rs`, `src/operator.rs`, `src/serverless.rs`, `src/snap.rs`, `src/single_vm.rs`, `src/desktop.rs`
- `src/deployment.rs` — dispatch table stays
- `fixtures/packs/terraform/` — reused as `greentic.deploy.gcp` pack
- `src/ext/dispatcher.rs`, `src/ext/cli.rs`, `src/ext/wasm.rs`, `src/ext/loader.rs`, `src/ext/registry.rs`, `src/ext/builtin_bridge.rs`, `src/ext/describe.rs`, `src/ext/diagnostic.rs`

---

## Phase A — `greentic-deployer` Tasks

## Task 1: Add `GcpCloudRunExtConfig` Deserialize struct

**Files:**
- Modify: `src/gcp.rs`

Work from: `/home/bimbim/works/greentic/greentic-deployer`

- [ ] **Step 1.1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests { ... }` block at the bottom of `src/gcp.rs`:

```rust
    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{
            "projectId": "my-gcp-project-12345",
            "region": "us-central1",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "gs://my-tf-state-bucket/greentic/staging"
        }"#;
        let cfg: GcpCloudRunExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.project_id, "my-gcp-project-12345");
        assert_eq!(cfg.region, "us-central1");
        assert_eq!(cfg.environment, "staging");
        assert_eq!(cfg.tenant, "default");
        assert!(cfg.dns_name.is_none());
        assert!(cfg.public_base_url.is_none());
    }

    #[test]
    fn ext_config_accepts_all_optionals() {
        let json = r#"{
            "projectId": "my-gcp-project-12345",
            "region": "us-central1",
            "environment": "prod",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "gs://my-tf-state-bucket/greentic/prod",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: GcpCloudRunExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_name.as_deref(), Some("api.example.com"));
        assert_eq!(cfg.public_base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(cfg.tenant, "acme");
    }

    #[test]
    fn ext_config_rejects_missing_project_id() {
        let json = r#"{
            "region": "us-central1",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "gs://..."
        }"#;
        let err = serde_json::from_str::<GcpCloudRunExtConfig>(json).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("projectId") || msg.contains("project_id"),
            "got: {msg}"
        );
    }
```

- [ ] **Step 1.2: Run tests to verify they fail**

```bash
cd /home/bimbim/works/greentic/greentic-deployer
cargo test --features extensions --lib gcp::tests::ext_config 2>&1 | tail -20
```

Expected: compile error — `GcpCloudRunExtConfig` not found.

- [ ] **Step 1.3: Add the struct + default_ext_tenant helper**

Edit `src/gcp.rs`. Find `pub fn resolve_config` (around line 104). Immediately BEFORE it, add:

```rust
/// Configuration shape consumed by `ext apply --target gcp-cloud-run-local`.
///
/// Mirrors the JSON schema declared by the `deploy-gcp` reference extension.
/// Keys use camelCase on the wire; Rust field names use snake_case with serde rename.
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

- [ ] **Step 1.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib gcp::tests::ext_config 2>&1 | tail -20
```

Expected: 3 tests pass.

- [ ] **Step 1.5: Commit**

```bash
git add src/gcp.rs
git commit -m "feat(gcp): add GcpCloudRunExtConfig for ext apply JSON input

New Deserialize struct mirrors the deploy-gcp reference extension's
config schema. camelCase on the wire, snake_case internally. Required
fields: projectId, region, environment, operatorImageDigest, bundleSource,
bundleDigest, remoteStateBackend. Optional: dns/URL/registry bases,
admin clients, tenant (defaults to 'default')."
```

---

## Task 2: Add `build_gcp_request_from_ext` helper + `apply_from_ext` + `destroy_from_ext`

**Files:**
- Modify: `src/gcp.rs`

- [ ] **Step 2.1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` block in `src/gcp.rs`:

```rust
    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_missing_required_field() {
        let json = r#"{"projectId":"my-project"}"#;
        let err = apply_from_ext(json, "{}", None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field")
                || msg.contains("bundleSource")
                || msg.contains("bundle_source"),
            "got: {msg}"
        );
    }

    #[test]
    fn destroy_from_ext_rejects_invalid_json() {
        let err = destroy_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }
```

**Note on `{err:#}`:** anyhow's default Display shows only the outermost context. Alternate display `{:#}` shows full error chain including serde's "missing field" message. Same pattern used in `src/aws.rs` tests (Phase B #4b precedent).

- [ ] **Step 2.2: Run tests to verify they fail**

```bash
cargo test --features extensions --lib gcp::tests::apply_from_ext 2>&1 | tail -15
cargo test --features extensions --lib gcp::tests::destroy_from_ext 2>&1 | tail -15
```

Expected: compile error — `apply_from_ext` and `destroy_from_ext` not found.

- [ ] **Step 2.3: Add the helper + entry points**

Edit `src/gcp.rs`. Find `pub fn ensure_gcp_config` (around line 108). Immediately AFTER the closing `}` of `ensure_gcp_config` (around line 117), before `pub async fn run`, add:

```rust
/// Build a `GcpRequest` from the extension-provided config. Used by
/// `apply_from_ext` / `destroy_from_ext`. Fields unused by the extension
/// path default to `None` / `false` / sensible defaults.
fn build_gcp_request_from_ext(
    capability: DeployerCapability,
    cfg: &GcpCloudRunExtConfig,
    pack_path: Option<&std::path::Path>,
) -> GcpRequest {
    GcpRequest {
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
/// today, GCP credentials come from the ambient Google Application Default
/// Credentials (ADC) chain (`gcloud auth application-default login` or
/// `GOOGLE_APPLICATION_CREDENTIALS`).
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: GcpCloudRunExtConfig =
        serde_json::from_str(config_json).context("parse gcp cloud-run config JSON")?;
    let request = build_gcp_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve GCP deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for GCP deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run GCP deployment pipeline")?;
    Ok(())
}

/// Extension-driven destroy entry point: same shape as `apply_from_ext`
/// with `capability: Destroy`.
pub fn destroy_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: GcpCloudRunExtConfig =
        serde_json::from_str(config_json).context("parse gcp cloud-run config JSON")?;
    let request = build_gcp_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve GCP deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for GCP destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run GCP destroy pipeline")?;
    Ok(())
}
```

**Note on imports:** `DeployerCapability` is already imported at `src/gcp.rs:4` (`use crate::contract::DeployerCapability;`). No new import needed. `GcpRequest` struct definition is at lines 11-36.

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib gcp::tests::apply_from_ext 2>&1 | tail -15
cargo test --features extensions --lib gcp::tests::destroy_from_ext 2>&1 | tail -15
cargo build --features extensions 2>&1 | tail -5
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: 3 tests pass. Clean build. Fmt clean (if not, run `cargo fmt --all`).

- [ ] **Step 2.5: Commit**

```bash
git add src/gcp.rs
git commit -m "feat(gcp): add apply_from_ext / destroy_from_ext entry points

Extension-driven dispatch: parse JSON config, build GcpRequest, call
existing resolve_config + apply::run. Async isolated via internal
tokio::runtime::Runtime::new().block_on() — adapter layer stays sync.

_creds_json reserved for future secret URI resolution (Phase B #2);
GCP credentials resolved via ambient Google ADC chain (gcloud auth /
GOOGLE_APPLICATION_CREDENTIALS)."
```

---

## Task 3: Verify existing GCP CLI integration suite still green

This task is a checkpoint — no code changes, but CRITICAL for the zero-touch guarantee.

**Files:** none (verification only)

- [ ] **Step 3.1: Run full gcp CLI integration suite**

```bash
cargo test --test gcp_cli --features extensions 2>&1 | tail -20
```

Expected: all tests in `tests/gcp_cli.rs` pass. If any fail, STOP and investigate — we may have accidentally broken something in `src/gcp.rs`.

- [ ] **Step 3.2: Run full lib test suite**

```bash
cargo test --features extensions --lib 2>&1 | tail -10
```

Expected: all library tests pass.

- [ ] **Step 3.3: Run no-default-features baseline**

```bash
cargo build --no-default-features 2>&1 | tail -10
```

Expected: clean build (verifies our new code is properly feature-gated).

**No commit for this task** — verification only.

---

## Task 4: Add GCP match arms to `backend_adapter`

**Files:**
- Modify: `src/ext/backend_adapter.rs`

- [ ] **Step 4.1: Write the failing tests**

In `src/ext/backend_adapter.rs`, inside the existing `#[cfg(test)] mod tests { ... }` block, add:

```rust
    #[test]
    fn gcp_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Gcp,
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
                backend: BuiltinBackendId::Gcp,
                ..
            }
        ));
    }

    #[test]
    fn gcp_destroy_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Gcp,
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
                backend: BuiltinBackendId::Gcp,
                ..
            }
        ));
    }
```

**Update 2 existing tests** — since GCP is now supported, swap to `BuiltinBackendId::Azure`:

Find:
```rust
    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Gcp,
            ...
```

Replace the backend identifier in BOTH the call and the assertion to `BuiltinBackendId::Azure`:

```rust
    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Azure,
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
                backend: BuiltinBackendId::Azure
            }
        ));
    }
```

Same swap for `unsupported_backend_returns_adapter_not_implemented_destroy` (currently uses Gcp — change to Azure in both call and assertion).

- [ ] **Step 4.2: Run tests to verify behavior**

```bash
cargo test --features extensions --lib ext::backend_adapter 2>&1 | tail -20
```

Expected: the 2 new GCP tests FAIL (no match arms yet, fall through to AdapterNotImplemented). The 2 updated "unsupported backend" tests PASS (Azure still unsupported).

- [ ] **Step 4.3: Add the GCP match arms**

Edit `src/ext/backend_adapter.rs`. Find the `match (backend, action) { ... }` block. Add the following arms BEFORE the `_ =>` catch-all (after the existing `(Aws, ...)` arms):

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

- [ ] **Step 4.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib ext::backend_adapter 2>&1 | tail -20
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: all tests pass. Fmt clean (if not, run `cargo fmt --all` before commit).

- [ ] **Step 4.5: Commit**

```bash
git add src/ext/backend_adapter.rs
git commit -m "feat(ext): wire GCP backend into backend_adapter

Adds match arms for (Gcp, Apply) and (Gcp, Destroy) delegating to
gcp::apply_from_ext / destroy_from_ext. Errors wrapped in
BackendExecutionFailed with source chain preserved.

Existing 'unsupported backend' tests updated to use Azure
(GCP is now supported)."
```

---

## Task 5: Update `AdapterNotImplemented` error message

**Files:**
- Modify: `src/ext/errors.rs`

- [ ] **Step 5.1: Update the error message**

Edit `src/ext/errors.rs`. Find the `AdapterNotImplemented` variant. Currently reads:

```rust
    #[error(
        "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws)"
    )]
    AdapterNotImplemented { backend: BuiltinBackendId },
```

Replace with:

```rust
    #[error(
        "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws, Gcp)"
    )]
    AdapterNotImplemented { backend: BuiltinBackendId },
```

- [ ] **Step 5.2: Update the corresponding test**

In `src/ext/errors.rs`, find `adapter_not_implemented_displays_backend` test. Current version uses `BuiltinBackendId::Gcp`. Since GCP is now supported, swap to `Azure` and update assertions to include Gcp:

```rust
    #[test]
    fn adapter_not_implemented_displays_backend() {
        let err = ExtensionError::AdapterNotImplemented {
            backend: BuiltinBackendId::Azure,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Azure"), "got: {msg}");
        assert!(msg.contains("Desktop"), "got: {msg}");
        assert!(msg.contains("SingleVm"), "got: {msg}");
        assert!(msg.contains("Aws"), "got: {msg}");
        assert!(msg.contains("Gcp"), "got: {msg}");
    }
```

- [ ] **Step 5.3: Run tests**

```bash
cargo test --features extensions --lib ext::errors 2>&1 | tail -15
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: 4 tests pass. Fmt clean.

- [ ] **Step 5.4: Commit**

```bash
git add src/ext/errors.rs
git commit -m "chore(ext): update AdapterNotImplemented message for GCP wiring

Now lists Desktop, SingleVm, Aws, Gcp as supported backends. Test
updated to use Azure as example unsupported backend."
```

---

## Task 6: Add ignored integration test placeholder

**Files:**
- Modify: `tests/ext_apply_integration.rs`

- [ ] **Step 6.1: Add the ignored test**

Append to `tests/ext_apply_integration.rs`:

```rust
#[test]
#[ignore = "unignore when deploy-gcp fixture lands in testdata/ext/ (Phase B #4d follow-up)"]
fn ext_apply_gcp_target_requires_required_config_fields() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    // Missing required fields (only region provided)
    let config = write_tempfile(tmp.path(), "config.json", r#"{"region":"us-central1"}"#);
    let args = ExtApplyArgs {
        target: "gcp-cloud-run-local".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    // Requires testdata/ext/greentic.deploy-gcp-stub/ with describe.json + WASM.
    // Currently ignored; will be unignored after #4d publishes deploy-gcp@0.1.0
    // and we copy a stub into this repo's testdata/.
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    // Either ValidationFailed (schema) or TargetNotFound depending on fixture state
    assert!(
        matches!(
            err,
            ExtensionError::ValidationFailed { .. } | ExtensionError::TargetNotFound(_)
        ),
        "got: {err:?}"
    );
}
```

- [ ] **Step 6.2: Verify the test is ignored**

```bash
cargo test --features extensions,test-utils --test ext_apply_integration 2>&1 | tail -10
cargo fmt --all -- --check 2>&1 | tail -5
```

Expected: shows `X passed; 0 failed; 2 ignored` (the 2 ignored include the existing AWS ignored test from #4b and this new GCP one). Fmt clean.

- [ ] **Step 6.3: Commit**

```bash
git add tests/ext_apply_integration.rs
git commit -m "test(ext): add ignored integration test for gcp-cloud-run-local

Placeholder scoped for when deploy-gcp stub fixture lands in
testdata/ext/ after Phase B #4d publishes deploy-gcp@0.1.0. Unignore
and pair with fixture drop in a future PR."
```

---

## Task 7: Full local CI + fmt/clippy pass

**Files:** none (verification + potential fixes)

- [ ] **Step 7.1: Run full local CI**

```bash
cd /home/bimbim/works/greentic/greentic-deployer
./ci/local_check.sh 2>&1 | tail -40
```

Expected: all 9 gates pass (fmt, clippy, internal-tools, all tests, doc, no-default baseline, extensions build, extensions test).

- [ ] **Step 7.2: If fmt/clippy fails, fix**

If `cargo fmt --check` fails:
```bash
cargo fmt --all
git add -u
git commit -m "chore(fmt): cargo fmt after gcp ext additions"
```

If clippy warnings, read the warning, fix directly in the file, commit:
```bash
git add -u
git commit -m "chore(clippy): fix [specific warning] in [file]"
```

- [ ] **Step 7.3: Final verification — existing GCP tests untouched**

```bash
cargo test --test gcp_cli --features extensions 2>&1 | tail -20
```

Expected: all pass — this is the key acceptance criteria that existing cloud paths are bit-for-bit preserved.

---

## Task 8: Push Phase A branch + open deployer PR

**Files:** none

- [ ] **Step 8.1: Verify branch state**

```bash
git log --oneline main..HEAD
```

Expected: 7–9 commits (spec + 6 feature commits + optional fmt/clippy fixes).

- [ ] **Step 8.2: Push to origin**

```bash
git push -u origin spec/phase-b-4d-gcp-cloud-run 2>&1 | tail -10
```

- [ ] **Step 8.3: Open PR**

```bash
gh pr create --title "feat(ext): Phase B #4d wire GCP Cloud Run backend into ext apply/destroy" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4d deployer side per `docs/superpowers/specs/2026-04-19-phase-b-4d-gcp-cloud-run-design.md`
- Wires `ext apply --target gcp-cloud-run-local` and `ext destroy --target gcp-cloud-run-local` to the existing GCP cloud deployment pipeline
- Reuses existing `greentic.deploy.gcp` pack (no new pack authoring)
- Pair PR in `greentic-biz/greentic-deployer-extensions` will ship `deploy-gcp@0.1.0.gtxpack` ref ext

## Architecture

- `src/gcp.rs`: new `GcpCloudRunExtConfig` Deserialize struct, `build_gcp_request_from_ext` helper, `apply_from_ext` / `destroy_from_ext` entry points
- Entry points delegate to existing `resolve_config` + `apply::run` — zero touch to existing GCP clap path
- Async isolated via internal `tokio::runtime::Runtime::new().block_on()`
- `src/ext/backend_adapter.rs`: 2 new match arms for `BuiltinBackendId::Gcp`
- GCP credentials via ambient Google ADC chain (no JSON creds; secret URI resolution = Phase B #2)

## Zero-touch guarantee

Explicit non-goals per spec: existing `src/gcp.rs` pub fns (`resolve_config`, `ensure_gcp_config`, `run`, `run_config`, `run_with_plan`), `src/main.rs::run_gcp`, `src/apply.rs`, and all other cloud backend files (`aws.rs`, `azure.rs`, `terraform.rs`, etc.) receive zero line changes. Dispatch table in `deployment.rs` and `fixtures/packs/terraform/` reused as-is. Task 3 explicit checkpoint ran `cargo test --test gcp_cli --features extensions`.

## Test plan

- [x] Unit tests: gcp (6 new), backend_adapter (2 new + 2 updated), errors (1 updated) — all passing
- [x] Existing integration: `tests/gcp_cli.rs` passes unchanged — zero regression
- [x] New ignored integration: `tests/ext_apply_integration.rs` (1 test, scoped for ref ext fixture follow-up)
- [x] `ci/local_check.sh` all 9 gates green
- [x] `cargo build --no-default-features` baseline green

## Follow-up PR

`greentic-biz/greentic-deployer-extensions` — `feat/deploy-gcp-0.1.0` branch ships `deploy-gcp@0.1.0.gtxpack` ref ext. Merge this PR first, then that one.

## Spec & plan

- Spec: `docs/superpowers/specs/2026-04-19-phase-b-4d-gcp-cloud-run-design.md`
- Plan: `docs/superpowers/plans/2026-04-19-phase-b-4d-gcp-cloud-run.md`
EOF
)" 2>&1 | tail -5
```

- [ ] **Step 8.4: Report PR URL**

Capture the URL from `gh pr create` output.

---

## Phase B — `greentic-deployer-extensions` Tasks

## Task 9: Set up branch + scaffold `deploy-gcp/` crate

**Files:**
- Create: `reference-extensions/deploy-gcp/Cargo.toml`
- Create: `reference-extensions/deploy-gcp/rust-toolchain.toml`
- Create: `reference-extensions/deploy-gcp/.gitignore`

Work from: `/home/bimbim/works/greentic/greentic-deployer-extensions`

- [ ] **Step 9.1: Sync + create branch**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git fetch origin
git checkout main
git pull --ff-only origin main
git checkout -b feat/deploy-gcp-0.1.0
```

- [ ] **Step 9.2: Create directories**

```bash
mkdir -p reference-extensions/deploy-gcp/src
mkdir -p reference-extensions/deploy-gcp/schemas
mkdir -p reference-extensions/deploy-gcp/wit
```

- [ ] **Step 9.3: Create Cargo.toml**

Write `reference-extensions/deploy-gcp/Cargo.toml` with EXACT content:

```toml
[workspace]

[package]
name = "greentic-deploy-gcp-extension"
version = "0.1.0"
edition = "2024"
license = "MIT"
publish = false
description = "Greentic deploy extension for GCP Cloud Run targets"

[lib]
crate-type = ["cdylib", "rlib"]
path = "src/lib.rs"

[dependencies]
wit-bindgen = "0.41"
wit-bindgen-rt = "0.41"

[package.metadata.component]
package = "greentic:deploy-gcp-extension"

[package.metadata.component.target]
path = "wit"
world = "deploy-extension"

[package.metadata.component.target.dependencies]
"greentic:extension-base"   = { path = "../../wit/extension-base.wit" }
"greentic:extension-host"   = { path = "../../wit/extension-host.wit" }
"greentic:extension-deploy" = { path = "../../wit/extension-deploy.wit" }
```

- [ ] **Step 9.4: Create rust-toolchain.toml**

```bash
cp reference-extensions/deploy-aws/rust-toolchain.toml reference-extensions/deploy-gcp/rust-toolchain.toml
```

- [ ] **Step 9.5: Create .gitignore**

**CRITICAL:** This must ONLY exclude `src/bindings.rs`. Do NOT exclude `Cargo.lock` or `/wit` — lesson from PR #4 CI failure. `Cargo.lock` must be committed for `--locked` builds to work in CI.

Write `reference-extensions/deploy-gcp/.gitignore` with EXACT content:

```
# Auto-generated by wit-bindgen at build time; not source-controlled
src/bindings.rs
```

- [ ] **Step 9.6: Commit**

```bash
git add reference-extensions/deploy-gcp/Cargo.toml \
        reference-extensions/deploy-gcp/rust-toolchain.toml \
        reference-extensions/deploy-gcp/.gitignore
git commit -m "feat(deploy-gcp): scaffold reference extension crate

Mirror deploy-aws structure: empty workspace, cdylib+rlib lib,
wit-bindgen 0.41 deps pointing to shared wit/ files in parent repo.
.gitignore only excludes src/bindings.rs (Cargo.lock committed for
--locked CI builds per lesson from deploy-aws PR #4 hotfix)."
```

---

## Task 10: Add wit/world.wit + describe.json + schemas

**Files:**
- Create: `reference-extensions/deploy-gcp/wit/world.wit`
- Create: `reference-extensions/deploy-gcp/describe.json`
- Create: `reference-extensions/deploy-gcp/schemas/gcp-cloud-run.credentials.schema.json`
- Create: `reference-extensions/deploy-gcp/schemas/gcp-cloud-run.config.schema.json`

- [ ] **Step 10.1: Create wit/world.wit**

Write `reference-extensions/deploy-gcp/wit/world.wit`:

```
package greentic:deploy-gcp-extension;

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

- [ ] **Step 10.2: Create describe.json**

Write `reference-extensions/deploy-gcp/describe.json`:

```json
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": {
    "id": "greentic.deploy-gcp",
    "name": "GCP Deploy",
    "version": "0.1.0",
    "summary": "GCP Cloud Run deployment via Terraform",
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
        "id": "greentic:deploy/gcp-cloud-run",
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
        "id": "gcp-cloud-run-local",
        "displayName": "GCP Cloud Run (local Terraform)",
        "description": "Deploy to GCP Cloud Run via Terraform using ambient Google credentials",
        "execution": {
          "backend": "gcp",
          "handler": null,
          "kind": "builtin"
        },
        "supportsRollback": true
      }
    ]
  }
}
```

- [ ] **Step 10.3: Create credentials schema (empty object — ambient ADC)**

Write `reference-extensions/deploy-gcp/schemas/gcp-cloud-run.credentials.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "GCP Cloud Run credentials",
  "description": "Empty object. GCP credentials resolved via ambient Google Application Default Credentials chain (gcloud auth application-default login, GOOGLE_APPLICATION_CREDENTIALS, or service-attached credentials).",
  "type": "object",
  "properties": {},
  "additionalProperties": false
}
```

- [ ] **Step 10.4: Create config schema**

Write `reference-extensions/deploy-gcp/schemas/gcp-cloud-run.config.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "GCP Cloud Run deployment config",
  "type": "object",
  "required": [
    "projectId",
    "region",
    "environment",
    "operatorImageDigest",
    "bundleSource",
    "bundleDigest",
    "remoteStateBackend"
  ],
  "properties": {
    "projectId": {
      "type": "string",
      "minLength": 1,
      "description": "GCP project ID (e.g., my-project-12345)"
    },
    "region": {
      "type": "string",
      "minLength": 1,
      "description": "GCP region (e.g., us-central1)"
    },
    "environment": {
      "type": "string",
      "minLength": 1,
      "description": "Environment label (staging, prod, etc.)"
    },
    "operatorImageDigest": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$",
      "description": "sha256 digest of the greentic operator container image"
    },
    "bundleSource": {
      "type": "string",
      "minLength": 1,
      "description": "Bundle source URI (oci://, http://, https://, repo://, store://)"
    },
    "bundleDigest": {
      "type": "string",
      "pattern": "^sha256:[a-f0-9]{64}$",
      "description": "sha256 digest of the bundle"
    },
    "remoteStateBackend": {
      "type": "string",
      "minLength": 1,
      "description": "Terraform remote state backend URI (e.g., gs://bucket/path)"
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

- [ ] **Step 10.5: Validate schemas parse as JSON**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions/reference-extensions/deploy-gcp
jq empty describe.json
jq empty schemas/gcp-cloud-run.credentials.schema.json
jq empty schemas/gcp-cloud-run.config.schema.json
```

Expected: no output (all valid JSON).

- [ ] **Step 10.6: Commit**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git add reference-extensions/deploy-gcp/wit/ \
        reference-extensions/deploy-gcp/describe.json \
        reference-extensions/deploy-gcp/schemas/
git commit -m "feat(deploy-gcp): add wit/world.wit + describe.json + schemas

Single target 'gcp-cloud-run-local' with backend=gcp, handler=null.

Config schema mirrors GcpCloudRunExtConfig in greentic-deployer
(required: projectId, region, environment, operatorImageDigest,
bundleSource, bundleDigest, remoteStateBackend). Creds schema is
empty object — GCP credentials resolved via ambient Google ADC chain."
```

---

## Task 11: Add WASM Guest impl (`src/lib.rs`)

**Files:**
- Create: `reference-extensions/deploy-gcp/src/lib.rs`

- [ ] **Step 11.1: Create lib.rs**

Write `reference-extensions/deploy-gcp/src/lib.rs`:

```rust
//! greentic.deploy-gcp — reference deploy extension for GCP Cloud Run.
//!
//! Mode A only: metadata + schemas served here; deployer host routes actual
//! deploy/poll/rollback to its built-in `gcp` backend. See parent spec
//! `greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4d-gcp-cloud-run-design.md`.

#[allow(warnings)]
mod bindings;

use bindings::exports::greentic::extension_base::{lifecycle, manifest};
use bindings::exports::greentic::extension_deploy::{deployment, targets};
use bindings::greentic::extension_base::types;

const CREDS_SCHEMA: &str = include_str!("../schemas/gcp-cloud-run.credentials.schema.json");
const CONFIG_SCHEMA: &str = include_str!("../schemas/gcp-cloud-run.config.schema.json");

const TARGET_GCP_CLOUD_RUN: &str = "gcp-cloud-run-local";

struct Component;

impl manifest::Guest for Component {
    fn get_identity() -> types::ExtensionIdentity {
        types::ExtensionIdentity {
            id: "greentic.deploy-gcp".into(),
            version: "0.1.0".into(),
            kind: types::Kind::Deploy,
        }
    }

    fn get_offered() -> Vec<types::CapabilityRef> {
        vec![types::CapabilityRef {
            id: "greentic:deploy/gcp-cloud-run".into(),
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
            id: TARGET_GCP_CLOUD_RUN.into(),
            display_name: "GCP Cloud Run (local Terraform)".into(),
            description: "Deploy to GCP Cloud Run via Terraform using ambient Google credentials".into(),
            icon_path: None,
            supports_rollback: true,
        }]
    }

    fn credential_schema(target_id: String) -> Result<String, types::ExtensionError> {
        match target_id.as_str() {
            TARGET_GCP_CLOUD_RUN => Ok(CREDS_SCHEMA.into()),
            other => Err(types::ExtensionError::InvalidInput(format!(
                "unknown target: {other}"
            ))),
        }
    }

    fn config_schema(target_id: String) -> Result<String, types::ExtensionError> {
        match target_id.as_str() {
            TARGET_GCP_CLOUD_RUN => Ok(CONFIG_SCHEMA.into()),
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
            TARGET_GCP_CLOUD_RUN => vec![],
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
            "deploy-gcp uses Mode A builtin execution; dispatcher should route via \
             backend=gcp, not WASM"
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
git add reference-extensions/deploy-gcp/src/lib.rs
git commit -m "feat(deploy-gcp): add WASM Guest impl for GCP Cloud Run target

Mode A only: metadata + schemas exposed; deploy/poll/rollback return
Internal error pointing at host routing via backend=gcp. Mirrors
deploy-aws pattern, single target."
```

---

## Task 12: Add build.sh + local build

**Files:**
- Create: `reference-extensions/deploy-gcp/build.sh`
- Produce: `reference-extensions/deploy-gcp/greentic.deploy-gcp-0.1.0.gtxpack` (local artifact, NOT committed — gitignored via `*.gtxpack` in parent repo gitignore, or add to ref ext gitignore if needed)

- [ ] **Step 12.1: Copy build.sh from deploy-aws**

```bash
cp reference-extensions/deploy-aws/build.sh reference-extensions/deploy-gcp/build.sh
```

- [ ] **Step 12.2: Replace desktop/aws references with gcp**

Edit `reference-extensions/deploy-gcp/build.sh`. Replace these occurrences carefully (audit each replacement):
- `greentic.deploy-aws` → `greentic.deploy-gcp`
- `greentic_deploy_aws_extension` → `greentic_deploy_gcp_extension`
- "aws" in comments at top → "gcp"

Do NOT blindly `sed` — the build.sh may have bare "aws" references that would confuse the script. Read the file after editing:

```bash
cat reference-extensions/deploy-gcp/build.sh
```

- [ ] **Step 12.3: Make build.sh executable**

```bash
chmod +x reference-extensions/deploy-gcp/build.sh
```

- [ ] **Step 12.4: Run build.sh locally**

```bash
cd reference-extensions/deploy-gcp
./build.sh 2>&1 | tail -30
```

Expected:
- `cargo component build --release --locked --target wasm32-wasip1` succeeds
- `wasm-tools validate` passes
- Produces `greentic.deploy-gcp-0.1.0.gtxpack` archive
- Build completes with "unsigned build (GREENTIC_EXT_SIGNING_KEY_PEM not set — dev mode)"

This will generate `Cargo.lock` in the crate directory if not already present.

**Prerequisites check:** `cargo-component`, `wasm-tools`, `jq`, `zip` must be installed. Phase B #4c already verified these on this machine.

- [ ] **Step 12.5: Verify .gtxpack contents**

```bash
unzip -l reference-extensions/deploy-gcp/greentic.deploy-gcp-0.1.0.gtxpack 2>&1 | head -15
```

Expected: shows `describe.json`, `schemas/*.schema.json`, `extension.wasm`.

- [ ] **Step 12.6: Commit build.sh + Cargo.lock (CRITICAL)**

The `.gtxpack` file is gitignored. But **Cargo.lock must be committed** (lesson from PR #4). Verify `Cargo.lock` was generated and is staged:

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
ls reference-extensions/deploy-gcp/Cargo.lock  # should exist
git status reference-extensions/deploy-gcp/
```

Expected: `Cargo.lock` and `build.sh` both show as untracked/modified. `greentic.deploy-gcp-0.1.0.gtxpack` should be gitignored.

If `Cargo.lock` is in `.gitignore` by mistake (it shouldn't be — we only ignored `src/bindings.rs` in Task 9), verify the .gitignore:

```bash
cat reference-extensions/deploy-gcp/.gitignore
```

Should ONLY contain `src/bindings.rs` and its comment.

Commit:

```bash
git add reference-extensions/deploy-gcp/build.sh reference-extensions/deploy-gcp/Cargo.lock
git commit -m "feat(deploy-gcp): add build.sh + commit Cargo.lock

Mirrors deploy-aws build.sh: validate schemas, cargo component build,
wasm-tools validate, env-aware signing (GREENTIC_EXT_SIGNING_KEY_PEM
from CI secret), zip to .gtxpack. Cargo.lock committed so CI --locked
builds work (lesson from deploy-aws PR #4 hotfix)."
```

- [ ] **Step 12.7: Verify .gtxpack not committed**

```bash
git ls-files reference-extensions/deploy-gcp/ | grep -i gtxpack
```

Expected: no output (`.gtxpack` should not be tracked).

If the .gtxpack somehow got tracked, check parent repo `.gitignore` for `*.gtxpack` rule. If missing, the ref ext `.gitignore` needs updating — add `*.gtxpack` line.

---

## Task 13: Extend CI workflow + push + open ref ext PR

**Files:**
- Modify: `ci/local_check.sh`

- [ ] **Step 13.1: Extend ci/local_check.sh with deploy-gcp build+validate**

Read current content:

```bash
cat ci/local_check.sh
```

Find the existing block for deploy-aws (near the end, after deploy-single-vm):

```bash
echo "==> build deploy-aws"
(cd reference-extensions/deploy-aws && bash build.sh)

echo "==> validate deploy-aws .gtxpack"
bash ci/validate-gtxpack.sh \
    reference-extensions/deploy-aws/greentic.deploy-aws-0.1.0.gtxpack
```

Add AFTER the deploy-aws validate block, BEFORE `echo "Local check completed successfully."`:

```bash
echo "==> build deploy-gcp"
(cd reference-extensions/deploy-gcp && bash build.sh)

echo "==> validate deploy-gcp .gtxpack"
bash ci/validate-gtxpack.sh \
    reference-extensions/deploy-gcp/greentic.deploy-gcp-0.1.0.gtxpack
```

- [ ] **Step 13.2: Run local_check.sh end-to-end**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
bash ci/local_check.sh 2>&1 | tail -30
```

Expected: all 4 extensions (desktop, single-vm, aws, gcp) build + validate successfully. Script exits "Local check completed successfully."

- [ ] **Step 13.3: Commit workflow update**

```bash
git add ci/local_check.sh
git commit -m "ci(deploy-gcp): extend local_check.sh to build+validate deploy-gcp

Mirrors deploy-aws / deploy-single-vm / deploy-desktop pattern.
CI_REQUIRE_SIGNED guardrail from workflow env applies on main push."
```

- [ ] **Step 13.4: Verify branch state**

```bash
git log --oneline main..HEAD
```

Expected: 5 commits (scaffold, wit+describe+schemas, lib.rs, build.sh+Cargo.lock, ci).

- [ ] **Step 13.5: Push branch**

```bash
git push -u origin feat/deploy-gcp-0.1.0 2>&1 | tail -5
```

- [ ] **Step 13.6: Open PR**

```bash
gh pr create --title "feat(deploy-gcp): ship deploy-gcp@0.1.0 reference extension" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4d deployer-extensions side per `greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4d-gcp-cloud-run-design.md`
- New reference extension `deploy-gcp@0.1.0.gtxpack` with single target `gcp-cloud-run-local`
- Backend `gcp`, handler `null`, execution kind `builtin` (Mode A)
- Pairs with `greentic-deployer` Phase B #4d PR which wires the GCP backend in `ext apply/destroy`

## Architecture

- `reference-extensions/deploy-gcp/` — new crate mirroring `deploy-aws@0.1.0` structure
- Single target: `gcp-cloud-run-local`
- Config schema: required `projectId, region, environment, operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend`; optional DNS/URL/registry bases, tenant
- Credentials schema: empty object — GCP creds via ambient Google ADC (gcloud auth / `GOOGLE_APPLICATION_CREDENTIALS`)

## Test plan

- [x] `jq` validates describe.json + both schemas as JSON
- [x] `cargo component build --release --locked --target wasm32-wasip1` succeeds
- [x] `wasm-tools validate` passes
- [x] `./build.sh` produces `.gtxpack` archive containing describe.json + schemas + extension.wasm
- [x] `ci/local_check.sh` extended to build+validate deploy-gcp alongside existing extensions
- [x] Cargo.lock committed (lesson from deploy-aws PR #4 hotfix)
- [ ] CI produces signed artifact on push to main (gated by `EXT_SIGNING_KEY_PEM` secret)
- [ ] End-to-end verification with deployer Phase B #4d PR

## Merge order

1. Merge `greenticai/greentic-deployer` Phase B #4d PR first
2. Merge this PR second

## Spec & plan

- Spec: `greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4d-gcp-cloud-run-design.md`
- Plan: `greentic-deployer/docs/superpowers/plans/2026-04-19-phase-b-4d-gcp-cloud-run.md` (Tasks 9–13)
EOF
)" 2>&1 | tail -5
```

- [ ] **Step 13.7: Report both PR URLs**

Output Phase A (deployer) + Phase B (deployer-extensions) PR URLs for user review.

---

## Self-Review Checklist

**Spec coverage:**
- §2 Q1–Q3 design decisions → Tasks 1–5 ✓
- §3 Architecture (adapter match arms, thin wrapper, async isolation) → Tasks 2, 4 ✓
- §4.1 gcp.rs additions (struct, helper, apply/destroy) → Tasks 1, 2 ✓
- §4.2 backend_adapter match arms → Task 4 ✓
- §4.3 errors.rs updated message → Task 5 ✓
- §4.4 ignored integration test → Task 6 ✓
- §4.5 ref ext crate → Tasks 9, 10, 11 ✓
- §4.6 ci/local_check.sh → Task 13 ✓
- §5 data flow → exercised via Tasks 2, 4 ✓
- §6 error handling → Tasks 2, 4, 5 (messages wrapping) ✓
- §7.1 gcp.rs unit tests (6) → Tasks 1, 2 ✓
- §7.2 backend_adapter unit tests → Task 4 ✓
- §7.3 errors.rs test → Task 5 ✓
- §7.4 ignored integration → Task 6 ✓
- §7.5 existing gcp_cli.rs relied upon → Task 3 (explicit checkpoint) ✓
- §8 acceptance criteria 1–11 → verified via Tasks 3, 7 (local CI), 8 (PR), 13 (Phase B PR) ✓
- §9.1 risk: `.gitignore` Cargo.lock trap → Task 9 Step 9.5 explicit warning, Task 12 Step 12.6 explicit commit ✓

**Placeholder scan:**
- No TBD/TODO/"implement later" in code blocks ✓
- Commit messages literal and complete ✓
- Task 12 Step 12.2 says "audit each replacement" which is judgment-based — acceptable because exhaustive sed substitution list was given (greentic.deploy-aws, greentic_deploy_aws_extension, aws-in-comments)

**Type consistency:**
- `GcpCloudRunExtConfig` field names consistent Tasks 1, 2, 10, 11 ✓
- `apply_from_ext`/`destroy_from_ext` signatures: `(config_json: &str, _creds_json: &str, pack_path: Option<&Path>) -> anyhow::Result<()>` consistent Tasks 2, 4 ✓
- `build_gcp_request_from_ext(capability, cfg, pack_path) -> GcpRequest` consistent Task 2 ✓
- `default_ext_tenant` fn name consistent Task 1 ✓
- `TARGET_GCP_CLOUD_RUN` const name consistent Task 11 ✓
- `BuiltinBackendId::Gcp` / `::Azure` usage consistent Tasks 4, 5 ✓

**Scope coverage verified — plan is complete.**
