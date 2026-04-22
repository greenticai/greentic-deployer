# Phase B #4b + #4c — AWS ECS Fargate Deploy Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `greentic-deployer ext apply --target aws-ecs-fargate-local` to actually deploy via AWS ECS Fargate using existing `greentic.deploy.aws` pack, and ship matching `deploy-aws@0.1.0` reference extension.

**Architecture:** Two-repo delivery. `greentic-deployer` adds `aws::apply_from_ext` / `destroy_from_ext` entry points that parse JSON config, build an `AwsRequest`, call existing `aws::resolve_config` + `apply::run` via internal tokio runtime — zero touch to existing clap path. `backend_adapter` gains AWS match arms. `greentic-deployer-extensions` gets a new `deploy-aws/` ref ext crate mirroring `deploy-desktop@0.2.0` structure.

**Tech Stack:** Rust 2024, tokio (existing dep), serde, thiserror, anyhow, wit-bindgen (ref ext), cargo-component (ref ext build).

**Spec:** `docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`

**Branches:**
- `greentic-deployer`: `spec/phase-b-4b-4c-aws-ecs-fargate` (already checked out)
- `greentic-deployer-extensions`: `feat/deploy-aws-0.1.0` (will create in Phase C)

**Delivery structure:**
- **Phase A** — `greentic-deployer` changes (Tasks 1–8) → one PR
- **Phase B** — `greentic-deployer-extensions` changes (Tasks 9–13) → one PR in sibling repo
- Merge order: Phase A first (ref ext can be authored without deployer changes, but end-to-end flow needs both merged)

---

## File Structure

### Phase A — `greentic-deployer` repo

| Path | New/Modified | Responsibility |
|------|--------------|----------------|
| `src/aws.rs` | Modified (+~160 LoC) | New: `AwsEcsFargateExtConfig` struct, `build_aws_request_from_ext` helper, `apply_from_ext`, `destroy_from_ext`. Unchanged: existing `resolve_config`, `ensure_aws_config`, `run_admin_tunnel`. |
| `src/ext/backend_adapter.rs` | Modified (+~35 LoC) | Add 2 match arms for `BuiltinBackendId::Aws`. Update 1 existing test to use `Gcp` instead of `Aws` as "unsupported" example. |
| `src/ext/errors.rs` | Modified (~3 LoC) | Update `AdapterNotImplemented` error message to list new supported backends. |
| `tests/ext_apply_integration.rs` | Modified (+~30 LoC) | One new `#[ignore]` integration test scoped for future `deploy-aws` fixture. |

### Phase B — `greentic-deployer-extensions` repo

| Path | New/Modified | Responsibility |
|------|--------------|----------------|
| `reference-extensions/deploy-aws/Cargo.toml` | New | Crate metadata, wit-bindgen deps (mirror `deploy-desktop`). |
| `reference-extensions/deploy-aws/rust-toolchain.toml` | New | Pin to same toolchain as `deploy-desktop` (1.94.0). |
| `reference-extensions/deploy-aws/src/lib.rs` | New | Minimal WASM Guest impl — schemas + validate_credentials. Mode A only. |
| `reference-extensions/deploy-aws/describe.json` | New | Metadata + target contribution (`aws-ecs-fargate-local`, backend=aws). |
| `reference-extensions/deploy-aws/schemas/aws-ecs-fargate.credentials.schema.json` | New | Empty object (ambient creds). |
| `reference-extensions/deploy-aws/schemas/aws-ecs-fargate.config.schema.json` | New | Mirrors `AwsEcsFargateExtConfig` (camelCase required fields). |
| `reference-extensions/deploy-aws/build.sh` | New | cargo-component build + wasm-tools validate + env-aware sign + zip. |
| `.github/workflows/release.yml` | Modified | Add `deploy-aws` to build matrix (mirror `deploy-desktop` pattern). |

### Files explicitly UNCHANGED (verify no regression)

- `src/main.rs` — all clap paths including `run_aws`
- `src/apply.rs` — `apply::run` entry (line 341)
- `src/aws.rs` existing fns: `resolve_config` (119), `ensure_aws_config` (123), `run_admin_tunnel` (160), `AwsRequest::new` (54), `into_deployer_request` (87)
- `src/azure.rs`, `src/gcp.rs`, `src/terraform.rs`, `src/helm.rs`, `src/k8s_raw.rs`, `src/juju_k8s.rs`, `src/juju_machine.rs`, `src/operator.rs`, `src/serverless.rs`, `src/snap.rs`, `src/single_vm.rs`, `src/desktop.rs`
- `src/deployment.rs` — dispatch table stays
- `fixtures/packs/terraform/` — reused as `greentic.deploy.aws` pack
- `src/ext/dispatcher.rs`, `src/ext/cli.rs`, `src/ext/wasm.rs`, `src/ext/loader.rs`, `src/ext/registry.rs`, `src/ext/builtin_bridge.rs`, `src/ext/describe.rs`, `src/ext/diagnostic.rs` — all Phase B #4a

---

## Phase A — `greentic-deployer` Tasks

## Task 1: Add `AwsEcsFargateExtConfig` Deserialize struct

**Files:**
- Modify: `src/aws.rs`

Work from: `/home/bimbim/works/greentic/greentic-deployer`

- [ ] **Step 1.1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests { ... }` block at the bottom of `src/aws.rs`:

```rust
    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{
            "region": "us-east-1",
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "s3://my-tf-state-bucket/greentic/staging"
        }"#;
        let cfg: AwsEcsFargateExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.environment, "staging");
        assert_eq!(cfg.tenant, "default");
        assert!(cfg.dns_name.is_none());
        assert!(cfg.public_base_url.is_none());
    }

    #[test]
    fn ext_config_accepts_all_optionals() {
        let json = r#"{
            "region": "us-east-1",
            "environment": "prod",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "bundleDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "remoteStateBackend": "s3://my-tf-state-bucket/greentic/prod",
            "dnsName": "api.example.com",
            "publicBaseUrl": "https://api.example.com",
            "repoRegistryBase": "https://repo.example.com",
            "storeRegistryBase": "https://store.example.com",
            "adminAllowedClients": "CN=admin",
            "tenant": "acme"
        }"#;
        let cfg: AwsEcsFargateExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.dns_name.as_deref(), Some("api.example.com"));
        assert_eq!(cfg.public_base_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(cfg.tenant, "acme");
    }

    #[test]
    fn ext_config_rejects_missing_region() {
        let json = r#"{
            "environment": "staging",
            "operatorImageDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "bundleSource": "oci://...",
            "bundleDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "remoteStateBackend": "s3://..."
        }"#;
        let err = serde_json::from_str::<AwsEcsFargateExtConfig>(json).unwrap_err();
        assert!(format!("{err}").contains("region"), "got: {err}");
    }
```

- [ ] **Step 1.2: Run tests to verify they fail**

```bash
cd /home/bimbim/works/greentic/greentic-deployer
cargo test --features extensions --lib aws::tests::ext_config 2>&1 | tail -20
```

Expected: compile error — `AwsEcsFargateExtConfig` not found.

- [ ] **Step 1.3: Add the struct + default_tenant helper**

Edit `src/aws.rs`. Find the existing `AwsRequest` struct (line 19). Immediately BEFORE `impl AwsRequest {` (around line 54), add:

```rust
/// Configuration shape consumed by `ext apply --target aws-ecs-fargate-local`.
///
/// Mirrors the JSON schema declared by the `deploy-aws` reference extension.
/// Keys use camelCase on the wire; Rust field names use snake_case with serde rename.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsEcsFargateExtConfig {
    pub region: String,
    pub environment: String,
    pub operator_image_digest: String,
    pub bundle_source: String,
    pub bundle_digest: String,
    pub remote_state_backend: String,
    #[serde(default)]
    pub dns_name: Option<String>,
    #[serde(default)]
    pub public_base_url: Option<String>,
    #[serde(default)]
    pub repo_registry_base: Option<String>,
    #[serde(default)]
    pub store_registry_base: Option<String>,
    #[serde(default)]
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
cargo test --features extensions --lib aws::tests::ext_config 2>&1 | tail -20
```

Expected: 3 tests pass.

- [ ] **Step 1.5: Commit**

```bash
git add src/aws.rs
git commit -m "feat(aws): add AwsEcsFargateExtConfig for ext apply JSON input

New Deserialize struct mirrors the deploy-aws reference extension's
config schema. camelCase on the wire, snake_case internally. Required
fields: region, environment, operatorImageDigest, bundleSource,
bundleDigest, remoteStateBackend. Optional: dns/URL/registry bases,
admin clients, tenant (defaults to 'default')."
```

---

## Task 2: Add `build_aws_request_from_ext` helper + `apply_from_ext` + `destroy_from_ext`

**Files:**
- Modify: `src/aws.rs`

- [ ] **Step 2.1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` block in `src/aws.rs`:

```rust
    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"), "got: {err}");
    }

    #[test]
    fn apply_from_ext_rejects_missing_required_field() {
        let json = r#"{"region":"us-east-1"}"#;
        let err = apply_from_ext(json, "{}", None).unwrap_err();
        let msg = format!("{err}");
        // serde error mentions missing field by name — either the Rust field or the JSON key
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

- [ ] **Step 2.2: Run tests to verify they fail**

```bash
cargo test --features extensions --lib aws::tests::apply_from_ext 2>&1 | tail -15
cargo test --features extensions --lib aws::tests::destroy_from_ext 2>&1 | tail -15
```

Expected: compile error — `apply_from_ext` and `destroy_from_ext` not found.

- [ ] **Step 2.3: Add the helper + entry points**

Edit `src/aws.rs`. Find `pub fn resolve_config` (around line 119). Immediately AFTER the closing `}` of `ensure_aws_config` (around line 158, before `pub fn run_admin_tunnel`), add:

```rust
/// Build an `AwsRequest` from the extension-provided config. Used by
/// `apply_from_ext` / `destroy_from_ext`. Fields unused by the extension
/// path default to `None` / `false` / sensible defaults.
fn build_aws_request_from_ext(
    capability: DeployerCapability,
    cfg: &AwsEcsFargateExtConfig,
    pack_path: Option<&std::path::Path>,
) -> AwsRequest {
    AwsRequest {
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
/// today, AWS credentials come from the ambient provider chain.
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AwsEcsFargateExtConfig =
        serde_json::from_str(config_json).context("parse aws ecs-fargate config JSON")?;
    let request = build_aws_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve AWS deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for AWS deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run AWS deployment pipeline")?;
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
    let cfg: AwsEcsFargateExtConfig =
        serde_json::from_str(config_json).context("parse aws ecs-fargate config JSON")?;
    let request = build_aws_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve AWS deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for AWS destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run AWS destroy pipeline")?;
    Ok(())
}
```

**Note on imports:** verify top of `src/aws.rs` already imports `DeployerCapability`. If not, add `use crate::contract::DeployerCapability;` (or `use greentic_deployer::DeployerCapability` depending on existing pattern — grep existing usage of `DeployerCapability::Apply` in aws.rs to confirm).

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib aws::tests::apply_from_ext 2>&1 | tail -15
cargo test --features extensions --lib aws::tests::destroy_from_ext 2>&1 | tail -15
cargo build --features extensions 2>&1 | tail -5
```

Expected: 3 tests pass. Clean build.

- [ ] **Step 2.5: Commit**

```bash
git add src/aws.rs
git commit -m "feat(aws): add apply_from_ext / destroy_from_ext entry points

Extension-driven dispatch: parse JSON config, build AwsRequest, call
existing resolve_config + apply::run. Async isolated via internal
tokio::runtime::Runtime::new().block_on() — adapter layer stays sync.

_creds_json reserved for future secret URI resolution (Phase B #2);
AWS credentials resolved via ambient provider chain (env / ~/.aws /
IAM instance profile)."
```

---

## Task 3: Verify existing AWS CLI integration suite still green

This task is a checkpoint — no code changes, but CRITICAL for the zero-touch guarantee.

**Files:** none (verification only)

- [ ] **Step 3.1: Run full aws CLI integration suite**

```bash
cargo test --test aws_cli --features extensions 2>&1 | tail -20
```

Expected: all tests in `tests/aws_cli.rs` pass. If any fail, STOP and investigate — we may have accidentally broken something in `src/aws.rs`.

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

## Task 4: Add AWS match arms to `backend_adapter`

**Files:**
- Modify: `src/ext/backend_adapter.rs`

- [ ] **Step 4.1: Write the failing tests**

In `src/ext/backend_adapter.rs`, inside the existing `#[cfg(test)] mod tests { ... }` block, add:

```rust
    #[test]
    fn aws_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Aws,
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
                backend: BuiltinBackendId::Aws,
                ..
            }
        ));
    }

    #[test]
    fn aws_destroy_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Aws,
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
                backend: BuiltinBackendId::Aws,
                ..
            }
        ));
    }
```

Also **modify the existing tests** `unsupported_backend_returns_adapter_not_implemented_apply` and `unsupported_backend_returns_adapter_not_implemented_destroy` — since AWS is now supported, swap to `BuiltinBackendId::Gcp` and `BuiltinBackendId::Azure`:

Find the existing test:
```rust
    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Aws,
            ...
```

Replace with:
```rust
    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Gcp,
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
                backend: BuiltinBackendId::Gcp
            }
        ));
    }
```

Existing test `unsupported_backend_returns_adapter_not_implemented_destroy` already uses `Gcp` — no change needed (verified earlier).

- [ ] **Step 4.2: Run tests to verify behavior**

```bash
cargo test --features extensions --lib ext::backend_adapter 2>&1 | tail -20
```

Expected: the 2 new AWS tests FAIL (no match arms yet, fall through to `AdapterNotImplemented`). The 2 "unsupported backend" tests should PASS (Gcp/Azure still unsupported).

- [ ] **Step 4.3: Add the AWS match arms**

Edit `src/ext/backend_adapter.rs`. Find the `match (backend, action) { ... }` block. Add the following arms BEFORE the `_ =>` catch-all:

```rust
        (BuiltinBackendId::Aws, ExtAction::Apply) => {
            crate::aws::apply_from_ext(config_json, creds_json, pack_path).map_err(|e| {
                ExtensionError::BackendExecutionFailed {
                    backend,
                    source: e,
                }
            })
        }
        (BuiltinBackendId::Aws, ExtAction::Destroy) => {
            crate::aws::destroy_from_ext(config_json, creds_json, pack_path).map_err(|e| {
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
```

Expected: all tests pass (2 new + existing unchanged).

- [ ] **Step 4.5: Commit**

```bash
git add src/ext/backend_adapter.rs
git commit -m "feat(ext): wire AWS backend into backend_adapter

Adds match arms for (Aws, Apply) and (Aws, Destroy) delegating to
aws::apply_from_ext / destroy_from_ext. Errors wrapped in
BackendExecutionFailed with source chain preserved.

Existing 'unsupported backend' tests updated to use Gcp/Azure
(AWS is now supported)."
```

---

## Task 5: Update `AdapterNotImplemented` error message

**Files:**
- Modify: `src/ext/errors.rs`

- [ ] **Step 5.1: Update the error message**

Edit `src/ext/errors.rs`. Find the `AdapterNotImplemented` variant:

```rust
    #[error(
        "backend '{backend:?}' has no execution adapter wired (Phase B #4a supports: Desktop, SingleVm)"
    )]
    AdapterNotImplemented { backend: BuiltinBackendId },
```

Replace message with:

```rust
    #[error(
        "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws)"
    )]
    AdapterNotImplemented { backend: BuiltinBackendId },
```

- [ ] **Step 5.2: Update the corresponding test**

In `src/ext/errors.rs`, find `adapter_not_implemented_displays_backend` test. The assertion on "Phase B #4a" will now fail. Update:

```rust
    #[test]
    fn adapter_not_implemented_displays_backend() {
        let err = ExtensionError::AdapterNotImplemented {
            backend: BuiltinBackendId::Gcp,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Gcp"), "got: {msg}");
        assert!(msg.contains("Desktop"), "got: {msg}");
        assert!(msg.contains("SingleVm"), "got: {msg}");
        assert!(msg.contains("Aws"), "got: {msg}");
    }
```

(Changed backend from `Aws` to `Gcp` since AWS is now supported; assertions reflect new supported list.)

- [ ] **Step 5.3: Run tests**

```bash
cargo test --features extensions --lib ext::errors 2>&1 | tail -15
```

Expected: 4 tests pass.

- [ ] **Step 5.4: Commit**

```bash
git add src/ext/errors.rs
git commit -m "chore(ext): update AdapterNotImplemented message for AWS wiring

Now lists Desktop, SingleVm, Aws as supported backends. Test updated
to use Gcp as example unsupported backend."
```

---

## Task 6: Add ignored integration test placeholder

**Files:**
- Modify: `tests/ext_apply_integration.rs`

- [ ] **Step 6.1: Add the ignored test**

Append to `tests/ext_apply_integration.rs`:

```rust
#[test]
#[ignore = "unignore when deploy-aws fixture lands in testdata/ext/ (Phase B #4c follow-up)"]
fn ext_apply_aws_target_requires_required_config_fields() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    // Missing required fields (only region provided)
    let config = write_tempfile(tmp.path(), "config.json", r#"{"region":"us-east-1"}"#);
    let args = ExtApplyArgs {
        target: "aws-ecs-fargate-local".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    // Requires testdata/ext/greentic.deploy-aws-stub/ with describe.json + WASM.
    // Currently ignored; will be unignored after #4c publishes deploy-aws@0.1.0
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

- [ ] **Step 6.2: Verify the test is ignored (not running, not breaking)**

```bash
cargo test --features extensions,test-utils --test ext_apply_integration 2>&1 | tail -10
```

Expected: existing 4 tests pass + 1 ignored (shows as `1 ignored` in output).

- [ ] **Step 6.3: Commit**

```bash
git add tests/ext_apply_integration.rs
git commit -m "test(ext): add ignored integration test for aws-ecs-fargate-local

Placeholder scoped for when deploy-aws stub fixture lands in
testdata/ext/ after Phase B #4c publishes deploy-aws@0.1.0. Unignore
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
git commit -m "chore(fmt): cargo fmt after aws ecs-fargate ext additions"
```

If clippy warnings, read the warning, fix directly in the file, commit:
```bash
git add -u
git commit -m "chore(clippy): fix [specific warning] in [file]"
```

- [ ] **Step 7.3: Final verification — existing AWS tests untouched**

```bash
cargo test --test aws_cli --features extensions 2>&1 | tail -20
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
git push -u origin spec/phase-b-4b-4c-aws-ecs-fargate 2>&1 | tail -10
```

- [ ] **Step 8.3: Open PR**

```bash
gh pr create --title "feat(ext): Phase B #4b wire AWS ECS Fargate backend into ext apply/destroy" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4b per `docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`
- Wires `ext apply --target aws-ecs-fargate-local` and `ext destroy --target aws-ecs-fargate-local` to the existing AWS cloud deployment pipeline
- Reuses existing `greentic.deploy.aws` pack (no new pack authoring)
- Pair PR in `greentic-biz/greentic-deployer-extensions` (Phase B #4c) will ship `deploy-aws@0.1.0.gtxpack` ref ext

## Architecture

- `src/aws.rs`: new `AwsEcsFargateExtConfig` Deserialize struct, `build_aws_request_from_ext` helper, `apply_from_ext` / `destroy_from_ext` entry points
- Entry points delegate to existing `resolve_config` + `apply::run` — zero touch to existing AWS clap path
- Async isolated via internal `tokio::runtime::Runtime::new().block_on()`
- `src/ext/backend_adapter.rs`: 2 new match arms for `BuiltinBackendId::Aws`
- AWS credentials via ambient provider chain (no JSON creds; secret URI resolution = Phase B #2)

## Zero-touch guarantee

Explicit non-goals per spec: existing `src/aws.rs` pub fns (`resolve_config`, `ensure_aws_config`, `run_admin_tunnel`), `src/main.rs::run_aws`, `src/apply.rs`, and all other cloud backend files (`azure.rs`, `gcp.rs`, `terraform.rs`, etc.) receive zero line changes. Dispatch table in `deployment.rs` and `fixtures/packs/terraform/` reused as-is.

## Test plan

- [x] Unit tests: aws (6 new), backend_adapter (2 new + 2 updated), errors (1 updated) — all passing
- [x] Existing integration: `tests/aws_cli.rs` (7 tests) passes unchanged — zero regression
- [x] New ignored integration: `tests/ext_apply_integration.rs` (1 test, scoped for #4c fixture follow-up)
- [x] `ci/local_check.sh` all 9 gates green
- [x] `cargo build --no-default-features` baseline green
- [x] Manual: `greentic-deployer ext apply --target aws-ecs-fargate-local --help` wired

## Follow-up PR

`greentic-biz/greentic-deployer-extensions` — `feat/deploy-aws-0.1.0` branch ships `deploy-aws@0.1.0.gtxpack` ref ext (Phase B #4c). Merge this PR first, then that one.

## Spec & plan

- Spec: `docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`
- Plan: `docs/superpowers/plans/2026-04-19-phase-b-4b-4c-aws-ecs-fargate.md`
EOF
)" 2>&1 | tail -5
```

- [ ] **Step 8.4: Report PR URL**

Capture the URL from `gh pr create` output. Paste it in the session for user review.

---

## Phase B — `greentic-deployer-extensions` Tasks

Phase B ships the `deploy-aws@0.1.0` reference extension in the sibling repo. Work is in `/home/bimbim/works/greentic/greentic-deployer-extensions/` (adjust path if the repo lives elsewhere on the host machine).

## Task 9: Set up branch + scaffold `deploy-aws/` crate

**Files:**
- Create: `reference-extensions/deploy-aws/Cargo.toml`
- Create: `reference-extensions/deploy-aws/rust-toolchain.toml`
- Create: `reference-extensions/deploy-aws/.gitignore`

Work from: `/home/bimbim/works/greentic/greentic-deployer-extensions`

- [ ] **Step 9.1: Sync + create branch**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git fetch origin
git checkout main
git pull --ff-only origin main
git checkout -b feat/deploy-aws-0.1.0
```

- [ ] **Step 9.2: Create directory + Cargo.toml**

```bash
mkdir -p reference-extensions/deploy-aws/src
mkdir -p reference-extensions/deploy-aws/schemas
```

Create `reference-extensions/deploy-aws/Cargo.toml` with content:

```toml
[workspace]

[package]
name = "greentic-deploy-aws-extension"
version = "0.1.0"
edition = "2024"
license = "MIT"
publish = false
description = "Greentic deploy extension for AWS ECS Fargate targets"

[lib]
crate-type = ["cdylib", "rlib"]
path = "src/lib.rs"

[dependencies]
wit-bindgen = "0.41"
wit-bindgen-rt = "0.41"

[package.metadata.component]
package = "greentic:deploy-aws-extension"

[package.metadata.component.target]
path = "wit"
world = "deploy-extension"

[package.metadata.component.target.dependencies]
"greentic:extension-base"   = { path = "../../wit/extension-base.wit" }
"greentic:extension-host"   = { path = "../../wit/extension-host.wit" }
"greentic:extension-deploy" = { path = "../../wit/extension-deploy.wit" }
```

- [ ] **Step 9.3: Create rust-toolchain.toml**

Copy from `deploy-desktop`:

```bash
cp reference-extensions/deploy-desktop/rust-toolchain.toml reference-extensions/deploy-aws/rust-toolchain.toml
```

- [ ] **Step 9.4: Create .gitignore**

Create `reference-extensions/deploy-aws/.gitignore`:

```
/target
Cargo.lock
*.gtxpack
/wit
```

**Note on `wit` directory:** `deploy-desktop`'s build.sh copies wit files from `../../wit/` into a local `wit/` directory during build. We follow the same pattern; the generated `wit/` is gitignored.

- [ ] **Step 9.5: Commit**

```bash
git add reference-extensions/deploy-aws/Cargo.toml \
        reference-extensions/deploy-aws/rust-toolchain.toml \
        reference-extensions/deploy-aws/.gitignore
git commit -m "feat(deploy-aws): scaffold reference extension crate

Mirror deploy-desktop structure: empty workspace, cdylib+rlib lib,
wit-bindgen deps pointing to shared wit/ files in parent repo."
```

---

## Task 10: Add describe.json + schemas

**Files:**
- Create: `reference-extensions/deploy-aws/describe.json`
- Create: `reference-extensions/deploy-aws/schemas/aws-ecs-fargate.credentials.schema.json`
- Create: `reference-extensions/deploy-aws/schemas/aws-ecs-fargate.config.schema.json`

- [ ] **Step 10.1: Create describe.json**

```json
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": {
    "id": "greentic.deploy-aws",
    "name": "AWS Deploy",
    "version": "0.1.0",
    "summary": "AWS ECS Fargate deployment via Terraform",
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
        "id": "greentic:deploy/aws-ecs-fargate",
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
        "id": "aws-ecs-fargate-local",
        "displayName": "AWS ECS Fargate (local Terraform)",
        "description": "Deploy to AWS ECS+Fargate+ALB via Terraform using ambient AWS credentials",
        "execution": {
          "backend": "aws",
          "handler": null,
          "kind": "builtin"
        },
        "supportsRollback": true
      }
    ]
  }
}
```

- [ ] **Step 10.2: Create credentials schema (empty object — ambient creds)**

Create `reference-extensions/deploy-aws/schemas/aws-ecs-fargate.credentials.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AWS ECS Fargate credentials",
  "description": "Empty object. AWS credentials resolved via ambient AWS provider chain (env vars, ~/.aws/credentials, IAM instance profile, SSO).",
  "type": "object",
  "properties": {},
  "additionalProperties": false
}
```

- [ ] **Step 10.3: Create config schema (mirrors AwsEcsFargateExtConfig)**

Create `reference-extensions/deploy-aws/schemas/aws-ecs-fargate.config.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "AWS ECS Fargate deployment config",
  "type": "object",
  "required": [
    "region",
    "environment",
    "operatorImageDigest",
    "bundleSource",
    "bundleDigest",
    "remoteStateBackend"
  ],
  "properties": {
    "region": {
      "type": "string",
      "minLength": 1,
      "description": "AWS region (e.g., us-east-1)"
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
      "description": "Terraform remote state backend URI (e.g., s3://bucket/path)"
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

- [ ] **Step 10.4: Validate schemas parse as JSON**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions/reference-extensions/deploy-aws
jq empty describe.json
jq empty schemas/aws-ecs-fargate.credentials.schema.json
jq empty schemas/aws-ecs-fargate.config.schema.json
```

Expected: no output (all valid JSON).

- [ ] **Step 10.5: Commit**

```bash
git add reference-extensions/deploy-aws/describe.json \
        reference-extensions/deploy-aws/schemas/
git commit -m "feat(deploy-aws): add describe.json + credentials/config schemas

Single target 'aws-ecs-fargate-local' with backend=aws, handler=null
(AWS backend doesn't use handler variants in Phase B #4a+b).

Config schema mirrors AwsEcsFargateExtConfig in greentic-deployer
(required: region, environment, operatorImageDigest, bundleSource,
bundleDigest, remoteStateBackend). Creds schema is empty object —
AWS credentials resolved via ambient provider chain."
```

---

## Task 11: Add WASM Guest impl (`src/lib.rs`)

**Files:**
- Create: `reference-extensions/deploy-aws/src/lib.rs`

- [ ] **Step 11.1: Create lib.rs**

Content (mirrors `deploy-desktop/src/lib.rs` structure, single target):

```rust
//! greentic.deploy-aws — reference deploy extension for AWS ECS Fargate.
//!
//! Mode A only: metadata + schemas served here; deployer host routes actual
//! deploy/poll/rollback to its built-in `aws` backend. See parent spec
//! `greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`.

#[allow(warnings)]
mod bindings;

use bindings::exports::greentic::extension_base::{lifecycle, manifest};
use bindings::exports::greentic::extension_deploy::{deployment, targets};
use bindings::greentic::extension_base::types;

const CREDS_SCHEMA: &str = include_str!("../schemas/aws-ecs-fargate.credentials.schema.json");
const CONFIG_SCHEMA: &str = include_str!("../schemas/aws-ecs-fargate.config.schema.json");

const TARGET_AWS_ECS_FARGATE: &str = "aws-ecs-fargate-local";

struct Component;

impl manifest::Guest for Component {
    fn get_identity() -> types::ExtensionIdentity {
        types::ExtensionIdentity {
            id: "greentic.deploy-aws".into(),
            version: "0.1.0".into(),
            kind: types::Kind::Deploy,
        }
    }

    fn get_offered() -> Vec<types::CapabilityRef> {
        vec![types::CapabilityRef {
            id: "greentic:deploy/aws-ecs-fargate".into(),
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
            id: TARGET_AWS_ECS_FARGATE.into(),
            display_name: "AWS ECS Fargate (local Terraform)".into(),
            description: "Deploy to AWS ECS+Fargate+ALB via Terraform using ambient AWS credentials".into(),
            icon_path: None,
            supports_rollback: true,
        }]
    }

    fn credential_schema(target_id: String) -> Result<String, types::ExtensionError> {
        match target_id.as_str() {
            TARGET_AWS_ECS_FARGATE => Ok(CREDS_SCHEMA.into()),
            other => Err(types::ExtensionError::InvalidInput(format!(
                "unknown target: {other}"
            ))),
        }
    }

    fn config_schema(target_id: String) -> Result<String, types::ExtensionError> {
        match target_id.as_str() {
            TARGET_AWS_ECS_FARGATE => Ok(CONFIG_SCHEMA.into()),
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
            TARGET_AWS_ECS_FARGATE => vec![],
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
            "deploy-aws uses Mode A builtin execution; dispatcher should route via \
             backend=aws, not WASM"
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
git add reference-extensions/deploy-aws/src/lib.rs
git commit -m "feat(deploy-aws): add WASM Guest impl for AWS ECS Fargate target

Mode A only: metadata + schemas exposed; deploy/poll/rollback return
Internal error pointing at host routing via backend=aws. Mirrors
deploy-desktop pattern, single target."
```

---

## Task 12: Add build.sh + build + sign

**Files:**
- Create: `reference-extensions/deploy-aws/build.sh`

- [ ] **Step 12.1: Copy build.sh from deploy-desktop + adjust**

```bash
cp reference-extensions/deploy-desktop/build.sh reference-extensions/deploy-aws/build.sh
```

Edit `reference-extensions/deploy-aws/build.sh`. Replace occurrences:
- `greentic.deploy-desktop` → `greentic.deploy-aws`
- `greentic_deploy_desktop_extension.wasm` → `greentic_deploy_aws_extension.wasm`

- [ ] **Step 12.2: Make build.sh executable**

```bash
chmod +x reference-extensions/deploy-aws/build.sh
```

- [ ] **Step 12.3: Run build.sh locally (produces unsigned .gtxpack)**

```bash
cd reference-extensions/deploy-aws
./build.sh 2>&1 | tail -30
```

Expected: `greentic.deploy-aws-0.1.0.gtxpack` produced (unsigned — local dev mode). Build logs show: cargo component build → wasm-tools validate → zip.

If build fails due to missing `cargo-component`, `wasm-tools`, `jq`, or `zip`:
- `cargo install cargo-component --locked`
- `cargo install wasm-tools --locked`
- Install `jq` and `zip` via system package manager

- [ ] **Step 12.4: Verify zip contents**

```bash
unzip -l reference-extensions/deploy-aws/greentic.deploy-aws-0.1.0.gtxpack
```

Expected to see: `describe.json`, `schemas/*`, `extension.wasm`.

- [ ] **Step 12.5: Commit build.sh (not the .gtxpack artifact)**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git add reference-extensions/deploy-aws/build.sh
git commit -m "feat(deploy-aws): add build.sh for reproducible .gtxpack

Mirrors deploy-desktop build.sh: validate schemas, cargo component
build, wasm-tools validate, env-aware signing (GREENTIC_EXT_SIGNING_KEY_PEM
from CI secret), zip to .gtxpack. Dev mode ships unsigned with
runtime rejecting unless GREENTIC_EXT_ALLOW_UNSIGNED=1."
```

---

## Task 13: Extend CI workflow + push + open ref ext PR

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 13.1: Extend release.yml with deploy-aws build**

Read the existing workflow:

```bash
cat .github/workflows/release.yml
```

Find the existing deploy-desktop build step/job (look for `deploy-desktop` occurrences — they typically appear in a matrix, build script invocation, or artifact upload). Add `deploy-aws` parallel entries. The edit is mechanical; mirror whatever pattern `deploy-single-vm` uses since it was added in Wave 2 with the same type of pattern.

**If the workflow uses a matrix** (e.g., `strategy.matrix.extension: [deploy-desktop, deploy-single-vm]`):

```yaml
strategy:
  matrix:
    extension: [deploy-desktop, deploy-single-vm, deploy-aws]
```

**If the workflow has explicit jobs per extension**, duplicate the `deploy-single-vm` job block and rename to `deploy-aws`, adjusting paths.

- [ ] **Step 13.2: Verify workflow YAML syntax locally**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
```

Expected: no output (valid YAML).

- [ ] **Step 13.3: Commit workflow update**

```bash
git add .github/workflows/release.yml
git commit -m "ci(deploy-aws): extend release workflow to build+sign deploy-aws

Mirror deploy-desktop / deploy-single-vm pattern. CI_REQUIRE_SIGNED
guardrail applies on main push."
```

- [ ] **Step 13.4: Final verification**

```bash
cd reference-extensions/deploy-aws
./build.sh 2>&1 | tail -10
```

Expected: successful rebuild of `.gtxpack`.

- [ ] **Step 13.5: Push branch**

```bash
cd /home/bimbim/works/greentic/greentic-deployer-extensions
git push -u origin feat/deploy-aws-0.1.0 2>&1 | tail -5
```

- [ ] **Step 13.6: Open PR**

```bash
gh pr create --title "feat(deploy-aws): ship deploy-aws@0.1.0 reference extension" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4c per `greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`
- New reference extension `deploy-aws@0.1.0.gtxpack` with single target `aws-ecs-fargate-local`
- Backend `aws`, handler `null`, execution kind `builtin` (Mode A)
- Pairs with `greentic-deployer` PR (Phase B #4b) which wires the AWS backend in `ext apply/destroy`

## Architecture

- `reference-extensions/deploy-aws/` — new crate mirroring `deploy-desktop@0.2.0` structure
- Single target: `aws-ecs-fargate-local`
- Config schema: required `region, environment, operatorImageDigest, bundleSource, bundleDigest, remoteStateBackend`; optional DNS/URL/registry bases, tenant
- Credentials schema: empty object — AWS creds via ambient provider chain (env / ~/.aws / IAM)

## Test plan

- [x] `jq` validates describe.json + both schemas as JSON
- [x] `cargo component build --release --locked --target wasm32-wasip1` succeeds
- [x] `wasm-tools validate` passes
- [x] `./build.sh` produces `.gtxpack` archive containing describe.json + schemas + extension.wasm
- [ ] CI produces signed artifact on push to main (gated by `EXT_SIGNING_KEY_PEM` secret)
- [ ] End-to-end verification with `greentic-deployer` Phase B #4b PR (merge deployer first)

## Merge order

1. Merge `greenticai/greentic-deployer` Phase B #4b PR first
2. Merge this PR second
3. Optionally unignore the integration test in the deployer repo after this is published

## Spec & plan

- Spec: `greentic-deployer/docs/superpowers/specs/2026-04-19-phase-b-4b-4c-aws-ecs-fargate-design.md`
- Plan: `greentic-deployer/docs/superpowers/plans/2026-04-19-phase-b-4b-4c-aws-ecs-fargate.md` (Tasks 9–13)
EOF
)" 2>&1 | tail -5
```

- [ ] **Step 13.7: Report both PR URLs**

Output both PR URLs (Phase A + Phase B) for user review.

---

## Self-Review Checklist (for plan author)

**Spec coverage:**
- §2 Q1–Q5 design decisions → Tasks 1–5 ✓
- §3 Architecture (adapter match arms, thin wrapper, async isolation) → Tasks 2, 4 ✓
- §4.1 aws.rs additions (struct, helper, apply/destroy) → Tasks 1, 2 ✓
- §4.2 backend_adapter match arms + updated message → Tasks 4, 5 ✓
- §4.3 ignored integration test → Task 6 ✓
- §4.4 ref ext crate → Tasks 9, 10, 11 ✓
- §4.5 ref ext CI workflow → Task 13 ✓
- §5 data flow → exercised via Tasks 2, 4 (adapter+cli) ✓
- §6 error handling → Tasks 2, 4 (BackendExecutionFailed wrapping), Task 5 (AdapterNotImplemented message) ✓
- §7.1 aws.rs unit tests (6) → Tasks 1, 2 ✓
- §7.2 backend_adapter unit tests (2 new + 1 updated) → Task 4 ✓
- §7.3 ignored integration → Task 6 ✓
- §7.4 existing aws_cli.rs relied upon → Task 3 (explicit checkpoint) ✓
- §7.5 ref ext tests → implicit in Tasks 11, 12 (describe.json roundtrip via build.sh's jq check + wasm-tools validate)
- §8 acceptance criteria 1–11 → verified via Tasks 3, 7 (local CI), 8 (PR) ✓

**Placeholder scan:**
- No TBD/TODO/"implement later" in code blocks ✓
- Task 13 Step 13.1 acknowledges "if matrix / if explicit jobs" branch — this is judgment based on unseen workflow file. Appropriate for the situation since the actual workflow shape will be read at exec time.
- Commit messages literal and complete ✓

**Type consistency:**
- `AwsEcsFargateExtConfig` field names consistent Tasks 1, 2, 10, 11 ✓
- `apply_from_ext`/`destroy_from_ext` signatures: `(config_json: &str, _creds_json: &str, pack_path: Option<&Path>) -> anyhow::Result<()>` consistent Tasks 2, 4 ✓
- `build_aws_request_from_ext(capability, cfg, pack_path) -> AwsRequest` consistent Task 2 ✓
- `default_ext_tenant` fn name consistent Task 1 ✓
- `TARGET_AWS_ECS_FARGATE` const name consistent Task 11 ✓
- `BuiltinBackendId::Aws` / `::Gcp` / `::Azure` usage consistent Tasks 4, 5 ✓

**Scope coverage verified — plan is complete.**
