# Phase B #4b + #4c — AWS ECS Fargate Deploy Extension

- **Date:** 2026-04-19
- **Status:** Draft, pending user review
- **Branch:** `spec/phase-b-4b-4c-aws-ecs-fargate`
- **Owner:** TBD
- **Related:**
  - Parent: `memory/deploy-extension-next-steps.md` (Phase B #4b/#4c)
  - Phase B #4a (MERGED): `docs/superpowers/specs/2026-04-19-phase-b-4a-deployer-cli-wiring-design.md`
  - Phase B #4a plan (MERGED): `docs/superpowers/plans/2026-04-19-phase-b-4a-ext-cli-wiring.md`
  - Ref exts repo: `greentic-biz/greentic-deployer-extensions` (ships `deploy-desktop@0.2.0`, `deploy-single-vm@0.1.0`, will ship `deploy-aws@0.1.0`)
  - Reused pack fixture: `greentic-deployer/fixtures/packs/terraform/` (cloud-aware, `greentic.deploy.aws` pack_id)

## 1. Context & motivation

### Current state after Phase B #4a (merged 2026-04-19)

`ext apply --target X` routes via `src/ext/backend_adapter.rs` to `Desktop` and `SingleVm` backends. For `Aws`/`Gcp`/`Azure`/`Terraform`/etc., the adapter returns `AdapterNotImplemented` with a "Phase B #4a supports: Desktop, SingleVm" message. `deploy-desktop@0.2.0` and `deploy-single-vm@0.1.0` ref exts are signed + shipping.

### Goal

Make `greentic-deployer ext apply --target aws-ecs-fargate-local ...` actually deploy to AWS via the existing `greentic.deploy.aws` pack (which wraps the `fixtures/packs/terraform/` modules). Ship a new `deploy-aws@0.1.0.gtxpack` ref ext. Validate the extension → cloud story end-to-end for one cloud.

Two sub-projects tracked together in one spec (combined PR strategy per Phase B #4a precedent):
- **Phase B #4b** — `greentic-deployer` changes: AWS match arms in `backend_adapter`, new `aws::apply_from_ext` / `destroy_from_ext` entry points.
- **Phase B #4c** — `greentic-biz/greentic-deployer-extensions` changes: new `deploy-aws/` ref ext crate.

### Hard non-negotiable constraint

**Existing `greentic-deployer` cloud paths must remain bit-for-bit untouched.** No changes to:
- `src/aws.rs` existing pub fns (`resolve_config`, `ensure_aws_config`, `run_admin_tunnel`)
- `src/main.rs` clap `run_aws` path
- `src/apply.rs` (`apply::run`)
- `src/deployment.rs` dispatch table
- `fixtures/packs/terraform/` modules

User explicitly called this out: they didn't author the existing deployer and want zero regression risk from this feature.

### Non-goals

- No Mode B (`execution.kind: "wasm"`) — Phase B #2.
- No `host::http`/`host::secrets`/`host::storage` — Phase B #2.
- No secret URI resolution — secrets injected via ambient AWS credential chain (env vars, `~/.aws/credentials`, IAM), not via `secrets://...` URIs.
- No new AWS target variants — single target `aws-ecs-fargate-local` only. EKS / Lambda / production env split deferred.
- No new pack authoring — reuse existing `greentic.deploy.aws` pack (multi-cloud-aware via `cloud: aws|azure|gcp` input).
- No GCP / Azure ref exts — Phase B #4d.
- No preview/dry-run flag on `ext apply` path — user who wants preview uses built-in `greentic-deployer aws plan`.

## 2. Design decisions (from brainstorming)

| # | Question | Decision | Reason |
|---|---|---|---|
| Q1 | Pack scope | A: Reuse existing `greentic.deploy.aws` pack (cloud-aware) | YAGNI; pack already tested + multi-cloud. Dispatch table already references this pack_id. |
| Q2 | Ref ext target count | A: Single `aws-ecs-fargate-local` | First ship validates pattern; expand to ECS-prod/EKS/Lambda in 0.2.0 if demand. |
| Q3 | AWS credentials | C: Region required in config; creds from ambient AWS provider chain | Matches real AWS CLI UX. `aws configure` users need no JSON creds. Secret URI resolution = Phase B #2. |
| Q4 | Config JSON shape | B: Narrow `AwsEcsFargateExtConfig` Rust wrapper; `cloud: "aws"` inferred from target id | Consistent with Phase B #4a `SingleVmExtConfig` pattern. |
| Q5 | Execution path | A: Thin wrapper; delegate to existing `resolve_config` + `apply::run` | Maximum code reuse, zero touch existing logic. Async handled via internal `tokio::runtime::Runtime::new().block_on()`. |

## 3. Architecture

```
┌─ Existing Phase B #4a path (UNCHANGED) ──────────────────────────────┐
│   ext::cli::run_apply(args)                                          │
│      → dispatch_extension(reg, invoker, input) → Builtin(bridge)     │
│      → backend_adapter::run(bridge.backend, handler, ExtAction, …)   │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ src/ext/backend_adapter.rs (EXTENDED) ──────────────────────────────┐
│   match (backend, action) {                                          │
│     (Desktop, ...) UNCHANGED                                         │
│     (SingleVm, ...) UNCHANGED                                        │
│     (Aws, Apply)   => aws::apply_from_ext(json, creds, pack_path)    │  ← NEW
│     (Aws, Destroy) => aws::destroy_from_ext(json, creds, pack_path)  │  ← NEW
│     _ => AdapterNotImplemented                                       │
│   }                                                                  │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ src/aws.rs (ADDITIVE ONLY) ─────────────────────────────────────────┐
│   existing:   pub fn resolve_config(AwsRequest) -> Result<...>       │
│   existing:   pub fn ensure_aws_config(...)                          │
│   existing:   pub fn run_admin_tunnel(...)                           │
│   NEW:        pub struct AwsEcsFargateExtConfig                      │
│   NEW:        pub fn apply_from_ext(config_json, _creds, pack_path)  │
│                 1. parse JSON → AwsEcsFargateExtConfig               │
│                 2. build AwsRequest { capability: Apply, ... }       │
│                 3. resolve_config(req) → DeployerConfig              │
│                 4. tokio::runtime::Runtime::new()                    │
│                 5.   .block_on(apply::run(cfg))     │
│                 6. drop OperationResult → Ok(())                     │
│   NEW:        pub fn destroy_from_ext(config_json, _creds, pack_path)│
│                 (same with capability: Destroy)                      │
└───────────────────┬──────────────────────────────────────────────────┘
                    │
                    ▼
┌─ Existing deploy pipeline (ENTIRELY UNCHANGED) ──────────────────────┐
│   apply::run → terraform plan/apply                 │
│   pack discovery → greentic.deploy.aws (reuses fixtures/packs/…)     │
└──────────────────────────────────────────────────────────────────────┘
```

**Async isolation:** Adapter and CLI layers are sync. AWS deploy is async. `aws::apply_from_ext` creates its own tokio runtime and `block_on`s internally. Async never leaks to the adapter interface.

## 4. Components & files

### 4.1 `greentic-deployer` — `src/aws.rs` additions (~100 impl + ~60 tests)

New Deserialize struct (placed after existing request types):

```rust
#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default = "default_tenant")]
    pub tenant: String,
}

fn default_tenant() -> String {
    "default".to_string()
}
```

New private helper (dedupes AwsRequest construction between apply/destroy):

```rust
fn build_aws_request_from_ext(
    capability: DeployerCapability,
    cfg: &AwsEcsFargateExtConfig,
    pack_path: Option<&Path>,
) -> AwsRequest {
    AwsRequest {
        capability,
        tenant: cfg.tenant.clone(),
        pack_path: pack_path.map(Path::to_path_buf).unwrap_or_default(),
        bundle_source: Some(cfg.bundle_source.clone()),
        bundle_digest: Some(cfg.bundle_digest.clone()),
        repo_registry_base: cfg.repo_registry_base.clone(),
        store_registry_base: cfg.store_registry_base.clone(),
        provider_pack: None,  // pack discovery uses providers_dir/packs_dir
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
        execute_local: true,  // ext path executes directly, no remote runner
        output: crate::config::OutputFormat::Text,
        config_path: None,
        allow_remote_in_offline: false,
        providers_dir: PathBuf::from("providers/deployer"),
        packs_dir: PathBuf::from("packs"),
    }
}
```

**Note:** this helper's field population may need adjustment once we inspect the exact `AwsRequest` struct definition during implementation. The plan step will verify each field. Any field we miss gets flagged immediately by the compiler. Fields that don't have an ext-path equivalent get sensible defaults (`None` / `false` / defaults).

New public entry points:

```rust
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AwsEcsFargateExtConfig = serde_json::from_str(config_json)
        .context("parse aws ecs-fargate config JSON")?;
    let request = build_aws_request_from_ext(DeployerCapability::Apply, &cfg, pack_path);
    let config = resolve_config(request).context("resolve AWS deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for AWS deploy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run AWS deployment pipeline")?;
    Ok(())
}

pub fn destroy_from_ext(
    config_json: &str,
    _creds_json: &str,
    pack_path: Option<&Path>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let cfg: AwsEcsFargateExtConfig = serde_json::from_str(config_json)
        .context("parse aws ecs-fargate config JSON")?;
    let request = build_aws_request_from_ext(DeployerCapability::Destroy, &cfg, pack_path);
    let config = resolve_config(request).context("resolve AWS deployer config")?;
    let rt = tokio::runtime::Runtime::new().context("create tokio runtime for AWS destroy")?;
    let _outcome = rt
        .block_on(crate::apply::run(config))
        .context("run AWS destroy pipeline")?;
    Ok(())
}
```

**`_creds_json` unused:** AWS provider uses ambient creds (Q3). Prefix with `_` signals intent. Future secret URI resolution (Phase B #2) will populate this.

Unit tests in existing `#[cfg(test)] mod tests`: 6 tests covering JSON parse, required field validation, apply/destroy parse-error paths. Listed in §7.1.

### 4.2 `greentic-deployer` — `src/ext/backend_adapter.rs` additions (~35 LoC)

Add 2 match arms before `_ =>`:

```rust
(BuiltinBackendId::Aws, ExtAction::Apply) => {
    crate::aws::apply_from_ext(config_json, creds_json, pack_path)
        .map_err(|e| ExtensionError::BackendExecutionFailed {
            backend,
            source: e,
        })
}
(BuiltinBackendId::Aws, ExtAction::Destroy) => {
    crate::aws::destroy_from_ext(config_json, creds_json, pack_path)
        .map_err(|e| ExtensionError::BackendExecutionFailed {
            backend,
            source: e,
        })
}
```

Update `AdapterNotImplemented` error message in `src/ext/errors.rs` to reflect expanded scope:

```rust
#[error(
    "backend '{backend:?}' has no execution adapter wired (supported: Desktop, SingleVm, Aws)"
)]
AdapterNotImplemented { backend: BuiltinBackendId },
```

Add 2 new unit tests in `backend_adapter::tests`:
- `aws_invalid_config_surfaces_as_backend_execution_failed`
- `aws_destroy_invalid_config_surfaces_as_backend_execution_failed`

Update existing `unsupported_backend_returns_adapter_not_implemented_apply` to use `BuiltinBackendId::Gcp` (was `Aws`); same for Destroy variant.

### 4.3 `greentic-deployer` — `tests/ext_apply_integration.rs` additions (~30 LoC)

Add 1 `#[ignore]` test scoped for when `deploy-aws` fixture lands:

```rust
#[test]
#[ignore = "unignore when deploy-aws fixture lands in testdata/ext/"]
fn ext_apply_aws_target_requires_required_config_fields() {
    // ...
}
```

Ignored because: adding `deploy-aws` fixture to this repo's `testdata/ext/` crosses repo boundaries (ref ext lives in `greentic-deployer-extensions`). Unignore when #4c ships and we copy a stub describe.json + WASM into testdata for dedicated adapter-level testing. Not blocking.

### 4.4 `greentic-biz/greentic-deployer-extensions` — new `deploy-aws/` ref ext crate

Directory structure (mirrors `deploy-desktop@0.2.0` and `deploy-single-vm@0.1.0`):

```
reference-extensions/deploy-aws/
├── Cargo.toml                  # [workspace] empty table, version 0.1.0
├── build.sh                    # env-aware: gtdx sign + package .gtxpack
├── describe.json               # unsigned source
├── describe.signed.json        # output of `gtdx sign` (committed for reproducibility)
├── src/lib.rs                  # minimal Guest impl — schemas + validate_credentials
└── schemas/
    ├── creds.schema.json       # empty object
    └── config.schema.json      # mirrors AwsEcsFargateExtConfig
```

**`describe.json`:**

```json
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": {
    "id": "greentic.deploy-aws",
    "version": "0.1.0",
    "summary": "Deploy Greentic bundles to AWS ECS Fargate via Terraform"
  },
  "engine": {
    "greenticDesigner": "*",
    "extRuntime": ">=0.5.0"
  },
  "capabilities": {},
  "runtime": {
    "component": "extension.wasm",
    "permissions": {}
  },
  "contributions": {
    "targets": [{
      "id": "aws-ecs-fargate-local",
      "displayName": "AWS ECS Fargate (local Terraform execution)",
      "description": "Provisions AWS ECS+Fargate+ALB via Terraform using ambient AWS credentials",
      "supportsRollback": true,
      "execution": {
        "kind": "builtin",
        "backend": "aws",
        "handler": null
      }
    }]
  }
}
```

**`schemas/creds.schema.json`** (empty object — ambient creds):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {},
  "additionalProperties": false
}
```

**`schemas/config.schema.json`** (mirrors Rust struct 1:1):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["region", "environment", "operatorImageDigest", "bundleSource", "bundleDigest", "remoteStateBackend"],
  "properties": {
    "region":               { "type": "string", "minLength": 1 },
    "environment":          { "type": "string", "minLength": 1 },
    "operatorImageDigest":  { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
    "bundleSource":         { "type": "string", "minLength": 1 },
    "bundleDigest":         { "type": "string", "pattern": "^sha256:[a-f0-9]{64}$" },
    "remoteStateBackend":   { "type": "string", "minLength": 1 },
    "dnsName":              { "type": "string" },
    "publicBaseUrl":        { "type": "string" },
    "repoRegistryBase":     { "type": "string" },
    "storeRegistryBase":    { "type": "string" },
    "adminAllowedClients":  { "type": "string" },
    "tenant":               { "type": "string" }
  },
  "additionalProperties": false
}
```

**`src/lib.rs`:** minimal WASM Guest impl. Returns schemas as bundled strings, `validate_credentials` returns empty diagnostics (ambient creds). Mirrors `deploy-desktop/src/lib.rs` pattern.

**`build.sh`:** mirrors `deploy-desktop` — `cargo build --target wasm32-wasip2 --release`, `wasm-tools component new`, `gtdx sign` (reads `EXT_SIGNING_KEY_PEM` from env), zip to `deploy-aws-0.1.0.gtxpack`.

**`Cargo.toml`:**

```toml
[package]
name = "deploy-aws"
version = "0.1.0"
edition = "2024"
publish = false

[workspace]

[lib]
crate-type = ["cdylib"]

[dependencies]
# Same shape as deploy-desktop
greentic-ext-contract = { git = "...", rev = "94e6ba4" }
# ...
```

### 4.5 `greentic-biz/greentic-deployer-extensions` — CI workflow extension

Extend `.github/workflows/release.yml` to build + sign + publish `deploy-aws-0.1.0.gtxpack` alongside existing `deploy-desktop@0.2.0` and `deploy-single-vm@0.1.0`. `CI_REQUIRE_SIGNED` guardrail (Wave 2) applies.

### 4.6 Delta summary

| Repo / file | LoC delta |
|---|---|
| `greentic-deployer/src/aws.rs` | +~160 (~100 impl + ~60 tests) |
| `greentic-deployer/src/ext/backend_adapter.rs` | +~35 |
| `greentic-deployer/src/ext/errors.rs` | ~3 (message text update) |
| `greentic-deployer/tests/ext_apply_integration.rs` | +~30 (ignored) |
| **Deployer PR total** | **~225** |
| `greentic-deployer-extensions/reference-extensions/deploy-aws/` (NEW) | +~250 (all new) |
| **Total across 2 PRs** | **~475 LoC** |

### 4.7 Files EXPLICITLY unchanged

- `src/main.rs` — all clap paths including `run_aws`
- `src/apply.rs` — `apply::run` entry
- `src/azure.rs`, `src/gcp.rs`, `src/terraform.rs`, `src/helm.rs`, etc.
- `src/deployment.rs` — dispatch table stays as-is
- `fixtures/packs/terraform/` — reused as-is
- `src/desktop.rs`, `src/single_vm.rs` — Phase B #4a untouched
- `src/ext/dispatcher.rs`, `src/ext/cli.rs` — Phase B #4a untouched
- All existing tests

## 5. Data flow

### 5.1 Happy path (apply)

User prerequisites (outside our tool):
1. `aws configure` done (or `AWS_ACCESS_KEY_ID` / `~/.aws/credentials`)
2. `terraform` binary on PATH
3. `deploy-aws-0.1.0.gtxpack` installed in `~/.greentic/extensions/deploy/`
4. `greentic.deploy.aws.gtpack` in `./packs/` or `./providers/deployer/` (or `--pack` flag)

```bash
greentic-deployer ext apply \
  --target aws-ecs-fargate-local \
  --creds creds.json \
  --config config.json \
  --ext-dir ~/.greentic/extensions/deploy
```

`creds.json`: `{}`

`config.json`:

```json
{
  "region": "us-east-1",
  "environment": "staging",
  "operatorImageDigest": "sha256:abcd...64hex",
  "bundleSource": "oci://registry.example/acme/prod-bundle@sha256:...",
  "bundleDigest": "sha256:ef01...64hex",
  "remoteStateBackend": "s3://my-tf-state-bucket/greentic/staging"
}
```

### 5.2 Sequence

```
1. clap → TopLevelCommand::Ext(ExtCommand{ command: Apply(args) })
2. main.rs → ext::cli::run(cmd) → ext::cli::run_apply(&dir, args)
3. fs::read_to_string(creds_path) → creds_json = "{}"
4. fs::read_to_string(config_path) → config_json = <JSON>
5. scan(&ext_dir) → [LoadedExtension{greentic.deploy-aws}]
6. ExtensionRegistry::build(...) ; WasmtimeInvoker::new(&[ext_root])
7. dispatch_extension(reg, invoker, DispatchInput{target: "aws-ecs-fargate-local", ...})
   a. Validate creds against empty schema (passes)
   b. Validate config against AwsEcsFargateExtConfig schema (required fields checked)
   c. WASM validate_credentials returns []
   d. Return DispatchAction::Builtin(BridgeResolved{backend: Aws, handler: None})
8. backend_adapter::run(Aws, None, ExtAction::Apply, creds_json, config_json, None)
9. → aws::apply_from_ext(config_json, creds_json, None)
10.  a. parse config_json → AwsEcsFargateExtConfig
     b. build_aws_request_from_ext(Apply, &cfg, None) → AwsRequest
     c. aws::resolve_config(request)? → DeployerConfig (pack discovery + contract read)
     d. tokio::runtime::Runtime::new()?
     e. rt.block_on(apply::run(config))? → OperationResult
     f. drop OperationResult, return Ok(())
11. Exit 0
```

### 5.3 Destroy flow

Identical to 5.2 through step 8, then `ExtAction::Destroy` → `destroy_from_ext` → same underlying `apply::run` with `capability: Destroy` (terraform destroy).

### 5.4 Pack discovery

Handled by existing `find_pack_for_dispatch` in `src/deployment.rs`. Search order (unchanged):

1. `--pack` CLI arg if provided (via `pack_path` → `provider_pack` field)
2. `config.providers_dir` (default `providers/deployer/`)
3. `config.packs_dir` (default `packs/`)
4. `dist/`, `examples/`

### 5.5 What `apply::run` does (existing, unchanged)

1. Reads pack manifest + contract from resolved pack
2. Resolves `flow_id` for capability (`apply_terraform` for Apply, `destroy_terraform` for Destroy)
3. Executes flow — terraform `init` + `plan` + `apply`/`destroy`
4. AWS provider uses ambient creds
5. Streams output to stdout
6. Returns `OperationResult` (discarded by our path)

## 6. Error handling

### 6.1 Error matrix

| Layer | Scenario | Variant |
|---|---|---|
| CLI | Creds/config file missing | `CredsReadError` / `ConfigReadError` (existing Phase B #4a) |
| Dispatcher | Target not in registry | `TargetNotFound` |
| Dispatcher | Config schema violation | `ValidationFailed` |
| Dispatcher | Mode B target | `ModeBNotImplemented` |
| Adapter | Config JSON parse error | `BackendExecutionFailed { backend: Aws, source }` |
| Adapter | Missing required field | `BackendExecutionFailed { backend: Aws, source }` (serde error via `anyhow::Error::from`) |
| Adapter | Pack not found | `BackendExecutionFailed { backend: Aws, source }` (wraps `DeployerError` from `resolve_config`) |
| Adapter | Tokio runtime creation fails | `BackendExecutionFailed { backend: Aws, source }` (via `.context()`) |
| Adapter | Terraform CLI failure (AWS API denies, plan error) | `BackendExecutionFailed { backend: Aws, source }` |
| Adapter | Ambient AWS creds missing | Propagated from terraform as standard error, in source chain |

### 6.2 No new error variants

Phase B #4a already ships `CredsReadError`, `ConfigReadError`, `AdapterNotImplemented`, `BackendExecutionFailed`. Phase B #4b/#4c only adds code that produces existing variants.

### 6.3 Example error output

```
Error: backend 'Aws' execution failed: pack 'greentic.deploy.aws' not found; searched providers-dir (providers/deployer), packs-dir (packs), dist, examples (candidates: none)
```

```
Error: backend 'Aws' execution failed: parse aws ecs-fargate config JSON: missing field `region` at line 2 column 3
```

```
Error: backend 'Aws' execution failed: run AWS deployment pipeline: terraform apply: Error: No valid credential sources found. Please see https://...
```

### 6.4 Non-goals

- No retry logic — Phase B #4a precedent; backend failures propagate once
- No structured error codes — string messages only
- No partial-apply rollback from adapter — user re-runs `ext destroy`

## 7. Testing strategy

### 7.1 Unit tests — `src/aws.rs` (6 new)

```rust
#[test]
fn ext_config_parses_minimum_fields() { /* all required populated, optionals defaulted */ }

#[test]
fn ext_config_accepts_all_optionals() { /* DNS + public URL + registries populated */ }

#[test]
fn ext_config_rejects_missing_region() { /* serde error mentions region */ }

#[test]
fn apply_from_ext_rejects_invalid_json() { /* "not json" → parse error */ }

#[test]
fn apply_from_ext_rejects_missing_required_field() { /* partial JSON → missing field error */ }

#[test]
fn destroy_from_ext_rejects_invalid_json() { /* parse path error */ }
```

**No happy-path unit test** — requires terraform binary + real pack discovery. Covered by existing `tests/aws_cli.rs` integration suite (fake terraform bin + `build_provider_gtpack("terraform", ..., "greentic.deploy.aws")`).

### 7.2 Unit tests — `src/ext/backend_adapter.rs` (2 new + 1 updated)

```rust
#[test]
fn aws_invalid_config_surfaces_as_backend_execution_failed() { /* Aws+Apply+"not json" */ }

#[test]
fn aws_destroy_invalid_config_surfaces_as_backend_execution_failed() { /* Aws+Destroy+"not json" */ }
```

**Update existing:** `unsupported_backend_returns_adapter_not_implemented_apply` — swap `Aws` → `Gcp` (Aws is now supported). Same for Destroy variant.

### 7.3 Integration tests — 1 new, ignored

`tests/ext_apply_integration.rs` gains one `#[ignore]` test scoped for when `testdata/ext/greentic.deploy-aws-stub/` lands. Keeps reminder without blocking on cross-repo fixture authoring.

### 7.4 Existing integration suite — relied upon (no changes)

`tests/aws_cli.rs` already verifies built-in `greentic-deployer aws apply/plan/generate` via fake terraform bin. Since `apply_from_ext` delegates to the same `resolve_config` + `apply::run` path, existing coverage transitively covers the adapter path's core deploy flow.

### 7.5 Ref ext repo tests (#4c)

In `greentic-biz/greentic-deployer-extensions/reference-extensions/deploy-aws/`:

1. `tests/` in crate — describe.json roundtrip, schema parses example JSON matching `AwsEcsFargateExtConfig`. Mirror `deploy-desktop` test structure (~3 tests).
2. CI workflow — same pattern as `deploy-desktop`: `gtdx sign` check, artifact upload.
3. `CI_REQUIRE_SIGNED` guardrail (Wave 2) — reject unsigned push to main.

### 7.6 CLI smoke tests

No new smoke tests. AWS-specific behavior goes through JSON config (no new flags). Existing `ext apply --help` / missing args / unknown target coverage is backend-agnostic.

### 7.7 Explicit out-of-scope

- Real AWS deploy in CI
- Cross-cloud (GCP/Azure via same pack)
- Performance/load testing
- Multi-tenant state file conflict testing

## 8. Acceptance criteria

Ship PR when all hold:

1. `greentic-deployer ext apply --target aws-ecs-fargate-local --creds creds.json --config config.json` dispatches to `aws::apply_from_ext` (verified by adding `eprintln!("[ext] aws apply path")` temporarily and removing before commit, OR by observing terraform CLI invocation in logs).
2. `--config` with invalid JSON → non-zero exit, stderr shows "parse aws ecs-fargate config JSON" + serde error.
3. `--config` with missing required field → non-zero exit, stderr surfaces the field name.
4. `--config` with no pack on disk → non-zero exit, stderr shows "pack 'greentic.deploy.aws' not found; searched ...".
5. `ext apply --target <unknown-aws-variant>` → `TargetNotFound` error (unchanged from Phase B #4a).
6. Existing `greentic-deployer aws apply ...` clap CLI path produces bit-for-bit identical output to pre-change (`cargo test --test aws_cli` passes).
7. All existing tests pass (`cargo test` with and without `--features extensions`).
8. `cargo fmt --check` + `cargo clippy -D warnings` green with `--features extensions`.
9. `cargo build --no-default-features` (baseline, no `extensions` feature) still green.
10. `ci/local_check.sh` all 9 gates pass.
11. Ref ext repo (`deploy-aws@0.1.0`) builds, signs, publishes to GitHub release assets via CI.

## 9. Rollout & risk

### 9.1 Risk matrix

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `AwsRequest` field shape diverges from what helper constructs | Medium | Medium | Plan step verifies each field against `src/aws.rs` actual struct; compiler catches missing fields. |
| Tokio runtime conflict when called from within async context | Low | Medium | `block_on` is safe from sync context (which this is — adapter is sync). Will NOT work if ever called from async context, but we don't do that. |
| Existing `aws_cli.rs` tests break due to refactor | Low | High | Zero refactor; additive only. Plan Task X runs `cargo test --test aws_cli` as explicit gate. |
| `apply::run` async path has hidden thread-local or global state that conflicts with our runtime | Low | High | Integration test on existing `aws_cli.rs` covers main.rs → `tokio::main` path; ours is symmetric except we own the runtime lifecycle. If issues surface, move to `futures::executor::block_on` or store runtime in `once_cell` Lazy. |
| Ref ext cargo project type (cdylib vs dylib vs wasm32-wasip2) mismatch vs `deploy-desktop` precedent | Medium | Low | Copy `deploy-desktop/Cargo.toml` exactly, adjust metadata only. Same build.sh. |
| Signing key rotation (EXT_SIGNING_KEY_PEM) happens mid-stream | Low | Low | CI uses org-level secret; rotation is separate operational task. |
| `AwsEcsFargateExtConfig` camelCase keys mismatch pack input schema | Low | Medium | Schema is single source of truth (schemas/config.schema.json); Rust struct mirrors 1:1. Test `ext_config_parses_minimum_fields` catches divergence. |

### 9.2 Out-of-scope follow-ups (tracked for later)

- Add `ext plan` subcommand for dry-run (requires Mode A plan semantics)
- Bundle `greentic.deploy.aws.gtpack` alongside ref ext so users don't need separate download
- Add structured output (`--output json`) to `ext apply` path
- Support ECS-Fargate production environment as separate target (currently `aws-ecs-fargate-local` — "local" referring to where terraform executes, not env)
- Secret URI resolution when Phase B #2 host::secrets lands

## 10. References

- Phase B #4a spec: `docs/superpowers/specs/2026-04-19-phase-b-4a-deployer-cli-wiring-design.md`
- Phase B #4a plan: `docs/superpowers/plans/2026-04-19-phase-b-4a-ext-cli-wiring.md`
- Memory: `deploy-extension-migration.md`, `deploy-extension-next-steps.md`, `phase-b-4a-cli-wiring.md`
- Existing pack fixture: `fixtures/packs/terraform/` (cloud-aware, reused as `greentic.deploy.aws`)
- Existing integration suite: `tests/aws_cli.rs` (fake terraform bin pattern via `write_fake_terraform_bin`)
- Ref ext precedent: `greentic-biz/greentic-deployer-extensions/reference-extensions/deploy-desktop` (`deploy-desktop@0.2.0`, signed)
