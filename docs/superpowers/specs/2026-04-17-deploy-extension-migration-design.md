# Deploy Extension Migration — Design

- **Date:** 2026-04-17
- **Status:** Draft, pending user review
- **Branch:** `spec/wasm-deploy-extensions`
- **Owner:** TBD
- **Related:** `greentic-designer-extensions` (WIT contracts, `greentic-ext-runtime`), PR #91 (built-in extension registry skeleton, merged), new repo `greentic-deployer-extensions` (reference extensions, to be created)
- **Repo split:** Hybrid (Option C). This repo owns host integration + the built-in `Desktop` backend + fixture extension. A sibling repo `greentic-deployer-extensions` (not yet created) owns shippable reference extensions, starting with `deploy-desktop`. Symmetric with the existing `greentic-designer` / `greentic-designer-extensions` split.

## 1. Context & motivation

### Current state

`greentic-deployer` is a mature single-crate Rust CLI/library (v0.4.52, edition 2024, toolchain 1.94.0) that ships 11 deploy backends: `single-vm`, `aws`, `azure`, `gcp`, `terraform`, `k8s-raw`, `helm`, `juju-k8s`, `juju-machine`, `operator`, `serverless`, `snap`. All backends dispatch synchronously through `cli_builtin_dispatch.rs`, a built-in registry landed in PR #91 with the supporting types `BuiltinBackendId` and `DeploymentExtensionContract` under `src/extension.rs`.

A first WASM component (`components/iac-write-files/`) establishes a project pattern: **WASM units are narrow IO primitives, host Rust owns the execution logic**. The `DeploymentExecutor` async trait exists in `src/deployment.rs` as a future seam but is currently unwired (`set_deployment_executor()` returns `None`).

Separately, `greentic-designer-extensions` defines WIT contracts for a full extension ecosystem — `greentic:extension-base@0.1.0`, `greentic:extension-deploy@0.1.0`, `greentic:extension-design@0.1.0`, `greentic:extension-host@0.1.0` — and a runtime crate (`greentic-ext-runtime`) with wasmtime Component Model support, hot reload, and capability resolution. One reference extension (`adaptive-cards`) ships today; no deploy reference extension exists yet.

### Goal

Add WASM deploy extension handling to `greentic-deployer` **without altering existing subprocess paths**. All current CLI invocations (`greentic-deployer single-vm apply`, `greentic-deployer aws ...`, etc.) remain bit-for-bit unchanged. The extension surface is additive, feature-gated, and default-off.

### Non-goals (explicit)

- **Do not** rewrite existing backends (`aws.rs`, `single_vm.rs`, `terraform.rs`, etc.) in WASM.
- **Do not** implement Mode B full-WASM execution in Phase A — only the contract is defined.
- **Do not** migrate `greentic-designer/src/orchestrate/deployer.rs` off subprocess in this effort.
- **Do not** convert the crate to a Cargo workspace in this effort.
- **Do not** implement `host::http`, `host::secrets`, or a new `host::storage` interface in this effort (Phase B prereqs).
- **Do not** ship reference extensions from this repo. `deploy-desktop` and all future reference extensions belong in the new `greentic-deployer-extensions` repo (see §7.2, §12).

## 2. Architecture

### Layering

```
┌──────────────────────────────────────────────────────────────────┐
│  greentic-deployer CLI (main.rs)                                 │
│  - Existing subcommands (single-vm, aws, …) UNCHANGED            │
│  - New subcommand: `ext [list|info|validate|install-dir]`        │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  cli_builtin_dispatch (existing, from PR #91)                    │
│  + fallback: unknown target-id → ext::dispatcher                 │
└────────────┬─────────────────────────────────┬───────────────────┘
             │                                 │
             ▼                                 ▼
    ┌─────────────────────┐         ┌─────────────────────────────┐
    │ existing Rust       │         │ src/ext/ (NEW)              │
    │ backends            │         │ feature-gated: `extensions` │
    │ UNCHANGED           │         │ discovery + registry +      │
    └─────────────────────┘         │ dispatcher + WASM wrapper   │
                                    └────────┬────────────────────┘
                                             │ kind=builtin
                                             │ (delegates back to
                                             │  cli_builtin_dispatch)
                                             │ kind=wasm (Phase B)
                                             ▼
                                    ┌─────────────────────────────┐
                                    │ greentic-ext-runtime        │
                                    │ (git dep, pinned rev)       │
                                    └─────────────────────────────┘
```

### Principles

1. **Existing paths untouched.** Files `apply.rs`, `aws.rs`, `single_vm.rs`, `terraform.rs`, `deployment.rs`, `extension.rs` receive **zero line changes** in Phase A.
2. **Feature-gated default-off.** The new behavior ships behind `--features extensions`. When disabled, the `ext` module is excluded from compilation entirely; binary size and compile time stay unchanged for existing users.
3. **Unified registry.** The existing `DeploymentExtensionContract` type is reused: built-in backends are registered from the existing enum; loaded WASM extensions push additional entries into the same registry.
4. **Single-crate.** No workspace conversion. Revisit after 6 months if `src/ext/` exceeds ~1500 LoC.
5. **Git-dep cross-repo.** `greentic-ext-runtime` and `greentic-ext-contract` from `greentic-designer-extensions` are pinned via `git+rev` in `Cargo.toml` (matches the pattern already used for `adaptive-card-core`).

### Extension execution modes

Each target contribution declares one of two execution modes in its `describe.json`:

| Mode | `execution.kind` | Who runs `deploy/poll/rollback` | Who runs metadata (`list-targets`, schemas, `validate-credentials`) |
| --- | --- | --- | --- |
| **A — Builtin delegated** | `"builtin"` | Existing Rust backend routed by `BuiltinBackendId` + handler | WASM extension |
| **B — Full WASM** | `"wasm"` | WASM extension via `greentic-ext-runtime` (Phase B) | WASM extension |

Phase A implements **Mode A only**. Mode B is specified but returns `ExtensionError::ModeBNotImplemented` at dispatch time.

## 3. Module layout

### New module tree

```
src/ext/
├── mod.rs               Public API surface, feature-gate guard
├── describe.rs          Parse describe.json + deploy-specific `execution` field
├── loader.rs            Filesystem discovery, signature verification hook
├── registry.rs          Unifies built-in + WASM contracts, conflict detection
├── dispatcher.rs        Route Execution::Builtin | ::Wasm
├── builtin_bridge.rs    Glue: BuiltinBackendId + handler → Rust backend call
├── wasm.rs              Thin wrapper over greentic_ext_runtime::ExtensionRuntime
└── errors.rs            ExtensionError enum (thiserror)
```

### Changes to existing files (minimal)

| File | Change |
| --- | --- |
| `Cargo.toml` | Add `[features] extensions = […]` and optional deps `greentic-ext-runtime`, `greentic-ext-contract` via `git+rev` |
| `src/lib.rs` | `#[cfg(feature = "extensions")] pub mod ext;` |
| `src/main.rs` | Add `Ext(ExtCommand)` to `TopLevelCommand` (feature-gated variant) |
| `src/cli_builtin_dispatch.rs` | Fallback: when `target_id` does not parse into `BuiltinBackendId`, call `ext::dispatcher::dispatch_extension` (feature-gated; without the feature, return the existing "unknown target" error) |

No other files are touched.

### Key types

```rust
// src/ext/describe.rs
#[derive(Deserialize)]
pub struct DeployTargetContribution {
    pub id: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_path: Option<PathBuf>,
    pub supports_rollback: bool,
    pub execution: Execution,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Execution {
    Builtin { backend: String, handler: Option<String> },
    Wasm,
}
```

```rust
// src/ext/registry.rs
pub struct ExtensionRegistry {
    entries: HashMap<TargetId, ResolvedTarget>,
}

pub struct ResolvedTarget {
    pub ext_id: String,
    pub contribution: DeployTargetContribution,
    pub wasm_path: PathBuf,
}

impl ExtensionRegistry {
    pub fn resolve(&self, target_id: &str) -> Option<&ResolvedTarget>;
    pub fn list(&self) -> impl Iterator<Item = &ResolvedTarget>;
}
```

### Feature flag

```toml
[features]
default = []                  # extensions NOT default-on in Phase A
extensions = [
    "dep:greentic-ext-runtime",
    "dep:greentic-ext-contract",
]

[dependencies]
greentic-ext-runtime  = { git = "ssh://git@github.com/greenticai/greentic-designer-extensions", rev = "<pin>", optional = true }
greentic-ext-contract = { git = "ssh://git@github.com/greenticai/greentic-designer-extensions", rev = "<pin>", optional = true }
```

`wasmtime` arrives transitively through `greentic-ext-runtime`; no direct dep in deployer.

### Extension directory layout on disk

```
~/.greentic/extensions/deploy/
└── greentic.deploy-desktop/
    ├── describe.json
    ├── extension.wasm
    └── schemas/
        ├── docker-compose.credentials.schema.json
        ├── docker-compose.config.schema.json
        └── podman.{credentials,config}.schema.json
```

- Default root: `~/.greentic/extensions/deploy/`.
- Env override: `GREENTIC_DEPLOY_EXT_DIR=/custom/path`.
- CLI override (per invocation of `ext` subcommand): `--ext-dir <PATH>`.

## 4. Data flow

### 4.1 Startup / discovery

```
main.rs
  └─> if feature = "extensions":
        ext::loader::scan(dir)
          └─ for each subdirectory:
               read describe.json
               verify signature (greentic-ext-contract)
               parse DeployTargetContribution[]
               (wasmtime::Component NOT instantiated yet — lazy)
          └─> Vec<LoadedExtension>
        ext::registry::build(builtins, loaded)
          └─ conflict detection (two extensions claiming same target-id)
          └─> ExtensionRegistry
        passed to cli_builtin_dispatch fallback path
```

- **Lazy WASM instantiation.** `describe.json` parses at startup; `wasmtime::Component` instantiates on first invocation. Users who never touch an extension pay zero WASM cost.
- **Conflict policy.** On duplicate target-id, emit warning during `ext list`; fail hard only when the conflicted target is actually dispatched.
- **Signature enforcement.** Unsigned extensions are rejected unless `GREENTIC_EXT_ALLOW_UNSIGNED=1` is set (matches the env convention already used in sibling repos).

### 4.2 Mode A deploy (Phase A scope)

```
User / Designer
  │ greentic-deployer <target-id> apply --pack ... --config ...
  ▼
main.rs → dispatch(target_id)
  │
  ├─ BuiltinBackendId::from_str(target_id)?  ✗  (e.g., "docker-compose-local")
  │
  ▼
ext::dispatcher::dispatch_extension(registry, target_id, Apply, req)
  │
  ├─ registry.resolve(target_id) → (ext_id, contribution)
  │
  ├─ match contribution.execution:
  │     Execution::Builtin { backend, handler } → builtin path
  │
  ├─ [pre-deploy validation]
  │     schema_creds  = wasm.invoke("credential-schema", target_id)
  │     schema_config = wasm.invoke("config-schema",     target_id)
  │     jsonschema validate creds_json, config_json (host-side)
  │     diags = wasm.invoke("validate-credentials", target_id, creds_json)
  │     any severity=error → abort with structured error
  │
  ├─ builtin_bridge::execute(backend="Desktop", handler=Some("docker-compose"), req)
  │     └─ BuiltinBackendId::from_str(backend)?
  │     └─ cli_builtin_dispatch::dispatch(backend, handler, req)
  │          └─ existing Rust code (aws::apply | single_vm::apply | …)
  │
  └─ ExecutionOutcome returned
```

- `deploy/poll/rollback` are **never called on the WASM extension in Mode A** — the bridge dispatches to the built-in Rust backend.
- State tracking stays in the existing backend (terraform state files, systemd unit state, etc.). No new state machine.

### 4.3 Mode B deploy (Phase B — designed, not implemented)

```
ext::dispatcher::dispatch_extension(...)
  │
  ├─ match contribution.execution:
  │     Execution::Wasm → wasm path
  │
  ├─ [pre-deploy validation] (same as Mode A)
  │
  ├─ wasm.invoke("deploy", DeployRequest { target_id, artifact_bytes,
  │                                        credentials_json, config_json,
  │                                        deployment_name })
  │     └─ inside WASM:
  │         host::http::fetch(...)         (stub today — Phase B prereq)
  │         host::secrets::get(...)        (stub today — Phase B prereq)
  │         host::storage::set(job_id, …)  (new interface — Phase B prereq)
  │     └─ DeployJob { id, status, endpoints }
  │
  ├─ wasm.invoke("poll", job_id) → DeployJob  (caller polls)
  │
  └─ wasm.invoke("rollback", job_id) → ()      (optional)
```

Mode B prerequisites, all outside this design's Phase A:
1. `host::http::fetch` implementation in `greentic-ext-runtime`.
2. `host::secrets::get` implementation.
3. New `host::storage` interface added to `greentic:extension-host` (semver-breaking to 0.2.0).
4. AWS Sig v4 helper (pure Rust, no tokio) for WASM-side signing.

## 5. Extension API contract

### 5.1 WIT — no changes

Extensions implement `greentic:extension-base@0.1.0` and `greentic:extension-deploy@0.1.0` from `greentic-designer-extensions/wit/` unchanged. Phase A extensions **must still export** all three `deployment.*` functions (`deploy`, `poll`, `rollback`) — stubbed to return `ExtensionError::Unsupported("handled by builtin")` — so that the same `.wasm` can later graduate to Mode B without altering the WIT surface.

Host call matrix:

| WIT export | Called in Phase A? | Mode A | Mode B |
| --- | --- | --- | --- |
| `manifest.get-identity` | Yes (startup) | ✓ | ✓ |
| `manifest.get-offered` | Yes (startup) | ✓ | ✓ |
| `lifecycle.init` | Yes (first use) | ✓ | ✓ |
| `targets.list-targets` | Yes (via `ext list`) | ✓ | ✓ |
| `targets.credential-schema` | Yes (pre-deploy) | ✓ | ✓ |
| `targets.config-schema` | Yes (pre-deploy) | ✓ | ✓ |
| `targets.validate-credentials` | Yes (pre-deploy) | ✓ | ✓ |
| `deployment.deploy` | No — routed to built-in | — | ✓ |
| `deployment.poll` | No | — | ✓ |
| `deployment.rollback` | No | — | ✓ |

### 5.2 describe.json — one new field

Only addition for `kind: DeployExtension`: `contributions.targets[].execution`.

```jsonc
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": { "id": "greentic.deploy-desktop", "version": "0.1.0" },
  "engine": { "extRuntime": "^0.1.0" },
  "capabilities": { "offered": [/* … */], "required": [] },
  "runtime": {
    "component": "extension.wasm",
    "memoryLimitMB": 64,
    "permissions": { "network": [], "secrets": [], "callExtensionKinds": [] }
  },
  "contributions": {
    "targets": [
      {
        "id": "docker-compose-local",
        "displayName": "Local Docker Compose",
        "description": "Run on local Docker engine via docker-compose",
        "iconPath": "assets/docker.svg",
        "supportsRollback": true,
        "execution": { "kind": "builtin", "backend": "Desktop", "handler": "docker-compose" }
      },
      {
        "id": "podman-local",
        "displayName": "Local Podman",
        "supportsRollback": true,
        "execution": { "kind": "builtin", "backend": "Desktop", "handler": "podman" }
      }
    ]
  }
}
```

For a Phase B fully-WASM extension: `"execution": { "kind": "wasm" }`.

Note: `credentialSchema` / `configSchema` path fields are intentionally **not** carried in `describe.json`. The WIT functions `targets.credential-schema(id)` and `targets.config-schema(id)` are the single source of truth. Extension authors typically embed the schema strings via `include_str!` at compile time.

### 5.3 Two-phase validation pipeline

```
Host (Rust)                                       WASM (extension)
───────────                                       ────────────────
1. user submits creds_json + config_json
                │
2. schema_creds   = wasm.credential-schema(id)
3. schema_config  = wasm.config-schema(id)
                │
4. jsonschema-rs validate (creds_json, schema_creds)     (host)
5. jsonschema-rs validate (config_json, schema_config)   (host)
                │
6. diags = wasm.validate-credentials(id, creds_json)
                ← Vec<Diagnostic>  (programmatic checks: connection
                                    probe, cross-field invariants)
                │
7. any severity=error diag → abort with structured error
8. otherwise → dispatch to builtin bridge (or WASM for Mode B)
```

### 5.4 Canonical `BuiltinBackendId` strings

`execution.builtin.backend` must be one of the existing `BuiltinBackendId` variant names as serialized by `#[serde(rename_all = "snake_case")]` (i.e. lowercase with underscores). Case-sensitive.

| Backend string | Variant | Handlers supported | Notes |
| --- | --- | --- | --- |
| `desktop` **(new in Phase A)** | `Desktop` | `docker-compose`, `podman` | New variant + `src/desktop.rs` backend |
| `aws` | `Aws` | None (Phase A: single handler) | Existing |
| `azure` | `Azure` | None | Existing |
| `gcp` | `Gcp` | None | Existing |
| `terraform` | `Terraform` | None | Existing |
| `helm` | `Helm` | None | Existing |
| `k8s_raw` | `K8sRaw` | None | Existing |
| `juju_k8s` | `JujuK8s` | None | Existing |
| `juju_machine` | `JujuMachine` | None | Existing |
| `operator` | `Operator` | None | Existing |
| `serverless` | `Serverless` | None | Existing |
| `snap` | `Snap` | None | Existing |

`SingleVm` is NOT in `BuiltinBackendId` today — it dispatches via its own CLI subcommand path (`src/single_vm.rs`), not through pack-based dispatch. Extensions that want to target single-vm deploys would need Phase B custom execution or a separate bridge path (deferred).

Implementation additions needed:
- `impl FromStr for BuiltinBackendId` (not present on `main`).
- `fn BuiltinBackendId::as_str(self) -> &'static str` mirror of serde serialization.
- `fn BuiltinBackendId::handler_matches(&self, Option<&str>) -> bool` for registry-build-time validation.

## 6. Error handling

### Domain error enum

```rust
// src/ext/errors.rs
#[derive(thiserror::Error, Debug)]
pub enum ExtensionError {
    #[error("extension directory not found: {0}")]
    DirNotFound(PathBuf),

    #[error("invalid describe.json at {path}: {source}")]
    DescribeParse { path: PathBuf, source: serde_json::Error },

    #[error("extension '{id}' signature verification failed")]
    SignatureInvalid { id: String },

    #[error("target '{target_id}' provided by both '{a}' and '{b}'")]
    TargetConflict { target_id: String, a: String, b: String },

    #[error("target '{0}' not registered (try: `greentic-deployer ext list`)")]
    TargetNotFound(String),

    #[error("builtin backend '{backend}' unknown for target '{target_id}'")]
    UnknownBuiltinBackend { backend: String, target_id: String },

    #[error("builtin backend '{backend}' does not support handler '{handler:?}'")]
    UnsupportedHandler { backend: String, handler: Option<String> },

    #[error("credential validation failed with {n} errors")]
    ValidationFailed { n: usize, diagnostics: Vec<Diagnostic> },

    #[error("WASM invocation failed: {0}")]
    WasmRuntime(#[from] anyhow::Error),

    #[error("Mode B (full WASM execution) not yet implemented — Phase B")]
    ModeBNotImplemented,
}
```

Domain errors convert to `anyhow::Error` at the CLI boundary via `.context()`. Errors from existing Rust backends (`aws.rs`, `single_vm.rs`, etc.) bubble up unchanged — `builtin_bridge.rs` does not wrap or re-type them.

### User-facing behavior

| Situation | Behavior |
| --- | --- |
| Unknown target-id on CLI | Print `TargetNotFound` with hint listing available targets; exit 1 |
| Malformed `describe.json` in one extension | `ext list` skips that extension with a warning; other extensions still load; startup succeeds |
| Two extensions claim the same target-id | Warning at startup; **fatal** at dispatch of that target |
| Unsigned extension in production | Fatal unless `GREENTIC_EXT_ALLOW_UNSIGNED=1` |
| Validation diagnostic severity=warning | Default: warn + continue. With `--strict-validate`: block deploy |
| Validation diagnostic severity=error | Block deploy before bridge dispatch |
| WASM trap during pre-deploy | Log ext_id + target_id; fail pre-deploy; do not dispatch to backend |

### JSON output mode

Existing `--output json` is honored: extension errors serialize as structured objects with `code`, `message`, optional `diagnostics[]`. Required for designer consumption (machine-readable).

## 7. Testing strategy

### Unit tests — `src/ext/` per file

| File | Coverage |
| --- | --- |
| `describe.rs` | Parse valid describe.json, malformed JSON, missing `execution`, unknown `execution.kind` |
| `loader.rs` | Discover extensions, skip non-dirs, missing describe.json, env override |
| `registry.rs` | Build with built-ins + loaded, conflict detection, `resolve()` hit/miss |
| `builtin_bridge.rs` | `BuiltinBackendId::from_str` roundtrip, `handler_matches` per backend |
| `dispatcher.rs` | Route `Execution::Builtin` → bridge (mocked), `Execution::Wasm` → `ModeBNotImplemented` |

Discipline (per parent CLAUDE.md): `cargo test --workspace --all-features` must pass. Existing tests zero regression when `--no-default-features` **and** when default (extensions off).

### Integration tests — `tests/ext_*.rs`

| File | Behavior |
| --- | --- |
| `tests/ext_loader_integration.rs` | Load fixture tree, assert N extensions + target listing |
| `tests/ext_dispatch_mode_a.rs` | End-to-end: `greentic-deployer <target> plan` with fixture ext + mocked backend → assert `ExecutionOutcome` shape |
| `tests/ext_cli.rs` | `ext list|info|validate` via `assert_cmd` |

### 7.1 Fixture extension — `testdata/ext/greentic.deploy-testfixture/`

Mini extension:
- `describe.json` — 2 targets, both `execution.kind = "builtin"`, backend `SingleVm`.
- `extension.wasm` — pre-built minimal component, committed for determinism and CI speed.
  - Implements all 7 required WIT exports.
  - `list-targets` returns 2 hardcoded targets.
  - `credential-schema` / `config-schema` return small fixture JSON schemas.
  - `validate-credentials` returns empty diagnostics.
  - `deploy/poll/rollback` return `Unsupported`.
- `schemas/*.json` — also host-readable (separate fixtures for host-side JSON Schema tests).
- `testdata/ext/build_fixture.sh` — regeneration script (not run in CI).

### 7.2 Reference extension — delivered from sibling repo

Shippable reference extensions (starting with `deploy-desktop`) are **not part of this repo**. They live in the new sibling repo `greentic-deployer-extensions` (Option C hybrid split). That repo owns:

- `reference-extensions/deploy-desktop/` (Phase A scope there)
- `reference-extensions/deploy-aws/`, `deploy-gcp/`, `deploy-azure/`, etc. (future)
- Shared build tooling (`cargo component build` wrapper, signing scripts, describe.json schema lint)
- Independent CI per reference extension + release cadence per-target-family

Target package shape in the sibling repo (for reference only, authoritative spec lives there):
```
reference-extensions/deploy-desktop/
    Cargo.toml          # crate-type = ["cdylib", "rlib"], target wasm32-wasip2
    describe.json       # docker-compose + podman targets, Mode A → Desktop backend
    wit/                # copy or symlink of designer-extensions/wit/
    src/lib.rs          # WIT exports wrapping const schema strings
    schemas/*.schema.json
    assets/docker.svg
    build.sh            # cargo component build → extension.wasm + package
```

The sibling repo's Phase A spec + plan is a separate brainstorming / writing-plans session once this repo's PR#1 is in flight. Integration between the two repos for end-to-end Phase A testing is via installed artifact: build `deploy-desktop` from the sibling repo, drop the resulting extension bundle into `~/.greentic/extensions/deploy/`, run deployer acceptance tests from this repo.

CI note: this repo's CI does **not** build reference extensions — the sibling repo does. This repo's CI uses only the in-repo fixture extension (§7.1, previously the "Fixture extension" subsection).

### CI matrix additions

| Config | Purpose |
| --- | --- |
| `cargo build --no-default-features` | Prove feature gate fully excludes new code |
| `cargo build` (default, no `extensions`) | Prove Phase A = default-off, no regression |
| `cargo build --features extensions` | Compile check for `ext/` module |
| `cargo test --features extensions` | Unit + integration tests (fixture extension only) |

Existing `ci/local_check.sh` gets one additional step for the features matrix — not rewritten. Reference extension builds live in the sibling repo's CI.

### Not tested in Phase A

- Real AWS/GCP/Azure deploys (no cloud creds in CI).
- Mode B execution (Phase B).
- Signature generation (only verification; generation uses existing `greentic-ext-contract` tooling).
- Performance / load (defer until Mode B has real users).

## 8. Phase boundaries

### Phase A — scope of this design (this repo only)

1. `src/ext/` module (8 files listed in §3).
2. New `BuiltinBackendId::Desktop` variant + `src/desktop.rs` backend (docker-compose + podman).
3. `impl FromStr for BuiltinBackendId` + `handler_matches`.
4. Fallback wiring in `cli_builtin_dispatch.rs`.
5. `Ext(ExtCommand)` top-level CLI subcommand (`list | info | validate | install-dir`).
6. Fixture extension under `testdata/ext/` (minimal, checked-in `.wasm`).
7. CI matrix extension (features-matrix only; no reference extension builds here).
8. Feature flag `extensions` (default-off).
9. Git deps on `greentic-ext-runtime`, `greentic-ext-contract` (pinned rev).
10. No changes to any existing backend file.

### Phase A — scope in the sibling `greentic-deployer-extensions` repo

Tracked in that repo's own spec (future writing-plans session). Summary here for cross-reference:
- Bootstrap repo skeleton, CI, release automation (clone pattern from `greentic-designer-extensions`).
- `reference-extensions/deploy-desktop/` — first shippable reference extension (docker-compose + podman).
- Build + package + signing pipeline.
- Smoke test against a pre-release build of this repo's deployer binary.

### Phase B — future work (designed, not implemented)

- Implement `host::http::fetch` in `greentic-ext-runtime`.
- Implement `host::secrets::get` in `greentic-ext-runtime`.
- Add `host::storage` interface to `greentic:extension-host` (semver-breaking → 0.2.0).
- AWS Sig v4 pure-Rust helper usable inside WASM.
- First Mode B extension (likely a bespoke target, e.g., `deploy-cisco-box`).
- Migrate `greentic-designer/src/orchestrate/deployer.rs` off subprocess, onto `greentic-ext-runtime` directly.
- Flip `extensions` feature to default-on once Phase A has stable users.

## 9. Acceptance criteria — Phase A

1. `cargo build --no-default-features` succeeds with zero new code compiled.
2. `cargo build` (default features) produces a binary with no new runtime dependencies compiled in (i.e. `Cargo.lock` adds only dev/optional entries needed by the `extensions` feature, not transitive runtime deps). Existing compiled binary size delta < 1% from v0.4.52.
3. `cargo build --features extensions` succeeds; new deps resolve; binary includes `ext` module.
4. `cargo test --features extensions` passes all new unit + integration tests.
5. Existing test suite passes unchanged under both default and `--features extensions`.
6. `greentic-deployer ext list` (with feature on, empty extensions dir) exits 0 with an empty table.
7. `greentic-deployer ext validate <fixture-dir>` exits 0 against the in-repo fixture extension.
8. With the fixture extension installed (or pointed to via `GREENTIC_DEPLOY_EXT_DIR`), `greentic-deployer ext list` shows the fixture targets.
9. `greentic-deployer <fixture-target> plan --pack <fixture-pack>` routes through `ext::dispatcher` → `builtin_bridge` → `desktop.rs::plan` (or `single_vm::plan` for fixture), returns a valid `ExecutionOutcome`. (Fixture may delegate to `SingleVm` to avoid requiring docker in CI.)
10. `greentic-deployer docker-compose-local apply --pack <fixture-pack>` starts a real local container **on a developer machine with docker installed**. This acceptance item gated on `deploy-desktop` from the sibling repo being available — out of CI scope. Developer-machine smoke test, not automated.
11. `greentic-deployer some-wasm-target apply ...` against a Mode-B extension returns `ExtensionError::ModeBNotImplemented` with a clear message.
12. All existing subcommands (`single-vm`, `aws`, `azure`, …) behave bit-for-bit as on `main` — regression test passes.
13. `ci/local_check.sh` passes, including the new features-matrix step.

## 10. Open questions

- **Q1 — CLI subcommand spelling.** `ext` vs `extensions`. Design uses `ext` (shorter); if long-form preferred, rename at implementation time.
- **Q2 — Pinned git rev source.** `greentic-designer-extensions` main branch moves; pin the specific commit that contains the WIT files we target. Record the pin in `Cargo.toml` with a comment pointing to the corresponding tag once cut.
- **Q3 — `src/desktop.rs` backend surface.** Whether the Desktop backend ships a full-featured `plan/apply/destroy/status/rollback` or only a subset in Phase A is a scoping decision for the writing-plans step.
- **Q4 — Signature enforcement default.** Production default `GREENTIC_EXT_ALLOW_UNSIGNED=0` is correct; confirm CI sets this when running reference extensions (reference extensions must be signed as part of build pipeline).
- **Q5 — Dependency version alignment.** `greentic-ext-runtime` uses wasmtime v43 (per designer-extensions findings); deployer currently has no direct wasmtime dep. Confirm the pinned rev's wasmtime version does not conflict with any transitive dep already in deployer's Cargo.lock.

## 11. Development strategy — Strategy X (deployer-first)

**Order:** This repo's host integration first, sibling repo's reference extension second. Rationale: fixture ext in-repo lets us exercise the entire contract (loader → registry → dispatcher → bridge → backend) end-to-end before scaling up to a shippable reference. Reference extension in the sibling repo then becomes "scale up fixture" instead of "build from scratch against unproven host".

**PR#1 — this repo (`greentic-deployer`), branch `feat/ext-module`, estimated 1–2 weeks solo:**

1. `Cargo.toml` — add `[features] extensions = [...]` + optional `git+rev` deps on `greentic-ext-runtime`, `greentic-ext-contract`.
2. `src/ext/errors.rs` — `ExtensionError` enum (thiserror).
3. `src/ext/describe.rs` — parse `describe.json` with `execution` field + unit tests.
4. `src/ext/loader.rs` — filesystem discovery + unit tests (in-memory fixtures).
5. `src/ext/registry.rs` — unify built-in + loaded, conflict detection + tests.
6. `src/extension.rs` (existing) — add `impl FromStr for BuiltinBackendId` + `handler_matches` (smallest tweak; reviewed as independent commit).
7. `src/ext/builtin_bridge.rs` — glue layer + unit tests.
8. `src/ext/wasm.rs` — thin wrapper over `greentic-ext-runtime` (minimal: `list-targets`, `credential-schema`, `config-schema`, `validate-credentials`; Mode A does not call `deploy/poll/rollback`).
9. `src/ext/dispatcher.rs` — route `Execution::Builtin` to bridge, `Execution::Wasm` to `ModeBNotImplemented` + unit tests (mocked wasm).
10. `testdata/ext/greentic.deploy-testfixture/` — fixture extension with checked-in pre-built `.wasm`. Delegates to `SingleVm` backend (no docker dependency in CI).
11. `tests/ext_loader_integration.rs` + `tests/ext_dispatch_mode_a.rs` — integration tests against fixture.
12. `src/desktop.rs` — new backend (docker-compose + podman subprocess wrappers) + unit tests.
13. `src/extension.rs` (existing) — add `BuiltinBackendId::Desktop` variant.
14. `src/main.rs` — add `Ext(ExtCommand)` top-level subcommand.
15. `tests/ext_cli.rs` — CLI smoke tests via `assert_cmd`.
16. `src/cli_builtin_dispatch.rs` — fallback wiring to `ext::dispatcher` (feature-gated).
17. `ci/local_check.sh` — extend with features matrix step.

Each numbered item is one commit (or a small series). Review scope per commit ≤ 500 LoC per parent CLAUDE.md coding standard.

**PR#2 — sibling repo `greentic-deployer-extensions`, branch `feat/deploy-desktop`, estimated 2–3 days:**

Covered by that repo's own writing-plans session. Summary:

1. Repo skeleton (clone shape from `greentic-designer-extensions`).
2. `reference-extensions/deploy-desktop/` — Cargo.toml, `describe.json`, WIT bindings, `src/lib.rs` (WIT exports wrapping const schema strings), schemas, assets, `build.sh`.
3. Release pipeline for packaging `.wasm` + `describe.json` + signature into a distributable bundle.
4. Smoke test against a `--features extensions` build of this repo's deployer binary.

**Integration test window (after both PRs merge):**

- Build `deploy-desktop` artifact from sibling repo.
- Drop it into `~/.greentic/extensions/deploy/`.
- Run the developer-machine acceptance test: `greentic-deployer docker-compose-local apply --pack <fixture-pack>` → real container runs.

## 12. References

- `greentic-designer-extensions/wit/extension-deploy.wit` — WIT contract (unchanged).
- `greentic-designer-extensions/wit/extension-base.wit` — WIT contract (unchanged).
- `greentic-designer-extensions/crates/greentic-ext-runtime/` — host runtime (consumed as git dep).
- `greentic-designer-extensions/reference-extensions/adaptive-cards/` — pattern reference for reference-extension build + describe.json shape.
- `greentic-deployer/src/extension.rs` — existing `BuiltinBackendId`, `DeploymentExtensionContract` (PR #91).
- `greentic-deployer/src/cli_builtin_dispatch.rs` — existing built-in dispatch entry point.
- `greentic-deployer/src/deployment.rs:504` — `DeploymentExecutor` trait (unused seam, not consumed by this design).
- `greentic-deployer/components/iac-write-files/` — narrow-IO WASM component pattern.
