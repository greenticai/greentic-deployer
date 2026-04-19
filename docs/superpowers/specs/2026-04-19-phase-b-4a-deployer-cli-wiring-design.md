# Phase B #4a — Deployer CLI Wiring for Extension-Provided Targets

- **Date:** 2026-04-19
- **Status:** Draft, pending user review
- **Branch:** `spec/phase-b-4a-ext-cli-wiring`
- **Owner:** TBD
- **Related:**
  - Parent plan: `memory/deploy-extension-next-steps.md` (Phase B #4a sub-project)
  - Parent spec: `docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md` (Phase A merged; §11 identified §4a as deferred wiring)
  - Wave 3 plan: `docs/superpowers/plans/2026-04-18-extension-signing-wave3.md` (shipped: rev pin to `94e6ba4`, `BuiltinBackendId::SingleVm` variant)
  - Ref extensions: `greentic-biz/greentic-deployer-extensions` (signed `deploy-desktop@0.2.0`, `deploy-single-vm@0.1.0`)

## 1. Context & motivation

### Current state

Phase A (merged 2026-04-17) shipped `src/ext/` module with:
- `loader` / `registry` / `dispatcher` / `builtin_bridge` / `wasm` orchestration
- `ext::cli::ExtCommand` subcommand exposing `list`, `info`, `validate` (introspection only)
- `cli_builtin_dispatch::maybe_dispatch_via_extensions(target_id)` helper defined as `pub(crate)` but **bails with a "PR#2 required" message on success path**; never called from `main.rs` dispatch

Wave 3 (merged 2026-04-19, v0.4.54) added:
- `BuiltinBackendId::SingleVm` + `BuiltinBackendHandlerId::SingleVm` variants (mirrors `Desktop`)
- Rev pin to `greentic-designer-extensions@94e6ba4` (signing pipeline)
- Runtime verify gate + `GREENTIC_EXT_ALLOW_UNSIGNED=1` escape hatch

Ref extension repo `greentic-deployer-extensions` ships:
- `deploy-desktop@0.2.0` — signed, Mode A, backend `desktop` with handler `docker-compose`/`podman`
- `deploy-single-vm@0.1.0` — signed, Mode A, backend `single-vm` with handler `single-vm`

### Gap

Users can:
- `greentic-deployer ext list` — see `docker-compose-local` / `single-vm-local` in table ✓
- `greentic-deployer ext info deploy-desktop` — inspect metadata ✓
- `greentic-deployer ext validate <dir>` — load-time schema check ✓

Users **cannot**:
- Actually deploy via extension. No CLI path invokes `dispatch_extension()` + runs the backend. The `DispatchAction::Builtin(BridgeResolved)` output exists but has no consumer.

### Goal

Add `ext apply` and `ext destroy` subcommands that wire the existing dispatcher into the existing built-in backend execution, so `deploy-desktop` and `deploy-single-vm` work end-to-end. No changes to built-in clap path. Mode A only — Mode B continues to return `ExtensionError::ModeBNotImplemented`.

### Non-goals

- No Mode B (`execution.kind: "wasm"`) execution — Phase B #2.
- No `host::http` / `host::secrets` / `host::storage` — Phase B #2.
- No secret URI resolution (`secrets://...` placeholders treated as literal strings) — future work.
- No cloud backends (`aws`/`gcp`/`azure`/`terraform`/etc.) — Phase B #4b/c/d. Adapter returns clear `AdapterNotImplemented` error for these.
- No top-level CLI fallback (`greentic-deployer <target-id> apply`). Explicit `ext` subgroup only; keeps clap parsing strict.
- No rollback / status / poll subcommands. Apply + destroy only covers the golden path.
- No changes to existing built-in clap path (`greentic-deployer aws apply`, etc.).
- No secret resolution (`secrets://...` URIs passed literally to WASM).

## 2. Design decisions (from brainstorming)

| # | Question | Decision | Reason |
|---|---|---|---|
| Q1 | CLI UX shape | Flat: `ext apply --target X --creds f --config g` | Clap-friendly, discoverable, matches existing `ExtensionResolveArgs` |
| Q2 | Action scope | `apply` + `destroy` | Deploy + teardown golden path; rollback/status = Phase B #2 |
| Q3 | Config→backend adapter | Per-backend `*_from_ext` lib fns, new `src/ext/backend_adapter.rs` | Clean boundary (ext ≠ clap); WASM-declared schema is source of truth |
| Q4 | `maybe_dispatch_via_extensions` helper | **Delete** | Dead code magnet; new path doesn't need top-level fallback |
| Q5 | Creds/config input | File paths only, no secret URI resolution | Simplest, future-compatible; secret integration = Phase B #2 |

## 3. Architecture

### Layering

```
┌─ main.rs ─────────────────────────────────────────────────────────┐
│   TopLevelCommand::Ext(ExtCommand) → ext::cli::run()              │
│   (dispatches to existing list/info/validate OR new apply/destroy)│
└───────────────────────┬───────────────────────────────────────────┘
                        │
                        ▼ ext::cli::run_apply() / run_destroy()
┌─ src/ext/cli.rs ──────────────────────────────────────────────────┐
│  1. Read creds.json + config.json from disk                       │
│  2. scan + build registry                                         │
│  3. Build WasmtimeInvoker                                         │
│  4. dispatch_extension(...) → DispatchAction::Builtin(bridge)     │
│  5. backend_adapter::run(bridge, action, creds, config, pack)     │
└───────────────────────┬───────────────────────────────────────────┘
                        │
                        ▼
┌─ src/ext/backend_adapter.rs  (NEW, ~150 LoC) ─────────────────────┐
│  pub enum ExtAction { Apply, Destroy }                            │
│  pub fn run(backend, handler, action, creds, config, pack)        │
│    match (backend, action) {                                      │
│      (Desktop, Apply)  => desktop::apply_from_ext(...)            │
│      (Desktop, Destroy)=> desktop::destroy_from_ext(...)          │
│      (SingleVm, Apply) => single_vm::apply_from_ext(...)          │
│      (SingleVm, Destroy)=> single_vm::destroy_from_ext(...)       │
│      other => ExtensionError::AdapterNotImplemented               │
│    }                                                              │
└───────────────────────┬───────────────────────────────────────────┘
                        │
                        ▼
┌─ src/desktop.rs + src/single_vm.rs (MINOR) ───────────────────────┐
│   +pub fn apply_from_ext(config_json, creds_json) -> Result<()>   │
│   +pub fn destroy_from_ext(config_json, creds_json) -> Result<()> │
│   Internal: parse JSON → existing typed structs → reuse lib fns   │
└───────────────────────────────────────────────────────────────────┘
```

### Principles

1. **Zero changes to built-in clap path.** Files `aws.rs`, `terraform.rs`, `cli_builtin_dispatch.rs::dispatch_builtin_backend_command`, `main.rs` existing arms — untouched.
2. **Feature-gated `extensions`.** All new code under `#[cfg(feature = "extensions")]`.
3. **Clean ext ↔ clap boundary.** Adapter layer translates JSON → typed args. Backend lib fns get idiomatic Rust input, no clap dependency.
4. **Reuse existing dispatcher.** `src/ext/dispatcher::dispatch_extension` already does schema validation + WASM `validate_credentials`. Adapter layer is pure execution.
5. **No silent Mode B path.** Dispatcher returns `ExtensionError::ModeBNotImplemented` for `execution.kind: "wasm"` — adapter never reached.

## 4. Components & files

### 4.1 New files

#### `src/ext/backend_adapter.rs` (NEW, ~150 LoC)

```rust
//! Adapter layer: translate extension dispatch → built-in backend execution.
//! Mode A only. Mode B is rejected earlier in `dispatcher::dispatch_extension`.

use std::path::Path;
use crate::extension::BuiltinBackendId;
use crate::ext::errors::{ExtensionError, ExtensionResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtAction {
    Apply,
    Destroy,
}

pub fn run(
    backend: BuiltinBackendId,
    handler: Option<&str>,
    action: ExtAction,
    creds_json: &str,
    config_json: &str,
    pack_path: Option<&Path>,
) -> ExtensionResult<()> {
    match (backend, action) {
        (BuiltinBackendId::Desktop, ExtAction::Apply) => {
            crate::desktop::apply_from_ext(handler, config_json, creds_json)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Desktop, ExtAction::Destroy) => {
            crate::desktop::destroy_from_ext(handler, config_json, creds_json)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::SingleVm, ExtAction::Apply) => {
            crate::single_vm::apply_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::SingleVm, ExtAction::Destroy) => {
            crate::single_vm::destroy_from_ext(config_json, creds_json)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        _ => Err(ExtensionError::AdapterNotImplemented { backend }),
    }
}

#[cfg(test)]
mod tests { /* adapter dispatch tests */ }
```

### 4.2 Modified files

#### `src/ext/cli.rs` (+~80 LoC)

- Extend `ExtSubcommand` enum:
  ```rust
  pub enum ExtSubcommand {
      List,
      Info { ext_id: String },
      Validate { dir: PathBuf },
      Apply(ExtApplyArgs),
      Destroy(ExtDestroyArgs),
  }

  #[derive(Parser)]
  pub struct ExtApplyArgs {
      #[arg(long)] pub target: String,
      #[arg(long)] pub creds: PathBuf,
      #[arg(long)] pub config: PathBuf,
      #[arg(long)] pub pack: Option<PathBuf>,
      #[arg(long, default_value_t = false)] pub strict_validate: bool,
  }

  // ExtDestroyArgs identical shape
  ```

- `run()` dispatches new variants to `run_apply` / `run_destroy`.

- New `run_apply(dir: &Path, args: ExtApplyArgs) -> ExtensionResult<()>`:
  1. `fs::read_to_string(&args.creds)` → creds_json (wrap error in `CredsReadError`)
  2. `fs::read_to_string(&args.config)` → config_json (wrap in `ConfigReadError`)
  3. `scan(dir)` → loaded; `ExtensionRegistry::build(loaded)` → registry
  4. `WasmtimeInvoker::new(&[dir])` → invoker
  5. `dispatch_extension(&registry, &invoker, DispatchInput { ... })` → `DispatchAction::Builtin(bridge)`
  6. `backend_adapter::run(bridge.backend, bridge.handler.as_deref(), ExtAction::Apply, &creds_json, &config_json, args.pack.as_deref())`

- `run_destroy` identical with `ExtAction::Destroy`.

#### `src/desktop.rs` (+~60 LoC)

- `pub fn apply_from_ext(handler: Option<&str>, config_json: &str, creds_json: &str) -> anyhow::Result<()>`
- `pub fn destroy_from_ext(handler: Option<&str>, config_json: &str, creds_json: &str) -> anyhow::Result<()>`
- Parse `config_json` → `DesktopConfig` (already `Deserialize`)
- Derive `RuntimeKind` from `handler` (`Some("docker-compose")` → `DockerCompose`, `Some("podman")` → `Podman`, others → error)
- Call existing `plan()` + execution paths
- `creds_json` unused at Phase B #4a (Desktop has no auth); parsed-and-ignored so future changes are safe

#### `src/single_vm.rs` (+~60 LoC)

- `pub fn apply_from_ext(config_json: &str, creds_json: &str, pack_path: Option<&Path>) -> anyhow::Result<()>`
- `pub fn destroy_from_ext(config_json: &str, creds_json: &str) -> anyhow::Result<()>`
- Parse `config_json` → `SingleVmApplyOptions` / `SingleVmDestroyOptions` (derive `Deserialize` for these if not already)
- Call existing `apply_single_vm_plan_output_with_options` / `destroy_single_vm_plan_output_with_options`

#### `src/ext/errors.rs` (+~20 LoC)

New `ExtensionError` variants:
```rust
#[error("failed to read creds file '{path}': {source}")]
CredsReadError { path: PathBuf, #[source] source: std::io::Error },

#[error("failed to read config file '{path}': {source}")]
ConfigReadError { path: PathBuf, #[source] source: std::io::Error },

#[error("backend '{backend:?}' has no execution adapter wired (Phase B #4a supports: Desktop, SingleVm)")]
AdapterNotImplemented { backend: BuiltinBackendId },

#[error("backend '{backend:?}' execution failed: {source}")]
BackendExecutionFailed { backend: BuiltinBackendId, #[source] source: anyhow::Error },
```

#### `src/ext/mod.rs` (+1 line)

```rust
pub mod backend_adapter;
```

#### `src/main.rs` (no line change, existing `TopLevelCommand::Ext` arm already forwards to `ext::cli::run`)

Verified no changes needed — extending `ExtSubcommand` internally is transparent to `main.rs`.

#### `src/cli_builtin_dispatch.rs` (−27 LoC)

Delete entire `maybe_dispatch_via_extensions` function + `#[cfg(feature = "extensions")]` block (Q4 decision).

### 4.3 Delta summary

| File | LoC delta |
|---|---|
| `src/ext/backend_adapter.rs` (new) | +150 |
| `src/ext/cli.rs` | +80 |
| `src/ext/errors.rs` | +20 |
| `src/ext/mod.rs` | +1 |
| `src/desktop.rs` | +60 |
| `src/single_vm.rs` | +60 |
| `src/cli_builtin_dispatch.rs` | −27 |
| **Total** | **~344** |

## 5. Data flow

### 5.1 Happy path (apply, desktop extension)

```
User: greentic-deployer ext apply \
        --target docker-compose-local \
        --creds creds.json --config config.json

1. clap → TopLevelCommand::Ext(ExtCommand{
     ext_dir: None (defaults to $GREENTIC_DEPLOY_EXT_DIR or ~/.greentic/extensions/deploy),
     command: ExtSubcommand::Apply(ExtApplyArgs{..}),
   })

2. main.rs → ext::cli::run(cmd)
3. → ext::cli::run_apply(&dir, args)
4. fs::read_to_string(&args.creds) → creds_json
5. fs::read_to_string(&args.config) → config_json
6. scan(&dir) → Vec<LoadedExtension>
7. ExtensionRegistry::build(loaded)
8. WasmtimeInvoker::new(&[&dir])
9. dispatch_extension(&registry, &invoker, DispatchInput {
     target_id: "docker-compose-local",
     creds_json: &creds_json,
     config_json: &config_json,
     strict_validate: args.strict_validate,
   })
   → Ok(DispatchAction::Builtin(BridgeResolved {
       backend: BuiltinBackendId::Desktop,
       handler: Some("docker-compose"),
     }))
10. backend_adapter::run(Desktop, Some("docker-compose"), ExtAction::Apply,
                        &creds_json, &config_json, None)
11. → desktop::apply_from_ext(Some("docker-compose"), &config_json, &creds_json)
12.   parse config_json → DesktopConfig
13.   derive RuntimeKind::DockerCompose
14.   plan(runtime, &desktop_config) → DesktopPlan
15.   execute plan → docker-compose up
16. Exit 0
```

### 5.2 Destroy path

Identical to 5.1 steps 1-9, then:
- Step 10: `ExtAction::Destroy`
- Step 11: `desktop::destroy_from_ext(...)` → docker-compose down
- Exit 0

### 5.3 Validation failure (schema violation)

Steps 1-8 same. At step 9, `dispatch_extension` validates `config_json` against WASM-declared `config-schema`. If violation:
- Returns `ExtensionError::ValidationFailed { n, diagnostics: [...] }`
- `run_apply` propagates error
- CLI prints structured diagnostics to stderr, exits non-zero
- Adapter + backend never invoked

### 5.4 Unsupported backend (e.g., user installed Phase B #4c `deploy-aws` early)

Steps 1-9 resolve successfully (WASM schemas OK). At step 10:
- `backend_adapter::run(Aws, ..., Apply, ...)` matches `_` arm
- Returns `ExtensionError::AdapterNotImplemented { backend: Aws }`
- User sees: `"backend 'Aws' has no execution adapter wired (Phase B #4a supports: Desktop, SingleVm)"`

## 6. Error handling

Matrix of error scenarios:

| Scenario | Error variant | Source | Exit |
|---|---|---|---|
| Creds file missing / unreadable | `CredsReadError { path, source }` | NEW | non-zero |
| Config file missing / unreadable | `ConfigReadError { path, source }` | NEW | non-zero |
| Invalid JSON in creds/config | Propagated from `dispatch_extension` (`DescribeParse`) or backend adapter (`anyhow::Context`) | Existing / wrapped | non-zero |
| Schema violation | `ValidationFailed { n, diagnostics }` | Existing | non-zero |
| WASM `validate_credentials` fatal diag | `ValidationFailed` | Existing | non-zero |
| Unknown target-id | `TargetNotFound(target_id)` | Existing | non-zero |
| Ambiguous target-id | `AmbiguousTarget { target_id, providers }` | Existing | non-zero |
| Mode B target (`execution.kind: "wasm"`) | `ModeBNotImplemented` | Existing | non-zero |
| Handler mismatch (e.g., Desktop+"kubernetes") | `UnsupportedHandler { backend, handler }` | Existing | non-zero |
| Unsupported backend (no adapter yet) | `AdapterNotImplemented { backend }` | NEW | non-zero |
| Backend execution failure (e.g., docker-compose fails) | `BackendExecutionFailed { backend, source }` | NEW | non-zero |

**No partial-apply rollback** at Phase B #4a. If `docker-compose up` fails mid-way, cleanup is user responsibility (future `ext destroy` can be run). Proper orchestrated rollback = Phase B #2 territory.

## 7. Testing strategy

### 7.1 Unit tests

**`src/ext/backend_adapter.rs`:**
- `run_desktop_apply_dispatches_to_desktop_from_ext` — inject stub via `#[cfg(test)]` trait indirection; assert desktop::apply_from_ext reached
- `run_single_vm_apply_dispatches_correctly`
- `run_unsupported_backend_returns_adapter_not_implemented` — e.g., `Aws` backend
- `run_destroy_action_routes_to_destroy_variants`
- `run_mode_b_dispatch_path_unreachable_by_construction` — sanity-check match arms cover only Mode A

**`src/desktop.rs` new fns:**
- `apply_from_ext_parses_valid_config`
- `apply_from_ext_rejects_invalid_json`
- `apply_from_ext_rejects_unknown_handler`
- `destroy_from_ext_requires_existing_plan` (if applicable)

**`src/single_vm.rs` new fns:** parse-only analog.

**`src/ext/cli.rs`:**
- `run_apply_reads_creds_and_config_files`
- `run_apply_missing_creds_file_errors_clearly`
- `run_destroy_unknown_target_bubbles_target_not_found`

### 7.2 Integration tests (`tests/ext_apply_integration.rs`, NEW)

Reuse existing `testdata/ext/` fixture (Phase A) or add minimal `deploy-desktop-stub/` under `testdata/ext/`.

**Stubbing execution**: real `docker-compose up` / VM provisioning must not run in CI. Implementation plan picks one of:
- Option A — `desktop::apply_from_ext` / `single_vm::apply_from_ext` consult a `dry_run` flag in their JSON config; tests set this flag.
- Option B — introduce a minimal `CommandRunner` trait/function-pointer injection at the `desktop` / `single_vm` module boundary; `#[cfg(test)]` swaps in a no-op runner.

Option B preferred (cleaner isolation, no production-surface `dry_run` leak). Decision deferred to plan step.

Scenarios:
- `ext_apply_desktop_full_validation_pass` — dummy creds/config satisfy schema, adapter reaches stubbed `apply_from_ext` which returns Ok without touching docker
- `ext_apply_schema_violation_fails` — missing required config field → `ValidationFailed` surfaces before adapter reached
- `ext_apply_strict_validate_fails_on_warning` — warn diagnostic + `--strict-validate` flag → `ValidationFailed`
- `ext_destroy_unknown_target_fails_cleanly`

All gated with `GREENTIC_EXT_ALLOW_UNSIGNED=1` via `tests/support/env_guard.rs` (pattern from Wave 3).

### 7.3 CLI smoke tests (extend `tests/ext_cli_smoke.rs`)

- `ext_apply_help_lists_required_flags`
- `ext_apply_without_target_errors`
- `ext_apply_with_unknown_target_prints_target_not_found`
- `ext_destroy_help_lists_required_flags`

### 7.4 CI

- Existing `--features extensions` matrix in `.github/workflows/ci.yml` picks up new tests automatically
- Run: `cargo test --features extensions` locally via `ci/local_check.sh` before push
- Fmt + clippy gates already enforce pre-push via `.githooks/` (Wave 3)

### 7.5 Explicit non-tests (out of scope)

- Real `docker-compose up` (CI environment lacks daemon)
- Real VM provisioning
- Cross-platform (Windows/macOS) integration — Linux CI only
- Performance / load

## 8. Acceptance criteria

Ship PR when **all** hold:

1. `greentic-deployer ext apply --help` shows all 5 flags (`--target`, `--creds`, `--config`, `--pack`, `--strict-validate`) with descriptions
2. `greentic-deployer ext apply --target docker-compose-local --creds fake.json --config fake.json --ext-dir testdata/ext` succeeds against fixture `deploy-desktop` extension (with valid creds/config JSON matching schema) via stubbed `desktop::apply_from_ext` (per 7.2) — no real docker-compose invocation in CI
3. Same flow with intentional schema violation → exit non-zero, stderr shows diagnostic list
4. `greentic-deployer ext destroy --target single-vm-local ...` works symmetrically
5. `greentic-deployer ext apply --target aws-eks-local ...` (hypothetical aws ref ext installed) returns `AdapterNotImplemented` error with clear message
6. All existing tests pass (Phase A + Wave 3 regression clean)
7. `cargo fmt --check` + `cargo clippy -D warnings` green with `--features extensions`
8. `cargo test --no-default-features` (baseline, no `extensions` feature) still green
9. `maybe_dispatch_via_extensions` deletion verified (no dangling references)
10. New tests: ≥8 unit + ≥4 integration + ≥4 smoke all pass

## 9. Rollout & risk

### Risk matrix

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `SingleVmApplyOptions`/`SingleVmDestroyOptions` don't derive `Deserialize` cleanly | Medium | Medium | Derive at module level; if nested fields conflict, add `#[serde(...)]` attrs. Mark in implementation plan. |
| Fixture describe.json signing friction | Low | Low | Use `GREENTIC_EXT_ALLOW_UNSIGNED=1` pattern (Wave 3 EnvGuard) |
| Delete `maybe_dispatch_via_extensions` breaks some doc link or dead cross-ref | Low | Low | Grep for "maybe_dispatch_via_extensions" before commit; update stale docs |
| User confusion re: `--pack` optional vs required | Medium | Low | Doc the semantic: required for `single-vm` + cloud backends, ignored for `desktop`. Clap help text explains. |

### Out-of-scope follow-ups (tracked for post-ship)

- Add `ext plan` subcommand (dry-run) — requires Mode A `plan` semantics from extension contract
- Add `ext status` — requires `host::storage` for state lookup (Phase B #2)
- Add `ext list` output: "apply supported: yes/no" column based on adapter registration (nice-to-have)
- User-facing docs page in `greentic-docs` for `ext apply/destroy` workflow
- Consider top-level CLI sugar `greentic-deployer <target-id> apply ...` once adapter table stabilizes

## 10. References

- Phase A spec: `docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md`
- Phase A plan: `docs/superpowers/plans/2026-04-17-deploy-extension-pr1.md`
- Wave 3 plan: `docs/superpowers/plans/2026-04-18-extension-signing-wave3.md`
- Memory: `memory/deploy-extension-migration.md`, `memory/deploy-extension-next-steps.md`
- Upstream: `greentic-designer-extensions` @ rev `94e6ba4` (signing pipeline)
- Ref exts: `greentic-biz/greentic-deployer-extensions` (`deploy-desktop@0.2.0`, `deploy-single-vm@0.1.0`)
