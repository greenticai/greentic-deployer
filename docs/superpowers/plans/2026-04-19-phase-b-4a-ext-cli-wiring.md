# Phase B #4a — Deployer CLI Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire extension-provided deploy targets into the deployer CLI so `deploy-desktop@0.2.0` and `deploy-single-vm@0.1.0` become end-to-end invocable via `greentic-deployer ext apply` / `ext destroy`.

**Architecture:** New `src/ext/backend_adapter.rs` translates WASM-validated JSON creds/config to existing Desktop + SingleVm lib functions via new `*_from_ext` entry points (with `CommandRunner` trait injection for test stubbing). `ExtSubcommand::{Apply,Destroy}` added to `src/ext/cli.rs`. Legacy `maybe_dispatch_via_extensions` placeholder deleted. Mode A only; cloud + Mode B deferred.

**Tech Stack:** Rust 2024 edition, clap v4, serde/serde_json, thiserror, anyhow, existing `ext::dispatcher` + `ext::registry`, wasmtime-based `WasmtimeInvoker` (Phase A).

**Spec:** `docs/superpowers/specs/2026-04-19-phase-b-4a-deployer-cli-wiring-design.md`

**Branch:** `spec/phase-b-4a-ext-cli-wiring` (already checked out)

---

## File Structure

### New files

| Path | Purpose |
|------|---------|
| `src/ext/backend_adapter.rs` | Thin dispatch layer: `(BuiltinBackendId, handler, ExtAction, creds, config, pack) → backend lib fn`. ~150 LoC. |
| `tests/ext_apply_integration.rs` | Integration tests for `ext::cli::run_apply/run_destroy` (schema validation, adapter-not-implemented, target-not-found). ~80 LoC. |

### Modified files

| Path | Purpose | Δ LoC |
|------|---------|-------|
| `src/ext/errors.rs` | New error variants: `CredsReadError`, `ConfigReadError`, `AdapterNotImplemented`, `BackendExecutionFailed`. | +25 |
| `src/ext/mod.rs` | Export `backend_adapter` module. | +1 |
| `src/ext/cli.rs` | Add `Apply(ExtApplyArgs)` / `Destroy(ExtDestroyArgs)` subcommands + `run_apply` / `run_destroy` functions. | +80 |
| `src/desktop.rs` | Add `CommandRunner` trait + `RealCommandRunner` + `apply_from_ext` / `destroy_from_ext` + `*_with_runner` variants for testing. | +90 |
| `src/single_vm.rs` | Add `apply_from_ext` / `destroy_from_ext` (parse JSON spec path + options → existing lib fns). No runner trait needed (lib fns already accept options). | +60 |
| `src/cli_builtin_dispatch.rs` | Delete `maybe_dispatch_via_extensions` (dead placeholder). | −27 |
| `tests/ext_cli.rs` | Extend smoke tests: `ext apply --help`, missing target errors, unknown target. | +60 |

### Unchanged (critical to verify no regression)

- `src/main.rs` — `TopLevelCommand::Ext` arm already forwards to `ext::cli::run()`; extending `ExtSubcommand` internally is transparent.
- `src/aws.rs`, `src/terraform.rs`, `src/helm.rs`, `src/k8s_raw.rs`, etc. — built-in backend execution paths untouched.
- `src/ext/dispatcher.rs`, `src/ext/builtin_bridge.rs`, `src/ext/loader.rs`, `src/ext/registry.rs` — Phase A modules reused as-is.

---

## Task 1: Add new error variants

**Files:**
- Modify: `src/ext/errors.rs`

- [ ] **Step 1.1: Write the failing tests**

Append to `src/ext/errors.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension::BuiltinBackendId;
    use std::io::ErrorKind;

    #[test]
    fn creds_read_error_displays_path() {
        let err = ExtensionError::CredsReadError {
            path: PathBuf::from("/nope/creds.json"),
            source: std::io::Error::new(ErrorKind::NotFound, "not found"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/nope/creds.json"), "got: {msg}");
        assert!(msg.contains("creds"), "got: {msg}");
    }

    #[test]
    fn config_read_error_displays_path() {
        let err = ExtensionError::ConfigReadError {
            path: PathBuf::from("/nope/config.json"),
            source: std::io::Error::new(ErrorKind::PermissionDenied, "denied"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("/nope/config.json"), "got: {msg}");
        assert!(msg.contains("config"), "got: {msg}");
    }

    #[test]
    fn adapter_not_implemented_displays_backend() {
        let err = ExtensionError::AdapterNotImplemented {
            backend: BuiltinBackendId::Aws,
        };
        let msg = format!("{err}");
        assert!(msg.contains("Aws"), "got: {msg}");
        assert!(msg.contains("Phase B #4a"), "got: {msg}");
    }

    #[test]
    fn backend_execution_failed_displays_source() {
        let err = ExtensionError::BackendExecutionFailed {
            backend: BuiltinBackendId::Desktop,
            source: anyhow::anyhow!("docker-compose: exit 1"),
        };
        let msg = format!("{err}");
        assert!(msg.contains("Desktop"), "got: {msg}");
    }
}
```

- [ ] **Step 1.2: Run tests to verify they fail**

```bash
cd /home/bimbim/works/greentic/greentic-deployer
cargo test --features extensions --lib ext::errors::tests 2>&1 | tail -20
```

Expected: compilation error on unknown variants `CredsReadError`, `ConfigReadError`, `AdapterNotImplemented`, `BackendExecutionFailed`.

- [ ] **Step 1.3: Add the error variants**

Edit `src/ext/errors.rs`. Add these variants to the `ExtensionError` enum, and add the `BuiltinBackendId` import at the top:

```rust
use std::path::PathBuf;

use crate::extension::BuiltinBackendId;

#[derive(thiserror::Error, Debug)]
pub enum ExtensionError {
    // ... existing variants ...

    #[error("failed to read creds file '{path}': {source}")]
    CredsReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read config file '{path}': {source}")]
    ConfigReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "backend '{backend:?}' has no execution adapter wired (Phase B #4a supports: Desktop, SingleVm)"
    )]
    AdapterNotImplemented { backend: BuiltinBackendId },

    #[error("backend '{backend:?}' execution failed: {source}")]
    BackendExecutionFailed {
        backend: BuiltinBackendId,
        #[source]
        source: anyhow::Error,
    },
}
```

- [ ] **Step 1.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib ext::errors::tests 2>&1 | tail -15
```

Expected: 4 new tests pass.

- [ ] **Step 1.5: Commit**

```bash
git add src/ext/errors.rs
git commit -m "feat(ext): add error variants for apply/destroy CLI wiring

New variants: CredsReadError, ConfigReadError (file IO failures),
AdapterNotImplemented (backends not in Phase B #4a scope),
BackendExecutionFailed (wraps backend lib fn anyhow errors)."
```

---

## Task 2: Desktop `*_from_ext` with `CommandRunner` trait

**Files:**
- Modify: `src/desktop.rs`

- [ ] **Step 2.1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests { ... }` block in `src/desktop.rs`:

```rust
    #[test]
    fn runtime_from_handler_maps_known_handlers() {
        assert_eq!(
            runtime_from_handler(Some("docker-compose")).unwrap(),
            RuntimeKind::DockerCompose
        );
        assert_eq!(
            runtime_from_handler(Some("podman")).unwrap(),
            RuntimeKind::Podman
        );
    }

    #[test]
    fn runtime_from_handler_rejects_unknown() {
        let err = runtime_from_handler(Some("kubernetes")).unwrap_err();
        assert!(format!("{err}").contains("kubernetes"));
    }

    #[test]
    fn runtime_from_handler_rejects_missing() {
        let err = runtime_from_handler(None).unwrap_err();
        assert!(format!("{err}").contains("missing handler"));
    }

    #[derive(Default)]
    struct RecordingRunner {
        captured: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus> {
            let argv: Vec<String> = std::iter::once(cmd.get_program().to_string_lossy().to_string())
                .chain(cmd.get_args().map(|a| a.to_string_lossy().to_string()))
                .collect();
            self.captured.lock().unwrap().push(argv);
            Ok(fake_exit_success())
        }
    }

    fn fake_exit_success() -> std::process::ExitStatus {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(0)
        }
        #[cfg(not(unix))]
        {
            use std::os::windows::process::ExitStatusExt;
            std::process::ExitStatus::from_raw(0)
        }
    }

    fn sample_config_json() -> String {
        r#"{
            "image": "nginx:stable",
            "composeFile": "/tmp/compose.yml",
            "ports": ["8080:80"],
            "env": [],
            "deploymentName": "my-app",
            "projectDir": "/tmp/proj"
        }"#
        .to_string()
    }

    #[test]
    fn apply_from_ext_with_runner_invokes_up_command() {
        let runner = RecordingRunner::default();
        apply_from_ext_with_runner(
            Some("docker-compose"),
            &sample_config_json(),
            "{}",
            &runner,
        )
        .expect("apply ok");
        let captured = runner.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let argv = &captured[0];
        assert_eq!(argv[0], "docker");
        assert!(argv.contains(&"up".to_string()));
        assert!(argv.contains(&"my-app".to_string()));
    }

    #[test]
    fn destroy_from_ext_with_runner_invokes_down_command() {
        let runner = RecordingRunner::default();
        destroy_from_ext_with_runner(
            Some("docker-compose"),
            &sample_config_json(),
            "{}",
            &runner,
        )
        .expect("destroy ok");
        let captured = runner.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].contains(&"down".to_string()));
    }

    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let runner = RecordingRunner::default();
        let err = apply_from_ext_with_runner(
            Some("docker-compose"),
            "not json",
            "{}",
            &runner,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn apply_from_ext_rejects_unknown_handler() {
        let runner = RecordingRunner::default();
        let err = apply_from_ext_with_runner(
            Some("kubernetes"),
            &sample_config_json(),
            "{}",
            &runner,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("kubernetes"));
    }

    #[test]
    fn apply_from_ext_propagates_nonzero_exit() {
        struct FailingRunner;
        impl CommandRunner for FailingRunner {
            fn run(&self, _cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus> {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    Ok(std::process::ExitStatus::from_raw(1 << 8))
                }
                #[cfg(not(unix))]
                {
                    use std::os::windows::process::ExitStatusExt;
                    Ok(std::process::ExitStatus::from_raw(1))
                }
            }
        }
        let err = apply_from_ext_with_runner(
            Some("docker-compose"),
            &sample_config_json(),
            "{}",
            &FailingRunner,
        )
        .unwrap_err();
        assert!(format!("{err}").contains("exited"));
    }
```

- [ ] **Step 2.2: Run tests to verify they fail**

```bash
cargo test --features extensions --lib desktop::tests 2>&1 | tail -20
```

Expected: compile errors — `runtime_from_handler`, `CommandRunner`, `apply_from_ext_with_runner`, `destroy_from_ext_with_runner` not found.

- [ ] **Step 2.3: Implement trait + entry points**

Edit `src/desktop.rs`. Add after existing imports:

```rust
use anyhow::Context;
```

(if not already present).

Add after the `preflight_check` function (around line 164):

```rust
/// Abstraction for command execution so tests can stub.
pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus>;
}

/// Production runner: invokes `Command::status()`.
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, cmd: &mut Command) -> anyhow::Result<std::process::ExitStatus> {
        let program = cmd.get_program().to_string_lossy().to_string();
        cmd.status().with_context(|| format!("spawn {program}"))
    }
}

/// Map extension-contributed handler string → `RuntimeKind`.
pub fn runtime_from_handler(handler: Option<&str>) -> Result<RuntimeKind> {
    match handler {
        Some("docker-compose") => Ok(RuntimeKind::DockerCompose),
        Some("podman") => Ok(RuntimeKind::Podman),
        Some(other) => Err(anyhow::anyhow!(
            "unsupported desktop handler: '{other}' (expected 'docker-compose' or 'podman')"
        )),
        None => Err(anyhow::anyhow!(
            "missing handler for desktop backend (expected 'docker-compose' or 'podman')"
        )),
    }
}

/// Extension-driven apply: parse JSON config, dispatch to real runner.
pub fn apply_from_ext(
    handler: Option<&str>,
    config_json: &str,
    creds_json: &str,
) -> Result<()> {
    apply_from_ext_with_runner(handler, config_json, creds_json, &RealCommandRunner)
}

/// Extension-driven destroy: parse JSON config, dispatch to real runner.
pub fn destroy_from_ext(
    handler: Option<&str>,
    config_json: &str,
    creds_json: &str,
) -> Result<()> {
    destroy_from_ext_with_runner(handler, config_json, creds_json, &RealCommandRunner)
}

/// Test-friendly apply: accepts an injected runner.
pub fn apply_from_ext_with_runner(
    handler: Option<&str>,
    config_json: &str,
    _creds_json: &str,
    runner: &dyn CommandRunner,
) -> Result<()> {
    let config: DesktopConfig =
        serde_json::from_str(config_json).context("parse desktop config JSON")?;
    let runtime = runtime_from_handler(handler)?;
    let plan_result = plan(runtime, &config)?;
    let program_name = plan_result.runtime.cmd_name();
    let mut cmd = build_up_command(&plan_result);
    let status = runner.run(&mut cmd)?;
    if !status.success() {
        anyhow::bail!("{} up exited with status {}", program_name, status);
    }
    Ok(())
}

/// Test-friendly destroy: accepts an injected runner.
pub fn destroy_from_ext_with_runner(
    handler: Option<&str>,
    config_json: &str,
    _creds_json: &str,
    runner: &dyn CommandRunner,
) -> Result<()> {
    let config: DesktopConfig =
        serde_json::from_str(config_json).context("parse desktop config JSON")?;
    let runtime = runtime_from_handler(handler)?;
    let plan_result = plan(runtime, &config)?;
    let program_name = plan_result.runtime.cmd_name();
    let mut cmd = build_down_command(&plan_result);
    let status = runner.run(&mut cmd)?;
    if !status.success() {
        anyhow::bail!("{} down exited with status {}", program_name, status);
    }
    Ok(())
}
```

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib desktop::tests 2>&1 | tail -20
```

Expected: all desktop tests pass (existing + 8 new).

- [ ] **Step 2.5: Commit**

```bash
git add src/desktop.rs
git commit -m "feat(desktop): add apply_from_ext / destroy_from_ext with CommandRunner

Entry points for extension-driven dispatch: parse JSON config, map handler
string to RuntimeKind, build command, run via injectable CommandRunner.
Production path uses RealCommandRunner; tests inject recording stub."
```

---

## Task 3: SingleVm `*_from_ext`

**Files:**
- Modify: `src/single_vm.rs`

- [ ] **Step 3.1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests { ... }` block in `src/single_vm.rs` (find it near the end of the file):

```rust
    #[test]
    fn ext_config_parses_minimum_fields() {
        let json = r#"{"specPath": "/tmp/spec.yaml"}"#;
        let cfg: SingleVmExtConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.spec_path, PathBuf::from("/tmp/spec.yaml"));
        assert!(!cfg.apply_options.pull_image);
        assert!(!cfg.destroy_options.stop_service);
    }

    #[test]
    fn ext_config_accepts_options() {
        let json = r#"{
            "specPath": "/tmp/spec.yaml",
            "applyOptions": {
                "pullImage": true,
                "daemonReload": true,
                "enableService": false,
                "restartService": true
            },
            "destroyOptions": {
                "stopService": true,
                "disableService": false
            }
        }"#;
        let cfg: SingleVmExtConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.apply_options.pull_image);
        assert!(cfg.apply_options.daemon_reload);
        assert!(!cfg.apply_options.enable_service);
        assert!(cfg.apply_options.restart_service);
        assert!(cfg.destroy_options.stop_service);
        assert!(!cfg.destroy_options.disable_service);
    }

    #[test]
    fn apply_from_ext_rejects_invalid_json() {
        let err = apply_from_ext("not json", "{}", None).unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn apply_from_ext_rejects_missing_spec_path() {
        let err = apply_from_ext(r#"{"applyOptions": {}}"#, "{}", None).unwrap_err();
        // serde should flag missing `specPath`
        assert!(
            format!("{err}").contains("specPath") || format!("{err}").contains("missing field"),
            "got: {err}"
        );
    }

    #[test]
    fn destroy_from_ext_rejects_invalid_json() {
        let err = destroy_from_ext("not json", "{}").unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    // Note: We do NOT test apply_from_ext happy-path here because it would
    // require a real spec file + actual systemd/systemctl on the test host.
    // Integration tests cover schema-level validation up to the adapter layer;
    // production verification happens via e2e on a real VM.
```

**Note on Deserialize attribute:** `SingleVmApplyOptions` and `SingleVmDestroyOptions` already derive `Deserialize` (verified at `src/single_vm.rs:160-172`). However they use snake_case field names. Extension describe.json typically declares camelCase. We handle this with `#[serde(rename_all = "camelCase")]` on the new wrapper struct only (the existing types stay snake_case for existing callers).

- [ ] **Step 3.2: Run tests to verify they fail**

```bash
cargo test --features extensions --lib single_vm::tests 2>&1 | tail -20
```

Expected: `SingleVmExtConfig`, `apply_from_ext`, `destroy_from_ext` not found.

- [ ] **Step 3.3: Implement entry points**

Edit `src/single_vm.rs`. Add after the existing `SingleVmDestroyOptions` struct (around line 172):

```rust
/// Extension-contributed config shape for single-vm apply/destroy via
/// `ext::backend_adapter`. Extensions declare a matching JSON schema in their
/// `config-schema`; this struct is the Rust-side view.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleVmExtConfig {
    pub spec_path: PathBuf,
    #[serde(default)]
    pub apply_options: SingleVmApplyOptions,
    #[serde(default)]
    pub destroy_options: SingleVmDestroyOptions,
}
```

**Note:** `SingleVmApplyOptions` and `SingleVmDestroyOptions` already have `#[serde(default)]`-friendly shape (all fields bool, all derive Default). For the wrapper to accept camelCase, add `#[serde(rename_all = "camelCase")]` — BUT the existing options types use snake_case field names (`pull_image`, `daemon_reload`, etc.). To honor extension's camelCase convention without changing the existing types, replace with explicit field-level renames. Since the existing types already have `Deserialize + Default` derived and JSON parsing will work if we fix the wrapper only, the cleanest approach is:

```rust
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleVmExtConfig {
    pub spec_path: PathBuf,
    #[serde(default, rename = "applyOptions")]
    pub apply_options: SingleVmApplyOptions,
    #[serde(default, rename = "destroyOptions")]
    pub destroy_options: SingleVmDestroyOptions,
}
```

However `SingleVmApplyOptions` itself (`pull_image`, etc.) still expects snake_case in JSON. Per spec §9 risk, add `#[serde(rename_all = "camelCase")]` to the existing `SingleVmApplyOptions` and `SingleVmDestroyOptions` struct-level attributes. **Verify first** this doesn't break any other callers that serialize these via YAML or JSON — grep for their usage:

```bash
rg 'SingleVmApplyOptions|SingleVmDestroyOptions' --type rust -l
```

If only internal callers (build options then call lib fn), adding `camelCase` is safe. If external serialization exists (e.g. JSON output of `plan` command), this is a breaking change — in that case, add a separate `FromExt` wrapper type.

**Current check (2026-04-19, before implementation):** Existing callers are `main.rs` (clap-constructed) + internal tests. Safe to add `camelCase` rename.

Edit `src/single_vm.rs` lines 160 and 168:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SingleVmApplyOptions {
    pub pull_image: bool,
    pub daemon_reload: bool,
    pub enable_service: bool,
    pub restart_service: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SingleVmDestroyOptions {
    pub stop_service: bool,
    pub disable_service: bool,
}
```

Add entry points after `destroy_single_vm_plan_output_with_options` (around line 534 or right after `destroy_single_vm_spec_path`):

```rust
/// Extension-driven apply: parse JSON config, load spec path, call existing
/// `apply_single_vm_plan_output_with_options`. `pack_path` reserved for future
/// use (cloud refs); ignored by single-vm.
pub fn apply_from_ext(
    config_json: &str,
    _creds_json: &str,
    _pack_path: Option<&std::path::Path>,
) -> Result<()> {
    use anyhow::Context;
    let cfg: SingleVmExtConfig = serde_json::from_str(config_json)
        .map_err(|e| DeployerError::Other(format!("parse single-vm config JSON: {e}")))?;
    let plan = plan_single_vm_spec_path(&cfg.spec_path)
        .context("plan single-vm from spec")
        .map_err(|e| DeployerError::Other(format!("{e}")))?;
    let _report = apply_single_vm_plan_output_with_options(&plan, &cfg.apply_options)?;
    Ok(())
}

/// Extension-driven destroy: parse JSON config, load spec path, call existing
/// `destroy_single_vm_plan_output_with_options`.
pub fn destroy_from_ext(config_json: &str, _creds_json: &str) -> Result<()> {
    let cfg: SingleVmExtConfig = serde_json::from_str(config_json)
        .map_err(|e| DeployerError::Other(format!("parse single-vm config JSON: {e}")))?;
    let plan = plan_single_vm_spec_path(&cfg.spec_path)
        .map_err(|e| DeployerError::Other(format!("plan single-vm: {e}")))?;
    let _report = destroy_single_vm_plan_output_with_options(&plan, &cfg.destroy_options)?;
    Ok(())
}
```

- [ ] **Step 3.4: Verify no breakage from camelCase rename**

```bash
cargo build --features extensions 2>&1 | tail -20
cargo test --features extensions --lib 2>&1 | tail -30
```

Expected: no compile errors. Any test that parsed snake_case JSON into these types would break — if any fail, add `#[serde(alias = "pull_image")]` etc. or revert to per-call renames.

- [ ] **Step 3.5: Run single_vm tests to verify they pass**

```bash
cargo test --features extensions --lib single_vm::tests 2>&1 | tail -20
```

Expected: all single_vm tests pass.

- [ ] **Step 3.6: Commit**

```bash
git add src/single_vm.rs
git commit -m "feat(single-vm): add apply_from_ext / destroy_from_ext + SingleVmExtConfig

Parses JSON config with camelCase keys (matches extension describe.json
convention), loads spec from path, delegates to existing
apply_single_vm_plan_output_with_options / destroy_*. pack_path parameter
reserved for future cloud backends."
```

---

## Task 4: Backend adapter module

**Files:**
- Create: `src/ext/backend_adapter.rs`
- Modify: `src/ext/mod.rs`

- [ ] **Step 4.1: Write the failing tests (in new file)**

Create `src/ext/backend_adapter.rs` with skeleton + tests:

```rust
//! Adapter layer: translate extension dispatch → built-in backend execution.
//!
//! Mode A only. Mode B is rejected earlier in `dispatcher::dispatch_extension`.
//! Currently wired backends: Desktop (docker-compose/podman), SingleVm
//! (systemd/service). Other BuiltinBackendId variants return
//! `AdapterNotImplemented` — users see a clear message that the backend exists
//! but no execution adapter has been shipped yet.

use std::path::Path;

use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::extension::BuiltinBackendId;

/// Action to run against the resolved backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtAction {
    Apply,
    Destroy,
}

/// Dispatch to the appropriate backend `*_from_ext` entry point.
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
                .map_err(|e| ExtensionError::BackendExecutionFailed {
                    backend,
                    source: anyhow::anyhow!("{e}"),
                })
        }
        (BuiltinBackendId::SingleVm, ExtAction::Destroy) => {
            crate::single_vm::destroy_from_ext(config_json, creds_json)
                .map_err(|e| ExtensionError::BackendExecutionFailed {
                    backend,
                    source: anyhow::anyhow!("{e}"),
                })
        }
        _ => Err(ExtensionError::AdapterNotImplemented { backend }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Aws,
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
                backend: BuiltinBackendId::Aws
            }
        ));
    }

    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_destroy() {
        let err = run(
            BuiltinBackendId::Gcp,
            None,
            ExtAction::Destroy,
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

    #[test]
    fn desktop_invalid_handler_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Desktop,
            Some("kubernetes"),
            ExtAction::Apply,
            "{}",
            r#"{"deploymentName":"x","projectDir":"/tmp"}"#,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Desktop,
                ..
            }
        ));
    }

    #[test]
    fn single_vm_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::SingleVm,
            Some("single-vm"),
            ExtAction::Apply,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::SingleVm,
                ..
            }
        ));
    }

    #[test]
    fn ext_action_copy_semantics() {
        let a = ExtAction::Apply;
        let b = a;
        assert_eq!(a, b);
    }
}
```

Edit `src/ext/mod.rs` to add:

```rust
pub mod backend_adapter;
```

- [ ] **Step 4.2: Run tests to verify they fail initially**

```bash
cargo test --features extensions --lib ext::backend_adapter::tests 2>&1 | tail -20
```

Expected: compile success, 5 tests pass (since the implementation is provided in the same file). If any test fails due to desktop/single-vm test behavior differing, investigate.

**Note:** This task is special — creating the file and adding tests at the same time is a TDD shortcut acceptable when the module is net-new and depends on Task 2+3 already landed. The tests would have failed if Task 2/3 were not done first.

- [ ] **Step 4.3: Commit**

```bash
git add src/ext/backend_adapter.rs src/ext/mod.rs
git commit -m "feat(ext): backend_adapter dispatches to desktop/single-vm from_ext fns

Pure match-table: (BuiltinBackendId, ExtAction) → backend::*_from_ext.
Desktop + SingleVm wired; other backends return AdapterNotImplemented
with clear Phase B #4a scope message. BackendExecutionFailed wraps
any error from the backend lib fn for clean CLI presentation."
```

---

## Task 5: Extend `ExtSubcommand` with Apply + Destroy

**Files:**
- Modify: `src/ext/cli.rs`

- [ ] **Step 5.1: Write the failing unit tests**

Append to `src/ext/cli.rs` at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn run_apply_missing_creds_file_errors_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let args = ExtApplyArgs {
            target: "x".into(),
            creds: tmp.path().join("does-not-exist.json"),
            config: config_path,
            pack: None,
            strict_validate: false,
        };
        let err = run_apply(tmp.path(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does-not-exist.json"), "got: {msg}");
    }

    #[test]
    fn run_apply_missing_config_file_errors_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let creds_path = tmp.path().join("creds.json");
        std::fs::write(&creds_path, "{}").unwrap();
        let args = ExtApplyArgs {
            target: "x".into(),
            creds: creds_path,
            config: tmp.path().join("missing-config.json"),
            pack: None,
            strict_validate: false,
        };
        let err = run_apply(tmp.path(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing-config.json"), "got: {msg}");
    }

    #[test]
    fn run_destroy_missing_creds_file_errors_with_path() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let args = ExtDestroyArgs {
            target: "x".into(),
            creds: tmp.path().join("does-not-exist.json"),
            config: config_path,
            pack: None,
            strict_validate: false,
        };
        let err = run_destroy(tmp.path(), args).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("does-not-exist.json"), "got: {msg}");
    }
}
```

- [ ] **Step 5.2: Run tests to verify they fail**

```bash
cargo test --features extensions --lib ext::cli::tests 2>&1 | tail -20
```

Expected: `ExtApplyArgs`, `ExtDestroyArgs`, `run_apply`, `run_destroy` not found.

- [ ] **Step 5.3: Extend subcommand + implement run fns**

Edit `src/ext/cli.rs`. Replace the entire file contents with:

```rust
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::ext::backend_adapter::{ExtAction, run as run_adapter};
use crate::ext::dispatcher::{DispatchAction, DispatchInput, dispatch_extension};
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::ext::loader::{resolve_extension_dir, scan};
use crate::ext::registry::ExtensionRegistry;
use crate::ext::wasm::WasmtimeInvoker;

#[derive(Parser)]
pub struct ExtCommand {
    /// Override the extension directory. Default: $GREENTIC_DEPLOY_EXT_DIR or
    /// ~/.greentic/extensions/deploy/.
    #[arg(long = "ext-dir", global = true)]
    pub ext_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: ExtSubcommand,
}

#[derive(Subcommand)]
pub enum ExtSubcommand {
    /// List loaded extensions and their contributed targets.
    List,
    /// Show metadata for one extension.
    Info { ext_id: String },
    /// Validate a describe.json + referenced wasm at the given path.
    Validate { dir: PathBuf },
    /// Apply an extension-contributed deploy target.
    Apply(ExtApplyArgs),
    /// Destroy an extension-contributed deploy target.
    Destroy(ExtDestroyArgs),
}

#[derive(Parser)]
pub struct ExtApplyArgs {
    /// Target id as declared by the extension (see `ext list`).
    #[arg(long)]
    pub target: String,
    /// Path to credentials JSON file.
    #[arg(long)]
    pub creds: PathBuf,
    /// Path to config JSON file.
    #[arg(long)]
    pub config: PathBuf,
    /// Optional pack path (required by some backends, e.g. cloud refs).
    #[arg(long)]
    pub pack: Option<PathBuf>,
    /// Treat validation warnings as errors.
    #[arg(long, default_value_t = false)]
    pub strict_validate: bool,
}

#[derive(Parser)]
pub struct ExtDestroyArgs {
    /// Target id as declared by the extension (see `ext list`).
    #[arg(long)]
    pub target: String,
    /// Path to credentials JSON file.
    #[arg(long)]
    pub creds: PathBuf,
    /// Path to config JSON file.
    #[arg(long)]
    pub config: PathBuf,
    /// Optional pack path (required by some backends, e.g. cloud refs).
    #[arg(long)]
    pub pack: Option<PathBuf>,
    /// Treat validation warnings as errors.
    #[arg(long, default_value_t = false)]
    pub strict_validate: bool,
}

pub fn run(cmd: ExtCommand) -> ExtensionResult<()> {
    let dir = resolve_extension_dir(cmd.ext_dir.as_deref());
    match cmd.command {
        ExtSubcommand::List => run_list(&dir),
        ExtSubcommand::Info { ext_id } => run_info(&dir, &ext_id),
        ExtSubcommand::Validate { dir: target } => run_validate(&target),
        ExtSubcommand::Apply(args) => run_apply(&dir, args),
        ExtSubcommand::Destroy(args) => run_destroy(&dir, args),
    }
}

fn run_list(dir: &Path) -> ExtensionResult<()> {
    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let mut targets: Vec<_> = reg.list().collect();
    targets.sort_by(|a, b| a.contribution.id.cmp(&b.contribution.id));
    println!("{:<30}  {:<30}  {:<30}", "TARGET", "EXTENSION", "EXECUTION");
    for t in targets {
        let exec = match &t.contribution.execution {
            crate::ext::describe::Execution::Builtin { backend, handler } => match handler {
                Some(h) => format!("builtin:{backend}:{h}"),
                None => format!("builtin:{backend}"),
            },
            crate::ext::describe::Execution::Wasm => "wasm".to_string(),
        };
        println!("{:<30}  {:<30}  {}", t.contribution.id, t.ext_id, exec);
    }
    if !reg.conflicts().is_empty() {
        eprintln!(
            "\nWARNING: {} target id conflict(s) detected.",
            reg.conflicts().len()
        );
        for c in reg.conflicts() {
            eprintln!("  {} provided by: {:?}", c.target_id, c.providers);
        }
    }
    Ok(())
}

fn run_info(dir: &Path, ext_id: &str) -> ExtensionResult<()> {
    let loaded = scan(dir)?;
    let ext = loaded
        .iter()
        .find(|e| e.describe.metadata.id == ext_id)
        .ok_or_else(|| ExtensionError::TargetNotFound(ext_id.into()))?;
    println!("id:      {}", ext.describe.metadata.id);
    println!("version: {}", ext.describe.metadata.version);
    println!("root:    {}", ext.root_dir.display());
    println!("wasm:    {}", ext.wasm_path.display());
    println!("targets:");
    for t in &ext.describe.contributions.targets {
        println!("  - {} ({})", t.id, t.display_name);
    }
    Ok(())
}

fn run_validate(dir: &Path) -> ExtensionResult<()> {
    let v = scan(dir)?;
    if v.is_empty() {
        return Err(ExtensionError::DirNotFound(dir.into()));
    }
    for ext in &v {
        println!(
            "OK  {} ({} targets)",
            ext.describe.metadata.id,
            ext.describe.contributions.targets.len()
        );
    }
    Ok(())
}

pub fn run_apply(dir: &Path, args: ExtApplyArgs) -> ExtensionResult<()> {
    let creds_json = std::fs::read_to_string(&args.creds)
        .map_err(|source| ExtensionError::CredsReadError {
            path: args.creds.clone(),
            source,
        })?;
    let config_json = std::fs::read_to_string(&args.config)
        .map_err(|source| ExtensionError::ConfigReadError {
            path: args.config.clone(),
            source,
        })?;

    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let invoker = WasmtimeInvoker::new(&[dir])?;
    let action = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: &args.target,
            creds_json: &creds_json,
            config_json: &config_json,
            strict_validate: args.strict_validate,
        },
    )?;
    match action {
        DispatchAction::Builtin(bridge) => run_adapter(
            bridge.backend,
            bridge.handler.as_deref(),
            ExtAction::Apply,
            &creds_json,
            &config_json,
            args.pack.as_deref(),
        ),
    }
}

pub fn run_destroy(dir: &Path, args: ExtDestroyArgs) -> ExtensionResult<()> {
    let creds_json = std::fs::read_to_string(&args.creds)
        .map_err(|source| ExtensionError::CredsReadError {
            path: args.creds.clone(),
            source,
        })?;
    let config_json = std::fs::read_to_string(&args.config)
        .map_err(|source| ExtensionError::ConfigReadError {
            path: args.config.clone(),
            source,
        })?;

    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let invoker = WasmtimeInvoker::new(&[dir])?;
    let action = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: &args.target,
            creds_json: &creds_json,
            config_json: &config_json,
            strict_validate: args.strict_validate,
        },
    )?;
    match action {
        DispatchAction::Builtin(bridge) => run_adapter(
            bridge.backend,
            bridge.handler.as_deref(),
            ExtAction::Destroy,
            &creds_json,
            &config_json,
            args.pack.as_deref(),
        ),
    }
}

#[cfg(test)]
mod tests {
    // ... tests from Step 5.1 go here ...
}
```

Paste the tests from Step 5.1 into the `#[cfg(test)] mod tests { ... }` block at the bottom (replacing the `// ...` comment).

**Note:** Ensure `tempfile` is already in `[dev-dependencies]` in `Cargo.toml`. It's used in other tests so should be present. If not: `cargo add --dev tempfile`.

- [ ] **Step 5.4: Run tests to verify they pass**

```bash
cargo test --features extensions --lib ext::cli::tests 2>&1 | tail -20
```

Expected: 3 new tests pass.

- [ ] **Step 5.5: Build full binary to verify main.rs still compiles**

```bash
cargo build --features extensions 2>&1 | tail -15
```

Expected: clean build. `main.rs` doesn't need changes because `ExtSubcommand` extension is transparent to the `TopLevelCommand::Ext(cmd) => ext::cli::run(cmd)` arm.

- [ ] **Step 5.6: Commit**

```bash
git add src/ext/cli.rs
git commit -m "feat(ext): add Apply + Destroy subcommands to ext CLI

New: \`ext apply --target X --creds f --config g [--pack P] [--strict-validate]\`
New: \`ext destroy --target X ...\` (same shape)

Reads creds/config JSON from disk, builds ExtensionRegistry + WasmtimeInvoker,
dispatches via existing ext::dispatcher, executes via ext::backend_adapter.
File IO errors surface path in message. Clean separation: CLI knows nothing
about clap-structured BuiltinBackendCommand."
```

---

## Task 6: Delete `maybe_dispatch_via_extensions` placeholder

**Files:**
- Modify: `src/cli_builtin_dispatch.rs`

- [ ] **Step 6.1: Verify no callers of the helper**

```bash
rg 'maybe_dispatch_via_extensions' --type rust
```

Expected output: only the definition in `src/cli_builtin_dispatch.rs` and possibly doc references. No active callers.

- [ ] **Step 6.2: Delete the function**

Edit `src/cli_builtin_dispatch.rs`. Remove lines from `/// Resolve a non-builtin target-id through the extension registry.` (around line 198) through the end of `maybe_dispatch_via_extensions` function (around line 233) — inclusive of all comments, `#[cfg]` attribute, `#[allow]` attribute, signature, and body.

Also verify the final content of the file is clean (no trailing comments referencing PR#2).

- [ ] **Step 6.3: Build + test to verify no regression**

```bash
cargo build --features extensions 2>&1 | tail -10
cargo test --features extensions --lib 2>&1 | tail -30
```

Expected: clean build, all tests pass.

- [ ] **Step 6.4: Verify no dangling doc references**

```bash
rg 'maybe_dispatch_via_extensions|PR#2 \(deploy-desktop\)' --type rust --type md
```

Expected: no matches, or only historical references in `docs/superpowers/specs/2026-04-17-*` (fine; historical). If any active doc references the helper, update or remove.

- [ ] **Step 6.5: Commit**

```bash
git add src/cli_builtin_dispatch.rs
git commit -m "refactor(dispatch): remove maybe_dispatch_via_extensions placeholder

The Phase A helper bailed with 'PR#2 required' and was never called from
the main dispatch. Phase B #4a replaces it with ext::cli::run_apply /
run_destroy that dispatch via ext::backend_adapter directly."
```

---

## Task 7: Integration tests

**Files:**
- Create: `tests/ext_apply_integration.rs`

- [ ] **Step 7.1: Write the integration tests**

Create `tests/ext_apply_integration.rs`:

```rust
#![cfg(feature = "extensions")]

#[path = "support/env_guard.rs"]
mod env_guard;

use env_guard::EnvGuard;
use greentic_deployer::ext::cli::{ExtApplyArgs, ExtDestroyArgs, run_apply, run_destroy};
use greentic_deployer::ext::errors::ExtensionError;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

fn write_tempfile(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn ext_apply_missing_target_returns_target_not_found() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let args = ExtApplyArgs {
        target: "does-not-exist".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    assert!(
        matches!(err, ExtensionError::TargetNotFound(_)),
        "got: {err:?}"
    );
}

#[test]
fn ext_destroy_missing_target_returns_target_not_found() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let args = ExtDestroyArgs {
        target: "does-not-exist".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_destroy(&fixture_dir(), args).unwrap_err();
    assert!(
        matches!(err, ExtensionError::TargetNotFound(_)),
        "got: {err:?}"
    );
}

#[test]
fn ext_apply_testfixture_terraform_returns_adapter_not_implemented() {
    // The existing fixture uses backend=terraform, which is NOT in the
    // Phase B #4a adapter table. A successful dispatch must therefore bubble
    // AdapterNotImplemented rather than silently succeed.
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let creds = write_tempfile(tmp.path(), "creds.json", "{}");
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let args = ExtApplyArgs {
        target: "testfixture-noop".into(),
        creds,
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    assert!(
        matches!(err, ExtensionError::AdapterNotImplemented { .. }),
        "got: {err:?}"
    );
}

#[test]
fn ext_apply_missing_creds_file_propagates_creds_read_error() {
    let _env = EnvGuard::set("GREENTIC_EXT_ALLOW_UNSIGNED", "1");
    let tmp = tempfile::tempdir().unwrap();
    let config = write_tempfile(tmp.path(), "config.json", "{}");
    let args = ExtApplyArgs {
        target: "testfixture-noop".into(),
        creds: tmp.path().join("no-such.json"),
        config,
        pack: None,
        strict_validate: false,
    };
    let err = run_apply(&fixture_dir(), args).unwrap_err();
    assert!(
        matches!(err, ExtensionError::CredsReadError { .. }),
        "got: {err:?}"
    );
}
```

- [ ] **Step 7.2: Run integration tests**

```bash
cargo test --features extensions --test ext_apply_integration 2>&1 | tail -20
```

Expected: 4 tests pass. Note: `fixture_dir()` must exist; verify `testdata/ext/greentic.deploy-testfixture/` present.

- [ ] **Step 7.3: Commit**

```bash
git add tests/ext_apply_integration.rs
git commit -m "test(ext): integration tests for ext apply / ext destroy CLI

Covers: target-not-found path, adapter-not-implemented for terraform
backend in fixture, file-read error with path. Uses existing
testdata/ext/ fixture + GREENTIC_EXT_ALLOW_UNSIGNED=1 guard pattern
from Wave 3."
```

---

## Task 8: Extend CLI smoke tests

**Files:**
- Modify: `tests/ext_cli.rs`

- [ ] **Step 8.1: Inspect existing file to know how to extend**

```bash
cat tests/ext_cli.rs
```

- [ ] **Step 8.2: Add smoke tests (uses existing cli_binary support helper)**

Append to `tests/ext_cli.rs` (note: reuses existing `cli_binary` support module already imported at file top):

```rust
#[test]
fn ext_apply_help_lists_required_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args(["ext", "apply", "--help"]));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--target"), "stdout: {stdout}");
    assert!(stdout.contains("--creds"), "stdout: {stdout}");
    assert!(stdout.contains("--config"), "stdout: {stdout}");
    assert!(stdout.contains("--pack"), "stdout: {stdout}");
    assert!(stdout.contains("--strict-validate"), "stdout: {stdout}");
}

#[test]
fn ext_destroy_help_lists_required_flags() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args(["ext", "destroy", "--help"]));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--target"), "stdout: {stdout}");
    assert!(stdout.contains("--creds"), "stdout: {stdout}");
    assert!(stdout.contains("--config"), "stdout: {stdout}");
}

#[test]
fn ext_apply_without_required_flags_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args(["ext", "apply"]));
    assert!(!output.status.success(), "should fail without --target");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("--target"),
        "stderr: {stderr}"
    );
}

#[test]
fn ext_apply_unknown_target_exits_nonzero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let tmp_creds_dir = tempfile::tempdir().expect("tempdir");
    let creds = tmp_creds_dir.path().join("creds.json");
    let config = tmp_creds_dir.path().join("config.json");
    std::fs::write(&creds, "{}").unwrap();
    std::fs::write(&config, "{}").unwrap();
    let output = command_output_with_busy_retry(
        Command::new(&binary)
            .env("GREENTIC_EXT_ALLOW_UNSIGNED", "1")
            .args([
                "ext",
                "apply",
                "--ext-dir",
                fixture_dir().to_str().unwrap(),
                "--target",
                "does-not-exist",
                "--creds",
                creds.to_str().unwrap(),
                "--config",
                config.to_str().unwrap(),
            ]),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does-not-exist") || stderr.contains("not registered"),
        "stderr: {stderr}"
    );
}
```

**Note:** Uses existing `cli_binary::copied_test_binary` + `command_output_with_busy_retry` helpers already imported in `tests/ext_cli.rs:9`. No new dev-dependencies needed.

- [ ] **Step 8.3: Run smoke tests**

```bash
cargo test --features extensions --test ext_cli 2>&1 | tail -20
```

Expected: all existing + 4 new tests pass.

- [ ] **Step 8.4: Commit**

```bash
git add tests/ext_cli.rs
git commit -m "test(ext): CLI smoke tests for ext apply / ext destroy

Verifies: --help lists required flags, missing args → non-zero exit,
unknown target exits non-zero with clear stderr."
```

---

## Task 9: Full local CI pass + docs update

**Files:**
- Modify: `README.md` (optionally — document new subcommand)

- [ ] **Step 9.1: Run full local CI**

```bash
cd /home/bimbim/works/greentic/greentic-deployer
./ci/local_check.sh 2>&1 | tail -40
```

Expected: all gates pass (fmt, clippy, replay scaffolds, fixture gtpacks build, test all, doc, no-default-features baseline, extensions feature build, extensions feature test).

If fmt/clippy fails, fix and re-commit. If test fails, investigate and fix. Do not proceed until clean.

- [ ] **Step 9.2: Add README entry (optional but recommended)**

Check if README has an "Extensions" or "CLI subcommands" section. If yes, add a brief paragraph about `ext apply`/`destroy`. If no, skip this step — doc expansion can come in a follow-up PR.

```bash
grep -n -A 2 'ext list\|ext info\|ext validate' README.md
```

If existing mention of `ext list`/etc., append near it:

```markdown
Phase B #4a adds `ext apply` and `ext destroy` for extension-provided targets:

\`\`\`bash
greentic-deployer ext apply \\
  --target docker-compose-local \\
  --creds creds.json --config config.json \\
  --ext-dir ~/.greentic/extensions/deploy
\`\`\`

Currently supports Desktop (docker-compose/podman) + SingleVm (systemd) backends.
```

- [ ] **Step 9.3: Commit README update (if made)**

```bash
git add README.md
git commit -m "docs(readme): document ext apply / ext destroy subcommands"
```

---

## Task 10: Push branch + open PR

- [ ] **Step 10.1: Verify branch is ahead of main**

```bash
git log --oneline main..HEAD
```

Expected: 7-9 commits (spec + 8 impl + optional doc).

- [ ] **Step 10.2: Push to origin**

```bash
git push -u origin spec/phase-b-4a-ext-cli-wiring 2>&1 | tail -10
```

- [ ] **Step 10.3: Open PR**

```bash
gh pr create --title "feat(ext): Phase B #4a deployer CLI wiring for extension-provided targets" --body "$(cat <<'EOF'
## Summary

- Implements Phase B #4a per `docs/superpowers/specs/2026-04-19-phase-b-4a-deployer-cli-wiring-design.md`
- Adds `ext apply` + `ext destroy` CLI subcommands so `deploy-desktop@0.2.0` and `deploy-single-vm@0.1.0` become end-to-end invocable
- Desktop + SingleVm backends wired; other backends (aws/gcp/azure/terraform/etc.) return clean `AdapterNotImplemented` with a Phase B #4a scope message — shippable without blocking on Phase B #4b/c/d
- Deletes `maybe_dispatch_via_extensions` placeholder from `cli_builtin_dispatch.rs` (dead since Phase A)

## Architecture

- New `src/ext/backend_adapter.rs`: thin match table `(BuiltinBackendId, ExtAction) → backend lib fn`
- New `src/desktop.rs::apply_from_ext` / `destroy_from_ext` with `CommandRunner` trait injection for test stubbing (no real docker-compose in CI)
- New `src/single_vm.rs::apply_from_ext` / `destroy_from_ext` + `SingleVmExtConfig` JSON wrapper
- New error variants: `CredsReadError`, `ConfigReadError`, `AdapterNotImplemented`, `BackendExecutionFailed`
- Extended `ExtSubcommand::{Apply, Destroy}` + `run_apply` / `run_destroy` in `src/ext/cli.rs`
- No changes to built-in clap path (aws/terraform/etc. unchanged)

## Test plan

- [ ] Unit tests: errors (4), desktop (8), single_vm (5), backend_adapter (5), cli (3)
- [ ] Integration tests: `tests/ext_apply_integration.rs` (4) — target-not-found, adapter-not-implemented for terraform backend, file-read errors
- [ ] Smoke tests: `tests/ext_cli.rs` (4 new) — --help, missing args, unknown target
- [ ] `ci/local_check.sh` passes end-to-end (fmt, clippy, all tests, no-default-features baseline, extensions feature)
- [ ] Manual: `greentic-deployer ext apply --help` shows all 5 flags
EOF
)"
```

- [ ] **Step 10.4: Paste PR URL in session for user review**

---

## Self-Review Checklist (for plan author)

**Spec coverage:**
- §2 Q1 UX (flat `ext apply --target X`) → Task 5 ✓
- §2 Q2 scope (apply + destroy) → Tasks 5, 7, 8 ✓
- §2 Q3 adapter (per-backend `*_from_ext`) → Tasks 2, 3, 4 ✓
- §2 Q4 delete helper → Task 6 ✓
- §2 Q5 file paths only → Task 5 (flags shape) ✓
- §4.1 backend_adapter.rs → Task 4 ✓
- §4.2 cli.rs / desktop.rs / single_vm.rs / errors.rs / mod.rs → Tasks 5/2/3/1 ✓
- §5 data flow → exercised in Tasks 5, 7 ✓
- §6 error handling → Tasks 1, 4, 5 (each variant raised/tested) ✓
- §7 testing strategy (stubbing via CommandRunner = Option B) → Task 2 ✓
- §7.2 integration tests → Task 7 ✓
- §7.3 smoke tests → Task 8 ✓
- §8 acceptance criteria 1-10 → verified implicitly across tasks + Task 9 (local_check.sh)

**Placeholder scan:** No TBD/TODO/implement-later. Every code block is complete.

**Type consistency:**
- `CommandRunner` trait signature: `fn run(&self, cmd: &mut Command) -> anyhow::Result<ExitStatus>` — identical in Task 2 definition and Task 2 test usage ✓
- `SingleVmExtConfig` fields: `spec_path`, `apply_options`, `destroy_options` — consistent Task 3 ✓
- `ExtAction` enum: `Apply`, `Destroy` — consistent Tasks 4, 5 ✓
- `ExtApplyArgs` / `ExtDestroyArgs` fields: `target`, `creds`, `config`, `pack`, `strict_validate` — consistent Tasks 5, 7, 8 ✓
- `BuiltinBackendId` variants used: `Desktop`, `SingleVm`, `Aws`, `Gcp` — all verified present in existing `src/extension.rs` via Wave 3 ✓
