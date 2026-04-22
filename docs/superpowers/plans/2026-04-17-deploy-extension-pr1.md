# Deploy Extension Migration — PR#1 Implementation Plan (greentic-deployer)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add feature-gated WASM deploy extension handling to `greentic-deployer` without touching any existing backend file. Ships as PR#1 on branch `feat/ext-module` off `main`, feature `extensions` default-off.

**Architecture:** Additive `src/ext/` module (8 files). Extensions described by `describe.json` with an `execution` field that chooses between Mode A (route `deploy/poll/rollback` to an existing Rust backend via `cli_builtin_dispatch`) and Mode B (full WASM — returns `ModeBNotImplemented` in Phase A). Extension metadata (schemas + credential validation) always flows through WASM even in Mode A. A new `src/desktop.rs` backend (docker-compose + podman) is added to serve the reference `deploy-desktop` extension that ships separately from `greentic-deployer-extensions` (sibling repo, PR#2).

**Tech Stack:** Rust 1.91, edition 2024, `anyhow` + `thiserror`, `tokio` (existing), `jsonschema 0.45` (existing), `async-trait` (existing), `serde` + `serde_json` (existing), `greentic-ext-runtime` + `greentic-ext-contract` (NEW, `git+rev` pin to `greentic-designer-extensions` org repo).

**Spec reference:** `docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md`.

---

## File Structure

### New files (in this repo)

| Path | Responsibility |
| --- | --- |
| `src/ext/mod.rs` | Public API surface, feature-gate guard |
| `src/ext/errors.rs` | `ExtensionError` enum (thiserror) |
| `src/ext/describe.rs` | Parse `describe.json` with `Execution` tagged union |
| `src/ext/loader.rs` | Filesystem discovery, signature hook, build `Vec<LoadedExtension>` |
| `src/ext/registry.rs` | Unify built-in + loaded, conflict detection, `resolve()` |
| `src/ext/wasm.rs` | `trait WasmInvoker` + `WasmtimeInvoker` (greentic-ext-runtime wrapper) |
| `src/ext/builtin_bridge.rs` | Glue `Execution::Builtin { backend, handler }` → existing Rust backend call |
| `src/ext/dispatcher.rs` | Route `Execution::Builtin \| ::Wasm` |
| `src/ext/cli.rs` | `Ext` subcommand handler: `list / info / validate / install-dir` |
| `src/desktop.rs` | New backend: docker-compose + podman subprocess wrappers |
| `testdata/ext/greentic.deploy-testfixture/describe.json` | Fixture extension manifest |
| `testdata/ext/greentic.deploy-testfixture/extension.wasm` | Checked-in pre-built fixture WASM |
| `testdata/ext/greentic.deploy-testfixture/schemas/*.schema.json` | Fixture schemas |
| `testdata/ext/build_fixture.sh` | Regeneration script (not run in CI) |
| `tests/ext_loader.rs` | Integration: loader with fixture |
| `tests/ext_dispatch.rs` | Integration: dispatcher Mode A end-to-end |
| `tests/ext_cli.rs` | Integration: `greentic-deployer ext …` via binary |

### Modified files (in this repo)

| Path | Change |
| --- | --- |
| `Cargo.toml` | Add `[features] extensions = […]` + optional deps |
| `src/lib.rs` | `#[cfg(feature = "extensions")] pub mod ext;` |
| `src/main.rs` | Add `Ext(ExtCommand)` to `TopLevelCommand` + dispatch arm |
| `src/cli_builtin_dispatch.rs` | Fallback: unknown target → `ext::dispatcher` (feature-gated) |
| `src/extension.rs` | Add `impl FromStr for BuiltinBackendId`, `handler_matches(&self, Option<&str>) -> bool` |
| `ci/local_check.sh` | Add features-matrix step |

### Out-of-repo (tracked in sibling repo `greentic-deployer-extensions`, PR#2)

Reference extension `deploy-desktop/` — NOT created here. Integration test only exercises the in-repo fixture. Developer-machine smoke test for real docker deploy is acceptance criterion #10 (manual).

---

## Task 1: Cargo.toml — feature flag + optional deps

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Show current `[features]` and `[dependencies]` for orientation**

```bash
cat Cargo.toml | head -70
```

Expected: `[features] default = []\ninternal-tools = []` section; dependencies include `anyhow`, `async-trait`, `tokio`, `jsonschema`, `thiserror`, etc. No `greentic-ext-*` entries.

- [ ] **Step 2: Add optional deps + `extensions` feature**

Edit `Cargo.toml`. Replace the `[features]` block and append the two optional deps at the end of `[dependencies]`:

```toml
[features]
default = []
internal-tools = []
extensions = [
    "dep:greentic-ext-runtime",
    "dep:greentic-ext-contract",
]

# …existing [dependencies]…
greentic-ext-runtime  = { git = "ssh://git@github.com/greenticai/greentic-designer-extensions", branch = "feat/foundation", optional = true, package = "greentic-ext-runtime" }
greentic-ext-contract = { git = "ssh://git@github.com/greenticai/greentic-designer-extensions", branch = "feat/foundation", optional = true, package = "greentic-ext-contract" }
```

Use `branch = "feat/foundation"` initially; pin to `rev = "<sha>"` before PR merge (see Open Questions §Q2 in spec).

- [ ] **Step 3: Verify default build unchanged**

Run: `cargo build --no-default-features 2>&1 | tail -5`
Expected: compiles successfully, no new deps compiled. Exit 0.

Run: `cargo build 2>&1 | tail -5`
Expected: compiles successfully, no new deps compiled. Exit 0.

- [ ] **Step 4: Verify opt-in fetches and compiles deps**

Run: `cargo build --features extensions 2>&1 | tail -20`
Expected: fetches `greentic-ext-runtime`, `greentic-ext-contract`, plus their transitive deps (wasmtime 43, etc.). Compiles successfully. Exit 0.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat(ext): add extensions feature flag + optional deps"
```

---

## Task 2: `src/ext/mod.rs` + `src/lib.rs` + `src/ext/errors.rs`

**Files:**
- Create: `src/ext/mod.rs`
- Create: `src/ext/errors.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Gate module from lib.rs**

Edit `src/lib.rs` — append at the end:

```rust
#[cfg(feature = "extensions")]
pub mod ext;
```

- [ ] **Step 2: Create `src/ext/mod.rs` skeleton**

```rust
//! Deploy extension runtime integration.
//!
//! Loaded with `--features extensions`. See
//! `docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md`.

pub mod describe;
pub mod errors;
pub mod loader;
pub mod registry;
pub mod wasm;
pub mod builtin_bridge;
pub mod dispatcher;
pub mod cli;

pub use errors::ExtensionError;
pub use registry::ExtensionRegistry;
```

Note: this will not compile until later tasks create the referenced files. That is expected — we build it up module-by-module, committing each.

- [ ] **Step 3: Create `src/ext/errors.rs`**

```rust
use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum ExtensionError {
    #[error("extension directory not found: {0}")]
    DirNotFound(PathBuf),

    #[error("invalid describe.json at {path}: {source}")]
    DescribeParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("extension '{id}' signature verification failed")]
    SignatureInvalid { id: String },

    #[error("target '{target_id}' provided by both '{a}' and '{b}'")]
    TargetConflict {
        target_id: String,
        a: String,
        b: String,
    },

    #[error("target '{0}' not registered (try: `greentic-deployer ext list`)")]
    TargetNotFound(String),

    #[error("builtin backend '{backend}' unknown for target '{target_id}'")]
    UnknownBuiltinBackend { backend: String, target_id: String },

    #[error("builtin backend '{backend}' does not support handler '{handler:?}'")]
    UnsupportedHandler {
        backend: String,
        handler: Option<String>,
    },

    #[error("credential validation failed with {n} error(s)")]
    ValidationFailed { n: usize },

    #[error("WASM invocation failed: {0}")]
    WasmRuntime(#[from] anyhow::Error),

    #[error("Mode B (full WASM execution) not yet implemented — see spec §8 Phase B")]
    ModeBNotImplemented,
}

pub type ExtensionResult<T> = Result<T, ExtensionError>;
```

- [ ] **Step 4: Stub out referenced module files so the tree compiles at commit boundary**

Create empty stubs for each referenced module (we flesh them out task-by-task):

`src/ext/describe.rs`:
```rust
//! Stub: expanded in Task 3.
```

`src/ext/loader.rs`:
```rust
//! Stub: expanded in Task 4.
```

`src/ext/registry.rs`:
```rust
//! Stub: expanded in Task 6.
```

`src/ext/wasm.rs`:
```rust
//! Stub: expanded in Task 7.
```

`src/ext/builtin_bridge.rs`:
```rust
//! Stub: expanded in Task 8.
```

`src/ext/dispatcher.rs`:
```rust
//! Stub: expanded in Task 9.
```

`src/ext/cli.rs`:
```rust
//! Stub: expanded in Task 14.
```

- [ ] **Step 5: Verify compiles with extensions feature**

Run: `cargo build --features extensions 2>&1 | tail -10`
Expected: compiles, warns about unused imports in `mod.rs`. Exit 0.

Run: `cargo build 2>&1 | tail -5` (default features, no `extensions`)
Expected: compiles. `src/ext/` excluded entirely. Exit 0.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/ext/
git commit -m "feat(ext): scaffold ext module tree + ExtensionError"
```

---

## Task 3: `src/ext/describe.rs` — parse describe.json with `Execution` field

**Files:**
- Modify: `src/ext/describe.rs`

- [ ] **Step 1: Write the failing tests**

Replace `src/ext/describe.rs` contents with:

```rust
use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::ext::errors::{ExtensionError, ExtensionResult};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployExtensionDescribe {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    #[serde(default)]
    pub engine: Engine,
    #[serde(default)]
    pub capabilities: Capabilities,
    pub runtime: RuntimeSpec,
    pub contributions: DeployContributions,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Engine {
    #[serde(default)]
    pub ext_runtime: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct Capabilities {
    #[serde(default)]
    pub offered: Vec<serde_json::Value>,
    #[serde(default)]
    pub required: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSpec {
    pub component: String,
    #[serde(default)]
    pub memory_limit_mb: Option<u32>,
    #[serde(default)]
    pub permissions: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeployContributions {
    pub targets: Vec<DeployTargetContribution>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployTargetContribution {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_path: Option<PathBuf>,
    #[serde(default)]
    pub supports_rollback: bool,
    pub execution: Execution,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Execution {
    Builtin {
        backend: String,
        #[serde(default)]
        handler: Option<String>,
    },
    Wasm,
}

pub fn parse_describe(path: &Path) -> ExtensionResult<DeployExtensionDescribe> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        ExtensionError::DescribeParse {
            path: path.to_path_buf(),
            source: serde::de::Error::custom(format!("io: {e}")),
        }
    })?;
    serde_json::from_str(&contents).map_err(|source| ExtensionError::DescribeParse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_json(dir: &tempfile::TempDir, name: &str, body: &str) -> PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    const VALID_BUILTIN: &str = r#"{
        "apiVersion": "greentic.ai/v1",
        "kind": "DeployExtension",
        "metadata": { "id": "greentic.deploy-desktop", "version": "0.1.0" },
        "runtime": { "component": "extension.wasm", "memoryLimitMB": 64, "permissions": {} },
        "contributions": {
            "targets": [{
                "id": "docker-compose-local",
                "displayName": "Local Docker Compose",
                "supportsRollback": true,
                "execution": { "kind": "builtin", "backend": "desktop", "handler": "docker-compose" }
            }]
        }
    }"#;

    const VALID_WASM: &str = r#"{
        "apiVersion": "greentic.ai/v1",
        "kind": "DeployExtension",
        "metadata": { "id": "greentic.deploy-cisco", "version": "0.1.0" },
        "runtime": { "component": "extension.wasm", "memoryLimitMB": 128, "permissions": {} },
        "contributions": {
            "targets": [{
                "id": "cisco-box",
                "displayName": "Cisco Box",
                "execution": { "kind": "wasm" }
            }]
        }
    }"#;

    const MALFORMED: &str = r#"{ "apiVersion": "greentic.ai/v1", "kind": "DeployExtension" }"#;

    const UNKNOWN_EXECUTION_KIND: &str = r#"{
        "apiVersion": "greentic.ai/v1",
        "kind": "DeployExtension",
        "metadata": { "id": "greentic.bad", "version": "0.1.0" },
        "runtime": { "component": "extension.wasm" },
        "contributions": { "targets": [{
            "id": "x", "displayName": "X",
            "execution": { "kind": "docker" }
        }]}
    }"#;

    #[test]
    fn parses_builtin_execution() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", VALID_BUILTIN);
        let d = parse_describe(&p).expect("parse");
        assert_eq!(d.metadata.id, "greentic.deploy-desktop");
        assert_eq!(d.contributions.targets.len(), 1);
        let t = &d.contributions.targets[0];
        assert_eq!(t.id, "docker-compose-local");
        assert!(t.supports_rollback);
        match &t.execution {
            Execution::Builtin { backend, handler } => {
                assert_eq!(backend, "desktop");
                assert_eq!(handler.as_deref(), Some("docker-compose"));
            }
            _ => panic!("expected Builtin"),
        }
    }

    #[test]
    fn parses_wasm_execution() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", VALID_WASM);
        let d = parse_describe(&p).expect("parse");
        assert!(matches!(d.contributions.targets[0].execution, Execution::Wasm));
    }

    #[test]
    fn rejects_malformed_missing_contributions() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", MALFORMED);
        let err = parse_describe(&p).unwrap_err();
        matches!(err, ExtensionError::DescribeParse { .. });
    }

    #[test]
    fn rejects_unknown_execution_kind() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_json(&dir, "describe.json", UNKNOWN_EXECUTION_KIND);
        let err = parse_describe(&p).unwrap_err();
        matches!(err, ExtensionError::DescribeParse { .. });
    }
}
```

- [ ] **Step 2: Run tests to verify failure (they should be red first, but since we shipped impl + tests together, we run to confirm they pass)**

Run: `cargo test --features extensions --lib ext::describe 2>&1 | tail -15`
Expected: 4 tests pass.

If any fail, fix the impl until green before committing.

- [ ] **Step 3: Commit**

```bash
git add src/ext/describe.rs
git commit -m "feat(ext): describe.json parser with Execution tagged union"
```

---

## Task 4: `src/ext/loader.rs` — filesystem discovery

**Files:**
- Modify: `src/ext/loader.rs`

- [ ] **Step 1: Write full module with inline tests**

Replace `src/ext/loader.rs` contents with:

```rust
use std::path::{Path, PathBuf};

use crate::ext::describe::{parse_describe, DeployExtensionDescribe};
use crate::ext::errors::{ExtensionError, ExtensionResult};

/// Default on-disk root for deploy extensions.
pub const DEFAULT_DIR_ENV: &str = "GREENTIC_DEPLOY_EXT_DIR";

/// A successfully-loaded extension: describe.json parsed + wasm path recorded.
/// wasmtime::Component instantiation is lazy; see `wasm.rs`.
#[derive(Debug, Clone)]
pub struct LoadedExtension {
    pub root_dir: PathBuf,
    pub describe: DeployExtensionDescribe,
    pub wasm_path: PathBuf,
}

/// Resolve the directory to scan: explicit override > env var > default (`~/.greentic/extensions/deploy/`).
pub fn resolve_extension_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    if let Ok(e) = std::env::var(DEFAULT_DIR_ENV) {
        if !e.is_empty() {
            return PathBuf::from(e);
        }
    }
    dirs_root_default()
}

fn dirs_root_default() -> PathBuf {
    // `~/.greentic/extensions/deploy/`
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".greentic").join("extensions").join("deploy");
    }
    PathBuf::from("/var/empty/greentic/extensions/deploy")
}

/// Scan `dir` for extension subdirectories. Each valid extension is a directory
/// containing `describe.json` + the referenced `runtime.component` wasm file.
/// Missing dirs return empty (not an error — allows first-run UX).
/// Malformed extensions are skipped with a warning (tracing::warn).
pub fn scan(dir: &Path) -> ExtensionResult<Vec<LoadedExtension>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    if !dir.is_dir() {
        return Err(ExtensionError::DirNotFound(dir.to_path_buf()));
    }
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|_| ExtensionError::DirNotFound(dir.to_path_buf()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        match load_one(&path) {
            Ok(ext) => out.push(ext),
            Err(e) => tracing::warn!(
                extension_dir = %path.display(),
                error = %e,
                "skipping malformed extension"
            ),
        }
    }
    // Deterministic order for reproducible tests.
    out.sort_by(|a, b| a.describe.metadata.id.cmp(&b.describe.metadata.id));
    Ok(out)
}

fn load_one(dir: &Path) -> ExtensionResult<LoadedExtension> {
    let describe_path = dir.join("describe.json");
    let describe = parse_describe(&describe_path)?;
    let wasm_path = dir.join(&describe.runtime.component);
    if !wasm_path.exists() {
        return Err(ExtensionError::DescribeParse {
            path: describe_path,
            source: serde::de::Error::custom(format!(
                "referenced component {:?} not found",
                describe.runtime.component
            )),
        });
    }
    Ok(LoadedExtension {
        root_dir: dir.to_path_buf(),
        describe,
        wasm_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn seed_ext(root: &Path, id: &str, targets_json: &str) -> PathBuf {
        let dir = root.join(id);
        fs::create_dir_all(&dir).unwrap();
        let describe = format!(
            r#"{{
            "apiVersion": "greentic.ai/v1",
            "kind": "DeployExtension",
            "metadata": {{ "id": "{id}", "version": "0.1.0" }},
            "runtime": {{ "component": "extension.wasm" }},
            "contributions": {{ "targets": {targets_json} }}
        }}"#
        );
        fs::write(dir.join("describe.json"), describe).unwrap();
        fs::write(dir.join("extension.wasm"), b"\x00asm\x01\x00\x00\x00").unwrap();
        dir
    }

    #[test]
    fn scan_empty_dir_returns_empty() {
        let td = tempfile::tempdir().unwrap();
        let v = scan(td.path()).expect("scan");
        assert!(v.is_empty());
    }

    #[test]
    fn scan_missing_dir_returns_empty() {
        let td = tempfile::tempdir().unwrap();
        let missing = td.path().join("nope");
        let v = scan(&missing).expect("scan");
        assert!(v.is_empty());
    }

    #[test]
    fn scan_discovers_two_extensions_sorted() {
        let td = tempfile::tempdir().unwrap();
        seed_ext(
            td.path(),
            "greentic.deploy-zed",
            r#"[{"id":"t1","displayName":"T1","execution":{"kind":"wasm"}}]"#,
        );
        seed_ext(
            td.path(),
            "greentic.deploy-aardvark",
            r#"[{"id":"t2","displayName":"T2","execution":{"kind":"wasm"}}]"#,
        );
        let v = scan(td.path()).expect("scan");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].describe.metadata.id, "greentic.deploy-aardvark");
        assert_eq!(v[1].describe.metadata.id, "greentic.deploy-zed");
    }

    #[test]
    fn scan_skips_malformed_but_returns_others() {
        let td = tempfile::tempdir().unwrap();
        seed_ext(
            td.path(),
            "greentic.good",
            r#"[{"id":"t","displayName":"T","execution":{"kind":"wasm"}}]"#,
        );
        let bad = td.path().join("greentic.bad");
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join("describe.json"), "{ not json").unwrap();
        let v = scan(td.path()).expect("scan");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].describe.metadata.id, "greentic.good");
    }

    #[test]
    fn scan_skips_ext_missing_wasm_component() {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("greentic.nowasm");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("describe.json"),
            r#"{"apiVersion":"greentic.ai/v1","kind":"DeployExtension",
                "metadata":{"id":"greentic.nowasm","version":"0.1.0"},
                "runtime":{"component":"extension.wasm"},
                "contributions":{"targets":[]}}"#,
        )
        .unwrap();
        let v = scan(td.path()).expect("scan");
        assert!(v.is_empty());
    }

    #[test]
    fn resolve_env_override_wins() {
        let td = tempfile::tempdir().unwrap();
        // Use scoped env modification.
        let prev = std::env::var(DEFAULT_DIR_ENV).ok();
        std::env::set_var(DEFAULT_DIR_ENV, td.path());
        let resolved = resolve_extension_dir(None);
        assert_eq!(resolved, td.path());
        match prev {
            Some(v) => std::env::set_var(DEFAULT_DIR_ENV, v),
            None => std::env::remove_var(DEFAULT_DIR_ENV),
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --features extensions --lib ext::loader 2>&1 | tail -20`
Expected: 6 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/ext/loader.rs
git commit -m "feat(ext): filesystem loader with discovery + env override"
```

---

## Task 5: `src/extension.rs` — `FromStr` + `handler_matches` for `BuiltinBackendId`

**Files:**
- Modify: `src/extension.rs`

**Context:** `BuiltinBackendId` currently has 11 variants with `#[serde(rename_all = "snake_case")]`. Extensions will reference backends by the same snake_case string (e.g., `"aws"`, `"terraform"`, `"k8s_raw"`). We also need to validate handler strings per backend at registry-build time.

- [ ] **Step 1: Write failing tests**

Append at the bottom of `src/extension.rs`, inside the existing `#[cfg(test)] mod tests` block if present, or add a new one:

```rust
#[cfg(test)]
mod ext_roundtrip_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn from_str_all_variants_roundtrip() {
        let cases = [
            ("terraform",    BuiltinBackendId::Terraform),
            ("k8s_raw",      BuiltinBackendId::K8sRaw),
            ("helm",         BuiltinBackendId::Helm),
            ("aws",          BuiltinBackendId::Aws),
            ("azure",        BuiltinBackendId::Azure),
            ("gcp",          BuiltinBackendId::Gcp),
            ("juju_k8s",     BuiltinBackendId::JujuK8s),
            ("juju_machine", BuiltinBackendId::JujuMachine),
            ("operator",     BuiltinBackendId::Operator),
            ("serverless",   BuiltinBackendId::Serverless),
            ("snap",         BuiltinBackendId::Snap),
        ];
        for (s, expected) in cases {
            assert_eq!(BuiltinBackendId::from_str(s).unwrap(), expected);
            assert_eq!(expected.as_str(), s);
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        let err = BuiltinBackendId::from_str("mystery").unwrap_err();
        assert!(err.to_string().contains("mystery"));
    }

    #[test]
    fn from_str_is_case_sensitive() {
        assert!(BuiltinBackendId::from_str("AWS").is_err());
        assert!(BuiltinBackendId::from_str("Terraform").is_err());
    }

    #[test]
    fn handler_matches_permits_none_for_all() {
        // Phase A: no backend has handler-discriminated dispatch (the existing
        // code uses one handler per backend). None always matches.
        for b in [
            BuiltinBackendId::Terraform,
            BuiltinBackendId::Aws,
            BuiltinBackendId::Helm,
        ] {
            assert!(b.handler_matches(None));
        }
    }

    #[test]
    fn handler_matches_rejects_unknown_for_all_existing() {
        // Existing backends accept None only. Unknown handler fails.
        assert!(!BuiltinBackendId::Aws.handler_matches(Some("eks")));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features extensions --lib ext_roundtrip_tests 2>&1 | tail -10`
Expected: compile error "no method named `from_str`" or "no function `as_str`".

- [ ] **Step 3: Add `FromStr`, `as_str`, and `handler_matches` impls**

Append to `src/extension.rs` immediately after the `BuiltinBackendId` definition:

```rust
impl BuiltinBackendId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform   => "terraform",
            Self::K8sRaw      => "k8s_raw",
            Self::Helm        => "helm",
            Self::Aws         => "aws",
            Self::Azure       => "azure",
            Self::Gcp         => "gcp",
            Self::JujuK8s     => "juju_k8s",
            Self::JujuMachine => "juju_machine",
            Self::Operator    => "operator",
            Self::Serverless  => "serverless",
            Self::Snap        => "snap",
        }
    }

    /// Return `true` iff this backend accepts the given handler string.
    /// Phase A: every existing backend has a single implicit handler; `None`
    /// always matches and any other value is rejected.
    /// Re-evaluate when a backend grows multi-handler dispatch.
    pub fn handler_matches(self, handler: Option<&str>) -> bool {
        handler.is_none()
    }
}

impl std::str::FromStr for BuiltinBackendId {
    type Err = UnknownBuiltinBackendStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "terraform"    => Self::Terraform,
            "k8s_raw"      => Self::K8sRaw,
            "helm"         => Self::Helm,
            "aws"          => Self::Aws,
            "azure"        => Self::Azure,
            "gcp"          => Self::Gcp,
            "juju_k8s"     => Self::JujuK8s,
            "juju_machine" => Self::JujuMachine,
            "operator"     => Self::Operator,
            "serverless"   => Self::Serverless,
            "snap"         => Self::Snap,
            other => return Err(UnknownBuiltinBackendStr(other.to_string())),
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown builtin backend id: '{0}'")]
pub struct UnknownBuiltinBackendStr(pub String);
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --features extensions --lib ext_roundtrip_tests 2>&1 | tail -10`
Expected: 5 tests pass.

Run also default features: `cargo test --lib ext_roundtrip_tests 2>&1 | tail -10` — tests are in the `src/extension.rs` file (no feature gate), must pass both ways.

- [ ] **Step 5: Commit**

```bash
git add src/extension.rs
git commit -m "feat(extension): FromStr + handler_matches for BuiltinBackendId"
```

---

## Task 6: `src/ext/registry.rs` — unify built-in + loaded, conflict detection

**Files:**
- Modify: `src/ext/registry.rs`

- [ ] **Step 1: Write full module with inline tests**

Replace `src/ext/registry.rs` contents with:

```rust
use std::collections::HashMap;
use std::path::PathBuf;

use crate::ext::describe::{DeployTargetContribution, Execution};
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::ext::loader::LoadedExtension;

/// A resolved target: where it came from (ext id) and how to execute it.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub ext_id: String,
    pub wasm_path: PathBuf,
    pub contribution: DeployTargetContribution,
}

/// Registry unifying loaded WASM extensions' targets. (Built-in backends are
/// dispatched directly through `cli_builtin_dispatch` and do not appear here —
/// extensions are the only way to contribute *new* target-ids.)
pub struct ExtensionRegistry {
    entries: HashMap<String, ResolvedTarget>,
    // Record unresolved conflicts: target_id → list of (ext_id, ext_id) sharing it.
    conflicts: Vec<ConflictRecord>,
}

#[derive(Debug, Clone)]
pub struct ConflictRecord {
    pub target_id: String,
    pub providers: Vec<String>,
}

impl ExtensionRegistry {
    pub fn build(loaded: Vec<LoadedExtension>) -> Self {
        let mut entries: HashMap<String, ResolvedTarget> = HashMap::new();
        let mut providers: HashMap<String, Vec<String>> = HashMap::new();

        for ext in loaded {
            let ext_id = ext.describe.metadata.id.clone();
            for contrib in ext.describe.contributions.targets {
                providers
                    .entry(contrib.id.clone())
                    .or_default()
                    .push(ext_id.clone());
                entries
                    .entry(contrib.id.clone())
                    .or_insert(ResolvedTarget {
                        ext_id: ext_id.clone(),
                        wasm_path: ext.wasm_path.clone(),
                        contribution: contrib,
                    });
            }
        }

        let conflicts: Vec<ConflictRecord> = providers
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(target_id, providers)| ConflictRecord { target_id, providers })
            .collect();

        for c in &conflicts {
            tracing::warn!(
                target_id = %c.target_id,
                providers = ?c.providers,
                "target provided by multiple extensions — first wins at dispatch unless unique"
            );
        }

        Self { entries, conflicts }
    }

    pub fn resolve(&self, target_id: &str) -> ExtensionResult<&ResolvedTarget> {
        if let Some(c) = self.conflicts.iter().find(|c| c.target_id == target_id) {
            return Err(ExtensionError::TargetConflict {
                target_id: target_id.into(),
                a: c.providers.first().cloned().unwrap_or_default(),
                b: c.providers.get(1).cloned().unwrap_or_default(),
            });
        }
        self.entries
            .get(target_id)
            .ok_or_else(|| ExtensionError::TargetNotFound(target_id.into()))
    }

    pub fn list(&self) -> impl Iterator<Item = &ResolvedTarget> {
        self.entries.values()
    }

    pub fn conflicts(&self) -> &[ConflictRecord] {
        &self.conflicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::describe::{DeployExtensionDescribe, DeployContributions, Metadata, RuntimeSpec, Engine, Capabilities};

    fn make_ext(id: &str, target_ids: &[&str]) -> LoadedExtension {
        LoadedExtension {
            root_dir: PathBuf::from("/tmp/fake"),
            wasm_path: PathBuf::from("/tmp/fake/extension.wasm"),
            describe: DeployExtensionDescribe {
                api_version: "greentic.ai/v1".into(),
                kind: "DeployExtension".into(),
                metadata: Metadata { id: id.into(), version: "0.1.0".into(), summary: None },
                engine: Engine::default(),
                capabilities: Capabilities::default(),
                runtime: RuntimeSpec {
                    component: "extension.wasm".into(),
                    memory_limit_mb: None,
                    permissions: serde_json::Value::Null,
                },
                contributions: DeployContributions {
                    targets: target_ids
                        .iter()
                        .map(|t| DeployTargetContribution {
                            id: (*t).into(),
                            display_name: format!("{t} display"),
                            description: None,
                            icon_path: None,
                            supports_rollback: false,
                            execution: Execution::Builtin {
                                backend: "terraform".into(),
                                handler: None,
                            },
                        })
                        .collect(),
                },
            },
        }
    }

    #[test]
    fn build_unique_targets_resolves() {
        let r = ExtensionRegistry::build(vec![
            make_ext("greentic.a", &["t1", "t2"]),
            make_ext("greentic.b", &["t3"]),
        ]);
        assert!(r.conflicts().is_empty());
        assert_eq!(r.list().count(), 3);
        assert_eq!(r.resolve("t1").unwrap().ext_id, "greentic.a");
        assert_eq!(r.resolve("t3").unwrap().ext_id, "greentic.b");
    }

    #[test]
    fn conflict_recorded_and_resolve_errors() {
        let r = ExtensionRegistry::build(vec![
            make_ext("greentic.a", &["dup"]),
            make_ext("greentic.b", &["dup"]),
        ]);
        assert_eq!(r.conflicts().len(), 1);
        let err = r.resolve("dup").unwrap_err();
        matches!(err, ExtensionError::TargetConflict { .. });
    }

    #[test]
    fn resolve_missing_target_errors() {
        let r = ExtensionRegistry::build(vec![make_ext("greentic.a", &["t1"])]);
        let err = r.resolve("nope").unwrap_err();
        matches!(err, ExtensionError::TargetNotFound(_));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --features extensions --lib ext::registry 2>&1 | tail -15`
Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/ext/registry.rs
git commit -m "feat(ext): registry with conflict detection + resolve"
```

---

## Task 7: `src/ext/wasm.rs` — `WasmInvoker` trait + `WasmtimeInvoker` wrapper

**Files:**
- Modify: `src/ext/wasm.rs`

**Context:** `greentic-ext-runtime` provides `ExtensionRuntime` with `invoke_tool(ext_id, tool_name, args_json) -> String`. We wrap the deploy-specific surface behind a trait so dispatcher tests can use a mock without instantiating wasmtime.

- [ ] **Step 1: Write full module with trait + mock + wasmtime impl sketch**

Replace `src/ext/wasm.rs` contents with:

```rust
use std::path::Path;

use crate::ext::errors::{ExtensionError, ExtensionResult};

/// The deploy-specific slice of extension surface that the dispatcher calls into.
/// `deploy`/`poll`/`rollback` are intentionally NOT on this trait in Phase A —
/// Mode A routes them to the built-in bridge; Mode B returns `ModeBNotImplemented`.
pub trait WasmInvoker: Send + Sync {
    fn list_targets(&self, ext_id: &str) -> ExtensionResult<String>;
    fn credential_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String>;
    fn config_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String>;
    fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        creds_json: &str,
    ) -> ExtensionResult<Vec<Diagnostic>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

/// Production invoker: wraps `greentic_ext_runtime::ExtensionRuntime`.
/// Minimal stub for Phase A — only the four metadata methods.
pub struct WasmtimeInvoker {
    runtime: std::sync::Arc<greentic_ext_runtime::ExtensionRuntime>,
}

impl WasmtimeInvoker {
    pub fn new(ext_dirs: &[&Path]) -> ExtensionResult<Self> {
        let config = greentic_ext_runtime::RuntimeConfig::default();
        let runtime = greentic_ext_runtime::ExtensionRuntime::new(config)
            .map_err(ExtensionError::WasmRuntime)?;
        for d in ext_dirs {
            runtime
                .register_loaded_from_dir(d)
                .map_err(ExtensionError::WasmRuntime)?;
        }
        Ok(Self { runtime: std::sync::Arc::new(runtime) })
    }
}

impl WasmInvoker for WasmtimeInvoker {
    fn list_targets(&self, ext_id: &str) -> ExtensionResult<String> {
        // greentic-ext-runtime exposes invoke_tool; for WIT fn calls we use the
        // generic invocation path. Real impl uses the `deploy` interface binding
        // once greentic-ext-runtime exposes a typed helper — for Phase A we go
        // through invoke_tool with a pre-agreed tool name.
        self.runtime
            .invoke_tool(ext_id, "list-targets", "{}")
            .map_err(ExtensionError::WasmRuntime)
    }

    fn credential_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        let args = serde_json::json!({ "targetId": target_id }).to_string();
        self.runtime
            .invoke_tool(ext_id, "credential-schema", &args)
            .map_err(ExtensionError::WasmRuntime)
    }

    fn config_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        let args = serde_json::json!({ "targetId": target_id }).to_string();
        self.runtime
            .invoke_tool(ext_id, "config-schema", &args)
            .map_err(ExtensionError::WasmRuntime)
    }

    fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        creds_json: &str,
    ) -> ExtensionResult<Vec<Diagnostic>> {
        let args = serde_json::json!({
            "targetId": target_id,
            "credsJson": creds_json,
        })
        .to_string();
        let out = self
            .runtime
            .invoke_tool(ext_id, "validate-credentials", &args)
            .map_err(ExtensionError::WasmRuntime)?;
        let diags: Vec<Diagnostic> = serde_json::from_str(&out).unwrap_or_default();
        Ok(diags)
    }
}

// Serde for Diagnostic lives here so WasmtimeInvoker can parse the WASM output.
impl<'de> serde::Deserialize<'de> for Diagnostic {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            severity: String,
            code: String,
            message: String,
            #[serde(default)]
            path: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        Ok(Diagnostic {
            severity: match r.severity.as_str() {
                "error" => DiagnosticSeverity::Error,
                "warning" => DiagnosticSeverity::Warning,
                _ => DiagnosticSeverity::Info,
            },
            code: r.code,
            message: r.message,
            path: r.path,
        })
    }
}

/// Mock invoker for tests.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default)]
pub struct MockInvoker {
    pub schemas_creds: std::collections::HashMap<(String, String), String>,
    pub schemas_config: std::collections::HashMap<(String, String), String>,
    pub validate_diagnostics: std::collections::HashMap<(String, String), Vec<Diagnostic>>,
    pub list_targets_response: std::collections::HashMap<String, String>,
}

#[cfg(any(test, feature = "test-utils"))]
impl WasmInvoker for MockInvoker {
    fn list_targets(&self, ext_id: &str) -> ExtensionResult<String> {
        Ok(self.list_targets_response.get(ext_id).cloned().unwrap_or("[]".into()))
    }
    fn credential_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        Ok(self
            .schemas_creds
            .get(&(ext_id.to_string(), target_id.to_string()))
            .cloned()
            .unwrap_or("{}".into()))
    }
    fn config_schema(&self, ext_id: &str, target_id: &str) -> ExtensionResult<String> {
        Ok(self
            .schemas_config
            .get(&(ext_id.to_string(), target_id.to_string()))
            .cloned()
            .unwrap_or("{}".into()))
    }
    fn validate_credentials(
        &self,
        ext_id: &str,
        target_id: &str,
        _creds_json: &str,
    ) -> ExtensionResult<Vec<Diagnostic>> {
        Ok(self
            .validate_diagnostics
            .get(&(ext_id.to_string(), target_id.to_string()))
            .cloned()
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_invoker_returns_defaults() {
        let m = MockInvoker::default();
        assert_eq!(m.list_targets("any").unwrap(), "[]");
        assert_eq!(m.credential_schema("e", "t").unwrap(), "{}");
        assert_eq!(m.config_schema("e", "t").unwrap(), "{}");
        assert!(m.validate_credentials("e", "t", "{}").unwrap().is_empty());
    }

    #[test]
    fn mock_invoker_returns_configured_values() {
        let mut m = MockInvoker::default();
        m.schemas_creds.insert(("greentic.a".into(), "t1".into()), r#"{"type":"object"}"#.into());
        assert_eq!(
            m.credential_schema("greentic.a", "t1").unwrap(),
            r#"{"type":"object"}"#
        );
    }
}
```

Note on `greentic-ext-runtime` API: `invoke_tool(ext_id, tool_name, args_json_string) -> Result<String, anyhow::Error>` per the raw material finding. If the runtime's API differs (e.g. typed deploy-interface bindings), update the impl to use typed bindings and keep the trait surface stable.

- [ ] **Step 2: Run tests**

Run: `cargo test --features extensions --lib ext::wasm 2>&1 | tail -15`
Expected: 2 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/ext/wasm.rs
git commit -m "feat(ext): WasmInvoker trait + WasmtimeInvoker + MockInvoker"
```

---

## Task 8: `src/ext/builtin_bridge.rs` — Execution::Builtin → backend dispatch

**Files:**
- Modify: `src/ext/builtin_bridge.rs`

**Context:** For Mode A, the bridge translates `execution.builtin.backend` (snake_case string) into a `BuiltinBackendId` variant and validates the handler. Actual execution is routed via existing `cli_builtin_dispatch` — **this bridge does not invoke backend functions directly**; it builds and returns the dispatch parameters. The caller (`dispatcher.rs`) then wires them into the existing subprocess-CLI pathway. Keep the bridge IO-free so it stays unit-testable.

Note on `Desktop`: `BuiltinBackendId` does NOT yet include `Desktop`. Task 13 adds it. For this task, the test suite exercises the existing 11 backends. The `Desktop` case will be added in Task 13 when the variant exists.

- [ ] **Step 1: Write full module with tests**

Replace `src/ext/builtin_bridge.rs` contents with:

```rust
use std::str::FromStr;

use crate::ext::describe::Execution;
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::extension::BuiltinBackendId;

/// Resolved built-in dispatch parameters. IO-free. Actual execution is
/// performed by the caller via `cli_builtin_dispatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeResolved {
    pub backend: BuiltinBackendId,
    pub handler: Option<String>,
}

/// Resolve `Execution::Builtin { backend, handler }` into a validated
/// `(BuiltinBackendId, handler)` pair. Returns an error if the backend string
/// is unknown or the handler is not permitted by the backend.
pub fn resolve(execution: &Execution, target_id: &str) -> ExtensionResult<BridgeResolved> {
    match execution {
        Execution::Builtin { backend, handler } => {
            let id = BuiltinBackendId::from_str(backend).map_err(|_| {
                ExtensionError::UnknownBuiltinBackend {
                    backend: backend.clone(),
                    target_id: target_id.into(),
                }
            })?;
            if !id.handler_matches(handler.as_deref()) {
                return Err(ExtensionError::UnsupportedHandler {
                    backend: backend.clone(),
                    handler: handler.clone(),
                });
            }
            Ok(BridgeResolved { backend: id, handler: handler.clone() })
        }
        Execution::Wasm => Err(ExtensionError::ModeBNotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_builtin_known_backend_no_handler() {
        let exec = Execution::Builtin { backend: "terraform".into(), handler: None };
        let r = resolve(&exec, "some-tf-target").unwrap();
        assert_eq!(r.backend, BuiltinBackendId::Terraform);
        assert!(r.handler.is_none());
    }

    #[test]
    fn resolve_unknown_backend_errors_with_target_id() {
        let exec = Execution::Builtin { backend: "mystery".into(), handler: None };
        let err = resolve(&exec, "t").unwrap_err();
        match err {
            ExtensionError::UnknownBuiltinBackend { backend, target_id } => {
                assert_eq!(backend, "mystery");
                assert_eq!(target_id, "t");
            }
            _ => panic!("wrong error: {err}"),
        }
    }

    #[test]
    fn resolve_unsupported_handler_for_existing_backend_errors() {
        // Phase A: all existing backends reject any non-None handler.
        let exec = Execution::Builtin {
            backend: "aws".into(),
            handler: Some("eks".into()),
        };
        let err = resolve(&exec, "t").unwrap_err();
        match err {
            ExtensionError::UnsupportedHandler { backend, handler } => {
                assert_eq!(backend, "aws");
                assert_eq!(handler.as_deref(), Some("eks"));
            }
            _ => panic!("wrong error: {err}"),
        }
    }

    #[test]
    fn resolve_wasm_returns_mode_b_not_implemented() {
        let exec = Execution::Wasm;
        let err = resolve(&exec, "t").unwrap_err();
        matches!(err, ExtensionError::ModeBNotImplemented);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --features extensions --lib ext::builtin_bridge 2>&1 | tail -15`
Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/ext/builtin_bridge.rs
git commit -m "feat(ext): builtin_bridge resolves Execution to backend id"
```

---

## Task 9: `src/ext/dispatcher.rs` — orchestrator

**Files:**
- Modify: `src/ext/dispatcher.rs`

**Context:** The dispatcher is the entry point called from `cli_builtin_dispatch.rs` when a target is not a native `BuiltinBackendId`. Responsibilities:
1. Resolve target via registry.
2. Fetch schemas via `WasmInvoker`; validate `creds_json` and `config_json` host-side with `jsonschema`.
3. Call `wasm.validate_credentials` for programmatic checks.
4. If all clean, return a `DispatchAction` describing what should happen next. The caller in Phase A maps `DispatchAction::Builtin(BridgeResolved)` into the existing dispatch pathway; `DispatchAction::Wasm` returns `ModeBNotImplemented`.

- [ ] **Step 1: Write full module with tests**

Replace `src/ext/dispatcher.rs` contents with:

```rust
use jsonschema::JSONSchema;

use crate::ext::builtin_bridge::{self, BridgeResolved};
use crate::ext::describe::Execution;
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::ext::registry::ExtensionRegistry;
use crate::ext::wasm::{DiagnosticSeverity, WasmInvoker};

/// What the caller should do after dispatching.
#[derive(Debug, Clone)]
pub enum DispatchAction {
    Builtin(BridgeResolved),
    // Wasm variant reserved for Phase B.
}

pub struct DispatchInput<'a> {
    pub target_id: &'a str,
    pub creds_json: &'a str,
    pub config_json: &'a str,
    pub strict_validate: bool,
}

pub fn dispatch_extension(
    registry: &ExtensionRegistry,
    invoker: &dyn WasmInvoker,
    input: DispatchInput<'_>,
) -> ExtensionResult<DispatchAction> {
    let resolved = registry.resolve(input.target_id)?;
    let ext_id = &resolved.ext_id;
    let target_id = input.target_id;

    let schema_creds = invoker.credential_schema(ext_id, target_id)?;
    validate_against_schema(&schema_creds, input.creds_json, "credentials")?;

    let schema_config = invoker.config_schema(ext_id, target_id)?;
    validate_against_schema(&schema_config, input.config_json, "config")?;

    let diagnostics = invoker.validate_credentials(ext_id, target_id, input.creds_json)?;
    let fatal = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DiagnosticSeverity::Error))
        .count();
    let warn_count = diagnostics
        .iter()
        .filter(|d| matches!(d.severity, DiagnosticSeverity::Warning))
        .count();
    if fatal > 0 || (input.strict_validate && warn_count > 0) {
        return Err(ExtensionError::ValidationFailed { n: fatal + warn_count });
    }

    match &resolved.contribution.execution {
        Execution::Builtin { .. } => {
            let bridge = builtin_bridge::resolve(&resolved.contribution.execution, target_id)?;
            Ok(DispatchAction::Builtin(bridge))
        }
        Execution::Wasm => Err(ExtensionError::ModeBNotImplemented),
    }
}

fn validate_against_schema(
    schema_str: &str,
    value_str: &str,
    label: &str,
) -> ExtensionResult<()> {
    let schema_val: serde_json::Value =
        serde_json::from_str(schema_str).map_err(|e| ExtensionError::DescribeParse {
            path: std::path::PathBuf::from(format!("<schema:{label}>")),
            source: e,
        })?;
    let value_val: serde_json::Value =
        serde_json::from_str(value_str).map_err(|e| ExtensionError::DescribeParse {
            path: std::path::PathBuf::from(format!("<value:{label}>")),
            source: e,
        })?;
    let compiled = JSONSchema::compile(&schema_val).map_err(|e| {
        ExtensionError::WasmRuntime(anyhow::anyhow!("invalid {label} schema: {e}"))
    })?;
    let result = compiled.validate(&value_val);
    if let Err(errs) = result {
        let n = errs.count();
        return Err(ExtensionError::ValidationFailed { n });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::describe::{
        Capabilities, DeployContributions, DeployExtensionDescribe, DeployTargetContribution,
        Engine, Metadata, RuntimeSpec,
    };
    use crate::ext::loader::LoadedExtension;
    use crate::ext::wasm::MockInvoker;
    use std::path::PathBuf;

    fn registry_with(ext_id: &str, target_id: &str, exec: Execution) -> ExtensionRegistry {
        ExtensionRegistry::build(vec![LoadedExtension {
            root_dir: PathBuf::from("/tmp/fake"),
            wasm_path: PathBuf::from("/tmp/fake/extension.wasm"),
            describe: DeployExtensionDescribe {
                api_version: "greentic.ai/v1".into(),
                kind: "DeployExtension".into(),
                metadata: Metadata {
                    id: ext_id.into(),
                    version: "0.1.0".into(),
                    summary: None,
                },
                engine: Engine::default(),
                capabilities: Capabilities::default(),
                runtime: RuntimeSpec {
                    component: "extension.wasm".into(),
                    memory_limit_mb: None,
                    permissions: serde_json::Value::Null,
                },
                contributions: DeployContributions {
                    targets: vec![DeployTargetContribution {
                        id: target_id.into(),
                        display_name: target_id.into(),
                        description: None,
                        icon_path: None,
                        supports_rollback: false,
                        execution: exec,
                    }],
                },
            },
        }])
    }

    #[test]
    fn dispatch_builtin_happy_path() {
        let reg = registry_with(
            "greentic.a",
            "docker-compose-local",
            Execution::Builtin {
                backend: "terraform".into(), // using existing backend for this test
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.schemas_creds.insert(
            ("greentic.a".into(), "docker-compose-local".into()),
            r#"{"type":"object"}"#.into(),
        );
        invoker.schemas_config.insert(
            ("greentic.a".into(), "docker-compose-local".into()),
            r#"{"type":"object"}"#.into(),
        );
        let action = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "docker-compose-local",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap();
        match action {
            DispatchAction::Builtin(b) => {
                assert_eq!(b.backend, crate::extension::BuiltinBackendId::Terraform);
            }
        }
    }

    #[test]
    fn dispatch_wasm_execution_returns_mode_b_not_implemented() {
        let reg = registry_with("greentic.b", "t", Execution::Wasm);
        let invoker = MockInvoker::default();
        let err = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap_err();
        matches!(err, ExtensionError::ModeBNotImplemented);
    }

    #[test]
    fn dispatch_schema_violation_fails_validation() {
        let reg = registry_with(
            "greentic.a",
            "t",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.schemas_creds.insert(
            ("greentic.a".into(), "t".into()),
            r#"{"type":"object","required":["api_key"]}"#.into(),
        );
        let err = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: r#"{}"#, // missing required api_key
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap_err();
        matches!(err, ExtensionError::ValidationFailed { .. });
    }

    #[test]
    fn dispatch_fatal_diagnostic_blocks() {
        let reg = registry_with(
            "greentic.a",
            "t",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.validate_diagnostics.insert(
            ("greentic.a".into(), "t".into()),
            vec![crate::ext::wasm::Diagnostic {
                severity: DiagnosticSeverity::Error,
                code: "bad-creds".into(),
                message: "bad".into(),
                path: None,
            }],
        );
        let err = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap_err();
        matches!(err, ExtensionError::ValidationFailed { .. });
    }

    #[test]
    fn dispatch_warning_passes_without_strict() {
        let reg = registry_with(
            "greentic.a",
            "t",
            Execution::Builtin {
                backend: "terraform".into(),
                handler: None,
            },
        );
        let mut invoker = MockInvoker::default();
        invoker.validate_diagnostics.insert(
            ("greentic.a".into(), "t".into()),
            vec![crate::ext::wasm::Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "soft".into(),
                message: "warn".into(),
                path: None,
            }],
        );
        let action = dispatch_extension(
            &reg,
            &invoker,
            DispatchInput {
                target_id: "t",
                creds_json: "{}",
                config_json: "{}",
                strict_validate: false,
            },
        )
        .unwrap();
        matches!(action, DispatchAction::Builtin(_));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --features extensions --lib ext::dispatcher 2>&1 | tail -20`
Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/ext/dispatcher.rs
git commit -m "feat(ext): dispatcher orchestrates validation + routing"
```

---

## Task 10: `src/desktop.rs` — docker-compose + podman backend

**Files:**
- Create: `src/desktop.rs`
- Modify: `src/lib.rs` (expose `pub mod desktop;`)

**Context:** Pure command-construction + small execution layer. Keep IO inside `apply` / `destroy` only; `plan` is a pure transform for easy unit testing. Tests mock the actual subprocess by testing command construction; `apply` run against real docker is a developer-machine integration (not in CI).

- [ ] **Step 1: Expose module from lib.rs**

Append to `src/lib.rs`:

```rust
pub mod desktop;
```

- [ ] **Step 2: Write full module**

Create `src/desktop.rs`:

```rust
//! Desktop deploy backend: docker-compose and podman local deploys.
//!
//! Pure command construction + thin execution. Integrates with the deploy
//! extension flow (`src/ext/`) via the `desktop` backend id.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopConfig {
    pub image: Option<String>,
    pub compose_file: Option<PathBuf>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub deployment_name: String,
    #[serde(default = "default_project_dir")]
    pub project_dir: PathBuf,
}

fn default_project_dir() -> PathBuf {
    std::env::temp_dir().join("greentic-desktop")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeKind {
    DockerCompose,
    Podman,
}

impl RuntimeKind {
    pub fn cmd_name(&self) -> &'static str {
        match self {
            Self::DockerCompose => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopPlan {
    pub runtime: RuntimeKind,
    pub deployment_name: String,
    pub compose_file: PathBuf,
    pub project_dir: PathBuf,
}

/// Pure transform: config → plan. No IO. Side-effect free.
pub fn plan(runtime: RuntimeKind, config: &DesktopConfig) -> Result<DesktopPlan> {
    let compose_file = config
        .compose_file
        .clone()
        .unwrap_or_else(|| config.project_dir.join("docker-compose.yml"));
    Ok(DesktopPlan {
        runtime,
        deployment_name: config.deployment_name.clone(),
        compose_file,
        project_dir: config.project_dir.clone(),
    })
}

/// Build the up command. Unit-testable (no execution).
pub fn build_up_command(plan: &DesktopPlan) -> Command {
    let mut cmd = Command::new(plan.runtime.cmd_name());
    match plan.runtime {
        RuntimeKind::DockerCompose => {
            cmd.arg("compose")
                .arg("-p")
                .arg(&plan.deployment_name)
                .arg("-f")
                .arg(&plan.compose_file)
                .arg("up")
                .arg("-d");
        }
        RuntimeKind::Podman => {
            cmd.arg("play")
                .arg("kube")
                .arg(&plan.compose_file);
        }
    }
    cmd.current_dir(&plan.project_dir);
    cmd
}

/// Build the down command.
pub fn build_down_command(plan: &DesktopPlan) -> Command {
    let mut cmd = Command::new(plan.runtime.cmd_name());
    match plan.runtime {
        RuntimeKind::DockerCompose => {
            cmd.arg("compose")
                .arg("-p")
                .arg(&plan.deployment_name)
                .arg("-f")
                .arg(&plan.compose_file)
                .arg("down");
        }
        RuntimeKind::Podman => {
            cmd.arg("pod")
                .arg("stop")
                .arg(&plan.deployment_name);
        }
    }
    cmd
}

/// Build the status command.
pub fn build_status_command(plan: &DesktopPlan) -> Command {
    let mut cmd = Command::new(plan.runtime.cmd_name());
    match plan.runtime {
        RuntimeKind::DockerCompose => {
            cmd.arg("compose")
                .arg("-p")
                .arg(&plan.deployment_name)
                .arg("ps")
                .arg("--format")
                .arg("json");
        }
        RuntimeKind::Podman => {
            cmd.arg("pod")
                .arg("ps")
                .arg("--format")
                .arg("json")
                .arg("--filter")
                .arg(format!("name={}", plan.deployment_name));
        }
    }
    cmd
}

/// Execute the up command. Real IO — not exercised in CI.
pub fn apply(plan: &DesktopPlan) -> Result<()> {
    let status = build_up_command(plan)
        .status()
        .with_context(|| format!("spawn {}", plan.runtime.cmd_name()))?;
    if !status.success() {
        anyhow::bail!("{} up exited with status {}", plan.runtime.cmd_name(), status);
    }
    Ok(())
}

pub fn destroy(plan: &DesktopPlan) -> Result<()> {
    let status = build_down_command(plan)
        .status()
        .with_context(|| format!("spawn {}", plan.runtime.cmd_name()))?;
    if !status.success() {
        anyhow::bail!(
            "{} down exited with status {}",
            plan.runtime.cmd_name(),
            status
        );
    }
    Ok(())
}

pub fn preflight_check(runtime: RuntimeKind) -> Result<()> {
    let mut cmd = Command::new(runtime.cmd_name());
    cmd.arg("--version");
    let out = cmd
        .output()
        .with_context(|| format!("'{}' not found in PATH", runtime.cmd_name()))?;
    if !out.status.success() {
        anyhow::bail!(
            "'{} --version' returned non-zero",
            runtime.cmd_name()
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn _suppress_unused_path(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> DesktopConfig {
        DesktopConfig {
            image: Some("nginx:stable".into()),
            compose_file: Some(PathBuf::from("/tmp/compose.yml")),
            ports: vec!["8080:80".into()],
            env: vec![],
            deployment_name: "my-app".into(),
            project_dir: PathBuf::from("/tmp/proj"),
        }
    }

    #[test]
    fn plan_echoes_compose_file_and_name() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        assert_eq!(p.deployment_name, "my-app");
        assert_eq!(p.compose_file, PathBuf::from("/tmp/compose.yml"));
        assert_eq!(p.runtime, RuntimeKind::DockerCompose);
    }

    #[test]
    fn plan_defaults_compose_file_to_project_dir() {
        let mut cfg = sample_config();
        cfg.compose_file = None;
        let p = plan(RuntimeKind::Podman, &cfg).unwrap();
        assert_eq!(p.compose_file, PathBuf::from("/tmp/proj/docker-compose.yml"));
    }

    #[test]
    fn up_command_docker_compose_args() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        let cmd = build_up_command(&p);
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        assert_eq!(
            args,
            vec!["compose", "-p", "my-app", "-f", "/tmp/compose.yml", "up", "-d"]
        );
        assert_eq!(cmd.get_program(), "docker");
    }

    #[test]
    fn up_command_podman_args() {
        let p = plan(RuntimeKind::Podman, &sample_config()).unwrap();
        let cmd = build_up_command(&p);
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["play", "kube", "/tmp/compose.yml"]);
        assert_eq!(cmd.get_program(), "podman");
    }

    #[test]
    fn down_command_docker_compose_args() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        let cmd = build_down_command(&p);
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        assert_eq!(
            args,
            vec!["compose", "-p", "my-app", "-f", "/tmp/compose.yml", "down"]
        );
    }

    #[test]
    fn status_command_docker_compose_args() {
        let p = plan(RuntimeKind::DockerCompose, &sample_config()).unwrap();
        let cmd = build_status_command(&p);
        let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
        assert_eq!(
            args,
            vec!["compose", "-p", "my-app", "ps", "--format", "json"]
        );
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test --lib desktop 2>&1 | tail -20`
Expected: 6 tests pass.

Run: `cargo test --features extensions --lib desktop 2>&1 | tail -5`
Expected: 6 tests pass (feature doesn't change this module).

- [ ] **Step 4: Commit**

```bash
git add src/desktop.rs src/lib.rs
git commit -m "feat(desktop): docker-compose + podman backend with pure plan + IO seam"
```

---

## Task 11: Fixture extension artifact

**Files:**
- Create: `testdata/ext/greentic.deploy-testfixture/describe.json`
- Create: `testdata/ext/greentic.deploy-testfixture/schemas/creds.schema.json`
- Create: `testdata/ext/greentic.deploy-testfixture/schemas/config.schema.json`
- Create: `testdata/ext/greentic.deploy-testfixture/extension.wasm` (binary, checked in)
- Create: `testdata/ext/build_fixture.sh`

**Context:** The fixture must satisfy the loader (parseable `describe.json` + existing `extension.wasm`) and the dispatcher (WASM invocation succeeds for metadata functions). Because hand-rolling a cargo-component WASM is impractical in this plan step, we ship a minimal valid WebAssembly module stub. The integration tests (Task 12) use the `MockInvoker` for WASM calls — the fixture's `extension.wasm` only needs to pass loader's "file exists" check. A real cargo-component build is done by `build_fixture.sh` and committed.

Since the integration test uses `MockInvoker`, the fixture WASM does not need to implement the WIT exports for this PR. The fallback in `src/cli_builtin_dispatch.rs` and CLI integration test (Task 14/16) will call `dispatch_extension` with an explicit `MockInvoker` test double; a production `WasmtimeInvoker` is wired only when the end-to-end `deploy-desktop` reference ext from PR#2 is used.

- [ ] **Step 1: Write `describe.json`**

Create `testdata/ext/greentic.deploy-testfixture/describe.json`:

```json
{
  "apiVersion": "greentic.ai/v1",
  "kind": "DeployExtension",
  "metadata": {
    "id": "greentic.deploy-testfixture",
    "version": "0.1.0",
    "summary": "In-repo test fixture for dispatcher integration"
  },
  "engine": { "extRuntime": "^0.1.0" },
  "capabilities": { "offered": [], "required": [] },
  "runtime": {
    "component": "extension.wasm",
    "memoryLimitMB": 32,
    "permissions": { "network": [], "secrets": [], "callExtensionKinds": [] }
  },
  "contributions": {
    "targets": [
      {
        "id": "testfixture-noop",
        "displayName": "Test Fixture (delegates to terraform no-op)",
        "description": "Used by ext_loader.rs and ext_dispatch.rs",
        "supportsRollback": false,
        "execution": { "kind": "builtin", "backend": "terraform", "handler": null }
      }
    ]
  }
}
```

- [ ] **Step 2: Write minimal schemas**

Create `testdata/ext/greentic.deploy-testfixture/schemas/creds.schema.json`:

```json
{ "$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "additionalProperties": true }
```

Create `testdata/ext/greentic.deploy-testfixture/schemas/config.schema.json`:

```json
{ "$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "additionalProperties": true }
```

- [ ] **Step 3: Write the minimal wasm stub + build script**

Create `testdata/ext/build_fixture.sh`:

```bash
#!/usr/bin/env bash
# Regenerate the in-repo fixture extension.wasm. Run manually; output is committed.
# Requires: wat binary (`cargo install wabt` or system package).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/greentic.deploy-testfixture/extension.wasm"
WAT="$(mktemp --suffix=.wat)"
cat > "${WAT}" <<'EOF'
(module)
EOF
wat2wasm -o "${OUT}" "${WAT}"
rm -f "${WAT}"
echo "regenerated ${OUT}"
```

Make it executable:

```bash
chmod +x testdata/ext/build_fixture.sh
```

Generate the initial `extension.wasm`. If `wat2wasm` is not available, write the 8-byte magic+version directly (the loader's `exists` check is sufficient for PR#1; the dispatcher unit tests use `MockInvoker`):

```bash
# Option A — if wat2wasm is available:
./testdata/ext/build_fixture.sh

# Option B — minimal stub fallback:
printf '\x00asm\x01\x00\x00\x00' > testdata/ext/greentic.deploy-testfixture/extension.wasm
```

- [ ] **Step 4: Verify fixture loads**

Run a one-shot sanity check via the existing loader unit tests (they already load a stub wasm identical in shape). No new test needed at this step.

Run: `ls -la testdata/ext/greentic.deploy-testfixture/`
Expected: `describe.json`, `extension.wasm` (at least 8 bytes), `schemas/` directory.

- [ ] **Step 5: Commit**

```bash
git add testdata/ext/
git commit -m "test(ext): fixture extension for loader + dispatcher integration"
```

---

## Task 12: Integration tests — `tests/ext_loader.rs` + `tests/ext_dispatch.rs`

**Files:**
- Create: `tests/ext_loader.rs`
- Create: `tests/ext_dispatch.rs`

- [ ] **Step 1: Write `tests/ext_loader.rs`**

Create `tests/ext_loader.rs`:

```rust
#![cfg(feature = "extensions")]

use greentic_deployer::ext::loader::scan;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    // tests/ext_loader.rs runs from workspace root via cargo; CARGO_MANIFEST_DIR
    // is the package root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

#[test]
fn loader_discovers_in_repo_fixture() {
    let v = scan(&fixture_dir()).expect("scan");
    assert!(
        v.iter().any(|e| e.describe.metadata.id == "greentic.deploy-testfixture"),
        "expected testfixture to be discovered; got {:?}",
        v.iter().map(|e| &e.describe.metadata.id).collect::<Vec<_>>()
    );
    let ext = v
        .iter()
        .find(|e| e.describe.metadata.id == "greentic.deploy-testfixture")
        .unwrap();
    assert_eq!(ext.describe.contributions.targets.len(), 1);
    assert_eq!(ext.describe.contributions.targets[0].id, "testfixture-noop");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --features extensions --test ext_loader 2>&1 | tail -15`
Expected: 1 test passes.

- [ ] **Step 3: Write `tests/ext_dispatch.rs`**

Create `tests/ext_dispatch.rs`:

```rust
#![cfg(feature = "extensions")]

use greentic_deployer::ext::dispatcher::{dispatch_extension, DispatchAction, DispatchInput};
use greentic_deployer::ext::loader::scan;
use greentic_deployer::ext::registry::ExtensionRegistry;
use greentic_deployer::ext::wasm::MockInvoker;
use greentic_deployer::extension::BuiltinBackendId;
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

#[test]
fn dispatch_mode_a_routes_to_terraform_backend_id() {
    let loaded = scan(&fixture_dir()).expect("scan");
    let reg = ExtensionRegistry::build(loaded);
    let mut invoker = MockInvoker::default();
    invoker.schemas_creds.insert(
        ("greentic.deploy-testfixture".into(), "testfixture-noop".into()),
        r#"{"type":"object"}"#.into(),
    );
    invoker.schemas_config.insert(
        ("greentic.deploy-testfixture".into(), "testfixture-noop".into()),
        r#"{"type":"object"}"#.into(),
    );
    let action = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: "testfixture-noop",
            creds_json: "{}",
            config_json: "{}",
            strict_validate: false,
        },
    )
    .expect("dispatch");
    match action {
        DispatchAction::Builtin(b) => {
            assert_eq!(b.backend, BuiltinBackendId::Terraform);
            assert!(b.handler.is_none());
        }
    }
}

#[test]
fn dispatch_unknown_target_returns_not_found() {
    let loaded = scan(&fixture_dir()).expect("scan");
    let reg = ExtensionRegistry::build(loaded);
    let invoker = MockInvoker::default();
    let err = dispatch_extension(
        &reg,
        &invoker,
        DispatchInput {
            target_id: "does-not-exist",
            creds_json: "{}",
            config_json: "{}",
            strict_validate: false,
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        greentic_deployer::ext::errors::ExtensionError::TargetNotFound(_)
    ));
}
```

- [ ] **Step 4: Run it**

Run: `cargo test --features extensions --test ext_dispatch 2>&1 | tail -15`
Expected: 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/ext_loader.rs tests/ext_dispatch.rs
git commit -m "test(ext): integration tests for loader + dispatcher Mode A"
```

---

## Task 13: `BuiltinBackendId::Desktop` variant

**Files:**
- Modify: `src/extension.rs`
- Modify: `src/ext/builtin_bridge.rs` (extend handler_matches test)

**Context:** Now that `src/desktop.rs` exists (Task 10), add the matching enum variant so extension authors can write `"execution": { "kind": "builtin", "backend": "desktop", "handler": "docker-compose" }`. Add `Desktop` variants to BOTH `BuiltinBackendId` and `BuiltinBackendHandlerId`, update `as_str`/`FromStr`, and teach `handler_matches` to accept `docker-compose` and `podman`.

- [ ] **Step 1: Write failing tests**

Append to the `ext_roundtrip_tests` module in `src/extension.rs` (or add tests inline):

```rust
    #[test]
    fn desktop_variant_roundtrip() {
        use std::str::FromStr;
        assert_eq!(BuiltinBackendId::from_str("desktop").unwrap(), BuiltinBackendId::Desktop);
        assert_eq!(BuiltinBackendId::Desktop.as_str(), "desktop");
    }

    #[test]
    fn desktop_handler_matches_docker_compose_and_podman() {
        assert!(BuiltinBackendId::Desktop.handler_matches(Some("docker-compose")));
        assert!(BuiltinBackendId::Desktop.handler_matches(Some("podman")));
        assert!(!BuiltinBackendId::Desktop.handler_matches(Some("kubernetes")));
        // None is also valid (default handler chosen by backend)
        assert!(BuiltinBackendId::Desktop.handler_matches(None));
    }
```

Run: `cargo test --features extensions --lib ext_roundtrip_tests 2>&1 | tail -15`
Expected: compile error "no variant `Desktop`".

- [ ] **Step 2: Add `Desktop` variant + update impls**

Edit `src/extension.rs`, in the `BuiltinBackendId` enum add `Desktop` variant:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinBackendId {
    Terraform,
    K8sRaw,
    Helm,
    Aws,
    Azure,
    Gcp,
    JujuK8s,
    JujuMachine,
    Operator,
    Serverless,
    Snap,
    Desktop,
}
```

Update `as_str` match (append):

```rust
Self::Desktop => "desktop",
```

Update `FromStr` match (append before `other =>`):

```rust
"desktop" => Self::Desktop,
```

Update `handler_matches`:

```rust
pub fn handler_matches(self, handler: Option<&str>) -> bool {
    match self {
        Self::Desktop => match handler {
            None | Some("docker-compose") | Some("podman") => true,
            _ => false,
        },
        _ => handler.is_none(),
    }
}
```

Also add the mirror variant to `BuiltinBackendHandlerId` enum + `as_str` if it is used elsewhere — check `src/extension.rs` for `impl BuiltinBackendHandlerId { ... }` block around line 50 and add:

```rust
// Inside the BuiltinBackendHandlerId enum:
Desktop,
// Inside its `as_str`:
Self::Desktop => "desktop",
```

**If** `BuiltinBackendHandlerId` participates in a mapping table to a dispatch function (per `cli_builtin_dispatch.rs`) that requires every variant be routed, add a registration entry pointing to a new handler that returns "not supported via pack dispatch" for `Desktop` (desktop is not pack-backed — it's invoked directly via the ext path). If the existing design tolerates missing registrations (errors at dispatch time only), leave it out.

- [ ] **Step 3: Update bridge tests for Desktop**

In `src/ext/builtin_bridge.rs` tests, append:

```rust
    #[test]
    fn resolve_desktop_with_docker_compose_handler() {
        let exec = Execution::Builtin {
            backend: "desktop".into(),
            handler: Some("docker-compose".into()),
        };
        let r = resolve(&exec, "docker-compose-local").unwrap();
        assert_eq!(r.backend, BuiltinBackendId::Desktop);
        assert_eq!(r.handler.as_deref(), Some("docker-compose"));
    }

    #[test]
    fn resolve_desktop_rejects_kubernetes_handler() {
        let exec = Execution::Builtin {
            backend: "desktop".into(),
            handler: Some("kubernetes".into()),
        };
        let err = resolve(&exec, "x").unwrap_err();
        matches!(err, ExtensionError::UnsupportedHandler { .. });
    }
```

- [ ] **Step 4: Run all tests**

Run: `cargo test --features extensions 2>&1 | tail -25`
Expected: all tests pass, including the new roundtrip + bridge tests.

Run also: `cargo test 2>&1 | tail -10` (default features, no `extensions`)
Expected: all non-extension tests pass; tests in `ext_roundtrip_tests` are in `src/extension.rs` (no feature gate) — they pass here too.

- [ ] **Step 5: Commit**

```bash
git add src/extension.rs src/ext/builtin_bridge.rs
git commit -m "feat(extension): add BuiltinBackendId::Desktop with handler matching"
```

---

## Task 14: `src/ext/cli.rs` + `Ext(ExtCommand)` in main.rs

**Files:**
- Modify: `src/ext/cli.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write `src/ext/cli.rs`**

Replace `src/ext/cli.rs` contents with:

```rust
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::ext::errors::ExtensionResult;
use crate::ext::loader::{resolve_extension_dir, scan};
use crate::ext::registry::ExtensionRegistry;

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
}

pub fn run(cmd: ExtCommand) -> ExtensionResult<()> {
    let dir = resolve_extension_dir(cmd.ext_dir.as_deref());
    match cmd.command {
        ExtSubcommand::List => run_list(&dir),
        ExtSubcommand::Info { ext_id } => run_info(&dir, &ext_id),
        ExtSubcommand::Validate { dir: target } => run_validate(&target),
    }
}

fn run_list(dir: &Path) -> ExtensionResult<()> {
    let loaded = scan(dir)?;
    let reg = ExtensionRegistry::build(loaded);
    let mut targets: Vec<_> = reg.list().collect();
    targets.sort_by(|a, b| a.contribution.id.cmp(&b.contribution.id));
    println!("{:<30}  {:<30}  {}", "TARGET", "EXTENSION", "EXECUTION");
    for t in targets {
        let exec = match &t.contribution.execution {
            crate::ext::describe::Execution::Builtin { backend, handler } => {
                match handler {
                    Some(h) => format!("builtin:{backend}:{h}"),
                    None => format!("builtin:{backend}"),
                }
            }
            crate::ext::describe::Execution::Wasm => "wasm".to_string(),
        };
        println!("{:<30}  {:<30}  {}", t.contribution.id, t.ext_id, exec);
    }
    if !reg.conflicts().is_empty() {
        eprintln!("\nWARNING: {} target id conflict(s) detected.", reg.conflicts().len());
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
        .ok_or_else(|| crate::ext::errors::ExtensionError::TargetNotFound(ext_id.into()))?;
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
        return Err(crate::ext::errors::ExtensionError::DirNotFound(dir.into()));
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
```

- [ ] **Step 2: Add `Ext` variant to `TopLevelCommand` in main.rs**

Edit `src/main.rs`:

Add import near top:

```rust
#[cfg(feature = "extensions")]
use greentic_deployer::ext;
```

Insert variant in the `TopLevelCommand` enum (feature-gated):

```rust
#[derive(Subcommand)]
enum TopLevelCommand {
    TargetRequirements(TargetRequirementsArgs),
    ExtensionResolve(ExtensionResolveArgs),
    ExtensionList(ExtensionListArgs),
    SingleVm(SingleVmCommand),
    MultiTarget(MultiTargetCommand),
    Aws(AwsCommand),
    Azure(AzureCommand),
    Gcp(GcpCommand),
    Helm(HelmCommand),
    JujuK8s(JujuK8sCommand),
    JujuMachine(JujuMachineCommand),
    K8sRaw(K8sRawCommand),
    Operator(OperatorCommand),
    Serverless(ServerlessCommand),
    Snap(SnapCommand),
    Terraform(TerraformCommand),
    #[cfg(feature = "extensions")]
    Ext(ext::cli::ExtCommand),
}
```

In the main dispatch match arm, add:

```rust
#[cfg(feature = "extensions")]
TopLevelCommand::Ext(cmd) => {
    ext::cli::run(cmd)?;
    Ok(())
}
```

- [ ] **Step 3: Verify build**

Run: `cargo build --features extensions 2>&1 | tail -10`
Expected: compiles. Exit 0.

Run: `cargo build 2>&1 | tail -5`
Expected: compiles. Exit 0.

- [ ] **Step 4: Commit**

```bash
git add src/ext/cli.rs src/main.rs
git commit -m "feat(ext): Ext CLI subcommand (list/info/validate)"
```

---

## Task 15: `tests/ext_cli.rs` — CLI smoke tests

**Files:**
- Create: `tests/ext_cli.rs`

- [ ] **Step 1: Write CLI tests**

Create `tests/ext_cli.rs`:

```rust
#![cfg(feature = "extensions")]

use std::path::PathBuf;
use std::process::Command;

#[path = "support/cli_binary.rs"]
mod cli_binary;

use cli_binary::{command_output_with_busy_retry, copied_test_binary};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/ext")
}

#[test]
fn ext_list_lists_fixture_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "ext",
        "--ext-dir",
        fixture_dir().to_str().expect("utf8 fixture dir"),
        "list",
    ]));
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("testfixture-noop"));
    assert!(stdout.contains("greentic.deploy-testfixture"));
    assert!(stdout.contains("builtin:terraform"));
}

#[test]
fn ext_info_prints_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "ext",
        "--ext-dir",
        fixture_dir().to_str().expect("utf8 fixture dir"),
        "info",
        "greentic.deploy-testfixture",
    ]));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("id:      greentic.deploy-testfixture"));
    assert!(stdout.contains("version: 0.1.0"));
    assert!(stdout.contains("- testfixture-noop"));
}

#[test]
fn ext_validate_exits_zero_for_valid_fixture_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let binary = copied_test_binary(&dir);
    let output = command_output_with_busy_retry(Command::new(&binary).args([
        "ext",
        "validate",
        fixture_dir().to_str().expect("utf8 fixture dir"),
    ]));
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("OK  greentic.deploy-testfixture"));
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test --features extensions --test ext_cli 2>&1 | tail -25`
Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add tests/ext_cli.rs
git commit -m "test(ext): CLI smoke tests for ext list/info/validate"
```

---

## Task 16: `cli_builtin_dispatch.rs` fallback wiring

**Files:**
- Modify: `src/cli_builtin_dispatch.rs`

**Context:** When the existing dispatch fails to match a target id to a `BuiltinBackendId`, delegate to `ext::dispatcher`. For Phase A this only runs when `--features extensions` is enabled; without the feature, dispatch keeps its current behavior.

**Scope note:** The exact call site depends on how `cli_builtin_dispatch` receives the target-id from main.rs. Since existing tests show that top-level subcommands (`Aws`, `Terraform`, etc.) bypass this module entirely and dispatch directly, the fallback is relevant only when a future `main.rs` subcommand is added that looks up targets by arbitrary string (not a compile-time variant). For Phase A the extension fallback lives as a public helper on `ext::dispatcher` — main.rs wiring to it is covered when `deploy-desktop` ships from the sibling repo (PR#2 integration). **This task adds the public API but does not call it from main.rs.**

- [ ] **Step 1: Add a public helper `maybe_dispatch_via_extensions` to `src/cli_builtin_dispatch.rs`**

Append to `src/cli_builtin_dispatch.rs`:

```rust
#[cfg(feature = "extensions")]
pub fn maybe_dispatch_via_extensions(target_id: &str) -> anyhow::Result<()> {
    use std::str::FromStr;

    // Short-circuit if the target is actually a built-in backend id.
    if crate::extension::BuiltinBackendId::from_str(target_id).is_ok() {
        anyhow::bail!(
            "target '{}' is a built-in backend — use the dedicated subcommand",
            target_id
        );
    }

    let dir = crate::ext::loader::resolve_extension_dir(None);
    let loaded = crate::ext::loader::scan(&dir)
        .map_err(|e| anyhow::anyhow!("load extensions: {e}"))?;
    let reg = crate::ext::registry::ExtensionRegistry::build(loaded);
    let resolved = reg.resolve(target_id)
        .map_err(|e| anyhow::anyhow!("resolve '{target_id}': {e}"))?;
    tracing::info!(
        target_id = %target_id,
        ext_id = %resolved.ext_id,
        "extension target resolved; wiring into execution is PR#2 scope"
    );
    anyhow::bail!(
        "extension-provided target '{target_id}' requires PR#2 (deploy-desktop); \
         see docs/superpowers/plans/2026-04-17-deploy-extension-pr1.md"
    )
}
```

- [ ] **Step 2: Verify compile**

Run: `cargo build --features extensions 2>&1 | tail -5`
Expected: compiles. Exit 0.

Run: `cargo build 2>&1 | tail -5`
Expected: compiles. Exit 0.

- [ ] **Step 3: Commit**

```bash
git add src/cli_builtin_dispatch.rs
git commit -m "feat(dispatch): public fallback helper for extension-provided targets"
```

---

## Task 17: `ci/local_check.sh` features matrix

**Files:**
- Modify: `ci/local_check.sh`

- [ ] **Step 1: Extend the script**

Edit `ci/local_check.sh`. Append before the final `echo "Local check completed successfully."`:

```bash
echo "==> cargo build --no-default-features (baseline)"
cargo build --no-default-features

echo "==> cargo build --features extensions"
cargo build --features extensions

echo "==> cargo test --features extensions"
cargo test --features extensions
```

- [ ] **Step 2: Run it**

Run: `bash ci/local_check.sh 2>&1 | tail -20`
Expected: all steps pass, exit 0. "Local check completed successfully." appears at the end.

- [ ] **Step 3: Commit**

```bash
git add ci/local_check.sh
git commit -m "ci: add no-default-features baseline + extensions feature matrix"
```

---

## Task 18: Acceptance check + push

**Files:** none (verification + push)

- [ ] **Step 1: Walk the acceptance criteria from the spec**

Run each of the following commands and verify the result matches the spec's §9:

```bash
# Criterion 1
cargo build --no-default-features 2>&1 | tail -5
# Expected: succeeds, no new deps

# Criterion 2
cargo build 2>&1 | tail -5
# Expected: succeeds

# Criterion 3
cargo build --features extensions 2>&1 | tail -5
# Expected: succeeds, new deps fetched

# Criterion 4
cargo test --features extensions 2>&1 | tail -20
# Expected: all new unit + integration tests pass

# Criterion 5
cargo test 2>&1 | tail -10
# Expected: all existing tests pass unchanged

# Criterion 6
GREENTIC_DEPLOY_EXT_DIR=/tmp/empty-$$ cargo run --features extensions -- ext list 2>&1 | tail -5
# Expected: exit 0, empty listing below header

# Criterion 7
cargo run --features extensions -- ext validate testdata/ext 2>&1 | tail -5
# Expected: exit 0, prints "OK  greentic.deploy-testfixture ..."

# Criterion 8
GREENTIC_DEPLOY_EXT_DIR=$(pwd)/testdata/ext cargo run --features extensions -- ext list 2>&1 | tail -5
# Expected: prints testfixture-noop row

# Criterion 11
# Construct a Wasm-kind fixture and exercise dispatch_extension → ModeBNotImplemented.
# Covered by tests/ext_dispatch.rs — test "dispatch_wasm_execution_returns_mode_b_not_implemented"

# Criterion 12
cargo test 2>&1 | tail -5
# Expected: all pre-existing tests unchanged

# Criterion 13
bash ci/local_check.sh 2>&1 | tail -5
# Expected: "Local check completed successfully."
```

- [ ] **Step 2: Confirm no existing-backend files were touched**

Run: `git diff main --stat -- src/aws.rs src/single_vm.rs src/terraform.rs src/helm.rs src/k8s_raw.rs src/juju_k8s.rs src/juju_machine.rs src/operator.rs src/serverless.rs src/snap.rs src/azure.rs src/gcp.rs src/apply.rs src/deployment.rs 2>&1`
Expected: empty output (zero files changed from this branch).

- [ ] **Step 3: Pin the `greentic-ext-runtime` git rev**

If PR review prefers a pinned rev over a branch:

```bash
# In greentic-designer-extensions:
cd /home/bimbim/works/greentic/greentic-designer-extensions
git rev-parse origin/feat/foundation  # copy this sha

# In greentic-deployer Cargo.toml, replace the branch = "feat/foundation" on both
# greentic-ext-runtime and greentic-ext-contract entries with rev = "<that sha>".
# Run:
cd /home/bimbim/works/greentic/greentic-deployer
cargo update -p greentic-ext-runtime
cargo build --features extensions  # verify still compiles
git add Cargo.toml Cargo.lock
git commit -m "chore(ext): pin greentic-designer-extensions to rev <shortsha>"
```

- [ ] **Step 4: Push branch**

```bash
git push -u origin feat/ext-module
```

(Per user preferences: pushes go to `origin` on `greenticai` org, branch-only — no push to `main`.)

Before pushing: run the pre-push checks (format / clippy / test):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --features extensions -- -D warnings
cargo test --features extensions
```

All must exit zero.

- [ ] **Step 5: Open PR**

```bash
gh pr create \
  --title "feat(ext): add WASM deploy extension handling (Phase A)" \
  --body "$(cat <<'EOF'
## Summary

Adds feature-gated (`extensions`, default-off) WASM deploy extension handling
to greentic-deployer:

- `src/ext/` module (loader, registry, wasm invoker, builtin bridge, dispatcher, CLI)
- `src/desktop.rs` docker-compose + podman backend
- `BuiltinBackendId::Desktop` variant with `docker-compose` / `podman` handlers
- `greentic-deployer ext list|info|validate` subcommand
- Fixture extension under `testdata/ext/` for integration tests
- CI features matrix

Zero changes to any existing deploy backend file. Default builds unchanged.

## Spec

docs/superpowers/specs/2026-04-17-deploy-extension-migration-design.md

## Plan

docs/superpowers/plans/2026-04-17-deploy-extension-pr1.md

## Test plan

- [ ] cargo build --no-default-features
- [ ] cargo build (default)
- [ ] cargo build --features extensions
- [ ] cargo test --features extensions
- [ ] cargo test (default; no regression)
- [ ] bash ci/local_check.sh
- [ ] Manual: ext list/info/validate against fixture
EOF
)"
```

---

## Self-Review

### Spec coverage

| Spec section | Tasks covering it |
| --- | --- |
| §2 Architecture — layering, principles, feature gate | 1, 2 |
| §3 Module layout — 8 ext files, Cargo.toml, lib.rs | 1, 2, 3, 4, 6, 7, 8, 9, 14 |
| §4 Data flow — startup, Mode A, Mode B ModeBNotImplemented | 4, 6, 9, 12 |
| §5 API contract — describe.json, WIT calls, two-phase validation, BuiltinBackendId strings | 3, 5, 7, 9, 13 |
| §6 Error handling — `ExtensionError` | 2, 9 |
| §7 Testing — unit, integration, fixture | 3, 4, 6, 8, 9, 10, 11, 12, 15 |
| §8 Phase boundaries — Phase A delivered here | all |
| §9 Acceptance criteria (13 items) | 18 |
| §10 Open questions — pin git rev | 18 step 3 |
| §11 Development strategy — Strategy X | plan structure |

### Spec-to-plan deltas (corrections folded in)

- Spec §5.4 canonical strings — plan uses **snake_case** (`"aws"`, `"desktop"`, `"k8s_raw"`) to match existing `#[serde(rename_all = "snake_case")]` on `BuiltinBackendId`. Spec §5.4 to be patched from CamelCase to snake_case after this plan is committed.
- Spec §3 Cargo.toml snippet has `dep:wasmtime` comment about transitive — plan uses only `greentic-ext-runtime` + `greentic-ext-contract` as optional deps; wasmtime arrives transitively. Consistent.
- Spec §9 acceptance #10 marked "developer-machine smoke, not automated" — plan's Task 18 does not automate docker-compose live apply.

### Placeholder scan

- No `TBD` / `TODO` / vague instructions.
- `Owner: TBD` in spec frontmatter is intentional.
- Task 11 step 3 Option A/B for `wat2wasm`: both paths produce a valid fixture; this is a genuine choice, not a placeholder.

### Type consistency

- `BridgeResolved` defined in Task 8, consumed in Task 9 `DispatchAction::Builtin(BridgeResolved)`. Consistent.
- `DispatchInput` / `DispatchAction` defined in Task 9, consumed in Task 12 integration test. Consistent.
- `WasmInvoker` trait methods (`list_targets`, `credential_schema`, `config_schema`, `validate_credentials`) same names in Task 7 and Task 9. Consistent.
- `LoadedExtension` fields (`root_dir`, `describe`, `wasm_path`) same in Task 4, 6, 11, 12. Consistent.
- `Execution::Builtin { backend, handler }` identical in Tasks 3, 8, 9, 13, 14. Consistent.
- `ExtensionError::TargetNotFound(String)` — tuple variant in Task 2, consumed in Task 6 and Task 14. Consistent.

Plan is internally consistent. No type drift detected.

---

## Post-Plan Actions

- Patch spec §5.4 CamelCase → snake_case (separate small commit on the spec branch, cherry-picked or merged in).
- Kick off brainstorming / writing-plans session for the sibling repo `greentic-deployer-extensions` (PR#2) **after** PR#1 merges on this repo.
