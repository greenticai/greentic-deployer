//! `gtc op env migrate-state <env_id>` (`A6` of `plans/next-gen-deployment.md`).
//!
//! One-shot cleanup of the legacy `~/.greentic/state/deploy/` artifact tree.
//! The tree is written by [`crate::apply::run`] via
//! [`crate::config::DeployerConfig::provider_output_dir`] every deploy run
//! (`plan.json`, `invoke.json`, `runner-handoff.json`, adapter outputs).
//!
//! Per the A6 audit, no production reader downstream of `apply()` consumes
//! these artifacts at runtime — they are transient build outputs. A6 surfaces
//! and renames the tree out of the way so Phase B's path-flip (writing into
//! `~/.greentic/environments/<env_id>/...`) lands cleanly.
//!
//! Two verbs (mirroring A4b's `migrate-dev`):
//!
//! - `--check` runs the scanner and emits a [`MigrateStateReport`]. `clean`
//!   is `true` iff no scanner reported a [`FindingSeverity::Blocking`]
//!   finding.
//! - `--apply` re-runs the check, refuses with [`OpError::Conflict`] if not
//!   clean, then performs a single [`std::fs::rename`] of
//!   `<state_dir>/deploy/` to `<state_dir>/.deploy-migrated-<ts>/` and
//!   re-scans to verify zero residue. Idempotent.
//!
//! Scope is intentionally narrow:
//!
//! - Covers only `<state_dir>/deploy/`. `state/runtime/` is live cross-crate
//!   data exchange (greentic-start writes / greentic-setup reads
//!   `endpoints.json`) and ships with Phase B's atomic flip.
//!   `.dev.secrets.env` is hardcoded across four crates plus vendored copies
//!   and ships as a separate coordinated effort.
//! - Discard-only rename. No reader of the legacy tree exists, so the
//!   contents are not preserved into the new layout — Phase B writers will
//!   recreate the artifacts they need.
//! - The `<env_id>` argument gates apply on env-existence in the
//!   [`crate::environment::EnvironmentStore`]. It does not constrain *which*
//!   subdirectories get renamed — the entire `<state_dir>/deploy/` tree
//!   moves regardless.
//!
//! Known limitations: source and target of the rename share `<state_dir>/`,
//! so `EXDEV` is extremely unlikely; unusual bind-mount setups would surface
//! it as [`OpError::Io`].

use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use greentic_deploy_spec::EnvId;
use serde::Serialize;
use serde_json::{Value, json};

use super::migrate::{FindingSeverity, MigrationFinding};
use super::{OpError, OpFlags, OpOutcome};
use crate::environment::{EnvironmentStore, LocalFsStore};

const NOUN: &str = "env";
const OP: &str = "migrate-state";

/// Marker prefix prepended to the legacy tree on `--apply`. Starts with a `.`
/// so directory listings de-emphasize it; not interpreted by
/// `EnvironmentStore` (this lives under `state/`, not `environments/`).
const MIGRATED_PREFIX: &str = ".deploy-migrated-";

/// `--check` report.
#[derive(Debug, Clone, Serialize)]
pub struct MigrateStateReport {
    pub env_id: String,
    pub state_dir: String,
    /// `true` iff no scanner reported a [`FindingSeverity::Blocking`] finding.
    pub clean: bool,
    pub findings: Vec<MigrationFinding>,
}

/// `--apply` outcome.
#[derive(Debug, Clone, Serialize)]
pub struct MigrateStateApplyOutcome {
    pub env_id: String,
    pub state_dir: String,
    /// New path the legacy `deploy/` directory was renamed to. `None` if no
    /// legacy tree existed (apply was a no-op).
    pub legacy_dir_renamed_to: Option<String>,
    /// Total count of `<provider>/<tenant>/<env>/<scope>` leaf directories
    /// observed in the tree at scan time. Zero if the directory existed but
    /// was empty (or did not exist).
    pub scanned_paths_count: usize,
}

/// `op env migrate-state <env_id> --check`. Reports findings without touching
/// state.
pub fn check(
    store: &LocalFsStore,
    flags: &OpFlags,
    target: &str,
    state_dir_override: Option<&Path>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, OP, schema()));
    }
    let env_id = parse_env_id(target)?;
    require_env_exists(store, &env_id)?;
    let state_dir = resolve_state_dir(state_dir_override)?;
    let report = run_check(&env_id, &state_dir);
    Ok(OpOutcome::new(
        NOUN,
        OP,
        serde_json::to_value(report).expect("MigrateStateReport is json-safe"),
    ))
}

/// `op env migrate-state <env_id> --apply`. Re-runs the check, refuses with
/// [`OpError::Conflict`] if not clean, then renames `<state_dir>/deploy/` to
/// a hidden `.deploy-migrated-<ts>` sentinel under the same parent.
///
/// Idempotent: if no legacy tree exists, returns a no-op outcome with
/// `legacy_dir_renamed_to: None`.
pub fn apply(
    store: &LocalFsStore,
    flags: &OpFlags,
    target: &str,
    state_dir_override: Option<&Path>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, OP, schema()));
    }
    let env_id = parse_env_id(target)?;
    require_env_exists(store, &env_id)?;
    let state_dir = resolve_state_dir(state_dir_override)?;
    let report = run_check(&env_id, &state_dir);
    if !report.clean {
        let blocking = report
            .findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Blocking)
            .count();
        return Err(OpError::Conflict(format!(
            "migrate-state refuses --apply: {blocking} blocking finding(s); run `--check` for the full list"
        )));
    }
    let deploy_dir = state_dir.join("deploy");
    let scanned_paths_count = report
        .findings
        .iter()
        .filter(|f| f.kind == "legacy-deploy-tree")
        .map(|f| count_from_finding(f).unwrap_or(0))
        .sum::<usize>();
    if !deploy_dir.exists() {
        // Idempotent no-op.
        let outcome = MigrateStateApplyOutcome {
            env_id: env_id.as_str().to_string(),
            state_dir: state_dir.display().to_string(),
            legacy_dir_renamed_to: None,
            scanned_paths_count: 0,
        };
        return Ok(OpOutcome::new(
            NOUN,
            OP,
            serde_json::to_value(outcome).expect("apply outcome is json-safe"),
        ));
    }
    let renamed = rename_legacy_tree(&state_dir, &deploy_dir)?;
    // Verify-after-apply: a successful atomic rename leaves zero residue.
    // A non-empty re-scan implies a concurrent writer recreated the tree
    // between the rename and the re-scan.
    let post = scan_legacy_deploy_dir(&deploy_dir);
    if !post.is_empty() {
        return Err(OpError::Conflict(format!(
            "residue detected after rename — concurrent writer or partial permissions issue; {} finding(s) remain",
            post.len()
        )));
    }
    let outcome = MigrateStateApplyOutcome {
        env_id: env_id.as_str().to_string(),
        state_dir: state_dir.display().to_string(),
        legacy_dir_renamed_to: Some(renamed.display().to_string()),
        scanned_paths_count,
    };
    Ok(OpOutcome::new(
        NOUN,
        OP,
        serde_json::to_value(outcome).expect("apply outcome is json-safe"),
    ))
}

fn run_check(env_id: &EnvId, state_dir: &Path) -> MigrateStateReport {
    let deploy_dir = state_dir.join("deploy");
    let findings = scan_legacy_deploy_dir(&deploy_dir);
    let clean = !findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Blocking);
    MigrateStateReport {
        env_id: env_id.as_str().to_string(),
        state_dir: state_dir.display().to_string(),
        clean,
        findings,
    }
}

/// Scans `<state_dir>/deploy/` and returns observations.
///
/// - Directory does not exist → empty vec (clean, no finding).
/// - Directory exists but empty → one `legacy-deploy-tree` Info finding.
/// - Directory populated → one `legacy-deploy-tree` Info finding listing the
///   `<provider>/<tenant>/<env>` tuples discovered and a total count of leaf
///   scope-key directories.
/// - `read_dir` IO error → one `legacy-deploy-unreadable` Blocking finding.
fn scan_legacy_deploy_dir(deploy_dir: &Path) -> Vec<MigrationFinding> {
    if !deploy_dir.exists() {
        return Vec::new();
    }
    if !deploy_dir.is_dir() {
        return vec![MigrationFinding {
            kind: "legacy-deploy-unreadable",
            severity: FindingSeverity::Blocking,
            location: deploy_dir.display().to_string(),
            message: format!(
                "expected `{}` to be a directory, found a non-directory entry; resolve before migrating",
                deploy_dir.display()
            ),
        }];
    }
    let mut tuples: Vec<String> = Vec::new();
    let mut leaf_count: usize = 0;
    let providers = match std::fs::read_dir(deploy_dir) {
        Ok(it) => it,
        Err(err) => {
            return vec![MigrationFinding {
                kind: "legacy-deploy-unreadable",
                severity: FindingSeverity::Blocking,
                location: deploy_dir.display().to_string(),
                message: format!("read_dir failed: {err}"),
            }];
        }
    };
    for provider_entry in providers.flatten() {
        if !provider_entry.path().is_dir() {
            continue;
        }
        let provider = provider_entry.file_name().to_string_lossy().into_owned();
        let tenants = match std::fs::read_dir(provider_entry.path()) {
            Ok(it) => it,
            Err(_) => continue,
        };
        for tenant_entry in tenants.flatten() {
            if !tenant_entry.path().is_dir() {
                continue;
            }
            let tenant = tenant_entry.file_name().to_string_lossy().into_owned();
            let envs = match std::fs::read_dir(tenant_entry.path()) {
                Ok(it) => it,
                Err(_) => continue,
            };
            for env_entry in envs.flatten() {
                if !env_entry.path().is_dir() {
                    continue;
                }
                let env = env_entry.file_name().to_string_lossy().into_owned();
                tuples.push(format!("{provider}/{tenant}/{env}"));
                let scopes = match std::fs::read_dir(env_entry.path()) {
                    Ok(it) => it,
                    Err(_) => continue,
                };
                for scope_entry in scopes.flatten() {
                    if scope_entry.path().is_dir() {
                        leaf_count += 1;
                    }
                }
            }
        }
    }
    let message = if tuples.is_empty() {
        format!(
            "legacy `{}` exists but is empty; eligible for `--apply` rename (hygiene). note: `greentic-deployer::apply()` still writes to this location until Phase B ships the path flip; re-running `--check` after a deploy will surface new findings.",
            deploy_dir.display()
        )
    } else {
        format!(
            "legacy `{}` contains {} `<provider>/<tenant>/<env>` tuple(s): [{}] across {} leaf scope dir(s). eligible for `--apply` rename. note: `greentic-deployer::apply()` still writes to this location until Phase B ships the path flip; re-running `--check` after a deploy will surface new findings.",
            deploy_dir.display(),
            tuples.len(),
            tuples.join(", "),
            leaf_count
        )
    };
    vec![MigrationFinding {
        kind: "legacy-deploy-tree",
        severity: FindingSeverity::Info,
        location: deploy_dir.display().to_string(),
        message,
    }]
}

fn parse_env_id(target: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(target)
        .map_err(|e| OpError::InvalidArgument(format!("target env_id `{target}`: {e}")))
}

fn require_env_exists(store: &LocalFsStore, env_id: &EnvId) -> Result<(), OpError> {
    if store.exists(env_id)? {
        Ok(())
    } else {
        Err(OpError::NotFound(format!(
            "target env `{env_id}` does not exist; bootstrap it (e.g. `gtc op env create {env_id}` or `gtc setup`) before running migrate-state"
        )))
    }
}

/// Resolve `<state_dir>` either from the explicit override or by anchoring
/// at `$HOME/.greentic/state/`. Mirrors
/// [`crate::environment::LocalFsStore::default_root`]'s `$HOME`-based shape.
fn resolve_state_dir(override_path: Option<&Path>) -> Result<PathBuf, OpError> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| {
            OpError::InvalidArgument("no --state-dir and HOME / USERPROFILE not set".to_string())
        })?;
    Ok(PathBuf::from(home).join(".greentic").join("state"))
}

/// Rename `<state_dir>/deploy/` to `<state_dir>/.deploy-migrated-<rfc3339-nanos>/`.
fn rename_legacy_tree(state_dir: &Path, deploy_dir: &Path) -> Result<PathBuf, OpError> {
    let ts = Utc::now()
        .to_rfc3339_opts(SecondsFormat::Nanos, true)
        .replace([':', '.'], "-");
    let dst_name = format!("{MIGRATED_PREFIX}{ts}");
    let dst = state_dir.join(dst_name);
    std::fs::rename(deploy_dir, &dst).map_err(|source| OpError::Io {
        path: deploy_dir.to_path_buf(),
        source,
    })?;
    Ok(dst)
}

/// Best-effort extraction of the leaf-scope count from a `legacy-deploy-tree`
/// finding so the apply outcome can report it without re-walking the tree
/// (which is now renamed). Falls back to `None` if the message shape changes.
fn count_from_finding(f: &MigrationFinding) -> Option<usize> {
    let needle = "across ";
    let i = f.message.find(needle)?;
    let rest = &f.message[i + needle.len()..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

fn schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "MigrateStatePayload",
        "description": "Inputs to `op env migrate-state`: positional `<target>` env id (must exist in EnvironmentStore), plus `--check` or `--apply`, plus optional `--state-dir` override (defaults to $HOME/.greentic/state).",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "target_env_id": {"type": "string", "description": "Env id whose existence gates the migration; the entire <state_dir>/deploy tree is renamed regardless."},
            "mode": {"type": "string", "enum": ["check", "apply"]},
            "state_dir": {"type": "string", "description": "Optional override for the legacy state-dir root. Defaults to $HOME/.greentic/state."}
        },
        "required": ["target_env_id", "mode"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use tempfile::tempdir;

    fn seed_local_env(store: &LocalFsStore) {
        store.save(&make_env("local")).expect("seed local env");
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, contents).expect("write file");
    }

    #[test]
    fn check_clean_when_no_deploy_dir() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let outcome = check(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        assert_eq!(outcome.op, OP);
        assert_eq!(outcome.noun, NOUN);
        assert_eq!(outcome.result["clean"], true);
        assert_eq!(outcome.result["env_id"], "local");
        assert_eq!(outcome.result["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn check_reports_populated_tree() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-xyz/plan.json"),
            "{}",
        );
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-abc/invoke.json"),
            "{}",
        );
        let outcome = check(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        assert_eq!(outcome.result["clean"], true);
        let findings = outcome.result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["kind"], "legacy-deploy-tree");
        assert_eq!(findings[0]["severity"], "info");
        let msg = findings[0]["message"].as_str().unwrap();
        assert!(msg.contains("aws/acme/prod"), "got: {msg}");
        assert!(msg.contains("across 2 leaf scope"), "got: {msg}");
    }

    #[test]
    fn check_reports_empty_deploy_dir() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(state_dir.join("deploy")).unwrap();
        let outcome = check(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        assert_eq!(outcome.result["clean"], true);
        let findings = outcome.result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["kind"], "legacy-deploy-tree");
        let msg = findings[0]["message"].as_str().unwrap();
        assert!(msg.contains("exists but is empty"), "got: {msg}");
    }

    #[test]
    fn check_blocks_on_unreadable_deploy() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        // deploy/ is a file, not a dir.
        std::fs::write(state_dir.join("deploy"), "not a dir").unwrap();
        let outcome = check(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        assert_eq!(outcome.result["clean"], false);
        let findings = outcome.result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["kind"], "legacy-deploy-unreadable");
        assert_eq!(findings[0]["severity"], "blocking");
    }

    #[test]
    fn check_requires_env_exists() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        // no env seeded
        let state_dir = dir.path().join("state");
        let err = check(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn check_schema_only_returns_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        // schema short-circuits before env-existence check, so no seed.
        let flags = OpFlags {
            schema_only: true,
            answers: None,
        };
        let outcome = check(&store, &flags, "local", None).unwrap();
        assert_eq!(outcome.result["title"], "MigrateStatePayload");
    }

    #[test]
    fn apply_happy_path_renames_and_verifies() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-xyz/plan.json"),
            "{}",
        );
        let outcome = apply(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        let renamed = outcome.result["legacy_dir_renamed_to"].as_str().unwrap();
        assert!(renamed.contains(".deploy-migrated-"), "got: {renamed}");
        assert!(Path::new(renamed).exists());
        assert!(!state_dir.join("deploy").exists());
        assert_eq!(outcome.result["scanned_paths_count"], 1);
    }

    #[test]
    fn apply_idempotent_after_success() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-xyz/plan.json"),
            "{}",
        );
        let _ = apply(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        let outcome = apply(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        assert_eq!(outcome.result["legacy_dir_renamed_to"], Value::Null);
        assert_eq!(outcome.result["scanned_paths_count"], 0);
    }

    #[test]
    fn apply_refuses_on_blocking_finding() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("deploy"), "not a dir").unwrap();
        let err = apply(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn apply_requires_env_exists() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        let state_dir = dir.path().join("state");
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-xyz/plan.json"),
            "{}",
        );
        let err = apply(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)), "got {err:?}");
        // Verify nothing was renamed.
        assert!(state_dir.join("deploy").exists());
    }

    #[test]
    fn apply_no_op_when_deploy_dir_missing() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let outcome = apply(&store, &OpFlags::default(), "local", Some(&state_dir)).unwrap();
        assert_eq!(outcome.result["legacy_dir_renamed_to"], Value::Null);
        assert_eq!(outcome.result["scanned_paths_count"], 0);
    }

    #[test]
    fn resolve_state_dir_uses_override() {
        let custom = PathBuf::from("/tmp/custom-state-a6");
        let resolved = resolve_state_dir(Some(&custom)).unwrap();
        assert_eq!(resolved, custom);
    }

    #[test]
    fn resolve_state_dir_falls_back_to_home() {
        // Capture and restore HOME safely without `unsafe` env mutation.
        // We can't actually set env vars under `#![forbid(unsafe_code)]`
        // (Rust 2024 set_var/remove_var are unsafe). Instead, exercise the
        // observable HOME-derived path indirectly: when the resolver reads
        // the current process HOME, it should produce
        // `<HOME>/.greentic/state`. If HOME is unset on this runner, accept
        // the InvalidArgument error path instead.
        let resolved = resolve_state_dir(None);
        match (std::env::var_os("HOME"), resolved) {
            (Some(home), Ok(p)) => {
                let expected = PathBuf::from(home).join(".greentic").join("state");
                assert_eq!(p, expected);
            }
            (None, Err(OpError::InvalidArgument(msg))) => {
                assert!(msg.contains("HOME"));
            }
            (have_home, result) => {
                panic!("unexpected combination: HOME={have_home:?}, resolved={result:?}")
            }
        }
    }
}
