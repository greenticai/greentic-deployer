//! `gtc op env migrate-state <env_id>` (`A6` of `plans/next-gen-deployment.md`).
//!
//! **This verb archives the legacy `<state_dir>/deploy/` tree; it does NOT
//! copy its contents into the new env-pack-bound layout.** The verb name
//! "migrate-state" reflects the Phase A → Phase B contract (A6 archives,
//! Phase B redirects writes into `~/.greentic/environments/<env_id>/...`);
//! by itself this verb leaves the legacy artifacts in a hidden
//! `.deploy-migrated-<ts>/` sentinel under the same parent for manual
//! cleanup. Callers expecting their legacy artifacts to land in the new
//! layout should NOT run `--apply` until Phase B ships and any required
//! content-bearing migration is in place.
//!
//! The tree is written by [`crate::apply::run`] via
//! [`crate::config::DeployerConfig::provider_output_dir`] every deploy run
//! (`plan.json`, `invoke.json`, `runner-handoff.json`, adapter outputs).
//!
//! Per the A6 audit, no production reader downstream of `apply::run`
//! consumes these artifacts at runtime — they are transient build outputs,
//! recomputed on the next deploy. A6 archives them out of the way so Phase
//! B's path-flip (writing into `~/.greentic/environments/<env_id>/...`)
//! lands cleanly.
//!
//! Two verbs (mirroring A4b's `migrate-dev`):
//!
//! - `--check` runs the scanner and emits a [`MigrateStateReport`]. `clean`
//!   is `true` iff no scanner reported a [`FindingSeverity::Blocking`]
//!   finding. Read-only; not lock-coordinated against concurrent
//!   `--apply` (which would invalidate the snapshot anyway).
//! - `--apply` acquires the state-dir migration lock, re-runs the check
//!   inside the lock, refuses with [`OpError::Conflict`] if not clean,
//!   then performs a single [`std::fs::rename`] of `<state_dir>/deploy/`
//!   to `<state_dir>/.deploy-migrated-<ts>/`, then re-scans inside the
//!   lock to verify zero residue. Idempotent. Two concurrent `--apply`
//!   invocations on the same `state_dir` serialize on the lock.
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
//! Known limitations:
//!
//! - **Cross-module race vs. live deploys.** `apply::run` does not
//!   participate in the migration lock today (its `state_dir` is resolved
//!   from `GreenticConfig::paths.state_dir`, which may differ from this
//!   verb's `$HOME`-anchored default). A concurrent live deploy may race
//!   with the rename. Operators should quiesce deploys before running
//!   `--apply`. Cross-module lock participation is tracked as Phase B
//!   hardening alongside the path-flip.
//! - **EXDEV on rename.** Source and destination share `<state_dir>/`, so
//!   `EXDEV` is extremely unlikely; unusual bind-mount setups would
//!   surface it as [`OpError::Io`].

use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use greentic_deploy_spec::EnvId;
use serde::Serialize;
use serde_json::{Value, json};

use super::migrate::{FindingSeverity, MigrationFinding};
use super::{OpError, OpFlags, OpOutcome};
use crate::environment::{EnvFlock, EnvironmentStore, LocalFsStore};

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

    // Acquire the state-dir migration lock for the entire scan → decide →
    // rename → verify critical section. Prevents two concurrent
    // `migrate-state --apply` invocations from observing the same `clean`
    // state and racing on the rename. Held until the function returns.
    //
    // KNOWN LIMITATION: `greentic-deployer::apply::run` writes to
    // `state/deploy/<provider>/<tenant>/<env>/<scope>/...` without taking
    // this lock today. A concurrent live deploy can still race with the
    // rename. Cross-module participation in this lock requires resolving the
    // state_dir-resolver divergence (this verb anchors at
    // `$HOME/.greentic/state`; `apply::run` reads it from
    // `GreenticConfig::paths.state_dir`) and is tracked as a separate
    // hardening step. Operators should quiesce deploys before running
    // `--apply`.
    let lock_path = migration_lock_path(&state_dir);
    let _lock = EnvFlock::acquire(&lock_path).map_err(|source| OpError::Store(source.into()))?;

    // Re-scan inside the lock so a concurrent writer that landed changes
    // between the resolver and the lock acquisition cannot bypass the
    // blocking-finding gate.
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
    // Probe with `try_exists` so a permission-denied stat surfaces, rather
    // than collapsing into the no-op path.
    match deploy_dir.try_exists() {
        Ok(false) => {
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
        Err(err) => {
            return Err(OpError::Io {
                path: deploy_dir,
                source: err,
            });
        }
        Ok(true) => {}
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

/// `<state_dir>/.migrate-state.lock` — exclusive flock held during `--apply`'s
/// scan → decide → rename → verify critical section. Parents are
/// `create_dir_all`-d by [`EnvFlock::acquire`].
fn migration_lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join(".migrate-state.lock")
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
/// Fails loud on residue: every IO error encountered while walking the tree
/// (existence probe, `read_dir`, `DirEntry`, `metadata`) is propagated as a
/// [`FindingSeverity::Blocking`] finding rather than silently skipped.
/// `--apply` refuses on any blocking finding, so an unreadable subtree
/// cannot mask itself as `clean=true`.
///
/// - Top-level not present (`try_exists` = `Ok(false)`) → empty vec.
/// - Top-level probe IO error (`try_exists` = `Err`) → one blocking finding.
/// - Top-level exists but is not a directory → one blocking finding.
/// - Directory exists but empty → one `legacy-deploy-tree` info finding.
/// - Directory populated → one `legacy-deploy-tree` info finding listing the
///   `<provider>/<tenant>/<env>` tuples discovered and a total count of leaf
///   scope-key directories. Any per-subtree IO error appends an additional
///   `legacy-deploy-unreadable` blocking finding (does not stop the walk).
fn scan_legacy_deploy_dir(deploy_dir: &Path) -> Vec<MigrationFinding> {
    let mut findings: Vec<MigrationFinding> = Vec::new();
    match deploy_dir.try_exists() {
        Ok(false) => return findings,
        Ok(true) => {}
        Err(err) => {
            findings.push(blocking(
                deploy_dir,
                format!("existence probe failed: {err}"),
            ));
            return findings;
        }
    }
    let md = match std::fs::symlink_metadata(deploy_dir) {
        Ok(md) => md,
        Err(err) => {
            findings.push(blocking(
                deploy_dir,
                format!("symlink_metadata failed: {err}"),
            ));
            return findings;
        }
    };
    if !md.file_type().is_dir() {
        findings.push(blocking(
            deploy_dir,
            format!(
                "expected `{}` to be a directory; found a non-directory entry (file_type: {:?}). resolve before migrating",
                deploy_dir.display(),
                md.file_type()
            ),
        ));
        return findings;
    }
    let mut tuples: Vec<String> = Vec::new();
    let mut leaf_count: usize = 0;
    if !walk_provider_layer(deploy_dir, &mut tuples, &mut leaf_count, &mut findings) {
        // Top-level read_dir failed → blocking finding already pushed; no
        // tuple info to report.
        return findings;
    }
    let message = if tuples.is_empty() {
        format!(
            "legacy `{}` exists but is empty; eligible for `--apply` rename (hygiene). note: this verb renames the legacy tree to a hidden `.deploy-migrated-<ts>/` sentinel — it does NOT move contents into the new env-pack-bound layout. `greentic-deployer::apply::run` still writes to this location until Phase B ships the path flip; re-running `--check` after a deploy will surface new findings.",
            deploy_dir.display()
        )
    } else {
        format!(
            "legacy `{}` contains {} `<provider>/<tenant>/<env>` tuple(s): [{}] across {} leaf scope dir(s). eligible for `--apply` rename. note: this verb renames the legacy tree to a hidden `.deploy-migrated-<ts>/` sentinel — it does NOT move contents into the new env-pack-bound layout. `greentic-deployer::apply::run` still writes to this location until Phase B ships the path flip; re-running `--check` after a deploy will surface new findings.",
            deploy_dir.display(),
            tuples.len(),
            tuples.join(", "),
            leaf_count
        )
    };
    findings.push(MigrationFinding {
        kind: "legacy-deploy-tree",
        severity: FindingSeverity::Info,
        location: deploy_dir.display().to_string(),
        message,
    });
    findings
}

/// Walks `<deploy>/<provider>/<tenant>/<env>/<scope>/`. Returns `false` only
/// if the top-level `read_dir` failed (no tuple info reachable).
fn walk_provider_layer(
    deploy_dir: &Path,
    tuples: &mut Vec<String>,
    leaf_count: &mut usize,
    findings: &mut Vec<MigrationFinding>,
) -> bool {
    let providers = match std::fs::read_dir(deploy_dir) {
        Ok(it) => it,
        Err(err) => {
            findings.push(blocking(deploy_dir, format!("read_dir failed: {err}")));
            return false;
        }
    };
    for entry_result in providers {
        let provider_entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                findings.push(blocking(
                    deploy_dir,
                    format!("read_dir entry failed: {err}"),
                ));
                continue;
            }
        };
        let path = provider_entry.path();
        if !is_dir_loud(&path, findings) {
            continue;
        }
        let provider = provider_entry.file_name().to_string_lossy().into_owned();
        walk_tenant_layer(&path, &provider, tuples, leaf_count, findings);
    }
    true
}

fn walk_tenant_layer(
    provider_dir: &Path,
    provider: &str,
    tuples: &mut Vec<String>,
    leaf_count: &mut usize,
    findings: &mut Vec<MigrationFinding>,
) {
    let tenants = match std::fs::read_dir(provider_dir) {
        Ok(it) => it,
        Err(err) => {
            findings.push(blocking(provider_dir, format!("read_dir failed: {err}")));
            return;
        }
    };
    for entry_result in tenants {
        let tenant_entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                findings.push(blocking(
                    provider_dir,
                    format!("read_dir entry failed: {err}"),
                ));
                continue;
            }
        };
        let path = tenant_entry.path();
        if !is_dir_loud(&path, findings) {
            continue;
        }
        let tenant = tenant_entry.file_name().to_string_lossy().into_owned();
        walk_env_layer(&path, provider, &tenant, tuples, leaf_count, findings);
    }
}

fn walk_env_layer(
    tenant_dir: &Path,
    provider: &str,
    tenant: &str,
    tuples: &mut Vec<String>,
    leaf_count: &mut usize,
    findings: &mut Vec<MigrationFinding>,
) {
    let envs = match std::fs::read_dir(tenant_dir) {
        Ok(it) => it,
        Err(err) => {
            findings.push(blocking(tenant_dir, format!("read_dir failed: {err}")));
            return;
        }
    };
    for entry_result in envs {
        let env_entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                findings.push(blocking(
                    tenant_dir,
                    format!("read_dir entry failed: {err}"),
                ));
                continue;
            }
        };
        let path = env_entry.path();
        if !is_dir_loud(&path, findings) {
            continue;
        }
        let env = env_entry.file_name().to_string_lossy().into_owned();
        tuples.push(format!("{provider}/{tenant}/{env}"));
        count_scope_leafs(&path, leaf_count, findings);
    }
}

fn count_scope_leafs(env_dir: &Path, leaf_count: &mut usize, findings: &mut Vec<MigrationFinding>) {
    let scopes = match std::fs::read_dir(env_dir) {
        Ok(it) => it,
        Err(err) => {
            findings.push(blocking(env_dir, format!("read_dir failed: {err}")));
            return;
        }
    };
    for entry_result in scopes {
        let scope_entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                findings.push(blocking(env_dir, format!("read_dir entry failed: {err}")));
                continue;
            }
        };
        if is_dir_loud(&scope_entry.path(), findings) {
            *leaf_count += 1;
        }
    }
}

/// `symlink_metadata`-based dir check that surfaces IO failures as blocking
/// findings rather than silently treating the entry as "not a dir". Returns
/// `true` only if the entry is a real directory.
fn is_dir_loud(path: &Path, findings: &mut Vec<MigrationFinding>) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(md) => md.file_type().is_dir(),
        Err(err) => {
            findings.push(blocking(path, format!("symlink_metadata failed: {err}")));
            false
        }
    }
}

fn blocking(location: &Path, message: String) -> MigrationFinding {
    MigrationFinding {
        kind: "legacy-deploy-unreadable",
        severity: FindingSeverity::Blocking,
        location: location.display().to_string(),
        message,
    }
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

    /// Verifies Codex finding #2: an unreadable provider subtree must
    /// surface as a blocking finding rather than being silently skipped
    /// by `.flatten()`. Unix-only because the test relies on `chmod 000`.
    #[cfg(unix)]
    #[test]
    fn check_blocks_on_unreadable_provider_subtree() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        // Two providers: one readable, one we'll chmod 000.
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-1/plan.json"),
            "{}",
        );
        let walled = state_dir.join("deploy/gcp");
        std::fs::create_dir_all(walled.join("acme/prod/scope-2")).unwrap();
        std::fs::write(walled.join("acme/prod/scope-2/plan.json"), "{}").unwrap();
        let mut perms = std::fs::metadata(&walled).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&walled, perms).unwrap();

        let outcome = check(&store, &OpFlags::default(), "local", Some(&state_dir));

        // Restore permissions BEFORE asserting so a failed assert still
        // lets tempdir clean up.
        let mut restore = std::fs::metadata(&walled).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&walled, restore).unwrap();

        let outcome = outcome.unwrap();
        assert_eq!(outcome.result["clean"], false);
        let findings = outcome.result["findings"].as_array().unwrap();
        let blocking: Vec<&serde_json::Value> = findings
            .iter()
            .filter(|f| f["severity"] == "blocking")
            .collect();
        assert!(
            !blocking.is_empty(),
            "expected at least one blocking finding for the unreadable subtree, got: {findings:?}"
        );
        assert!(
            blocking
                .iter()
                .any(|f| f["kind"] == "legacy-deploy-unreadable"),
            "expected legacy-deploy-unreadable kind, got: {blocking:?}"
        );
    }

    /// Verifies Codex finding #2: top-level `existence probe` failures
    /// surface as blocking findings rather than collapsing to "not
    /// present". Implemented via a path with an unreadable parent so
    /// `try_exists()` returns `Err` rather than `Ok(false)`.
    #[cfg(unix)]
    #[test]
    fn check_blocks_on_top_level_probe_io_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let outer = dir.path().join("outer");
        std::fs::create_dir_all(&outer).unwrap();
        let state_dir = outer.join("state");
        // Create state_dir then strip exec/read from the *outer* parent
        // so try_exists() on <state_dir>/deploy returns Err (cannot stat
        // through the unreadable parent).
        std::fs::create_dir_all(&state_dir).unwrap();
        let mut perms = std::fs::metadata(&outer).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&outer, perms).unwrap();

        let outcome = check(&store, &OpFlags::default(), "local", Some(&state_dir));

        // Restore so tempdir can clean up.
        let mut restore = std::fs::metadata(&outer).unwrap().permissions();
        restore.set_mode(0o755);
        std::fs::set_permissions(&outer, restore).unwrap();

        let outcome = outcome.unwrap();
        assert_eq!(outcome.result["clean"], false);
        let findings = outcome.result["findings"].as_array().unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f["kind"] == "legacy-deploy-unreadable" && f["severity"] == "blocking"),
            "expected blocking probe finding, got: {findings:?}"
        );
    }

    /// Verifies Codex finding #3: two concurrent `--apply` invocations on
    /// the same `state_dir` serialize through the `<state_dir>/.migrate-state.lock`
    /// flock — only one rename succeeds; the second observes a clean tree
    /// post-rename and returns the idempotent no-op.
    #[test]
    fn apply_serializes_under_state_dir_lock() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().join("envs"));
        seed_local_env(&store);
        let state_dir = dir.path().join("state");
        write_file(
            &state_dir.join("deploy/aws/acme/prod/scope-1/plan.json"),
            "{}",
        );

        let store_a = store.clone();
        let store_b = store.clone();
        let state_a = state_dir.clone();
        let state_b = state_dir.clone();

        let h1 = std::thread::spawn(move || {
            apply(&store_a, &OpFlags::default(), "local", Some(&state_a))
        });
        let h2 = std::thread::spawn(move || {
            apply(&store_b, &OpFlags::default(), "local", Some(&state_b))
        });
        let r1 = h1.join().expect("thread 1");
        let r2 = h2.join().expect("thread 2");

        // Both invocations must return Ok (the lock serializes them; the
        // second sees the post-rename empty tree and no-ops).
        let o1 = r1.unwrap();
        let o2 = r2.unwrap();

        // Exactly one of them performed the rename; the other was the
        // idempotent no-op.
        let renamed = [
            o1.result["legacy_dir_renamed_to"].clone(),
            o2.result["legacy_dir_renamed_to"].clone(),
        ];
        let non_null = renamed.iter().filter(|v| !v.is_null()).count();
        assert_eq!(
            non_null, 1,
            "exactly one apply should have renamed; got {renamed:?}"
        );

        // Lock file persists at the expected path.
        assert!(
            state_dir.join(".migrate-state.lock").exists(),
            "migration lock file should remain after apply"
        );
    }

    #[test]
    fn migration_lock_path_lives_under_state_dir() {
        let p = migration_lock_path(Path::new("/tmp/state-a6"));
        assert_eq!(p, PathBuf::from("/tmp/state-a6/.migrate-state.lock"));
    }
}
