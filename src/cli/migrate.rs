//! `gtc op env migrate-dev <target>` (`A4b` of `plans/next-gen-deployment.md`).
//!
//! Preflight-gated, one-shot migration of a legacy `dev` environment to the
//! [A4 bootstrap] target (typically `local`). Two verbs:
//!
//! - `--check` — runs every registered [`MigrationScanner`] and emits a
//!   [`MigrateDevReport`]. `clean` is `true` iff no scanner reported a
//!   [`FindingSeverity::Blocking`] finding.
//! - `--apply` — first re-runs the check, refuses with [`OpError::Conflict`]
//!   if not clean, then merges the source env into the target under the
//!   target's transact lock and renames the source directory to a
//!   `.dev-migrated-<ts>` sentinel that's hidden from
//!   [`EnvironmentStore::list`] (the leading dot is rejected by `EnvId`).
//!
//! Scope is intentionally narrow:
//!
//! - Refuses migration of any source env that carries bundles, revisions,
//!   traffic splits, or a `credentials_ref` — those require deep ref rewrites
//!   (env-scoped `SecretRef`s, `BundleDeployment.env_id`, etc.) which A4b's
//!   "presence guarantee" semantic does not promise.
//! - On a "simple" source (only `host_config` + optional pack bindings), the
//!   merge preserves user-customized bindings on the target: defaults missing
//!   from `target` get filled from `source`; slots already bound on `target`
//!   stay untouched (the A4 #206 lesson — bootstrap is presence, not
//!   replacement).
//! - Audit-log scanning (A7) and secrets-store scanning (A4b PR4) ship as
//!   `NotYetImplemented` placeholders so the report surface is forward-stable.
//!
//! [A4 bootstrap]: crate::cli::bootstrap

use chrono::{SecondsFormat, Utc};
use greentic_deploy_spec::{EnvId, EnvPackBinding, Environment};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};
use crate::defaults::LOCAL_ENV_ID;
use crate::environment::{EnvironmentStore, LocalFsStore, StoreError};

const NOUN: &str = "env";
const OP: &str = "migrate-dev";

/// Legacy env-id this migration moves *from*. The target env-id is provided
/// by the caller; defaults to [`LOCAL_ENV_ID`] in the binary clap layer.
pub const LEGACY_ENV_ID: &str = "dev";

/// Marker prefix prepended to the source directory on `--apply`. Starts with
/// `.` so the directory is silently skipped by [`EnvironmentStore::list`]
/// (the `EnvId` validator rejects ids beginning with `.`).
const MIGRATED_PREFIX: &str = ".dev-migrated-";

/// Severity classification for a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingSeverity {
    /// Informational — `--apply` can proceed.
    Info,
    /// Blocks `--apply` until the user manually resolves the issue. The
    /// per-finding `message` carries the recommended remediation.
    Blocking,
}

/// One observation from a scanner run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationFinding {
    /// Short, scanner-defined kind for machine consumers (e.g.
    /// `"legacy-env-dir"`, `"runtime-env-var"`).
    pub kind: &'static str,
    pub severity: FindingSeverity,
    /// Path / variable name / source the finding refers to. Free-form
    /// human-readable string.
    pub location: String,
    /// Operator-facing explanation of the finding and (for blocking findings)
    /// what to do about it.
    pub message: String,
}

/// Report returned by `migrate-dev --check`.
#[derive(Debug, Clone, Serialize)]
pub struct MigrateDevReport {
    pub from_env: String,
    pub to_env: String,
    /// `true` iff no scanner reported a [`FindingSeverity::Blocking`] finding.
    pub clean: bool,
    pub findings: Vec<MigrationFinding>,
}

/// Outcome of `migrate-dev --apply`. Only emitted when the check was clean.
#[derive(Debug, Clone, Serialize)]
pub struct MigrateDevApplyOutcome {
    pub from_env: String,
    pub to_env: String,
    /// Slots that were added to the target during the merge. Empty if the
    /// target already had everything the source contributed.
    pub merged_slots: Vec<String>,
    /// New path the legacy source directory was renamed to (so the user can
    /// verify and remove it manually). `None` if no source directory existed
    /// (apply was a no-op).
    pub legacy_dir_renamed_to: Option<String>,
}

/// Read-only context handed to every scanner.
pub struct ScanContext<'a> {
    pub store: &'a LocalFsStore,
    pub from_env: &'a EnvId,
    pub to_env: &'a EnvId,
}

/// Pluggable scanner — each implementation reports zero or more
/// [`MigrationFinding`]s for one slice of legacy `dev`-named state.
pub trait MigrationScanner {
    /// Stable, kebab-case identifier; surfaced in finding `kind` prefixes
    /// where helpful.
    fn name(&self) -> &'static str;
    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<MigrationFinding>, OpError>;
}

/// Bundle the set of scanners that ship with A4b. Future PRs add to this
/// vector; consumers that want a different set can call the individual
/// scanners directly.
pub fn default_scanners() -> Vec<Box<dyn MigrationScanner>> {
    vec![
        Box::new(LocalFsStoreScanner),
        Box::new(RuntimeConfigScanner),
        Box::new(SecretsStoreScanner),
        Box::new(AuditLogScanner),
        Box::new(BundleHintScanner),
    ]
}

/// Inspects the configured [`LocalFsStore`] root for a `<from_env>` directory.
/// Classifies any source env as either a "simple" candidate (only
/// `host_config` + optional pack bindings) or "complex" (carries bundles,
/// revisions, traffic splits, or a `credentials_ref`).
pub struct LocalFsStoreScanner;

impl MigrationScanner for LocalFsStoreScanner {
    fn name(&self) -> &'static str {
        "local-fs-store"
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<MigrationFinding>, OpError> {
        let mut findings = Vec::new();
        if !ctx.store.exists(ctx.from_env)? {
            return Ok(findings);
        }
        let env_root = ctx.store.root().join(ctx.from_env.as_str());
        match ctx.store.load(ctx.from_env) {
            Ok(env) => {
                if let Some(complex_reason) = classify_source(&env) {
                    findings.push(MigrationFinding {
                        kind: "legacy-env-complex",
                        severity: FindingSeverity::Blocking,
                        location: env_root.display().to_string(),
                        message: format!(
                            "source env `{}` contains {} — manual migration required; A4b's `--apply` only moves a simple env (host_config + pack bindings)",
                            ctx.from_env, complex_reason
                        ),
                    });
                } else {
                    findings.push(MigrationFinding {
                        kind: "legacy-env-simple",
                        severity: FindingSeverity::Info,
                        location: env_root.display().to_string(),
                        message: format!(
                            "source env `{}` is present and eligible for `--apply` migration to `{}`",
                            ctx.from_env, ctx.to_env
                        ),
                    });
                }
            }
            Err(err) => {
                findings.push(MigrationFinding {
                    kind: "legacy-env-unreadable",
                    severity: FindingSeverity::Blocking,
                    location: env_root.display().to_string(),
                    message: format!(
                        "source env `{}` exists on disk but failed to load ({err}); resolve before migrating",
                        ctx.from_env
                    ),
                });
            }
        }
        Ok(findings)
    }
}

/// Reports a finding when `GREENTIC_ENV` is set to the legacy value in the
/// process environment running the check. The migration tool can't *fix*
/// this from inside the process (the var is set in the caller's shell), but
/// flagging it informs the operator that their shell will still resolve
/// `dev` after the on-disk migration.
pub struct RuntimeConfigScanner;

impl MigrationScanner for RuntimeConfigScanner {
    fn name(&self) -> &'static str {
        "runtime-config"
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Result<Vec<MigrationFinding>, OpError> {
        let value = std::env::var("GREENTIC_ENV").ok();
        Ok(classify_runtime_env_var(value.as_deref(), ctx.from_env)
            .into_iter()
            .collect())
    }
}

/// Pure classification helper for [`RuntimeConfigScanner`]. Returns
/// `Some(finding)` iff `value` equals the legacy env id. Extracted from the
/// scanner so tests can exercise the logic without mutating the process
/// environment — the crate is `#![forbid(unsafe_code)]` and Rust 2024
/// requires `unsafe` to set/remove env vars.
pub fn classify_runtime_env_var(value: Option<&str>, from: &EnvId) -> Option<MigrationFinding> {
    let value = value?;
    if value != from.as_str() {
        return None;
    }
    Some(MigrationFinding {
        kind: "runtime-env-var",
        severity: FindingSeverity::Info,
        location: "$GREENTIC_ENV".to_string(),
        message: format!(
            "shell env var `GREENTIC_ENV` is `{value}` — the dev→local compat alias (A4b PR2) will keep this working with a once-per-process warning until you unset or update it"
        ),
    })
}

/// Placeholder for the audit-log scanner. A7 adds an append-only audit log
/// keyed by env; until then we report a single informational finding so
/// operators don't expect this surface to silently catch missed references.
pub struct AuditLogScanner;

impl MigrationScanner for AuditLogScanner {
    fn name(&self) -> &'static str {
        "audit-log"
    }

    fn scan(&self, _ctx: &ScanContext<'_>) -> Result<Vec<MigrationFinding>, OpError> {
        Ok(vec![MigrationFinding {
            kind: "audit-log-scanner-deferred",
            severity: FindingSeverity::Info,
            location: "<audit-log>".to_string(),
            message: "audit-log scanning ships with A7; no audit log exists today".to_string(),
        }])
    }
}

/// Placeholder for the secrets-store scanner. PR4 of A4b adds the real
/// helper in `greentic-secrets-broker`; until then, no production
/// code-paths enumerate `dev`-scoped keys, so this scanner reports a
/// no-op informational finding.
pub struct SecretsStoreScanner;

impl MigrationScanner for SecretsStoreScanner {
    fn name(&self) -> &'static str {
        "secrets-store"
    }

    fn scan(&self, _ctx: &ScanContext<'_>) -> Result<Vec<MigrationFinding>, OpError> {
        Ok(vec![MigrationFinding {
            kind: "secrets-store-scanner-deferred",
            severity: FindingSeverity::Info,
            location: "<secrets-broker>".to_string(),
            message: "secrets-store enumeration ships with A4b PR4 (greentic-secrets-broker)"
                .to_string(),
        }])
    }
}

/// Permanent no-op scanner — bundles carry no embedded env hint in any
/// shipped code (per the A4b inventory), so any future drift would surface
/// as a new scanner rather than a finding here.
pub struct BundleHintScanner;

impl MigrationScanner for BundleHintScanner {
    fn name(&self) -> &'static str {
        "bundle-hint"
    }

    fn scan(&self, _ctx: &ScanContext<'_>) -> Result<Vec<MigrationFinding>, OpError> {
        Ok(Vec::new())
    }
}

/// Returns `Some(reason)` if the env carries any state A4b's `--apply` is
/// unwilling to rewrite. Returns `None` for envs that hold only
/// `host_config` + optional pack bindings.
fn classify_source(env: &Environment) -> Option<&'static str> {
    if env.credentials_ref.is_some() {
        return Some("a `credentials_ref` pointing at env-scoped secrets");
    }
    if !env.bundles.is_empty() {
        return Some("one or more `BundleDeployment`s");
    }
    if !env.revisions.is_empty() {
        return Some("one or more `Revision`s");
    }
    if !env.traffic_splits.is_empty() {
        return Some("one or more `TrafficSplit`s");
    }
    None
}

/// Run every scanner and produce the report.
pub fn run_check(
    store: &LocalFsStore,
    from: &EnvId,
    to: &EnvId,
) -> Result<MigrateDevReport, OpError> {
    let ctx = ScanContext {
        store,
        from_env: from,
        to_env: to,
    };
    let mut findings = Vec::new();
    for scanner in default_scanners() {
        findings.extend(scanner.scan(&ctx)?);
    }
    let clean = !findings
        .iter()
        .any(|f| f.severity == FindingSeverity::Blocking);
    Ok(MigrateDevReport {
        from_env: from.as_str().to_string(),
        to_env: to.as_str().to_string(),
        clean,
        findings,
    })
}

/// `op env migrate-dev <target> --check`. Reports findings without touching
/// state.
pub fn check(store: &LocalFsStore, flags: &OpFlags, target: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, OP, schema()));
    }
    let (from, to) = resolve_endpoints(target)?;
    let report = run_check(store, &from, &to)?;
    Ok(OpOutcome::new(
        NOUN,
        OP,
        serde_json::to_value(report).expect("MigrateDevReport is json-safe"),
    ))
}

/// `op env migrate-dev <target> --apply`. Re-runs the check, refuses with
/// [`OpError::Conflict`] if not clean, then merges the source env into the
/// target under the target's transact lock and renames the source directory
/// to a hidden `.dev-migrated-<ts>` sentinel.
///
/// Idempotent: if no source env exists, returns
/// [`MigrateDevApplyOutcome`] with empty `merged_slots` and
/// `legacy_dir_renamed_to: None`.
pub fn apply(store: &LocalFsStore, flags: &OpFlags, target: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, OP, schema()));
    }
    let (from, to) = resolve_endpoints(target)?;
    let ctx = AuditCtx {
        env_id: to.clone(),
        noun: NOUN,
        verb: OP,
        target: json!({
            "from_env": from.as_str(),
            "to_env": to.as_str(),
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let report = run_check(store, &from, &to)?;
        if !report.clean {
            return Err(OpError::Conflict(format!(
                "migrate-dev refuses --apply: {} blocking finding(s); run `--check` for the full list",
                report
                    .findings
                    .iter()
                    .filter(|f| f.severity == FindingSeverity::Blocking)
                    .count()
            )));
        }
        if !store.exists(&from)? {
            // Idempotent no-op: nothing to migrate.
            let outcome = MigrateDevApplyOutcome {
                from_env: from.as_str().to_string(),
                to_env: to.as_str().to_string(),
                merged_slots: Vec::new(),
                legacy_dir_renamed_to: None,
            };
            return Ok((
                OpOutcome::new(
                    NOUN,
                    OP,
                    serde_json::to_value(outcome).expect("apply outcome is json-safe"),
                ),
                super::AuditGens::NONE,
            ));
        }
        let source = store.load(&from)?;
        if classify_source(&source).is_some() {
            // run_check should have flagged this, but guard against a scanner
            // bypass.
            return Err(OpError::Conflict(
                "source env is not eligible for simple migration (see `--check`)".to_string(),
            ));
        }
        let merged_slots = store.transact(&to, |locked| -> Result<Vec<String>, OpError> {
            let mut target_env = match locked.load() {
                Ok(env) => env,
                Err(StoreError::NotFound(_)) => seed_target_from_source(&source, locked.env_id()),
                Err(e) => return Err(e.into()),
            };
            let mut added = Vec::new();
            for binding in &source.packs {
                if target_env.packs.iter().any(|b| b.slot == binding.slot) {
                    continue;
                }
                added.push(binding.slot.to_string());
                target_env.packs.push(cloned_binding(binding));
            }
            locked.save(&target_env)?;
            Ok(added)
        })?;
        let renamed = rename_legacy_dir(store, &from)?;
        let outcome = MigrateDevApplyOutcome {
            from_env: from.as_str().to_string(),
            to_env: to.as_str().to_string(),
            merged_slots,
            legacy_dir_renamed_to: Some(renamed.display().to_string()),
        };
        Ok((
            OpOutcome::new(
                NOUN,
                OP,
                serde_json::to_value(outcome).expect("apply outcome is json-safe"),
            ),
            super::AuditGens::NONE,
        ))
    })
}

fn resolve_endpoints(target: &str) -> Result<(EnvId, EnvId), OpError> {
    let from = EnvId::try_from(LEGACY_ENV_ID)
        .map_err(|e| OpError::InvalidArgument(format!("legacy env id `{LEGACY_ENV_ID}`: {e}")))?;
    let to = EnvId::try_from(target)
        .map_err(|e| OpError::InvalidArgument(format!("target env_id `{target}`: {e}")))?;
    if to == from {
        return Err(OpError::InvalidArgument(format!(
            "migration target must differ from `{LEGACY_ENV_ID}`"
        )));
    }
    Ok((from, to))
}

/// Construct a fresh target env seeded from the source's `host_config`
/// + the source's pack bindings. Used when the target doesn't exist yet.
fn seed_target_from_source(source: &Environment, target_env_id: &EnvId) -> Environment {
    Environment {
        schema: source.schema.clone(),
        environment_id: target_env_id.clone(),
        name: target_env_id.as_str().to_string(),
        host_config: greentic_deploy_spec::EnvironmentHostConfig {
            env_id: target_env_id.clone(),
            region: source.host_config.region.clone(),
            tenant_org_id: source.host_config.tenant_org_id.clone(),
            listen_addr: source.host_config.listen_addr,
        },
        packs: Vec::new(),
        credentials_ref: None,
        bundles: Vec::new(),
        revisions: Vec::new(),
        traffic_splits: Vec::new(),
        messaging_endpoints: Vec::new(),
        revocation: source.revocation.clone(),
        retention: source.retention.clone(),
        health: source.health.clone(),
    }
}

fn cloned_binding(binding: &EnvPackBinding) -> EnvPackBinding {
    EnvPackBinding {
        slot: binding.slot,
        kind: binding.kind.clone(),
        pack_ref: binding.pack_ref.clone(),
        answers_ref: binding.answers_ref.clone(),
        generation: binding.generation,
        previous_binding_ref: binding.previous_binding_ref.clone(),
    }
}

/// Rename `<root>/<from>/` to `<root>/.dev-migrated-<ts>/`. The leading dot
/// guarantees [`EnvironmentStore::list`] silently skips the directory
/// (`EnvId` rejects `.`-prefixed names) and lets the user verify state
/// before manual cleanup.
fn rename_legacy_dir(store: &LocalFsStore, from: &EnvId) -> Result<std::path::PathBuf, OpError> {
    let src = store.root().join(from.as_str());
    if !src.exists() {
        return Ok(src);
    }
    let ts = Utc::now()
        .to_rfc3339_opts(SecondsFormat::Nanos, true)
        .replace([':', '.'], "-");
    let dst_name = format!("{MIGRATED_PREFIX}{ts}");
    let dst = store.root().join(dst_name);
    std::fs::rename(&src, &dst).map_err(|source| OpError::Io { path: src, source })?;
    Ok(dst)
}

fn schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "MigrateDevPayload",
        "description": "Inputs to `op env migrate-dev`: positional `<target>` env id, plus `--check` or `--apply`. There is no JSON payload to load from disk; use the CLI flags directly.",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "target_env_id": {"type": "string", "description": "Env id to migrate `dev` to — typically `local`."},
            "mode": {"type": "string", "enum": ["check", "apply"]}
        },
        "required": ["target_env_id", "mode"],
        "x-default-target": LOCAL_ENV_ID
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{
        make_binding, make_bundle_deployment, make_env, make_revision, make_traffic_split,
    };
    use crate::defaults::{LOCAL_DEPLOYER_PACK, LOCAL_SECRETS_PACK, LOCAL_TELEMETRY_PACK};
    use crate::environment::EnvironmentStore;
    use greentic_deploy_spec::{CapabilitySlot, RevisionLifecycle};
    use tempfile::tempdir;

    #[test]
    fn check_clean_when_store_empty() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let outcome = check(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.op, "migrate-dev");
        assert_eq!(outcome.noun, "env");
        assert_eq!(outcome.result["clean"], true);
        assert_eq!(outcome.result["from_env"], "dev");
        assert_eq!(outcome.result["to_env"], "local");
    }

    #[test]
    fn check_flags_simple_dev_env_as_eligible() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        env.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        store.save(&env).unwrap();
        let outcome = check(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.result["clean"], true);
        let kinds: Vec<&str> = outcome.result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"legacy-env-simple"));
    }

    #[test]
    fn check_blocks_dev_env_with_bundles() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        let bundle = make_bundle_deployment("dev", "fast2flow");
        env.bundles.push(bundle);
        store.save(&env).unwrap();
        let outcome = check(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.result["clean"], false);
        let blocking_findings: Vec<&serde_json::Value> = outcome.result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["severity"] == "blocking")
            .collect();
        assert_eq!(blocking_findings.len(), 1);
        assert_eq!(blocking_findings[0]["kind"], "legacy-env-complex");
        let msg = blocking_findings[0]["message"].as_str().unwrap();
        assert!(msg.contains("BundleDeployment"), "got: {msg}");
    }

    #[test]
    fn check_blocks_dev_env_with_revisions() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        // Build a deployment + matching revision so spec validate() passes
        // before we save.
        let bundle = make_bundle_deployment("dev", "fast2flow");
        let rev = make_revision(
            "dev",
            "fast2flow",
            &bundle.deployment_id,
            1,
            RevisionLifecycle::Staged,
        );
        env.bundles.push(bundle);
        env.revisions.push(rev);
        store.save(&env).unwrap();
        let outcome = check(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.result["clean"], false);
    }

    #[test]
    fn check_blocks_dev_env_with_traffic_splits() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        let bundle = make_bundle_deployment("dev", "fast2flow");
        let rev = make_revision(
            "dev",
            "fast2flow",
            &bundle.deployment_id,
            1,
            RevisionLifecycle::Staged,
        );
        let split = make_traffic_split(
            "dev",
            "fast2flow",
            &bundle.deployment_id,
            &rev.revision_id,
            "init",
        );
        env.bundles.push(bundle);
        env.revisions.push(rev);
        env.traffic_splits.push(split);
        store.save(&env).unwrap();
        let outcome = check(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.result["clean"], false);
    }

    #[test]
    fn classify_runtime_env_var_matches_legacy_value() {
        let from = EnvId::try_from("dev").unwrap();
        let finding = classify_runtime_env_var(Some("dev"), &from).expect("matched");
        assert_eq!(finding.kind, "runtime-env-var");
        assert_eq!(finding.severity, FindingSeverity::Info);
        assert_eq!(finding.location, "$GREENTIC_ENV");
        assert!(finding.message.contains("`dev`"));
    }

    #[test]
    fn classify_runtime_env_var_ignores_other_values() {
        let from = EnvId::try_from("dev").unwrap();
        assert!(classify_runtime_env_var(Some("local"), &from).is_none());
        assert!(classify_runtime_env_var(Some(""), &from).is_none());
        assert!(classify_runtime_env_var(None, &from).is_none());
    }

    #[test]
    fn apply_refuses_when_not_clean() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        env.bundles.push(make_bundle_deployment("dev", "fast2flow"));
        store.save(&env).unwrap();
        let err = apply(&store, &OpFlags::default(), "local").unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn apply_is_idempotent_when_no_dev_env() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let outcome = apply(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.result["legacy_dir_renamed_to"], Value::Null);
        assert_eq!(outcome.result["merged_slots"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn apply_migrates_simple_dev_into_fresh_local() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        env.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        env.packs
            .push(make_binding(CapabilitySlot::Secrets, LOCAL_SECRETS_PACK));
        store.save(&env).unwrap();
        let outcome = apply(&store, &OpFlags::default(), "local").unwrap();
        assert!(
            outcome.result["legacy_dir_renamed_to"]
                .as_str()
                .unwrap()
                .contains(".dev-migrated-"),
            "got: {}",
            outcome.result["legacy_dir_renamed_to"]
        );
        let merged: Vec<&str> = outcome.result["merged_slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // Both slots were absent from local → both should be merged.
        assert_eq!(merged.len(), 2);

        // Target env exists with the expected bindings.
        let local = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(local.packs.len(), 2);
        // Source dir no longer reachable via list.
        let envs = store.list().unwrap();
        assert!(envs.iter().any(|e| e.as_str() == "local"));
        assert!(!envs.iter().any(|e| e.as_str() == "dev"));
    }

    #[test]
    fn apply_merges_into_existing_local_preserving_user_bindings() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());

        // Pre-existing `local` env with a user-customized secrets binding.
        let mut local = make_env("local");
        local.packs.push(make_binding(
            CapabilitySlot::Secrets,
            "greentic.secrets.aws-secrets-manager@1.0.0",
        ));
        store.save(&local).unwrap();

        // Legacy `dev` env with deployer + secrets defaults.
        let mut dev = make_env("dev");
        dev.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        dev.packs
            .push(make_binding(CapabilitySlot::Secrets, LOCAL_SECRETS_PACK));
        dev.packs.push(make_binding(
            CapabilitySlot::Telemetry,
            LOCAL_TELEMETRY_PACK,
        ));
        store.save(&dev).unwrap();

        let outcome = apply(&store, &OpFlags::default(), "local").unwrap();
        let merged: Vec<&str> = outcome.result["merged_slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        // local already had secrets bound — only deployer + telemetry should
        // be merged.
        assert_eq!(merged.len(), 2, "got {merged:?}");
        assert!(merged.contains(&"deployer"));
        assert!(merged.contains(&"telemetry"));

        // Verify the user's secrets descriptor was NOT overwritten.
        let local = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        let secrets_binding = local
            .packs
            .iter()
            .find(|b| b.slot == CapabilitySlot::Secrets)
            .expect("secrets slot");
        assert_eq!(
            secrets_binding.kind.as_str(),
            "greentic.secrets.aws-secrets-manager@1.0.0",
            "user-customized secrets descriptor was overwritten"
        );
    }

    #[test]
    fn apply_after_apply_is_a_no_op() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("dev");
        env.packs
            .push(make_binding(CapabilitySlot::Deployer, LOCAL_DEPLOYER_PACK));
        store.save(&env).unwrap();
        let _ = apply(&store, &OpFlags::default(), "local").unwrap();
        // Second apply: dev is gone, local has the binding — no-op.
        let outcome = apply(&store, &OpFlags::default(), "local").unwrap();
        assert_eq!(outcome.result["legacy_dir_renamed_to"], Value::Null);
        assert_eq!(outcome.result["merged_slots"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn check_rejects_self_target() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let err = check(&store, &OpFlags::default(), "dev").unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn check_schema_only_returns_schema() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let flags = OpFlags {
            schema_only: true,
            answers: None,
        };
        let outcome = check(&store, &flags, "local").unwrap();
        assert_eq!(outcome.result["title"], "MigrateDevPayload");
    }
}
