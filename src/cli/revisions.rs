//! `gtc op revisions {stage,warm,drain,archive,list}` (`A3`).
//!
//! Manages `Environment.revisions: Vec<Revision>` and the per-deployment
//! `current_revisions` list on each `BundleDeployment`. Lifecycle transitions
//! are validated against the spec's pure
//! [`is_valid_transition`]
//! predicate so the operator can't put a Revision into an impossible state.
//!
//! Heavy lifting deferred:
//!
//! - Bundle-archive staging (resolving `.gtbundle` → `pack_list` via the
//!   distributor-client's `stage_bundle` call, digest-verifying the
//!   artifact, and writing the pack-list lockfile atomically before the
//!   revision becomes `Staged`) is **Phase D** work — tracked at
//!   <https://github.com/greenticai/greentic-deployer/issues/209>. Today
//!   `stage` trusts caller-supplied `bundle_digest` / `pack_list` /
//!   `*_ref` fields verbatim. A5 delivered the lifecycle storage guard
//!   (`environment::lifecycle::apply_revision_transition`) and the
//!   distributor-client's `set_bundle_state` atomic-write + transition
//!   matrix, but did NOT integrate `stage_bundle` here.
//! - Runner warm/drain hooks (route-table build, in-flight session
//!   accounting) are owned by `greentic-start`; A3 only updates the
//!   lifecycle bit and stamps `warmed_at`. The full warm/drain dance lands
//!   when the dispatcher lands.

use std::path::PathBuf;

use chrono::Utc;
use greentic_deploy_spec::{
    BundleId, DeploymentId, EnvId, PackId, PackListEntry, Revision, RevisionId, RevisionLifecycle,
    SchemaVersion, SemVer, is_valid_transition,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "revisions";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionStagePayload {
    pub environment_id: String,
    pub deployment_id: String,
    pub bundle_digest: String,
    #[serde(default)]
    pub pack_list: Vec<PackListEntryPayload>,
    #[serde(default = "default_pack_list_lock_ref")]
    pub pack_list_lock_ref: PathBuf,
    #[serde(default = "default_config_digest")]
    pub config_digest: String,
    #[serde(default = "default_signature_sidecar_ref")]
    pub signature_sidecar_ref: PathBuf,
    #[serde(default = "default_drain_seconds")]
    pub drain_seconds: u32,
}

fn default_pack_list_lock_ref() -> PathBuf {
    PathBuf::from("pack-list.lock")
}
fn default_config_digest() -> String {
    "sha256:00".to_string()
}
fn default_signature_sidecar_ref() -> PathBuf {
    PathBuf::from("rev.sig")
}
fn default_drain_seconds() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackListEntryPayload {
    pub pack_id: String,
    pub version: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionTransitionPayload {
    pub environment_id: String,
    pub revision_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionSummary {
    pub revision_id: String,
    pub deployment_id: String,
    pub bundle_id: String,
    pub sequence: u64,
    pub lifecycle: RevisionLifecycle,
}

impl From<&Revision> for RevisionSummary {
    fn from(r: &Revision) -> Self {
        Self {
            revision_id: r.revision_id.to_string(),
            deployment_id: r.deployment_id.to_string(),
            bundle_id: r.bundle_id.as_str().to_string(),
            sequence: r.sequence,
            lifecycle: r.lifecycle,
        }
    }
}

/// `op revisions stage`. Creates a Revision at `inactive → staged`. Bumps
/// the sequence to one past the deployment's current max.
pub fn stage(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionStagePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "stage", stage_schema()));
    }
    let payload = resolve_payload::<RevisionStagePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    // Pre-parse the pack list outside the lock so a payload error doesn't
    // hold the flock.
    let pack_list = payload
        .pack_list
        .into_iter()
        .map(|e| {
            Ok::<_, OpError>(PackListEntry {
                pack_id: PackId::new(e.pack_id),
                version: e
                    .version
                    .parse::<SemVer>()
                    .map_err(|err| OpError::InvalidArgument(format!("pack version: {err}")))?,
                digest: e.digest,
                source_uri: e.source_uri,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !is_valid_transition(RevisionLifecycle::Inactive, RevisionLifecycle::Staged) {
        return Err(OpError::Conflict(
            "spec rejects inactive → staged".to_string(),
        ));
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "stage",
        target: json!({
            "deployment_id": deployment_id.to_string(),
            "lifecycle_to": "staged",
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
        let summary = store.transact(&env_id, |locked| -> Result<RevisionSummary, OpError> {
            let mut env = locked.load()?;
            let deployment = env
                .bundles
                .iter()
                .find(|b| b.deployment_id == deployment_id)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "deployment `{deployment_id}` not found in env `{env_id}`"
                    ))
                })?
                .clone();
            let bundle_id = deployment.bundle_id.clone();
            let next_sequence = env
                .revisions
                .iter()
                .filter(|r| r.deployment_id == deployment_id)
                .map(|r| r.sequence)
                .max()
                .unwrap_or(0)
                + 1;
            let now = Utc::now();
            let staged = Revision {
                schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
                revision_id: crate::environment::mint_revision_id(),
                env_id: env_id.clone(),
                bundle_id,
                deployment_id,
                sequence: next_sequence,
                created_at: now,
                bundle_digest: payload.bundle_digest.clone(),
                pack_list: pack_list.clone(),
                pack_list_lock_ref: payload.pack_list_lock_ref.clone(),
                config_digest: payload.config_digest.clone(),
                signature_sidecar_ref: payload.signature_sidecar_ref.clone(),
                lifecycle: RevisionLifecycle::Staged,
                staged_at: Some(now),
                warmed_at: None,
                drain_seconds: payload.drain_seconds,
                abort_metrics: Vec::new(),
            };
            let revision_id = staged.revision_id;
            env.revisions.push(staged);
            locked.save(&env)?;
            Ok(RevisionSummary::from(
                env.revisions
                    .iter()
                    .find(|r| r.revision_id == revision_id)
                    .expect("just pushed"),
            ))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "stage",
            serde_json::to_value(summary).expect("RevisionSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

/// `op revisions warm`. `staged → warming → ready`. The two-step move is
/// collapsed here for A3 because no async warm hooks exist yet; Phase D wires
/// the runner warm API.
///
/// Default warm path runs a **Noop** health gate so existing CLI callers stay
/// behavior-compatible. Producers in higher-tier crates (e.g.
/// `greentic-start`) wire a real B9 warm/ready gate via
/// [`warm_with_health_gate`].
pub fn warm(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    warm_with_health_gate(store, flags, payload, |_env, _revision| Ok(()))
}

/// Gate-aware variant of [`warm`] (B9 of `plans/next-gen-deployment.md`).
///
/// Drives the same `staged → warming → ready` chain but runs `health_gate`
/// against the post-chain `(env, revision)` view before `warmed_at` is
/// stamped and the env is saved. On gate rejection, the revision is
/// persisted in `Failed` and a `Conflict` (warm/ready health gate) is
/// surfaced — see
/// [`crate::environment::apply_revision_transition_with_health_gate`].
///
/// Higher-tier consumers construct the gate from concrete validators
/// (route-table validate, runtime-config load, signature verify, provider
/// probes); this function only forwards the closure into the lifecycle
/// helper, keeping `greentic-deployer` free of any health-check producers.
pub fn warm_with_health_gate<G>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    health_gate: G,
) -> Result<OpOutcome, OpError>
where
    G: FnOnce(
        &greentic_deploy_spec::Environment,
        &Revision,
    ) -> Result<(), crate::environment::HealthGateFailure>,
{
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "warm", transition_schema()));
    }
    transition_with_health_gate(
        store,
        flags,
        payload,
        "warm",
        &[
            (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
            (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
        ],
        |r| {
            r.warmed_at = Some(Utc::now());
        },
        false,
        health_gate,
    )
}

/// `op revisions drain`. `ready → draining`. The full in-flight drain dance
/// (sessions, WebSocket cleanup, etc.) lives in the runtime; this command
/// records the intent and stamps the lifecycle.
pub fn drain(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "drain", transition_schema()));
    }
    transition(
        store,
        flags,
        payload,
        "drain",
        &[(RevisionLifecycle::Ready, RevisionLifecycle::Draining)],
        |_| {},
        false,
    )
}

/// `op revisions archive`. Transitions the lifecycle to `archived` and
/// removes the revision from `BundleDeployment.current_revisions`. Refuses
/// archival of any revision still referenced by a live `TrafficSplit` —
/// callers must rebalance traffic through `gtc op traffic set` first.
///
/// Accepts the full retirement walk: `Staged | Warming | Ready | Failed`
/// archive in one hop; a revision already drained (Draining → Inactive
/// via the runtime) completes through `Inactive → Archived` in the same
/// CLI call.
pub fn archive(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "archive", transition_schema()));
    }
    transition(
        store,
        flags,
        payload,
        "archive",
        &[
            (RevisionLifecycle::Staged, RevisionLifecycle::Archived),
            (RevisionLifecycle::Warming, RevisionLifecycle::Archived),
            (RevisionLifecycle::Ready, RevisionLifecycle::Archived),
            (RevisionLifecycle::Failed, RevisionLifecycle::Archived),
            (RevisionLifecycle::Draining, RevisionLifecycle::Inactive),
            (RevisionLifecycle::Inactive, RevisionLifecycle::Archived),
        ],
        |_| {},
        true,
    )
}

/// `op revisions list <env>` (filterable by `--deployment <id>` later).
pub fn list(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({"input_schema": "env_id positional"}),
        ));
    }
    let env_id = parse_env_id(env_id)?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let revisions: Vec<RevisionSummary> = env.revisions.iter().map(RevisionSummary::from).collect();
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({"environment_id": env_id.as_str(), "revisions": revisions}),
    ))
}

// --- internals -----------------------------------------------------------

/// CLI-side adapter over [`crate::environment::apply_revision_transition`].
/// Resolves the payload, drives the env transact, and renders the outcome
/// envelope. The lifecycle matrix walk lives in
/// [`crate::environment::lifecycle`] so future B-phase consumers (gtc start
/// orchestration #221, A7 audit emission) can call it without going through
/// the CLI shell.
fn transition<F: FnOnce(&mut Revision)>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    op: &'static str,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    on_final: F,
    prune_from_splits: bool,
) -> Result<OpOutcome, OpError> {
    transition_with_health_gate(
        store,
        flags,
        payload,
        op,
        accepted_chain,
        on_final,
        prune_from_splits,
        |_env, _revision| Ok(()),
    )
}

/// Gate-aware variant of [`transition`] for the B9 warm/ready gate. Routes
/// `on_final` and the `health_gate` closure through
/// [`crate::environment::apply_revision_transition_with_health_gate`] inside
/// the same `store.transact` lock so the gate sees the same snapshot the
/// chain advance saw and the env is saved once (Failed on rejection, post-
/// transition otherwise).
// One extra arg over the 7-arg sibling `transition` to thread the gate
// closure; bundling into a struct would touch every existing warm/drain/
// archive caller for no readability win.
#[allow(clippy::too_many_arguments)]
fn transition_with_health_gate<F, G>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    op: &'static str,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    on_final: F,
    prune_from_splits: bool,
    health_gate: G,
) -> Result<OpOutcome, OpError>
where
    F: FnOnce(&mut Revision),
    G: FnOnce(
        &greentic_deploy_spec::Environment,
        &Revision,
    ) -> Result<(), crate::environment::HealthGateFailure>,
{
    let payload = resolve_payload::<RevisionTransitionPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let revision_id = parse_revision_id(&payload.revision_id)?;
    // The chain's final `to` state is the lifecycle this verb lands on. Serde
    // emits the canonical lowercase wire form, matching how lifecycle appears
    // everywhere else.
    let lifecycle_to = accepted_chain.last().map(|(_, to)| *to);
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: op,
        target: json!({
            "revision_id": revision_id.to_string(),
            "lifecycle_to": lifecycle_to,
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, || {
        let revision = store.transact(&env_id, |locked| -> Result<Revision, OpError> {
            let revision = crate::environment::apply_revision_transition_with_health_gate(
                locked,
                revision_id,
                accepted_chain,
                on_final,
                prune_from_splits,
                health_gate,
            )
            .map_err(OpError::from)?;
            // Lifecycle transitions don't change traffic splits today, so this
            // is a no-op refresh (guarded by change-detection); it keeps the
            // runtime-config contract uniform across every mutating verb.
            let env = locked.load()?;
            locked.refresh_runtime_config(&env)?;
            Ok(revision)
        })?;
        let summary = RevisionSummary::from(&revision);
        let outcome = OpOutcome::new(
            NOUN,
            op,
            serde_json::to_value(summary).expect("RevisionSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
    Ok(DeploymentId(ulid))
}

fn parse_revision_id(raw: &str) -> Result<RevisionId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("revision_id: {e}")))?;
    Ok(RevisionId(ulid))
}

#[allow(dead_code)]
fn discard_bundle(_id: &BundleId) {
    // bundle_id is never used after derivation; this helper keeps the type
    // around for future planning hooks (e.g. ensuring stage rejects a
    // revision whose payload bundle_id contradicts the deployment's).
}

fn stage_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "RevisionStagePayload",
        "type": "object",
        "required": ["environment_id", "deployment_id", "bundle_digest"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "ULID"},
            "bundle_digest": {"type": "string"},
            "pack_list": {"type": "array"},
            "pack_list_lock_ref": {"type": "string"},
            "config_digest": {"type": "string"},
            "signature_sidecar_ref": {"type": "string"},
            "drain_seconds": {"type": "integer", "minimum": 0}
        }
    })
}

fn transition_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "RevisionTransitionPayload",
        "type": "object",
        "required": ["environment_id", "revision_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "revision_id": {"type": "string", "description": "ULID"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_bundle_deployment, make_env};
    use tempfile::tempdir;

    fn seed_env_with_deployment(store: &LocalFsStore) -> DeploymentId {
        let mut env = make_env("local");
        let deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        env.bundles.push(deployment);
        store.save(&env).unwrap();
        did
    }

    fn stage_payload(deployment_id: &DeploymentId) -> RevisionStagePayload {
        RevisionStagePayload {
            environment_id: "local".to_string(),
            deployment_id: deployment_id.to_string(),
            bundle_digest: "sha256:00".to_string(),
            pack_list: vec![PackListEntryPayload {
                pack_id: "greentic.test.pack".to_string(),
                version: "1.0.0".to_string(),
                digest: "sha256:00".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: default_pack_list_lock_ref(),
            config_digest: default_config_digest(),
            signature_sidecar_ref: default_signature_sidecar_ref(),
            drain_seconds: default_drain_seconds(),
        }
    }

    #[test]
    fn stage_creates_revision_in_staged() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let outcome = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("staged")
        );
        assert_eq!(
            outcome.result.get("sequence").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[test]
    fn warm_advances_to_ready() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let warmed = warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
            }),
        )
        .unwrap();
        assert_eq!(
            warmed.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("ready")
        );
    }

    #[test]
    fn drain_after_warm_succeeds() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        warm(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.clone(),
            }),
        )
        .unwrap();
        let drained = drain(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
            }),
        )
        .unwrap();
        assert_eq!(
            drained.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("draining")
        );
    }

    #[test]
    fn drain_from_staged_errors() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let err = drain(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn archive_prunes_current_revisions_when_no_live_traffic() {
        // After the A5 follow-up landed the active-traffic guard, archive
        // no longer silently prunes live splits. This test exercises the
        // happy path: revision is in `current_revisions` but NOT in any
        // traffic split. Archive succeeds and strips the tracking
        // reference; no traffic state is touched.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let mut deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            RevisionLifecycle::Ready,
        );
        let rid = revision.revision_id;
        deployment.current_revisions.push(rid);
        env.bundles.push(deployment);
        env.revisions.push(revision);
        store.save(&env).unwrap();

        let outcome = archive(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.to_string(),
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("archived")
        );

        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert!(
            env.bundles[0].current_revisions.is_empty(),
            "current_revisions should be pruned"
        );
    }

    #[test]
    fn archive_refuses_when_revision_is_in_live_traffic_split() {
        // Operator workflow guarantee: archiving a revision that still
        // routes live traffic surfaces a Conflict pointing at the splits
        // to rebalance. The CLI maps `LifecycleError::ActiveTrafficReference`
        // through `From<LifecycleError> for OpError`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let mut deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            RevisionLifecycle::Ready,
        );
        let rid = revision.revision_id;
        deployment.current_revisions.push(rid);
        let split = crate::cli::tests_common::make_traffic_split(
            "local",
            "fast2flow",
            &did,
            &rid,
            "test-key",
        );
        env.bundles.push(deployment);
        env.revisions.push(revision);
        env.traffic_splits.push(split);
        store.save(&env).unwrap();

        let err = archive(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.to_string(),
            }),
        )
        .unwrap_err();
        match err {
            OpError::Conflict(msg) => {
                assert!(
                    msg.contains("live traffic split")
                        && msg.contains("rebalance via `gtc op traffic set`"),
                    "expected actionable conflict message, got: {msg}"
                );
            }
            other => panic!("expected Conflict, got `{other:?}`"),
        }

        // Nothing persisted: lifecycle still Ready, split intact.
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
        assert_eq!(env.traffic_splits.len(), 1);
        assert!(env.bundles[0].current_revisions.contains(&rid));
    }

    #[test]
    fn archive_completes_a_drained_revision_through_inactive() {
        // Operator action: `drain` moved Ready → Draining; runtime
        // separately moved Draining → Inactive (simulated here via the
        // store). Archive walks Inactive → Archived in a single CLI call.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let deployment = make_bundle_deployment("local", "fast2flow");
        let did = deployment.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            RevisionLifecycle::Inactive,
        );
        let rid = revision.revision_id;
        env.bundles.push(deployment);
        env.revisions.push(revision);
        store.save(&env).unwrap();

        let outcome = archive(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid.to_string(),
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("archived")
        );
    }

    #[test]
    fn list_reflects_stage_calls() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let revs = listed
            .result
            .get("revisions")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(revs.len(), 2);
        // Sequences 1 and 2.
        let seqs: Vec<u64> = revs
            .iter()
            .filter_map(|r| r.get("sequence").and_then(|v| v.as_u64()))
            .collect();
        assert_eq!(seqs, vec![1, 2]);
    }

    // --- B9 warm-with-health-gate tests -----------------------------------

    /// `warm_with_health_gate` with a passing closure behaves exactly like
    /// the gate-less `warm`: revision lands `Ready`, runtime-config refresh
    /// runs, and the outcome envelope is the same shape.
    #[test]
    fn warm_with_passing_gate_lands_ready() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let warmed = warm_with_health_gate(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid,
            }),
            |_env, _revision| Ok(()),
        )
        .unwrap();
        assert_eq!(
            warmed.result.get("lifecycle").and_then(|v| v.as_str()),
            Some("ready")
        );
    }

    /// `warm_with_health_gate` with a failing closure surfaces a Conflict
    /// (from `OpError::From<LifecycleError>`) and persists the revision in
    /// `Failed`. The on-disk env reflects the failed warm so a follow-up
    /// `archive` / retry sees the real state.
    #[test]
    fn warm_with_failing_gate_persists_failed_and_returns_conflict() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let did = seed_env_with_deployment(&store);
        let staged = stage(&store, &OpFlags::default(), Some(stage_payload(&did))).unwrap();
        let rid_str = staged
            .result
            .get("revision_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let err = warm_with_health_gate(
            &store,
            &OpFlags::default(),
            Some(RevisionTransitionPayload {
                environment_id: "local".to_string(),
                revision_id: rid_str.clone(),
            }),
            |_env, _revision| {
                Err(crate::environment::HealthGateFailure {
                    failed_checks: vec![crate::environment::HealthCheckId::RuntimeConfig],
                    message: "runtime-config.json missing".to_string(),
                })
            },
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
        let msg = format!("{err}");
        assert!(msg.contains("warm/ready health gate"), "msg: {msg}");
        assert!(msg.contains("RuntimeConfig"), "msg: {msg}");

        // On-disk: revision is now Failed.
        let env_id = EnvId::try_from("local").unwrap();
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions.len(), 1);
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
    }
}
