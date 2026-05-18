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
//! - Bundle-archive staging (resolving `.gtbundle` → `pack_list`) is the
//!   distributor-client `stage_bundle` call; A5 wraps that with atomic-write
//!   semantics. A3 records the `bundle_digest`/`pack_list` from the payload
//!   and trusts the caller; integration with the live distributor lives in
//!   A5 + Phase D.
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

use super::{OpError, OpFlags, OpOutcome};

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
    let mut env = store.load(&env_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
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
    let revision = Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id: crate::environment::mint_revision_id(),
        env_id: env_id.clone(),
        bundle_id,
        deployment_id,
        sequence: next_sequence,
        created_at: now,
        bundle_digest: payload.bundle_digest,
        pack_list: payload
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
            .collect::<Result<Vec<_>, _>>()?,
        pack_list_lock_ref: payload.pack_list_lock_ref,
        config_digest: payload.config_digest,
        signature_sidecar_ref: payload.signature_sidecar_ref,
        // Stage transition: every new Revision starts at `inactive` then
        // immediately moves to `staged`. Validate the transition with the
        // pure predicate to keep the spec honest even at insertion time.
        lifecycle: RevisionLifecycle::Inactive,
        staged_at: None,
        warmed_at: None,
        drain_seconds: payload.drain_seconds,
        abort_metrics: Vec::new(),
    };
    if !is_valid_transition(revision.lifecycle, RevisionLifecycle::Staged) {
        return Err(OpError::Conflict(format!(
            "cannot transition from `{:?}` to `staged`",
            revision.lifecycle
        )));
    }
    let mut staged = revision;
    staged.lifecycle = RevisionLifecycle::Staged;
    staged.staged_at = Some(now);
    let revision_id = staged.revision_id;
    env.revisions.push(staged);
    store.save(&env)?;
    let summary = RevisionSummary::from(
        env.revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .expect("just pushed"),
    );
    Ok(OpOutcome::new(
        NOUN,
        "stage",
        serde_json::to_value(summary).expect("RevisionSummary is json-safe"),
    ))
}

/// `op revisions warm`. `staged → warming → ready`. The two-step move is
/// collapsed here for A3 because no async warm hooks exist yet; Phase D wires
/// the runner warm API.
pub fn warm(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "warm", transition_schema()));
    }
    transition(
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

/// `op revisions archive`. Drops the revision from any traffic split, then
/// transitions the lifecycle to `archived`.
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

/// Walk the `accepted_chain` until the revision is in the final state, or
/// fail with a structured conflict. When `prune_from_splits` is true, the
/// revision is also removed from any `TrafficSplit.entries` referencing it
/// (archive path).
fn transition<F: FnMut(&mut Revision)>(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<RevisionTransitionPayload>,
    op: &'static str,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    mut on_final: F,
    prune_from_splits: bool,
) -> Result<OpOutcome, OpError> {
    let payload = resolve_payload::<RevisionTransitionPayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let mut env = store.load(&env_id)?;
    let revision_id = parse_revision_id(&payload.revision_id)?;
    let idx = env
        .revisions
        .iter()
        .position(|r| r.revision_id == revision_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "revision `{revision_id}` not found in env `{env_id}`"
            ))
        })?;
    // Apply the chain step by step, validating each hop.
    for (from, to) in accepted_chain {
        if env.revisions[idx].lifecycle == *from {
            if !is_valid_transition(*from, *to) {
                return Err(OpError::Conflict(format!(
                    "spec rejects transition `{:?} → {:?}`",
                    from, to
                )));
            }
            env.revisions[idx].lifecycle = *to;
        }
    }
    let final_state = accepted_chain
        .last()
        .map(|(_, to)| *to)
        .ok_or_else(|| OpError::InvalidArgument("empty transition chain".to_string()))?;
    if env.revisions[idx].lifecycle != final_state {
        return Err(OpError::Conflict(format!(
            "revision `{revision_id}` is in `{:?}`; expected one of {:?}",
            env.revisions[idx].lifecycle,
            accepted_chain.iter().map(|(f, _)| f).collect::<Vec<_>>(),
        )));
    }
    on_final(&mut env.revisions[idx]);
    if prune_from_splits {
        for split in env.traffic_splits.iter_mut() {
            split.entries.retain(|e| e.revision_id != revision_id);
        }
        // Also remove from each bundle's current_revisions list.
        let deployment_id = env.revisions[idx].deployment_id;
        for bundle in env.bundles.iter_mut() {
            if bundle.deployment_id == deployment_id {
                bundle.current_revisions.retain(|r| *r != revision_id);
            }
        }
        // Drop empty splits — Environment::validate refuses a zero-entry
        // split (BasisPointsSum != 10_000).
        env.traffic_splits.retain(|s| !s.entries.is_empty());
    }
    store.save(&env)?;
    let summary = RevisionSummary::from(&env.revisions[idx]);
    Ok(OpOutcome::new(
        NOUN,
        op,
        serde_json::to_value(summary).expect("RevisionSummary is json-safe"),
    ))
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
    fn archive_prunes_split_and_current_revisions() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        // Seed with: deployment + ready revision + traffic split + bundle.current_revisions
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
        assert!(env.traffic_splits.is_empty(), "split should be dropped");
        assert!(
            env.bundles[0].current_revisions.is_empty(),
            "current_revisions should be pruned"
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
}
