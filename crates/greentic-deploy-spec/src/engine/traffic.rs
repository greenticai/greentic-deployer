//! Pure traffic-split verb semantics (Phase D PR-4.2c).
//!
//! The traffic verb group (`set` / `rollback`) follows the PR-4.2a engine
//! contract: pure `&mut Environment` transforms with no I/O, no clock
//! (`now` is a parameter), and no key material. Both `LocalFsStore`
//! (greentic-deployer, behind a flock) and the operator-store-server
//! (behind SQLite CAS) drive the SAME functions, so the §5.3 admission
//! gate, the 10,000 bps sum invariant, and the idempotency contract cannot
//! drift between local and remote.
//!
//! # Persist rule (read before calling)
//!
//! Unlike the revision group there is no committed-on-error path here —
//! every check runs BEFORE the single mutation at the end of each
//! transform:
//!
//! - [`set_traffic_split`] `Ok` with `new_generation == Some(_)` — the env
//!   was mutated; persist it.
//! - [`set_traffic_split`] `Ok` with `new_generation == None` — idempotent
//!   same-key-same-entries replay; the env was NOT touched. Do not persist
//!   (backends with derived artifacts, e.g. `LocalFsStore`'s
//!   `runtime-config.json`, may still reconcile them — a retry must repair
//!   a publish that failed after the env was already durable).
//! - [`rollback_traffic_split`] `Ok` — always a mutation; persist.
//! - any `Err(_)` — the env was not mutated; nothing to persist.
//!
//! NOT here (deliberately): `runtime-config.json` materialization (a
//! `LocalFsStore` projection of `traffic_splits` — remote consumers project
//! it from the env document) and `TrafficSplitApplied` telemetry (emitted
//! at the operator CLI layer from the outcome's env snapshot, so both
//! backends produce identical events).
//!
//! # Wire shapes
//!
//! [`SetTrafficSplitPayload`] / [`RollbackTrafficSplitPayload`] double as
//! the A8 request bodies (`POST /environments/{env}/traffic` and
//! `POST /environments/{env}/traffic/rollback`);
//! [`ApplyTrafficSplitOutcome`] / [`RollbackTrafficSplitOutcome`] are the
//! response bodies. The wire-format tests at the bottom pin the encoding.
//! The A8 `Idempotency-Key` rides the HTTP header AND
//! [`set_traffic_split`]'s `idempotency_key` parameter — the traffic group
//! is special in that the key is part of the domain state
//! ([`TrafficSplit::idempotency_key`] preserves the rollback target across
//! same-key retries), not just transport metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

use crate::engine::inline_stash;
use crate::environment::Environment;
use crate::error::SpecError;
use crate::ids::{DeploymentId, RevisionId};
use crate::remote::IdempotencyKey;
use crate::revision::RevisionLifecycle;
use crate::traffic_split::{TrafficSplit, TrafficSplitEntry};
use crate::version::SchemaVersion;
use greentic_types::EnvId;

// ---------------------------------------------------------------------------
// Error surface
// ---------------------------------------------------------------------------

/// Failures produced by the pure traffic-split transforms. Each backend
/// maps these onto its own error vocabulary — `LocalFsStore` →
/// `StoreError`, the operator-store-server →
/// [`crate::remote::RemoteStoreError`]. Display strings are the verbatim
/// operator-facing messages the local store has always rendered.
/// (Not `Clone`: the [`TrafficSplitError::Invalid`] payload, [`SpecError`],
/// isn't.)
#[derive(Debug, PartialEq, Eq, Error)]
pub enum TrafficSplitError {
    /// The targeted deployment does not exist in the environment.
    #[error("deployment `{deployment_id}` not found in env `{env_id}`")]
    DeploymentNotFound {
        env_id: EnvId,
        deployment_id: DeploymentId,
    },
    /// An entry references a revision that does not exist (set-path
    /// referential check — maps to the dependent-not-found noun).
    #[error("revision `{revision_id}` not found in env `{env_id}`")]
    RevisionNotFound {
        env_id: EnvId,
        revision_id: RevisionId,
    },
    /// An entry references a revision owned by a different deployment.
    #[error("revision `{revision_id}` belongs to deployment `{actual}`, not `{expected}`")]
    WrongDeployment {
        revision_id: RevisionId,
        actual: DeploymentId,
        expected: DeploymentId,
    },
    /// A retry reused an idempotency key with different entries — a
    /// protocol violation, not a replay.
    #[error(
        "idempotency key `{key}` already used for deployment `{deployment_id}` with different entries"
    )]
    IdempotencyKeyReused {
        key: String,
        deployment_id: DeploymentId,
    },
    /// §5.3 admission found a routed revision missing from the env. Same
    /// message as [`TrafficSplitError::RevisionNotFound`] but a distinct
    /// variant: on the rollback path a historical split may reference a
    /// since-removed revision, which is a state conflict (409), not a
    /// caller-supplied bad id (404).
    #[error("revision `{revision_id}` not found in env `{env_id}`")]
    AdmissionRevisionMissing {
        env_id: EnvId,
        revision_id: RevisionId,
    },
    /// §5.3 admission: only `Ready` revisions may receive traffic.
    #[error(
        "revision `{revision_id}` is `{lifecycle:?}`; only `Ready` revisions may receive traffic"
    )]
    NotReady {
        revision_id: RevisionId,
        lifecycle: RevisionLifecycle,
    },
    /// Serializing the prior split for the rollback stash failed.
    #[error("snapshot prior split: {detail}")]
    SnapshotEncode { detail: String },
    /// No split exists for the deployment (rollback path).
    #[error("no traffic split for deployment `{deployment_id}` in env `{env_id}`")]
    NoSplit {
        env_id: EnvId,
        deployment_id: DeploymentId,
    },
    /// The live split carries no one-step-previous snapshot to restore.
    #[error("traffic split for `{deployment_id}` has no prior version to roll back to")]
    NoPreviousSnapshot { deployment_id: DeploymentId },
    /// The `previous_split_ref` token failed to decode.
    #[error("previous split payload `{}` missing", prev_ref.display())]
    SnapshotMissing { prev_ref: PathBuf },
    /// The decoded snapshot failed to deserialize as a [`TrafficSplit`].
    #[error("deserialise previous split: {detail}")]
    SnapshotDecode { detail: String },
    /// The assembled split failed spec validation (schema discriminator /
    /// 10,000 bps sum invariant).
    #[error(transparent)]
    Invalid(#[from] SpecError),
}

// ---------------------------------------------------------------------------
// Wire payloads + outcomes
// ---------------------------------------------------------------------------

/// Inputs to `EnvironmentMutations::set_traffic_split`, and the A8
/// `POST /environments/{env_id}/traffic` request body (field set pinned by
/// the PR-3b client's `SetTrafficSplitRequest`). The A8 idempotency key is
/// NOT a field — it rides the HTTP header and the engine parameter, because
/// the traffic group persists it into [`TrafficSplit::idempotency_key`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetTrafficSplitPayload {
    pub deployment_id: DeploymentId,
    pub entries: Vec<TrafficSplitEntry>,
    pub updated_by: String,
    /// Audit provenance; defaults to `auth.json` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
}

/// `POST /environments/{env_id}/traffic/rollback` request body. The
/// deployment id rides in the body (the route is per-env, not
/// per-deployment) — pinned by the PR-3b client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackTrafficSplitPayload {
    pub deployment_id: DeploymentId,
}

/// Outcome of `EnvironmentMutations::set_traffic_split`, and the A8
/// response body. Carries the post-apply split, the generation transition
/// for audit/observability, and the post-mutation env snapshot (the
/// operator CLI emits `TrafficSplitApplied` telemetry from it — tenant
/// attribution without a re-read, identical local and remote).
///
/// On an idempotent same-key-same-entries replay, `previous_generation`
/// and `new_generation` are both `None` (no state change — and no
/// telemetry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyTrafficSplitOutcome {
    pub split: TrafficSplit,
    pub previous_generation: Option<u64>,
    pub new_generation: Option<u64>,
    pub environment: Environment,
}

/// Outcome of `EnvironmentMutations::rollback_traffic_split`, and the A8
/// response body. A rollback always advances the generation, so both
/// generations are unconditional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackTrafficSplitOutcome {
    pub restored: TrafficSplit,
    pub previous_generation: u64,
    pub new_generation: u64,
    pub environment: Environment,
}

/// What [`set_traffic_split`] hands back to the storage layer: the applied
/// (or replayed) split and the generation transition. The backend wraps it
/// into [`ApplyTrafficSplitOutcome`] together with the env snapshot it just
/// persisted.
#[derive(Debug, Clone)]
pub struct TrafficSplitTransition {
    pub split: TrafficSplit,
    pub previous_generation: Option<u64>,
    pub new_generation: Option<u64>,
}

impl TrafficSplitTransition {
    /// Whether the transform actually mutated the environment (`false` =
    /// idempotent replay; see the module-level persist rule).
    pub fn mutated(&self) -> bool {
        self.new_generation.is_some()
    }
}

/// What [`rollback_traffic_split`] hands back to the storage layer.
#[derive(Debug, Clone)]
pub struct TrafficRollbackTransition {
    pub restored: TrafficSplit,
    pub previous_generation: u64,
    pub new_generation: u64,
}

// ---------------------------------------------------------------------------
// Pure transforms
// ---------------------------------------------------------------------------

/// Replace the entire traffic-split entry list for one deployment.
/// Validates the 10,000 bps sum invariant via [`TrafficSplit::validate`],
/// checks §5.3 admission (entries must route to `Ready` revisions), and
/// stashes the prior split inline for one-step rollback.
///
/// Idempotency: a same-key-same-entries replay (order-insensitive, see
/// [`entries_match`]) is a no-op success with both generations `None`.
/// Same-key-different-entries is
/// [`TrafficSplitError::IdempotencyKeyReused`]. A new key advances the
/// generation and snapshots the prior split as the rollback target.
pub fn set_traffic_split(
    env: &mut Environment,
    payload: SetTrafficSplitPayload,
    idempotency_key: &IdempotencyKey,
    now: DateTime<Utc>,
) -> Result<TrafficSplitTransition, TrafficSplitError> {
    let SetTrafficSplitPayload {
        deployment_id,
        entries,
        updated_by,
        authorization_ref,
    } = payload;
    let env_id = env.environment_id.clone();
    let deployment = env
        .bundles
        .iter()
        .find(|b| b.deployment_id == deployment_id)
        .ok_or_else(|| TrafficSplitError::DeploymentNotFound {
            env_id: env_id.clone(),
            deployment_id,
        })?;
    let bundle_id = deployment.bundle_id.clone();
    // Revision-belongs-to-deployment check.
    for entry in &entries {
        let rev = env
            .revisions
            .iter()
            .find(|r| r.revision_id == entry.revision_id)
            .ok_or_else(|| TrafficSplitError::RevisionNotFound {
                env_id: env_id.clone(),
                revision_id: entry.revision_id,
            })?;
        if rev.deployment_id != deployment_id {
            return Err(TrafficSplitError::WrongDeployment {
                revision_id: entry.revision_id,
                actual: rev.deployment_id,
                expected: deployment_id,
            });
        }
    }
    // Idempotency check: a retry with the same key against the same
    // (deployment, entries) is a no-op success; same key + different
    // payload is a conflict; new key advances generation.
    let prev_split_idx = env
        .traffic_splits
        .iter()
        .position(|s| s.deployment_id == deployment_id);
    if let Some(idx) = prev_split_idx {
        let prev = &env.traffic_splits[idx];
        if prev.idempotency_key == idempotency_key.as_str() {
            if entries_match(&prev.entries, &entries) {
                return Ok(TrafficSplitTransition {
                    split: prev.clone(),
                    previous_generation: None,
                    new_generation: None,
                });
            }
            return Err(TrafficSplitError::IdempotencyKeyReused {
                key: idempotency_key.as_str().to_string(),
                deployment_id,
            });
        }
    }
    // §5.3 admission, on the apply path only: the idempotent no-op replay
    // above must stay a success even if a routed revision later drains, so
    // a stale split is never rejected on retry.
    assert_entries_all_ready(env, &entries)?;
    let (generation, previous_split_ref, prev_gen) = match prev_split_idx {
        Some(idx) => {
            // Serialize a clone with previous_split_ref cleared: the stash is
            // one-step by contract (rollback overwrites the nested ref with
            // None and never follows it), so serializing the live ref would
            // nest stash-in-stash tokens that grow ~(4/3)^n without bound.
            let mut stash_copy = env.traffic_splits[idx].clone();
            let prev_generation = stash_copy.generation;
            stash_copy.previous_split_ref = None;
            let snapshot = serde_json::to_value(&stash_copy).map_err(|e| {
                TrafficSplitError::SnapshotEncode {
                    detail: e.to_string(),
                }
            })?;
            (
                prev_generation + 1,
                Some(inline_stash::stash_inline(snapshot)),
                Some(prev_generation),
            )
        }
        None => (0, None, None),
    };
    let split = TrafficSplit {
        schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
        env_id,
        deployment_id,
        bundle_id,
        generation,
        entries,
        updated_at: now,
        updated_by,
        idempotency_key: idempotency_key.as_str().to_string(),
        authorization_ref: authorization_ref
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("auth.json")),
        previous_split_ref,
    };
    split.validate()?;
    match prev_split_idx {
        Some(idx) => env.traffic_splits[idx] = split.clone(),
        None => env.traffic_splits.push(split.clone()),
    }
    Ok(TrafficSplitTransition {
        split,
        previous_generation: prev_gen,
        new_generation: Some(generation),
    })
}

/// Rollback the traffic split for a deployment to its one-step-previous
/// snapshot. Bumps the generation and re-validates §5.3 admission on the
/// restored entries (a historical split may route to revisions that have
/// since been archived, failed, or removed).
pub fn rollback_traffic_split(
    env: &mut Environment,
    deployment_id: DeploymentId,
    now: DateTime<Utc>,
) -> Result<TrafficRollbackTransition, TrafficSplitError> {
    let idx = env
        .traffic_splits
        .iter()
        .position(|s| s.deployment_id == deployment_id)
        .ok_or_else(|| TrafficSplitError::NoSplit {
            env_id: env.environment_id.clone(),
            deployment_id,
        })?;
    let prev_split_generation = env.traffic_splits[idx].generation;
    let prev_ref = env.traffic_splits[idx]
        .previous_split_ref
        .clone()
        .ok_or(TrafficSplitError::NoPreviousSnapshot { deployment_id })?;
    let prev_value = inline_stash::load_inline(&prev_ref)
        .ok_or(TrafficSplitError::SnapshotMissing { prev_ref })?;
    let mut restored: TrafficSplit =
        serde_json::from_value(prev_value).map_err(|e| TrafficSplitError::SnapshotDecode {
            detail: e.to_string(),
        })?;
    let new_generation = prev_split_generation + 1;
    restored.generation = new_generation;
    restored.previous_split_ref = None;
    restored.updated_at = now;
    restored.idempotency_key = format!("rollback-{}", env.traffic_splits[idx].idempotency_key);
    restored.validate()?;
    assert_entries_all_ready(env, &restored.entries)?;
    env.traffic_splits[idx] = restored.clone();
    Ok(TrafficRollbackTransition {
        restored,
        previous_generation: prev_split_generation,
        new_generation,
    })
}

/// §5.3 admission: every entry's revision must exist and be `Ready` before
/// its split goes live. Used by both [`set_traffic_split`] and
/// [`rollback_traffic_split`].
pub fn assert_entries_all_ready(
    env: &Environment,
    entries: &[TrafficSplitEntry],
) -> Result<(), TrafficSplitError> {
    for entry in entries {
        let rev = env
            .revisions
            .iter()
            .find(|r| r.revision_id == entry.revision_id)
            .ok_or_else(|| TrafficSplitError::AdmissionRevisionMissing {
                env_id: env.environment_id.clone(),
                revision_id: entry.revision_id,
            })?;
        if rev.lifecycle != RevisionLifecycle::Ready {
            return Err(TrafficSplitError::NotReady {
                revision_id: entry.revision_id,
                lifecycle: rev.lifecycle,
            });
        }
    }
    Ok(())
}

/// Order-insensitive equality on basis-points-per-revision_id. Two payloads
/// that route the same percentage to the same revision_id (in any
/// permutation) collapse to "same" for idempotency purposes.
pub fn entries_match(a: &[TrafficSplitEntry], b: &[TrafficSplitEntry]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<(&RevisionId, u32)> =
        a.iter().map(|e| (&e.revision_id, e.weight_bps)).collect();
    let mut b_sorted: Vec<(&RevisionId, u32)> =
        b.iter().map(|e| (&e.revision_id, e.weight_bps)).collect();
    a_sorted.sort_by_key(|(r, _)| r.to_string());
    b_sorted.sort_by_key(|(r, _)| r.to_string());
    a_sorted == b_sorted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_deployment::{
        BundleDeployment, BundleDeploymentStatus, RevenueShareEntry, RouteBinding, TenantSelector,
    };
    use crate::engine::{StageRevisionPayload, stage_revision};
    use crate::ids::{BundleId, CustomerId, PackId, PartyId};
    use crate::revision::PackListEntry;
    use crate::version::SemVer;
    use chrono::TimeZone;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn fixed_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 12, 12, 0, 0).unwrap()
    }

    fn idem(raw: &str) -> IdempotencyKey {
        IdempotencyKey::new(raw).expect("valid idempotency key")
    }

    fn deployment(deployment_id: DeploymentId) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id,
            env_id: env_id(),
            bundle_id: BundleId::new("fast2flow"),
            customer_id: CustomerId::new("local-dev"),
            status: BundleDeploymentStatus::Active,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: vec!["fast2flow.local".to_string()],
                path_prefixes: Vec::new(),
                tenant_selector: TenantSelector {
                    tenant: "default".to_string(),
                    team: "default".to_string(),
                },
            },
            revenue_share: vec![RevenueShareEntry {
                party_id: PartyId::new("greentic"),
                basis_points: 10_000,
            }],
            revenue_policy_ref: PathBuf::from("revenue.json"),
            usage: None,
            created_at: fixed_now(),
            authorization_ref: PathBuf::from("auth.json"),
            config_overrides: BTreeMap::new(),
        }
    }

    fn stage_payload(deployment_id: DeploymentId) -> StageRevisionPayload {
        StageRevisionPayload {
            revision_id: RevisionId::new(),
            deployment_id,
            bundle_digest: "sha256:00".to_string(),
            bundle_source_uri: None,
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("greentic.test.pack"),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:00".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            pack_config_refs: Vec::new(),
            config_digest: "sha256:00".to_string(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            drain_seconds: 30,
        }
    }

    /// Env with one deployment and two `Ready` revisions under it.
    fn env_with_ready_revisions(
        deployment_id: DeploymentId,
    ) -> (Environment, RevisionId, RevisionId) {
        let mut env = super::super::fresh_environment(
            &env_id(),
            "local".to_string(),
            crate::environment::EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
            Default::default(),
            Default::default(),
            Default::default(),
        );
        env.bundles.push(deployment(deployment_id));
        let r1 = stage_revision(&mut env, stage_payload(deployment_id), fixed_now())
            .unwrap()
            .revision_id;
        let r2 = stage_revision(&mut env, stage_payload(deployment_id), fixed_now())
            .unwrap()
            .revision_id;
        for rev in &mut env.revisions {
            rev.lifecycle = RevisionLifecycle::Ready;
        }
        (env, r1, r2)
    }

    fn set_payload(
        deployment_id: DeploymentId,
        entries: Vec<TrafficSplitEntry>,
    ) -> SetTrafficSplitPayload {
        SetTrafficSplitPayload {
            deployment_id,
            entries,
            updated_by: "operator@local".to_string(),
            authorization_ref: None,
        }
    }

    fn full_weight(revision_id: RevisionId) -> Vec<TrafficSplitEntry> {
        vec![TrafficSplitEntry {
            revision_id,
            weight_bps: 10_000,
        }]
    }

    // --- set: happy path + generation chain ---

    #[test]
    fn set_first_split_starts_at_generation_zero_without_stash() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, _) = env_with_ready_revisions(deployment_id);

        let t = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        assert!(t.mutated());
        assert_eq!(t.split.generation, 0);
        assert_eq!(t.previous_generation, None);
        assert_eq!(t.new_generation, Some(0));
        assert_eq!(t.split.previous_split_ref, None);
        assert_eq!(t.split.idempotency_key, "k1");
        assert_eq!(
            t.split.authorization_ref,
            PathBuf::from("auth.json"),
            "absent authorization_ref defaults"
        );
        assert_eq!(env.traffic_splits.len(), 1);
    }

    #[test]
    fn set_second_split_advances_generation_and_stashes_previous() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, r2) = env_with_ready_revisions(deployment_id);

        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        let t = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r2)),
            &idem("k2"),
            fixed_now(),
        )
        .unwrap();
        assert_eq!(t.previous_generation, Some(0));
        assert_eq!(t.new_generation, Some(1));
        let stash = t.split.previous_split_ref.as_ref().expect("stash present");
        let prev: TrafficSplit =
            serde_json::from_value(inline_stash::load_inline(stash).expect("stash decodes"))
                .expect("stash is a TrafficSplit");
        assert_eq!(prev.generation, 0);
        assert_eq!(prev.entries, full_weight(r1));
        assert_eq!(env.traffic_splits.len(), 1, "replace, not append");
    }

    // --- set: idempotency contract ---

    #[test]
    fn set_same_key_same_entries_is_a_no_op_replay() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, r2) = env_with_ready_revisions(deployment_id);

        let entries = vec![
            TrafficSplitEntry {
                revision_id: r1,
                weight_bps: 4_000,
            },
            TrafficSplitEntry {
                revision_id: r2,
                weight_bps: 6_000,
            },
        ];
        set_traffic_split(
            &mut env,
            set_payload(deployment_id, entries.clone()),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        let snapshot = env.clone();

        // Replay with the same key and the same entries PERMUTED — the
        // match is order-insensitive.
        let permuted: Vec<TrafficSplitEntry> = entries.into_iter().rev().collect();
        let t = set_traffic_split(
            &mut env,
            set_payload(deployment_id, permuted),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        assert!(!t.mutated());
        assert_eq!(t.previous_generation, None);
        assert_eq!(t.new_generation, None);
        assert_eq!(t.split.generation, 0, "replay returns the live split");
        assert_eq!(env, snapshot, "no-op replay must not touch the env");
    }

    #[test]
    fn set_same_key_different_entries_is_a_key_reuse_conflict() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, r2) = env_with_ready_revisions(deployment_id);

        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        let err = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r2)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, TrafficSplitError::IdempotencyKeyReused { key, .. } if key == "k1"),
            "unexpected error: {err:?}"
        );
    }

    // --- set: referential + admission guards ---

    #[test]
    fn set_rejects_unknown_deployment_and_unknown_revision() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, _) = env_with_ready_revisions(deployment_id);

        let err = set_traffic_split(
            &mut env,
            set_payload(DeploymentId::new(), full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(matches!(err, TrafficSplitError::DeploymentNotFound { .. }));

        let err = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(RevisionId::new())),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(matches!(err, TrafficSplitError::RevisionNotFound { .. }));
        assert!(env.traffic_splits.is_empty());
    }

    #[test]
    fn set_rejects_revision_owned_by_another_deployment() {
        let deployment_id = DeploymentId::new();
        let (mut env, _, _) = env_with_ready_revisions(deployment_id);
        let other_deployment = DeploymentId::new();
        env.bundles.push(deployment(other_deployment));
        let foreign = stage_revision(&mut env, stage_payload(other_deployment), fixed_now())
            .unwrap()
            .revision_id;
        env.revisions.last_mut().unwrap().lifecycle = RevisionLifecycle::Ready;

        let err = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(foreign)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                TrafficSplitError::WrongDeployment { revision_id, actual, expected }
                    if *revision_id == foreign
                        && *actual == other_deployment
                        && *expected == deployment_id
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn set_rejects_non_ready_revision_per_admission_gate() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, _) = env_with_ready_revisions(deployment_id);
        env.revisions[0].lifecycle = RevisionLifecycle::Staged;

        let err = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                TrafficSplitError::NotReady { lifecycle, .. }
                    if *lifecycle == RevisionLifecycle::Staged
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn set_rejects_weights_not_summing_to_ten_thousand() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, _) = env_with_ready_revisions(deployment_id);

        let err = set_traffic_split(
            &mut env,
            set_payload(
                deployment_id,
                vec![TrafficSplitEntry {
                    revision_id: r1,
                    weight_bps: 9_999,
                }],
            ),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(
            matches!(err, TrafficSplitError::Invalid(_)),
            "unexpected error: {err:?}"
        );
        assert!(env.traffic_splits.is_empty(), "invalid split not applied");
    }

    // --- rollback ---

    #[test]
    fn rollback_restores_previous_entries_and_advances_generation() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, r2) = env_with_ready_revisions(deployment_id);

        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r2)),
            &idem("k2"),
            fixed_now(),
        )
        .unwrap();

        let t = rollback_traffic_split(&mut env, deployment_id, fixed_now()).unwrap();
        assert_eq!(t.previous_generation, 1);
        assert_eq!(t.new_generation, 2, "rollback advances, never rewinds");
        assert_eq!(t.restored.entries, full_weight(r1));
        assert_eq!(t.restored.idempotency_key, "rollback-k2");
        assert_eq!(
            t.restored.previous_split_ref, None,
            "one-step rollback only"
        );
        assert_eq!(env.traffic_splits[0], t.restored);

        // The restored split has no further snapshot — a second rollback
        // is a conflict, not a flip-flop.
        let err = rollback_traffic_split(&mut env, deployment_id, fixed_now()).unwrap_err();
        assert!(matches!(err, TrafficSplitError::NoPreviousSnapshot { .. }));
    }

    #[test]
    fn rollback_without_split_is_no_split() {
        let deployment_id = DeploymentId::new();
        let (mut env, _, _) = env_with_ready_revisions(deployment_id);
        let err = rollback_traffic_split(&mut env, deployment_id, fixed_now()).unwrap_err();
        assert!(matches!(err, TrafficSplitError::NoSplit { .. }));
    }

    #[test]
    fn rollback_re_checks_admission_on_restored_entries() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, r2) = env_with_ready_revisions(deployment_id);

        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r2)),
            &idem("k2"),
            fixed_now(),
        )
        .unwrap();
        // The historical target drained/archived since the stash was taken.
        env.revisions[0].lifecycle = RevisionLifecycle::Archived;
        let snapshot = env.clone();

        let err = rollback_traffic_split(&mut env, deployment_id, fixed_now()).unwrap_err();
        assert!(
            matches!(&err, TrafficSplitError::NotReady { revision_id, .. } if *revision_id == r1),
            "unexpected error: {err:?}"
        );
        assert_eq!(env, snapshot, "failed rollback must not mutate the env");
    }

    // --- helpers ---

    #[test]
    fn entries_match_is_order_insensitive_and_weight_sensitive() {
        let (r1, r2) = (RevisionId::new(), RevisionId::new());
        let a = vec![
            TrafficSplitEntry {
                revision_id: r1,
                weight_bps: 4_000,
            },
            TrafficSplitEntry {
                revision_id: r2,
                weight_bps: 6_000,
            },
        ];
        let permuted: Vec<TrafficSplitEntry> = a.iter().rev().cloned().collect();
        assert!(entries_match(&a, &permuted));
        let reweighted = vec![
            TrafficSplitEntry {
                revision_id: r1,
                weight_bps: 5_000,
            },
            TrafficSplitEntry {
                revision_id: r2,
                weight_bps: 5_000,
            },
        ];
        assert!(!entries_match(&a, &reweighted));
        assert!(!entries_match(&a, &a[..1]));
    }

    // --- wire-format pinning (must match the PR-3b client encoding) ---

    #[test]
    fn set_payload_wire_format_is_pinned() {
        let deployment_id = DeploymentId::new();
        let revision_id = RevisionId::new();
        let payload = SetTrafficSplitPayload {
            deployment_id,
            entries: vec![TrafficSplitEntry {
                revision_id,
                weight_bps: 10_000,
            }],
            updated_by: "operator@local".to_string(),
            authorization_ref: None,
        };
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            json!({
                "deployment_id": deployment_id.to_string(),
                "entries": [{"revision_id": revision_id.to_string(), "weight_bps": 10_000}],
                "updated_by": "operator@local",
            }),
            "authorization_ref must be ABSENT when None (client encoding)"
        );

        let rollback = RollbackTrafficSplitPayload { deployment_id };
        assert_eq!(
            serde_json::to_value(&rollback).unwrap(),
            json!({"deployment_id": deployment_id.to_string()})
        );
    }

    #[test]
    fn apply_outcome_round_trips_with_environment_snapshot() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, _) = env_with_ready_revisions(deployment_id);
        let t = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        let outcome = ApplyTrafficSplitOutcome {
            split: t.split,
            previous_generation: t.previous_generation,
            new_generation: t.new_generation,
            environment: env,
        };
        let value = serde_json::to_value(&outcome).unwrap();
        assert_eq!(value["new_generation"], 0);
        assert_eq!(value["previous_generation"], serde_json::Value::Null);
        assert_eq!(value["environment"]["environment_id"], "local");
        let back: ApplyTrafficSplitOutcome = serde_json::from_value(value).unwrap();
        assert_eq!(back.split, outcome.split);
        assert_eq!(back.environment, outcome.environment);
    }

    #[test]
    fn stash_is_bounded_to_one_level_across_multiple_sets() {
        let deployment_id = DeploymentId::new();
        let (mut env, r1, r2) = env_with_ready_revisions(deployment_id);

        // Three successive sets with distinct keys, alternating revisions.
        set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k1"),
            fixed_now(),
        )
        .unwrap();
        let t2 = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r2)),
            &idem("k2"),
            fixed_now(),
        )
        .unwrap();
        let t3 = set_traffic_split(
            &mut env,
            set_payload(deployment_id, full_weight(r1)),
            &idem("k3"),
            fixed_now(),
        )
        .unwrap();

        // The live split's stash decodes into a TrafficSplit whose own
        // previous_split_ref is None — exactly one level, no nested token.
        let stash3 = t3
            .split
            .previous_split_ref
            .as_ref()
            .expect("stash present after set #3");
        let prev3: TrafficSplit =
            serde_json::from_value(inline_stash::load_inline(stash3).expect("stash decodes"))
                .expect("stash is a TrafficSplit");
        assert_eq!(
            prev3.previous_split_ref, None,
            "stash must be one level deep"
        );
        assert_eq!(prev3.generation, 1);
        assert_eq!(prev3.entries, full_weight(r2));

        // Same check on set #2's stash.
        let stash2 = t2
            .split
            .previous_split_ref
            .as_ref()
            .expect("stash present after set #2");
        let prev2: TrafficSplit =
            serde_json::from_value(inline_stash::load_inline(stash2).expect("stash decodes"))
                .expect("stash is a TrafficSplit");
        assert_eq!(
            prev2.previous_split_ref, None,
            "stash must be one level deep"
        );

        // Token length after set #3 is in the same ballpark as set #2 —
        // proves boundedness (without the fix, #3 would embed #2's token).
        let len3 = stash3.as_os_str().len();
        let len2 = stash2.as_os_str().len();
        assert!(
            len3 <= len2 + 64,
            "stash tokens must not grow unboundedly: len(#3)={len3} vs len(#2)={len2}",
        );
    }
}
