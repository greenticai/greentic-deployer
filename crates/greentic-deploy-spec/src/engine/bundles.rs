//! Pure bundle-deployment verb semantics (Phase D PR-4.2g).
//!
//! The bundles verb group (`op bundles add | update | remove`) follows the
//! PR-4.2a engine contract: pure `&mut Environment` transforms with no I/O,
//! no clock, and no key material. Both `LocalFsStore` (greentic-deployer,
//! behind a flock) and the operator-store-server (behind SQLite CAS) drive
//! the SAME functions, so the duplicate-deployment rule and the remove
//! live-state guard cannot drift between local and remote.
//!
//! # The revenue-policy seam
//!
//! `add` and `update --revenue-share` also write a signed, versioned
//! revenue-policy artifact (B10) — that step needs the operator key and
//! storage, so it is deliberately NOT here. The transforms return the
//! deployment's **index** into `Environment.bundles` instead of a clone:
//! the backend writes the policy artifact from `&env.bundles[idx]` (whose
//! `revenue_policy_ref` still holds the committed value the version
//! counter derives from), pins the fresh ref via the same index, and only
//! then persists. The pure builder both backends share is
//! `greentic_operator_trust::revenue_policy::build_revenue_policy_version`.
//!
//! # Persist rule (read before calling)
//!
//! - any `Ok(_)` — the env was mutated; the backend finishes the
//!   revenue-policy step (where flagged) and persists.
//! - any `Err(_)` — the env was not mutated; nothing to persist.
//!
//! The A8 `Idempotency-Key` is transport metadata only (as in the bindings
//! group): the engine never sees it, the server echoes it into the audit
//! record, and replay caching is the PR-4.3 ledger.
//!
//! # ID minting
//!
//! `add_bundle` takes a pre-minted [`DeploymentId`]: `LocalFsStore` mints
//! it CLI-side, the operator-store-server mints it handler-side. This
//! mirrors the PR-3b wire contract, where `POST /bundles` carries no
//! `deployment_id` — the authority that owns storage mints the ULID.
//!
//! # Wire shapes
//!
//! [`AddBundlePayload`] / [`UpdateBundlePayload`] double as the A8 request
//! bodies (`POST /environments/{env}/bundles` and
//! `PATCH /environments/{env}/bundles/{deployment_id}`);
//! [`RemoveBundleOutcome`] is the `DELETE` response body. The wire-format
//! tests at the bottom pin the encoding the PR-3b client established.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::bundle_deployment::{
    BundleDeployment, BundleDeploymentStatus, RevenueShareEntry, RouteBinding, TenantSelector,
};
use crate::environment::Environment;
use crate::ids::{BundleId, CustomerId, DeploymentId, RevisionId};
use crate::revision::RevisionLifecycle;
use crate::version::SchemaVersion;
use greentic_types::EnvId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a bundle verb refused to mutate the environment. Display strings are
/// verbatim what `LocalFsStore` raised before the move (PR-4.2g), so
/// operator-facing CLI errors are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BundleError {
    /// P6 anchor (§5.4): one `BundleDeployment` per
    /// `(env_id, bundle_id, customer_id)`.
    #[error("bundle `{bundle_id}` for customer `{customer_id}` already deployed in env `{env_id}`")]
    AlreadyDeployed {
        bundle_id: BundleId,
        customer_id: CustomerId,
        env_id: EnvId,
    },
    #[error("deployment `{deployment_id}` not found in env `{env_id}`")]
    DeploymentNotFound {
        deployment_id: DeploymentId,
        env_id: EnvId,
    },
    /// The remove live-state guard: any traffic split pointing at the
    /// deployment, or any non-`Archived` revision under it.
    #[error(
        "deployment `{deployment_id}` is still live: {active_splits} traffic split(s), \
         {active_revisions} non-archived revision(s). Archive revisions and clear the \
         split first."
    )]
    StillLive {
        deployment_id: DeploymentId,
        active_splits: usize,
        active_revisions: usize,
    },
}

// ---------------------------------------------------------------------------
// Wire payloads / outcomes
// ---------------------------------------------------------------------------

/// Inputs to `EnvironmentMutations::add_bundle`, and the A8
/// `POST /environments/{env}/bundles` request body.
///
/// No `deployment_id` — the storage-owning side mints it (see the module
/// doc). No `idempotency_key` — the key rides the trait method and the A8
/// `Idempotency-Key` header, matching every other verb group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddBundlePayload {
    pub bundle_id: BundleId,
    pub customer_id: CustomerId,
    pub revenue_share: Vec<RevenueShareEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_binding: Option<RouteBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_ref: Option<String>,
    #[serde(default)]
    pub config_overrides: BTreeMap<String, BTreeMap<String, Value>>,
}

/// Inputs to `EnvironmentMutations::update_bundle`, and the A8
/// `PATCH /environments/{env}/bundles/{deployment_id}` request body
/// (`deployment_id` rides in the body too — the server cross-checks it
/// against the URL segment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateBundlePayload {
    pub deployment_id: DeploymentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<BundleDeploymentStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_binding: Option<RouteBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revenue_share: Option<Vec<RevenueShareEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
}

/// Outcome of `EnvironmentMutations::remove_bundle`, and the A8 `DELETE`
/// response body. Surfaces the archived revisions pruned alongside the
/// deployment so the destructive side effect is explicit on the contract —
/// the CLI records the IDs in the audit target, and HTTP backends can apply
/// a separate authorization check against the prune set before committing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveBundleOutcome {
    pub deployment: BundleDeployment,
    /// IDs of revisions removed from `Environment.revisions` as part of the
    /// post-removal compaction (always in `Archived` state because the
    /// live-state guard refuses any non-archived revision under the
    /// deployment).
    pub pruned_revision_ids: Vec<RevisionId>,
}

/// What [`update_bundle`] changed, by index into `Environment.bundles`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleUpdateApplied {
    /// Index of the patched deployment in `Environment.bundles`.
    pub index: usize,
    /// `payload.revenue_share` was `Some` — the backend must write a new
    /// revenue-policy version and pin its ref before persisting. The
    /// deployment at [`Self::index`] still carries the COMMITTED
    /// `revenue_policy_ref`, which is exactly what the version counter
    /// derives from.
    pub revenue_share_changed: bool,
}

// ---------------------------------------------------------------------------
// Transforms
// ---------------------------------------------------------------------------

/// Append a fresh [`BundleDeployment`] to `env.bundles` and return its
/// index. Rejects with [`BundleError::AlreadyDeployed`] when
/// `(bundle_id, customer_id)` is already deployed.
///
/// The new deployment's `revenue_policy_ref` is the empty placeholder —
/// the backend writes the v1 policy artifact from `&env.bundles[idx]` and
/// pins the resulting ref before persisting (see the module doc).
pub fn add_bundle(
    env: &mut Environment,
    payload: AddBundlePayload,
    deployment_id: DeploymentId,
    now: DateTime<Utc>,
) -> Result<usize, BundleError> {
    if env
        .bundles
        .iter()
        .any(|b| b.bundle_id == payload.bundle_id && b.customer_id == payload.customer_id)
    {
        return Err(BundleError::AlreadyDeployed {
            bundle_id: payload.bundle_id,
            customer_id: payload.customer_id,
            env_id: env.environment_id.clone(),
        });
    }
    let route_binding = payload.route_binding.unwrap_or_else(|| RouteBinding {
        hosts: Vec::new(),
        path_prefixes: Vec::new(),
        tenant_selector: TenantSelector {
            tenant: "default".to_string(),
            team: "default".to_string(),
        },
    });
    let authorization_ref = payload
        .authorization_ref
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("auth.json"));
    env.bundles.push(BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id,
        env_id: env.environment_id.clone(),
        bundle_id: payload.bundle_id,
        customer_id: payload.customer_id,
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding,
        revenue_share: payload.revenue_share,
        // Replaced with the v1 policy sidecar path by the backend.
        revenue_policy_ref: PathBuf::new(),
        usage: None,
        created_at: now,
        authorization_ref,
        config_overrides: payload.config_overrides,
    });
    Ok(env.bundles.len() - 1)
}

/// Patch a [`BundleDeployment`]'s scalar fields in place. `None` fields are
/// skipped. Returns the patched index plus whether `revenue_share` changed
/// (the backend's signal to write a new policy version — see
/// [`BundleUpdateApplied`]).
///
/// Rejects with [`BundleError::DeploymentNotFound`] when `deployment_id`
/// is absent under the env.
pub fn update_bundle(
    env: &mut Environment,
    payload: UpdateBundlePayload,
) -> Result<BundleUpdateApplied, BundleError> {
    let UpdateBundlePayload {
        deployment_id,
        status,
        route_binding,
        revenue_share,
        config_overrides,
    } = payload;
    let index = env
        .bundles
        .iter()
        .position(|b| b.deployment_id == deployment_id)
        .ok_or_else(|| BundleError::DeploymentNotFound {
            deployment_id,
            env_id: env.environment_id.clone(),
        })?;
    if let Some(s) = status {
        env.bundles[index].status = s;
    }
    if let Some(rb) = route_binding {
        env.bundles[index].route_binding = rb;
    }
    if let Some(overrides) = config_overrides {
        env.bundles[index].config_overrides = overrides;
    }
    let revenue_share_changed = revenue_share.is_some();
    if let Some(shares) = revenue_share {
        env.bundles[index].revenue_share = shares;
    }
    Ok(BundleUpdateApplied {
        index,
        revenue_share_changed,
    })
}

/// Remove a [`BundleDeployment`] from the env. Refuses with
/// [`BundleError::StillLive`] if the deployment still carries live state
/// (any traffic split pointing at it, or any non-`Archived` revision under
/// it) — callers run `op traffic clear` and archive revisions first. Drops
/// archived revisions for the same `deployment_id` so the env stays
/// compact.
///
/// Rejects with [`BundleError::DeploymentNotFound`] when the deployment is
/// absent under the env.
pub fn remove_bundle(
    env: &mut Environment,
    deployment_id: DeploymentId,
) -> Result<RemoveBundleOutcome, BundleError> {
    let index = env
        .bundles
        .iter()
        .position(|b| b.deployment_id == deployment_id)
        .ok_or_else(|| BundleError::DeploymentNotFound {
            deployment_id,
            env_id: env.environment_id.clone(),
        })?;
    // Live-state guard + prune set computed in one pass over
    // `env.revisions`. `current_revisions` is plan-level future signal that
    // A3's stage/warm path does not yet maintain, so it can't be the gate;
    // the live-state proof is: any traffic split pointing at this
    // deployment, or any non-`Archived` revision for it.
    let active_splits = env
        .traffic_splits
        .iter()
        .filter(|s| s.deployment_id == deployment_id)
        .count();
    let mut active_revisions = 0usize;
    let mut pruned_revision_ids: Vec<RevisionId> = Vec::new();
    for r in env.revisions.iter() {
        if r.deployment_id != deployment_id {
            continue;
        }
        if matches!(r.lifecycle, RevisionLifecycle::Archived) {
            pruned_revision_ids.push(r.revision_id);
        } else {
            active_revisions += 1;
        }
    }
    if active_splits > 0 || active_revisions > 0 {
        return Err(BundleError::StillLive {
            deployment_id,
            active_splits,
            active_revisions,
        });
    }
    let deployment = env.bundles.remove(index);
    env.revisions.retain(|r| r.deployment_id != deployment_id);
    Ok(RemoveBundleOutcome {
        deployment,
        pruned_revision_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::fresh_environment;
    use crate::environment::EnvironmentHostConfig;
    use crate::ids::PartyId;
    use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};
    use crate::revision::Revision;
    use crate::traffic_split::TrafficSplit;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn minimal_env() -> Environment {
        fresh_environment(
            &env_id(),
            "Local".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
            RevocationConfig::default(),
            RetentionPolicy::default(),
            HealthStatus::default(),
        )
    }

    fn fixed_now() -> DateTime<Utc> {
        "2026-06-12T00:00:00Z".parse().unwrap()
    }

    fn shares() -> Vec<RevenueShareEntry> {
        vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }]
    }

    fn add_payload(bundle: &str, customer: &str) -> AddBundlePayload {
        AddBundlePayload {
            bundle_id: BundleId::new(bundle),
            customer_id: CustomerId::new(customer),
            revenue_share: shares(),
            route_binding: None,
            authorization_ref: None,
            config_overrides: BTreeMap::new(),
        }
    }

    fn revision_for(deployment_id: DeploymentId, lifecycle: RevisionLifecycle) -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: env_id(),
            bundle_id: BundleId::new("acme"),
            deployment_id,
            sequence: 1,
            created_at: fixed_now(),
            bundle_digest: "sha256:deadbeef".to_string(),
            bundle_source_uri: None,
            pack_list: Vec::new(),
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            pack_config_refs: Vec::new(),
            config_digest: "sha256:cafe".to_string(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 0,
            abort_metrics: Vec::new(),
        }
    }

    fn split_for(deployment_id: DeploymentId) -> TrafficSplit {
        TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id(),
            deployment_id,
            bundle_id: BundleId::new("acme"),
            generation: 1,
            entries: Vec::new(),
            updated_at: fixed_now(),
            updated_by: "test".to_string(),
            idempotency_key: "k".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        }
    }

    // --- add ---

    #[test]
    fn add_bundle_appends_with_defaults_and_empty_policy_ref() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        let idx = add_bundle(&mut env, add_payload("acme", "cust-1"), did, fixed_now())
            .expect("fresh pair deploys");
        assert_eq!(idx, 0);
        let dep = &env.bundles[0];
        assert_eq!(dep.deployment_id, did);
        assert_eq!(dep.status, BundleDeploymentStatus::Active);
        assert_eq!(dep.created_at, fixed_now());
        assert_eq!(dep.revenue_policy_ref, PathBuf::new(), "backend pins ref");
        assert_eq!(dep.authorization_ref, PathBuf::from("auth.json"));
        assert_eq!(dep.route_binding.tenant_selector.tenant, "default");
    }

    #[test]
    fn add_bundle_rejects_duplicate_bundle_customer_pair() {
        let mut env = minimal_env();
        add_bundle(
            &mut env,
            add_payload("acme", "cust-1"),
            DeploymentId::new(),
            fixed_now(),
        )
        .unwrap();
        let err = add_bundle(
            &mut env,
            add_payload("acme", "cust-1"),
            DeploymentId::new(),
            fixed_now(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "bundle `acme` for customer `cust-1` already deployed in env `local`"
        );
        assert_eq!(env.bundles.len(), 1, "env untouched on Err");
    }

    #[test]
    fn add_bundle_allows_same_bundle_for_different_customer() {
        let mut env = minimal_env();
        add_bundle(
            &mut env,
            add_payload("acme", "cust-1"),
            DeploymentId::new(),
            fixed_now(),
        )
        .unwrap();
        add_bundle(
            &mut env,
            add_payload("acme", "cust-2"),
            DeploymentId::new(),
            fixed_now(),
        )
        .expect("different customer is a distinct deployment");
        assert_eq!(env.bundles.len(), 2);
    }

    // --- update ---

    #[test]
    fn update_bundle_patches_fields_and_flags_revenue_change() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        add_bundle(&mut env, add_payload("acme", "cust-1"), did, fixed_now()).unwrap();
        let applied = update_bundle(
            &mut env,
            UpdateBundlePayload {
                deployment_id: did,
                status: Some(BundleDeploymentStatus::Paused),
                route_binding: None,
                revenue_share: Some(vec![RevenueShareEntry {
                    party_id: PartyId::new("partner"),
                    basis_points: 10_000,
                }]),
                config_overrides: None,
            },
        )
        .expect("known deployment patches");
        assert_eq!(applied.index, 0);
        assert!(applied.revenue_share_changed);
        assert_eq!(env.bundles[0].status, BundleDeploymentStatus::Paused);
        assert_eq!(env.bundles[0].revenue_share[0].party_id.as_str(), "partner");
    }

    #[test]
    fn update_bundle_without_revenue_share_does_not_flag() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        add_bundle(&mut env, add_payload("acme", "cust-1"), did, fixed_now()).unwrap();
        let applied = update_bundle(
            &mut env,
            UpdateBundlePayload {
                deployment_id: did,
                status: Some(BundleDeploymentStatus::Paused),
                route_binding: None,
                revenue_share: None,
                config_overrides: None,
            },
        )
        .unwrap();
        assert!(!applied.revenue_share_changed);
    }

    #[test]
    fn update_bundle_rejects_unknown_deployment() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        let err = update_bundle(
            &mut env,
            UpdateBundlePayload {
                deployment_id: did,
                status: None,
                route_binding: None,
                revenue_share: None,
                config_overrides: None,
            },
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("deployment `{did}` not found in env `local`")
        );
    }

    // --- remove ---

    #[test]
    fn remove_bundle_prunes_archived_revisions() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        add_bundle(&mut env, add_payload("acme", "cust-1"), did, fixed_now()).unwrap();
        env.revisions
            .push(revision_for(did, RevisionLifecycle::Archived));
        env.revisions
            .push(revision_for(did, RevisionLifecycle::Archived));
        let other = DeploymentId::new();
        env.revisions
            .push(revision_for(other, RevisionLifecycle::Ready));

        let outcome = remove_bundle(&mut env, did).expect("quiesced deployment removes");
        assert_eq!(outcome.deployment.deployment_id, did);
        assert_eq!(outcome.pruned_revision_ids.len(), 2);
        assert!(env.bundles.is_empty());
        assert_eq!(env.revisions.len(), 1, "other deployment's revision kept");
        assert_eq!(env.revisions[0].deployment_id, other);
    }

    #[test]
    fn remove_bundle_refuses_live_state() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        add_bundle(&mut env, add_payload("acme", "cust-1"), did, fixed_now()).unwrap();
        env.revisions
            .push(revision_for(did, RevisionLifecycle::Ready));
        env.traffic_splits.push(split_for(did));
        let err = remove_bundle(&mut env, did).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "deployment `{did}` is still live: 1 traffic split(s), 1 non-archived \
                 revision(s). Archive revisions and clear the split first."
            )
        );
        assert_eq!(env.bundles.len(), 1, "env untouched on Err");
        assert_eq!(env.revisions.len(), 1, "no pruning on refusal");
    }

    #[test]
    fn remove_bundle_rejects_unknown_deployment() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        let err = remove_bundle(&mut env, did).unwrap_err();
        assert!(matches!(err, BundleError::DeploymentNotFound { .. }));
    }

    // --- wire-format pins (the encoding the PR-3b client established) ---

    #[test]
    fn add_payload_wire_encoding_is_pinned() {
        let payload = add_payload("acme", "cust-1");
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "bundle_id": "acme",
                "customer_id": "cust-1",
                "revenue_share": [{"party_id": "greentic", "basis_points": 10_000}],
                "config_overrides": {},
            })
        );
        let decoded: AddBundlePayload = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn add_payload_decodes_without_optional_fields() {
        let decoded: AddBundlePayload = serde_json::from_value(serde_json::json!({
            "bundle_id": "acme",
            "customer_id": "cust-1",
            "revenue_share": [],
        }))
        .unwrap();
        assert!(decoded.route_binding.is_none());
        assert!(decoded.authorization_ref.is_none());
        assert!(decoded.config_overrides.is_empty());
    }

    #[test]
    fn update_payload_wire_encoding_is_pinned() {
        let did = DeploymentId::new();
        let payload = UpdateBundlePayload {
            deployment_id: did,
            status: Some(BundleDeploymentStatus::Paused),
            route_binding: None,
            revenue_share: None,
            config_overrides: None,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "deployment_id": did.to_string(),
                "status": "paused",
            })
        );
        let decoded: UpdateBundlePayload = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn remove_outcome_wire_encoding_round_trips() {
        let mut env = minimal_env();
        let did = DeploymentId::new();
        add_bundle(&mut env, add_payload("acme", "cust-1"), did, fixed_now()).unwrap();
        env.revisions
            .push(revision_for(did, RevisionLifecycle::Archived));
        let outcome = remove_bundle(&mut env, did).unwrap();
        let value = serde_json::to_value(&outcome).unwrap();
        assert_eq!(value["deployment"]["deployment_id"], did.to_string());
        assert_eq!(
            value["pruned_revision_ids"][0],
            outcome.pruned_revision_ids[0].to_string()
        );
        let decoded: RemoveBundleOutcome = serde_json::from_value(value).unwrap();
        assert_eq!(decoded, outcome);
    }
}
