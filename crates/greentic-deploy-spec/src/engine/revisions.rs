//! Pure revision-lifecycle verb semantics (Phase D PR-4.2b).
//!
//! The revision verb group (`stage` / `warm` / `drain` / `archive`) follows
//! the PR-4.2a engine contract: pure `&mut Environment` transforms with no
//! I/O, no clock (`now` is a parameter), and no key material. Both
//! `LocalFsStore` (greentic-deployer, behind a flock) and the
//! operator-store-server (behind SQLite CAS) drive the SAME functions, so
//! lifecycle semantics cannot drift between local and remote.
//!
//! # Persist rule (read before calling)
//!
//! These transforms mutate the borrowed [`Environment`] in place. Callers
//! own persistence and MUST apply this rule:
//!
//! - `Ok(_)` — persist the environment.
//! - `Err(e)` with [`RevisionLifecycleError::env_mutated`] `== true`
//!   (today: only `HealthGateFailed`) — the revision was flipped to
//!   `Failed`; persist the environment, THEN surface the error
//!   (committed-on-error, mirrors the local store's contract).
//! - any other `Err(_)` — the environment may be partially walked;
//!   DISCARD it (reload before reuse), never persist.
//!
//! # Wire shapes
//!
//! [`StageRevisionPayload`] and [`WarmRevisionPayload`] double as the A8
//! request bodies (`POST /environments/{env}/revisions` and
//! `POST /environments/{env}/revisions/{rid}/warm`);
//! [`RevisionTransitionOutcome`] is the response body for
//! warm/drain/archive. The wire-format tests at the bottom pin the
//! encoding. The A8 `Idempotency-Key` rides the HTTP header, never these
//! bodies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

use crate::environment::Environment;
use crate::ids::{BundleId, DeploymentId, RevisionId};
use crate::revision::{PackListEntry, Revision, RevisionLifecycle, is_valid_transition};
use crate::version::SchemaVersion;
use greentic_types::EnvId;

// ---------------------------------------------------------------------------
// Health-gate types (moved from greentic-deployer `environment::lifecycle`
// in PR-4.2b; semantics unchanged, serde added for the A8 wire)
// ---------------------------------------------------------------------------

/// Identifies which health-gate check failed in [`HealthGateFailure`].
///
/// The four checks correspond to the warm/ready gate's responsibilities
/// per `plans/next-gen-deployment.md` B9: route table, runtime config,
/// signature status, provider health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthCheckId {
    /// Static route table validates against the revision's pack list.
    RouteTable,
    /// Materialized `runtime-config.json` loads and validates.
    RuntimeConfig,
    /// Revision's `signature_sidecar_ref` exists and verifies.
    SignatureStatus,
    /// Providers in the revision's pack list are reachable / healthy.
    ProviderHealth,
}

/// Why a warm/ready health gate rejected a revision. Shipped by the deployer
/// CLI inside [`WarmRevisionPayload`] (the gate is evaluated client-side —
/// closures don't cross the A8 wire) and surfaced inside
/// [`RevisionLifecycleError::HealthGateFailed`] after the transform has
/// flipped the revision's lifecycle to `Failed`.
///
/// `failed_checks` MAY be empty (e.g. the gate aborted before any check
/// completed) — `message` always carries human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGateFailure {
    pub failed_checks: Vec<HealthCheckId>,
    pub message: String,
}

/// Identifies a `TrafficSplit` (by its `(deployment_id, bundle_id)` key)
/// for error-reporting purposes. Surfaced in
/// [`RevisionLifecycleError::ActiveTrafficReference`] so operators can
/// locate the splits they need to rebalance before retrying the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSplitRef {
    pub deployment_id: DeploymentId,
    pub bundle_id: BundleId,
    /// Weight (basis points) of the *archived* revision's entry in this
    /// split. Lets callers distinguish "100% live route" from "partial
    /// canary" without re-loading the env.
    pub weight_bps: u32,
}

// ---------------------------------------------------------------------------
// Error surface
// ---------------------------------------------------------------------------

/// Failures produced by the pure revision-lifecycle transforms. The pure
/// twin of greentic-deployer's `environment::lifecycle::LifecycleError`
/// (which adds a storage variant on top); each backend maps these onto its
/// own error vocabulary — `LocalFsStore` → `LifecycleError`/`StoreError`,
/// the operator-store-server → [`crate::remote::RemoteStoreError`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RevisionLifecycleError {
    /// The targeted revision was not present in the environment.
    #[error("revision `{revision_id}` not found in env `{env_id}`")]
    NotFound {
        env_id: EnvId,
        revision_id: RevisionId,
    },
    /// The spec matrix rejected an edge inside the requested chain. This is
    /// a programming error in the caller, not a runtime conflict — every
    /// chain passed in by the verb functions below is hand-curated.
    #[error("spec rejects transition `{from:?} → {to:?}`")]
    InvalidTransition {
        from: RevisionLifecycle,
        to: RevisionLifecycle,
    },
    /// The revision was loaded in a state that does not start any edge in
    /// the accepted chain (or, for `warm`, no longer carries the lifecycle
    /// the caller observed at gate-evaluation time). `actual` carries the
    /// lifecycle the transform found; `expected_starts` lists the states it
    /// would have accepted.
    #[error(
        "revision `{revision_id}` is in `{actual:?}`; expected one of {expected_starts:?} to apply the requested transition"
    )]
    Conflict {
        revision_id: RevisionId,
        actual: RevisionLifecycle,
        expected_starts: Vec<RevisionLifecycle>,
    },
    /// The caller passed an empty `accepted_chain`. Internal-API misuse.
    #[error("transition chain is empty; cannot apply any state change")]
    EmptyChain,
    /// The archive path (`prune_from_splits = true`) was invoked against a
    /// revision still referenced by one or more live traffic splits.
    /// Callers must rebalance traffic via `gtc op traffic set` before
    /// retrying.
    #[error(
        "revision `{revision_id}` is still referenced by {} live traffic split(s); rebalance via `gtc op traffic set` before archiving", splits.len()
    )]
    ActiveTrafficReference {
        revision_id: RevisionId,
        splits: Vec<ActiveSplitRef>,
    },
    /// The warm/ready health gate rejected the revision after the chain
    /// reached its final state. The transform has flipped the revision's
    /// lifecycle to `Failed` IN the borrowed environment — per the module's
    /// persist rule the caller MUST persist before surfacing this error.
    #[error(
        "revision `{revision_id}` failed health gate ({} check(s) failed): {message}",
        failed_checks.len()
    )]
    HealthGateFailed {
        revision_id: RevisionId,
        failed_checks: Vec<HealthCheckId>,
        message: String,
    },
    /// A revision with this id already exists in the environment. The
    /// stage verb's `revision_id` is caller-supplied (the bundle staging
    /// step names its rev_dir after the ULID before the verb runs), so a
    /// retry of a lost stage response replays the same id — appending a
    /// second copy would corrupt every `revision_id` lookup. Backends map
    /// this to their create-on-existing conflict (HTTP 409).
    #[error("revision `{revision_id}` already exists in env `{env_id}`")]
    DuplicateRevision {
        env_id: EnvId,
        revision_id: RevisionId,
    },
    /// The deployment the verb references does not exist in the environment.
    #[error("deployment `{deployment_id}` not found in env `{env_id}`")]
    DeploymentNotFound {
        env_id: EnvId,
        deployment_id: DeploymentId,
    },
}

impl RevisionLifecycleError {
    /// Whether the borrowed environment was mutated before this error was
    /// returned (and therefore MUST be persisted by the caller). True only
    /// for [`Self::HealthGateFailed`] — every other error leaves the
    /// environment in a discard-only state.
    pub fn env_mutated(&self) -> bool {
        matches!(self, Self::HealthGateFailed { .. })
    }
}

// ---------------------------------------------------------------------------
// Verb payloads (wire DTOs)
// ---------------------------------------------------------------------------

/// Inputs to `EnvironmentMutations::stage_revision`, and the A8
/// `POST /environments/{env_id}/revisions` request body.
///
/// `revision_id` is supplied by the caller because the bundle staging step
/// (extract + lock-pin + pack-config materialization) runs OUTSIDE the env
/// lock and names its on-disk `rev_dir` after the ULID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageRevisionPayload {
    pub revision_id: RevisionId,
    pub deployment_id: DeploymentId,
    pub bundle_digest: String,
    pub pack_list: Vec<PackListEntry>,
    pub pack_list_lock_ref: PathBuf,
    pub pack_config_refs: Vec<PathBuf>,
    pub config_digest: String,
    pub signature_sidecar_ref: PathBuf,
    pub drain_seconds: u32,
}

/// Inputs to `EnvironmentMutations::warm_revision`, and the A8
/// `POST /environments/{env_id}/revisions/{rid}/warm` request body
/// (`revision_id` rides in the body too — the server cross-checks it
/// against the URL).
///
/// The closure-based health gate can't cross the HTTP wire, so the deployer
/// CLI evaluates runner health locally and ships the typed outcome:
/// `Ok(())` advances the revision to `Ready`; `Err(failure)` flips it to
/// `Failed` atomically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmRevisionPayload {
    pub revision_id: RevisionId,
    /// The client-evaluated health-gate outcome, encoded on the wire as
    /// `{"ok": true}` / `{"ok": false, "failure": {…}}`.
    #[serde(with = "health_gate_wire")]
    pub health_gate: Result<(), HealthGateFailure>,
    /// The revision lifecycle the caller observed at gate-evaluation time.
    /// The transform re-checks that the revision still carries this
    /// lifecycle before applying the pre-evaluated gate result; on mismatch
    /// it rejects with [`RevisionLifecycleError::Conflict`] so a stale gate
    /// outcome is never applied to env state it didn't observe.
    ///
    /// The idempotent-retry path (revision already `Ready`) skips the check
    /// — the gate fires only when the chain actually advances.
    pub expected_lifecycle: RevisionLifecycle,
}

/// Wire encoding for [`WarmRevisionPayload::health_gate`]: serde's built-in
/// `Result` representation (externally tagged `Ok`/`Err`) is unidiomatic
/// JSON, so the field encodes as an explicit object instead.
mod health_gate_wire {
    use super::HealthGateFailure;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Repr {
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<HealthGateFailure>,
    }

    pub fn serialize<S: Serializer>(
        value: &Result<(), HealthGateFailure>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let repr = match value {
            Ok(()) => Repr {
                ok: true,
                failure: None,
            },
            Err(failure) => Repr {
                ok: false,
                failure: Some(failure.clone()),
            },
        };
        repr.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Result<(), HealthGateFailure>, D::Error> {
        let repr = Repr::deserialize(deserializer)?;
        match (repr.ok, repr.failure) {
            (true, None) => Ok(Ok(())),
            (false, Some(failure)) => Ok(Err(failure)),
            (true, Some(_)) => Err(serde::de::Error::custom(
                "health gate cannot be `ok: true` and carry a `failure`",
            )),
            (false, None) => Err(serde::de::Error::custom(
                "health gate `ok: false` must carry a `failure`",
            )),
        }
    }
}

/// Outcome of the warm/drain/archive verbs, and the A8 response body for
/// their routes. Carries the post-transition revision, the environment
/// after the mutation, and the starting lifecycle (the archive
/// eviction-vs-retirement discriminator in the deployer CLI's telemetry
/// emit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionTransitionOutcome {
    pub revision: Revision,
    pub environment: Environment,
    pub starting_lifecycle: RevisionLifecycle,
}

/// Intermediate result of the pure warm/drain/archive transforms: the
/// caller pairs it with the (now persisted) environment to build a
/// [`RevisionTransitionOutcome`].
#[derive(Debug, Clone)]
pub struct RevisionTransition {
    pub revision: Revision,
    pub starting_lifecycle: RevisionLifecycle,
}

// ---------------------------------------------------------------------------
// Pure transforms
// ---------------------------------------------------------------------------

/// Walk `revision_id` through an `accepted_chain` of `(from, to)` edges,
/// advancing the revision through every legal hop until it lands in the
/// final edge's `to` state (the pure core of the deployer's A5 storage
/// guard — see that module's docs for the full narrative).
///
/// **Idempotent on the final state:** a revision already at the chain's
/// final state succeeds without `Conflict`; `on_final` still runs (e.g.
/// re-stamps `warmed_at`) but `health_gate` does NOT (the revision is
/// already committed at its target state, possibly with live traffic — a
/// transient gate failure must not demote it).
///
/// `expected_start` is the warm verb's PR-3a.6b lifecycle precondition:
/// when `Some`, the revision's current lifecycle must equal it before any
/// edge applies, or the walk rejects with
/// [`RevisionLifecycleError::Conflict`]. The check is skipped when the
/// revision already sits at the chain's final state — the gate never fires
/// on that idempotent-retry path, so a stale snapshot is harmless there.
///
/// `prune_from_splits = true` is the archive-path knob: refuses with
/// [`RevisionLifecycleError::ActiveTrafficReference`] while any traffic
/// split still references the revision, otherwise removes the revision
/// from each matching `BundleDeployment::current_revisions` tracking list.
///
/// On gate failure the revision's lifecycle is flipped to `Failed` in
/// place and [`RevisionLifecycleError::HealthGateFailed`] is returned —
/// see the module's persist rule.
///
/// Returns the post-transition revision together with the lifecycle it
/// started from (the archive eviction-vs-retirement discriminator).
pub fn walk_revision_chain<F, G>(
    env: &mut Environment,
    revision_id: RevisionId,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    expected_start: Option<RevisionLifecycle>,
    on_final: F,
    prune_from_splits: bool,
    health_gate: G,
) -> Result<RevisionTransition, RevisionLifecycleError>
where
    F: FnOnce(&mut Revision),
    G: FnOnce(&Environment, &Revision) -> Result<(), HealthGateFailure>,
{
    if accepted_chain.is_empty() {
        return Err(RevisionLifecycleError::EmptyChain);
    }
    let final_state = accepted_chain
        .last()
        .map(|(_, to)| *to)
        .expect("chain non-empty: checked above");

    let idx = env
        .revisions
        .iter()
        .position(|r| r.revision_id == revision_id)
        .ok_or_else(|| RevisionLifecycleError::NotFound {
            env_id: env.environment_id.clone(),
            revision_id,
        })?;
    let starting_lifecycle = env.revisions[idx].lifecycle;

    if let Some(expected) = expected_start
        && starting_lifecycle != final_state
        && starting_lifecycle != expected
    {
        return Err(RevisionLifecycleError::Conflict {
            revision_id,
            actual: starting_lifecycle,
            expected_starts: vec![expected],
        });
    }

    let mut chain_advanced = false;
    for (from, to) in accepted_chain {
        if env.revisions[idx].lifecycle == *from {
            if !is_valid_transition(*from, *to) {
                return Err(RevisionLifecycleError::InvalidTransition {
                    from: *from,
                    to: *to,
                });
            }
            env.revisions[idx].lifecycle = *to;
            chain_advanced = true;
        }
    }

    if env.revisions[idx].lifecycle != final_state {
        let expected_starts = accepted_chain.iter().map(|(from, _)| *from).collect();
        return Err(RevisionLifecycleError::Conflict {
            revision_id,
            actual: env.revisions[idx].lifecycle,
            expected_starts,
        });
    }

    if prune_from_splits {
        // Refuse to archive a revision that still routes live traffic.
        // Blindly pruning would either silently drop the route (100%
        // single-entry split) or produce weights that no longer sum to
        // 10,000 bps (the spec invariant).
        let active_refs: Vec<ActiveSplitRef> = env
            .traffic_splits
            .iter()
            .flat_map(|split| {
                split
                    .entries
                    .iter()
                    .filter(|entry| entry.revision_id == revision_id)
                    .map(|entry| ActiveSplitRef {
                        deployment_id: split.deployment_id,
                        bundle_id: split.bundle_id.clone(),
                        weight_bps: entry.weight_bps,
                    })
            })
            .collect();
        if !active_refs.is_empty() {
            return Err(RevisionLifecycleError::ActiveTrafficReference {
                revision_id,
                splits: active_refs,
            });
        }
    }

    // Health gate fires ONLY when the chain actually advanced — an
    // idempotent retry against an already-final revision skips it (see the
    // doc comment above). On the chain-advanced path the gate sees the
    // post-chain `(env, revision)` view; rejection flips lifecycle to
    // `Failed` (caller persists per the module rule).
    if chain_advanced && let Err(failure) = health_gate(env, &env.revisions[idx]) {
        let prior = env.revisions[idx].lifecycle;
        if !is_valid_transition(prior, RevisionLifecycle::Failed) {
            // Caller passed a chain whose final state can't transition to
            // Failed (e.g. an archive-style chain). Bail — there's no
            // spec-legal way to record "failed gate" from here.
            return Err(RevisionLifecycleError::InvalidTransition {
                from: prior,
                to: RevisionLifecycle::Failed,
            });
        }
        env.revisions[idx].lifecycle = RevisionLifecycle::Failed;
        return Err(RevisionLifecycleError::HealthGateFailed {
            revision_id,
            failed_checks: failure.failed_checks,
            message: failure.message,
        });
    }

    on_final(&mut env.revisions[idx]);

    if prune_from_splits {
        // No live traffic references at this point (guard above). Remove
        // the revision from each matching deployment's tracking list;
        // traffic splits themselves are untouched.
        let deployment_id = env.revisions[idx].deployment_id;
        for bundle in env.bundles.iter_mut() {
            if bundle.deployment_id == deployment_id {
                bundle.current_revisions.retain(|rid| *rid != revision_id);
            }
        }
    }

    Ok(RevisionTransition {
        revision: env.revisions[idx].clone(),
        starting_lifecycle,
    })
}

/// Stage a fresh revision under `payload.deployment_id`: resolve the
/// deployment's `bundle_id`, assign the next per-deployment sequence
/// number, and push a `Staged` revision stamped at `now`.
pub fn stage_revision(
    env: &mut Environment,
    payload: StageRevisionPayload,
    now: DateTime<Utc>,
) -> Result<Revision, RevisionLifecycleError> {
    if env
        .revisions
        .iter()
        .any(|r| r.revision_id == payload.revision_id)
    {
        return Err(RevisionLifecycleError::DuplicateRevision {
            env_id: env.environment_id.clone(),
            revision_id: payload.revision_id,
        });
    }
    let bundle_id = env
        .bundles
        .iter()
        .find(|b| b.deployment_id == payload.deployment_id)
        .map(|b| b.bundle_id.clone())
        .ok_or_else(|| RevisionLifecycleError::DeploymentNotFound {
            env_id: env.environment_id.clone(),
            deployment_id: payload.deployment_id,
        })?;
    let next_sequence = env
        .revisions
        .iter()
        .filter(|r| r.deployment_id == payload.deployment_id)
        .map(|r| r.sequence)
        .max()
        .unwrap_or(0)
        + 1;
    let revision = Revision {
        schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
        revision_id: payload.revision_id,
        env_id: env.environment_id.clone(),
        bundle_id,
        deployment_id: payload.deployment_id,
        sequence: next_sequence,
        created_at: now,
        bundle_digest: payload.bundle_digest,
        pack_list: payload.pack_list,
        pack_list_lock_ref: payload.pack_list_lock_ref,
        pack_config_refs: payload.pack_config_refs,
        config_digest: payload.config_digest,
        signature_sidecar_ref: payload.signature_sidecar_ref,
        lifecycle: RevisionLifecycle::Staged,
        staged_at: Some(now),
        warmed_at: None,
        drain_seconds: payload.drain_seconds,
        abort_metrics: Vec::new(),
    };
    env.revisions.push(revision.clone());
    Ok(revision)
}

/// Drive a revision through `Staged → Warming → Ready` and apply the
/// client-evaluated health-gate outcome from the payload.
///
/// **Lifecycle precondition (PR-3a.6b).** The gate was evaluated outside
/// any lock; `payload.expected_lifecycle` records the lifecycle observed at
/// gate-evaluation time and is re-checked here so a stale gate outcome is
/// never applied. The check is skipped on the idempotent-retry path
/// (revision already `Ready`) — the gate fires only when the chain
/// actually advances, so the precondition is moot there.
///
/// `now` stamps `warmed_at` (also re-stamped on idempotent retry).
pub fn warm_revision(
    env: &mut Environment,
    payload: WarmRevisionPayload,
    now: DateTime<Utc>,
) -> Result<RevisionTransition, RevisionLifecycleError> {
    let WarmRevisionPayload {
        revision_id,
        health_gate,
        expected_lifecycle,
    } = payload;
    walk_revision_chain(
        env,
        revision_id,
        &[
            (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
            (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
        ],
        Some(expected_lifecycle),
        |r| {
            r.warmed_at = Some(now);
        },
        false,
        // FnOnce closure consumes the pre-evaluated outcome — the chain
        // walker only fires the gate when the chain actually advanced.
        |_env, _rev| health_gate,
    )
}

/// Transition a `Ready` revision to `Draining`. Pure lifecycle stamp — the
/// in-flight drain dance (sessions, WebSocket cleanup) is owned by
/// `greentic-start`.
pub fn drain_revision(
    env: &mut Environment,
    revision_id: RevisionId,
) -> Result<RevisionTransition, RevisionLifecycleError> {
    walk_revision_chain(
        env,
        revision_id,
        &[(RevisionLifecycle::Ready, RevisionLifecycle::Draining)],
        None,
        |_| {},
        false,
        |_env, _rev| Ok(()),
    )
}

/// Archive a revision, walking any of `Staged | Warming | Ready | Failed`
/// to `Archived` in one hop and the post-drain `Draining → Inactive →
/// Archived` walk end-to-end. Refuses if the revision still routes live
/// traffic — callers rebalance via `gtc op traffic set` first.
pub fn archive_revision(
    env: &mut Environment,
    revision_id: RevisionId,
) -> Result<RevisionTransition, RevisionLifecycleError> {
    walk_revision_chain(
        env,
        revision_id,
        &[
            (RevisionLifecycle::Staged, RevisionLifecycle::Archived),
            (RevisionLifecycle::Warming, RevisionLifecycle::Archived),
            (RevisionLifecycle::Ready, RevisionLifecycle::Archived),
            (RevisionLifecycle::Failed, RevisionLifecycle::Archived),
            (RevisionLifecycle::Draining, RevisionLifecycle::Inactive),
            (RevisionLifecycle::Inactive, RevisionLifecycle::Archived),
        ],
        None,
        |_| {},
        true,
        |_env, _rev| Ok(()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_deployment::{
        BundleDeployment, BundleDeploymentStatus, RevenueShareEntry, RouteBinding, TenantSelector,
    };
    use crate::ids::{CustomerId, PackId, PartyId};
    use crate::traffic_split::{TrafficSplit, TrafficSplitEntry};
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

    fn env_with_deployment(deployment_id: DeploymentId) -> Environment {
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
        env
    }

    fn stage_payload(deployment_id: DeploymentId) -> StageRevisionPayload {
        StageRevisionPayload {
            revision_id: RevisionId::new(),
            deployment_id,
            bundle_digest: "sha256:00".to_string(),
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

    fn warm_payload(revision_id: RevisionId) -> WarmRevisionPayload {
        WarmRevisionPayload {
            revision_id,
            health_gate: Ok(()),
            expected_lifecycle: RevisionLifecycle::Staged,
        }
    }

    // --- stage ---

    #[test]
    fn stage_assigns_per_deployment_sequence_and_staged_lifecycle() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);

        let first = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.lifecycle, RevisionLifecycle::Staged);
        assert_eq!(first.staged_at, Some(fixed_now()));
        assert_eq!(first.bundle_id, BundleId::new("fast2flow"));

        let second = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        assert_eq!(second.sequence, 2);
        assert_eq!(env.revisions.len(), 2);
    }

    #[test]
    fn stage_rejects_duplicate_revision_id() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);

        let payload = stage_payload(deployment_id);
        let dup = StageRevisionPayload {
            revision_id: payload.revision_id,
            ..stage_payload(deployment_id)
        };
        stage_revision(&mut env, payload, fixed_now()).unwrap();
        let err = stage_revision(&mut env, dup, fixed_now()).unwrap_err();
        assert_eq!(
            err,
            RevisionLifecycleError::DuplicateRevision {
                env_id: env_id(),
                revision_id: env.revisions[0].revision_id,
            }
        );
        assert_eq!(env.revisions.len(), 1);
        assert!(!err.env_mutated());
    }

    #[test]
    fn stage_rejects_unknown_deployment() {
        let mut env = env_with_deployment(DeploymentId::new());
        let other = DeploymentId::new();
        let err = stage_revision(&mut env, stage_payload(other), fixed_now()).unwrap_err();
        assert_eq!(
            err,
            RevisionLifecycleError::DeploymentNotFound {
                env_id: env_id(),
                deployment_id: other,
            }
        );
        assert!(env.revisions.is_empty());
    }

    // --- warm ---

    #[test]
    fn warm_advances_staged_to_ready_and_stamps_warmed_at() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();

        let out = warm_revision(&mut env, warm_payload(rev.revision_id), fixed_now()).unwrap();
        assert_eq!(out.revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(out.revision.warmed_at, Some(fixed_now()));
        assert_eq!(out.starting_lifecycle, RevisionLifecycle::Staged);
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
    }

    #[test]
    fn warm_gate_failure_flips_to_failed_and_marks_env_mutated() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();

        let mut payload = warm_payload(rev.revision_id);
        payload.health_gate = Err(HealthGateFailure {
            failed_checks: vec![HealthCheckId::RouteTable],
            message: "route table invalid".to_string(),
        });
        let err = warm_revision(&mut env, payload, fixed_now()).unwrap_err();
        assert!(err.env_mutated(), "gate failure must demand persistence");
        assert!(matches!(
            err,
            RevisionLifecycleError::HealthGateFailed { ref failed_checks, .. }
                if failed_checks == &vec![HealthCheckId::RouteTable]
        ));
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
        assert_eq!(env.revisions[0].warmed_at, None, "on_final must not run");
    }

    #[test]
    fn warm_stale_expected_lifecycle_conflicts_without_mutation() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        env.revisions[0].lifecycle = RevisionLifecycle::Warming;

        // Caller observed `Staged`; a concurrent mutation advanced to Warming.
        let err = warm_revision(&mut env, warm_payload(rev.revision_id), fixed_now()).unwrap_err();
        assert!(matches!(
            err,
            RevisionLifecycleError::Conflict {
                actual: RevisionLifecycle::Warming,
                ..
            }
        ));
        assert!(!err.env_mutated());
    }

    #[test]
    fn warm_idempotent_retry_skips_precondition_and_gate() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        env.revisions[0].lifecycle = RevisionLifecycle::Ready;

        // Stale snapshot + a failing gate: both must be ignored on retry.
        let mut payload = warm_payload(rev.revision_id);
        payload.health_gate = Err(HealthGateFailure {
            failed_checks: vec![],
            message: "transient".to_string(),
        });
        let later = Utc.with_ymd_and_hms(2026, 6, 12, 13, 0, 0).unwrap();
        let out = warm_revision(&mut env, payload, later).unwrap();
        assert_eq!(out.revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(out.revision.warmed_at, Some(later), "on_final re-stamps");
        assert_eq!(out.starting_lifecycle, RevisionLifecycle::Ready);
    }

    // --- drain / archive ---

    #[test]
    fn drain_requires_ready() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();

        let err = drain_revision(&mut env, rev.revision_id).unwrap_err();
        assert!(matches!(err, RevisionLifecycleError::Conflict { .. }));

        env.revisions[0].lifecycle = RevisionLifecycle::Ready;
        let out = drain_revision(&mut env, rev.revision_id).unwrap();
        assert_eq!(out.revision.lifecycle, RevisionLifecycle::Draining);
        assert_eq!(out.starting_lifecycle, RevisionLifecycle::Ready);
    }

    #[test]
    fn archive_walks_draining_to_archived_and_prunes_tracking_list() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        env.revisions[0].lifecycle = RevisionLifecycle::Draining;
        env.bundles[0].current_revisions.push(rev.revision_id);

        let out = archive_revision(&mut env, rev.revision_id).unwrap();
        assert_eq!(out.revision.lifecycle, RevisionLifecycle::Archived);
        assert_eq!(out.starting_lifecycle, RevisionLifecycle::Draining);
        assert!(env.bundles[0].current_revisions.is_empty());
    }

    #[test]
    fn archive_refuses_live_traffic_reference() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        env.revisions[0].lifecycle = RevisionLifecycle::Ready;
        env.traffic_splits.push(TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id(),
            deployment_id,
            bundle_id: BundleId::new("fast2flow"),
            generation: 0,
            entries: vec![TrafficSplitEntry {
                revision_id: rev.revision_id,
                weight_bps: 10_000,
            }],
            updated_at: fixed_now(),
            updated_by: "tester".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        });

        let err = archive_revision(&mut env, rev.revision_id).unwrap_err();
        let RevisionLifecycleError::ActiveTrafficReference { splits, .. } = err else {
            panic!("expected ActiveTrafficReference, got {err:?}");
        };
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].weight_bps, 10_000);
    }

    #[test]
    fn unknown_revision_is_not_found() {
        let mut env = env_with_deployment(DeploymentId::new());
        let missing = RevisionId::new();
        let err = drain_revision(&mut env, missing).unwrap_err();
        assert_eq!(
            err,
            RevisionLifecycleError::NotFound {
                env_id: env_id(),
                revision_id: missing,
            }
        );
    }

    // --- Wire-format pinning ---

    #[test]
    fn stage_payload_wire_format_is_pinned() {
        let deployment_id = DeploymentId::new();
        let payload = stage_payload(deployment_id);
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value,
            json!({
                "revision_id": payload.revision_id.to_string(),
                "deployment_id": deployment_id.to_string(),
                "bundle_digest": "sha256:00",
                "pack_list": [{
                    "pack_id": "greentic.test.pack",
                    "version": "1.0.0",
                    "digest": "sha256:00",
                }],
                "pack_list_lock_ref": "pack-list.lock",
                "pack_config_refs": [],
                "config_digest": "sha256:00",
                "signature_sidecar_ref": "rev.sig",
                "drain_seconds": 30,
            })
        );
        let back: StageRevisionPayload = serde_json::from_value(value).unwrap();
        assert_eq!(back.revision_id, payload.revision_id);
    }

    #[test]
    fn warm_payload_wire_format_is_pinned() {
        let revision_id = RevisionId::new();
        let ok = warm_payload(revision_id);
        assert_eq!(
            serde_json::to_value(&ok).unwrap(),
            json!({
                "revision_id": revision_id.to_string(),
                "health_gate": {"ok": true},
                "expected_lifecycle": "staged",
            })
        );

        let mut failing = warm_payload(revision_id);
        failing.health_gate = Err(HealthGateFailure {
            failed_checks: vec![HealthCheckId::RouteTable, HealthCheckId::ProviderHealth],
            message: "boom".to_string(),
        });
        let value = serde_json::to_value(&failing).unwrap();
        assert_eq!(
            value["health_gate"],
            json!({
                "ok": false,
                "failure": {
                    "failed_checks": ["route-table", "provider-health"],
                    "message": "boom",
                },
            })
        );
        let back: WarmRevisionPayload = serde_json::from_value(value).unwrap();
        assert_eq!(back.health_gate, failing.health_gate);
    }

    #[test]
    fn warm_payload_rejects_contradictory_health_gate() {
        let err = serde_json::from_value::<WarmRevisionPayload>(json!({
            "revision_id": RevisionId::new().to_string(),
            "health_gate": {"ok": true, "failure": {"failed_checks": [], "message": "x"}},
            "expected_lifecycle": "staged",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("cannot be `ok: true`"), "{err}");

        let err = serde_json::from_value::<WarmRevisionPayload>(json!({
            "revision_id": RevisionId::new().to_string(),
            "health_gate": {"ok": false},
            "expected_lifecycle": "staged",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("must carry a `failure`"), "{err}");
    }

    #[test]
    fn revision_transition_outcome_round_trips() {
        let deployment_id = DeploymentId::new();
        let mut env = env_with_deployment(deployment_id);
        let rev = stage_revision(&mut env, stage_payload(deployment_id), fixed_now()).unwrap();
        let outcome = RevisionTransitionOutcome {
            revision: rev,
            environment: env,
            starting_lifecycle: RevisionLifecycle::Staged,
        };
        let value = serde_json::to_value(&outcome).unwrap();
        assert_eq!(value["starting_lifecycle"], "staged");
        let back: RevisionTransitionOutcome = serde_json::from_value(value).unwrap();
        assert_eq!(back.revision.revision_id, outcome.revision.revision_id);
        assert_eq!(back.starting_lifecycle, RevisionLifecycle::Staged);
    }
}
