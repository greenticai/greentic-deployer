//! Revision-lifecycle storage guard (A5 of `plans/next-gen-deployment.md`).
//!
//! Wraps the pure [`greentic_deploy_spec::is_valid_transition`] predicate
//! from `greentic-deploy-spec` with the storage-side semantics that
//! operator commands and B-phase orchestrators need:
//!
//! - load the env from a [`Locked<'_>`](crate::environment::Locked) transaction,
//! - find the revision by id (typed `NotFound`),
//! - walk an `accepted_chain` of `(from, to)` edges, advancing the revision
//!   through every legal hop until it lands in the final state,
//! - report a typed `InvalidTransition` for any edge the spec rejects, and a
//!   typed `Conflict` for a revision that started outside the chain,
//! - optionally prune the revision from every traffic split and from each
//!   matching `BundleDeployment.current_revisions` (the archive path),
//! - save the env back through the same `Locked<'_>` handle so the per-env
//!   flock spans the whole load → mutate → save critical section.
//!
//! `cli::revisions::{stage, warm, drain, archive}` delegate the inner body
//! of their `transact` closures to [`apply_revision_transition`], and the
//! same helper is the entrypoint future B-phase consumers (gtc start
//! orchestration #221, B9 warm/ready gate, A7 audit emission) call when
//! they need to drive a revision through the matrix.
//!
//! The helper does **not** mint revisions — `stage` constructs the
//! `Revision` struct itself and pushes it onto `Environment.revisions`. The
//! lifecycle guard only owns transitions between *existing* revisions.

use greentic_deploy_spec::engine::RevisionLifecycleError;
use greentic_deploy_spec::{Environment, Revision, RevisionId, RevisionLifecycle};
use thiserror::Error;

use crate::environment::{Locked, StoreError};

// PR-4.2b: the pure types (and the chain-walk core below) moved to
// `greentic_deploy_spec::engine` so the operator-store-server applies the
// same lifecycle semantics as `LocalFsStore`. Re-exported here so every
// existing `environment::lifecycle::…` path keeps working.
pub use greentic_deploy_spec::engine::{ActiveSplitRef, HealthCheckId, HealthGateFailure};

/// Errors produced by [`apply_revision_transition`]. Cleanly maps onto
/// `cli::OpError` via the `From` impl in `cli/mod.rs`. The storage-free
/// variants mirror [`RevisionLifecycleError`] 1:1 (see the `From` impl
/// below); [`LifecycleError::Store`] is the local-storage addition.
#[derive(Debug, Error)]
pub enum LifecycleError {
    /// The targeted revision was not present in the loaded environment.
    #[error("revision `{revision_id}` not found in env `{env_id}`")]
    NotFound {
        env_id: greentic_deploy_spec::EnvId,
        revision_id: RevisionId,
    },
    /// The spec matrix rejected an edge inside the requested chain. This is
    /// a programming error in the caller, not a runtime conflict — the
    /// helper should never see this in production because every chain
    /// passed in from `cli::revisions` is hand-curated. Surfaced as a
    /// distinct variant so call sites can choose to panic in debug.
    #[error("spec rejects transition `{from:?} → {to:?}`")]
    InvalidTransition {
        from: RevisionLifecycle,
        to: RevisionLifecycle,
    },
    /// The revision was loaded in a state that does not start any edge in
    /// the accepted chain. `actual` carries the lifecycle the helper found;
    /// `expected_starts` lists the `from` states of each accepted edge so
    /// callers can render a useful error.
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
    /// Blindly pruning the entry would either silently drop the route
    /// (100%-single-entry split) or produce a split whose weights no
    /// longer sum to 10,000 bps (the spec invariant), so the helper
    /// refuses. Callers must rebalance traffic via `gtc op traffic set`
    /// before retrying. `splits` carries the offending references for
    /// rendering an actionable error.
    #[error(
        "revision `{revision_id}` is still referenced by {} live traffic split(s); rebalance via `gtc op traffic set` before archiving", splits.len()
    )]
    ActiveTrafficReference {
        revision_id: RevisionId,
        splits: Vec<ActiveSplitRef>,
    },
    /// The warm/ready health gate rejected the revision after the chain
    /// reached its final state. The helper has flipped the revision's
    /// lifecycle to `Failed` and persisted the env before surfacing this
    /// error, so the on-disk state reflects the failed warm — callers
    /// then choose to retry (`Failed → Staged`) or retire
    /// (`Failed → Archived`) via the operator CLI.
    #[error(
        "revision `{revision_id}` failed health gate ({} check(s) failed): {message}",
        failed_checks.len()
    )]
    HealthGateFailed {
        revision_id: RevisionId,
        failed_checks: Vec<HealthCheckId>,
        message: String,
    },
    /// Underlying storage layer failure (load/save through the `Locked<'_>`).
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Lift a pure-engine lifecycle failure onto the local storage-aware error.
/// Variants map 1:1; the engine's stage-verb `DeploymentNotFound` (which has
/// no lifecycle twin here) surfaces through the storage variant the CLI
/// already maps to a dependent-not-found.
impl From<RevisionLifecycleError> for LifecycleError {
    fn from(err: RevisionLifecycleError) -> Self {
        match err {
            RevisionLifecycleError::NotFound {
                env_id,
                revision_id,
            } => Self::NotFound {
                env_id,
                revision_id,
            },
            RevisionLifecycleError::InvalidTransition { from, to } => {
                Self::InvalidTransition { from, to }
            }
            RevisionLifecycleError::Conflict {
                revision_id,
                actual,
                expected_starts,
            } => Self::Conflict {
                revision_id,
                actual,
                expected_starts,
            },
            RevisionLifecycleError::EmptyChain => Self::EmptyChain,
            RevisionLifecycleError::ActiveTrafficReference {
                revision_id,
                splits,
            } => Self::ActiveTrafficReference {
                revision_id,
                splits,
            },
            RevisionLifecycleError::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            } => Self::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            },
            err @ RevisionLifecycleError::DuplicateRevision { .. } => {
                Self::Store(StoreError::Conflict(err.to_string()))
            }
            err @ RevisionLifecycleError::DeploymentNotFound { .. } => {
                Self::Store(StoreError::DependentNotFound(err.to_string()))
            }
        }
    }
}

/// Apply a revision lifecycle transition under an already-held env lock.
///
/// `accepted_chain` is a list of `(from, to)` edges, applied in order: the
/// helper finds the revision, then for each edge whose `from` matches the
/// revision's current lifecycle, it validates the edge against the spec
/// matrix and advances the revision. The chain terminates when no further
/// edge's `from` matches the (now mutated) revision, and the helper
/// asserts the revision has reached the final edge's `to` state.
///
/// **Idempotent on the final state:** if the revision starts already in
/// the chain's final state, the helper succeeds without raising
/// Conflict. `on_final` still runs (e.g. re-stamps `warmed_at`) and the
/// env is still saved through the lock; callers needing strict
/// once-only semantics must check the loaded state themselves. Conflict
/// surfaces only when the loaded state is neither one of the chain's
/// `from` states nor the chain's final `to` state.
///
/// `on_final` runs once after the last advance, on the freshly-mutated
/// [`Revision`] reference, before the env is saved. Use it to stamp
/// timestamps like `warmed_at`. The helper expects `FnOnce` because each
/// transition is a one-shot.
///
/// `prune_from_splits = true` is the archive-path knob. Before pruning,
/// the helper scans every `TrafficSplit.entries` for references to the
/// archived revision: if any are found, it refuses with
/// [`LifecycleError::ActiveTrafficReference`] (no save, no mutation) so
/// the operator can rebalance traffic through `gtc op traffic set`
/// first. If no live references exist, the revision is removed from each
/// [`BundleDeployment::current_revisions`](greentic_deploy_spec::BundleDeployment::current_revisions)
/// whose `deployment_id` matches the archived revision's (a tracking
/// field, not a routing-impact one). Empty traffic splits are not
/// possible at this point because the guard would have caught them; the
/// invariant is preserved across the save.
///
/// The helper saves the env through `locked.save(...)` before returning,
/// so the entire read-modify-write completes inside the caller's
/// `LocalFsStore::transact` lock scope. On any error, no save is performed
/// and the on-disk env remains untouched.
///
/// Returns the post-transition [`Revision`] (cloned out of the saved env)
/// so callers can render summaries or emit audit events without re-loading.
pub fn apply_revision_transition<F>(
    locked: &Locked<'_>,
    revision_id: RevisionId,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    on_final: F,
    prune_from_splits: bool,
) -> Result<Revision, LifecycleError>
where
    F: FnOnce(&mut Revision),
{
    apply_revision_transition_with_health_gate(
        locked,
        revision_id,
        accepted_chain,
        on_final,
        prune_from_splits,
        |_env, _revision| Ok(()),
    )
}

/// Gate-aware variant of [`apply_revision_transition`] for the B9 warm/ready
/// health gate.
///
/// Behaves exactly like the gate-less helper through chain advance and the
/// `prune_from_splits` active-traffic guard. The gate fires **only when an
/// edge in `accepted_chain` actually advanced the lifecycle** — an idempotent
/// retry against an already-final-state revision skips the gate entirely
/// (the revision is already committed at its target state, often with live
/// traffic routing to it; rerunning a transient gate would demote a healthy
/// live revision to `Failed` while the runtime-config materializer keeps
/// routing traffic to it). `on_final` still runs on the no-op-walk path per
/// the existing idempotent-retry contract — `warmed_at` is re-stamped, but
/// the lifecycle does not change.
///
/// When the chain advanced, `health_gate` runs against the freshly-mutated
/// `(env, revision)` view. The gate sees the **post-chain** revision (e.g.
/// `Ready`) so checks can branch on the would-be-committed state.
///
/// **On gate failure** (`Err(HealthGateFailure)`, chain-advanced path only):
/// - the revision's lifecycle is flipped to
///   [`RevisionLifecycle::Failed`] (the spec matrix allows
///   `Staged|Warming|Ready|Inactive → Failed`),
/// - `on_final` is **not** run (so `warmed_at` is not stamped on a failed warm),
/// - the prune mutation is **not** applied (only relevant when
///   `prune_from_splits = true`, which is archive-only),
/// - the env is saved through `locked.save(...)` so the on-disk state
///   reflects the failed warm,
/// - the helper returns [`LifecycleError::HealthGateFailed`].
///
/// If the spec matrix refuses `current → Failed` (no legal warm-chain final
/// state today triggers this, but defensive for future callers), the helper
/// surfaces [`LifecycleError::InvalidTransition`] without persisting — the
/// caller passed a chain that cannot fail to `Failed`.
///
/// On gate success, the helper runs `on_final`, prunes if armed, saves, and
/// returns the revision — identical to the gate-less path.
pub fn apply_revision_transition_with_health_gate<F, G>(
    locked: &Locked<'_>,
    revision_id: RevisionId,
    accepted_chain: &[(RevisionLifecycle, RevisionLifecycle)],
    on_final: F,
    prune_from_splits: bool,
    health_gate: G,
) -> Result<Revision, LifecycleError>
where
    F: FnOnce(&mut Revision),
    G: FnOnce(&Environment, &Revision) -> Result<(), HealthGateFailure>,
{
    // The pure chain-walk core moved to `greentic_deploy_spec::engine` in
    // PR-4.2b (the operator-store-server drives the same function). This
    // wrapper owns the storage halves: load before, save per the engine's
    // persist rule — `Ok` and `env_mutated` errors (the gate-failed flip to
    // `Failed`) persist; every other error discards the in-memory env.
    let mut env = locked.load()?;
    match greentic_deploy_spec::engine::walk_revision_chain(
        &mut env,
        revision_id,
        accepted_chain,
        None,
        on_final,
        prune_from_splits,
        health_gate,
    ) {
        Ok(transition) => {
            locked.save(&env)?;
            Ok(transition.revision)
        }
        Err(err) if err.env_mutated() => {
            locked.save(&env)?;
            Err(err.into())
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::{EnvironmentStore, LocalFsStore};
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
        Environment, EnvironmentHostConfig, PackId, PackListEntry, PartyId, RevenueShareEntry,
        Revision, RevisionId, RevisionLifecycle, RouteBinding, SchemaVersion, SemVer,
        TenantSelector, TrafficSplit, TrafficSplitEntry,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    const ENV_ID: &str = "local";

    fn env_id() -> EnvId {
        EnvId::try_from(ENV_ID).unwrap()
    }

    fn fixed_now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 19, 12, 0, 0).unwrap()
    }

    fn make_env() -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: env_id(),
            name: ENV_ID.to_string(),
            host_config: EnvironmentHostConfig::new(env_id()),
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            messaging_endpoints: Vec::new(),
            extensions: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn make_revision(deployment_id: DeploymentId, lifecycle: RevisionLifecycle) -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: env_id(),
            bundle_id: BundleId::new("fast2flow"),
            deployment_id,
            sequence: 1,
            created_at: fixed_now(),
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
            lifecycle,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 30,
            abort_metrics: Vec::new(),
        }
    }

    fn make_bundle_deployment() -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id: DeploymentId::new(),
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

    /// Build an env with one bundle + one revision in the given lifecycle.
    /// Returns `(store, env_id, revision_id)`.
    fn seed_one_revision(lifecycle: RevisionLifecycle) -> (LocalFsStore, EnvId, RevisionId) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path().to_path_buf());
        let mut env = make_env();
        let bundle = make_bundle_deployment();
        let did = bundle.deployment_id;
        let revision = make_revision(did, lifecycle);
        let rid = revision.revision_id;
        env.bundles.push(bundle);
        env.bundles[0].current_revisions.push(rid);
        env.revisions.push(revision);
        store.save(&env).unwrap();
        // Leak the tempdir into the returned store so the dir survives test scope.
        // (LocalFsStore holds its root by value; the tempdir guard is dropped at
        // function return, but our root is already inside the tempdir's path.
        // To survive, we extract the path and keep the dir alive via std::mem::forget.)
        std::mem::forget(dir);
        (store, env_id(), rid)
    }

    #[test]
    fn applies_two_hop_chain_to_final_state() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |_| {},
                    false,
                )
            })
            .unwrap();
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);

        // Persisted on disk.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
    }

    #[test]
    fn on_final_runs_once_on_post_advance_revision() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |r| {
                        r.warmed_at = Some(fixed_now());
                    },
                    false,
                )
            })
            .unwrap();
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(revision.warmed_at, Some(fixed_now()));
    }

    #[test]
    fn missing_revision_surfaces_not_found_without_touching_env() {
        let (store, env_id, _rid) = seed_one_revision(RevisionLifecycle::Staged);
        let ghost = RevisionId::new();
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    ghost,
                    &[(RevisionLifecycle::Staged, RevisionLifecycle::Warming)],
                    |_| {},
                    false,
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::NotFound {
                revision_id,
                env_id: e,
            } => {
                assert_eq!(revision_id, ghost);
                assert_eq!(e, env_id);
            }
            other => panic!("expected NotFound, got `{other:?}`"),
        }

        // Original revision still in `Staged` on disk.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Staged);
    }

    #[test]
    fn revision_outside_chain_surfaces_conflict() {
        // Seed in `Draining`, request the warm chain `Staged → Warming → Ready`.
        // `Draining` matches neither edge's `from` and isn't the chain's final
        // state, so the helper must surface a Conflict without mutating state.
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Draining);
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |_| {},
                    false,
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::Conflict {
                revision_id,
                actual,
                expected_starts,
            } => {
                assert_eq!(revision_id, rid);
                assert_eq!(actual, RevisionLifecycle::Draining);
                assert_eq!(
                    expected_starts,
                    vec![RevisionLifecycle::Staged, RevisionLifecycle::Warming]
                );
            }
            other => panic!("expected Conflict, got `{other:?}`"),
        }

        // No save happened — env still has the revision in its original state.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Draining);
    }

    #[test]
    fn already_in_final_state_is_idempotent_success() {
        // Seed in `Ready`, request the warm chain `Staged → Warming → Ready`.
        // No edge applies, but the revision is already at the final state →
        // helper returns Ok (idempotent retry semantics).
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |_| {},
                    false,
                )
            })
            .unwrap();
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);
    }

    #[test]
    fn empty_chain_returns_empty_chain_error() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(locked, rid, &[], |_| {}, false)
            })
            .unwrap_err();
        assert!(matches!(err, LifecycleError::EmptyChain));
    }

    #[test]
    fn archive_succeeds_and_prunes_current_revisions_when_no_live_traffic() {
        // Happy path: revision is not in any traffic split (or no splits
        // exist at all). The archive helper transitions the lifecycle and
        // strips the revision from each matching deployment's tracking
        // list. Traffic splits are untouched.
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);

        let archived = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[(RevisionLifecycle::Ready, RevisionLifecycle::Archived)],
                    |_| {},
                    true,
                )
            })
            .unwrap();
        assert_eq!(archived.lifecycle, RevisionLifecycle::Archived);

        let env = store.load(&env_id).unwrap();
        assert!(env.bundles[0].current_revisions.is_empty());
        assert!(env.traffic_splits.is_empty());
    }

    #[test]
    fn archive_refuses_when_revision_owns_100_percent_of_a_split() {
        // The most acute outage path: a single-entry 100%-bps split is the
        // deployment's only live route. Silent prune would either drop the
        // route entirely (operational outage) or — with empty-split
        // cleanup — leave the deployment unreachable. Guard refuses.
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let mut env = store.load(&env_id).unwrap();
        let did = env.bundles[0].deployment_id;
        env.traffic_splits.push(TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id.clone(),
            deployment_id: did,
            bundle_id: BundleId::new("fast2flow"),
            generation: 0,
            entries: vec![TrafficSplitEntry {
                revision_id: rid,
                weight_bps: 10_000,
            }],
            updated_at: fixed_now(),
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        });
        env.bundles[0].current_revisions.push(rid);
        store.save(&env).unwrap();

        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[(RevisionLifecycle::Ready, RevisionLifecycle::Archived)],
                    |_| {},
                    true,
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::ActiveTrafficReference {
                revision_id,
                splits,
            } => {
                assert_eq!(revision_id, rid);
                assert_eq!(splits.len(), 1);
                assert_eq!(splits[0].deployment_id, did);
                assert_eq!(splits[0].weight_bps, 10_000);
            }
            other => panic!("expected ActiveTrafficReference, got `{other:?}`"),
        }

        // Nothing persisted: lifecycle still Ready, split still owns the route,
        // current_revisions still references the revision.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
        assert_eq!(env.traffic_splits.len(), 1);
        assert_eq!(env.traffic_splits[0].entries.len(), 1);
        assert!(env.bundles[0].current_revisions.contains(&rid));
    }

    #[test]
    fn archive_refuses_when_revision_owns_partial_traffic_in_a_split() {
        // Multi-entry canary split: archiving the canary revision would
        // leave the other entries summing to <10_000 bps (a spec invariant
        // violation that would surface as a save-time SpecError). Guard
        // refuses before any mutation.
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let mut env = store.load(&env_id).unwrap();
        let did = env.bundles[0].deployment_id;

        // Add a second revision (the "main" line) and a 30/70 canary split.
        let main_revision = make_revision(did, RevisionLifecycle::Ready);
        let main_rid = main_revision.revision_id;
        env.revisions.push(main_revision);
        env.bundles[0].current_revisions.push(rid);
        env.bundles[0].current_revisions.push(main_rid);
        env.traffic_splits.push(TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id.clone(),
            deployment_id: did,
            bundle_id: BundleId::new("fast2flow"),
            generation: 0,
            entries: vec![
                TrafficSplitEntry {
                    revision_id: rid,
                    weight_bps: 3_000,
                },
                TrafficSplitEntry {
                    revision_id: main_rid,
                    weight_bps: 7_000,
                },
            ],
            updated_at: fixed_now(),
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        });
        store.save(&env).unwrap();

        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[(RevisionLifecycle::Ready, RevisionLifecycle::Archived)],
                    |_| {},
                    true,
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::ActiveTrafficReference {
                revision_id,
                splits,
            } => {
                assert_eq!(revision_id, rid);
                assert_eq!(splits.len(), 1);
                assert_eq!(splits[0].weight_bps, 3_000);
            }
            other => panic!("expected ActiveTrafficReference, got `{other:?}`"),
        }

        // Split is intact, weights still sum to 10_000.
        let env = store.load(&env_id).unwrap();
        let sum: u32 = env.traffic_splits[0]
            .entries
            .iter()
            .map(|e| e.weight_bps)
            .sum();
        assert_eq!(sum, 10_000);
    }

    #[test]
    fn drain_then_archive_walk_retires_a_live_revision_to_terminal() {
        // The full operator workflow: a Ready revision is drained, runtime
        // moves Draining → Inactive (simulated here via a direct save),
        // operator then archives. The widened archive chain accepts
        // Draining → Inactive → Archived so the drained revision completes
        // to the terminal state without manual state edits.
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Draining);
        // Simulate the runtime completing the drain.
        let mut env = store.load(&env_id).unwrap();
        env.revisions[0].lifecycle = RevisionLifecycle::Inactive;
        store.save(&env).unwrap();

        let archived = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
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
            })
            .unwrap();
        assert_eq!(archived.lifecycle, RevisionLifecycle::Archived);
    }

    #[test]
    fn matrix_walks_every_legal_outbound_edge() {
        // Drive a revision through every legal `from → to` and assert no
        // false rejections. We seed a fresh env per case because some
        // transitions are terminal (Archived) and would block subsequent
        // iterations.
        use RevisionLifecycle::*;
        for (from, to) in &[
            (Inactive, Staged),
            (Inactive, Failed),
            (Inactive, Archived),
            (Staged, Warming),
            (Staged, Failed),
            (Staged, Archived),
            (Warming, Ready),
            (Warming, Failed),
            (Warming, Archived),
            (Ready, Draining),
            (Ready, Failed),
            (Ready, Archived),
            (Draining, Inactive),
            (Failed, Staged),
            (Failed, Archived),
        ] {
            let (store, env_id, rid) = seed_one_revision(*from);
            let result = store.transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(locked, rid, &[(*from, *to)], |_| {}, false)
            });
            assert!(
                result.is_ok(),
                "matrix edge `{from:?} → {to:?}` was rejected: {:?}",
                result.err()
            );
            assert_eq!(result.unwrap().lifecycle, *to);
        }
    }

    // --- B9 health-gate tests ---------------------------------------------

    /// The warm chain through a passing gate: revision lands `Ready`,
    /// `on_final` runs (stamps `warmed_at`), env saved.
    #[test]
    fn health_gate_pass_advances_chain_and_runs_on_final() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |r| r.warmed_at = Some(fixed_now()),
                    false,
                    |_env, rev| {
                        // Gate sees the post-chain lifecycle (Ready).
                        assert_eq!(rev.lifecycle, RevisionLifecycle::Ready);
                        Ok(())
                    },
                )
            })
            .unwrap();
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(revision.warmed_at, Some(fixed_now()));

        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
        assert_eq!(env.revisions[0].warmed_at, Some(fixed_now()));
    }

    /// On gate failure, lifecycle flips to `Failed` and is persisted;
    /// `on_final` does NOT run (no `warmed_at` stamp on failure).
    #[test]
    fn health_gate_failure_persists_failed_and_skips_on_final() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let on_final_ran = std::cell::Cell::new(false);
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |r| {
                        on_final_ran.set(true);
                        r.warmed_at = Some(fixed_now());
                    },
                    false,
                    |_env, _rev| {
                        Err(HealthGateFailure {
                            failed_checks: vec![
                                HealthCheckId::RuntimeConfig,
                                HealthCheckId::SignatureStatus,
                            ],
                            message: "synthetic test failure".to_string(),
                        })
                    },
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            } => {
                assert_eq!(revision_id, rid);
                assert_eq!(
                    failed_checks,
                    vec![HealthCheckId::RuntimeConfig, HealthCheckId::SignatureStatus]
                );
                assert!(message.contains("synthetic"));
            }
            other => panic!("expected HealthGateFailed, got `{other:?}`"),
        }
        assert!(
            !on_final_ran.get(),
            "on_final must not run on health-gate failure"
        );

        // On disk: revision is Failed and warmed_at is NOT stamped.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
        assert_eq!(env.revisions[0].warmed_at, None);
    }

    /// Idempotent retry against an already-final revision must NOT invoke
    /// the gate and must NOT demote lifecycle on a transient failure —
    /// `runtime-config.json` is materialized from `traffic_splits`, so
    /// rerunning a flaky gate on a live Ready revision would persist
    /// `Failed` while the router keeps serving traffic to it. The retry
    /// stays a successful no-op; `on_final` re-stamps `warmed_at` per the
    /// existing idempotent contract.
    #[test]
    fn idempotent_retry_skips_gate_and_preserves_ready() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let gate_invoked = std::cell::Cell::new(false);
        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |r| r.warmed_at = Some(fixed_now()),
                    false,
                    |_env, _rev| {
                        gate_invoked.set(true);
                        Err(HealthGateFailure {
                            failed_checks: vec![HealthCheckId::ProviderHealth],
                            message: "would have demoted a live revision".to_string(),
                        })
                    },
                )
            })
            .unwrap();
        assert!(
            !gate_invoked.get(),
            "gate must not run on idempotent retry against an already-final revision"
        );
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(revision.warmed_at, Some(fixed_now()));

        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
    }

    /// The live-traffic protection case Codex flagged: a Ready revision is
    /// actively serving 100% of a deployment's traffic; a retry warm with
    /// a (transiently) failing gate must NOT demote it to `Failed` because
    /// the traffic split still routes to it. After the retry: lifecycle is
    /// still Ready, the split is intact, the route table stays serviceable.
    #[test]
    fn gate_skipped_on_retry_preserves_live_routed_revision() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let mut env = store.load(&env_id).unwrap();
        let did = env.bundles[0].deployment_id;
        env.traffic_splits.push(TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id.clone(),
            deployment_id: did,
            bundle_id: BundleId::new("fast2flow"),
            generation: 0,
            entries: vec![TrafficSplitEntry {
                revision_id: rid,
                weight_bps: 10_000,
            }],
            updated_at: fixed_now(),
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        });
        store.save(&env).unwrap();

        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |_| {},
                    false,
                    |_env, _rev| {
                        Err(HealthGateFailure {
                            failed_checks: vec![HealthCheckId::ProviderHealth],
                            message: "transient — must not demote".to_string(),
                        })
                    },
                )
            })
            .unwrap();
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);

        // Live traffic split untouched, lifecycle still Ready on disk.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
        assert_eq!(env.traffic_splits.len(), 1);
        assert_eq!(env.traffic_splits[0].entries.len(), 1);
        assert_eq!(env.traffic_splits[0].entries[0].revision_id, rid);
        assert_eq!(env.traffic_splits[0].entries[0].weight_bps, 10_000);
    }

    /// Gate-aware path with the gate-less default (Noop closure) is the
    /// public surface the existing `apply_revision_transition` wraps.
    /// Sanity-check that wrapper preserves the original behavior verbatim.
    #[test]
    fn apply_revision_transition_remains_a_noop_gate_wrapper() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let revision = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |r| r.warmed_at = Some(fixed_now()),
                    false,
                )
            })
            .unwrap();
        assert_eq!(revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(revision.warmed_at, Some(fixed_now()));
    }

    /// Defensive: a chain whose final state cannot transition to `Failed`
    /// (`Draining → Failed` is not in the spec matrix) surfaces an
    /// `InvalidTransition` rather than silently corrupting the lifecycle.
    /// The env must remain untouched on disk because we never invoke
    /// `locked.save` on this branch.
    #[test]
    fn gate_failure_with_no_legal_failed_transition_surfaces_invalid_transition() {
        // Seed Ready, drive the legal `Ready → Draining` hop, then have the
        // gate reject. `Draining → Failed` is not in the spec matrix, so
        // the helper must bail with InvalidTransition without persisting.
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[(RevisionLifecycle::Ready, RevisionLifecycle::Draining)],
                    |_| {},
                    false,
                    |_env, _rev| {
                        Err(HealthGateFailure {
                            failed_checks: vec![HealthCheckId::RouteTable],
                            message: "unreachable in practice for drain".to_string(),
                        })
                    },
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::InvalidTransition { from, to } => {
                assert_eq!(from, RevisionLifecycle::Draining);
                assert_eq!(to, RevisionLifecycle::Failed);
            }
            other => panic!("expected InvalidTransition, got `{other:?}`"),
        }

        // No save happened — revision still in `Ready`.
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Ready);
    }

    /// The gate runs AFTER the `prune_from_splits` active-refs guard, so a
    /// would-be archive that's blocked by live traffic refuses with the
    /// active-traffic error and never invokes the gate — guarding against
    /// running an arbitrary (possibly expensive) gate against a state the
    /// helper won't transition to.
    #[test]
    fn gate_is_not_invoked_when_prune_guard_refuses() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        let mut env = store.load(&env_id).unwrap();
        let did = env.bundles[0].deployment_id;
        env.traffic_splits.push(TrafficSplit {
            schema: SchemaVersion::new(SchemaVersion::TRAFFIC_SPLIT_V1),
            env_id: env_id.clone(),
            deployment_id: did,
            bundle_id: BundleId::new("fast2flow"),
            generation: 0,
            entries: vec![TrafficSplitEntry {
                revision_id: rid,
                weight_bps: 10_000,
            }],
            updated_at: fixed_now(),
            updated_by: "test".to_string(),
            idempotency_key: "k1".to_string(),
            authorization_ref: PathBuf::from("auth.json"),
            previous_split_ref: None,
        });
        store.save(&env).unwrap();

        let gate_invoked = std::cell::Cell::new(false);
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[(RevisionLifecycle::Ready, RevisionLifecycle::Archived)],
                    |_| {},
                    true,
                    |_env, _rev| {
                        gate_invoked.set(true);
                        Ok(())
                    },
                )
            })
            .unwrap_err();
        assert!(matches!(err, LifecycleError::ActiveTrafficReference { .. }));
        assert!(
            !gate_invoked.get(),
            "gate must not run when prune guard refuses"
        );
    }

    /// An empty `failed_checks` list is allowed (e.g. a gate that aborted
    /// before any check completed) — `message` carries the detail. The
    /// helper still flips to Failed and persists.
    #[test]
    fn gate_failure_with_empty_failed_checks_is_still_persisted() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Staged);
        let err = store
            .transact(&env_id, |locked| -> Result<Revision, LifecycleError> {
                apply_revision_transition_with_health_gate(
                    locked,
                    rid,
                    &[
                        (RevisionLifecycle::Staged, RevisionLifecycle::Warming),
                        (RevisionLifecycle::Warming, RevisionLifecycle::Ready),
                    ],
                    |_| {},
                    false,
                    |_env, _rev| {
                        Err(HealthGateFailure {
                            failed_checks: Vec::new(),
                            message: "gate aborted before any check completed".to_string(),
                        })
                    },
                )
            })
            .unwrap_err();
        match err {
            LifecycleError::HealthGateFailed {
                failed_checks,
                message,
                ..
            } => {
                assert!(failed_checks.is_empty());
                assert!(message.contains("aborted"));
            }
            other => panic!("expected HealthGateFailed, got `{other:?}`"),
        }
        let env = store.load(&env_id).unwrap();
        assert_eq!(env.revisions[0].lifecycle, RevisionLifecycle::Failed);
    }
}
