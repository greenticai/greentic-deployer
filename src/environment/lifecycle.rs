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

use greentic_deploy_spec::{Revision, RevisionId, RevisionLifecycle, is_valid_transition};
use thiserror::Error;

use crate::environment::{Locked, StoreError};

/// Errors produced by [`apply_revision_transition`]. Cleanly maps onto
/// `cli::OpError` via the `From` impl in `cli/mod.rs`.
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
    /// Underlying storage layer failure (load/save through the `Locked<'_>`).
    #[error(transparent)]
    Store(#[from] StoreError),
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
/// `prune_from_splits = true` is the archive-path knob: after the lifecycle
/// is in its final state, the revision is removed from every
/// [`TrafficSplit::entries`](greentic_deploy_spec::TrafficSplit::entries),
/// and from each [`BundleDeployment::current_revisions`](greentic_deploy_spec::BundleDeployment::current_revisions)
/// whose `deployment_id` matches the archived revision's. Splits whose
/// entry list becomes empty after the prune are dropped from the env.
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
    if accepted_chain.is_empty() {
        return Err(LifecycleError::EmptyChain);
    }

    let mut env = locked.load()?;
    let idx = env
        .revisions
        .iter()
        .position(|r| r.revision_id == revision_id)
        .ok_or_else(|| LifecycleError::NotFound {
            env_id: locked.env_id().clone(),
            revision_id,
        })?;

    for (from, to) in accepted_chain {
        if env.revisions[idx].lifecycle == *from {
            if !is_valid_transition(*from, *to) {
                return Err(LifecycleError::InvalidTransition {
                    from: *from,
                    to: *to,
                });
            }
            env.revisions[idx].lifecycle = *to;
        }
    }

    let final_state = accepted_chain
        .last()
        .map(|(_, to)| *to)
        .expect("chain non-empty: checked above");

    if env.revisions[idx].lifecycle != final_state {
        let expected_starts = accepted_chain.iter().map(|(from, _)| *from).collect();
        return Err(LifecycleError::Conflict {
            revision_id,
            actual: env.revisions[idx].lifecycle,
            expected_starts,
        });
    }

    on_final(&mut env.revisions[idx]);

    if prune_from_splits {
        let deployment_id = env.revisions[idx].deployment_id;
        for split in env.traffic_splits.iter_mut() {
            split
                .entries
                .retain(|entry| entry.revision_id != revision_id);
        }
        for bundle in env.bundles.iter_mut() {
            if bundle.deployment_id == deployment_id {
                bundle.current_revisions.retain(|rid| *rid != revision_id);
            }
        }
        env.traffic_splits.retain(|split| !split.entries.is_empty());
    }

    locked.save(&env)?;
    Ok(env.revisions[idx].clone())
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
            host_config: EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
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
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("greentic.test.pack"),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:00".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
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
    fn archive_prunes_revision_from_splits_and_current_revisions() {
        let (store, env_id, rid) = seed_one_revision(RevisionLifecycle::Ready);
        // Add a traffic split routing 100% to this revision.
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
        // Split lost its only entry and was dropped entirely.
        assert!(env.traffic_splits.is_empty());
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
}
