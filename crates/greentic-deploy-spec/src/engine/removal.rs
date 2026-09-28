//! Explicit removal verb semantics (unified release Phase 5, PD1).
//!
//! Two rulings shape everything here:
//!
//! - **Omission is never deletion.** Nothing in this module runs because a
//!   resource went missing from a manifest. Every transform is reached from
//!   an explicit verb (`op traffic clear`, `op bundles retire`) or from
//!   `op env apply --prune --confirm-prune`, whose [`prune_plan`] only ever
//!   names deployments the store's own apply ledger says it OWNS.
//! - **Retire is a sequence, not a delete.** A deployment leaves the
//!   environment by: marking it retiring and clearing its split
//!   ([`begin_retire`]) → draining its serving revisions → tearing down and
//!   then archiving every revision → removing the deployment ([`super::remove_bundle`]). Each step
//!   is idempotent and the store is the checkpoint, so a retire interrupted
//!   anywhere is finished by running it again.
//!
//! Like every other engine group these are pure `&mut Environment`
//! transforms: no I/O, no clock, no key material. The drain / teardown side
//! effects against a provider live in the deployer CLI behind a hook seam.
//!
//! # Persist rule
//!
//! - `Ok(outcome)` with `outcome.mutated() == true` — persist.
//! - `Ok(outcome)` with `mutated() == false` — idempotent replay; nothing
//!   changed.
//! - any `Err(_)` — the env was not touched.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bundle_deployment::BundleDeploymentStatus;
use crate::environment::Environment;
use crate::ids::{BundleId, DeploymentId, RevisionId};
use crate::revision::RevisionLifecycle;
use crate::traffic_split::TrafficSplit;
use greentic_types::EnvId;

/// Why a removal transform refused. Nothing was mutated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RemovalError {
    #[error("deployment `{deployment_id}` not found in env `{env_id}`")]
    DeploymentNotFound {
        deployment_id: DeploymentId,
        env_id: EnvId,
    },
    /// `op traffic clear` without a survivor takes the deployment offline,
    /// so it is only accepted for a deployment already marked retiring
    /// (status `archived`). Name a survivor, or retire the bundle.
    #[error(
        "deployment `{deployment_id}` is not retiring (status `{status:?}`): clearing its \
         split would take it offline. Pass `--survivor <revision>` to move all traffic to \
         one revision, or run `op bundles retire`"
    )]
    NotRetiring {
        deployment_id: DeploymentId,
        status: BundleDeploymentStatus,
    },
    /// A messaging endpoint still routes to the bundle and no other
    /// deployment of it would survive the retire. Removing it anyway would
    /// leave the endpoint linked to nothing.
    #[error(
        "bundle `{bundle_id}` is still linked from messaging endpoint(s) {endpoints:?}; \
         unlink it (`op messaging endpoint unlink-bundle`) before retiring"
    )]
    LinkedFromEndpoint {
        bundle_id: BundleId,
        endpoints: Vec<String>,
    },
    /// The env's bound deployer cannot tear a revision down, so removing the
    /// store record could leave its workload running with nothing recording
    /// it. Pass `--store-only` to accept that explicitly.
    #[error(
        "deployer `{deployer}` lacks the `{capability}` capability: it cannot tear revisions \
         down, so removing them from the store could orphan a running workload. Pass \
         `--store-only` to remove the store record anyway"
    )]
    MissingCapability {
        deployer: String,
        capability: String,
    },
}

/// Outcome of [`clear_traffic_split`], and the wire body of
/// `op traffic clear` without a survivor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearTrafficOutcome {
    pub deployment_id: DeploymentId,
    /// The split that was removed; `None` when there was none (idempotent
    /// replay).
    pub cleared: Option<TrafficSplit>,
}

impl ClearTrafficOutcome {
    pub fn mutated(&self) -> bool {
        self.cleared.is_some()
    }
}

/// Outcome of [`begin_retire`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginRetireOutcome {
    pub deployment_id: DeploymentId,
    /// The deployment's status moved to `archived` in this call.
    pub marked_retiring: bool,
    /// The split removed in this call, if any.
    pub cleared: Option<TrafficSplit>,
}

impl BeginRetireOutcome {
    pub fn mutated(&self) -> bool {
        self.marked_retiring || self.cleared.is_some()
    }
}

/// What remains to be done to retire one deployment, computed from the
/// env as it is now — so a retire resumed after a partial failure picks up
/// exactly where the first attempt stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireSteps {
    /// `Ready` revisions that still need the store-side drain stamp.
    pub drain_stamp: Vec<RevisionId>,
    /// Revisions that are (or are about to be) `Draining` — the provider
    /// drain hook runs for each. Includes every `drain_stamp` entry.
    pub drain_hook: Vec<RevisionId>,
    /// Revisions not yet `Archived`. Each is archived in the store only AFTER
    /// its provider teardown succeeded, so a failed teardown leaves the
    /// revision live in the store and the next attempt retries it.
    pub archive: Vec<RevisionId>,
    /// Every revision of the deployment: provider teardown is idempotent, so
    /// it also re-runs for revisions a previous attempt already archived.
    pub teardown: Vec<RevisionId>,
}

/// What `op env apply --prune` would remove: whole deployments only.
///
/// Revisions inside a deployment the manifest still declares are never
/// pruned — an unrouted `Ready` revision is also what a warmed canary looks
/// like before `op traffic set`, and tearing it down would be a removal
/// nobody asked for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunePlan {
    /// Owned deployments the manifest no longer declares — retired whole,
    /// through the same clear → drain → archive → remove sequence.
    pub retire: Vec<DeploymentId>,
}

impl PrunePlan {
    pub fn is_empty(&self) -> bool {
        self.retire.is_empty()
    }
}

fn deployment_index(env: &Environment, deployment_id: DeploymentId) -> Result<usize, RemovalError> {
    env.bundles
        .iter()
        .position(|b| b.deployment_id == deployment_id)
        .ok_or_else(|| RemovalError::DeploymentNotFound {
            deployment_id,
            env_id: env.environment_id.clone(),
        })
}

/// Remove the traffic split of a deployment that is already retiring.
/// Idempotent: no split is `Ok` with `cleared: None`. Refuses with
/// [`RemovalError::NotRetiring`] for a deployment whose status is not
/// `archived` — moving traffic to a survivor is `set_traffic_split`'s job.
pub fn clear_traffic_split(
    env: &mut Environment,
    deployment_id: DeploymentId,
) -> Result<ClearTrafficOutcome, RemovalError> {
    let idx = deployment_index(env, deployment_id)?;
    let status = env.bundles[idx].status;
    if status != BundleDeploymentStatus::Archived {
        return Err(RemovalError::NotRetiring {
            deployment_id,
            status,
        });
    }
    Ok(ClearTrafficOutcome {
        deployment_id,
        cleared: take_split(env, deployment_id),
    })
}

fn take_split(env: &mut Environment, deployment_id: DeploymentId) -> Option<TrafficSplit> {
    let pos = env
        .traffic_splits
        .iter()
        .position(|s| s.deployment_id == deployment_id)?;
    Some(env.traffic_splits.remove(pos))
}

/// Refuse a retire that would strand a messaging endpoint: an endpoint that
/// links (or welcomes into) the bundle, when no OTHER live deployment of the
/// same bundle id survives.
pub fn check_retire_links(
    env: &Environment,
    deployment_id: DeploymentId,
) -> Result<(), RemovalError> {
    check_retire_set_links(env, &BTreeSet::from([deployment_id]))
}

/// [`check_retire_links`] for a whole retire set, evaluated before any of it
/// runs. A sibling counts as a survivor only if it is outside the set and not
/// itself retiring (status `archived`), so two deployments of one bundle in
/// the same set cannot vouch for each other.
pub fn check_retire_set_links(
    env: &Environment,
    retiring: &BTreeSet<DeploymentId>,
) -> Result<(), RemovalError> {
    let mut bundles: Vec<BundleId> = Vec::new();
    for d in retiring {
        let idx = deployment_index(env, *d)?;
        let bundle_id = env.bundles[idx].bundle_id.clone();
        if !bundles.contains(&bundle_id) {
            bundles.push(bundle_id);
        }
    }
    for bundle_id in bundles {
        let sibling_survives = env.bundles.iter().any(|b| {
            b.bundle_id == bundle_id
                && !retiring.contains(&b.deployment_id)
                && b.status != BundleDeploymentStatus::Archived
        });
        if sibling_survives {
            continue;
        }
        let endpoints: Vec<String> = env
            .messaging_endpoints
            .iter()
            .filter(|ep| {
                ep.linked_bundles.contains(&bundle_id)
                    || ep
                        .welcome_flow
                        .as_ref()
                        .is_some_and(|wf| wf.bundle_id == bundle_id)
            })
            .map(|ep| ep.display_name.clone())
            .collect();
        if !endpoints.is_empty() {
            return Err(RemovalError::LinkedFromEndpoint {
                bundle_id,
                endpoints,
            });
        }
    }
    Ok(())
}

/// Step one of a retire: refuse if an endpoint would be stranded, mark the
/// deployment retiring (status `archived`) and remove its split. Idempotent.
pub fn begin_retire(
    env: &mut Environment,
    deployment_id: DeploymentId,
) -> Result<BeginRetireOutcome, RemovalError> {
    check_retire_links(env, deployment_id)?;
    let idx = deployment_index(env, deployment_id)?;
    let marked_retiring = env.bundles[idx].status != BundleDeploymentStatus::Archived;
    env.bundles[idx].status = BundleDeploymentStatus::Archived;
    Ok(BeginRetireOutcome {
        deployment_id,
        marked_retiring,
        cleared: take_split(env, deployment_id),
    })
}

/// The remaining retire work for `deployment_id`, in revision order.
pub fn retire_steps(
    env: &Environment,
    deployment_id: DeploymentId,
) -> Result<RetireSteps, RemovalError> {
    deployment_index(env, deployment_id)?;
    let mut steps = RetireSteps::default();
    for r in env
        .revisions
        .iter()
        .filter(|r| r.deployment_id == deployment_id)
    {
        match r.lifecycle {
            RevisionLifecycle::Ready => {
                steps.drain_stamp.push(r.revision_id);
                steps.drain_hook.push(r.revision_id);
            }
            RevisionLifecycle::Draining => steps.drain_hook.push(r.revision_id),
            _ => {}
        }
        if r.lifecycle != RevisionLifecycle::Archived {
            steps.archive.push(r.revision_id);
        }
        steps.teardown.push(r.revision_id);
    }
    Ok(steps)
}

/// Compute what `op env apply --prune` removes. `owned` is what THIS
/// manifest's ownership ledger records; `declared` is what the current
/// manifest resolved to. A deployment `owned` does not name is never touched,
/// whatever the manifest says.
pub fn prune_plan(
    env: &Environment,
    owned: &BTreeSet<DeploymentId>,
    declared: &BTreeSet<DeploymentId>,
) -> PrunePlan {
    PrunePlan {
        retire: env
            .bundles
            .iter()
            .map(|b| b.deployment_id)
            .filter(|d| owned.contains(d) && !declared.contains(d))
            .collect(),
    }
}

#[cfg(test)]
#[path = "removal_tests.rs"]
mod tests;
