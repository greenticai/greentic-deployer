//! Resolving the SoR phase before any cloud call — which units are declared,
//! which the ledger says were deployed, and WHERE — for both lanes that deploy
//! SoR units: the k8s reconcile (phase 3C) and the Cloud Run `op env up`
//! (phase 3E). Moved out of `mod.rs` (500-line cap) when the second lane
//! arrived; the k8s behaviour is unchanged.

use std::collections::BTreeSet;
use std::ffi::OsString;

use greentic_deploy_spec::{EnvId, Environment};

use super::{refuse_dev_secrets_path_override, require_dev_store_backend, resolve_sor_inputs};
use crate::cli::OpError;
use crate::cli::secrets::DEV_SECRETS_PATH_ENV;
use crate::env_packs::k8s::manifests::SecretsBackend;
use crate::env_packs::k8s::sor_reconcile::{SorReconcile, SorRoutePublisher, SorUnitRender};
use crate::environment::LocalFsStore;
use crate::environment::sor_units::{AppliedSorUnit, CloudRunSorPlacement, SorLane, SorUnit};

/// Where THIS run deploys SoR units.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "creds-gcp"), allow(dead_code))]
pub(crate) enum SorLanePlacement {
    K8s {
        namespace: String,
    },
    CloudRun {
        project: String,
        region: String,
        secret_prefix: String,
    },
}

impl SorLanePlacement {
    fn lane(&self) -> SorLane {
        match self {
            Self::K8s { .. } => SorLane::K8s,
            Self::CloudRun { .. } => SorLane::CloudRun,
        }
    }

    /// The ledger entry a unit deployed here is recorded as.
    fn applied(&self, unit: &SorUnit) -> AppliedSorUnit {
        let (namespace, cloud_run) = match self {
            Self::K8s { namespace } => (namespace.clone(), None),
            Self::CloudRun {
                project,
                region,
                secret_prefix,
            } => (
                String::new(),
                Some(CloudRunSorPlacement::for_unit(
                    project,
                    region,
                    secret_prefix,
                    &unit.unit_id,
                )),
            ),
        };
        AppliedSorUnit {
            unit_id: unit.unit_id.clone(),
            sor: unit.sor.clone(),
            namespace,
            cloud_run,
            input_refs: unit.input_refs().into_iter().map(str::to_string).collect(),
        }
    }
}

/// Input rel-paths the ledger records that no declared unit reads any more —
/// a retired unit's inputs, and the old target of a re-pointed `*_ref` —
/// split into `(deletable, foreign)`.
///
/// Only a path under the recording unit's OWN segment
/// (`<tenant>/_/sor-<unit_id>/<name>`) is deletable. Refs are recorded before
/// any reconcile succeeds, so a typo'd ref naming an unrelated key must never
/// cost that key: such a path is returned as foreign, to be reported by path
/// and left in place. (It stays excluded from the seed while on record.)
fn stale_input_refs(units: &[SorUnit], ledger: &[AppliedSorUnit]) -> (Vec<String>, Vec<String>) {
    let declared: BTreeSet<&str> = units.iter().flat_map(SorUnit::input_refs).collect();
    let mut owned = BTreeSet::new();
    let mut foreign = BTreeSet::new();
    for entry in ledger {
        for rel in &entry.input_refs {
            if declared.contains(rel.as_str()) {
                continue;
            }
            if is_owned_by(&entry.unit_id, rel) {
                owned.insert(rel.clone());
            } else {
                foreign.insert(rel.clone());
            }
        }
    }
    // A path some OTHER entry owns is still deletable through that entry.
    foreign.retain(|rel| !owned.contains(rel));
    (owned.into_iter().collect(), foreign.into_iter().collect())
}

/// `<tenant>/_/sor-<unit_id>/<name>` — the canonical place of a unit's inputs.
pub(super) fn is_owned_by(unit_id: &str, rel: &str) -> bool {
    let segments: Vec<&str> = rel.split('/').collect();
    matches!(
        segments.as_slice(),
        [tenant, "_", unit_segment, name]
            if !tenant.is_empty()
                && !name.is_empty()
                && unit_segment.strip_prefix("sor-") == Some(unit_id)
    )
}

/// Everything reconcile needs for the SoR phase, resolved before any cluster
/// call.
pub(crate) struct PreparedSor {
    pub(crate) units: Vec<SorUnitRender>,
    /// Ledger entries no declared unit lives at any more (same id AND
    /// namespace): their objects are pruned.
    pub(crate) retired_units: Vec<AppliedSorUnit>,
    /// SoR keys no declared unit claims any more: their route documents are
    /// deleted.
    pub(crate) retired_sors: Vec<String>,
    /// Input rel-paths no declared unit reads any more, under the recording
    /// unit's own `sor-<unit_id>/` segment: deleted from the store.
    pub(crate) stale_input_refs: Vec<String>,
    /// Stale refs OUTSIDE that segment: never deleted, reported by path.
    pub(crate) skipped_input_refs: Vec<String>,
    /// What the ledger narrows to once the reconcile succeeds.
    desired: Vec<AppliedSorUnit>,
}

impl PreparedSor {
    pub(crate) fn as_reconcile<'a>(
        &'a self,
        publisher: &'a dyn SorRoutePublisher,
    ) -> SorReconcile<'a> {
        SorReconcile {
            units: &self.units,
            retired_units: &self.retired_units,
            retired_sors: &self.retired_sors,
            stale_input_refs: &self.stale_input_refs,
            skipped_input_refs: &self.skipped_input_refs,
            publisher,
        }
    }

    /// Each declared unit's decrypted inputs beside the ledger entry it is
    /// recorded as. Both lists are built from the same `sor-units.json`, in the
    /// same order (`placed_units_pair_each_render_with_its_own_entry`).
    #[cfg_attr(not(feature = "creds-gcp"), allow(dead_code))]
    pub(crate) fn placed_units(&self) -> impl Iterator<Item = (&SorUnitRender, &AppliedSorUnit)> {
        self.units.iter().zip(self.desired.iter())
    }
}

/// Resolve the SoR phase. `None` when nothing is declared and nothing was
/// ever applied, so an env without SoR units reconciles exactly as before —
/// including how it fails: the deployer answers are parsed for the placement
/// only AFTER that early return, so an env with no SoR units never sees an
/// answers error from here.
///
/// Every refusal happens here, before the ledger or the cluster is touched —
/// the backend and `GREENTIC_DEV_SECRETS_PATH` checks come before any input is
/// read, because the input reader honours that override while the shipped
/// seed does not. Then the ledger is WIDENED to every unit this reconcile may
/// create: a reconcile that dies after applying a unit still leaves it on
/// record for the next one to prune.
pub(crate) fn prepare(
    store: &LocalFsStore,
    env: &Environment,
    answers: Option<&serde_json::Value>,
    backend: &SecretsBackend,
) -> Result<Option<PreparedSor>, OpError> {
    let placement = || {
        crate::env_packs::k8s::manifests::K8sParams::from_answers(env, answers)
            .map(|p| SorLanePlacement::K8s {
                namespace: p.namespace,
            })
            .map_err(|e| OpError::InvalidArgument(format!("invalid deployer answers: {e}")))
    };
    prepare_with_override(
        store,
        env,
        &placement,
        backend,
        std::env::var_os(DEV_SECRETS_PATH_ENV),
    )
}

/// [`prepare`] with the placement and the `GREENTIC_DEV_SECRETS_PATH` value
/// passed in, so the refusals are testable without mutating the process
/// environment. No lane-specific checks.
pub(super) fn prepare_with_override(
    store: &LocalFsStore,
    env: &Environment,
    placement: &dyn Fn() -> Result<SorLanePlacement, OpError>,
    backend: &SecretsBackend,
    dev_secrets_path_override: Option<OsString>,
) -> Result<Option<PreparedSor>, OpError> {
    prepare_inner(
        store,
        env,
        placement,
        backend,
        dev_secrets_path_override,
        &|_| Ok(()),
    )
}

/// The resolver both lanes share. `lane_checks` runs over the decrypted
/// renders after every shared refusal and BEFORE the ledger is widened, so a
/// lane-specific refusal writes nothing either.
pub(super) fn prepare_inner(
    store: &LocalFsStore,
    env: &Environment,
    placement: &dyn Fn() -> Result<SorLanePlacement, OpError>,
    backend: &SecretsBackend,
    dev_secrets_path_override: Option<OsString>,
    lane_checks: &dyn Fn(&[SorUnitRender]) -> Result<(), OpError>,
) -> Result<Option<PreparedSor>, OpError> {
    let env_id = &env.environment_id;
    let units = store.load_sor_units(env_id)?;
    let ledger = store.load_sor_ledger(env_id)?;
    if units.is_empty() && ledger.is_empty() {
        return Ok(None);
    }
    let placement = placement()?;
    refuse_foreign_lane(&ledger, placement.lane())?;
    // Only DECLARED units need the dev-store backend: a retire-only run on a
    // Vault env must be able to prune what an earlier dev-store era left.
    if !units.is_empty() {
        require_dev_store_backend(backend)?;
    }
    // Unconditional for any SoR phase — see `refuse_dev_secrets_path_override`.
    refuse_dev_secrets_path_override(dev_secrets_path_override)?;
    let renders = resolve_sor_inputs(store, env, &units)?;
    lane_checks(&renders)?;

    let desired: Vec<AppliedSorUnit> = units.iter().map(|u| placement.applied(u)).collect();
    // Retired = recorded somewhere no declared unit now lives (same id AND
    // place); a unit that only changed its `sor` keeps its objects.
    let retired_units: Vec<AppliedSorUnit> = ledger
        .iter()
        .filter(|a| !desired.iter().any(|d| d.same_place(a)))
        .cloned()
        .collect();
    let retired_sors: Vec<String> = ledger
        .iter()
        .map(|a| a.sor.clone())
        .filter(|sor| !units.iter().any(|u| &u.sor == sor))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (stale_input_refs, skipped_input_refs) = stale_input_refs(&units, &ledger);

    // Widen before any cloud call (see the 3C plan): an entry for the same unit
    // at the same place keeps every input it was ever recorded with until a
    // successful run narrows it.
    let mut intent = ledger;
    for d in &desired {
        match intent.iter_mut().find(|a| a.same_unit(d)) {
            Some(existing) => {
                for rel in &d.input_refs {
                    if !existing.input_refs.contains(rel) {
                        existing.input_refs.push(rel.clone());
                    }
                }
            }
            None => intent.push(d.clone()),
        }
    }
    store.transact(env_id, |locked| locked.save_sor_ledger(&intent))?;

    Ok(Some(PreparedSor {
        units: renders,
        retired_units,
        retired_sors,
        stale_input_refs,
        skipped_input_refs,
        desired,
    }))
}

/// A ledger entry of the OTHER lane can only be retired by the deployer that
/// created it — this one holds neither its credentials nor its API. Refused
/// before anything is written; also refuses a corrupt entry by name.
fn refuse_foreign_lane(ledger: &[AppliedSorUnit], lane: SorLane) -> Result<(), OpError> {
    for entry in ledger {
        let recorded = entry.lane().map_err(OpError::Conflict)?;
        if recorded != lane {
            return Err(OpError::Conflict(format!(
                "SoR unit `{}` was deployed by `{}`, but this environment now deploys with `{}`; \
                 retire it first by deploying `sor_units: []` while `{}` is still bound",
                entry.unit_id,
                recorded.deployer(),
                lane.deployer(),
                recorded.deployer(),
            )));
        }
    }
    Ok(())
}

/// Narrow the ledger to what is now declared. Only after a successful
/// reconcile — a failed one keeps the widened ledger for the next to prune.
pub(crate) fn record_applied(
    store: &LocalFsStore,
    env_id: &EnvId,
    prepared: &PreparedSor,
) -> Result<(), OpError> {
    store
        .transact(env_id, |locked| locked.save_sor_ledger(&prepared.desired))
        .map_err(OpError::from)
}
