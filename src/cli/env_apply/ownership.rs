//! The env-apply ownership ledger (unified release Phase 5, PD1).
//!
//! `op env apply --prune` may only remove what a manifest OWNS (P5-R1), and
//! nothing in `environment.json` says which deployments a manifest created
//! and which an operator added by hand with `op bundles add` / `op deploy`.
//! This sidecar is that record: every successful mutating apply writes the
//! deployments its manifest declared, and prune only ever considers
//! deployments listed here. A deployment applied before the ledger existed
//! is therefore never pruned until an apply has declared it once — the
//! fail-safe direction.
//!
//! Lives at `<env_dir>/env-apply-ownership.json`, written under the env
//! flock. It never changes what apply prints or what `environment.json`
//! holds.

use std::collections::BTreeSet;

use greentic_deploy_spec::{DeploymentId, EnvId, Environment};
use serde::{Deserialize, Serialize};

use crate::environment::{LocalFsStore, StoreError, atomic_write_json};

use super::super::OpError;

pub(super) const LEDGER_FILE: &str = "env-apply-ownership.json";
const LEDGER_SCHEMA_V1: &str = "greentic.env-apply-ownership.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OwnershipLedger {
    pub schema: String,
    #[serde(default)]
    pub deployments: Vec<OwnedDeployment>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct OwnedDeployment {
    pub deployment_id: DeploymentId,
    pub bundle_id: String,
    pub customer_id: String,
}

impl Default for OwnershipLedger {
    fn default() -> Self {
        Self {
            schema: LEDGER_SCHEMA_V1.to_string(),
            deployments: Vec::new(),
        }
    }
}

impl OwnershipLedger {
    pub fn ids(&self) -> BTreeSet<DeploymentId> {
        self.deployments.iter().map(|d| d.deployment_id).collect()
    }
}

/// Read the ledger; an absent file is an empty ledger. A present file that
/// does not parse is an error, never "owns nothing" — reading it as empty
/// would silently disable prune, and reading it as anything else could
/// remove the wrong thing.
pub(super) fn load(store: &LocalFsStore, env_id: &EnvId) -> Result<OwnershipLedger, OpError> {
    let path = store.env_dir(env_id)?.join(LEDGER_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OwnershipLedger::default());
        }
        Err(source) => return Err(OpError::Io { path, source }),
    };
    let ledger: OwnershipLedger =
        serde_json::from_slice(&bytes).map_err(|e| OpError::AnswersParse {
            path: path.clone(),
            message: e.to_string(),
        })?;
    if ledger.schema != LEDGER_SCHEMA_V1 {
        return Err(OpError::Conflict(format!(
            "{}: unsupported ownership ledger schema `{}` (expected `{LEDGER_SCHEMA_V1}`)",
            path.display(),
            ledger.schema
        )));
    }
    Ok(ledger)
}

/// Rewrite the ledger as: previously owned deployments that still exist in
/// `env`, plus every `declared` deployment. A pruned deployment is gone from
/// `env`, so it drops out here. Writes nothing when the result is unchanged.
pub(super) fn record(
    store: &LocalFsStore,
    env_id: &EnvId,
    env: &Environment,
    declared: &BTreeSet<DeploymentId>,
) -> Result<(), OpError> {
    let path = store.env_dir(env_id)?.join(LEDGER_FILE);
    store.transact(env_id, |_locked| {
        let before = load(store, env_id)?;
        let keep = before
            .ids()
            .union(declared)
            .copied()
            .collect::<BTreeSet<_>>();
        let mut deployments: Vec<OwnedDeployment> = env
            .bundles
            .iter()
            .filter(|b| keep.contains(&b.deployment_id))
            .map(|b| OwnedDeployment {
                deployment_id: b.deployment_id,
                bundle_id: b.bundle_id.as_str().to_string(),
                customer_id: b.customer_id.as_str().to_string(),
            })
            .collect();
        deployments.sort();
        let next = OwnershipLedger {
            deployments,
            ..OwnershipLedger::default()
        };
        if next == before {
            return Ok(());
        }
        atomic_write_json(&path, &next).map_err(|e| OpError::Store(StoreError::AtomicWrite(e)))
    })
}
