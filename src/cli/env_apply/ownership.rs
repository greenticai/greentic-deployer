//! The env-apply ownership ledger (unified release Phase 5, PD1).
//!
//! `op env apply --prune` may only remove what a manifest OWNS (P5-R1), and
//! nothing in `environment.json` says which deployments a manifest created
//! and which an operator added by hand with `op bundles add` / `op deploy`.
//! This sidecar is that record, keyed per MANIFEST: every successful mutating
//! apply writes, under its own owner key, the deployments that manifest
//! declared. A prune only ever considers its own manifest's entries, and
//! never one another manifest also owns — so two manifests applied to one env
//! cannot prune each other's bundles.
//!
//! The owner key is a hash of the manifest file's canonical path: move or
//! rename the manifest and it starts a fresh (empty) ownership, the fail-safe
//! direction. A deployment an apply ADOPTS (matched by `(bundle_id,
//! customer_id)`) becomes owned by that manifest from then on. A deployment
//! applied before this ledger existed is never pruned until a manifest has
//! declared it once.
//!
//! Lives at `<env_dir>/env-apply-ownership.json`, written under the env flock
//! and captured by env snapshots. It never changes what apply prints or what
//! `environment.json` holds.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use greentic_deploy_spec::{DeploymentId, EnvId, Environment};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::environment::{LocalFsStore, StoreError, atomic_write_json};

use super::super::OpError;

pub(crate) const LEDGER_FILE: &str = "env-apply-ownership.json";
const LEDGER_SCHEMA_V1: &str = "greentic.env-apply-ownership.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OwnershipLedger {
    pub schema: String,
    /// Owner key → what that manifest owns.
    #[serde(default)]
    pub owners: BTreeMap<String, OwnerEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OwnerEntry {
    /// The manifest path the key was derived from (informational).
    pub manifest: String,
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
            owners: BTreeMap::new(),
        }
    }
}

/// Identity of one manifest: its key and the path it was derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Owner {
    pub key: String,
    pub manifest: String,
}

impl Owner {
    pub fn for_manifest(path: &Path) -> Self {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let shown = canonical.display().to_string();
        let digest = Sha256::digest(shown.as_bytes());
        let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        Self {
            key: format!("manifest:{hex}"),
            manifest: shown,
        }
    }
}

impl OwnershipLedger {
    /// What `owner` may prune: its own entries that still match the env
    /// (bundle and customer unchanged) and that no OTHER owner also claims.
    pub fn prunable_by(&self, owner: &Owner, env: &Environment) -> BTreeSet<DeploymentId> {
        let Some(mine) = self.owners.get(&owner.key) else {
            return BTreeSet::new();
        };
        let claimed_elsewhere: BTreeSet<DeploymentId> = self
            .owners
            .iter()
            .filter(|(k, _)| **k != owner.key)
            .flat_map(|(_, e)| e.deployments.iter().map(|d| d.deployment_id))
            .collect();
        mine.deployments
            .iter()
            .filter(|d| !claimed_elsewhere.contains(&d.deployment_id))
            .filter(|d| {
                let matches = env.bundles.iter().any(|b| {
                    b.deployment_id == d.deployment_id
                        && b.bundle_id.as_str() == d.bundle_id
                        && b.customer_id.as_str() == d.customer_id
                });
                if !matches
                    && env
                        .bundles
                        .iter()
                        .any(|b| b.deployment_id == d.deployment_id)
                {
                    tracing::warn!(
                        deployment_id = %d.deployment_id,
                        "ownership ledger entry no longer matches the env's deployment; skipped"
                    );
                }
                matches
            })
            .map(|d| d.deployment_id)
            .collect()
    }
}

/// Read the ledger; an absent file is an empty ledger. A present file that
/// does not parse is a store error, never "owns nothing" — reading it as
/// empty would silently disable prune.
pub(super) fn load(store: &LocalFsStore, env_id: &EnvId) -> Result<OwnershipLedger, OpError> {
    let path = store.env_dir(env_id)?.join(LEDGER_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OwnershipLedger::default());
        }
        Err(source) => return Err(OpError::Store(StoreError::Io { path, source })),
    };
    let ledger: OwnershipLedger = serde_json::from_slice(&bytes).map_err(|source| {
        OpError::Store(StoreError::Json {
            path: path.clone(),
            source,
        })
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

/// Rewrite `owner`'s entry as: what it owned before that still exists in
/// `env`, plus every `declared` deployment. A pruned deployment is gone from
/// `env`, so it drops out here. Other owners' entries are pruned of
/// deployments that no longer exist and are otherwise untouched. Writes
/// nothing when the result is unchanged.
pub(super) fn record(
    store: &LocalFsStore,
    env_id: &EnvId,
    env: &Environment,
    owner: &Owner,
    declared: &BTreeSet<DeploymentId>,
) -> Result<(), OpError> {
    let path = store.env_dir(env_id)?.join(LEDGER_FILE);
    store.transact(env_id, |_locked| {
        let before = load(store, env_id)?;
        let mut next = before.clone();
        let live: BTreeSet<DeploymentId> = env.bundles.iter().map(|b| b.deployment_id).collect();
        for entry in next.owners.values_mut() {
            entry
                .deployments
                .retain(|d| live.contains(&d.deployment_id));
        }
        let entry = next.owners.entry(owner.key.clone()).or_default();
        entry.manifest = owner.manifest.clone();
        let mut keep: BTreeSet<DeploymentId> =
            entry.deployments.iter().map(|d| d.deployment_id).collect();
        keep.extend(declared.iter().copied());
        entry.deployments = env
            .bundles
            .iter()
            .filter(|b| keep.contains(&b.deployment_id))
            .map(|b| OwnedDeployment {
                deployment_id: b.deployment_id,
                bundle_id: b.bundle_id.as_str().to_string(),
                customer_id: b.customer_id.as_str().to_string(),
            })
            .collect();
        entry.deployments.sort();
        next.owners.retain(|_, e| !e.deployments.is_empty());
        if next == before {
            return Ok(());
        }
        atomic_write_json(&path, &next).map_err(|e| OpError::Store(StoreError::AtomicWrite(e)))
    })
}
