//! Orphan sweep for the K8s env-pack (`op env sweep`).
//!
//! `reconcile` prunes the workers of revisions it can still see in
//! `env.revisions`. A revision compacted out of the store (a removed bundle,
//! a hand-edited env) leaves its worker Deployment + Service running with
//! nothing that will ever reach them again. The sweep finds those by the
//! deployer's OWN labels and removes them:
//!
//! - it lists only objects carrying `app.kubernetes.io/managed-by=greentic`,
//!   `app.kubernetes.io/component=worker` and `greentic.ai/env=<env>` — an
//!   unlabeled object is never listed, so it is never touched;
//! - it re-checks those labels on every listed object (defence in depth
//!   against a cluster that ignores the selector);
//! - an object whose `greentic.ai/revision` names a revision still in the
//!   store is kept, whatever its lifecycle (`reconcile` owns those);
//! - the env id is NOT unique across stores (every designer store is
//!   `local`), so an orphan is claimed only when it also carries THIS store's
//!   `greentic.ai/store` label; one without it is reported `unattributed` and
//!   one with another store's label is skipped — neither is ever deleted;
//! - each delete re-checks every ownership label on the live object;
//! - dry-run is the default; `apply` deletes.
//!
//! Listing needs `list` on `deployments` and `services`. The bootstrap Role
//! grants it (`SWEEP_K8S_OPERATIONS`), but `op credentials requirements` does
//! not probe it, so an env bound before it existed keeps validating. The sweep
//! checks it itself first ([`require_sweep_access`]) and refuses, naming the
//! permission and the re-bootstrap, when the identity lacks it.

use std::collections::BTreeSet;
use std::path::Path;
use std::str::FromStr;

use greentic_deploy_spec::{Environment, RevisionId};
use serde::Serialize;
use serde_json::Value;

use super::K8sDeployerHandler;
use super::credentials::{AccessDecision, K8sValidatorClient, SWEEP_K8S_OPERATIONS};
use super::deployer::{params_from_answers, provider};
use super::manifests::{ENV_LABEL, STORE_LABEL};
use crate::env_packs::deployer::DeployerError;

const MANAGED_BY: (&str, &str) = ("app.kubernetes.io/managed-by", "greentic");
const COMPONENT: (&str, &str) = ("app.kubernetes.io/component", "worker");
const REVISION_LABEL: &str = "greentic.ai/revision";

/// Why `op env sweep` refused before listing anything.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SweepPreflightError {
    /// The identity lacks a permission the sweep needs. A Role bootstrapped
    /// before the sweep existed does not grant `list`.
    #[error(
        "`op env sweep` needs {permissions} in namespace `{namespace}`, which this identity \
         lacks. Re-run `gtc op credentials bootstrap {env_id}` (with `bind: true`, or re-apply \
         the rules pack it renders) to grant them, or run the sweep with an identity that can \
         list deployments and services",
        permissions = .permissions.join(", ")
    )]
    MissingPermission {
        env_id: String,
        namespace: String,
        /// Capability ids, e.g. `k8s.rbac.allow:apps/deployments:list`.
        permissions: Vec<String>,
    },
    /// The access review itself failed; refuse rather than guess.
    #[error("cannot check the sweep's permissions: {0}")]
    ReviewFailed(String),
}

/// Check up front (one `SelfSubjectAccessReview` per operation) that the
/// identity can list the deployer's workers — before anything is listed.
pub async fn require_sweep_access(
    validator: &dyn K8sValidatorClient,
    env_id: &str,
    namespace: &str,
) -> Result<(), SweepPreflightError> {
    let decisions = validator
        .review_access(namespace, SWEEP_K8S_OPERATIONS)
        .await
        .map_err(|e| SweepPreflightError::ReviewFailed(e.to_string()))?;
    if decisions.len() != SWEEP_K8S_OPERATIONS.len() {
        return Err(SweepPreflightError::ReviewFailed(format!(
            "expected {} access decisions, got {}",
            SWEEP_K8S_OPERATIONS.len(),
            decisions.len()
        )));
    }
    let permissions: Vec<String> = SWEEP_K8S_OPERATIONS
        .iter()
        .zip(&decisions)
        .filter(|(op, d)| d.operation != **op || d.decision != AccessDecision::Allowed)
        .map(|(op, _)| op.capability_id())
        .collect();
    if permissions.is_empty() {
        Ok(())
    } else {
        Err(SweepPreflightError::MissingPermission {
            env_id: env_id.to_string(),
            namespace: namespace.to_string(),
            permissions,
        })
    }
}

/// The label selector the sweep lists with.
pub fn worker_selector(env: &Environment) -> String {
    format!(
        "{}={},{}={},{ENV_LABEL}={}",
        MANAGED_BY.0,
        MANAGED_BY.1,
        COMPONENT.0,
        COMPONENT.1,
        env.environment_id.as_str()
    )
}

/// This store's identity for [`STORE_LABEL`]: a short hash of the store's
/// canonical env directory. Stable for a store (the path never moves under a
/// live store); distinct for two stores that share an env id. A store that is
/// moved gets a new label and its existing workers read as another store's —
/// the safe direction: they are skipped, never deleted.
pub fn store_label_for(env_dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    let canonical = std::fs::canonicalize(env_dir).unwrap_or_else(|_| env_dir.to_path_buf());
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("s-{hex}")
}

/// One worker object the sweep classified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweptObject {
    pub kind: String,
    pub name: String,
    pub revision_id: String,
}

/// A listed object the sweep refused to classify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedObject {
    pub kind: String,
    pub name: String,
    pub reason: String,
}

/// What a sweep found and (with `apply`) removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SweepReport {
    pub namespace: String,
    pub label_selector: String,
    /// This store's [`STORE_LABEL`] value — the only one the sweep claims.
    pub store_label: String,
    pub dry_run: bool,
    /// Workers stamped with THIS store's label whose revision is absent from
    /// the store.
    pub orphans: Vec<SweptObject>,
    /// The orphans actually deleted (empty on a dry run).
    pub removed: Vec<SweptObject>,
    /// Workers whose revision the store still records.
    pub kept: Vec<SweptObject>,
    /// Workers with no store label (rendered before store identity existed,
    /// or by a remote store): ownership cannot be proven, so never deleted.
    pub unattributed: Vec<SweptObject>,
    pub skipped: Vec<SkippedObject>,
}

impl K8sDeployerHandler {
    /// Find (and with `apply`, delete) worker Deployments/Services stamped
    /// with this env's AND this store's labels whose revision is absent from
    /// `env.revisions`. Each delete re-checks every ownership label on the
    /// live object (`delete_if_labeled`), so a label changed after the list
    /// leaves the object alone.
    pub async fn sweep(
        &self,
        env: &Environment,
        answers: Option<&Value>,
        apply: bool,
    ) -> Result<SweepReport, DeployerError> {
        let store = self.store_label.clone().ok_or_else(|| {
            DeployerError::Provider(
                "the sweep needs this store's identity (store label) to prove ownership; \
                 none was supplied"
                    .to_string(),
            )
        })?;
        let params = params_from_answers(env, answers)?;
        let selector = worker_selector(env);
        let listed = self
            .cluster
            .list(&params.namespace, &selector)
            .await
            .map_err(provider)?;
        let known: BTreeSet<RevisionId> = env.revisions.iter().map(|r| r.revision_id).collect();
        let env_id = env.environment_id.as_str();

        let mut report = SweepReport {
            namespace: params.namespace.clone(),
            label_selector: selector,
            store_label: store.clone(),
            dry_run: !apply,
            orphans: Vec::new(),
            removed: Vec::new(),
            kept: Vec::new(),
            unattributed: Vec::new(),
            skipped: Vec::new(),
        };
        for item in listed {
            let skip = |reason: String| SkippedObject {
                kind: item.object.kind.clone(),
                name: item.object.name.clone(),
                reason,
            };
            let label = |k: &str| item.labels.get(k).map(String::as_str);
            if label(MANAGED_BY.0) != Some(MANAGED_BY.1)
                || label(COMPONENT.0) != Some(COMPONENT.1)
                || label(ENV_LABEL) != Some(env_id)
            {
                report
                    .skipped
                    .push(skip("does not carry this env's worker labels".into()));
                continue;
            }
            if !matches!(item.object.kind.as_str(), "Deployment" | "Service") {
                report
                    .skipped
                    .push(skip("not a worker Deployment/Service".into()));
                continue;
            }
            let Some(raw_revision) = label(REVISION_LABEL) else {
                report
                    .skipped
                    .push(skip("no `greentic.ai/revision` label".into()));
                continue;
            };
            let Ok(ulid) = ulid::Ulid::from_str(raw_revision) else {
                report.skipped.push(skip(format!(
                    "unparseable `greentic.ai/revision` label `{raw_revision}`"
                )));
                continue;
            };
            let revision_id = RevisionId(ulid);
            let swept = SweptObject {
                kind: item.object.kind.clone(),
                name: item.object.name.clone(),
                revision_id: revision_id.to_string(),
            };
            if known.contains(&revision_id) {
                report.kept.push(swept);
                continue;
            }
            match label(STORE_LABEL) {
                None => {
                    report.unattributed.push(swept);
                    continue;
                }
                Some(other) if other != store => {
                    report.skipped.push(skip(format!(
                        "owned by another store (`{STORE_LABEL}={other}`)"
                    )));
                    continue;
                }
                Some(_) => {}
            }
            if apply {
                let ownership = [
                    MANAGED_BY,
                    COMPONENT,
                    (ENV_LABEL, env_id),
                    (STORE_LABEL, store.as_str()),
                    (REVISION_LABEL, raw_revision),
                ];
                let deleted = self
                    .cluster
                    .delete_if_labeled(&item.object, &ownership)
                    .await
                    .map_err(provider)?;
                if deleted {
                    report.removed.push(swept.clone());
                } else {
                    report.skipped.push(skip(
                        "ownership labels changed or object gone before the delete; left alone"
                            .into(),
                    ));
                    continue;
                }
            }
            report.orphans.push(swept);
        }
        Ok(report)
    }
}

#[cfg(test)]
#[path = "sweep_tests.rs"]
mod tests;
