//! `greentic.revision.v1` (`§5.2`).
//!
//! Revisions are per [`BundleDeployment`](crate::BundleDeployment); each
//! customer-scoped deployment in an Env has its own revision sequence and its
//! own [`TrafficSplit`](crate::TrafficSplit).

use crate::ids::{BundleId, DeploymentId, PackId, RevisionId};
use crate::version::{SchemaVersion, SemVer};
use chrono::{DateTime, Utc};
use greentic_types::EnvId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Lifecycle state for a revision (`§5.2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RevisionLifecycle {
    Inactive,
    Staged,
    Warming,
    Ready,
    Draining,
    Failed,
    Archived,
}

/// Pure spec-level predicate for the state-transition matrix at `§5.2`.
///
/// ```text
/// inactive → staged | failed | archived
/// staged   → warming | failed | archived
/// warming  → ready | failed | archived
/// ready    → draining | failed | archived
/// draining → inactive
/// failed   → staged (retry) | archived
/// archived → (terminal)
/// ```
///
/// `Inactive → Archived` closes the drain-complete loop: a revision that
/// reaches `Draining` (via the `ready → draining` operator action) is moved
/// to `Inactive` by the runtime when drain completes (`draining → inactive`);
/// the operator then archives the now-quiesced revision with `inactive → archived`.
/// Without this edge, drained revisions are stranded behind a runtime-only
/// transition because no `inactive → *` archival path exists.
///
/// A5 wraps this with the storage-level guard; consumers that need the predicate
/// without depending on the deployer should use this function directly.
pub fn is_valid_transition(from: RevisionLifecycle, to: RevisionLifecycle) -> bool {
    use RevisionLifecycle::*;
    matches!(
        (from, to),
        (Inactive, Staged)
            | (Inactive, Failed)
            | (Inactive, Archived)
            | (Staged, Warming)
            | (Staged, Failed)
            | (Staged, Archived)
            | (Warming, Ready)
            | (Warming, Failed)
            | (Warming, Archived)
            | (Ready, Draining)
            | (Ready, Failed)
            | (Ready, Archived)
            | (Draining, Inactive)
            | (Failed, Staged)
            | (Failed, Archived)
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackListEntry {
    pub pack_id: PackId,
    pub version: SemVer,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub schema: SchemaVersion,
    pub revision_id: RevisionId,
    pub env_id: EnvId,
    pub bundle_id: BundleId,
    pub deployment_id: DeploymentId,
    /// Monotonic per `deployment_id`.
    pub sequence: u64,
    pub created_at: DateTime<Utc>,
    /// Digest of the `.gtbundle` archive.
    pub bundle_digest: String,
    pub pack_list: Vec<PackListEntry>,
    /// Env-relative path to the pinned pack-list lockfile.
    pub pack_list_lock_ref: PathBuf,
    /// Hash of (setup-answers + pack_list).
    pub config_digest: String,
    /// Env-relative path to the revision DSSE sidecar.
    pub signature_sidecar_ref: PathBuf,
    pub lifecycle: RevisionLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warmed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub drain_seconds: u32,
    #[serde(default)]
    pub abort_metrics: Vec<String>,
}

impl Revision {
    pub fn schema_str() -> &'static str {
        SchemaVersion::REVISION_V1
    }

    /// Schema-discriminator check. Called by [`Environment::validate`] for
    /// every nested revision so a mixed-version document cannot survive a
    /// round-trip through the env compose view.
    pub fn validate(&self) -> Result<(), crate::error::SpecError> {
        if self.schema.as_str() != SchemaVersion::REVISION_V1 {
            return Err(crate::error::SpecError::SchemaMismatch {
                expected: SchemaVersion::REVISION_V1,
                actual: self.schema.as_str().to_string(),
            });
        }
        Ok(())
    }
}
