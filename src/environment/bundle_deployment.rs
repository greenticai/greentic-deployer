//! `BundleDeployment` lifecycle helpers (B10 of `plans/next-gen-deployment.md`).
//!
//! Owns the on-disk, **versioned revenue-policy artifact**. Every mutation of a
//! deployment's `revenue_share` (`gtc op bundles add` writes `v1`; each
//! `gtc op bundles update --revenue-share …` writes `v{N+1}`) materializes a
//! new policy version under:
//!
//! ```text
//! <env_dir>/billing-policies/<bundle_id>/<customer_id>/vN.json      # the document
//! <env_dir>/billing-policies/<bundle_id>/<customer_id>/vN.json.sig  # detached sidecar
//! ```
//!
//! `BundleDeployment.revenue_policy_ref` is set to the **env-relative** path of
//! the latest sidecar.
//!
//! ## Signing posture (B10 vs C2)
//!
//! The `.sig` sidecar carries a SHA-256 canonical-JSON integrity envelope
//! ([`RevenuePolicySignature`]) — tamper-evident, not yet cryptographically
//! authentic. Real DSSE+Ed25519 signing is C2's scope; the envelope is shaped
//! so C2 can attach `signature`/`key_id`/trust-root fields without changing the
//! on-disk layout or the document format.
//!
//! ## Concurrency
//!
//! [`write_revenue_policy_version`] derives the next version by scanning the
//! existing `vN.json` files, so callers MUST hold the env flock (i.e. run
//! inside `EnvironmentStore::transact`).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use greentic_deploy_spec::{
    BundleDeployment, RevenuePolicyDocument, RevenueShareEntry, SchemaVersion, StateIntegrity,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::atomic_write::{AtomicWriteError, atomic_write_json};

/// Env-relative root directory holding all revenue-policy versions.
const BILLING_DIR: &str = "billing-policies";

/// Schema discriminator for the [`RevenuePolicySignature`] sidecar.
pub const REVENUE_POLICY_SIGNATURE_V1: &str = "greentic.revenue-policy-signature.v1";

#[derive(Debug, Error)]
pub enum BundleDeploymentError {
    #[error("revenue-policy spec invalid: {0}")]
    Spec(#[from] greentic_deploy_spec::SpecError),
    #[error("revenue-policy integrity: {0}")]
    Integrity(#[from] greentic_deploy_spec::IntegrityError),
    #[error("revenue-policy write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: AtomicWriteError,
    },
    #[error(
        "unsafe path segment `{0}`: must be a single component, not `.`/`..`, and contain no path separators or NUL"
    )]
    UnsafeSegment(String),
    #[error("revenue-policy io on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Detached sidecar for a revenue-policy version.
///
/// B10: integrity-only (SHA-256 canonical JSON). C2 attaches the cryptographic
/// signature here without changing the layout (see module docs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenuePolicySignature {
    pub schema: String,
    pub integrity: StateIntegrity,
    pub signed_at: DateTime<Utc>,
}

/// What a successful policy-version write produced.
#[derive(Clone, Debug)]
pub struct RevenuePolicyVersion {
    /// Env-relative path to the new sidecar (→ `BundleDeployment.revenue_policy_ref`).
    pub policy_ref: PathBuf,
    pub version: u64,
    pub integrity: StateIntegrity,
}

/// Write the next revenue-policy version for `deployment` under `env_dir`,
/// using `revenue_share` as the version's policy and `created_at` as its
/// timestamp.
///
/// Returns the env-relative sidecar path the caller should store in
/// `BundleDeployment.revenue_policy_ref`. Versions are 1-based and monotonic
/// per `(bundle_id, customer_id)`; the new version chains backward to the prior
/// one via [`RevenuePolicyDocument::previous_version_ref`].
///
/// MUST run under the env flock (see module docs).
pub fn write_revenue_policy_version(
    env_dir: &Path,
    deployment: &BundleDeployment,
    revenue_share: &[RevenueShareEntry],
    created_at: DateTime<Utc>,
) -> Result<RevenuePolicyVersion, BundleDeploymentError> {
    // `BundleId`/`CustomerId` are opaque, unvalidated strings — guard against
    // path traversal before they become directory segments.
    let bundle_seg = safe_segment(deployment.bundle_id.as_str())?;
    let customer_seg = safe_segment(deployment.customer_id.as_str())?;
    let rel_dir = Path::new(BILLING_DIR).join(bundle_seg).join(customer_seg);
    let abs_dir = env_dir.join(&rel_dir);

    let version = next_version_in(&abs_dir)?;
    let previous_version_ref = (version > 1).then(|| rel_dir.join(sidecar_name(version - 1)));

    let doc = RevenuePolicyDocument {
        schema: SchemaVersion::new(SchemaVersion::REVENUE_POLICY_V1),
        version,
        deployment_id: deployment.deployment_id,
        env_id: deployment.env_id.clone(),
        bundle_id: deployment.bundle_id.clone(),
        customer_id: deployment.customer_id.clone(),
        revenue_share: revenue_share.to_vec(),
        created_at,
        previous_version_ref,
    };
    doc.validate()?;

    let integrity = StateIntegrity::sha256_of(&doc)?;
    let sidecar = RevenuePolicySignature {
        schema: REVENUE_POLICY_SIGNATURE_V1.to_string(),
        integrity: integrity.clone(),
        signed_at: created_at,
    };

    std::fs::create_dir_all(&abs_dir).map_err(|source| BundleDeploymentError::Io {
        path: abs_dir.clone(),
        source,
    })?;

    let doc_rel = rel_dir.join(document_name(version));
    let sig_rel = rel_dir.join(sidecar_name(version));
    write_json(&env_dir.join(&doc_rel), &doc)?;
    write_json(&env_dir.join(&sig_rel), &sidecar)?;

    Ok(RevenuePolicyVersion {
        policy_ref: sig_rel,
        version,
        integrity,
    })
}

fn document_name(version: u64) -> String {
    format!("v{version}.json")
}

fn sidecar_name(version: u64) -> String {
    format!("v{version}.json.sig")
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), BundleDeploymentError> {
    atomic_write_json(path, value).map_err(|source| BundleDeploymentError::Write {
        path: path.to_path_buf(),
        source,
    })
}

/// Reject anything that is not a single safe path component.
fn safe_segment(seg: &str) -> Result<&str, BundleDeploymentError> {
    if seg.is_empty()
        || seg == "."
        || seg == ".."
        || seg.contains('/')
        || seg.contains('\\')
        || seg.contains('\0')
    {
        return Err(BundleDeploymentError::UnsafeSegment(seg.to_string()));
    }
    Ok(seg)
}

/// Next 1-based version in `dir`: `max(existing vN.json) + 1`, or `1` when the
/// directory is absent or empty. Only `vN.json` documents are counted (the
/// `.sig` sidecars are ignored), so the two-file write stays in lockstep.
fn next_version_in(dir: &Path) -> Result<u64, BundleDeploymentError> {
    let mut max = 0u64;
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(1),
        Err(source) => {
            return Err(BundleDeploymentError::Io {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| BundleDeploymentError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(num) = name
            .strip_prefix('v')
            .and_then(|rest| rest.strip_suffix(".json"))
            && let Ok(n) = num.parse::<u64>()
        {
            max = max.max(n);
        }
    }
    Ok(max + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{
        BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId, PartyId, RouteBinding,
        TenantSelector,
    };
    use tempfile::tempdir;

    fn deployment(bundle: &str, customer: &str) -> BundleDeployment {
        BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id: DeploymentId::new(),
            env_id: EnvId::try_from("local").unwrap(),
            bundle_id: BundleId::new(bundle),
            customer_id: CustomerId::new(customer),
            status: BundleDeploymentStatus::Active,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: Vec::new(),
                path_prefixes: Vec::new(),
                tenant_selector: TenantSelector {
                    tenant: "default".to_string(),
                    team: "default".to_string(),
                },
            },
            revenue_share: shares(&[("greentic", 10_000)]),
            revenue_policy_ref: PathBuf::from("placeholder"),
            usage: None,
            created_at: Utc::now(),
            authorization_ref: PathBuf::from("auth.json"),
        }
    }

    fn shares(parts: &[(&str, u32)]) -> Vec<RevenueShareEntry> {
        parts
            .iter()
            .map(|(p, bps)| RevenueShareEntry {
                party_id: PartyId::new(*p),
                basis_points: *bps,
            })
            .collect()
    }

    #[test]
    fn first_write_is_v1_with_files_and_no_previous() {
        let dir = tempdir().unwrap();
        let dep = deployment("fast2flow", "local-dev");
        let v =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now()).unwrap();
        assert_eq!(v.version, 1);
        assert_eq!(
            v.policy_ref,
            PathBuf::from("billing-policies/fast2flow/local-dev/v1.json.sig")
        );
        assert!(dir.path().join(&v.policy_ref).is_file());
        assert!(
            dir.path()
                .join("billing-policies/fast2flow/local-dev/v1.json")
                .is_file()
        );
        let doc: RevenuePolicyDocument = serde_json::from_slice(
            &std::fs::read(
                dir.path()
                    .join("billing-policies/fast2flow/local-dev/v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(doc.previous_version_ref.is_none());
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn second_write_increments_and_chains() {
        let dir = tempdir().unwrap();
        let dep = deployment("fast2flow", "cust-acme");
        write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now()).unwrap();
        let v2 = write_revenue_policy_version(
            dir.path(),
            &dep,
            &shares(&[("agency-a", 3_000), ("greentic", 7_000)]),
            Utc::now(),
        )
        .unwrap();
        assert_eq!(v2.version, 2);
        let doc: RevenuePolicyDocument = serde_json::from_slice(
            &std::fs::read(
                dir.path()
                    .join("billing-policies/fast2flow/cust-acme/v2.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            doc.previous_version_ref,
            Some(PathBuf::from(
                "billing-policies/fast2flow/cust-acme/v1.json.sig"
            ))
        );
    }

    #[test]
    fn sidecar_integrity_matches_document() {
        let dir = tempdir().unwrap();
        let dep = deployment("fast2flow", "local-dev");
        let v =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now()).unwrap();
        let doc: RevenuePolicyDocument = serde_json::from_slice(
            &std::fs::read(
                dir.path()
                    .join("billing-policies/fast2flow/local-dev/v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let sig: RevenuePolicySignature =
            serde_json::from_slice(&std::fs::read(dir.path().join(&v.policy_ref)).unwrap())
                .unwrap();
        assert_eq!(sig.schema, REVENUE_POLICY_SIGNATURE_V1);
        assert!(sig.integrity.verify(&doc).unwrap());
    }

    #[test]
    fn unsafe_bundle_segment_rejected() {
        let dir = tempdir().unwrap();
        let dep = deployment("../escape", "local-dev");
        let err = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now())
            .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::UnsafeSegment(_)));
    }

    #[test]
    fn unsafe_customer_segment_rejected() {
        let dir = tempdir().unwrap();
        let dep = deployment("fast2flow", "a/b");
        let err = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now())
            .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::UnsafeSegment(_)));
    }

    #[test]
    fn invalid_revenue_share_rejected_before_write() {
        let dir = tempdir().unwrap();
        let dep = deployment("fast2flow", "local-dev");
        let err = write_revenue_policy_version(
            dir.path(),
            &dep,
            &shares(&[("greentic", 5_000)]),
            Utc::now(),
        )
        .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::Spec(_)));
        // Nothing should have been written.
        assert!(!dir.path().join("billing-policies").exists());
    }
}
