//! Pure revenue-policy version builder (B10 artifact, Phase D PR-4.2g).
//!
//! The storage-free half of the deployer's `write_revenue_policy_version`:
//! given a deployment, the new share list, the operator key, and the env
//! trust root, [`build_revenue_policy_version`] produces the exact bytes of
//! the `vN.json` document and its `vN.json.sig` DSSE sidecar, plus the
//! env-relative paths they belong at. Both backends drive THIS function —
//! `LocalFsStore` writes the bytes under `<env_dir>/billing-policies/…`,
//! the operator-store-server stores them in its `revenue_policies` table —
//! so document shape, version derivation, signing, and the trust-root
//! refusal cannot drift between local and remote.
//!
//! ## Trust-root contract (revocation durability)
//!
//! The builder NEVER mutates the trust root. It refuses to sign when the
//! operator's `key_id` is not already a trusted entry
//! ([`RevenuePolicyError::OperatorKeyNotTrusted`]), and self-verifies the
//! freshly-signed envelope against that same trust root before returning —
//! a misconfiguration that would yield an unverifiable sidecar fails the
//! build rather than landing in storage. Auto-seeding here would defeat
//! `trust-root remove` as a revocation boundary.
//!
//! ## Version derivation (partial-failure safety)
//!
//! The next version derives from the deployment's **committed**
//! `revenue_policy_ref`, never from a storage scan. Callers persist the
//! environment only after the artifact write succeeds, so a failed attempt
//! leaves the committed ref unchanged and a retry rebuilds the SAME
//! version — overwriting any orphan artifact — instead of advancing past
//! it. Committed state therefore never references an uncommitted or
//! dangling version.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use greentic_deploy_spec::{
    BundleDeployment, RevenuePolicyDocument, RevenueShareEntry, SchemaVersion,
};
use greentic_distributor_client::signing::{
    INTOTO_STATEMENT_TYPE, InTotoStatement, SigningError, Subject, TrustRoot, sign_statement,
    verify_artifact_dsse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::operator_key::OperatorKey;

/// Storage-relative root directory (or key prefix) holding all
/// revenue-policy versions.
pub const BILLING_DIR: &str = "billing-policies";

/// Predicate type discriminator for the revenue-policy DSSE statement.
pub const REVENUE_POLICY_PREDICATE_TYPE_V1: &str = "greentic.revenue-policy-predicate.v1";

/// Why the builder refused to produce a policy version. Display strings are
/// verbatim what the deployer's `BundleDeploymentError` raised before the
/// extraction (PR-4.2g), except [`Self::OperatorKeyNotTrusted`], which is
/// backend-neutral here — the deployer re-wraps it to keep its
/// `trust-root.json`-mentioning message byte-identical.
#[derive(Debug, Error)]
pub enum RevenuePolicyError {
    #[error("revenue-policy spec invalid: {0}")]
    Spec(#[from] greentic_deploy_spec::SpecError),
    #[error(
        "unsafe path segment `{0}`: must be a single component, not `.`/`..`, and contain no path separators or NUL"
    )]
    UnsafeSegment(String),
    #[error("revenue-policy version counter exhausted (committed ref already at the maximum)")]
    VersionOverflow,
    #[error("revenue-policy signing: {0}")]
    Sign(#[from] SigningError),
    #[error("revenue-policy serialize: {0}")]
    Serialize(serde_json::Error),
    /// The operator's `(key_id, public_pem)` is not in the env trust root.
    /// Auto-seeding would defeat revocation, so the builder refuses to sign
    /// until the caller explicitly bootstraps the env trust root.
    #[error("operator key `{key_id}` is not trusted in the env trust root")]
    OperatorKeyNotTrusted { key_id: String },
}

/// Predicate body recorded inside the DSSE Statement. Mirrors the
/// document's identity fields so a reader of the `.sig` envelope alone can
/// see what the signature covers without opening `vN.json`.
///
/// `previous_version_ref` is serialized as a forward-slash-normalized
/// `String` (not a `PathBuf`) so the predicate is portable across
/// operating systems — Windows back-slashes in a JSON path string would
/// not resolve on POSIX verifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenuePolicyPredicate {
    pub schema: String,
    pub deployment_id: greentic_deploy_spec::DeploymentId,
    pub env_id: greentic_deploy_spec::EnvId,
    pub bundle_id: greentic_deploy_spec::BundleId,
    pub customer_id: greentic_deploy_spec::CustomerId,
    pub version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version_ref: Option<String>,
    pub signed_at: DateTime<Utc>,
}

/// What [`build_revenue_policy_version`] produced: the exact artifact bytes
/// plus where they belong, ready for the backend's storage step.
#[derive(Clone, Debug)]
pub struct BuiltRevenuePolicyVersion {
    /// Storage-relative path of the document
    /// (`billing-policies/<bundle>/<customer>/vN.json`).
    pub doc_ref: PathBuf,
    /// Storage-relative path of the DSSE sidecar (`…/vN.json.sig`) — the
    /// value the caller pins on `BundleDeployment.revenue_policy_ref`.
    pub policy_ref: PathBuf,
    /// Exact bytes of `vN.json` (pretty canonical JSON; the DSSE subject
    /// pins their SHA-256).
    pub doc_bytes: Vec<u8>,
    /// Exact bytes of the DSSE envelope sidecar.
    pub envelope_bytes: Vec<u8>,
    /// 1-based version within `(bundle_id, customer_id)`.
    pub version: u64,
    /// Lowercase-hex SHA-256 of `doc_bytes`. Same value the envelope's
    /// `subject.digest.sha256` carries — callers can cross-reference
    /// without re-hashing.
    pub doc_sha256: String,
    /// `keyid` recorded in the DSSE envelope (matches the operator's
    /// canonical key id).
    pub key_id: String,
}

/// Build the next revenue-policy version for `deployment`, using
/// `revenue_share` as the version's policy, `created_at` as its timestamp,
/// `operator_key` for DSSE signing, and `trust_root` as the refusal +
/// self-verify anchor. Pure: no storage, no clock, no key I/O — see the
/// module docs for the contract both backends rely on.
pub fn build_revenue_policy_version(
    deployment: &BundleDeployment,
    revenue_share: &[RevenueShareEntry],
    created_at: DateTime<Utc>,
    operator_key: &OperatorKey,
    trust_root: &TrustRoot,
) -> Result<BuiltRevenuePolicyVersion, RevenuePolicyError> {
    // Refusal runs first so a failed precondition produces NO artifact
    // bytes for the caller to half-persist.
    let trusted = trust_root
        .keys
        .iter()
        .any(|k| k.key_id.eq_ignore_ascii_case(&operator_key.key_id));
    if !trusted {
        return Err(RevenuePolicyError::OperatorKeyNotTrusted {
            key_id: operator_key.key_id.clone(),
        });
    }

    // `BundleId`/`CustomerId` are opaque, unvalidated strings — guard against
    // path traversal before they become path/key segments.
    let bundle_seg = safe_segment(deployment.bundle_id.as_str())?;
    let customer_seg = safe_segment(deployment.customer_id.as_str())?;
    let rel_dir = Path::new(BILLING_DIR).join(bundle_seg).join(customer_seg);

    let version = next_version_from_ref(&deployment.revenue_policy_ref)?;
    // Reconstruct the backward link under THIS deployment's billing dir rather
    // than copying the committed ref verbatim. In the normal flow the two are
    // identical (refs are always canonical); reconstructing additionally
    // refuses to propagate a crafted/cross-env ref out of a tampered env doc.
    let previous_version_ref_path = (version > 1).then(|| rel_dir.join(sidecar_name(version - 1)));

    let doc = RevenuePolicyDocument {
        schema: SchemaVersion::new(SchemaVersion::REVENUE_POLICY_V1),
        version,
        deployment_id: deployment.deployment_id,
        env_id: deployment.env_id.clone(),
        bundle_id: deployment.bundle_id.clone(),
        customer_id: deployment.customer_id.clone(),
        revenue_share: revenue_share.to_vec(),
        created_at,
        previous_version_ref: previous_version_ref_path.clone(),
    };
    doc.validate()?;

    let doc_bytes = serde_json::to_vec_pretty(&doc).map_err(RevenuePolicyError::Serialize)?;
    let doc_sha256 = sha256_hex(&doc_bytes);

    let predicate = RevenuePolicyPredicate {
        schema: REVENUE_POLICY_PREDICATE_TYPE_V1.to_string(),
        deployment_id: deployment.deployment_id,
        env_id: deployment.env_id.clone(),
        bundle_id: deployment.bundle_id.clone(),
        customer_id: deployment.customer_id.clone(),
        version,
        previous_version_ref: previous_version_ref_path
            .as_deref()
            .map(path_to_forward_slash),
        signed_at: created_at,
    };
    let predicate_value =
        serde_json::to_value(&predicate).map_err(RevenuePolicyError::Serialize)?;

    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), doc_sha256.clone());
    let statement = InTotoStatement {
        type_: INTOTO_STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name: document_name(version),
            digest,
        }],
        predicate_type: REVENUE_POLICY_PREDICATE_TYPE_V1.to_string(),
        predicate: predicate_value,
    };

    let envelope = sign_statement(&statement, &operator_key.private_pem, &operator_key.key_id)?;
    let envelope_bytes =
        serde_json::to_vec_pretty(&envelope).map_err(RevenuePolicyError::Serialize)?;

    // Self-verify the signed envelope against the same trust root before
    // handing the bytes to storage — a key/trust mismatch fails the build,
    // not a later reader.
    verify_artifact_dsse(&envelope_bytes, &doc_sha256, trust_root)?;

    Ok(BuiltRevenuePolicyVersion {
        doc_ref: rel_dir.join(document_name(version)),
        policy_ref: rel_dir.join(sidecar_name(version)),
        doc_bytes,
        envelope_bytes,
        version,
        doc_sha256,
        key_id: operator_key.key_id.clone(),
    })
}

/// Lowercase-hex SHA-256 of `bytes` — the digest form pinned in the DSSE
/// subject. Exposed so backends re-derive the same value when they
/// integrity-check stored artifacts.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `vN.json` — the document file/key name for a version.
pub fn document_name(version: u64) -> String {
    format!("v{version}.json")
}

/// `vN.json.sig` — the DSSE sidecar file/key name for a version.
pub fn sidecar_name(version: u64) -> String {
    format!("v{version}.json.sig")
}

/// Reject anything that is not a single safe path component.
fn safe_segment(seg: &str) -> Result<&str, RevenuePolicyError> {
    if seg.is_empty()
        || seg == "."
        || seg == ".."
        || seg.contains('/')
        || seg.contains('\\')
        || seg.contains('\0')
    {
        return Err(RevenuePolicyError::UnsafeSegment(seg.to_string()));
    }
    Ok(seg)
}

/// Derive the next version from the deployment's committed
/// `revenue_policy_ref`.
///
/// A ref of the shape `…/vN.json.sig` (with `N >= 1`) yields `N + 1`; anything
/// else — an empty placeholder on a fresh `add`, or a pre-B10 ref like
/// `revenue.json` — yields `1`, i.e. the first B10 version. A committed ref
/// already at the maximum returns [`RevenuePolicyError::VersionOverflow`]
/// rather than panicking (debug) or wrapping to 0 (release).
fn next_version_from_ref(current_ref: &Path) -> Result<u64, RevenuePolicyError> {
    match parse_sidecar_version(current_ref) {
        Some(n) => n.checked_add(1).ok_or(RevenuePolicyError::VersionOverflow),
        None => Ok(1),
    }
}

/// Parse the version `N` out of a `…/vN.json.sig` sidecar path. Returns `None`
/// for `v0` (not a valid 1-based version) so a corrupted ref is treated as
/// "no prior version" instead of chaining to a schema-invalid v0.
fn parse_sidecar_version(ref_path: &Path) -> Option<u64> {
    let n = ref_path
        .file_name()?
        .to_str()?
        .strip_prefix('v')?
        .strip_suffix(".json.sig")?
        .parse::<u64>()
        .ok()?;
    (n >= 1).then_some(n)
}

/// Convert a `PathBuf` into a `/`-separated string for cross-platform
/// serialization inside DSSE predicates. On POSIX this is a no-op; on
/// Windows it replaces `\\` with `/`.
fn path_to_forward_slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_key::load_or_generate_at;
    use greentic_deploy_spec::EnvId;
    use greentic_deploy_spec::{
        BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, PartyId, RouteBinding,
        TenantSelector,
    };
    use greentic_distributor_client::signing::TrustedKey;
    use std::collections::BTreeMap as Map;
    use tempfile::tempdir;

    fn operator_key(dir: &Path) -> OperatorKey {
        load_or_generate_at(&dir.join("operator-key.pem")).expect("generate key")
    }

    #[test]
    fn parse_sidecar_version_rejects_zero_and_garbage() {
        assert_eq!(parse_sidecar_version(Path::new("a/b/v1.json.sig")), Some(1));
        assert_eq!(
            parse_sidecar_version(Path::new("a/b/v42.json.sig")),
            Some(42)
        );
        // v0 is not a valid 1-based version → treated as "no prior".
        assert_eq!(parse_sidecar_version(Path::new("a/b/v0.json.sig")), None);
        assert_eq!(parse_sidecar_version(Path::new("revenue.json")), None);
        assert_eq!(parse_sidecar_version(Path::new("v1.json")), None);
        assert_eq!(parse_sidecar_version(Path::new("")), None);
    }

    #[test]
    fn version_counter_overflow_is_an_error_not_a_panic() {
        let dir = tempdir().unwrap();
        let key = operator_key(dir.path());
        let root = trust_root_with(&key);
        let mut dep = deployment("acme", "cust-1");
        dep.revenue_policy_ref = PathBuf::from(format!(
            "billing-policies/acme/cust-1/v{}.json.sig",
            u64::MAX
        ));
        let err = build_revenue_policy_version(&dep, &dep.revenue_share, Utc::now(), &key, &root)
            .unwrap_err();
        assert!(matches!(err, RevenuePolicyError::VersionOverflow));
    }

    fn trust_root_with(key: &OperatorKey) -> TrustRoot {
        TrustRoot::new(vec![TrustedKey {
            key_id: key.key_id.clone(),
            public_key_pem: key.public_pem.clone(),
        }])
    }

    fn shares() -> Vec<RevenueShareEntry> {
        vec![RevenueShareEntry {
            party_id: PartyId::new("greentic"),
            basis_points: 10_000,
        }]
    }

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
            revenue_share: shares(),
            revenue_policy_ref: PathBuf::new(),
            usage: None,
            created_at: Utc::now(),
            authorization_ref: PathBuf::from("auth.json"),
            config_overrides: Map::new(),
        }
    }

    #[test]
    fn builds_v1_with_verified_envelope_and_canonical_paths() {
        let dir = tempdir().unwrap();
        let key = operator_key(dir.path());
        let root = trust_root_with(&key);
        let dep = deployment("acme", "cust-1");

        let built = build_revenue_policy_version(&dep, &dep.revenue_share, Utc::now(), &key, &root)
            .expect("trusted key builds");
        assert_eq!(built.version, 1);
        assert_eq!(
            built.policy_ref,
            Path::new("billing-policies/acme/cust-1/v1.json.sig")
        );
        assert_eq!(
            built.doc_ref,
            Path::new("billing-policies/acme/cust-1/v1.json")
        );
        assert_eq!(built.doc_sha256, sha256_hex(&built.doc_bytes));
        assert_eq!(built.key_id, key.key_id);
        // The envelope verifies standalone against the same root.
        verify_artifact_dsse(&built.envelope_bytes, &built.doc_sha256, &root)
            .expect("self-verified envelope re-verifies");
        // And the doc decodes back to a valid v1 document.
        let doc: RevenuePolicyDocument = serde_json::from_slice(&built.doc_bytes).unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.previous_version_ref.is_none());
    }

    #[test]
    fn chains_v2_from_committed_ref() {
        let dir = tempdir().unwrap();
        let key = operator_key(dir.path());
        let root = trust_root_with(&key);
        let mut dep = deployment("acme", "cust-1");
        dep.revenue_policy_ref = PathBuf::from("billing-policies/acme/cust-1/v1.json.sig");

        let built = build_revenue_policy_version(&dep, &dep.revenue_share, Utc::now(), &key, &root)
            .unwrap();
        assert_eq!(built.version, 2);
        let doc: RevenuePolicyDocument = serde_json::from_slice(&built.doc_bytes).unwrap();
        assert_eq!(
            doc.previous_version_ref.as_deref(),
            Some(Path::new("billing-policies/acme/cust-1/v1.json.sig"))
        );
    }

    #[test]
    fn untrusted_key_is_refused_before_any_bytes() {
        let dir = tempdir().unwrap();
        let key = operator_key(dir.path());
        let dep = deployment("acme", "cust-1");
        let err = build_revenue_policy_version(
            &dep,
            &dep.revenue_share,
            Utc::now(),
            &key,
            &TrustRoot::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RevenuePolicyError::OperatorKeyNotTrusted { .. }
        ));
    }

    #[test]
    fn traversal_segments_are_rejected() {
        let dir = tempdir().unwrap();
        let key = operator_key(dir.path());
        let root = trust_root_with(&key);
        let mut dep = deployment("acme", "cust-1");
        dep.bundle_id = BundleId::new("../escape");
        let err = build_revenue_policy_version(&dep, &dep.revenue_share, Utc::now(), &key, &root)
            .unwrap_err();
        assert!(matches!(err, RevenuePolicyError::UnsafeSegment(_)));
    }

    #[test]
    fn crafted_cross_env_ref_is_not_echoed_into_the_chain() {
        let dir = tempdir().unwrap();
        let key = operator_key(dir.path());
        let root = trust_root_with(&key);
        let mut dep = deployment("acme", "cust-1");
        dep.revenue_policy_ref = PathBuf::from("../other-env/billing-policies/x/y/v3.json.sig");

        let built = build_revenue_policy_version(&dep, &dep.revenue_share, Utc::now(), &key, &root)
            .unwrap();
        assert_eq!(built.version, 4, "version still derives from the ref");
        let doc: RevenuePolicyDocument = serde_json::from_slice(&built.doc_bytes).unwrap();
        assert_eq!(
            doc.previous_version_ref.as_deref(),
            Some(Path::new("billing-policies/acme/cust-1/v3.json.sig")),
            "back-link reconstructed under THIS deployment's dir"
        );
    }
}
