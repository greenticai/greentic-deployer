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
//! ## Signing posture (C2)
//!
//! The `.sig` sidecar is a DSSE envelope (`application/vnd.in-toto+json`)
//! whose in-toto v1 Statement pins the canonical-JSON SHA-256 of the
//! corresponding `vN.json` and carries a `greentic.revenue-policy-predicate.v1`
//! predicate. The envelope is signed Ed25519 with the operator's key (see
//! [`crate::operator_key`]) and verifiable via
//! [`greentic_distributor_client::signing::verify_artifact_dsse`] against the
//! env's [`super::trust_root`].
//!
//! ## Trust-root contract (Codex #1 — revocation durability)
//!
//! The writer NEVER mutates the env trust root. It loads
//! `<env_dir>/trust-root.json`, refuses to sign if the operator's `key_id`
//! is not already a trusted entry, and self-verifies the freshly-written
//! envelope against that same trust root before returning.
//!
//! This makes `gtc op trust-root remove` a real revocation boundary:
//! after removal, every subsequent `bundle add/update` aborts with
//! [`BundleDeploymentError::OperatorKeyNotTrusted`] until an authorized
//! caller runs the explicit `gtc op trust-root bootstrap` verb (or
//! rotates the operator's local key entirely). An earlier draft of this
//! writer auto-seeded the operator key on every write — that defeated
//! revocation because the next mutation always re-inserted the removed
//! key.
//!
//! ## Concurrency & partial-failure safety
//!
//! [`write_revenue_policy_version`] derives the next version from the
//! deployment's **committed** `revenue_policy_ref` (`env.json`), not from a
//! filesystem scan. Callers persist `env.json` only after this writer returns,
//! so a failed attempt (sidecar write or env save) leaves the committed ref
//! unchanged; a retry rewrites the *same* version, overwriting any orphan
//! files instead of advancing past them. Committed state therefore never
//! references an uncommitted or dangling version. Callers MUST still run inside
//! `EnvironmentStore::transact` so the file write and the `env.json` update
//! share one env flock.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use greentic_deploy_spec::{
    BundleDeployment, RevenuePolicyDocument, RevenueShareEntry, SchemaVersion, StateIntegrity,
};
use greentic_distributor_client::signing::{
    INTOTO_STATEMENT_TYPE, InTotoStatement, SigningError, Subject, sign_statement,
    verify_artifact_dsse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::atomic_write::AtomicWriteError;
use super::trust_root::{self, TrustRootError};
use crate::operator_key::{OperatorKey, OperatorKeyError};

/// Env-relative root directory holding all revenue-policy versions.
const BILLING_DIR: &str = "billing-policies";

/// Predicate type discriminator for the revenue-policy DSSE statement.
pub const REVENUE_POLICY_PREDICATE_TYPE_V1: &str = "greentic.revenue-policy-predicate.v1";

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
    #[error("revenue-policy version counter exhausted (committed ref already at the maximum)")]
    VersionOverflow,
    #[error("revenue-policy io on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("revenue-policy signing: {0}")]
    Sign(#[from] SigningError),
    #[error("revenue-policy operator key: {0}")]
    OperatorKey(#[from] OperatorKeyError),
    #[error("revenue-policy trust-root: {0}")]
    TrustRoot(#[from] TrustRootError),
    #[error("revenue-policy serialize: {0}")]
    Serialize(serde_json::Error),
    /// The operator's `(key_id, public_pem)` is not in the env trust root.
    /// Auto-seeding would defeat revocation, so the writer refuses to sign
    /// until the caller explicitly bootstraps the env trust root.
    #[error(
        "operator key `{key_id}` is not trusted in env `{env_dir}` (not present in `trust-root.json`); run `gtc op trust-root bootstrap <env-id>` first, or restore the key via `gtc op trust-root add`"
    )]
    OperatorKeyNotTrusted { key_id: String, env_dir: PathBuf },
}

/// Predicate body recorded inside the DSSE Statement. Mirrors the
/// document's identity fields so a reader of the `.sig` envelope alone can
/// see what the signature covers without opening `vN.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenuePolicyPredicate {
    pub schema: String,
    pub deployment_id: greentic_deploy_spec::DeploymentId,
    pub env_id: greentic_deploy_spec::EnvId,
    pub bundle_id: greentic_deploy_spec::BundleId,
    pub customer_id: greentic_deploy_spec::CustomerId,
    pub version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_version_ref: Option<PathBuf>,
    pub signed_at: DateTime<Utc>,
}

/// What a successful policy-version write produced.
#[derive(Clone, Debug)]
pub struct RevenuePolicyVersion {
    /// Env-relative path to the new sidecar (→ `BundleDeployment.revenue_policy_ref`).
    pub policy_ref: PathBuf,
    pub version: u64,
    /// Canonical SHA-256 integrity of the on-disk `vN.json` document (the
    /// digest the DSSE statement pins).
    pub integrity: StateIntegrity,
    /// `keyid` recorded in the DSSE envelope (matches the operator's
    /// canonical key id).
    pub key_id: String,
}

/// Write the next revenue-policy version for `deployment` under `env_dir`,
/// using `revenue_share` as the version's policy, `created_at` as its
/// timestamp, and `operator_key` for DSSE signing.
///
/// On disk, two files land under
/// `<env_dir>/billing-policies/<bundle_id>/<customer_id>/`:
/// - `vN.json` — the canonical-JSON [`RevenuePolicyDocument`].
/// - `vN.json.sig` — a DSSE envelope whose in-toto v1 Statement pins the
///   document's SHA-256 and carries a [`RevenuePolicyPredicate`].
///
/// **Trust-root precondition:** `operator_key.key_id` must already be
/// present in `<env_dir>/trust-root.json`; the writer never mutates the
/// trust root (see module docs on revocation durability). Bootstrap an
/// env's trust root once with `gtc op trust-root bootstrap <env-id>`.
///
/// The freshly-written envelope is re-loaded and re-verified against that
/// trust root before returning — a misconfiguration that would yield an
/// unverifiable sidecar fails the write rather than landing on disk.
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
    operator_key: &OperatorKey,
) -> Result<RevenuePolicyVersion, BundleDeploymentError> {
    // Codex #1: load the env trust root (do NOT mutate it) and refuse to
    // sign if the operator's key is not already trusted. Runs at the very
    // top of the function so a failed precondition leaves NO partial
    // artifacts (empty billing-policies subdirs, etc.) on disk. Auto-seeding
    // here would defeat `gtc op trust-root remove` as a revocation boundary.
    let trust_root = trust_root::load(env_dir)?;
    let trusted = trust_root
        .keys
        .iter()
        .any(|k| k.key_id.eq_ignore_ascii_case(&operator_key.key_id));
    if !trusted {
        return Err(BundleDeploymentError::OperatorKeyNotTrusted {
            key_id: operator_key.key_id.clone(),
            env_dir: env_dir.to_path_buf(),
        });
    }

    // `BundleId`/`CustomerId` are opaque, unvalidated strings — guard against
    // path traversal before they become directory segments.
    let bundle_seg = safe_segment(deployment.bundle_id.as_str())?;
    let customer_seg = safe_segment(deployment.customer_id.as_str())?;
    let rel_dir = Path::new(BILLING_DIR).join(bundle_seg).join(customer_seg);
    let abs_dir = env_dir.join(&rel_dir);

    // Version is derived from the deployment's *committed* `revenue_policy_ref`
    // (env.json), NOT from a filesystem scan. This keeps the operation
    // idempotent under partial-I/O retry: callers persist env.json only after
    // this writer returns, so a failed attempt (sidecar write or env save)
    // leaves the committed ref unchanged and a retry rewrites the SAME version
    // — overwriting any orphan files — instead of advancing past them. The
    // committed state therefore never references an uncommitted or dangling
    // version.
    let version = next_version_from_ref(&deployment.revenue_policy_ref)?;
    // Reconstruct the backward link under THIS deployment's billing dir rather
    // than copying the committed ref verbatim. In the normal flow the two are
    // identical (refs are always canonical); reconstructing additionally
    // refuses to propagate a crafted/cross-env ref out of a tampered env.json.
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
        previous_version_ref: previous_version_ref.clone(),
    };
    doc.validate()?;

    // Integrity envelope (kept on `RevenuePolicyVersion` for back-compat with
    // callers that previously cared about the SHA-256). The DSSE statement's
    // pinned digest is the same value.
    let integrity = StateIntegrity::sha256_of(&doc)?;
    let doc_bytes = serde_json::to_vec_pretty(&doc).map_err(BundleDeploymentError::Serialize)?;
    // The Statement pins the canonical-JSON SHA-256 of the on-disk doc.
    // This is the same shape `verify_artifact_dsse` reads.
    let doc_sha256_hex = sha256_hex(&doc_bytes);

    let predicate = RevenuePolicyPredicate {
        schema: REVENUE_POLICY_PREDICATE_TYPE_V1.to_string(),
        deployment_id: deployment.deployment_id,
        env_id: deployment.env_id.clone(),
        bundle_id: deployment.bundle_id.clone(),
        customer_id: deployment.customer_id.clone(),
        version,
        previous_version_ref,
        signed_at: created_at,
    };
    let predicate_value =
        serde_json::to_value(&predicate).map_err(BundleDeploymentError::Serialize)?;

    let mut digest = BTreeMap::new();
    digest.insert("sha256".to_string(), doc_sha256_hex.clone());
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
        serde_json::to_vec_pretty(&envelope).map_err(BundleDeploymentError::Serialize)?;

    std::fs::create_dir_all(&abs_dir).map_err(|source| BundleDeploymentError::Io {
        path: abs_dir.clone(),
        source,
    })?;

    let doc_rel = rel_dir.join(document_name(version));
    let sig_rel = rel_dir.join(sidecar_name(version));
    let doc_abs = env_dir.join(&doc_rel);
    let sig_abs = env_dir.join(&sig_rel);

    super::atomic_write::atomic_write_bytes(&doc_abs, &doc_bytes).map_err(|source| {
        BundleDeploymentError::Write {
            path: doc_abs.clone(),
            source,
        }
    })?;
    super::atomic_write::atomic_write_bytes(&sig_abs, &envelope_bytes).map_err(|source| {
        BundleDeploymentError::Write {
            path: sig_abs.clone(),
            source,
        }
    })?;

    // Self-verify: re-read from disk and verify against the env trust root.
    // A misconfigured key or trust-root seed would otherwise leak through.
    let written = std::fs::read(&sig_abs).map_err(|source| BundleDeploymentError::Io {
        path: sig_abs.clone(),
        source,
    })?;
    verify_artifact_dsse(&written, &doc_sha256_hex, &trust_root)?;

    Ok(RevenuePolicyVersion {
        policy_ref: sig_rel,
        version,
        integrity,
        key_id: operator_key.key_id.clone(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn document_name(version: u64) -> String {
    format!("v{version}.json")
}

fn sidecar_name(version: u64) -> String {
    format!("v{version}.json.sig")
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

/// Derive the next version from the deployment's committed `revenue_policy_ref`.
///
/// A ref of the shape `…/vN.json.sig` (with `N >= 1`) yields `N + 1`; anything
/// else — an empty placeholder on a fresh `add`, or a pre-B10 ref like
/// `revenue.json` — yields `1`, i.e. the first B10 version. A committed ref
/// already at the maximum returns [`BundleDeploymentError::VersionOverflow`]
/// rather than panicking (debug) or wrapping to 0 (release).
fn next_version_from_ref(current_ref: &Path) -> Result<u64, BundleDeploymentError> {
    match parse_sidecar_version(current_ref) {
        Some(n) => n
            .checked_add(1)
            .ok_or(BundleDeploymentError::VersionOverflow),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_key::{OperatorKey, load_or_generate_at};
    use greentic_deploy_spec::{
        BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId, PartyId, RouteBinding,
        TenantSelector,
    };
    use greentic_distributor_client::signing::{DsseEnvelope, TrustedKey, verify_artifact_dsse};
    use tempfile::{TempDir, tempdir};

    /// Test fixture: load/generate an operator key AND seed it into the env
    /// trust root. Mirrors the production flow where
    /// `gtc op trust-root bootstrap` runs once before any revenue-policy
    /// write. Tests that exercise the "operator not trusted" gate should NOT
    /// call this — use `test_operator_key_without_bootstrap` instead.
    fn test_operator_key(workdir: &TempDir) -> OperatorKey {
        let key = test_operator_key_without_bootstrap(workdir);
        trust_root::add_trusted_key(
            workdir.path(),
            TrustedKey {
                key_id: key.key_id.clone(),
                public_key_pem: key.public_pem.clone(),
            },
        )
        .expect("seed operator key into env trust root");
        key
    }

    fn test_operator_key_without_bootstrap(workdir: &TempDir) -> OperatorKey {
        // Each test gets its own key under its own tempdir so writes are
        // isolated and `~/.greentic/operator/key.pem` is never touched.
        load_or_generate_at(&workdir.path().join("operator-key.pem")).expect("generate key")
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
        let op = test_operator_key(&dir);
        let dep = deployment("fast2flow", "local-dev");
        let v = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
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
        let op = test_operator_key(&dir);
        // The version advances off the deployment's *committed* ref, so the
        // caller threads the prior ref onto the deployment between writes —
        // exactly what `cli::bundles::update` does after a successful save.
        let mut dep = deployment("fast2flow", "cust-acme");
        let v1 =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .unwrap();
        dep.revenue_policy_ref = v1.policy_ref;
        let v2 = write_revenue_policy_version(
            dir.path(),
            &dep,
            &shares(&[("agency-a", 3_000), ("greentic", 7_000)]),
            Utc::now(),
            &op,
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
    fn retry_after_uncommitted_write_reuses_same_version() {
        // Codex regression: a failed attempt (sidecar write or env.json save)
        // never advances the committed ref, so a retry must rewrite the SAME
        // version and overwrite the orphan files rather than advance past them.
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let dep = deployment("fast2flow", "local-dev"); // committed ref is the placeholder
        // First attempt "fails to commit": files land on disk but the caller
        // never persists the new ref onto the deployment.
        let a = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        assert_eq!(a.version, 1);
        // Retry with the SAME (still-uncommitted) deployment.
        let b = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        assert_eq!(b.version, 1, "retry must not advance past the orphan");
        // No v2 was ever produced.
        assert!(
            !dir.path()
                .join("billing-policies/fast2flow/local-dev/v2.json")
                .exists()
        );
    }

    #[test]
    fn retry_on_update_path_does_not_dangle_chain() {
        // Update committed v1 (ref threaded), then an update attempt to v2
        // "fails to commit" (ref left at v1); the retry rewrites v2 and chains
        // to the committed v1 sidecar — never to a missing/uncommitted one.
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let mut dep = deployment("fast2flow", "cust-acme");
        let v1 =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .unwrap();
        dep.revenue_policy_ref = v1.policy_ref; // v1 committed
        // First v2 attempt (uncommitted): ref stays at v1.
        write_revenue_policy_version(
            dir.path(),
            &dep,
            &shares(&[("greentic", 10_000)]),
            Utc::now(),
            &op,
        )
        .unwrap();
        // Retry: still derives v2 from committed v1.
        let v2 = write_revenue_policy_version(
            dir.path(),
            &dep,
            &shares(&[("greentic", 10_000)]),
            Utc::now(),
            &op,
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
        let prev = doc.previous_version_ref.expect("v2 chains to v1");
        assert!(
            dir.path().join(&prev).is_file(),
            "previous_version_ref must point at a real (committed) sidecar"
        );
        assert!(
            !dir.path()
                .join("billing-policies/fast2flow/cust-acme/v3.json")
                .exists()
        );
    }

    #[test]
    fn sidecar_is_dsse_envelope_that_verifies_against_doc_sha256() {
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let dep = deployment("fast2flow", "local-dev");
        let v = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        assert_eq!(v.key_id, op.key_id);

        let doc_path = dir
            .path()
            .join("billing-policies/fast2flow/local-dev/v1.json");
        let doc_bytes = std::fs::read(&doc_path).unwrap();
        let doc_sha256 = sha256_hex(&doc_bytes);
        // Round-trips through serde so the SHA-256 lines up with what the
        // writer pinned (canonical-JSON via serde_json::to_vec_pretty).
        let _doc: RevenuePolicyDocument = serde_json::from_slice(&doc_bytes).unwrap();

        let envelope_bytes = std::fs::read(dir.path().join(&v.policy_ref)).unwrap();
        let parsed: DsseEnvelope = serde_json::from_slice(&envelope_bytes).unwrap();
        assert_eq!(parsed.payload_type, "application/vnd.in-toto+json");
        assert_eq!(parsed.signatures.len(), 1);
        assert_eq!(parsed.signatures[0].keyid, op.key_id);

        // Trust root carries the bootstrapped operator key (fixture-seeded).
        let trust = super::super::trust_root::load(dir.path()).unwrap();
        assert!(!trust.is_empty(), "fixture must bootstrap trust-root.json");
        verify_artifact_dsse(&envelope_bytes, &doc_sha256, &trust)
            .expect("envelope must verify against the env trust root");
    }

    #[test]
    fn writer_does_not_mutate_trust_root() {
        // Codex #1 revocation durability: two consecutive writes must not
        // change the trust root — the writer is read-only against it.
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let pre = super::super::trust_root::load(dir.path()).unwrap();
        let mut dep = deployment("fast2flow", "local-dev");
        let v1 =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .unwrap();
        dep.revenue_policy_ref = v1.policy_ref;
        write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        let post = super::super::trust_root::load(dir.path()).unwrap();
        assert_eq!(pre.keys, post.keys, "writer must not mutate trust root");
    }

    #[test]
    fn writer_refuses_when_operator_key_not_in_trust_root() {
        // Codex #1: unbootstrapped trust root is a hard fail, never silent
        // auto-seed.
        let dir = tempdir().unwrap();
        let op = test_operator_key_without_bootstrap(&dir);
        let dep = deployment("fast2flow", "local-dev");
        let err =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .expect_err("unbootstrapped op must be rejected");
        match err {
            BundleDeploymentError::OperatorKeyNotTrusted { key_id, .. } => {
                assert_eq!(key_id, op.key_id);
            }
            other => panic!("expected OperatorKeyNotTrusted, got {other:?}"),
        }
        assert!(
            !dir.path().join("billing-policies").exists(),
            "no policy artifact must land on a failed precondition"
        );
    }

    #[test]
    fn writer_refuses_after_explicit_trust_root_remove() {
        // Codex #1 durability: once an operator key is removed via
        // `trust-root remove`, the writer must keep refusing — never silently
        // re-seed and resume signing.
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let dep = deployment("fast2flow", "local-dev");
        write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        super::super::trust_root::remove_trusted_key(dir.path(), &op.key_id).unwrap();
        let mut dep2 = dep.clone();
        dep2.bundle_id = BundleId::new("post-revocation");
        let err =
            write_revenue_policy_version(dir.path(), &dep2, &dep2.revenue_share, Utc::now(), &op)
                .expect_err("revoked op must stay revoked");
        assert!(matches!(
            err,
            BundleDeploymentError::OperatorKeyNotTrusted { .. }
        ));
        let trust = super::super::trust_root::load(dir.path()).unwrap();
        assert!(
            trust.keys.is_empty(),
            "revocation must be durable; got {:?}",
            trust.keys
        );
    }

    #[test]
    fn unsafe_bundle_segment_rejected() {
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let dep = deployment("../escape", "local-dev");
        let err =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::UnsafeSegment(_)));
    }

    #[test]
    fn unsafe_customer_segment_rejected() {
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let dep = deployment("fast2flow", "a/b");
        let err =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::UnsafeSegment(_)));
    }

    #[test]
    fn invalid_revenue_share_rejected_before_write() {
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let dep = deployment("fast2flow", "local-dev");
        let err = write_revenue_policy_version(
            dir.path(),
            &dep,
            &shares(&[("greentic", 5_000)]),
            Utc::now(),
            &op,
        )
        .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::Spec(_)));
        // Nothing should have been written.
        assert!(!dir.path().join("billing-policies").exists());
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
    fn corrupted_v0_ref_starts_fresh_at_v1_without_chain() {
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let mut dep = deployment("fast2flow", "local-dev");
        dep.revenue_policy_ref = PathBuf::from("billing-policies/fast2flow/local-dev/v0.json.sig");
        let v = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        assert_eq!(v.version, 1, "v0 ref must not chain; restart at v1");
        let doc: RevenuePolicyDocument = serde_json::from_slice(
            &std::fs::read(
                dir.path()
                    .join("billing-policies/fast2flow/local-dev/v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(doc.previous_version_ref.is_none());
    }

    #[test]
    fn version_counter_overflow_is_an_error_not_a_panic() {
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let mut dep = deployment("fast2flow", "local-dev");
        dep.revenue_policy_ref = PathBuf::from(format!(
            "billing-policies/fast2flow/local-dev/v{}.json.sig",
            u64::MAX
        ));
        let err =
            write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
                .unwrap_err();
        assert!(matches!(err, BundleDeploymentError::VersionOverflow));
    }

    #[test]
    fn previous_version_ref_is_reconstructed_not_copied_verbatim() {
        // A crafted cross-env committed ref must NOT propagate into the new
        // doc's previous_version_ref; the link is rebuilt under this
        // deployment's own billing dir.
        let dir = tempdir().unwrap();
        let op = test_operator_key(&dir);
        let mut dep = deployment("fast2flow", "cust-acme");
        dep.revenue_policy_ref =
            PathBuf::from("../../other-env/billing-policies/victim/cust/v3.json.sig");
        let v = write_revenue_policy_version(dir.path(), &dep, &dep.revenue_share, Utc::now(), &op)
            .unwrap();
        assert_eq!(v.version, 4); // derived from the parsed v3
        let doc: RevenuePolicyDocument = serde_json::from_slice(
            &std::fs::read(
                dir.path()
                    .join("billing-policies/fast2flow/cust-acme/v4.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            doc.previous_version_ref,
            Some(PathBuf::from(
                "billing-policies/fast2flow/cust-acme/v3.json.sig"
            )),
            "previous_version_ref must be rebuilt under this deployment's dir, not the crafted ref"
        );
    }
}
