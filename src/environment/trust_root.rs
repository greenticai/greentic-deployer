//! Per-environment trust-root persistence (C2 of `plans/next-gen-deployment.md`).
//!
//! Owns `<env_dir>/trust-root.json`, the **closed-by-default** allowlist of
//! Ed25519 public keys the operator trusts to sign artifacts whose digests
//! are pinned in revisions or revenue-policy documents under this env.
//!
//! The on-disk schema (`greentic.trust-root.v1`) is a thin envelope around
//! [`greentic_distributor_client::signing::TrustedKey`]; [`load`] returns a
//! ready-to-use [`greentic_distributor_client::signing::TrustRoot`] so
//! verifiers don't translate between two shapes. A missing file yields an
//! empty `TrustRoot` — verification then fails closed because no key matches.
//!
//! Mutations go through [`add_trusted_key`] / [`remove_trusted_key`], which
//! validate the public key parses as Ed25519 SPKI and that the supplied
//! `key_id` matches the derivation in
//! [`greentic_distributor_client::signing::key_id_for_public_key_pem`]
//! before persisting. This rejects stale/wrong-cased ids and a mismatch
//! between the PEM and the id at write time, where it's actionable, rather
//! than at verify time where the failure looks like a missing key.

use std::path::{Path, PathBuf};

use greentic_distributor_client::signing::{
    SigningError, TrustRoot, TrustedKey, key_id_for_public_key_pem,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::atomic_write::{AtomicWriteError, atomic_write_json, copy_to_backup};

/// Env-relative sub-directory under which previous `trust-root.json`
/// revisions are copied before each save (Codex #3 recovery hook).
const TRUST_ROOT_BACKUP_DIR: &str = "backups";

/// Schema discriminator for the trust-root file.
pub const TRUST_ROOT_SCHEMA_V1: &str = "greentic.trust-root.v1";

/// Filename under `<env_dir>` holding the trust-root document.
pub const TRUST_ROOT_FILE: &str = "trust-root.json";

#[derive(Debug, Error)]
pub enum TrustRootError {
    #[error("trust-root io on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("trust-root write {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: AtomicWriteError,
    },
    #[error("trust-root parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("trust-root schema `{found}` is not the expected `{TRUST_ROOT_SCHEMA_V1}`")]
    BadSchema { found: String },
    #[error("trust-root key validation: {0}")]
    Key(#[from] SigningError),
    #[error(
        "trust-root key_id `{supplied}` does not match the derivation from the public key (`{derived}`)"
    )]
    KeyIdMismatch { supplied: String, derived: String },
    #[error("trust-root key_id `{0}` must be a non-empty hex string")]
    EmptyKeyId(String),
}

/// On-disk envelope wrapping the distributor-client trust-root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustRootDocument {
    pub schema: String,
    pub keys: Vec<TrustedKey>,
}

impl TrustRootDocument {
    fn v1(keys: Vec<TrustedKey>) -> Self {
        Self {
            schema: TRUST_ROOT_SCHEMA_V1.to_string(),
            keys,
        }
    }

    fn into_trust_root(self) -> Result<TrustRoot, TrustRootError> {
        if self.schema != TRUST_ROOT_SCHEMA_V1 {
            return Err(TrustRootError::BadSchema { found: self.schema });
        }
        Ok(TrustRoot::new(self.keys))
    }
}

/// Absolute path to `<env_dir>/trust-root.json` (the file is not required to
/// exist).
pub fn trust_root_path(env_dir: &Path) -> PathBuf {
    env_dir.join(TRUST_ROOT_FILE)
}

/// Load `<env_dir>/trust-root.json` into a verifier-ready [`TrustRoot`].
///
/// A missing file returns an **empty** trust root (`is_empty() == true`) —
/// the verifier then rejects every signature, which is the intended
/// closed-by-default behavior.
pub fn load(env_dir: &Path) -> Result<TrustRoot, TrustRootError> {
    let path = trust_root_path(env_dir);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TrustRoot::default());
        }
        Err(source) => return Err(TrustRootError::Io { path, source }),
    };
    let doc: TrustRootDocument =
        serde_json::from_slice(&bytes).map_err(|source| TrustRootError::Parse {
            path: path.clone(),
            source,
        })?;
    doc.into_trust_root()
}

/// Add or overwrite a trusted key. Validates that `public_key_pem` parses as
/// an Ed25519 SPKI PEM and that `key_id` matches the canonical derivation.
///
/// Idempotent on case-insensitive `key_id` match: the existing entry's PEM
/// is replaced. Returns the resulting trust root.
///
/// MUST run under the env flock (callers wrap in
/// [`crate::environment::EnvironmentStore::transact`]).
pub fn add_trusted_key(env_dir: &Path, key: TrustedKey) -> Result<TrustRoot, TrustRootError> {
    if key.key_id.trim().is_empty() {
        return Err(TrustRootError::EmptyKeyId(key.key_id));
    }
    let derived = key_id_for_public_key_pem(&key.public_key_pem)?;
    if !key.key_id.eq_ignore_ascii_case(&derived) {
        return Err(TrustRootError::KeyIdMismatch {
            supplied: key.key_id,
            derived,
        });
    }

    let mut current = load_keys(env_dir)?;
    let normalized_id = derived;
    current.retain(|k| !k.key_id.eq_ignore_ascii_case(&normalized_id));
    current.push(TrustedKey {
        key_id: normalized_id,
        public_key_pem: key.public_key_pem,
    });
    save(env_dir, &current)?;
    Ok(TrustRoot::new(current))
}

/// Remove a trusted key by case-insensitive `key_id`. A missing key is a
/// silent no-op (the trust root is already in the requested state).
///
/// MUST run under the env flock.
pub fn remove_trusted_key(env_dir: &Path, key_id: &str) -> Result<TrustRoot, TrustRootError> {
    let mut current = load_keys(env_dir)?;
    current.retain(|k| !k.key_id.eq_ignore_ascii_case(key_id));
    save(env_dir, &current)?;
    Ok(TrustRoot::new(current))
}

fn load_keys(env_dir: &Path) -> Result<Vec<TrustedKey>, TrustRootError> {
    let root = load(env_dir)?;
    Ok(root.keys)
}

/// Atomically replace `<env_dir>/trust-root.json` with `keys`, first
/// copying the previous file (if any) into `<env_dir>/backups/` with an
/// RFC-3339 timestamp.
///
/// Codex #3: an accidental or malicious `add`/`remove` would otherwise be
/// unrecoverable — the CLI audit log records only `key_id`, not enough to
/// reconstruct removed PEMs. The backup keeps the prior trust root one
/// directory away, and the CLI emits the full `(key_id, public_pem)` pair
/// in its audit `target`.
fn save(env_dir: &Path, keys: &[TrustedKey]) -> Result<(), TrustRootError> {
    let path = trust_root_path(env_dir);
    copy_to_backup(&path, &env_dir.join(TRUST_ROOT_BACKUP_DIR)).map_err(|source| {
        TrustRootError::Write {
            path: path.clone(),
            source,
        }
    })?;
    let doc = TrustRootDocument::v1(keys.to_vec());
    atomic_write_json(&path, &doc).map_err(|source| TrustRootError::Write { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use tempfile::tempdir;

    fn keypair(seed: u8) -> (String, String) {
        let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let pub_pem = vk.to_public_key_pem(LineEnding::LF).unwrap();
        let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
        (pub_pem, key_id)
    }

    #[test]
    fn load_missing_file_returns_empty_trust_root() {
        let dir = tempdir().unwrap();
        let tr = load(dir.path()).unwrap();
        assert!(tr.is_empty());
    }

    #[test]
    fn add_then_load_roundtrips_a_key() {
        let dir = tempdir().unwrap();
        let (pem, key_id) = keypair(1);
        let tr = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: key_id.clone(),
                public_key_pem: pem.clone(),
            },
        )
        .unwrap();
        assert_eq!(tr.keys.len(), 1);
        assert_eq!(tr.keys[0].key_id, key_id);

        let reloaded = load(dir.path()).unwrap();
        assert_eq!(reloaded.keys, tr.keys);
    }

    #[test]
    fn add_with_uppercase_key_id_normalizes_to_canonical_lowercase() {
        let dir = tempdir().unwrap();
        let (pem, key_id) = keypair(2);
        let uppercase = key_id.to_uppercase();
        let tr = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: uppercase,
                public_key_pem: pem,
            },
        )
        .unwrap();
        assert_eq!(tr.keys[0].key_id, key_id, "stored id must be canonical");
    }

    #[test]
    fn add_with_mismatched_key_id_is_rejected() {
        let dir = tempdir().unwrap();
        let (pem_a, _id_a) = keypair(3);
        let (_pem_b, id_b) = keypair(4);
        let err = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_b,
                public_key_pem: pem_a,
            },
        )
        .expect_err("mismatched id must be rejected");
        assert!(matches!(err, TrustRootError::KeyIdMismatch { .. }));
        // File was never written.
        assert!(!trust_root_path(dir.path()).exists());
    }

    #[test]
    fn add_with_empty_key_id_is_rejected() {
        let dir = tempdir().unwrap();
        let (pem, _) = keypair(5);
        let err = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: "   ".into(),
                public_key_pem: pem,
            },
        )
        .expect_err("empty id must be rejected");
        assert!(matches!(err, TrustRootError::EmptyKeyId(_)));
    }

    #[test]
    fn add_with_malformed_pem_is_rejected_pre_write() {
        let dir = tempdir().unwrap();
        let err = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: "abcdef".repeat(5).chars().take(32).collect(),
                public_key_pem: "not-a-pem".into(),
            },
        )
        .expect_err("bad pem must be rejected");
        assert!(matches!(err, TrustRootError::Key(_)));
        assert!(!trust_root_path(dir.path()).exists());
    }

    #[test]
    fn add_replaces_existing_key_with_same_key_id() {
        let dir = tempdir().unwrap();
        let (pem, id) = keypair(6);
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id.clone(),
                public_key_pem: pem.clone(),
            },
        )
        .unwrap();
        let tr = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id.to_uppercase(),
                public_key_pem: pem,
            },
        )
        .unwrap();
        assert_eq!(tr.keys.len(), 1, "duplicate key_id must dedup");
    }

    #[test]
    fn add_two_distinct_keys_yields_two_entries() {
        let dir = tempdir().unwrap();
        let (pem_a, id_a) = keypair(7);
        let (pem_b, id_b) = keypair(8);
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_a,
                public_key_pem: pem_a,
            },
        )
        .unwrap();
        let tr = add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_b,
                public_key_pem: pem_b,
            },
        )
        .unwrap();
        assert_eq!(tr.keys.len(), 2);
    }

    #[test]
    fn remove_drops_only_matching_key() {
        let dir = tempdir().unwrap();
        let (pem_a, id_a) = keypair(9);
        let (pem_b, id_b) = keypair(10);
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_a.clone(),
                public_key_pem: pem_a,
            },
        )
        .unwrap();
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_b.clone(),
                public_key_pem: pem_b,
            },
        )
        .unwrap();
        let tr = remove_trusted_key(dir.path(), &id_a).unwrap();
        assert_eq!(tr.keys.len(), 1);
        assert_eq!(tr.keys[0].key_id, id_b);
    }

    #[test]
    fn remove_unknown_key_is_a_silent_noop() {
        let dir = tempdir().unwrap();
        let (pem, id) = keypair(11);
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id.clone(),
                public_key_pem: pem,
            },
        )
        .unwrap();
        let tr = remove_trusted_key(dir.path(), "00ff00ff00ff00ff00ff00ff00ff00ff").unwrap();
        assert_eq!(tr.keys.len(), 1, "non-matching removal is a no-op");
        assert_eq!(tr.keys[0].key_id, id);
    }

    #[test]
    fn add_writes_prior_trust_root_to_backups_dir() {
        // Codex #3: every save copies the previous file aside so a bad
        // `add`/`remove` is recoverable from disk.
        let dir = tempdir().unwrap();
        let (pem_a, id_a) = keypair(40);
        let (pem_b, id_b) = keypair(41);
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_a.clone(),
                public_key_pem: pem_a,
            },
        )
        .unwrap();
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id_b,
                public_key_pem: pem_b,
            },
        )
        .unwrap();
        // Second save copied the v1 (id_a-only) file to backups/.
        let backups: Vec<_> = std::fs::read_dir(dir.path().join("backups"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("trust-root.json.")
            })
            .collect();
        assert!(
            !backups.is_empty(),
            "expected a trust-root backup file under backups/"
        );
        let backup_contents = std::fs::read_to_string(backups[0].path()).unwrap();
        let parsed: TrustRootDocument = serde_json::from_str(&backup_contents).unwrap();
        assert_eq!(parsed.keys.len(), 1);
        assert!(parsed.keys[0].key_id.eq_ignore_ascii_case(&id_a));
    }

    #[test]
    fn remove_writes_prior_trust_root_to_backups_dir() {
        let dir = tempdir().unwrap();
        let (pem, id) = keypair(42);
        add_trusted_key(
            dir.path(),
            TrustedKey {
                key_id: id.clone(),
                public_key_pem: pem,
            },
        )
        .unwrap();
        remove_trusted_key(dir.path(), &id).unwrap();
        // The `add` saved once (no prior backup), the `remove` saved a
        // second time copying the post-add file into backups/.
        let backups: Vec<_> = std::fs::read_dir(dir.path().join("backups"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("trust-root.json.")
            })
            .collect();
        assert_eq!(backups.len(), 1, "remove must back up its predecessor");
        let parsed: TrustRootDocument =
            serde_json::from_str(&std::fs::read_to_string(backups[0].path()).unwrap()).unwrap();
        assert_eq!(parsed.keys.len(), 1);
        assert!(parsed.keys[0].key_id.eq_ignore_ascii_case(&id));
    }

    #[test]
    fn unknown_schema_is_rejected_on_load() {
        let dir = tempdir().unwrap();
        std::fs::write(
            trust_root_path(dir.path()),
            br#"{"schema":"greentic.trust-root.v999","keys":[]}"#,
        )
        .unwrap();
        let err = load(dir.path()).expect_err("bad schema must reject");
        assert!(matches!(err, TrustRootError::BadSchema { .. }));
    }

    #[test]
    fn malformed_json_is_rejected_on_load() {
        let dir = tempdir().unwrap();
        std::fs::write(trust_root_path(dir.path()), b"{not json}").unwrap();
        let err = load(dir.path()).expect_err("bad json must reject");
        assert!(matches!(err, TrustRootError::Parse { .. }));
    }
}
