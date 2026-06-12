//! Trust-root document semantics (`greentic.trust-root.v1`).
//!
//! The pure half of per-environment trust-root handling: the on-disk/on-wire
//! document envelope plus the validate/add/remove transforms. Persistence is
//! deliberately NOT here — the deployer's `LocalFsStore` keeps
//! `<env_dir>/trust-root.json` (atomic writes + backups) and the
//! operator-store-server keeps SQLite rows, but both drive these SAME
//! functions so key-id canonicalization and validation cannot drift between
//! backends.
//!
//! [`validate_trusted_key`] rejects empty key ids, public keys that do not
//! parse as Ed25519 SPKI PEM, and a supplied `key_id` that does not match the
//! canonical derivation in
//! [`greentic_distributor_client::signing::key_id_for_public_key_pem`] — at
//! write time, where the failure is actionable, rather than at verify time
//! where it looks like a missing key. The returned entry carries the
//! canonical (lowercase) id, so stores never persist a caller-cased one.

use greentic_distributor_client::signing::{
    SigningError, TrustRoot, TrustedKey, key_id_for_public_key_pem,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema discriminator for the trust-root document.
pub const TRUST_ROOT_SCHEMA_V1: &str = "greentic.trust-root.v1";

/// Validation and schema errors for trust-root documents. I/O errors stay
/// with the persisting caller — this crate never touches storage.
#[derive(Debug, Error)]
pub enum TrustRootDocError {
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

/// Document envelope wrapping the distributor-client trust-root. Identical
/// shape whether serialized to `trust-root.json` or a database column.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustRootDocument {
    pub schema: String,
    pub keys: Vec<TrustedKey>,
}

impl TrustRootDocument {
    /// Wrap `keys` in a v1 envelope.
    pub fn v1(keys: Vec<TrustedKey>) -> Self {
        Self {
            schema: TRUST_ROOT_SCHEMA_V1.to_string(),
            keys,
        }
    }

    /// Unwrap into a verifier-ready [`TrustRoot`], rejecting unknown schemas.
    pub fn into_trust_root(self) -> Result<TrustRoot, TrustRootDocError> {
        if self.schema != TRUST_ROOT_SCHEMA_V1 {
            return Err(TrustRootDocError::BadSchema { found: self.schema });
        }
        Ok(TrustRoot::new(self.keys))
    }
}

/// Validate a caller-supplied `(key_id, public_key_pem)` entry and return it
/// with the canonical (lowercase) key id. See the module docs for what is
/// rejected and why validation lives at write time.
pub fn validate_trusted_key(key: TrustedKey) -> Result<TrustedKey, TrustRootDocError> {
    if key.key_id.trim().is_empty() {
        return Err(TrustRootDocError::EmptyKeyId(key.key_id));
    }
    let derived = key_id_for_public_key_pem(&key.public_key_pem)?;
    if !key.key_id.eq_ignore_ascii_case(&derived) {
        return Err(TrustRootDocError::KeyIdMismatch {
            supplied: key.key_id,
            derived,
        });
    }
    Ok(TrustedKey {
        key_id: derived,
        public_key_pem: key.public_key_pem,
    })
}

/// Add or overwrite a trusted key, deduplicating on case-insensitive
/// `key_id`. `key` must already be canonical — call [`validate_trusted_key`]
/// first.
pub fn apply_add(keys: &mut Vec<TrustedKey>, key: TrustedKey) {
    keys.retain(|k| !k.key_id.eq_ignore_ascii_case(&key.key_id));
    keys.push(key);
}

/// Remove a trusted key by case-insensitive `key_id`. Returns `true` when an
/// entry was removed — callers use this to skip a persist on the silent
/// no-op (so a `remove` on a fresh env does not materialize an empty
/// document where none existed).
pub fn apply_remove(keys: &mut Vec<TrustedKey>, key_id: &str) -> bool {
    let before = keys.len();
    keys.retain(|k| !k.key_id.eq_ignore_ascii_case(key_id));
    keys.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;

    fn keypair(seed: u8) -> (String, String) {
        let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        let pub_pem = vk.to_public_key_pem(LineEnding::LF).unwrap();
        let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
        (pub_pem, key_id)
    }

    #[test]
    fn validate_accepts_canonical_entry() {
        let (pem, id) = keypair(1);
        let key = validate_trusted_key(TrustedKey {
            key_id: id.clone(),
            public_key_pem: pem,
        })
        .unwrap();
        assert_eq!(key.key_id, id);
    }

    #[test]
    fn validate_canonicalizes_uppercase_key_id() {
        let (pem, id) = keypair(2);
        let key = validate_trusted_key(TrustedKey {
            key_id: id.to_uppercase(),
            public_key_pem: pem,
        })
        .unwrap();
        assert_eq!(key.key_id, id, "stored id must be canonical lowercase");
    }

    #[test]
    fn validate_rejects_mismatched_key_id() {
        let (pem_a, _id_a) = keypair(3);
        let (_pem_b, id_b) = keypair(4);
        let err = validate_trusted_key(TrustedKey {
            key_id: id_b,
            public_key_pem: pem_a,
        })
        .expect_err("mismatched id must be rejected");
        assert!(matches!(err, TrustRootDocError::KeyIdMismatch { .. }));
    }

    #[test]
    fn validate_rejects_empty_and_whitespace_key_id() {
        let (pem, _) = keypair(5);
        let err = validate_trusted_key(TrustedKey {
            key_id: "   ".into(),
            public_key_pem: pem,
        })
        .expect_err("empty id must be rejected");
        assert!(matches!(err, TrustRootDocError::EmptyKeyId(_)));
    }

    #[test]
    fn validate_rejects_malformed_pem() {
        let err = validate_trusted_key(TrustedKey {
            key_id: "abcdef0123456789abcdef0123456789".into(),
            public_key_pem: "not-a-pem".into(),
        })
        .expect_err("bad pem must be rejected");
        assert!(matches!(err, TrustRootDocError::Key(_)));
    }

    #[test]
    fn apply_add_replaces_same_key_id_case_insensitively() {
        let (pem, id) = keypair(6);
        let mut keys = vec![TrustedKey {
            key_id: id.to_uppercase(),
            public_key_pem: "old".into(),
        }];
        apply_add(
            &mut keys,
            TrustedKey {
                key_id: id.clone(),
                public_key_pem: pem.clone(),
            },
        );
        assert_eq!(keys.len(), 1, "duplicate key_id must dedup");
        assert_eq!(keys[0].public_key_pem, pem, "PEM must be replaced");
    }

    #[test]
    fn apply_add_keeps_distinct_keys() {
        let (pem_a, id_a) = keypair(7);
        let (pem_b, id_b) = keypair(8);
        let mut keys = Vec::new();
        apply_add(
            &mut keys,
            TrustedKey {
                key_id: id_a,
                public_key_pem: pem_a,
            },
        );
        apply_add(
            &mut keys,
            TrustedKey {
                key_id: id_b,
                public_key_pem: pem_b,
            },
        );
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn apply_remove_drops_only_matching_key_and_reports_change() {
        let (pem_a, id_a) = keypair(9);
        let (pem_b, id_b) = keypair(10);
        let mut keys = vec![
            TrustedKey {
                key_id: id_a.clone(),
                public_key_pem: pem_a,
            },
            TrustedKey {
                key_id: id_b.clone(),
                public_key_pem: pem_b,
            },
        ];
        assert!(apply_remove(&mut keys, &id_a.to_uppercase()));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, id_b);
        assert!(
            !apply_remove(&mut keys, &id_a),
            "absent key must report no change"
        );
    }

    #[test]
    fn document_round_trips_and_rejects_unknown_schema() {
        let (pem, id) = keypair(11);
        let doc = TrustRootDocument::v1(vec![TrustedKey {
            key_id: id.clone(),
            public_key_pem: pem,
        }]);
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: TrustRootDocument = serde_json::from_str(&json).unwrap();
        let root = parsed.into_trust_root().unwrap();
        assert_eq!(root.keys.len(), 1);
        assert_eq!(root.keys[0].key_id, id);

        let bad: TrustRootDocument =
            serde_json::from_str(r#"{"schema":"greentic.trust-root.v999","keys":[]}"#).unwrap();
        let err = bad.into_trust_root().expect_err("bad schema must reject");
        assert!(matches!(err, TrustRootDocError::BadSchema { .. }));
    }
}
