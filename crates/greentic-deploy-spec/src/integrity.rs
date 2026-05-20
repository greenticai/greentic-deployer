//! Corruption-detection hash (A8 contract piece #6) and the canonical-JSON
//! form the hash is computed over.
//!
//! A production `EnvironmentStore` must be able to detect on-disk/at-rest
//! corruption of a persisted resource. The contract defines a content hash:
//! SHA-256 over the resource's *canonical JSON* — object keys sorted
//! lexicographically, no insignificant whitespace, arrays left in order. The
//! strong [`StateEtag`](crate::remote::StateEtag) reuses the same digest.
//!
//! Canonicalization sorts keys explicitly (not relying on `serde_json`'s map
//! ordering) so the digest is identical whether or not the `preserve_order`
//! feature is unified into the build.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The only hash algorithm defined by the Phase A contract.
pub const INTEGRITY_ALGORITHM_SHA256: &str = "sha-256";

#[derive(Debug, Error)]
pub enum IntegrityError {
    #[error("integrity serialize: {0}")]
    Serde(#[from] serde_json::Error),
    /// A stored [`StateIntegrity`] names an algorithm this build can't verify.
    #[error("unsupported integrity algorithm `{0}` (expected `{INTEGRITY_ALGORITHM_SHA256}`)")]
    UnsupportedAlgorithm(String),
}

/// Content hash of a persisted resource, used for corruption detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateIntegrity {
    /// Hash algorithm identifier — `sha-256` in Phase A.
    pub algorithm: String,
    /// Lowercase hex digest over the canonical JSON of the resource.
    pub digest: String,
}

impl StateIntegrity {
    /// Compute the SHA-256 integrity hash over `value`'s canonical JSON.
    pub fn sha256_of<T: Serialize>(value: &T) -> Result<Self, IntegrityError> {
        let mut hasher = Sha256::new();
        hasher.update(canonical_json(value)?.as_bytes());
        Ok(Self {
            algorithm: INTEGRITY_ALGORITHM_SHA256.to_string(),
            digest: hex::encode(hasher.finalize()),
        })
    }

    /// Recompute the hash over `value` and report whether it matches `self`.
    ///
    /// Errors if `self.algorithm` is not one this build can recompute, so a
    /// caller never silently treats an unknown algorithm as a match.
    pub fn verify<T: Serialize>(&self, value: &T) -> Result<bool, IntegrityError> {
        if self.algorithm != INTEGRITY_ALGORITHM_SHA256 {
            return Err(IntegrityError::UnsupportedAlgorithm(self.algorithm.clone()));
        }
        Ok(self.digest == Self::sha256_of(value)?.digest)
    }
}

/// Serialize `value` to canonical JSON: keys sorted lexicographically at every
/// object level, compact (no insignificant whitespace), arrays in order.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, IntegrityError> {
    let canonical = canonicalize(&serde_json::to_value(value)?);
    Ok(serde_json::to_string(&canonical)?)
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            // Emit keys in sorted order regardless of whether serde_json's
            // `preserve_order` is active in the build.
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            Value::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), canonicalize(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = serde_json::json!({"b": 1, "a": {"d": 4, "c": 3}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"c":3,"d":4},"b":1}"#
        );
    }

    #[test]
    fn canonical_json_preserves_array_order() {
        let value = serde_json::json!([3, 1, 2]);
        assert_eq!(canonical_json(&value).unwrap(), "[3,1,2]");
    }

    #[test]
    fn hash_is_stable_for_equal_content() {
        let a = serde_json::json!({"x": 1, "y": [1, 2]});
        let b = serde_json::json!({"x": 1, "y": [1, 2]});
        assert_eq!(
            StateIntegrity::sha256_of(&a).unwrap(),
            StateIntegrity::sha256_of(&b).unwrap()
        );
    }

    #[test]
    fn hash_independent_of_key_insertion_order() {
        let a = serde_json::json!({"first": 1, "second": 2});
        let b = serde_json::json!({"second": 2, "first": 1});
        assert_eq!(
            StateIntegrity::sha256_of(&a).unwrap().digest,
            StateIntegrity::sha256_of(&b).unwrap().digest
        );
    }

    #[test]
    fn hash_changes_when_content_changes() {
        let a = serde_json::json!({"x": 1});
        let b = serde_json::json!({"x": 2});
        assert_ne!(
            StateIntegrity::sha256_of(&a).unwrap().digest,
            StateIntegrity::sha256_of(&b).unwrap().digest
        );
    }

    #[test]
    fn verify_detects_tampering() {
        let original = serde_json::json!({"generation": 4, "name": "local"});
        let integrity = StateIntegrity::sha256_of(&original).unwrap();
        assert!(integrity.verify(&original).unwrap());

        let tampered = serde_json::json!({"generation": 5, "name": "local"});
        assert!(!integrity.verify(&tampered).unwrap());
    }

    #[test]
    fn verify_rejects_unknown_algorithm() {
        let integrity = StateIntegrity {
            algorithm: "blake3".to_string(),
            digest: "00".to_string(),
        };
        let err = integrity
            .verify(&serde_json::json!({}))
            .expect_err("unknown algorithm must error");
        assert!(matches!(err, IntegrityError::UnsupportedAlgorithm(a) if a == "blake3"));
    }

    #[test]
    fn digest_is_lowercase_hex_sha256() {
        let integrity = StateIntegrity::sha256_of(&serde_json::json!({})).unwrap();
        assert_eq!(integrity.algorithm, INTEGRITY_ALGORITHM_SHA256);
        assert_eq!(integrity.digest.len(), 64);
        assert!(
            integrity
                .digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
