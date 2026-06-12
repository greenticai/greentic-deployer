//! Trust-root verb group — wire shapes only (PR-4.2f).
//!
//! Unlike the other verb groups, the trust-root TRANSFORMS do not live in
//! this module: key-id canonicalization and Ed25519 SPKI validation need
//! crypto (`greentic-distributor-client::signing`), and this crate is
//! deliberately crypto-free. The shared pure semantics live in
//! `greentic-operator-trust::trust_root` (`validate_trusted_key` /
//! `apply_add` / `apply_remove`), which both `LocalFsStore` and the
//! operator-store-server drive. What IS shared here is the A8 wire
//! vocabulary: the request payload and the three outcome shapes the
//! `HttpEnvironmentStore` client decodes and the server serializes.

use serde::{Deserialize, Serialize};

/// Request body for `POST /environments/{env_id}/trust-root/keys`
/// (`EnvironmentMutations::add_trusted_key`). `key_id` must match the
/// canonical derivation from `public_key_pem` — the backend validates via
/// `greentic-operator-trust`'s `validate_trusted_key`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddTrustedKeyPayload {
    pub key_id: String,
    pub public_key_pem: String,
}

/// Outcome of seeding the bootstrap trust root for an env (the operator
/// signing key for revenue policies and other env-scoped DSSE artifacts).
///
/// `trusted_key_count` is the post-add total — the CLI surfaces it on the
/// wire so operators can see at a glance whether they added a duplicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootSeed {
    pub key_id: String,
    pub public_key_pem: String,
    pub trusted_key_count: usize,
}

/// Outcome of `EnvironmentMutations::add_trusted_key`. The store returns
/// typed data so every backend stays uniform; the CLI shapes the wire JSON
/// (adding `environment_id` from the caller's request context).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootAddOutcome {
    pub added_key_id: String,
    pub trusted_key_count: usize,
}

/// Outcome of `EnvironmentMutations::remove_trusted_key`.
/// `removed_public_key_pem` is `None` when the key was already absent
/// (silent no-op); the HTTP backend MUST cache the original `Some(pem)`
/// against the idempotency key so a retry returns the original PEM rather
/// than `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootRemoveOutcome {
    pub removed_key_id: String,
    /// Stays a bare `Option` (no `skip_serializing_if`): the local CLI wire
    /// shape emits an explicit `null` for the no-op case, so the remote
    /// encoding pins the same.
    pub removed_public_key_pem: Option<String>,
    pub trusted_key_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Wire-format pins: these encodings were established by the PR-3b
    // `HttpEnvironmentStore` client DTOs (deleted in PR-4.2f in favour of
    // these shared structs). Changing them breaks deployed client/server
    // pairs.

    #[test]
    fn add_payload_encoding_is_pinned() {
        let payload = AddTrustedKeyPayload {
            key_id: "abc123".to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            json!({"key_id": "abc123", "public_key_pem": "-----BEGIN PUBLIC KEY-----"})
        );
    }

    #[test]
    fn seed_encoding_is_pinned() {
        let seed = TrustRootSeed {
            key_id: "abc123".to_string(),
            public_key_pem: "pem".to_string(),
            trusted_key_count: 1,
        };
        assert_eq!(
            serde_json::to_value(&seed).unwrap(),
            json!({"key_id": "abc123", "public_key_pem": "pem", "trusted_key_count": 1})
        );
        // The seed-if-absent no-op travels as a JSON `null` result.
        assert_eq!(
            serde_json::to_value(Option::<TrustRootSeed>::None).unwrap(),
            json!(null)
        );
    }

    #[test]
    fn add_outcome_encoding_is_pinned() {
        let outcome = TrustRootAddOutcome {
            added_key_id: "abc123".to_string(),
            trusted_key_count: 2,
        };
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            json!({"added_key_id": "abc123", "trusted_key_count": 2})
        );
    }

    #[test]
    fn remove_outcome_encodes_noop_pem_as_explicit_null() {
        let outcome = TrustRootRemoveOutcome {
            removed_key_id: "abc123".to_string(),
            removed_public_key_pem: None,
            trusted_key_count: 0,
        };
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            json!({
                "removed_key_id": "abc123",
                "removed_public_key_pem": null,
                "trusted_key_count": 0
            })
        );
    }

    #[test]
    fn outcomes_round_trip() {
        let removed = TrustRootRemoveOutcome {
            removed_key_id: "abc123".to_string(),
            removed_public_key_pem: Some("pem".to_string()),
            trusted_key_count: 1,
        };
        let parsed: TrustRootRemoveOutcome =
            serde_json::from_str(&serde_json::to_string(&removed).unwrap()).unwrap();
        assert_eq!(parsed, removed);
    }
}
