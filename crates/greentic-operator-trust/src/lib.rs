//! Operator signing-key management and trust-root document semantics.
//!
//! Extracted from `greentic-deployer` (PR-4.2e of
//! `plans/next-gen-deployment.md`) so the `greentic-operator-store-server`
//! can drive the SAME key handling and trust-root validation the local
//! file-backed store uses — the trust-domain analogue of the
//! `greentic_deploy_spec::engine` rule that one derivation serves every
//! backend.
//!
//! - [`operator_key`] — hardened load/generate of the operator's Ed25519
//!   keypair (the key that signs revenue-policy DSSE envelopes and, later,
//!   revision manifests).
//! - [`trust_root`] — the `greentic.trust-root.v1` document envelope and
//!   the pure validate/add/remove transforms; persistence (file or SQL)
//!   stays with the caller.
//!
//! Verifier types ([`TrustRoot`](greentic_distributor_client::signing::TrustRoot),
//! [`TrustedKey`](greentic_distributor_client::signing::TrustedKey)) and the
//! canonical key-id derivation come from
//! [`greentic_distributor_client::signing`]; this crate deliberately adds no
//! second derivation path.

pub mod operator_key;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_support;
pub mod trust_root;
