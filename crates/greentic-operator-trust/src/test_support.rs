//! Test fixtures shared with downstream crates (behind the `test-utils`
//! feature, or `cfg(test)` for this crate's own tests).

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use greentic_distributor_client::signing::key_id_for_public_key_pem;

/// Deterministic Ed25519 fixture keypair: `(public_key_pem, key_id)` derived
/// from a `[seed; 32]` private key. The single source for the helper that
/// used to be copy-pasted into every trust-root test module — when the
/// key-id derivation changes, only this one moves.
pub fn keypair(seed: u8) -> (String, String) {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    let pub_pem = vk.to_public_key_pem(LineEnding::LF).unwrap();
    let key_id = key_id_for_public_key_pem(&pub_pem).unwrap();
    (pub_pem, key_id)
}
