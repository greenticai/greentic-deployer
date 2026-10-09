//! The process-default rustls `CryptoProvider`.
//!
//! rustls 0.23 refuses to auto-select a provider when more than one is
//! compiled in, and this binary links both: `ring` (kube's bundled TLS) and
//! `aws-lc-rs` (the AWS SDK's). Without an explicit default, the first TLS
//! handshake panics.
//!
//! This lives at process level rather than beside any one client because the
//! failure is not a property of any single subsystem. It was installed only by
//! the Kubernetes client, so every GCP path panicked before sending a single
//! request — `google-cloud-auth` aborts in its own `crypto_provider` module,
//! which then leaves `token_cache` unwrapping a closed channel. The symptom
//! reads as a GCP credential bug and is not one.

/// Install `ring` as the process default, once, if nothing has claimed the
/// slot yet.
///
/// Idempotent by construction: an already-installed provider wins and this is
/// a no-op, so a later caller (another subsystem, or a future dependency
/// default) is never overridden.
#[cfg(any(feature = "k8s-client", feature = "deploy-gcp-cloudrun"))]
pub fn install_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// No TLS-using feature is enabled, so no provider is linked to install.
#[cfg(not(any(feature = "k8s-client", feature = "deploy-gcp-cloudrun")))]
pub fn install_default_crypto_provider() {}

#[cfg(test)]
mod tests {
    /// The point of the module: after startup, a provider is installed.
    ///
    /// Asserted through `get_default()` rather than through the installer's
    /// return value, because the installer deliberately swallows a lost race —
    /// what matters to every later TLS handshake is that the slot is filled,
    /// not who filled it.
    #[cfg(any(feature = "k8s-client", feature = "deploy-gcp-cloudrun"))]
    #[test]
    fn a_provider_is_installed_and_installing_twice_is_harmless() {
        super::install_default_crypto_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "no process-default provider after install; every TLS path panics"
        );
        // Idempotent: the second call must not panic or unset anything.
        super::install_default_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
