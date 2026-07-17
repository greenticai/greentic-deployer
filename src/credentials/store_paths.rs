//! Canonical dev-store paths at which a deployer env-pack's
//! [`bootstrap`](super::DeployerCredentials::bootstrap) lands the bound
//! credential material it minted.
//!
//! These live here — beside the credentials contract, in an always-compiled
//! module — rather than inside each env-pack, for two reasons:
//!
//! 1. **Single source of truth.** The minting handlers build their
//!    `bound_credentials_ref` from these constants and the runtime-seed denylist
//!    (`cli::env::staging_excluded_uris`) excludes them, so the writer and the
//!    denylist provably cannot drift.
//! 2. **Feature independence.** A dev-store outlives the binary that wrote it.
//!    An AWS-capable build can land material at [`AWS_DEPLOYER_SESSION`] and
//!    crash; a later build compiled *without* `creds-aws` must still strip that
//!    material from any seed it stages. Gating the denylist on the SDK features
//!    of the *current* binary would reintroduce the leak, so the list is
//!    unconditional and additive: paths are only ever added, never removed.

/// Where the K8s bootstrap's `--bind` path lands the minted ServiceAccount
/// bearer. Aliased as `env_packs::k8s::bootstrap::DEPLOYER_TOKEN_STORE_PATH`.
pub(crate) const K8S_DEPLOYER_TOKEN: &str = "default/_/k8s-deployer/deployer_token";

/// Where the AWS bootstrap lands the assumed STS session. Aliased as
/// `env_packs::aws::credentials::DEPLOYER_SESSION_STORE_PATH`.
pub(crate) const AWS_DEPLOYER_SESSION: &str = "default/_/aws-deployer/deployer_session";

/// Every store-relative path at which a built-in deployer bootstrap has ever
/// landed bound credential material, `secret://<env>/<path>`-relative.
///
/// **Control-plane namespace.** These paths are reserved for the deployer's own
/// credentials; runtime material must not be written to them. Everything listed
/// is stripped from every staged runtime seed unconditionally — see
/// `cli::env::staging_excluded_uris` for why `credentials_ref` alone is not
/// enough (the bootstrap W1/W2 orphan window).
///
/// **Adding a deployer env-pack that mints bind material?** Its landing path
/// MUST be added here, or a crashed bootstrap can orphan a credential that the
/// seed denylist will miss. Only env-packs whose `bootstrap` returns
/// `bound_credentials_ref: Some(_)` need an entry: the GCP Cloud Run bootstrap
/// is render-only and writes no material, so it has none.
pub(crate) const BOUND_CREDENTIAL_STORE_PATHS: &[&str] =
    &[K8S_DEPLOYER_TOKEN, AWS_DEPLOYER_SESSION];

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift guard: the constants the minting handlers build their bound ref
    /// from must be the ones the denylist strips. Renaming one without the
    /// other would silently reopen the orphan leak.
    #[test]
    fn every_minting_handler_path_is_in_the_denylist() {
        assert!(
            BOUND_CREDENTIAL_STORE_PATHS
                .contains(&crate::env_packs::k8s::bootstrap::DEPLOYER_TOKEN_STORE_PATH),
            "the k8s bootstrap's landing path must be excluded from staged seeds"
        );
        #[cfg(feature = "creds-aws")]
        assert!(
            BOUND_CREDENTIAL_STORE_PATHS
                .contains(&crate::env_packs::aws::credentials::DEPLOYER_SESSION_STORE_PATH),
            "the aws bootstrap's landing path must be excluded from staged seeds"
        );
    }

    /// The denylist must not depend on which provider SDK features this binary
    /// compiled: a dev-store written by a fuller build outlives it.
    ///
    /// Note this assertion can only *bite* when compiled without `creds-aws`
    /// (`cargo test --lib --no-default-features`); a cfg-gated entry looks
    /// identical under the default feature set. CI builds that configuration but
    /// does not test it, so the real guard against regression is that
    /// [`BOUND_CREDENTIAL_STORE_PATHS`] is a plain unconditional const — keep it
    /// that way.
    #[test]
    fn denylist_is_feature_independent() {
        assert!(
            BOUND_CREDENTIAL_STORE_PATHS.contains(&AWS_DEPLOYER_SESSION),
            "the AWS path must be excluded even in a build without `creds-aws` — \
             an AWS-capable build can have orphaned material there"
        );
        assert!(BOUND_CREDENTIAL_STORE_PATHS.contains(&K8S_DEPLOYER_TOKEN));
    }

    /// Entries must be canonical four-segment store-relative paths, so
    /// `secret://<env>/<path>` parses as a store-aligned ref.
    #[test]
    fn paths_are_canonical_four_segment_store_relative() {
        for path in BOUND_CREDENTIAL_STORE_PATHS {
            assert_eq!(
                path.split('/').count(),
                4,
                "`{path}` must be <tenant>/<team>/<category>/<name>"
            );
            assert!(!path.starts_with('/'), "`{path}` must be store-relative");
        }
    }
}
