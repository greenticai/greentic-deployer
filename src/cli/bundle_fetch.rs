//! Fetch a `.gtbundle` from a remote `bundle_source_uri` to a local file, so
//! `op env apply` can stage a revision from a registry reference without a local
//! `bundle_path` on the apply host.
//!
//! v1 resolves `oci://` references only. Other schemes (`repo://`, `store://`,
//! `http(s)://`, local paths) return [`OpError::NotYetImplemented`] — author
//! those with a local `bundle_path` until the richer scheme handling in
//! `greentic-start`'s `bundle_ref::fetch_bundle_to_file` (which this
//! intentionally mirrors, restricted to the apply case) is consolidated into a
//! crate both repos can share. That consolidation is a tracked follow-up; this
//! module deliberately duplicates the minimal `oci://` path rather than taking
//! a dependency on `greentic-start` (which depends on this crate).
//!
//! The fetch is HTTPS-only and performs NO integrity check of its own: an
//! `oci://…@sha256:…` resolved digest is the *manifest* digest, not the
//! `.gtbundle` byte digest. The caller (`env_apply`) hashes the returned file
//! and gates it against the manifest's `bundle_digest`, and the K8s worker
//! re-verifies at boot (`materialize_revision_from_bundle`). Pulling over HTTPS
//! to the real registry is the apply-host analog of the worker's digest-gated
//! boot pull.

use std::path::PathBuf;

use greentic_distributor_client::oci_packs::DefaultRegistryClient;
use greentic_distributor_client::{OciPackFetcher, PackFetchOptions};

use super::OpError;

/// Scheme prefix this module resolves. Everything else routes to `bundle_path`.
const OCI_SCHEME: &str = "oci://";

/// Fetch the `.gtbundle` archive at `reference` to a local cache file and return
/// its path.
///
/// The returned path lives in the distributor's content-addressed cache; the
/// caller copies it into the env's revision directory during staging, so there
/// is nothing to clean up here. The returned file is the raw archive — the
/// caller owns the digest gate against the manifest's `bundle_digest`.
///
/// Only `oci://host/repo:tag` / `oci://host/repo@sha256:…` references are
/// supported; any other scheme is [`OpError::NotYetImplemented`].
pub fn fetch_bundle_uri_to_local(reference: &str) -> Result<PathBuf, OpError> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_source_uri cannot be empty".to_string(),
        ));
    }
    let oci_ref = trimmed.strip_prefix(OCI_SCHEME).ok_or_else(|| {
        OpError::NotYetImplemented(format!(
            "apply can only fetch `oci://` bundle_source_uri references; `{trimmed}` is \
             unsupported — declare a local `bundle_path` instead"
        ))
    })?;
    if oci_ref.is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "bundle_source_uri `{trimmed}` has no registry reference after `{OCI_SCHEME}`"
        )));
    }
    fetch_oci_to_cache(oci_ref)
}

/// Run the async OCI pull on a dedicated thread so it never nests inside the
/// command dispatcher's current-thread Tokio runtime: `main.rs` drives every
/// `op` verb under `block_on`, and building a second runtime to `block_on` from
/// within the first panics ("Cannot start a runtime from within a runtime"). A
/// scoped thread builds its own runtime off the ambient one. The fetch is a
/// one-shot network pull, so the extra thread is negligible.
fn fetch_oci_to_cache(oci_ref: &str) -> Result<PathBuf, OpError> {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| -> Result<PathBuf, OpError> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| OpError::Fetch(format!("build oci fetch runtime: {source}")))?;
            // `allow_tags` so `:tag` refs resolve (the deploy demo uses `:v1`);
            // `offline: false` so a cold cache pulls from the registry.
            let opts = PackFetchOptions {
                allow_tags: true,
                offline: false,
                ..PackFetchOptions::default()
            };
            // Google Artifact Registry authenticates PULLS as well as pushes,
            // and the default client pulls anonymously — so a bundle this same
            // binary had just pushed came back `Not authorized`, reported as a
            // missing input rather than as a credential problem. Mint the same
            // short-lived OAuth token the push path uses, for AR hosts only:
            // every other registry keeps the anonymous client, which is what
            // public packs need.
            let fetcher: OciPackFetcher<DefaultRegistryClient> =
                match artifact_registry_client(&rt, oci_ref) {
                    Some(client) => OciPackFetcher::with_client(client, opts),
                    None => OciPackFetcher::new(opts),
                };
            rt.block_on(fetcher.fetch_pack_to_cache(oci_ref))
                .map(|resolved| resolved.path)
                .map_err(|source| OpError::Fetch(format!("oci pull `{oci_ref}`: {source}")))
        });
        match handle.join() {
            Ok(result) => result,
            Err(_) => Err(OpError::Fetch("oci fetch thread panicked".to_string())),
        }
    })
}

/// Host suffix that identifies a Google Artifact Registry reference.
const ARTIFACT_REGISTRY_SUFFIX: &str = "-docker.pkg.dev";

/// An authenticated registry client for a Google Artifact Registry reference,
/// or `None` for any other host.
///
/// Returns `None` rather than an error when the credential cannot be resolved:
/// the caller then falls back to the anonymous client and the registry reports
/// the denial itself. Failing here instead would turn "this deployment has no
/// GCP credential" into a fetch error on references that never needed one.
#[cfg(feature = "creds-gcp")]
fn artifact_registry_client(
    rt: &tokio::runtime::Runtime,
    oci_ref: &str,
) -> Option<DefaultRegistryClient> {
    let host = oci_ref
        .trim_start_matches(OCI_SCHEME)
        .split('/')
        .next()
        .unwrap_or_default();
    if !host.ends_with(ARTIFACT_REGISTRY_SUFFIX) {
        return None;
    }
    // Both halves run INSIDE the runtime. `build_ambient_client` reaches
    // `google-cloud-auth`, which `tokio::spawn`s a token-refresh task in its
    // constructor — calling it outside a runtime context panics there rather
    // than returning an error, and the panic surfaces only as "oci fetch
    // thread panicked".
    rt.block_on(async {
        let client = crate::env_packs::gcp_cloudrun::credentials::build_ambient_client().ok()?;
        let token = client.access_token().await.ok()?;
        Some(DefaultRegistryClient::with_basic_auth(
            "oauth2accesstoken",
            token,
        ))
    })
}

/// Without the GCP credential stack there is nothing to authenticate with.
#[cfg(not(feature = "creds-gcp"))]
fn artifact_registry_client(
    _rt: &tokio::runtime::Runtime,
    _oci_ref: &str,
) -> Option<DefaultRegistryClient> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_reference_is_invalid_argument() {
        let err = fetch_bundle_uri_to_local("   ").unwrap_err();
        assert_eq!(err.kind(), "invalid-argument");
    }

    #[test]
    fn oci_scheme_with_no_target_is_invalid_argument() {
        let err = fetch_bundle_uri_to_local("oci://").unwrap_err();
        assert_eq!(err.kind(), "invalid-argument");
    }

    #[test]
    fn local_path_reference_is_not_yet_implemented() {
        let err = fetch_bundle_uri_to_local("/srv/bundles/webchat-bot.gtbundle").unwrap_err();
        assert_eq!(err.kind(), "not-yet-implemented");
    }

    #[test]
    fn repo_scheme_is_not_yet_implemented() {
        let err = fetch_bundle_uri_to_local("repo://acme/webchat-bot:v1").unwrap_err();
        assert_eq!(err.kind(), "not-yet-implemented");
    }

    #[test]
    fn store_scheme_is_not_yet_implemented() {
        let err = fetch_bundle_uri_to_local("store://acme/webchat-bot:v1").unwrap_err();
        assert_eq!(err.kind(), "not-yet-implemented");
    }

    #[test]
    fn https_scheme_is_not_yet_implemented() {
        let err =
            fetch_bundle_uri_to_local("https://example.com/webchat-bot.gtbundle").unwrap_err();
        assert_eq!(err.kind(), "not-yet-implemented");
    }

    #[test]
    fn http_scheme_is_not_yet_implemented() {
        let err = fetch_bundle_uri_to_local("http://example.com/webchat-bot.gtbundle").unwrap_err();
        assert_eq!(err.kind(), "not-yet-implemented");
    }

    #[test]
    fn oci_scheme_trims_surrounding_whitespace() {
        // Whitespace-padded empty ref → the trimmed string `oci://` strips
        // to an empty oci_ref, which should be InvalidArgument, not
        // NotYetImplemented (the strip_prefix succeeds, then the empty check
        // fires).
        let err = fetch_bundle_uri_to_local("  oci://  ").unwrap_err();
        assert_eq!(err.kind(), "invalid-argument");
    }

    #[test]
    fn oci_scheme_with_unreachable_registry_is_fetch_error() {
        // A syntactically valid OCI ref that points at a non-existent host.
        // Exercises the thread-scope + tokio runtime path in fetch_oci_to_cache.
        let err = fetch_bundle_uri_to_local("oci://this-host-does-not-exist.invalid/repo:tag")
            .unwrap_err();
        assert_eq!(err.kind(), "fetch");
    }

    #[test]
    fn oci_scheme_constant_matches_expected_prefix() {
        assert_eq!(OCI_SCHEME, "oci://");
    }

    /// Live OCI pull against the public demo bundle. Ignored by default (needs
    /// network + ghcr reachability); run with `--ignored` locally or in a
    /// network-enabled CI job. Verifies the `oci://` happy path end-to-end:
    /// thread-hop runtime, tag resolution, and a readable archive on disk.
    #[test]
    #[ignore = "network: pulls the public demo bundle from ghcr"]
    fn live_oci_pull_returns_a_readable_archive() {
        let path = fetch_bundle_uri_to_local(
            "oci://ghcr.io/greenticai/greentic-demo-bundles/webchat-bot:v1",
        )
        .expect("pull public demo bundle");
        assert!(
            path.is_file(),
            "fetched bundle should be a file: {}",
            path.display()
        );
        let len = std::fs::metadata(&path).expect("stat fetched bundle").len();
        assert!(len > 0, "fetched bundle should be non-empty");
    }
}
