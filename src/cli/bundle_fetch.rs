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
    #[cfg(test)]
    if let Some(result) = test_seam::intercept(reference) {
        return result;
    }
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
            //
            // Amazon ECR is the same shape: a pull needs a credential, and the
            // only one this process is handed is the `OCI_USERNAME` /
            // `OCI_PASSWORD` pair the caller minted from `ecr:GetAuthorizationToken`
            // (the same pair that authenticates the worker's own boot pull).
            let fetcher: OciPackFetcher<DefaultRegistryClient> =
                match artifact_registry_client(&rt, oci_ref).or_else(|| ecr_client(oci_ref)) {
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

/// Whether `host` is an Amazon ECR registry endpoint:
/// `<12 digits>.dkr.ecr[-fips].<region>.amazonaws.com[.cn]`.
///
/// Deliberately strict. The credential below is attached to a host only when
/// this matches, so a manifest that also names `ghcr.io` or a customer's own
/// registry never receives an ECR token.
fn is_ecr_host(host: &str) -> bool {
    let host = host.split(':').next().unwrap_or_default();
    let Some((account, rest)) = host.split_once('.') else {
        return false;
    };
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(rest) = rest
        .strip_prefix("dkr.ecr.")
        .or_else(|| rest.strip_prefix("dkr.ecr-fips."))
    else {
        return false;
    };
    let Some(region) = rest
        .strip_suffix(".amazonaws.com")
        .or_else(|| rest.strip_suffix(".amazonaws.com.cn"))
    else {
        return false;
    };
    !region.is_empty()
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The `OCI_USERNAME` / `OCI_PASSWORD` pair, only when both are non-empty —
/// the rule greentic-start applies to its own boot pull
/// (`bundle_ref::generic_registry_credentials`), so the two processes
/// authenticate the same reference the same way.
fn oci_credentials_from(get: impl Fn(&str) -> Option<String>) -> Option<(String, String)> {
    let non_blank = |name: &str| get(name).filter(|v| !v.trim().is_empty());
    Some((non_blank("OCI_USERNAME")?, non_blank("OCI_PASSWORD")?))
}

/// An authenticated client for an Amazon ECR reference when `credentials` is
/// present, else `None` (the anonymous client then lets the registry report
/// the denial itself, exactly as for any other host).
fn ecr_client_with(
    oci_ref: &str,
    credentials: Option<(String, String)>,
) -> Option<DefaultRegistryClient> {
    let host = oci_ref
        .trim_start_matches(OCI_SCHEME)
        .split('/')
        .next()
        .unwrap_or_default();
    if !is_ecr_host(host) {
        return None;
    }
    let (user, password) = credentials?;
    Some(DefaultRegistryClient::with_basic_auth(user, password))
}

fn ecr_client(oci_ref: &str) -> Option<DefaultRegistryClient> {
    ecr_client_with(
        oci_ref,
        oci_credentials_from(|name| std::env::var(name).ok()),
    )
}

/// Host suffix that identifies a Google Artifact Registry reference.
#[cfg(feature = "deploy-gcp-cloudrun")]
const ARTIFACT_REGISTRY_SUFFIX: &str = "-docker.pkg.dev";

/// An authenticated registry client for a Google Artifact Registry reference,
/// or `None` for any other host.
///
/// Returns `None` rather than an error when the credential cannot be resolved:
/// the caller then falls back to the anonymous client and the registry reports
/// the denial itself. Failing here instead would turn "this deployment has no
/// GCP credential" into a fetch error on references that never needed one.
///
/// Gated on `deploy-gcp-cloudrun` (not the narrower `creds-gcp`) because it
/// calls `credentials::build_ambient_client`, which reaches the real
/// `google-cloud-auth`-backed client and only exists under that feature. A
/// `creds-gcp`-only build (the seam/fake/orchestration slice) has no ambient
/// client to build, so it falls through to the `None`-returning stub below.
#[cfg(feature = "deploy-gcp-cloudrun")]
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

/// Without the real GCP credential stack there is nothing to authenticate
/// with — including under `creds-gcp` alone, which has the seam and the fake
/// but no ambient-ADC client.
#[cfg(not(feature = "deploy-gcp-cloudrun"))]
fn artifact_registry_client(
    _rt: &tokio::runtime::Runtime,
    _oci_ref: &str,
) -> Option<DefaultRegistryClient> {
    None
}

/// Test-only fetch seam: lets apply tests serve a URI from a local fixture
/// and count how many pulls a plan/apply performed, without a registry.
/// Thread-local, so parallel tests never see each other's overrides.
#[cfg(test)]
pub(crate) mod test_seam {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::OpError;

    #[derive(Default)]
    struct Seam {
        served: BTreeMap<String, PathBuf>,
        fetches: Vec<String>,
    }

    thread_local! {
        static SEAM: RefCell<Option<Seam>> = const { RefCell::new(None) };
    }

    /// Serve `uri` from `path` for the rest of this thread's test. Installing
    /// the first entry also turns on fetch recording.
    pub(crate) fn serve(uri: &str, path: PathBuf) {
        SEAM.with(|s| {
            s.borrow_mut()
                .get_or_insert_with(Seam::default)
                .served
                .insert(uri.to_string(), path);
        });
    }

    /// Stop serving `uri` (a later fetch of it fails like an unreachable
    /// registry).
    pub(crate) fn unserve(uri: &str) {
        SEAM.with(|s| {
            if let Some(seam) = s.borrow_mut().as_mut() {
                seam.served.remove(uri);
            }
        });
    }

    /// Every URI fetched on this thread since the seam was installed.
    pub(crate) fn fetched() -> Vec<String> {
        SEAM.with(|s| {
            s.borrow()
                .as_ref()
                .map(|s| s.fetches.clone())
                .unwrap_or_default()
        })
    }

    /// Forget the recorded fetches (keep the served URIs).
    pub(crate) fn reset_fetched() {
        SEAM.with(|s| {
            if let Some(seam) = s.borrow_mut().as_mut() {
                seam.fetches.clear();
            }
        });
    }

    /// `Some` when the seam is installed on this thread: the served path, or
    /// a `Fetch` error for an unknown URI (never a real network pull).
    pub(super) fn intercept(reference: &str) -> Option<Result<PathBuf, OpError>> {
        SEAM.with(|s| {
            let mut guard = s.borrow_mut();
            let seam = guard.as_mut()?;
            seam.fetches.push(reference.to_string());
            Some(seam.served.get(reference).cloned().ok_or_else(|| {
                OpError::Fetch(format!("test seam: nothing served at `{reference}`"))
            }))
        })
    }
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
    fn ecr_hosts_are_recognised_and_nothing_else_is() {
        for host in [
            "599558443099.dkr.ecr.ap-southeast-1.amazonaws.com",
            "599558443099.dkr.ecr-fips.us-gov-west-1.amazonaws.com",
            "599558443099.dkr.ecr.cn-north-1.amazonaws.com.cn",
            "599558443099.dkr.ecr.eu-west-1.amazonaws.com:443",
        ] {
            assert!(is_ecr_host(host), "{host} is an ECR endpoint");
        }
        for host in [
            "ghcr.io",
            "docker.io",
            "us-docker.pkg.dev",
            "59955844309.dkr.ecr.eu-west-1.amazonaws.com",
            "5995584430999.dkr.ecr.eu-west-1.amazonaws.com",
            "abcdefghijkl.dkr.ecr.eu-west-1.amazonaws.com",
            "599558443099.dkr.ecr..amazonaws.com",
            "599558443099.dkr.ecr.eu-west-1.amazonaws.com.evil.example",
            "evil.example/599558443099.dkr.ecr.eu-west-1.amazonaws.com",
            "",
        ] {
            assert!(!is_ecr_host(host), "{host:?} is not an ECR endpoint");
        }
    }

    #[test]
    fn the_credential_needs_both_halves() {
        let env = |user: Option<&'static str>, pass: Option<&'static str>| {
            oci_credentials_from(move |name| match name {
                "OCI_USERNAME" => user.map(str::to_string),
                "OCI_PASSWORD" => pass.map(str::to_string),
                _ => None,
            })
        };
        assert_eq!(
            env(Some("AWS"), Some("tok")),
            Some(("AWS".into(), "tok".into()))
        );
        assert_eq!(env(Some("AWS"), None), None);
        assert_eq!(env(None, Some("tok")), None);
        assert_eq!(env(Some("AWS"), Some("  ")), None);
    }

    #[test]
    fn only_an_ecr_host_ever_gets_the_credential() {
        let creds = || Some(("AWS".to_string(), "tok".to_string()));
        assert!(ecr_client_with("oci://ghcr.io/greenticai/x:v1", creds()).is_none());
        assert!(
            ecr_client_with(
                "oci://599558443099.dkr.ecr.eu-west-1.amazonaws.com/r:t",
                creds()
            )
            .is_some()
        );
        assert!(
            ecr_client_with(
                "oci://599558443099.dkr.ecr.eu-west-1.amazonaws.com/r:t",
                None
            )
            .is_none(),
            "no credential handed over: stay anonymous"
        );
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
