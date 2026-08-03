//! Pushing a bundle to an OCI registry (Google Artifact Registry).

use std::path::Path;

use greentic_distributor_client::oci_distribution;
use greentic_distributor_client::oci_packs::DefaultRegistryClient;
use greentic_distributor_client::oci_push::{OciPushError, RegistryPusher, push_pack_with_client};

use crate::bundle_upload::error::{BundleUploadError, BundleUploadResult};
use crate::bundle_upload::types::{UploadOptions, UploadedBundle};
use crate::bundle_upload::uploader::BundleUploader;
use crate::env_packs::gcp_cloudrun::credentials;

/// A validated `oci://` push target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciTarget {
    /// Registry host, e.g. `asia-southeast1-docker.pkg.dev`.
    pub registry: String,
    /// The reference without the `oci://` scheme, as `oci-distribution` wants it.
    pub reference: String,
}

impl OciTarget {
    pub fn parse(url: &str) -> BundleUploadResult<Self> {
        let rest = url.strip_prefix("oci://").ok_or_else(|| {
            BundleUploadError::InvalidUrl(format!("expected an oci:// target, got `{url}`"))
        })?;
        let registry = rest
            .split('/')
            .next()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| {
                BundleUploadError::InvalidUrl(format!(
                    "oci:// target has no registry host: `{url}`"
                ))
            })?
            .to_string();
        // A tag is required: the epic derives it from the bundle's content
        // digest, and defaulting to `latest` would let two deploys disagree
        // about what one reference means.
        let path_after_host = &rest[registry.len()..];
        if !path_after_host.contains(':') {
            return Err(BundleUploadError::InvalidUrl(format!(
                "oci:// target needs an explicit tag, e.g. `…/worker:abc123`: `{url}`"
            )));
        }
        Ok(Self {
            registry,
            reference: rest.to_string(),
        })
    }

    /// Best-effort decomposition of a Google Artifact Registry reference into
    /// `(project, repository, location)`, used only to build
    /// [`BundleUploadError::OciRepositoryMissing`]'s actionable `gcloud`
    /// command. `None` when the registry host is not a `*-docker.pkg.dev` GAR
    /// host, or the reference has fewer path segments than a GAR reference
    /// requires (`<location>-docker.pkg.dev/<project>/<repository>/<image>:<tag>`)
    /// — the existing generic error mapping covers those instead of guessing.
    fn gar_project_repository_location(&self) -> Option<(String, String, String)> {
        let location = self.registry.strip_suffix("-docker.pkg.dev")?.to_string();
        let path_after_host = self.reference.strip_prefix(&self.registry)?;
        let mut segments = path_after_host.trim_start_matches('/').splitn(3, '/');
        let project = segments.next()?.to_string();
        let repository = segments.next()?.to_string();
        segments.next()?; // the `<image>:<tag>` segment must exist too
        Some((project, repository, location))
    }
}

/// Push `bundle` to `target` using an injected pusher, authenticated as
/// `principal`.
///
/// The pusher is a parameter so this is testable without a registry, a network,
/// or GCP; the CLI path passes a `DefaultRegistryClient` built with a fresh GAR
/// token. `principal` plays no role in authentication — the pusher already
/// carries the credential — it is used only to name who was denied if the
/// registry answers with a permission error (see `classify_push_error` below).
///
/// `UploadedBundle::digest` is the CONTENT digest of the bundle bytes. It goes
/// in a manifest's `bundle_digest`. It must NEVER be appended to the reference
/// as `@sha256:…` — a registry resolves that against the *manifest* digest,
/// which is a different value.
///
/// Memory, deliberately accepted: this reads the whole bundle in, and
/// `push_pack_with_client` copies it again into an `ImageLayer`, so a large
/// bundle is held twice. `sha256_file` (`src/cli/bundle_stage.rs:420`) streams
/// specifically to avoid that, so the asymmetry is real — but `oci-distribution`
/// 0.11's `ImageLayer` owns its data and offers no streaming push.
pub async fn push_bundle_with<P: RegistryPusher>(
    pusher: &P,
    target: &OciTarget,
    bundle: &Path,
    principal: &str,
) -> BundleUploadResult<UploadedBundle> {
    let bytes = std::fs::read(bundle).map_err(|e| {
        BundleUploadError::InvalidUrl(format!("cannot read bundle {}: {e}", bundle.display()))
    })?;
    let pushed = push_pack_with_client(pusher, &target.reference, &bytes)
        .await
        .map_err(|e| classify_push_error(e, target, principal))?;
    Ok(UploadedBundle {
        url: format!("oci://{}", pushed.reference),
        digest: pushed.digest,
        // An OCI reference is not presigned; there is nothing to expire.
        expires_at: None,
        object_ref: pushed.reference,
    })
}

/// Map a registry push failure onto an actionable error where the failure is
/// the operator's to fix. Anything else keeps the existing generic mapping —
/// reclassifying an unrecognised failure into a friendlier one would hide it,
/// which is the defect this epic keeps closing.
///
/// A missing Artifact Registry repository answers with the OCI distribution
/// spec's `NAME_UNKNOWN` code (conventionally HTTP 404). We deliberately never
/// create the repository ourselves: that needs
/// `artifactregistry.repositories.create`, a far broader grant, and would
/// make resources inside someone's project unasked. A denied write answers
/// with `DENIED` (conventionally HTTP 403).
fn classify_push_error(
    err: OciPushError,
    target: &OciTarget,
    principal: &str,
) -> BundleUploadError {
    if let OciPushError::Registry(oci_distribution::errors::OciDistributionError::RegistryError {
        envelope,
        ..
    }) = &err
    {
        let codes = envelope.errors.iter().map(|e| &e.code);
        for code in codes {
            match code {
                oci_distribution::errors::OciErrorCode::NameUnknown => {
                    if let Some((project, repository, location)) =
                        target.gar_project_repository_location()
                    {
                        return BundleUploadError::OciRepositoryMissing {
                            repository,
                            project,
                            location,
                        };
                    }
                }
                oci_distribution::errors::OciErrorCode::Denied => {
                    return BundleUploadError::OciPushDenied {
                        principal: principal.to_string(),
                    };
                }
                _ => {}
            }
        }
    }
    BundleUploadError::Other(format!("push failed: {err}"))
}

/// Pushes bundles to an OCI registry. Holds only the target: the GAR token is
/// minted per upload because it is short-lived, and `DefaultRegistryClient`
/// freezes whatever credential it is built with.
#[derive(Debug)]
pub struct OciBundleUploader {
    target: OciTarget,
}

impl OciBundleUploader {
    pub fn new(target: OciTarget) -> Self {
        Self { target }
    }
}

#[async_trait::async_trait]
impl BundleUploader for OciBundleUploader {
    async fn upload(
        &self,
        bundle_path: &Path,
        // Nothing about an OCI push is presigned — a GAR reference has no
        // expiry to control — so `presign_expires_secs` does not apply here.
        // Bound to `_opts` rather than dropped from the signature so a reader
        // does not wonder whether expiry handling was forgotten.
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        let client = credentials::build_ambient_client()
            .map_err(|e| BundleUploadError::Other(format!("resolving GCP credentials: {e}")))?;
        // Only needed to name who was denied if the push fails with 403 — the
        // push itself authenticates with the access token below, not this.
        let identity = client.get_caller_identity().await.map_err(|e| {
            BundleUploadError::Other(format!("resolving the GCP caller identity: {e}"))
        })?;
        // Minted per upload, never cached: Artifact Registry OAuth2 tokens are
        // short-lived, and `DefaultRegistryClient` freezes whatever credential
        // it is built with for its own lifetime, so a fresh client is built
        // per push rather than reused across pushes.
        let token = client
            .access_token()
            .await
            .map_err(|e| BundleUploadError::Other(format!("minting a GAR access token: {e}")))?;
        let pusher = DefaultRegistryClient::with_basic_auth("oauth2accesstoken", token);
        push_bundle_with(&pusher, &self.target, bundle_path, &identity.email).await
    }

    async fn refresh_url(
        &self,
        object_ref: &str,
        // See `upload`: an OCI reference has nothing to expire, so there is
        // nothing for `presign_expires_secs` to control here either.
        _opts: &UploadOptions,
    ) -> BundleUploadResult<UploadedBundle> {
        // An OCI reference cannot expire, so returning the same reference
        // unchanged is the correct answer here, not a stub — there is nothing
        // to re-issue. The digest IS recoverable, but only via a network
        // round-trip (re-pulling the manifest to recompute the content
        // digest), which this call does not perform; fabricating a digest
        // instead would let a wrong value fail closed at deploy time in
        // another repo rather than failing honestly here.
        Err(BundleUploadError::Other(format!(
            "refreshing oci:// reference `{object_ref}` would require a network round-trip to \
             recover its content digest, which is not implemented; the reference itself does not \
             expire, so re-issuing it is unnecessary"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gar_reference_is_parsed_into_its_parts() {
        let target = OciTarget::parse(
            "oci://asia-southeast1-docker.pkg.dev/my-proj/greentic/worker-a:abc123def456",
        )
        .expect("valid GAR reference");
        assert_eq!(target.registry, "asia-southeast1-docker.pkg.dev");
        assert_eq!(
            target.reference,
            "asia-southeast1-docker.pkg.dev/my-proj/greentic/worker-a:abc123def456"
        );
    }

    #[test]
    fn the_oci_scheme_is_required() {
        let err = OciTarget::parse("https://example.test/x:1").unwrap_err();
        assert!(
            format!("{err}").contains("oci://"),
            "error should name the expected scheme: {err}"
        );
    }

    #[test]
    fn a_reference_without_a_tag_is_rejected() {
        // The epic derives the tag from the bundle's content digest, so an
        // untagged reference means the caller forgot it — not that we should
        // invent `latest`, which would let two deploys disagree about what a
        // reference means.
        let err =
            OciTarget::parse("oci://asia-southeast1-docker.pkg.dev/my-proj/greentic/worker-a")
                .unwrap_err();
        assert!(
            format!("{err}").contains("tag"),
            "error should name the missing tag: {err}"
        );
    }

    #[test]
    fn a_registry_host_colon_port_is_not_mistaken_for_a_tag_separator() {
        // The tag search must start after the registry host, not from byte 0
        // of the whole reference — a bare `rest.contains(':')` would treat a
        // registry port (`localhost:5000`) as satisfying the tag requirement
        // even when the image path after it has none.
        let err = OciTarget::parse("oci://localhost:5000/x/y").unwrap_err();
        assert!(
            format!("{err}").contains("tag"),
            "a host with a port but no image tag must still be rejected: {err}"
        );
    }

    #[test]
    fn a_tag_after_a_registry_host_colon_port_is_accepted() {
        let target = OciTarget::parse("oci://localhost:5000/x/y:tag").expect("valid reference");
        assert_eq!(target.registry, "localhost:5000");
        assert_eq!(target.reference, "localhost:5000/x/y:tag");
    }

    use std::sync::Mutex;

    /// Records what would have been pushed, so the upload path is testable
    /// without a registry, a network, or GCP.
    #[derive(Default)]
    struct RecordingPusher {
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl greentic_distributor_client::oci_push::RegistryPusher for RecordingPusher {
        async fn push_artifact(
            &self,
            reference: &oci_distribution::Reference,
            bytes: &[u8],
            _media_type: &str,
        ) -> Result<(), oci_distribution::errors::OciDistributionError> {
            self.calls
                .lock()
                .unwrap()
                .push((reference.whole(), bytes.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn upload_pushes_the_bundle_bytes_and_returns_the_oci_ref_with_its_content_digest() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("worker.gtbundle");
        // SquashFS magic — the shape a real .gtbundle takes.
        std::fs::write(&bundle, b"hsqs\x00\x01\x02\x03payload").unwrap();

        let pusher = RecordingPusher::default();
        let outcome = push_bundle_with(
            &pusher,
            &OciTarget::parse("oci://r.example.test/p/greentic/worker-a:abc123").unwrap(),
            &bundle,
            "deployer@my-proj.iam.gserviceaccount.com",
        )
        .await
        .expect("push succeeds");

        let calls = pusher.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "r.example.test/p/greentic/worker-a:abc123");
        assert_eq!(calls[0].1, b"hsqs\x00\x01\x02\x03payload");

        assert_eq!(
            outcome.url,
            "oci://r.example.test/p/greentic/worker-a:abc123"
        );
        // Pinned exact value, not just the `sha256:` prefix, so a regression
        // that hashed the wrong buffer (e.g. an empty or truncated read)
        // would be caught. Computed with:
        //   printf 'hsqs\x00\x01\x02\x03payload' | sha256sum
        assert_eq!(
            outcome.digest,
            "sha256:6ce6c48d3210a2ab08af08fcc0e09d571dddf0132235724e93a37c008631847e"
        );
        assert!(
            outcome.expires_at.is_none(),
            "an OCI reference is not presigned and cannot expire"
        );
    }
}
