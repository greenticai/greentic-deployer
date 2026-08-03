//! Pushing a bundle to an OCI registry (Google Artifact Registry).

use std::path::Path;

use greentic_distributor_client::oci_push::{RegistryPusher, push_pack_with_client};

use crate::bundle_upload::error::{BundleUploadError, BundleUploadResult};
use crate::bundle_upload::types::UploadedBundle;

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
}

/// Push `bundle` to `target` using an injected pusher.
///
/// The pusher is a parameter so this is testable without a registry, a network,
/// or GCP; the CLI path passes a `DefaultRegistryClient` built with a fresh GAR
/// token.
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
) -> BundleUploadResult<UploadedBundle> {
    let bytes = std::fs::read(bundle).map_err(|e| {
        BundleUploadError::InvalidUrl(format!("cannot read bundle {}: {e}", bundle.display()))
    })?;
    let pushed = push_pack_with_client(pusher, &target.reference, &bytes)
        .await
        .map_err(|e| BundleUploadError::InvalidUrl(format!("push failed: {e}")))?;
    Ok(UploadedBundle {
        url: format!("oci://{}", pushed.reference),
        digest: pushed.digest,
        // An OCI reference is not presigned; there is nothing to expire.
        expires_at: None,
        object_ref: pushed.reference,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_distributor_client::oci_distribution;

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
        assert!(
            outcome.digest.starts_with("sha256:"),
            "digest must be the sha256:<hex> content digest: {}",
            outcome.digest
        );
        assert!(
            outcome.expires_at.is_none(),
            "an OCI reference is not presigned and cannot expire"
        );
    }
}
