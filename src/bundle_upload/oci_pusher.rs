//! The registry push transport for `oci://` bundle uploads.
//!
//! This exists because the shared `DefaultRegistryClient` cannot push a bundle
//! larger than four mebibytes to Google Artifact Registry, and offers no knob
//! to change that from outside. See [`MonolithicRegistryPusher`] for the whole
//! reasoning; the short version is that it pushes a blob as ONE `PUT` instead
//! of a sequence of `PATCH`es.

use greentic_distributor_client::oci_distribution::Reference;
use greentic_distributor_client::oci_distribution::client::{
    Client, ClientConfig, ClientProtocol, Config, ImageLayer,
};
use greentic_distributor_client::oci_distribution::errors::OciDistributionError;
use greentic_distributor_client::oci_distribution::secrets::RegistryAuth;
use greentic_distributor_client::oci_push::RegistryPusher;

/// The config blob every artifact this crate pushes carries.
///
/// An artifact, not a runnable image: the fetch path
/// (`greentic_distributor_client::oci_packs`) never inspects the config blob's
/// content or media type, so an empty JSON object is the conventional filler.
/// Mirrors what `DefaultRegistryClient`'s own `push_artifact` sends, so moving
/// onto this pusher changes the bytes on the wire in exactly one way — how the
/// LAYER is transferred.
const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";

/// A [`RegistryPusher`] that uploads each blob **monolithically**: one `POST`
/// to open the upload session, then one `PUT` carrying the whole blob.
///
/// # Why this is not `DefaultRegistryClient`
///
/// `oci-client`'s `push_blob` prefers the spec's *chunked* flow (`POST`, then
/// one `PATCH` per `push_chunk_size` bytes — 4 MiB by default — then a final
/// `PUT`). Google Artifact Registry accepts the session `POST` and the FIRST
/// `PATCH`, hands back a different upload location, and then answers a SECOND
/// `PATCH` with `405 Method Not Allowed`: the location it redirected to
/// finishes with `PUT` and takes no further chunk. So every blob of one chunk
/// or less succeeds and every larger blob fails. Measured against the live
/// registry on 2026-09-24 with a `4 MiB + 1000` byte blob: `POST 202` →
/// `PATCH 202` → `PATCH 405`.
///
/// `push_blob` does carry a monolithic fallback, and it does not fire here: it
/// is reached only from `Err(OciDistributionError::SpecViolationError(_))`,
/// which `extract_location_header` produces solely for a *success* status that
/// is not the expected one. A clean `405` takes the other branch and becomes
/// `ServerError { code: 405, .. }`, which `push_blob` returns verbatim.
///
/// # Why monolithic rather than a smarter chunked client
///
/// Monolithic `POST`-then-`PUT` is one of the two blob-upload flows the OCI
/// distribution specification defines, not a Google special case — nothing
/// here inspects the registry host or the shape of a `Location` header, and
/// the same two requests are sent to every registry.
///
/// Chunking would buy nothing on this path even where it works. The caller
/// (`oci::push_bundle_with`) has already read the whole bundle into memory and
/// `ImageLayer` owns a second copy, so there is no streaming to preserve; and
/// `oci-client` cannot resume a broken session, so a failed chunked upload
/// restarts from byte zero exactly as a failed monolithic one does. What
/// chunking adds here is a second, less widely implemented code path for the
/// same bytes.
///
/// The cost, stated plainly: a registry that implements ONLY chunked upload
/// would now fail where it previously worked. No such registry is reachable
/// from this crate — the `oci://` backend is compiled only under
/// `deploy-gcp-cloudrun` and mints a Google Artifact Registry token per push
/// (`oci::OciBundleUploader::upload`) — and `POST`-then-`PUT` is the flow every
/// registry implements. If one ever turns up, the fix is a fallback to
/// chunked, not a return to chunked-first.
pub struct MonolithicRegistryPusher {
    client: Client,
    auth: RegistryAuth,
}

impl MonolithicRegistryPusher {
    /// Push authenticated by HTTP basic auth over HTTPS.
    ///
    /// Artifact Registry takes an OAuth2 access token as the password under
    /// the fixed username `oauth2accesstoken`. The credential is frozen into
    /// the pusher, so a caller holding a short-lived token must build a fresh
    /// pusher per push rather than reusing one.
    pub fn with_basic_auth(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::with_protocol(
            ClientProtocol::Https,
            RegistryAuth::Basic(username.into(), password.into()),
        )
    }

    fn with_protocol(protocol: ClientProtocol, auth: RegistryAuth) -> Self {
        let config = ClientConfig {
            protocol,
            // The whole point of this type. `oci-client` defaults this to
            // `false`, which selects the chunked flow Artifact Registry
            // refuses past the first chunk.
            use_monolithic_push: true,
            ..Default::default()
        };
        Self {
            client: Client::new(config),
            auth,
        }
    }

    /// Plain HTTP against the named registries, for driving a stub server in
    /// tests. Never reachable from a production path: every caller there goes
    /// through [`Self::with_basic_auth`], which is HTTPS-only.
    #[cfg(test)]
    fn insecure_with_basic_auth(
        registry: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self::with_protocol(
            ClientProtocol::HttpsExcept(vec![registry.into()]),
            RegistryAuth::Basic(username.into(), password.into()),
        )
    }
}

#[async_trait::async_trait]
impl RegistryPusher for MonolithicRegistryPusher {
    async fn push_artifact(
        &self,
        reference: &Reference,
        bytes: &[u8],
        media_type: &str,
    ) -> Result<(), OciDistributionError> {
        let layers = vec![ImageLayer::new(
            bytes.to_vec(),
            media_type.to_string(),
            None,
        )];
        let config = Config::new(b"{}".to_vec(), EMPTY_CONFIG_MEDIA_TYPE.to_string(), None);
        self.client
            .push(reference, &layers, config, &self.auth, None)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_distributor_client::oci_packs::DefaultRegistryClient;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// One chunk more than `oci-client`'s `PUSH_CHUNK_MAX_SIZE` (4 MiB), so a
    /// chunked push needs a second `PATCH` and a monolithic one does not.
    const OVER_ONE_CHUNK: usize = 4 * 1024 * 1024 + 1000;

    /// Counts what a push actually did, so a test can assert the transport
    /// rather than only the outcome.
    #[derive(Default)]
    struct ArCalls {
        sessions: AtomicUsize,
        patches: AtomicUsize,
        puts: AtomicUsize,
        rejected_patches: AtomicUsize,
        manifests: AtomicUsize,
        authenticated_requests: AtomicUsize,
        largest_put_body: AtomicUsize,
    }

    /// A stub that answers the way Google Artifact Registry was measured to
    /// answer on 2026-09-24, including the two behaviours that break a
    /// chunked push:
    ///
    /// * the first `PATCH` returns `202` with a `Location` of a DIFFERENT
    ///   shape from the session the `POST` opened (AR's own `/v2/…/pkg/…`
    ///   path), and
    /// * that second location answers `PUT` with `201` and any further
    ///   `PATCH` with `405 Method Not Allowed`.
    ///
    /// It also demands HTTP basic auth on `GET /v2/`, so the credential
    /// wiring is exercised rather than assumed.
    async fn spawn_ar_stub() -> (String, Arc<ArCalls>, tokio::task::JoinHandle<()>) {
        use axum::extract::State;
        use axum::http::{HeaderMap, StatusCode};
        use axum::response::IntoResponse;
        use axum::routing::{any, get};

        let calls = Arc::new(ArCalls::default());

        fn count_auth(calls: &ArCalls, headers: &HeaderMap) {
            if headers.contains_key(axum::http::header::AUTHORIZATION) {
                calls.authenticated_requests.fetch_add(1, Ordering::SeqCst);
            }
        }

        // `oci-client` probes `GET /v2/` to discover the auth scheme. A
        // `WWW-Authenticate` value it cannot parse as a bearer challenge makes
        // it fall back to the basic credential it was built with.
        async fn version() -> impl IntoResponse {
            (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Basic realm=\"registry\"")],
            )
        }

        // `POST /v2/<name>/blobs/uploads/` — opens the session and answers
        // with AR's first, non-`/v2/` location.
        async fn open_session(
            State(calls): State<Arc<ArCalls>>,
            headers: HeaderMap,
        ) -> impl IntoResponse {
            count_auth(&calls, &headers);
            calls.sessions.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::ACCEPTED,
                [(
                    "Location",
                    "/artifacts-uploads/namespaces/proj/repositories/repo/uploads/upload-id",
                )],
            )
        }

        // The first location: one `PATCH` is accepted and redirects to the
        // `/v2/…/pkg/…` location; a `PUT` here finishes a monolithic upload.
        async fn first_location(
            State(calls): State<Arc<ArCalls>>,
            method: axum::http::Method,
            headers: HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            count_auth(&calls, &headers);
            match method {
                axum::http::Method::PATCH => {
                    calls.patches.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::ACCEPTED,
                        [("Location", "/v2/proj/repo/pkg/blobs/uploads/upload-id")],
                    )
                        .into_response()
                }
                axum::http::Method::PUT => {
                    calls.puts.fetch_add(1, Ordering::SeqCst);
                    calls
                        .largest_put_body
                        .fetch_max(body.len(), Ordering::SeqCst);
                    (
                        StatusCode::CREATED,
                        [("Location", "/v2/proj/repo/blobs/sha256:stub")],
                    )
                        .into_response()
                }
                _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
            }
        }

        // The redirected location: `PUT` only. This is the behaviour that
        // makes a chunked push of more than one chunk impossible.
        async fn second_location(
            State(calls): State<Arc<ArCalls>>,
            method: axum::http::Method,
            headers: HeaderMap,
            body: axum::body::Bytes,
        ) -> axum::response::Response {
            count_auth(&calls, &headers);
            match method {
                axum::http::Method::PUT => {
                    calls.puts.fetch_add(1, Ordering::SeqCst);
                    calls
                        .largest_put_body
                        .fetch_max(body.len(), Ordering::SeqCst);
                    (
                        StatusCode::CREATED,
                        [("Location", "/v2/proj/repo/blobs/sha256:stub")],
                    )
                        .into_response()
                }
                axum::http::Method::PATCH => {
                    calls.rejected_patches.fetch_add(1, Ordering::SeqCst);
                    StatusCode::METHOD_NOT_ALLOWED.into_response()
                }
                _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
            }
        }

        async fn manifest(
            State(calls): State<Arc<ArCalls>>,
            headers: HeaderMap,
        ) -> impl IntoResponse {
            count_auth(&calls, &headers);
            calls.manifests.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::CREATED,
                [("Location", "/v2/proj/repo/manifests/sha256:stub")],
            )
        }

        let app = axum::Router::new()
            .route("/v2/", get(version))
            .route("/v2/proj/repo/blobs/uploads/", any(open_session))
            .route(
                "/artifacts-uploads/namespaces/proj/repositories/repo/uploads/{id}",
                any(first_location),
            )
            .route("/v2/proj/repo/pkg/blobs/uploads/{id}", any(second_location))
            .route("/v2/proj/repo/manifests/{tag}", any(manifest))
            // A blob larger than one chunk is the whole point of this stub,
            // and axum's default 2 MiB body cap would reject it before any
            // handler ran — as a `413`, which reads like a registry refusal.
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(Arc::clone(&calls));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a stub registry");
        let addr = listener.local_addr().expect("stub registry address");
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("127.0.0.1:{}", addr.port()), calls, handle)
    }

    /// The regression this module exists for: a blob larger than one chunk
    /// reaches a registry that only accepts a single `PATCH` per session.
    #[tokio::test]
    async fn a_blob_larger_than_one_chunk_is_pushed_as_a_single_put() {
        let (registry, calls, server) = spawn_ar_stub().await;
        let reference =
            Reference::from_str(&format!("{registry}/proj/repo:v1")).expect("valid reference");

        let pusher = MonolithicRegistryPusher::insecure_with_basic_auth(
            registry.clone(),
            "oauth2accesstoken",
            "a-token",
        );
        let outcome = pusher
            .push_artifact(
                &reference,
                &vec![7u8; OVER_ONE_CHUNK],
                "application/octet-stream",
            )
            .await;
        server.abort();

        assert!(outcome.is_ok(), "push should succeed: {outcome:?}");
        assert_eq!(
            calls.patches.load(Ordering::SeqCst),
            0,
            "a monolithic push must send no PATCH at all"
        );
        assert_eq!(
            calls.rejected_patches.load(Ordering::SeqCst),
            0,
            "nothing may reach the PUT-only location with a PATCH"
        );
        // Two blobs: the layer and the `{}` config.
        assert_eq!(calls.sessions.load(Ordering::SeqCst), 2);
        assert_eq!(calls.puts.load(Ordering::SeqCst), 2);
        assert_eq!(calls.manifests.load(Ordering::SeqCst), 1);
        assert_eq!(
            calls.largest_put_body.load(Ordering::SeqCst),
            OVER_ONE_CHUNK,
            "the whole blob must travel in one request body"
        );
        assert!(
            calls.authenticated_requests.load(Ordering::SeqCst) > 0,
            "the basic credential must reach the registry"
        );
    }

    /// Pins the defect itself, so this module cannot be deleted as redundant:
    /// the shared `DefaultRegistryClient` — the client this path used before —
    /// still fails against the same stub, with the same `405`.
    #[tokio::test]
    async fn the_chunked_client_still_fails_on_the_second_patch() {
        let (registry, calls, server) = spawn_ar_stub().await;
        let reference =
            Reference::from_str(&format!("{registry}/proj/repo:v1")).expect("valid reference");

        let pusher = DefaultRegistryClient::with_basic_auth("oauth2accesstoken", "a-token")
            .with_insecure_transport(vec![registry.clone()]);
        let err = pusher
            .push_artifact(
                &reference,
                &vec![7u8; OVER_ONE_CHUNK],
                "application/octet-stream",
            )
            .await
            .expect_err("a chunked push of more than one chunk must fail here");
        server.abort();

        match err {
            OciDistributionError::ServerError { code, .. } => assert_eq!(
                code, 405,
                "the failure must be the 405 on the second PATCH, not something else"
            ),
            other => panic!("expected a 405 ServerError, got {other:?}"),
        }
        assert_eq!(
            calls.rejected_patches.load(Ordering::SeqCst),
            1,
            "the client must have tried a second PATCH against the redirected location"
        );
    }

    /// A blob that fits in one chunk already worked before this change; it
    /// must still work, and must still be one `PUT`.
    #[tokio::test]
    async fn a_blob_smaller_than_one_chunk_is_pushed_the_same_way() {
        let (registry, calls, server) = spawn_ar_stub().await;
        let reference =
            Reference::from_str(&format!("{registry}/proj/repo:v1")).expect("valid reference");

        let pusher = MonolithicRegistryPusher::insecure_with_basic_auth(
            registry.clone(),
            "oauth2accesstoken",
            "a-token",
        );
        let outcome = pusher
            .push_artifact(
                &reference,
                b"hsqs\x00\x01\x02\x03payload",
                "application/octet-stream",
            )
            .await;
        server.abort();

        assert!(outcome.is_ok(), "push should succeed: {outcome:?}");
        assert_eq!(calls.patches.load(Ordering::SeqCst), 0);
        assert_eq!(calls.puts.load(Ordering::SeqCst), 2);
    }
}
