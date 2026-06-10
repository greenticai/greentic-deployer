//! [`HttpEnvironmentStore`] — remote HTTP-backed implementation of
//! [`EnvironmentMutations`].
//!
//! Talks to a future `greentic-operator-store-server` (PR-4) over the
//! **A8 HTTP contract** specified in [`greentic_deploy_spec::remote`].
//! JSON over the wire, `reqwest::blocking::Client` for transport so the
//! sync `EnvironmentMutations` trait stays sync (no Tokio runtime needed
//! at call sites — see project memory `project_next_gen_deployment_phase_b`
//! for the `block_in_place` panic precedent that rules out async-in-sync).
//!
//! # Route table
//!
//! Every mutation maps to a single HTTP endpoint. The server (PR-4) mirrors
//! this table.
//!
//! | Trait method                   | Method | Path                                                      |
//! |-------------------------------|--------|-----------------------------------------------------------|
//! | `create_environment`          | POST   | `/environments`                                           |
//! | `update_environment`          | PATCH  | `/environments/{env_id}`                                  |
//! | `migrate_merge_bindings`      | POST   | `/environments/{env_id}/migrate-bindings`                 |
//! | `stage_revision`              | POST   | `/environments/{env_id}/revisions`                        |
//! | `warm_revision`               | POST   | `/environments/{env_id}/revisions/{rid}/warm`             |
//! | `drain_revision`              | POST   | `/environments/{env_id}/revisions/{rid}/drain`            |
//! | `archive_revision`            | POST   | `/environments/{env_id}/revisions/{rid}/archive`          |
//! | `add_bundle`                  | POST   | `/environments/{env_id}/bundles`                          |
//! | `update_bundle`               | PATCH  | `/environments/{env_id}/bundles/{deployment_id}`          |
//! | `remove_bundle`               | DELETE | `/environments/{env_id}/bundles/{deployment_id}`          |
//! | `add_pack_binding`            | POST   | `/environments/{env_id}/packs`                            |
//! | `update_pack_binding`         | PATCH  | `/environments/{env_id}/packs/{slot}`                     |
//! | `remove_pack_binding`         | DELETE | `/environments/{env_id}/packs/{slot}`                     |
//! | `rollback_pack_binding`       | POST   | `/environments/{env_id}/packs/{slot}/rollback`            |
//! | `add_extension_binding`       | POST   | `/environments/{env_id}/extensions`                       |
//! | `update_extension_binding`    | PATCH  | `/environments/{env_id}/extensions`                       |
//! | `remove_extension_binding`    | DELETE | `/environments/{env_id}/extensions`                       |
//! | `rollback_extension_binding`  | POST   | `/environments/{env_id}/extensions/rollback`              |
//! | `set_traffic_split`           | POST   | `/environments/{env_id}/traffic`                          |
//! | `rollback_traffic_split`      | POST   | `/environments/{env_id}/traffic/rollback`                 |
//! | `add_messaging_endpoint`      | POST   | `/environments/{env_id}/messaging`                        |
//! | `link_messaging_bundle`       | POST   | `/environments/{env_id}/messaging/{eid}/link`             |
//! | `unlink_messaging_bundle`     | POST   | `/environments/{env_id}/messaging/{eid}/unlink`           |
//! | `set_messaging_welcome_flow`  | POST   | `/environments/{env_id}/messaging/{eid}/welcome-flow`     |
//! | `remove_messaging_endpoint`   | DELETE | `/environments/{env_id}/messaging/{eid}`                  |
//! | `rotate_messaging_webhook_secret` | POST | `/environments/{env_id}/messaging/{eid}/rotate-secret` |
//! | `bootstrap_trust_root`        | POST   | `/environments/{env_id}/trust-root/bootstrap`             |
//! | `seed_trust_root_if_absent`   | POST   | `/environments/{env_id}/trust-root/seed`                  |
//! | `add_trusted_key`             | POST   | `/environments/{env_id}/trust-root/keys`                  |
//! | `remove_trusted_key`          | DELETE | `/environments/{env_id}/trust-root/keys/{key_id}`         |
//!
//! # Headers
//!
//! - `Content-Type: application/json` / `Accept: application/json` on every request.
//! - `Authorization: Bearer <token>` when [`AuthMethod::Bearer`].
//! - `Idempotency-Key: <ulid>` when the payload carries an [`IdempotencyKey`].
//!
//! # ETag / CAS
//!
//! Deferred to a follow-up (PR-3b-fu). Today the server is the source of
//! truth and we use last-write-wins. [`Precondition`] types from
//! `remote.rs` are ready but adding an optional precondition parameter to
//! the trait changes the trait — out of scope for this PR.
//!
//! # Error mapping
//!
//! Transport errors (connection refused, timeout, TLS handshake) map to
//! `StoreError::Conflict("transport: ...")`. A dedicated
//! `StoreError::Transport` variant would be cleaner but adding a new enum
//! variant cascades into every `match` site — follow-up.
//!
//! # Follow-ups
//!
//! - ETag/CAS at the wire layer (PR-3b-fu)
//! - `StoreError::Transport` variant
//! - `AuthMethod::Mtls` for production (mTLS)
//! - PR-3c wires dispatch between `LocalFsStore` and `HttpEnvironmentStore`

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CapabilitySlot, CustomerId, DeploymentId,
    EnvId, EnvPackBinding, Environment, EnvironmentHostConfig, ExtensionBinding, HealthStatus,
    IdempotencyKey, MessagingEndpoint, MessagingEndpointId, PackId, PackListEntry,
    RemoteStoreError, RetentionPolicy, RevenueShareEntry, Revision, RevisionId, RevisionLifecycle,
    RevocationConfig, RouteBinding, TrafficSplit, TrafficSplitEntry,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use super::mutations::{
    AddBundlePayload, AddMessagingEndpointPayload, ApplyTrafficSplitOutcome, EnvironmentMutations,
    ExtensionKey, FieldUpdate, MigrateMergePayload, RemoveBundleOutcome, RevisionTransitionOutcome,
    RollbackTrafficSplitOutcome, SetMessagingWelcomeFlowPayload, StageRevisionPayload,
    TrustRootAddOutcome, TrustRootRemoveOutcome, TrustRootSeed, UpdateBundlePayload,
    UpdateEnvironmentPayload, WarmRevisionPayload,
};
use super::store::StoreError;

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/// How the client authenticates to the remote store server.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// No authentication (dev/loopback).
    None,
    /// Bearer token (Phase A).
    Bearer(String),
    // mTLS deferred — note in module doc but not implemented here.
}

// ---------------------------------------------------------------------------
// HttpEnvironmentStore
// ---------------------------------------------------------------------------

/// Remote HTTP-backed implementation of [`EnvironmentMutations`].
///
/// See the module-level doc for the route table and design rationale.
#[derive(Debug, Clone)]
pub struct HttpEnvironmentStore {
    client: Client,
    base_url: Url,
    auth: AuthMethod,
}

impl HttpEnvironmentStore {
    /// Build with the default `reqwest::blocking::Client`.
    pub fn new(base_url: Url, auth: AuthMethod) -> Self {
        Self {
            client: Client::new(),
            base_url,
            auth,
        }
    }

    /// Build with a caller-supplied client (custom timeouts, TLS config, etc.).
    pub fn with_client(client: Client, base_url: Url, auth: AuthMethod) -> Self {
        Self {
            client,
            base_url,
            auth,
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build a full URL by joining `path` onto `base_url`.
    fn url(&self, path: &str) -> Result<Url, StoreError> {
        // Ensure base URL ends with "/" so join works correctly.
        let mut base = self.base_url.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(path)
            .map_err(|e| StoreError::Conflict(format!("transport: invalid URL path `{path}`: {e}")))
    }

    /// Send an HTTP request and parse the JSON response.
    ///
    /// - Sets `Content-Type` and `Accept` to `application/json`.
    /// - Adds `Authorization: Bearer` if configured.
    /// - Adds `Idempotency-Key` header when provided.
    /// - On success (2xx), deserializes the body as `R`.
    /// - On error, maps the HTTP status + body to [`StoreError`].
    fn send<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        idempotency_key: Option<&str>,
        body: Option<&P>,
    ) -> Result<R, StoreError> {
        let url = self.url(path)?;
        let mut builder = self
            .client
            .request(method, url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");

        if let AuthMethod::Bearer(ref token) = self.auth {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(key) = idempotency_key {
            builder = builder.header("Idempotency-Key", key);
        }
        if let Some(payload) = body {
            builder = builder.json(payload);
        }

        let response = builder
            .send()
            .map_err(|e| StoreError::Conflict(format!("transport: {e}")))?;

        let status = response.status();
        if status.is_success() {
            // 204 No Content: return the unit-ish default. The caller should
            // use `()` or a type that deserializes from `null`/empty.
            if status == reqwest::StatusCode::NO_CONTENT {
                // Try deserializing from "null" for types that accept it.
                return serde_json::from_str("null").map_err(|e| {
                    StoreError::Conflict(format!("transport: cannot deserialize 204 body: {e}"))
                });
            }
            response
                .json::<R>()
                .map_err(|e| StoreError::Conflict(format!("transport: invalid response body: {e}")))
        } else {
            Err(map_error_response(status, response))
        }
    }

    /// Variant of [`send`](Self::send) that takes no body (GET/DELETE with no
    /// body).
    fn send_no_body<R: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        idempotency_key: Option<&str>,
    ) -> Result<R, StoreError> {
        self.send::<(), R>(method, path, idempotency_key, None)
    }
}

/// Map an error HTTP response to [`StoreError`].
///
/// Tries to parse the body as [`RemoteStoreError`] (the A8 error contract);
/// falls back to a generic `StoreError::Conflict` with the status code and
/// raw body text.
fn map_error_response(
    status: reqwest::StatusCode,
    response: reqwest::blocking::Response,
) -> StoreError {
    let body_text = response.text().unwrap_or_default();

    // Try to parse as the A8 contract error shape.
    if let Ok(remote_err) = serde_json::from_str::<RemoteStoreError>(&body_text) {
        return map_remote_error(&remote_err);
    }

    // Fallback: map by status code with raw body.
    match status.as_u16() {
        404 => StoreError::NotFound(EnvId::try_from("unknown").unwrap_or_else(|_| {
            // EnvId::try_from should not fail for "unknown" but guard anyway.
            unreachable!("EnvId::try_from(\"unknown\") must succeed")
        })),
        409 => StoreError::Conflict(body_text),
        400 | 422 => StoreError::InvalidArgument(body_text),
        401 | 403 => StoreError::Conflict(format!("authorization: {body_text}")),
        _ => StoreError::Conflict(format!("server ({status}): {body_text}")),
    }
}

/// Map a parsed [`RemoteStoreError`] to [`StoreError`].
fn map_remote_error(err: &RemoteStoreError) -> StoreError {
    match err {
        RemoteStoreError::NotFound => StoreError::NotFound(
            EnvId::try_from("unknown")
                .unwrap_or_else(|_| unreachable!("EnvId::try_from(\"unknown\") must succeed")),
        ),
        RemoteStoreError::PreconditionFailed(conflict) => {
            StoreError::Conflict(format!("precondition failed: {conflict:?}"))
        }
        RemoteStoreError::PreconditionRequired { detail } => {
            StoreError::Conflict(format!("precondition required: {detail}"))
        }
        RemoteStoreError::IdempotencyConflict { reason } => {
            StoreError::Conflict(format!("idempotency conflict: {reason}"))
        }
        RemoteStoreError::Unauthorized { policy, reason } => {
            StoreError::Conflict(format!("authorization: {reason} (policy `{policy}`)"))
        }
        RemoteStoreError::IntegrityMismatch { expected, actual } => StoreError::InvalidArgument(
            format!("integrity mismatch: expected {expected}, computed {actual}"),
        ),
        RemoteStoreError::NotYetImplemented { detail } => {
            StoreError::Conflict(format!("not yet implemented: {detail}"))
        }
        RemoteStoreError::Internal { message } => {
            StoreError::Conflict(format!("server: {message}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types — request payloads sent to the server.
//
// The trait's payload structs (`StageRevisionPayload`, etc.) don't derive
// `Serialize` (they are deployer-internal). We define thin wire DTOs here
// that do, and convert at the call boundary.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CreateEnvironmentRequest {
    env_id: EnvId,
    name: String,
    host_config: EnvironmentHostConfig,
}

/// JSON tri-state for [`FieldUpdate<T>`]: `null` = keep, `{"clear": true}` =
/// clear, `{"value": T}` = set. Using tagged-enum serde so the server can
/// distinguish keep (field absent / null) from clear.
#[derive(Serialize)]
#[serde(untagged)]
enum WireFieldUpdate<T: Serialize> {
    Set { value: T },
    Clear { clear: bool },
}

#[derive(Serialize)]
struct UpdateEnvironmentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<WireFieldUpdate<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_org_id: Option<WireFieldUpdate<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listen_addr: Option<WireFieldUpdate<SocketAddr>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_base_url: Option<WireFieldUpdate<String>>,
}

impl From<UpdateEnvironmentPayload> for UpdateEnvironmentRequest {
    fn from(p: UpdateEnvironmentPayload) -> Self {
        fn wire<T: Serialize>(fu: FieldUpdate<T>) -> Option<WireFieldUpdate<T>> {
            match fu {
                FieldUpdate::Keep => None,
                FieldUpdate::Set(v) => Some(WireFieldUpdate::Set { value: v }),
                FieldUpdate::Clear => Some(WireFieldUpdate::Clear { clear: true }),
            }
        }
        Self {
            name: p.name,
            region: wire(p.region),
            tenant_org_id: wire(p.tenant_org_id),
            listen_addr: wire(p.listen_addr),
            public_base_url: wire(p.public_base_url),
        }
    }
}

#[derive(Serialize)]
struct MigrateSeedWire {
    host_config: EnvironmentHostConfig,
    revocation: RevocationConfig,
    retention: RetentionPolicy,
    health: HealthStatus,
}

#[derive(Serialize)]
struct MigrateMergeRequest {
    packs: Vec<EnvPackBinding>,
    extensions: Vec<ExtensionBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed_if_missing: Option<MigrateSeedWire>,
}

impl From<MigrateMergePayload> for MigrateMergeRequest {
    fn from(p: MigrateMergePayload) -> Self {
        Self {
            packs: p.packs,
            extensions: p.extensions,
            seed_if_missing: p.seed_if_missing.map(|s| MigrateSeedWire {
                host_config: s.host_config,
                revocation: s.revocation,
                retention: s.retention,
                health: s.health,
            }),
        }
    }
}

/// Server returns the two merge-result lists.
#[derive(Deserialize)]
struct MigrateMergeResponse {
    merged_slots: Vec<String>,
    merged_extensions: Vec<String>,
}

#[derive(Serialize)]
struct StageRevisionRequest {
    revision_id: RevisionId,
    deployment_id: DeploymentId,
    bundle_digest: String,
    pack_list: Vec<PackListEntry>,
    pack_list_lock_ref: PathBuf,
    pack_config_refs: Vec<PathBuf>,
    config_digest: String,
    signature_sidecar_ref: PathBuf,
    drain_seconds: u32,
}

#[derive(Serialize)]
struct WarmRevisionRequest {
    health_gate_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_gate_failure: Option<WireHealthGateFailure>,
    expected_lifecycle: RevisionLifecycle,
}

#[derive(Serialize)]
struct WireHealthGateFailure {
    failed_checks: Vec<String>,
    message: String,
}

/// Response for revision lifecycle transitions (warm/drain/archive).
#[derive(Deserialize)]
struct RevisionTransitionResponse {
    revision: Revision,
    environment: Environment,
    starting_lifecycle: RevisionLifecycle,
}

#[derive(Serialize)]
struct DrainRevisionRequest {
    // Body intentionally minimal — the revision_id is in the URL path.
}

#[derive(Serialize)]
struct ArchiveRevisionRequest {
    // Body intentionally minimal — the revision_id is in the URL path.
}

#[derive(Serialize)]
struct AddBundleRequest {
    bundle_id: BundleId,
    customer_id: CustomerId,
    revenue_share: Vec<RevenueShareEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_binding: Option<RouteBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_ref: Option<String>,
    config_overrides: BTreeMap<String, BTreeMap<String, Value>>,
}

#[derive(Serialize)]
struct UpdateBundleRequest {
    deployment_id: DeploymentId,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<BundleDeploymentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_binding: Option<RouteBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revenue_share: Option<Vec<RevenueShareEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
}

#[derive(Deserialize)]
struct RemoveBundleResponse {
    deployment: BundleDeployment,
    pruned_revision_ids: Vec<RevisionId>,
}

#[derive(Serialize)]
struct PackBindingRequest {
    binding: EnvPackBinding,
}

/// Response for pack/extension update/remove/rollback that returns a binding + generation.
#[derive(Deserialize)]
struct BindingGenerationResponse<T> {
    binding: T,
    generation: u64,
}

#[derive(Serialize)]
struct ExtensionBindingRequest {
    binding: ExtensionBinding,
}

#[derive(Serialize)]
struct ExtensionKeyedRequest {
    key: WireExtensionKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<ExtensionBinding>,
}

#[derive(Serialize)]
struct WireExtensionKey {
    kind_path: String,
    instance_id: Option<String>,
}

impl From<&ExtensionKey> for WireExtensionKey {
    fn from(k: &ExtensionKey) -> Self {
        Self {
            kind_path: k.kind_path.clone(),
            instance_id: k.instance_id.clone(),
        }
    }
}

#[derive(Serialize)]
struct SetTrafficSplitRequest {
    deployment_id: DeploymentId,
    entries: Vec<TrafficSplitEntry>,
    updated_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_ref: Option<String>,
}

#[derive(Deserialize)]
struct ApplyTrafficSplitResponse {
    split: TrafficSplit,
    previous_generation: Option<u64>,
    new_generation: Option<u64>,
}

#[derive(Serialize)]
struct RollbackTrafficSplitRequest {
    deployment_id: DeploymentId,
}

#[derive(Deserialize)]
struct RollbackTrafficSplitResponse {
    restored: TrafficSplit,
    previous_generation: u64,
    new_generation: u64,
}

#[derive(Serialize)]
struct AddMessagingEndpointRequest {
    provider_id: String,
    provider_type: String,
    display_name: String,
    secret_refs: Vec<String>,
    updated_by: String,
}

#[derive(Serialize)]
struct LinkMessagingBundleRequest {
    bundle_id: BundleId,
    updated_by: String,
}

#[derive(Serialize)]
struct UnlinkMessagingBundleRequest {
    bundle_id: BundleId,
    updated_by: String,
}

#[derive(Serialize)]
struct SetMessagingWelcomeFlowRequest {
    endpoint_id: MessagingEndpointId,
    bundle_id: BundleId,
    pack_id: PackId,
    flow_id: String,
    updated_by: String,
}

#[derive(Serialize)]
struct RotateWebhookSecretRequest {
    updated_by: String,
}

#[derive(Serialize)]
struct AddTrustedKeyRequest {
    key_id: String,
    public_key_pem: String,
}

#[derive(Deserialize)]
struct TrustRootSeedResponse {
    key_id: String,
    public_key_pem: String,
    trusted_key_count: usize,
}

#[derive(Deserialize)]
struct TrustRootAddResponse {
    added_key_id: String,
    trusted_key_count: usize,
}

#[derive(Deserialize)]
struct TrustRootRemoveResponse {
    removed_key_id: String,
    removed_public_key_pem: Option<String>,
    trusted_key_count: usize,
}

// ---------------------------------------------------------------------------
// EnvironmentMutations impl
// ---------------------------------------------------------------------------

impl EnvironmentMutations for HttpEnvironmentStore {
    fn create_environment(
        &self,
        env_id: &EnvId,
        name: String,
        host_config: EnvironmentHostConfig,
    ) -> Result<Environment, StoreError> {
        let req = CreateEnvironmentRequest {
            env_id: env_id.clone(),
            name,
            host_config,
        };
        self.send(reqwest::Method::POST, "environments", None, Some(&req))
    }

    fn update_environment(
        &self,
        env_id: &EnvId,
        patch: UpdateEnvironmentPayload,
    ) -> Result<Environment, StoreError> {
        let req: UpdateEnvironmentRequest = patch.into();
        self.send(
            reqwest::Method::PATCH,
            &format!("environments/{env_id}"),
            None,
            Some(&req),
        )
    }

    fn migrate_merge_bindings(
        &self,
        target_env_id: &EnvId,
        payload: MigrateMergePayload,
    ) -> Result<(Vec<String>, Vec<String>), StoreError> {
        let req: MigrateMergeRequest = payload.into();
        let resp: MigrateMergeResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{target_env_id}/migrate-bindings"),
            None,
            Some(&req),
        )?;
        Ok((resp.merged_slots, resp.merged_extensions))
    }

    fn stage_revision(
        &self,
        env_id: &EnvId,
        payload: StageRevisionPayload,
    ) -> Result<Revision, StoreError> {
        let idem_key = payload.idempotency_key.as_str().to_string();
        let req = StageRevisionRequest {
            revision_id: payload.revision_id,
            deployment_id: payload.deployment_id,
            bundle_digest: payload.bundle_digest,
            pack_list: payload.pack_list,
            pack_list_lock_ref: payload.pack_list_lock_ref,
            pack_config_refs: payload.pack_config_refs,
            config_digest: payload.config_digest,
            signature_sidecar_ref: payload.signature_sidecar_ref,
            drain_seconds: payload.drain_seconds,
        };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/revisions"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let idem_key = payload.idempotency_key.as_str().to_string();
        let rid = &payload.revision_id;
        let req = WarmRevisionRequest {
            health_gate_ok: payload.health_gate.is_ok(),
            health_gate_failure: payload.health_gate.err().map(|f| WireHealthGateFailure {
                failed_checks: f.failed_checks.iter().map(|c| format!("{c:?}")).collect(),
                message: f.message,
            }),
            expected_lifecycle: payload.expected_lifecycle,
        };
        let resp: RevisionTransitionResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/revisions/{rid}/warm"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok(RevisionTransitionOutcome {
            revision: resp.revision,
            environment: resp.environment,
            starting_lifecycle: resp.starting_lifecycle,
        })
    }

    fn drain_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = DrainRevisionRequest {};
        let resp: RevisionTransitionResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/revisions/{revision_id}/drain"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok(RevisionTransitionOutcome {
            revision: resp.revision,
            environment: resp.environment,
            starting_lifecycle: resp.starting_lifecycle,
        })
    }

    fn archive_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = ArchiveRevisionRequest {};
        let resp: RevisionTransitionResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/revisions/{revision_id}/archive"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok(RevisionTransitionOutcome {
            revision: resp.revision,
            environment: resp.environment,
            starting_lifecycle: resp.starting_lifecycle,
        })
    }

    fn add_bundle(
        &self,
        env_id: &EnvId,
        payload: AddBundlePayload,
    ) -> Result<BundleDeployment, StoreError> {
        let idem_key = payload.idempotency_key.as_str().to_string();
        let req = AddBundleRequest {
            bundle_id: payload.bundle_id,
            customer_id: payload.customer_id,
            revenue_share: payload.revenue_share,
            route_binding: payload.route_binding,
            authorization_ref: payload.authorization_ref,
            config_overrides: payload.config_overrides,
        };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/bundles"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn update_bundle(
        &self,
        env_id: &EnvId,
        payload: UpdateBundlePayload,
    ) -> Result<BundleDeployment, StoreError> {
        let idem_key = payload.idempotency_key.as_str().to_string();
        let did = &payload.deployment_id;
        let req = UpdateBundleRequest {
            deployment_id: payload.deployment_id,
            status: payload.status,
            route_binding: payload.route_binding,
            revenue_share: payload.revenue_share,
            config_overrides: payload.config_overrides,
        };
        self.send(
            reqwest::Method::PATCH,
            &format!("environments/{env_id}/bundles/{did}"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn remove_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RemoveBundleOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let resp: RemoveBundleResponse = self.send_no_body(
            reqwest::Method::DELETE,
            &format!("environments/{env_id}/bundles/{deployment_id}"),
            Some(&idem_key),
        )?;
        Ok(RemoveBundleOutcome {
            deployment: resp.deployment,
            pruned_revision_ids: resp.pruned_revision_ids,
        })
    }

    fn add_pack_binding(
        &self,
        env_id: &EnvId,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<EnvPackBinding, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = PackBindingRequest { binding };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/packs"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn update_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = PackBindingRequest { binding };
        let resp: BindingGenerationResponse<EnvPackBinding> = self.send(
            reqwest::Method::PATCH,
            &format!("environments/{env_id}/packs/{slot}"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn remove_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let resp: BindingGenerationResponse<EnvPackBinding> = self.send_no_body(
            reqwest::Method::DELETE,
            &format!("environments/{env_id}/packs/{slot}"),
            Some(&idem_key),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn rollback_pack_binding(
        &self,
        env_id: &EnvId,
        slot: CapabilitySlot,
        idempotency_key: IdempotencyKey,
    ) -> Result<(EnvPackBinding, u64), StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let resp: BindingGenerationResponse<EnvPackBinding> = self.send_no_body(
            reqwest::Method::POST,
            &format!("environments/{env_id}/packs/{slot}/rollback"),
            Some(&idem_key),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn add_extension_binding(
        &self,
        env_id: &EnvId,
        binding: ExtensionBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<ExtensionBinding, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = ExtensionBindingRequest { binding };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/extensions"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn update_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        binding: ExtensionBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = ExtensionKeyedRequest {
            key: WireExtensionKey::from(&key),
            binding: Some(binding),
        };
        let resp: BindingGenerationResponse<ExtensionBinding> = self.send(
            reqwest::Method::PATCH,
            &format!("environments/{env_id}/extensions"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn remove_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = ExtensionKeyedRequest {
            key: WireExtensionKey::from(&key),
            binding: None,
        };
        let resp: BindingGenerationResponse<ExtensionBinding> = self.send(
            reqwest::Method::DELETE,
            &format!("environments/{env_id}/extensions"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn rollback_extension_binding(
        &self,
        env_id: &EnvId,
        key: ExtensionKey,
        idempotency_key: IdempotencyKey,
    ) -> Result<(ExtensionBinding, u64), StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = ExtensionKeyedRequest {
            key: WireExtensionKey::from(&key),
            binding: None,
        };
        let resp: BindingGenerationResponse<ExtensionBinding> = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/extensions/rollback"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn set_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        entries: Vec<TrafficSplitEntry>,
        idempotency_key: IdempotencyKey,
        updated_by: String,
        authorization_ref: Option<String>,
    ) -> Result<ApplyTrafficSplitOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = SetTrafficSplitRequest {
            deployment_id,
            entries,
            updated_by,
            authorization_ref,
        };
        let resp: ApplyTrafficSplitResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/traffic"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok(ApplyTrafficSplitOutcome {
            split: resp.split,
            previous_generation: resp.previous_generation,
            new_generation: resp.new_generation,
        })
    }

    fn rollback_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RollbackTrafficSplitOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = RollbackTrafficSplitRequest { deployment_id };
        let resp: RollbackTrafficSplitResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/traffic/rollback"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok(RollbackTrafficSplitOutcome {
            restored: resp.restored,
            previous_generation: resp.previous_generation,
            new_generation: resp.new_generation,
        })
    }

    fn add_messaging_endpoint(
        &self,
        env_id: &EnvId,
        payload: AddMessagingEndpointPayload,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = payload.idempotency_key.as_str().to_string();
        let req = AddMessagingEndpointRequest {
            provider_id: payload.provider_id,
            provider_type: payload.provider_type,
            display_name: payload.display_name,
            secret_refs: payload.secret_refs,
            updated_by: payload.updated_by,
        };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/messaging"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn link_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = LinkMessagingBundleRequest {
            bundle_id,
            updated_by,
        };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/messaging/{endpoint_id}/link"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn unlink_messaging_bundle(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        bundle_id: BundleId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = UnlinkMessagingBundleRequest {
            bundle_id,
            updated_by,
        };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/messaging/{endpoint_id}/unlink"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn set_messaging_welcome_flow(
        &self,
        env_id: &EnvId,
        payload: SetMessagingWelcomeFlowPayload,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = payload.idempotency_key.as_str().to_string();
        let eid = &payload.endpoint_id;
        let req = SetMessagingWelcomeFlowRequest {
            endpoint_id: payload.endpoint_id,
            bundle_id: payload.bundle_id,
            pack_id: payload.pack_id,
            flow_id: payload.flow_id,
            updated_by: payload.updated_by,
        };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/messaging/{eid}/welcome-flow"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn remove_messaging_endpoint(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
    ) -> Result<MessagingEndpointId, StoreError> {
        self.send_no_body(
            reqwest::Method::DELETE,
            &format!("environments/{env_id}/messaging/{endpoint_id}"),
            None,
        )
    }

    fn rotate_messaging_webhook_secret(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
        updated_by: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = RotateWebhookSecretRequest { updated_by };
        self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/messaging/{endpoint_id}/rotate-secret"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn bootstrap_trust_root(&self, env_id: &EnvId) -> Result<TrustRootSeed, StoreError> {
        let resp: TrustRootSeedResponse = self.send_no_body(
            reqwest::Method::POST,
            &format!("environments/{env_id}/trust-root/bootstrap"),
            None,
        )?;
        Ok(TrustRootSeed {
            key_id: resp.key_id,
            public_key_pem: resp.public_key_pem,
            trusted_key_count: resp.trusted_key_count,
        })
    }

    fn seed_trust_root_if_absent(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<TrustRootSeed>, StoreError> {
        let resp: Option<TrustRootSeedResponse> = self.send_no_body(
            reqwest::Method::POST,
            &format!("environments/{env_id}/trust-root/seed"),
            None,
        )?;
        Ok(resp.map(|r| TrustRootSeed {
            key_id: r.key_id,
            public_key_pem: r.public_key_pem,
            trusted_key_count: r.trusted_key_count,
        }))
    }

    fn add_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        public_key_pem: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootAddOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = AddTrustedKeyRequest {
            key_id,
            public_key_pem,
        };
        let resp: TrustRootAddResponse = self.send(
            reqwest::Method::POST,
            &format!("environments/{env_id}/trust-root/keys"),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok(TrustRootAddOutcome {
            added_key_id: resp.added_key_id,
            trusted_key_count: resp.trusted_key_count,
        })
    }

    fn remove_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootRemoveOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let resp: TrustRootRemoveResponse = self.send_no_body(
            reqwest::Method::DELETE,
            &format!("environments/{env_id}/trust-root/keys/{key_id}"),
            Some(&idem_key),
        )?;
        Ok(TrustRootRemoveOutcome {
            removed_key_id: resp.removed_key_id,
            removed_public_key_pem: resp.removed_public_key_pem,
            trusted_key_count: resp.trusted_key_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;

    /// Minimal mock server: binds an ephemeral port, accepts one request,
    /// validates it with `check`, and responds with the given status + body.
    struct MockServer {
        addr: SocketAddr,
        _handle: std::thread::JoinHandle<()>,
    }

    type CheckFn = Arc<dyn Fn(&str, &str, &[u8]) + Send + Sync>;

    /// A mock that serves multiple sequential requests.
    fn start_mock(responses: Vec<(u16, &str)>, check: Option<CheckFn>) -> MockServer {
        let responses: Vec<(u16, String)> = responses
            .into_iter()
            .map(|(s, b)| (s, b.to_string()))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for (status, body) in responses {
                let (stream, _) = listener.accept().unwrap();
                // Use a single BufReader for both headers and body so buffered
                // bytes are not lost between the header scan and the body read.
                let mut reader = BufReader::new(stream);
                let mut lines: Vec<String> = Vec::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                    if trimmed.is_empty() {
                        break;
                    }
                    lines.push(trimmed.to_string());
                }
                // Read body if Content-Length present (same buffered reader).
                let content_length: usize = lines
                    .iter()
                    .find(|l| l.to_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut req_body = vec![0u8; content_length];
                if content_length > 0 {
                    std::io::Read::read_exact(&mut reader, &mut req_body).unwrap();
                }

                if let Some(ref check_fn) = check {
                    let request_line = lines.first().map(|s| s.as_str()).unwrap_or("");
                    let headers = lines[1..].join("\r\n");
                    check_fn(request_line, &headers, &req_body);
                }

                let status_text = match status {
                    200 => "OK",
                    201 => "Created",
                    204 => "No Content",
                    400 => "Bad Request",
                    404 => "Not Found",
                    409 => "Conflict",
                    422 => "Unprocessable Entity",
                    500 => "Internal Server Error",
                    _ => "Unknown",
                };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let stream_ref = reader.get_mut();
                stream_ref.write_all(response.as_bytes()).unwrap();
                stream_ref.flush().unwrap();
            }
        });
        MockServer {
            addr,
            _handle: handle,
        }
    }

    fn mock_store(addr: SocketAddr, auth: AuthMethod) -> HttpEnvironmentStore {
        HttpEnvironmentStore::new(Url::parse(&format!("http://{addr}")).unwrap(), auth)
    }

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn idem() -> IdempotencyKey {
        IdempotencyKey::new("01JABC000000000000000000ZZ").unwrap()
    }

    // -----------------------------------------------------------------------
    // Environment lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn create_environment_happy_path() {
        let body = serde_json::json!({
            "schema": "greentic.environment.v1",
            "environment_id": "local",
            "name": "test",
            "host_config": {"env_id": "local"},
            "packs": [],
            "bundles": [],
            "revisions": [],
            "traffic_splits": [],
            "messaging_endpoints": [],
            "extensions": [],
            "revocation": {},
            "retention": {},
            "health": {}
        });
        let mock = start_mock(vec![(201, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.create_environment(
            &env_id(),
            "test".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            },
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test");
    }

    #[test]
    fn create_environment_conflict_returns_conflict() {
        let err_body = serde_json::json!({
            "kind": "idempotency-conflict",
            "reason": "environment already exists"
        });
        let mock = start_mock(vec![(409, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.create_environment(
            &env_id(),
            "test".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
            },
        );
        assert!(matches!(result, Err(StoreError::Conflict(_))));
    }

    #[test]
    fn update_environment_happy_path() {
        let body = serde_json::json!({
            "schema": "greentic.environment.v1",
            "environment_id": "local",
            "name": "updated",
            "host_config": {"env_id": "local"},
            "packs": [],
            "bundles": [],
            "revisions": [],
            "traffic_splits": [],
            "messaging_endpoints": [],
            "extensions": [],
            "revocation": {},
            "retention": {},
            "health": {}
        });
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_environment(
            &env_id(),
            UpdateEnvironmentPayload {
                name: Some("updated".to_string()),
                ..Default::default()
            },
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "updated");
    }

    #[test]
    fn update_environment_not_found() {
        let err_body = serde_json::json!({"kind": "not-found"});
        let mock = start_mock(vec![(404, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    // -----------------------------------------------------------------------
    // Migration
    // -----------------------------------------------------------------------

    #[test]
    fn migrate_merge_bindings_happy_path() {
        let body = serde_json::json!({
            "merged_slots": ["messaging"],
            "merged_extensions": ["capability/memory/long-term"]
        });
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.migrate_merge_bindings(
            &env_id(),
            MigrateMergePayload {
                packs: Vec::new(),
                extensions: Vec::new(),
                seed_if_missing: None,
            },
        );
        assert!(result.is_ok());
        let (slots, exts) = result.unwrap();
        assert_eq!(slots, vec!["messaging"]);
        assert_eq!(exts, vec!["capability/memory/long-term"]);
    }

    // -----------------------------------------------------------------------
    // Revision lifecycle
    // -----------------------------------------------------------------------

    fn sample_revision_response() -> String {
        serde_json::json!({
            "schema": "greentic.revision.v1",
            "revision_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
            "env_id": "local",
            "bundle_id": "fast2flow",
            "deployment_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
            "sequence": 1,
            "created_at": "2026-06-09T12:00:00Z",
            "bundle_digest": "sha256:00",
            "pack_list": [],
            "pack_list_lock_ref": "",
            "pack_config_refs": [],
            "config_digest": "sha256:00",
            "signature_sidecar_ref": "rev.sig",
            "lifecycle": "staged",
            "staged_at": "2026-06-09T12:00:00Z",
            "drain_seconds": 30,
            "abort_metrics": []
        })
        .to_string()
    }

    #[test]
    fn stage_revision_happy_path() {
        let body = sample_revision_response();
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.stage_revision(
            &env_id(),
            StageRevisionPayload {
                revision_id: RevisionId::new(),
                deployment_id: DeploymentId::new(),
                bundle_digest: "sha256:00".to_string(),
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                drain_seconds: 30,
                idempotency_key: idem(),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn stage_revision_422_returns_invalid_argument() {
        let err_body = serde_json::json!({
            "kind": "integrity-mismatch",
            "expected": "abc",
            "actual": "def"
        });
        let mock = start_mock(vec![(422, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.stage_revision(
            &env_id(),
            StageRevisionPayload {
                revision_id: RevisionId::new(),
                deployment_id: DeploymentId::new(),
                bundle_digest: "sha256:00".to_string(),
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                drain_seconds: 30,
                idempotency_key: idem(),
            },
        );
        assert!(matches!(result, Err(StoreError::InvalidArgument(_))));
    }

    fn sample_transition_response(lifecycle: &str) -> String {
        serde_json::json!({
            "revision": {
                "schema": "greentic.revision.v1",
                "revision_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
                "env_id": "local",
                "bundle_id": "fast2flow",
                "deployment_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
                "sequence": 1,
                "created_at": "2026-06-09T12:00:00Z",
                "bundle_digest": "sha256:00",
                "pack_list": [],
                "pack_list_lock_ref": "",
                "pack_config_refs": [],
                "config_digest": "sha256:00",
                "signature_sidecar_ref": "rev.sig",
                "lifecycle": lifecycle,
                "staged_at": "2026-06-09T12:00:00Z",
                "drain_seconds": 30,
                "abort_metrics": []
            },
            "environment": {
                "schema": "greentic.environment.v1",
                "environment_id": "local",
                "name": "test",
                "host_config": {"env_id": "local"},
                "packs": [],
                "bundles": [],
                "revisions": [],
                "traffic_splits": [],
                "messaging_endpoints": [],
                "extensions": [],
                "revocation": {},
                "retention": {},
                "health": {}
            },
            "starting_lifecycle": "staged"
        })
        .to_string()
    }

    #[test]
    fn warm_revision_happy_path() {
        let body = sample_transition_response("ready");
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.warm_revision(
            &env_id(),
            WarmRevisionPayload {
                revision_id: RevisionId::new(),
                health_gate: Ok(()),
                idempotency_key: idem(),
                expected_lifecycle: RevisionLifecycle::Staged,
            },
        );
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(outcome.starting_lifecycle, RevisionLifecycle::Staged);
    }

    #[test]
    fn drain_revision_happy_path() {
        let body = sample_transition_response("draining");
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.drain_revision(&env_id(), RevisionId::new(), idem());
        assert!(result.is_ok());
    }

    #[test]
    fn archive_revision_happy_path() {
        let body = sample_transition_response("archived");
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.archive_revision(&env_id(), RevisionId::new(), idem());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Bundle CRUD
    // -----------------------------------------------------------------------

    fn sample_bundle_deployment() -> String {
        serde_json::json!({
            "schema": "greentic.bundle-deployment.v1",
            "deployment_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
            "env_id": "local",
            "bundle_id": "fast2flow",
            "customer_id": "local-dev",
            "status": "active",
            "current_revisions": [],
            "route_binding": {
                "hosts": ["fast2flow.local"],
                "path_prefixes": [],
                "tenant_selector": {"tenant": "default", "team": "default"}
            },
            "revenue_share": [{"party_id": "greentic", "basis_points": 10000}],
            "revenue_policy_ref": "revenue.json",
            "created_at": "2026-06-09T12:00:00Z",
            "authorization_ref": "auth.json",
            "config_overrides": {}
        })
        .to_string()
    }

    #[test]
    fn add_bundle_happy_path() {
        let body = sample_bundle_deployment();
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.add_bundle(
            &env_id(),
            AddBundlePayload {
                bundle_id: BundleId::new("fast2flow"),
                customer_id: CustomerId::new("local-dev"),
                revenue_share: Vec::new(),
                route_binding: None,
                authorization_ref: None,
                config_overrides: BTreeMap::new(),
                idempotency_key: idem(),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn update_bundle_happy_path() {
        let body = sample_bundle_deployment();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_bundle(
            &env_id(),
            UpdateBundlePayload {
                deployment_id: DeploymentId::new(),
                status: Some(BundleDeploymentStatus::Active),
                route_binding: None,
                revenue_share: None,
                config_overrides: None,
                idempotency_key: idem(),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn remove_bundle_happy_path() {
        let body = serde_json::json!({
            "deployment": {
                "schema": "greentic.bundle-deployment.v1",
                "deployment_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
                "env_id": "local",
                "bundle_id": "fast2flow",
                "customer_id": "local-dev",
                "status": "active",
                "current_revisions": [],
                "route_binding": {
                    "hosts": ["fast2flow.local"],
                    "path_prefixes": [],
                    "tenant_selector": {"tenant": "default", "team": "default"}
                },
                "revenue_share": [{"party_id": "greentic", "basis_points": 10000}],
                "revenue_policy_ref": "revenue.json",
                "created_at": "2026-06-09T12:00:00Z",
                "authorization_ref": "auth.json",
                "config_overrides": {}
            },
            "pruned_revision_ids": []
        });
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.remove_bundle(&env_id(), DeploymentId::new(), idem());
        assert!(result.is_ok());
        assert!(result.unwrap().pruned_revision_ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // Pack binding CRUD
    // -----------------------------------------------------------------------

    fn sample_pack_binding() -> String {
        serde_json::json!({
            "slot": "messaging",
            "kind": "greentic.messaging@0.5.0",
            "pack_ref": "greentic-messaging",
            "generation": 1
        })
        .to_string()
    }

    fn sample_binding_generation_response(binding_json: &str, generation: u64) -> String {
        format!(r#"{{"binding": {binding_json}, "generation": {generation}}}"#)
    }

    #[test]
    fn add_pack_binding_happy_path() {
        let body = sample_pack_binding();
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let binding: EnvPackBinding = serde_json::from_str(&body).unwrap();
        let result = store.add_pack_binding(&env_id(), binding, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn update_pack_binding_happy_path() {
        let binding_json = sample_pack_binding();
        let body = sample_binding_generation_response(&binding_json, 2);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let binding: EnvPackBinding = serde_json::from_str(&binding_json).unwrap();
        let result =
            store.update_pack_binding(&env_id(), CapabilitySlot::Messaging, binding, idem());
        assert!(result.is_ok());
        let (_, generation) = result.unwrap();
        assert_eq!(generation, 2);
    }

    #[test]
    fn remove_pack_binding_happy_path() {
        let binding_json = sample_pack_binding();
        let body = sample_binding_generation_response(&binding_json, 3);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.remove_pack_binding(&env_id(), CapabilitySlot::Messaging, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn rollback_pack_binding_happy_path() {
        let binding_json = sample_pack_binding();
        let body = sample_binding_generation_response(&binding_json, 4);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.rollback_pack_binding(&env_id(), CapabilitySlot::Messaging, idem());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Extension binding CRUD
    // -----------------------------------------------------------------------

    fn sample_extension_binding() -> String {
        serde_json::json!({
            "kind": "greentic.memory-chronicle@0.1.0",
            "pack_ref": "greentic-chronicle",
            "generation": 1
        })
        .to_string()
    }

    #[test]
    fn add_extension_binding_happy_path() {
        let body = sample_extension_binding();
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let binding: ExtensionBinding = serde_json::from_str(&body).unwrap();
        let result = store.add_extension_binding(&env_id(), binding, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn update_extension_binding_happy_path() {
        let ext_json = sample_extension_binding();
        let body = sample_binding_generation_response(&ext_json, 2);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let binding: ExtensionBinding = serde_json::from_str(&ext_json).unwrap();
        let key = ExtensionKey::new("capability/memory/long-term", None);
        let result = store.update_extension_binding(&env_id(), key, binding, idem());
        assert!(result.is_ok());
        let (_, generation) = result.unwrap();
        assert_eq!(generation, 2);
    }

    #[test]
    fn remove_extension_binding_happy_path() {
        let ext_json = sample_extension_binding();
        let body = sample_binding_generation_response(&ext_json, 3);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let key = ExtensionKey::new("capability/memory/long-term", None);
        let result = store.remove_extension_binding(&env_id(), key, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn rollback_extension_binding_happy_path() {
        let ext_json = sample_extension_binding();
        let body = sample_binding_generation_response(&ext_json, 4);
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let key = ExtensionKey::new("capability/memory/long-term", None);
        let result = store.rollback_extension_binding(&env_id(), key, idem());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Traffic
    // -----------------------------------------------------------------------

    fn sample_traffic_split() -> serde_json::Value {
        serde_json::json!({
            "schema": "greentic.traffic-split.v1",
            "env_id": "local",
            "deployment_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
            "bundle_id": "fast2flow",
            "generation": 2,
            "entries": [],
            "updated_at": "2026-06-09T12:00:00Z",
            "updated_by": "tester",
            "idempotency_key": "01JABC000000000000000000ZZ",
            "authorization_ref": "auth.json"
        })
    }

    #[test]
    fn set_traffic_split_happy_path() {
        let body = serde_json::json!({
            "split": sample_traffic_split(),
            "previous_generation": 1,
            "new_generation": 2
        });
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.set_traffic_split(
            &env_id(),
            DeploymentId::new(),
            Vec::new(),
            idem(),
            "tester".to_string(),
            None,
        );
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.previous_generation, Some(1));
        assert_eq!(outcome.new_generation, Some(2));
    }

    #[test]
    fn rollback_traffic_split_happy_path() {
        let body = serde_json::json!({
            "restored": sample_traffic_split(),
            "previous_generation": 2,
            "new_generation": 3
        });
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.rollback_traffic_split(&env_id(), DeploymentId::new(), idem());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Messaging endpoints
    // -----------------------------------------------------------------------

    fn sample_messaging_endpoint() -> String {
        serde_json::json!({
            "schema": "greentic.messaging-endpoint.v1",
            "env_id": "local",
            "endpoint_id": "01JTKW5B4W4Q5Y1CQW93F7S5VH",
            "provider_id": "tg-bot",
            "provider_type": "telegram",
            "display_name": "Telegram Bot",
            "secret_refs": [],
            "linked_bundles": [],
            "generation": 0,
            "created_at": "2026-06-09T12:00:00Z",
            "updated_at": "2026-06-09T12:00:00Z",
            "updated_by": "tester"
        })
        .to_string()
    }

    #[test]
    fn add_messaging_endpoint_happy_path() {
        let body = sample_messaging_endpoint();
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.add_messaging_endpoint(
            &env_id(),
            AddMessagingEndpointPayload {
                provider_id: "tg-bot".to_string(),
                provider_type: "telegram".to_string(),
                display_name: "Telegram Bot".to_string(),
                secret_refs: Vec::new(),
                updated_by: "tester".to_string(),
                idempotency_key: idem(),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn link_messaging_bundle_happy_path() {
        let body = sample_messaging_endpoint();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.link_messaging_bundle(
            &env_id(),
            MessagingEndpointId::new(),
            BundleId::new("fast2flow"),
            "tester".to_string(),
            idem(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn unlink_messaging_bundle_happy_path() {
        let body = sample_messaging_endpoint();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.unlink_messaging_bundle(
            &env_id(),
            MessagingEndpointId::new(),
            BundleId::new("fast2flow"),
            "tester".to_string(),
            idem(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn set_messaging_welcome_flow_happy_path() {
        let body = sample_messaging_endpoint();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.set_messaging_welcome_flow(
            &env_id(),
            SetMessagingWelcomeFlowPayload {
                endpoint_id: MessagingEndpointId::new(),
                bundle_id: BundleId::new("fast2flow"),
                pack_id: PackId::new("greentic-messaging"),
                flow_id: "welcome".to_string(),
                updated_by: "tester".to_string(),
                idempotency_key: idem(),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn remove_messaging_endpoint_happy_path() {
        let eid = MessagingEndpointId::new();
        let body = serde_json::json!(eid.to_string());
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.remove_messaging_endpoint(&env_id(), eid);
        assert!(result.is_ok());
    }

    #[test]
    fn rotate_messaging_webhook_secret_happy_path() {
        let body = sample_messaging_endpoint();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.rotate_messaging_webhook_secret(
            &env_id(),
            MessagingEndpointId::new(),
            "tester".to_string(),
            idem(),
        );
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Trust root
    // -----------------------------------------------------------------------

    fn sample_trust_root_seed() -> String {
        serde_json::json!({
            "key_id": "op-key-1",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
            "trusted_key_count": 1
        })
        .to_string()
    }

    #[test]
    fn bootstrap_trust_root_happy_path() {
        let body = sample_trust_root_seed();
        let mock = start_mock(vec![(201, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.bootstrap_trust_root(&env_id());
        assert!(result.is_ok());
        let seed = result.unwrap();
        assert_eq!(seed.key_id, "op-key-1");
        assert_eq!(seed.trusted_key_count, 1);
    }

    #[test]
    fn seed_trust_root_if_absent_when_seeded() {
        let body = sample_trust_root_seed();
        let mock = start_mock(vec![(200, &body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.seed_trust_root_if_absent(&env_id());
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn seed_trust_root_if_absent_when_already_exists() {
        let mock = start_mock(vec![(200, "null")], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.seed_trust_root_if_absent(&env_id());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn add_trusted_key_happy_path() {
        let body = serde_json::json!({
            "added_key_id": "external-key-1",
            "trusted_key_count": 2
        });
        let mock = start_mock(vec![(201, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.add_trusted_key(
            &env_id(),
            "external-key-1".to_string(),
            "PEM-DATA".to_string(),
            idem(),
        );
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.added_key_id, "external-key-1");
        assert_eq!(outcome.trusted_key_count, 2);
    }

    #[test]
    fn remove_trusted_key_happy_path() {
        let body = serde_json::json!({
            "removed_key_id": "external-key-1",
            "removed_public_key_pem": "PEM-DATA",
            "trusted_key_count": 1
        });
        let mock = start_mock(vec![(200, &body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.remove_trusted_key(&env_id(), "external-key-1".to_string(), idem());
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.removed_key_id, "external-key-1");
        assert_eq!(outcome.removed_public_key_pem, Some("PEM-DATA".to_string()));
    }

    // -----------------------------------------------------------------------
    // Auth + header tests
    // -----------------------------------------------------------------------

    #[test]
    fn bearer_auth_sends_authorization_header() {
        let body = sample_trust_root_seed();
        let check = Arc::new(|_req_line: &str, headers: &str, _body: &[u8]| {
            assert!(
                headers.contains("Authorization: Bearer my-secret-token"),
                "expected Bearer header in: {headers}"
            );
        });
        let mock = start_mock(vec![(200, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::Bearer("my-secret-token".to_string()));
        let _ = store.bootstrap_trust_root(&env_id());
    }

    #[test]
    fn idempotency_key_header_is_sent() {
        let body = sample_revision_response();
        let check = Arc::new(|_req_line: &str, headers: &str, _body: &[u8]| {
            assert!(
                headers.contains("Idempotency-Key: 01JABC000000000000000000ZZ"),
                "expected Idempotency-Key header in: {headers}"
            );
        });
        let mock = start_mock(vec![(201, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::None);
        let _ = store.stage_revision(
            &env_id(),
            StageRevisionPayload {
                revision_id: RevisionId::new(),
                deployment_id: DeploymentId::new(),
                bundle_digest: "sha256:00".to_string(),
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                drain_seconds: 30,
                idempotency_key: idem(),
            },
        );
    }

    // -----------------------------------------------------------------------
    // Error mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_404_maps_to_not_found() {
        let err_body = serde_json::json!({"kind": "not-found"});
        let mock = start_mock(vec![(404, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    #[test]
    fn error_409_maps_to_conflict() {
        let err_body = serde_json::json!({
            "kind": "idempotency-conflict",
            "reason": "key reused"
        });
        let mock = start_mock(vec![(409, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        assert!(matches!(result, Err(StoreError::Conflict(_))));
    }

    #[test]
    fn error_500_maps_to_conflict_server() {
        let err_body = serde_json::json!({
            "kind": "internal",
            "message": "disk full"
        });
        let mock = start_mock(vec![(500, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Conflict(msg)) => {
                assert!(
                    msg.contains("server:"),
                    "expected 'server:' prefix, got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn error_403_maps_to_conflict_authorization() {
        let err_body = serde_json::json!({
            "kind": "unauthorized",
            "policy": "rbac-v1",
            "reason": "insufficient permissions"
        });
        let mock = start_mock(vec![(403, &err_body.to_string())], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Conflict(msg)) => {
                assert!(
                    msg.contains("authorization:"),
                    "expected 'authorization:' prefix, got: {msg}"
                );
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn transport_error_maps_to_conflict() {
        // Connect to a port that is definitely not listening.
        let store =
            HttpEnvironmentStore::new(Url::parse("http://127.0.0.1:1").unwrap(), AuthMethod::None);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Conflict(msg)) => {
                assert!(
                    msg.starts_with("transport:"),
                    "expected 'transport:' prefix, got: {msg}"
                );
            }
            other => panic!("expected Conflict(transport:...), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Object-safety compile guard (same as mutations.rs)
    // -----------------------------------------------------------------------

    #[allow(dead_code)]
    fn _http_store_is_trait_object(store: &HttpEnvironmentStore) {
        let _dyn: &dyn EnvironmentMutations = store;
    }
}
