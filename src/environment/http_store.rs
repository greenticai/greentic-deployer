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
//! | `load_environment`            | GET    | `/environments/{env_id}`                                  |
//!
//! `load_environment` is the one READ verb (no idempotency key, no audit
//! envelope) — the remote dispatch uses it to evaluate client-side
//! preconditions such as the `warm` health-gate's expected lifecycle.
//!
//! The backup/restore group (A8 #5, PR-4.4) is server-only — `LocalFsStore`
//! has no implementation, so these are inherent methods on
//! [`HttpEnvironmentStore`], not `EnvironmentMutations` verbs:
//!
//! | Inherent method               | Method | Path                                                      |
//! |-------------------------------|--------|-----------------------------------------------------------|
//! | `create_backup`               | POST   | `/environments/{env_id}/backups`                          |
//! | `list_backups`                | GET    | `/environments/{env_id}/backups`                          |
//! | `delete_backup`               | DELETE | `/environments/{env_id}/backups/{backup_id}`              |
//! | `restore`                     | POST   | `/environments/{env_id}/restore`                          |
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

use greentic_deploy_spec::{
    AuditDecision, AuditEvent, AuditResult, BackupManifest, BindingGenerationOutcome,
    BundleDeployment, BundleId, CapabilitySlot, DeploymentId, EnvId, EnvPackBinding, Environment,
    EnvironmentHostConfig, EnvironmentRuntime, ExtensionBinding, ExtensionBindingPayload,
    ExtensionKeyedPayload, IdempotencyKey, IdempotencyOutcome, MessagingBundleLinkPayload,
    MessagingEndpoint, MessagingEndpointId, PackBindingPayload, RemoteStoreError, RestoreOutcome,
    RestoreRequest, Revision, RevisionId, RollbackTrafficSplitPayload, RotateWebhookSecretPayload,
    StateEtag,
};
use greentic_distributor_client::signing::TrustedKey;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use super::reads::EnvironmentReads;

use super::mutations::{
    AddBundlePayload, AddMessagingEndpointPayload, AddTrustedKeyPayload, ApplyTrafficSplitOutcome,
    EnvironmentMutations, ExtensionKey, MigrateMergePayload, RemoveBundleOutcome,
    RevisionTransitionOutcome, RollbackTrafficSplitOutcome, SetMessagingWelcomeFlowPayload,
    SetTrafficSplitPayload, StageRevisionPayload, TrustRootAddOutcome, TrustRootRemoveOutcome,
    TrustRootSeed, UpdateBundlePayload, UpdateEnvironmentPayload, WarmRevisionPayload,
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
// URL path-segment encoding (Fix 1: prevent path-traversal via dynamic IDs)
// ---------------------------------------------------------------------------

/// Characters that MUST be percent-encoded when interpolated into a URL path
/// segment. Covers RFC 3986 reserved + unsafe characters that `Url::join`
/// would otherwise interpret structurally (`/`, `?`, `#`, `..` via `.`).
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%')
    .add(b'.');

/// Percent-encode a dynamic identifier for safe interpolation into a URL path
/// segment. Normal alphanumeric identifiers pass through unchanged; characters
/// like `/`, `..`, `?`, `#` are escaped so they cannot alter the request path.
fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, PATH_SEGMENT_ENCODE_SET).to_string()
}

// ---------------------------------------------------------------------------
// Construction errors
// ---------------------------------------------------------------------------

/// Errors that can occur when constructing an [`HttpEnvironmentStore`].
#[derive(Debug, thiserror::Error)]
pub enum ConstructionError {
    /// Bearer auth over plaintext HTTP to a non-loopback host exposes the token.
    #[error(
        "bearer auth over http:// is only allowed to loopback hosts; \
         got `{0}` — use https:// or AuthMethod::None"
    )]
    InsecureTransport(String),
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
    /// Pre-rendered `Authorization: Bearer <token>` value, built once at
    /// construction. `None` when [`AuthMethod::None`].
    auth_header_value: Option<String>,
}

/// Ensure `base_url`'s path ends with `/` so [`Url::join`] treats relative
/// paths as siblings of the base, not replacements of the last segment.
/// Idempotent — called once at construction.
fn normalize_base_url(mut base_url: Url) -> Url {
    if !base_url.path().ends_with('/') {
        let normalized = format!("{}/", base_url.path());
        base_url.set_path(&normalized);
    }
    base_url
}

/// Whether `url` points at a loopback address (`127.0.0.0/8`, `::1`, or
/// `localhost`). Used by the insecure-transport guard.
fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

/// Validate that bearer auth is not used over plaintext HTTP to non-loopback.
fn validate_transport(url: &Url, auth: &AuthMethod) -> Result<(), ConstructionError> {
    if let AuthMethod::Bearer(_) = auth
        && url.scheme() == "http"
    {
        if is_loopback(url) {
            tracing::warn!(
                url = %url,
                "bearer auth over http:// to loopback — acceptable for dev, \
                 not for production"
            );
        } else {
            return Err(ConstructionError::InsecureTransport(
                url.host_str().unwrap_or("<none>").to_string(),
            ));
        }
    }
    Ok(())
}

impl HttpEnvironmentStore {
    /// Build with the default `reqwest::blocking::Client`.
    ///
    /// Returns [`ConstructionError::InsecureTransport`] if `auth` is
    /// [`AuthMethod::Bearer`] and `base_url` is `http://` to a non-loopback
    /// host.
    pub fn new(base_url: Url, auth: AuthMethod) -> Result<Self, ConstructionError> {
        Self::with_client(Client::new(), base_url, auth)
    }

    /// Build with a caller-supplied client (custom timeouts, TLS config, etc.).
    ///
    /// Returns [`ConstructionError::InsecureTransport`] if `auth` is
    /// [`AuthMethod::Bearer`] and `base_url` is `http://` to a non-loopback
    /// host.
    pub fn with_client(
        client: Client,
        base_url: Url,
        auth: AuthMethod,
    ) -> Result<Self, ConstructionError> {
        validate_transport(&base_url, &auth)?;
        let auth_header_value = match auth {
            AuthMethod::Bearer(token) => Some(format!("Bearer {token}")),
            AuthMethod::None => None,
        };
        Ok(Self {
            client,
            base_url: normalize_base_url(base_url),
            auth_header_value,
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build a full URL by joining `path` onto `base_url`. The base is
    /// trailing-slash-normalized in the constructor so [`Url::join`] resolves
    /// `path` relative to the API root, not by replacing the last segment.
    fn url(&self, path: &str) -> Result<Url, StoreError> {
        self.base_url
            .join(path)
            .map_err(|e| StoreError::Conflict(format!("transport: invalid URL path `{path}`: {e}")))
    }

    /// Build the env-scoped request path: `environments/{env}{suffix}`. The
    /// returned string is suitable for [`Self::send_mutation`] et al; pass
    /// `""` for the env itself or `"/revisions"` (already-encoded) for
    /// sub-resources. For multi-segment paths (e.g. `/revisions/{rid}/warm`),
    /// callers still encode each dynamic segment themselves and inline the
    /// `format!` — the helper is only a win for the env-only and
    /// env+constant-suffix shapes.
    fn env_path(&self, env_id: &EnvId, suffix: &str) -> String {
        format!("environments/{}{suffix}", encode_segment(env_id.as_str()))
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

        if let Some(value) = &self.auth_header_value {
            builder = builder.header("Authorization", value);
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
            // After a 2xx the mutation may already be committed server-side.
            // Decode failures must not look retriable-with-a-fresh-key — wrap
            // them in `CommittedAfterSave`. Safe because `send_mutation` is
            // `send`'s only caller, so the 2xx path is exclusively mutations.
            if status == reqwest::StatusCode::NO_CONTENT {
                return serde_json::from_str("null").map_err(|e| {
                    committed_after_save(
                        format!("transport: cannot deserialize 204 body: {e}"),
                        idempotency_key,
                    )
                });
            }
            response.json::<R>().map_err(|e| {
                committed_after_save(
                    format!("transport: invalid response body: {e}"),
                    idempotency_key,
                )
            })
        } else {
            Err(map_error_response(status, response))
        }
    }

    /// Send a mutating request whose A8 response is a [`MutationEnvelope`]
    /// wrapping the domain result alongside ETag/generation/idempotency
    /// metadata. Enforces the A8 §4 audit invariant on the success envelope
    /// (see [`MutationEnvelope::validated`]) against `expected_env` — the
    /// env the request targeted — then returns only the domain `result`;
    /// PR-3b-fu will surface the remaining envelope metadata via a
    /// return-type extension.
    fn send_mutation<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        expected_env: &EnvId,
        method: reqwest::Method,
        path: &str,
        idempotency_key: Option<&str>,
        body: Option<&P>,
    ) -> Result<R, StoreError> {
        let envelope: MutationEnvelope<R> = self.send(method, path, idempotency_key, body)?;
        envelope.validated(expected_env, idempotency_key)
    }

    /// [`send_mutation`](Self::send_mutation) variant with no request body.
    fn send_mutation_no_body<R: serde::de::DeserializeOwned>(
        &self,
        expected_env: &EnvId,
        method: reqwest::Method,
        path: &str,
        idempotency_key: Option<&str>,
    ) -> Result<R, StoreError> {
        self.send_mutation::<(), R>(expected_env, method, path, idempotency_key, None)
    }

    // -----------------------------------------------------------------------
    // Backup / restore (A8 #5, PR-4.4) — server-only operations
    // -----------------------------------------------------------------------
    //
    // `LocalFsStore` has no backup implementation (a local store is backed
    // up by copying the directory), so these live as inherent methods
    // rather than `EnvironmentMutations` verbs. The mutating three wear the
    // standard A8 envelope (audit validation applies unchanged); `list` is
    // a plain read.

    /// `POST /environments/{env_id}/backups` — snapshot the environment's
    /// stored state server-side; returns the contract's manifest.
    pub fn create_backup(
        &self,
        env_id: &EnvId,
        idempotency_key: &IdempotencyKey,
    ) -> Result<BackupManifest, StoreError> {
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/backups"),
            Some(idempotency_key.as_str()),
        )
    }

    /// `GET /environments/{env_id}/backups` — list backup manifests,
    /// oldest first.
    pub fn list_backups(&self, env_id: &EnvId) -> Result<Vec<BackupManifest>, StoreError> {
        #[derive(Deserialize)]
        struct BackupsResponse {
            backups: Vec<BackupManifest>,
        }
        let response: BackupsResponse = self.send::<(), _>(
            reqwest::Method::GET,
            &self.env_path(env_id, "/backups"),
            None,
            None,
        )?;
        Ok(response.backups)
    }

    /// `DELETE /environments/{env_id}/backups/{backup_id}` — drop one
    /// backup (the server's per-env backup store is bounded; at the cap,
    /// `create_backup` refuses until old ones are deleted).
    pub fn delete_backup(
        &self,
        env_id: &EnvId,
        backup_id: &str,
        idempotency_key: &IdempotencyKey,
    ) -> Result<(), StoreError> {
        let path = format!(
            "{}/{}",
            self.env_path(env_id, "/backups"),
            encode_segment(backup_id)
        );
        let _ack: serde_json::Value = self.send_mutation_no_body(
            env_id,
            reqwest::Method::DELETE,
            &path,
            Some(idempotency_key.as_str()),
        )?;
        Ok(())
    }

    /// `POST /environments/{env_id}/restore` — restore the environment
    /// from a named backup. `request.precondition` MUST pin prior state
    /// (the server answers 428 otherwise; a stale pin is a 412). The
    /// returned outcome's `integrity` equals the backup's recorded digest,
    /// and [`RestoreOutcome::etag`] is the restored state's strong
    /// validator for the next CAS write.
    pub fn restore(
        &self,
        env_id: &EnvId,
        request: &RestoreRequest,
        idempotency_key: &IdempotencyKey,
    ) -> Result<RestoreOutcome, StoreError> {
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/restore"),
            Some(idempotency_key.as_str()),
            Some(request),
        )
    }

    /// `GET /environments/{env_id}/trust-root` — the env's trusted-key set
    /// (empty for an absent row, which the server treats as closed-by-default;
    /// a missing ENV is still a 404 → [`StoreError::NotFound`]). Inherent
    /// rather than on [`EnvironmentReads`] because trust roots are a separate
    /// document with their own error type and have no `LocalFsStore`
    /// equivalent on that trait.
    pub fn load_trust_root_keys(&self, env_id: &EnvId) -> Result<Vec<TrustedKey>, StoreError> {
        #[derive(Deserialize)]
        struct TrustRootResponse {
            keys: Vec<TrustedKey>,
        }
        let response: TrustRootResponse = self.send::<(), _>(
            reqwest::Method::GET,
            &self.env_path(env_id, "/trust-root"),
            None,
            None,
        )?;
        Ok(response.keys)
    }
}

impl EnvironmentReads for HttpEnvironmentStore {
    /// `GET /environments` → the sorted env-id set (RBAC read-scope filtering
    /// is applied server-side).
    fn list_env_ids(&self) -> Result<Vec<EnvId>, StoreError> {
        #[derive(Deserialize)]
        struct EnvsResponse {
            environments: Vec<EnvId>,
        }
        let response: EnvsResponse =
            self.send::<(), _>(reqwest::Method::GET, "environments", None, None)?;
        Ok(response.environments)
    }

    /// A `GET` of the env mapped to a boolean: 200 → present, 404 → absent.
    fn env_exists(&self, env_id: &EnvId) -> Result<bool, StoreError> {
        match self.load_env(env_id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound(_)) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// The environment document. Delegates to the mutation-side read
    /// [`EnvironmentMutations::load_environment`] (`GET
    /// /environments/{env_id}`) so the env GET shape lives in one place; the
    /// read verbs only project the returned document.
    fn load_env(&self, env_id: &EnvId) -> Result<Environment, StoreError> {
        EnvironmentMutations::load_environment(self, env_id)
    }

    /// `GET /environments/{env_id}/runtime` → the runtime host-config sidecar
    /// (`null` when none has been written) so remote `env show` reports the
    /// real runtime instead of conflating "absent" with "not exposed".
    fn read_runtime(&self, env_id: &EnvId) -> Result<Option<EnvironmentRuntime>, StoreError> {
        #[derive(Deserialize)]
        struct GetRuntimeResponse {
            runtime: Option<EnvironmentRuntime>,
        }
        let response: GetRuntimeResponse = self.send::<(), _>(
            reqwest::Method::GET,
            &self.env_path(env_id, "/runtime"),
            None,
            None,
        )?;
        Ok(response.runtime)
    }
}

/// PR-4.0 (F2): enforce the A8 §4 audit invariant on a success envelope.
///
/// The local path fails closed on audit via `cli::audit_and_record`; the
/// remote path skips local audit because the server owns the durable record
/// (A8 §4). That hand-off is only sound if the server actually returned the
/// record — so a 2xx envelope missing it, or carrying one that contradicts
/// the success (a `deny` decision, a non-`ok` result) or names a different
/// environment than the request targeted, is a contract violation the client
/// must reject rather than report as success.
///
/// `sent_idempotency_key`: when `Some(key)`, the audit record's
/// `idempotency_key` must match — otherwise a stale record from a
/// different request could satisfy the check. A8 §2 replays carry the
/// SAME key by definition, so replays pass. When `None` (no current
/// caller supplies one), the equality check is skipped.
fn validate_success_audit(
    audit: Option<&AuditEvent>,
    expected_env: &EnvId,
    sent_idempotency_key: Option<&str>,
) -> Result<(), StoreError> {
    let Some(audit) = audit else {
        return Err(StoreError::Conflict(
            "A8 contract violation: success response is missing the audit record (§4)".to_string(),
        ));
    };
    if let AuditDecision::Deny { policy, reason } = &audit.authorization {
        return Err(StoreError::Conflict(format!(
            "A8 contract violation: success response carries a deny audit decision \
             (policy `{policy}`: {reason}); a denial must be a 403"
        )));
    }
    match &audit.result {
        AuditResult::Ok => {}
        other => {
            return Err(StoreError::Conflict(format!(
                "A8 contract violation: success response carries a non-ok audit result \
                 ({other:?})"
            )));
        }
    }
    if audit.env_id != expected_env.as_str() {
        return Err(StoreError::Conflict(format!(
            "A8 contract violation: audit record names env `{}` but the request targeted \
             env `{expected_env}`",
            audit.env_id
        )));
    }
    // Bind the audit record to the request via the idempotency key: a
    // stale same-env record cannot carry the request's fresh ULID.
    if let Some(sent) = sent_idempotency_key {
        let audit_key = audit.idempotency_key.as_deref();
        if audit_key != Some(sent) {
            return Err(StoreError::Conflict(format!(
                "A8 contract violation: audit record idempotency key `{}` does not match \
                 the request's key `{sent}` — the record does not belong to this mutation",
                audit_key.unwrap_or("<missing>")
            )));
        }
    }
    Ok(())
}

/// Wrap a post-2xx failure in [`StoreError::CommittedAfterSave`] with the
/// shared replay guidance. After a 2xx status the mutation may already be
/// committed server-side, so the error must not look retriable — re-running
/// with a freshly minted idempotency key would double-apply, while the SAME
/// key replays (A8 §2).
fn committed_after_save(message: String, idempotency_key: Option<&str>) -> StoreError {
    let replay = match idempotency_key {
        Some(key) => format!(" — replay with Idempotency-Key `{key}` instead of re-applying"),
        None => {
            " — re-running with the SAME Idempotency-Key replays instead of re-applying".to_string()
        }
    };
    StoreError::CommittedAfterSave(Box::new(StoreError::Conflict(format!(
        "{message} — the server reported success (2xx), so the mutation may already be \
         committed{replay}"
    ))))
}

// ---------------------------------------------------------------------------
// A8 mutation-response envelope
// ---------------------------------------------------------------------------

/// The A8 success envelope for mutating calls. The server returns the domain
/// `result` alongside CAS/idempotency/audit metadata defined in
/// [`greentic_deploy_spec::remote::MutationResponse`].
///
/// PR-3b parses the full envelope so that a future return-type extension
/// (PR-3b-fu) can surface ETag/generation without re-parsing. Today the
/// trait methods return bare domain types, so callers see only `result` —
/// except `audit`, which [`validate_success_audit`] enforces on every
/// success (PR-4.0/F2). It stays `Option` so a missing record is rejected
/// with a precise contract-violation message instead of a generic serde
/// deserialize error.
#[derive(Debug, Deserialize)]
struct MutationEnvelope<T> {
    result: T,
    // Fields present per A8 but not yet surfaced to callers (PR-3b-fu).
    #[serde(default)]
    #[allow(dead_code)]
    etag: Option<StateEtag>,
    #[serde(default)]
    #[allow(dead_code)]
    generation: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    idempotency: Option<IdempotencyOutcome>,
    #[serde(default)]
    audit: Option<AuditEvent>,
}

impl<T> MutationEnvelope<T> {
    /// Enforce the A8 §4 audit invariant (see [`validate_success_audit`])
    /// and return the domain `result`. Consuming the envelope here couples
    /// the invariant to the type: any future path that deserializes a
    /// `MutationEnvelope` must go through `validated` to reach the result,
    /// so the check cannot be silently skipped. Violations are wrapped in
    /// [`StoreError::CommittedAfterSave`] — the envelope only exists after
    /// a 2xx, so the mutation may already be committed server-side.
    fn validated(
        self,
        expected_env: &EnvId,
        sent_idempotency_key: Option<&str>,
    ) -> Result<T, StoreError> {
        validate_success_audit(self.audit.as_ref(), expected_env, sent_idempotency_key)
            .map_err(|inner| committed_after_save(inner.to_string(), sent_idempotency_key))?;
        Ok(self.result)
    }
}

/// Mint a one-shot idempotency key for methods whose trait signature does
/// not carry one. Delegates to [`crate::cli::mint_idempotency_key`] so the
/// ULID-generation strategy stays in one place. Returns the inner string for
/// header-value use; each call produces a unique ULID so retries by the
/// caller are safe.
fn mint_idempotency_key() -> String {
    crate::cli::mint_idempotency_key().as_str().to_string()
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
        let actual = status.as_u16();
        let expected = remote_err.http_status();
        // A8 defines `Unauthorized` as 403; accept 401 (unauthenticated) as
        // well since both express a denial. All other kinds must match exactly.
        let consistent = actual == expected
            || (actual == 401 && matches!(remote_err, RemoteStoreError::Unauthorized { .. }));
        if consistent {
            return map_remote_error(remote_err);
        }
        return StoreError::Conflict(format!(
            "A8 contract violation: HTTP status {actual} contradicts the A8 error body \
             (kind expects {expected}): {remote_err}"
        ));
    }

    // Fallback: map by status code with raw body.
    match status.as_u16() {
        404 => StoreError::NotFound(EnvId::try_from("unknown").unwrap_or_else(|_| {
            // EnvId::try_from should not fail for "unknown" but guard anyway.
            unreachable!("EnvId::try_from(\"unknown\") must succeed")
        })),
        409 => StoreError::Conflict(body_text),
        400 | 422 => StoreError::InvalidArgument(body_text),
        // PR-4.0 (F4): a 401/403 whose body is not the A8 error shape (e.g.
        // from a proxy/LB in front of the store) is still a denial — keep
        // the `unauthorized` noun rather than degrading to `conflict`.
        401 | 403 => StoreError::Unauthorized {
            policy: GATEWAY_DENIAL_POLICY.to_string(),
            reason: body_text,
        },
        501 => StoreError::NotYetImplemented(body_text),
        _ => StoreError::Conflict(format!("server ({status}): {body_text}")),
    }
}

/// `policy` value for denials that did not come through the A8 error shape
/// (non-A8 401/403 bodies, e.g. a proxy/LB in front of the store). Named so
/// downstream consumers matching on `policy` have one stable value.
const GATEWAY_DENIAL_POLICY: &str = "remote";

/// Map a parsed [`RemoteStoreError`] to [`StoreError`]. Takes the error by
/// value so the owned `String` fields move instead of cloning.
fn map_remote_error(err: RemoteStoreError) -> StoreError {
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
            StoreError::Unauthorized { policy, reason }
        }
        // Same noun the local impl uses for create-on-existing — the CLI
        // mapper downcasts `Conflict` uniformly across backends.
        RemoteStoreError::AlreadyExists { detail } => StoreError::Conflict(detail),
        RemoteStoreError::Conflict { detail } => StoreError::Conflict(detail),
        RemoteStoreError::DependentNotFound { detail } => StoreError::DependentNotFound(detail),
        // Reconstruct the local store's typed health-gate failure so CLI
        // callers (committed-on-error handling, gate-failed telemetry emit)
        // behave identically against a remote store. The server persisted
        // the `Failed` lifecycle before responding — committed, like local.
        RemoteStoreError::HealthGateFailed {
            revision_id,
            failed_checks,
            message,
        } => StoreError::Lifecycle(Box::new(
            crate::environment::LifecycleError::HealthGateFailed {
                revision_id,
                failed_checks,
                message,
            },
        )),
        RemoteStoreError::InvalidRequest { detail } => StoreError::InvalidArgument(detail),
        RemoteStoreError::IntegrityMismatch { expected, actual } => StoreError::InvalidArgument(
            format!("integrity mismatch: expected {expected}, computed {actual}"),
        ),
        RemoteStoreError::NotYetImplemented { detail } => StoreError::NotYetImplemented(detail),
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

// Env-lifecycle wire shapes (`CreateEnvironmentPayload`,
// `UpdateEnvironmentPayload`, `MigrateMergePayload`, `MergeReport`) moved to
// `greentic_deploy_spec::engine` in PR-4.2a; the revision verb group's
// (`StageRevisionPayload`, `WarmRevisionPayload`,
// `RevisionTransitionOutcome`) followed in PR-4.2b — the payload structs
// now carry serde derives in the exact wire encoding this module
// established, so the client serializes them directly and the
// operator-store-server deserializes the same types. Remaining verb groups
// migrate as their routes land.

// Bundle wire shapes (`AddBundlePayload`, `UpdateBundlePayload`,
// `RemoveBundleOutcome`) are the shared `greentic_deploy_spec::engine`
// types since PR-4.2g — the client serializes the same structs the server
// deserializes.

// Binding wire shapes (`PackBindingPayload`, `ExtensionBindingPayload`,
// `ExtensionKeyedPayload`, `BindingGenerationOutcome`) are the shared
// `greentic_deploy_spec::engine` types since PR-4.2d — the client
// serializes the same structs the server deserializes.

// Traffic wire shapes (`SetTrafficSplitPayload`,
// `RollbackTrafficSplitPayload`, `ApplyTrafficSplitOutcome`,
// `RollbackTrafficSplitOutcome`) are the shared
// `greentic_deploy_spec::engine` types since PR-4.2c — the client
// serializes the same structs the server deserializes.

// Messaging wire shapes (`AddMessagingEndpointPayload`,
// `MessagingBundleLinkPayload`, `SetMessagingWelcomeFlowPayload`,
// `RotateWebhookSecretPayload`) are the shared
// `greentic_deploy_spec::engine` types since PR-4.2h — the client
// serializes the same structs the server deserializes.

// Trust-root wire shapes (`AddTrustedKeyPayload`, `TrustRootSeed`,
// `TrustRootAddOutcome`, `TrustRootRemoveOutcome`) are the shared
// `greentic_deploy_spec::engine` types since PR-4.2f — the client
// serializes/deserializes the same structs the server does.

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
        let idem_key = mint_idempotency_key();
        let req = greentic_deploy_spec::CreateEnvironmentPayload {
            env_id: env_id.clone(),
            name,
            host_config,
        };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            "environments",
            Some(&idem_key),
            Some(&req),
        )
    }

    fn update_environment(
        &self,
        env_id: &EnvId,
        patch: UpdateEnvironmentPayload,
    ) -> Result<Environment, StoreError> {
        let idem_key = mint_idempotency_key();
        self.send_mutation(
            env_id,
            reqwest::Method::PATCH,
            &self.env_path(env_id, ""),
            Some(&idem_key),
            Some(&patch),
        )
    }

    fn load_environment(&self, env_id: &EnvId) -> Result<Environment, StoreError> {
        // `GET /environments/{env_id}` → `GetEnvironmentResponse`. A read
        // carries no A8 audit envelope, so use the plain `send` — the mutation
        // helper would reject the (correctly) absent audit record.
        #[derive(serde::Deserialize)]
        struct GetEnvResponse {
            environment: Environment,
        }
        let resp: GetEnvResponse =
            self.send::<(), _>(reqwest::Method::GET, &self.env_path(env_id, ""), None, None)?;
        Ok(resp.environment)
    }

    fn trust_root_is_seeded(&self, env_id: &EnvId) -> Result<bool, StoreError> {
        // `GET /environments/{env_id}/trust-root` → `{ keys: [...] }`. A read
        // carries no A8 audit envelope, so use the plain `send` (the mutation
        // helper would reject the correctly-absent audit record).
        #[derive(serde::Deserialize)]
        struct TrustRootView {
            keys: Vec<serde_json::Value>,
        }
        let resp: TrustRootView = self.send::<(), _>(
            reqwest::Method::GET,
            &self.env_path(env_id, "/trust-root"),
            None,
            None,
        )?;
        Ok(!resp.keys.is_empty())
    }

    fn migrate_merge_bindings(
        &self,
        target_env_id: &EnvId,
        payload: MigrateMergePayload,
    ) -> Result<(Vec<String>, Vec<String>), StoreError> {
        let idem_key = mint_idempotency_key();
        let resp: greentic_deploy_spec::MergeReport = self.send_mutation(
            target_env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/migrate-bindings",
                encode_segment(target_env_id.as_str())
            ),
            Some(&idem_key),
            Some(&payload),
        )?;
        Ok((resp.merged_slots, resp.merged_extensions))
    }

    fn stage_revision(
        &self,
        env_id: &EnvId,
        payload: StageRevisionPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<Revision, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/revisions"),
            Some(&idem_key),
            Some(&payload),
        )
    }

    fn warm_revision(
        &self,
        env_id: &EnvId,
        payload: WarmRevisionPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let rid = payload.revision_id;
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/revisions/{}/warm",
                encode_segment(env_id.as_str()),
                encode_segment(&rid.to_string()),
            ),
            Some(&idem_key),
            Some(&payload),
        )
    }

    fn drain_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/revisions/{}/drain",
                encode_segment(env_id.as_str()),
                encode_segment(&revision_id.to_string()),
            ),
            Some(&idem_key),
        )
    }

    fn archive_revision(
        &self,
        env_id: &EnvId,
        revision_id: RevisionId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RevisionTransitionOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/revisions/{}/archive",
                encode_segment(env_id.as_str()),
                encode_segment(&revision_id.to_string()),
            ),
            Some(&idem_key),
        )
    }

    fn add_bundle(
        &self,
        env_id: &EnvId,
        payload: AddBundlePayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<BundleDeployment, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/bundles"),
            Some(&idem_key),
            Some(&payload),
        )
    }

    fn update_bundle(
        &self,
        env_id: &EnvId,
        payload: UpdateBundlePayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<BundleDeployment, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let did = payload.deployment_id.to_string();
        self.send_mutation(
            env_id,
            reqwest::Method::PATCH,
            &format!(
                "environments/{}/bundles/{}",
                encode_segment(env_id.as_str()),
                encode_segment(&did),
            ),
            Some(&idem_key),
            Some(&payload),
        )
    }

    fn remove_bundle(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RemoveBundleOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::DELETE,
            &format!(
                "environments/{}/bundles/{}",
                encode_segment(env_id.as_str()),
                encode_segment(&deployment_id.to_string()),
            ),
            Some(&idem_key),
        )
    }

    fn add_pack_binding(
        &self,
        env_id: &EnvId,
        binding: EnvPackBinding,
        idempotency_key: IdempotencyKey,
    ) -> Result<EnvPackBinding, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = PackBindingPayload { binding };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/packs"),
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
        let req = PackBindingPayload { binding };
        let resp: BindingGenerationOutcome<EnvPackBinding> = self.send_mutation(
            env_id,
            reqwest::Method::PATCH,
            &format!(
                "environments/{}/packs/{}",
                encode_segment(env_id.as_str()),
                encode_segment(&slot.to_string()),
            ),
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
        let resp: BindingGenerationOutcome<EnvPackBinding> = self.send_mutation_no_body(
            env_id,
            reqwest::Method::DELETE,
            &format!(
                "environments/{}/packs/{}",
                encode_segment(env_id.as_str()),
                encode_segment(&slot.to_string()),
            ),
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
        let resp: BindingGenerationOutcome<EnvPackBinding> = self.send_mutation_no_body(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/packs/{}/rollback",
                encode_segment(env_id.as_str()),
                encode_segment(&slot.to_string()),
            ),
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
        let req = ExtensionBindingPayload { binding };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/extensions",
                encode_segment(env_id.as_str())
            ),
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
        let req = ExtensionKeyedPayload {
            key,
            binding: Some(binding),
        };
        let resp: BindingGenerationOutcome<ExtensionBinding> = self.send_mutation(
            env_id,
            reqwest::Method::PATCH,
            &format!(
                "environments/{}/extensions",
                encode_segment(env_id.as_str())
            ),
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
        let req = ExtensionKeyedPayload { key, binding: None };
        let resp: BindingGenerationOutcome<ExtensionBinding> = self.send_mutation(
            env_id,
            reqwest::Method::DELETE,
            &format!(
                "environments/{}/extensions",
                encode_segment(env_id.as_str())
            ),
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
        let req = ExtensionKeyedPayload { key, binding: None };
        let resp: BindingGenerationOutcome<ExtensionBinding> = self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/extensions/rollback",
                encode_segment(env_id.as_str())
            ),
            Some(&idem_key),
            Some(&req),
        )?;
        Ok((resp.binding, resp.generation))
    }

    fn set_traffic_split(
        &self,
        env_id: &EnvId,
        payload: SetTrafficSplitPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<ApplyTrafficSplitOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/traffic"),
            Some(&idem_key),
            Some(&payload),
        )
    }

    fn rollback_traffic_split(
        &self,
        env_id: &EnvId,
        deployment_id: DeploymentId,
        idempotency_key: IdempotencyKey,
    ) -> Result<RollbackTrafficSplitOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = RollbackTrafficSplitPayload { deployment_id };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/traffic/rollback",
                encode_segment(env_id.as_str())
            ),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn add_messaging_endpoint(
        &self,
        env_id: &EnvId,
        payload: AddMessagingEndpointPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/messaging"),
            Some(&idem_key),
            Some(&payload),
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
        let req = MessagingBundleLinkPayload {
            bundle_id,
            updated_by,
        };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/messaging/{}/link",
                encode_segment(env_id.as_str()),
                encode_segment(&endpoint_id.to_string()),
            ),
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
        let req = MessagingBundleLinkPayload {
            bundle_id,
            updated_by,
        };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/messaging/{}/unlink",
                encode_segment(env_id.as_str()),
                encode_segment(&endpoint_id.to_string()),
            ),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn set_messaging_welcome_flow(
        &self,
        env_id: &EnvId,
        payload: SetMessagingWelcomeFlowPayload,
        idempotency_key: IdempotencyKey,
    ) -> Result<MessagingEndpoint, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let eid = payload.endpoint_id.to_string();
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/messaging/{}/welcome-flow",
                encode_segment(env_id.as_str()),
                encode_segment(&eid),
            ),
            Some(&idem_key),
            Some(&payload),
        )
    }

    fn remove_messaging_endpoint(
        &self,
        env_id: &EnvId,
        endpoint_id: MessagingEndpointId,
    ) -> Result<MessagingEndpointId, StoreError> {
        let idem_key = mint_idempotency_key();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::DELETE,
            &format!(
                "environments/{}/messaging/{}",
                encode_segment(env_id.as_str()),
                encode_segment(&endpoint_id.to_string()),
            ),
            Some(&idem_key),
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
        let req = RotateWebhookSecretPayload { updated_by };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &format!(
                "environments/{}/messaging/{}/rotate-secret",
                encode_segment(env_id.as_str()),
                encode_segment(&endpoint_id.to_string()),
            ),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn bootstrap_trust_root(&self, env_id: &EnvId) -> Result<TrustRootSeed, StoreError> {
        let idem_key = mint_idempotency_key();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/trust-root/bootstrap"),
            Some(&idem_key),
        )
    }

    fn seed_trust_root_if_absent(
        &self,
        env_id: &EnvId,
    ) -> Result<Option<TrustRootSeed>, StoreError> {
        let idem_key = mint_idempotency_key();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/trust-root/seed"),
            Some(&idem_key),
        )
    }

    fn add_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        public_key_pem: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootAddOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        let req = AddTrustedKeyPayload {
            key_id,
            public_key_pem,
        };
        self.send_mutation(
            env_id,
            reqwest::Method::POST,
            &self.env_path(env_id, "/trust-root/keys"),
            Some(&idem_key),
            Some(&req),
        )
    }

    fn remove_trusted_key(
        &self,
        env_id: &EnvId,
        key_id: String,
        idempotency_key: IdempotencyKey,
    ) -> Result<TrustRootRemoveOutcome, StoreError> {
        let idem_key = idempotency_key.as_str().to_string();
        self.send_mutation_no_body(
            env_id,
            reqwest::Method::DELETE,
            &format!(
                "environments/{}/trust-root/keys/{}",
                encode_segment(env_id.as_str()),
                encode_segment(&key_id),
            ),
            Some(&idem_key),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use greentic_deploy_spec::{PackId, RevisionLifecycle};
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;
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

                // Extract the Idempotency-Key header value from the request
                // and substitute `{{IDEMPOTENCY_KEY}}` in the response body
                // so happy-path tests echo the real sent key back in the
                // audit record (FIX 1 correlation).
                let body = if body.contains("{{IDEMPOTENCY_KEY}}") {
                    let idem_val = lines
                        .iter()
                        .find(|l| l.to_lowercase().starts_with("idempotency-key:"))
                        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                        .unwrap_or_default();
                    body.replace("{{IDEMPOTENCY_KEY}}", &idem_val)
                } else {
                    body
                };

                let status_text = match status {
                    200 => "OK",
                    201 => "Created",
                    204 => "No Content",
                    400 => "Bad Request",
                    401 => "Unauthorized",
                    403 => "Forbidden",
                    404 => "Not Found",
                    409 => "Conflict",
                    422 => "Unprocessable Entity",
                    500 => "Internal Server Error",
                    501 => "Not Implemented",
                    _ => "Unknown",
                };
                // Recompute Content-Length after substitution.
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
        HttpEnvironmentStore::new(Url::parse(&format!("http://{addr}")).unwrap(), auth).unwrap()
    }

    /// One-shot helper for the common no-auth single-response test shape:
    /// start a mock that returns `(status, body)` once and build a store
    /// pointed at it. Callers must hold the returned `MockServer` alive
    /// (binding it; dropping closes the listener mid-test).
    fn happy_store(status: u16, body: &str) -> (MockServer, HttpEnvironmentStore) {
        let mock = start_mock(vec![(status, body)], None);
        let store = mock_store(mock.addr, AuthMethod::None);
        (mock, store)
    }

    /// Wrap a domain-type JSON value in the A8 `MutationEnvelope` shape.
    fn wrap_mutation(domain: serde_json::Value) -> String {
        serde_json::json!({
            "result": domain,
            "etag": "sha256:test",
            "generation": 1,
            "idempotency": {"idempotency": "applied"},
            "audit": {
                "schema": "greentic.audit-event.v1",
                "event_id": "01TEST000000000000000000AA",
                "ts": "2026-06-09T12:00:00Z",
                "actor": {"kind": "operator"},
                "env_id": "local",
                "noun": "test",
                "verb": "test",
                "target": null,
                "authorization": {"decision": "allow", "policy": "local-only", "reason": "test"},
                "result": {"outcome": "ok"},
                "idempotency_key": "{{IDEMPOTENCY_KEY}}"
            }
        })
        .to_string()
    }

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn idem() -> IdempotencyKey {
        IdempotencyKey::new("01JABC000000000000000000ZZ").unwrap()
    }

    /// A minimal valid `Environment` domain body for envelope-shape tests.
    fn sample_env_domain() -> serde_json::Value {
        serde_json::json!({
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
        })
    }

    /// [`wrap_mutation`] variant with the envelope mutated by `tweak` after
    /// assembly — for the PR-4.0/F2 audit-invariant negative tests.
    fn wrap_mutation_tweaked(
        domain: serde_json::Value,
        tweak: impl FnOnce(&mut serde_json::Value),
    ) -> String {
        let mut envelope: serde_json::Value = serde_json::from_str(&wrap_mutation(domain)).unwrap();
        tweak(&mut envelope);
        envelope.to_string()
    }

    // -----------------------------------------------------------------------
    // PR-4.0 (F2): A8 §4 audit invariant on success envelopes
    // -----------------------------------------------------------------------

    /// Helper: unwrap a `CommittedAfterSave` wrapper and return the inner
    /// `Conflict` message string. Panics if the shape doesn't match.
    fn unwrap_committed_conflict(result: Result<Environment, StoreError>) -> String {
        match result {
            Err(StoreError::CommittedAfterSave(inner)) => match *inner {
                StoreError::Conflict(msg) => msg,
                other => panic!("expected inner Conflict, got {other:?}"),
            },
            other => panic!("expected CommittedAfterSave, got {other:?}"),
        }
    }

    /// Shared skeleton for the audit-invariant negative tests: serve a 200
    /// envelope mutated by `tweak`, run a mutation, and assert the
    /// `CommittedAfterSave`-wrapped violation message contains
    /// `expected_substr`.
    fn assert_audit_violation(tweak: impl FnOnce(&mut serde_json::Value), expected_substr: &str) {
        let body = wrap_mutation_tweaked(sample_env_domain(), tweak);
        let (_mock, store) = happy_store(200, &body);
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        let msg = unwrap_committed_conflict(result);
        assert!(
            msg.contains(expected_substr),
            "expected `{expected_substr}` violation, got: {msg}"
        );
    }

    #[test]
    fn success_without_audit_is_rejected() {
        assert_audit_violation(
            |env| {
                env.as_object_mut().unwrap().remove("audit");
            },
            "missing the audit record",
        );
    }

    #[test]
    fn success_with_deny_audit_is_rejected() {
        assert_audit_violation(
            |env| {
                env["audit"]["authorization"] = serde_json::json!({
                    "decision": "deny", "policy": "rbac-v1", "reason": "nope"
                });
            },
            "deny audit decision",
        );
    }

    #[test]
    fn success_with_non_ok_audit_result_is_rejected() {
        assert_audit_violation(
            |env| {
                env["audit"]["result"] = serde_json::json!({
                    "outcome": "error", "kind": "store", "message": "boom"
                });
            },
            "non-ok audit result",
        );
    }

    #[test]
    fn success_with_mismatched_audit_env_is_rejected() {
        assert_audit_violation(
            |env| {
                env["audit"]["env_id"] = serde_json::json!("other-env");
            },
            "names env `other-env`",
        );
    }

    // FIX 1: audit idempotency key correlation tests

    #[test]
    fn success_with_wrong_audit_idempotency_key_is_rejected() {
        assert_audit_violation(
            |env| {
                // Set audit key to a fixed wrong value (not the placeholder).
                env["audit"]["idempotency_key"] = serde_json::json!("01WRONG00000000000000000XX");
            },
            "does not belong",
        );
    }

    #[test]
    fn success_with_missing_audit_idempotency_key_is_rejected() {
        assert_audit_violation(
            |env| {
                env["audit"]
                    .as_object_mut()
                    .unwrap()
                    .remove("idempotency_key");
            },
            "does not belong",
        );
    }

    // FIX 2: post-2xx failures wrapped in CommittedAfterSave

    #[test]
    fn success_2xx_with_garbage_body_maps_to_committed_after_save() {
        // A 200 response with a non-JSON body: the mutation may already be
        // committed, so the error must be CommittedAfterSave.
        let (_mock, store) = happy_store(200, "this is not json");
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        let msg = unwrap_committed_conflict(result);
        assert!(
            msg.contains("already be committed"),
            "expected committed guidance, got: {msg}"
        );
    }

    // FIX 3: A8 status/kind agreement tests

    #[test]
    fn error_500_with_unauthorized_body_is_contract_violation() {
        // HTTP 500 but the A8 body claims `unauthorized` (expects 403) — don't
        // trust either side.
        let err_body = serde_json::json!({
            "kind": "unauthorized",
            "policy": "rbac-v1",
            "reason": "nope"
        });
        let (_mock, store) = happy_store(500, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Conflict(msg)) => {
                assert!(
                    msg.contains("contradicts"),
                    "expected contract violation, got: {msg}"
                );
            }
            other => panic!("expected Conflict(contradicts...), got {other:?}"),
        }
    }

    #[test]
    fn error_401_with_unauthorized_body_maps_to_unauthorized() {
        // HTTP 401 with an A8 `unauthorized`-kind body: the 401 allowance
        // means we trust the body.
        let err_body = serde_json::json!({
            "kind": "unauthorized",
            "policy": "rbac-v1",
            "reason": "expired token"
        });
        let (_mock, store) = happy_store(401, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Unauthorized { policy, reason }) => {
                assert_eq!(policy, "rbac-v1");
                assert_eq!(reason, "expired token");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Environment lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn create_environment_happy_path() {
        let domain = serde_json::json!({
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
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(201, &body);
        let result = store.create_environment(
            &env_id(),
            "test".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
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
        let (_mock, store) = happy_store(409, &err_body.to_string());
        let result = store.create_environment(
            &env_id(),
            "test".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
        );
        assert!(matches!(result, Err(StoreError::Conflict(_))));
    }

    #[test]
    fn update_environment_happy_path() {
        let domain = serde_json::json!({
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
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(200, &body);
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
        let (_mock, store) = happy_store(404, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    // -----------------------------------------------------------------------
    // Migration
    // -----------------------------------------------------------------------

    #[test]
    fn migrate_merge_bindings_happy_path() {
        let domain = serde_json::json!({
            "merged_slots": ["messaging"],
            "merged_extensions": ["capability/memory/long-term"]
        });
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(200, &body);
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
        wrap_mutation(serde_json::json!({
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
        }))
    }

    #[test]
    fn stage_revision_happy_path() {
        let body = sample_revision_response();
        let (_mock, store) = happy_store(201, &body);
        let result = store.stage_revision(
            &env_id(),
            StageRevisionPayload {
                revision_id: RevisionId::new(),
                deployment_id: DeploymentId::new(),
                bundle_digest: "sha256:00".to_string(),
                bundle_source_uri: None,
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                drain_seconds: 30,
            },
            idem(),
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
        let (_mock, store) = happy_store(422, &err_body.to_string());
        let result = store.stage_revision(
            &env_id(),
            StageRevisionPayload {
                revision_id: RevisionId::new(),
                deployment_id: DeploymentId::new(),
                bundle_digest: "sha256:00".to_string(),
                bundle_source_uri: None,
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                drain_seconds: 30,
            },
            idem(),
        );
        assert!(matches!(result, Err(StoreError::InvalidArgument(_))));
    }

    fn sample_transition_response(lifecycle: &str) -> String {
        wrap_mutation(serde_json::json!({
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
        }))
    }

    #[test]
    fn warm_revision_happy_path() {
        let body = sample_transition_response("ready");
        let (_mock, store) = happy_store(200, &body);
        let result = store.warm_revision(
            &env_id(),
            WarmRevisionPayload {
                revision_id: RevisionId::new(),
                health_gate: Ok(()),
                expected_lifecycle: RevisionLifecycle::Staged,
            },
            idem(),
        );
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.revision.lifecycle, RevisionLifecycle::Ready);
        assert_eq!(outcome.starting_lifecycle, RevisionLifecycle::Staged);
    }

    #[test]
    fn drain_revision_happy_path() {
        let body = sample_transition_response("draining");
        let (_mock, store) = happy_store(200, &body);
        let result = store.drain_revision(&env_id(), RevisionId::new(), idem());
        assert!(result.is_ok());
    }

    #[test]
    fn archive_revision_happy_path() {
        let body = sample_transition_response("archived");
        let (_mock, store) = happy_store(200, &body);
        let result = store.archive_revision(&env_id(), RevisionId::new(), idem());
        assert!(result.is_ok());
    }

    #[test]
    fn load_environment_happy_path() {
        // `GET /environments/{id}` → `GetEnvironmentResponse`: a plain read,
        // NOT a mutation envelope (no audit record on the wire).
        let body = serde_json::json!({
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
            "etag": "sha256:test",
            "generation": 3
        })
        .to_string();
        let (_mock, store) = happy_store(200, &body);
        let env = store.load_environment(&env_id()).expect("load ok");
        assert_eq!(env.environment_id.as_str(), "local");
        assert_eq!(env.name, "test");
    }

    #[test]
    fn load_environment_404_returns_not_found() {
        let err_body = serde_json::json!({"kind": "not-found", "detail": "no such env"});
        let (_mock, store) = happy_store(404, &err_body.to_string());
        let result = store.load_environment(&env_id());
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    // -----------------------------------------------------------------------
    // Bundle CRUD
    // -----------------------------------------------------------------------

    fn sample_bundle_deployment() -> String {
        wrap_mutation(serde_json::json!({
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
        }))
    }

    #[test]
    fn add_bundle_happy_path() {
        let body = sample_bundle_deployment();
        let (_mock, store) = happy_store(201, &body);
        let result = store.add_bundle(
            &env_id(),
            AddBundlePayload {
                bundle_id: BundleId::new("fast2flow"),
                customer_id: greentic_deploy_spec::CustomerId::new("local-dev"),
                revenue_share: Vec::new(),
                route_binding: None,
                authorization_ref: None,
                config_overrides: std::collections::BTreeMap::new(),
            },
            idem(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn update_bundle_happy_path() {
        let body = sample_bundle_deployment();
        let (_mock, store) = happy_store(200, &body);
        let result = store.update_bundle(
            &env_id(),
            UpdateBundlePayload {
                deployment_id: DeploymentId::new(),
                status: Some(greentic_deploy_spec::BundleDeploymentStatus::Active),
                route_binding: None,
                revenue_share: None,
                config_overrides: None,
            },
            idem(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn remove_bundle_happy_path() {
        let domain = serde_json::json!({
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
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(200, &body);
        let result = store.remove_bundle(&env_id(), DeploymentId::new(), idem());
        assert!(result.is_ok());
        assert!(result.unwrap().pruned_revision_ids.is_empty());
    }

    // -----------------------------------------------------------------------
    // Pack binding CRUD
    // -----------------------------------------------------------------------

    fn sample_pack_binding_json() -> String {
        serde_json::json!({
            "slot": "messaging",
            "kind": "greentic.messaging@0.5.0",
            "pack_ref": "greentic-messaging",
            "generation": 1
        })
        .to_string()
    }

    fn sample_pack_binding() -> String {
        wrap_mutation(serde_json::from_str(&sample_pack_binding_json()).unwrap())
    }

    fn sample_binding_generation_response(binding_json: &str, generation: u64) -> String {
        let domain: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"binding": {binding_json}, "generation": {generation}}}"#
        ))
        .unwrap();
        wrap_mutation(domain)
    }

    #[test]
    fn add_pack_binding_happy_path() {
        let body = sample_pack_binding();
        let (_mock, store) = happy_store(201, &body);
        let binding: EnvPackBinding = serde_json::from_str(&sample_pack_binding_json()).unwrap();
        let result = store.add_pack_binding(&env_id(), binding, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn update_pack_binding_happy_path() {
        let binding_json = sample_pack_binding_json();
        let body = sample_binding_generation_response(&binding_json, 2);
        let (_mock, store) = happy_store(200, &body);
        let binding: EnvPackBinding = serde_json::from_str(&binding_json).unwrap();
        let result =
            store.update_pack_binding(&env_id(), CapabilitySlot::Messaging, binding, idem());
        assert!(result.is_ok());
        let (_, generation) = result.unwrap();
        assert_eq!(generation, 2);
    }

    #[test]
    fn remove_pack_binding_happy_path() {
        let binding_json = sample_pack_binding_json();
        let body = sample_binding_generation_response(&binding_json, 3);
        let (_mock, store) = happy_store(200, &body);
        let result = store.remove_pack_binding(&env_id(), CapabilitySlot::Messaging, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn rollback_pack_binding_happy_path() {
        let binding_json = sample_pack_binding_json();
        let body = sample_binding_generation_response(&binding_json, 4);
        let (_mock, store) = happy_store(200, &body);
        let result = store.rollback_pack_binding(&env_id(), CapabilitySlot::Messaging, idem());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Extension binding CRUD
    // -----------------------------------------------------------------------

    fn sample_extension_binding_json() -> String {
        serde_json::json!({
            "kind": "greentic.memory-chronicle@0.1.0",
            "pack_ref": "greentic-chronicle",
            "generation": 1
        })
        .to_string()
    }

    fn sample_extension_binding() -> String {
        wrap_mutation(serde_json::from_str(&sample_extension_binding_json()).unwrap())
    }

    #[test]
    fn add_extension_binding_happy_path() {
        let body = sample_extension_binding();
        let (_mock, store) = happy_store(201, &body);
        let binding: ExtensionBinding =
            serde_json::from_str(&sample_extension_binding_json()).unwrap();
        let result = store.add_extension_binding(&env_id(), binding, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn update_extension_binding_happy_path() {
        let ext_json = sample_extension_binding_json();
        let body = sample_binding_generation_response(&ext_json, 2);
        let (_mock, store) = happy_store(200, &body);
        let binding: ExtensionBinding = serde_json::from_str(&ext_json).unwrap();
        let key = ExtensionKey::new("capability/memory/long-term", None);
        let result = store.update_extension_binding(&env_id(), key, binding, idem());
        assert!(result.is_ok());
        let (_, generation) = result.unwrap();
        assert_eq!(generation, 2);
    }

    #[test]
    fn remove_extension_binding_happy_path() {
        let ext_json = sample_extension_binding_json();
        let body = sample_binding_generation_response(&ext_json, 3);
        let (_mock, store) = happy_store(200, &body);
        let key = ExtensionKey::new("capability/memory/long-term", None);
        let result = store.remove_extension_binding(&env_id(), key, idem());
        assert!(result.is_ok());
    }

    #[test]
    fn rollback_extension_binding_happy_path() {
        let ext_json = sample_extension_binding_json();
        let body = sample_binding_generation_response(&ext_json, 4);
        let (_mock, store) = happy_store(200, &body);
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
        let domain = serde_json::json!({
            "split": sample_traffic_split(),
            "previous_generation": 1,
            "new_generation": 2,
            "environment": sample_env_domain()
        });
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(200, &body);
        let result = store.set_traffic_split(
            &env_id(),
            SetTrafficSplitPayload {
                deployment_id: DeploymentId::new(),
                entries: Vec::new(),
                updated_by: "tester".to_string(),
                authorization_ref: None,
            },
            idem(),
        );
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert_eq!(outcome.previous_generation, Some(1));
        assert_eq!(outcome.new_generation, Some(2));
        assert_eq!(outcome.environment.environment_id, env_id());
    }

    #[test]
    fn rollback_traffic_split_happy_path() {
        let domain = serde_json::json!({
            "restored": sample_traffic_split(),
            "previous_generation": 2,
            "new_generation": 3,
            "environment": sample_env_domain()
        });
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(200, &body);
        let result = store.rollback_traffic_split(&env_id(), DeploymentId::new(), idem());
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Messaging endpoints
    // -----------------------------------------------------------------------

    fn sample_messaging_endpoint() -> String {
        wrap_mutation(serde_json::json!({
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
        }))
    }

    #[test]
    fn add_messaging_endpoint_happy_path() {
        let body = sample_messaging_endpoint();
        let (_mock, store) = happy_store(201, &body);
        let result = store.add_messaging_endpoint(
            &env_id(),
            AddMessagingEndpointPayload {
                provider_id: "tg-bot".to_string(),
                provider_type: "telegram".to_string(),
                display_name: "Telegram Bot".to_string(),
                secret_refs: Vec::new(),
                webhook_secret_ref: Some(
                    "secret://local/default/_/messaging-byo/webhook_secret".to_string(),
                ),
                updated_by: "tester".to_string(),
            },
            idem(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn link_messaging_bundle_happy_path() {
        let body = sample_messaging_endpoint();
        let (_mock, store) = happy_store(200, &body);
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
        let (_mock, store) = happy_store(200, &body);
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
        let (_mock, store) = happy_store(200, &body);
        let result = store.set_messaging_welcome_flow(
            &env_id(),
            SetMessagingWelcomeFlowPayload {
                endpoint_id: MessagingEndpointId::new(),
                bundle_id: BundleId::new("fast2flow"),
                pack_id: PackId::new("greentic-messaging"),
                flow_id: "welcome".to_string(),
                updated_by: "tester".to_string(),
            },
            idem(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn remove_messaging_endpoint_happy_path() {
        let eid = MessagingEndpointId::new();
        let body = wrap_mutation(serde_json::json!(eid.to_string()));
        let (_mock, store) = happy_store(200, &body);
        let result = store.remove_messaging_endpoint(&env_id(), eid);
        assert!(result.is_ok());
    }

    #[test]
    fn rotate_messaging_webhook_secret_happy_path() {
        let body = sample_messaging_endpoint();
        let (_mock, store) = happy_store(200, &body);
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
        wrap_mutation(serde_json::json!({
            "key_id": "op-key-1",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
            "trusted_key_count": 1
        }))
    }

    #[test]
    fn bootstrap_trust_root_happy_path() {
        let body = sample_trust_root_seed();
        let (_mock, store) = happy_store(201, &body);
        let result = store.bootstrap_trust_root(&env_id());
        assert!(result.is_ok());
        let seed = result.unwrap();
        assert_eq!(seed.key_id, "op-key-1");
        assert_eq!(seed.trusted_key_count, 1);
    }

    #[test]
    fn seed_trust_root_if_absent_when_seeded() {
        let body = sample_trust_root_seed();
        let (_mock, store) = happy_store(200, &body);
        let result = store.seed_trust_root_if_absent(&env_id());
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn seed_trust_root_if_absent_when_already_exists() {
        let body = wrap_mutation(serde_json::Value::Null);
        let (_mock, store) = happy_store(200, &body);
        let result = store.seed_trust_root_if_absent(&env_id());
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn add_trusted_key_happy_path() {
        let domain = serde_json::json!({
            "added_key_id": "external-key-1",
            "trusted_key_count": 2
        });
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(201, &body);
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
        let domain = serde_json::json!({
            "removed_key_id": "external-key-1",
            "removed_public_key_pem": "PEM-DATA",
            "trusted_key_count": 1
        });
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(200, &body);
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
                bundle_source_uri: None,
                pack_list: Vec::new(),
                pack_list_lock_ref: PathBuf::new(),
                pack_config_refs: Vec::new(),
                config_digest: "sha256:00".to_string(),
                signature_sidecar_ref: PathBuf::from("rev.sig"),
                drain_seconds: 30,
            },
            idem(),
        );
    }

    // -----------------------------------------------------------------------
    // Error mapping tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_404_maps_to_not_found() {
        let err_body = serde_json::json!({"kind": "not-found"});
        let (_mock, store) = happy_store(404, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        assert!(matches!(result, Err(StoreError::NotFound(_))));
    }

    #[test]
    fn error_409_maps_to_conflict() {
        let err_body = serde_json::json!({
            "kind": "idempotency-conflict",
            "reason": "key reused"
        });
        let (_mock, store) = happy_store(409, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        assert!(matches!(result, Err(StoreError::Conflict(_))));
    }

    #[test]
    fn error_500_maps_to_conflict_server() {
        let err_body = serde_json::json!({
            "kind": "internal",
            "message": "disk full"
        });
        let (_mock, store) = happy_store(500, &err_body.to_string());
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
    fn error_403_maps_to_unauthorized() {
        // PR-4.0 (F4): an A8 `unauthorized` body keeps its typed noun —
        // previously it was flattened into `StoreError::Conflict`, so RBAC
        // denials rendered as `error.kind: conflict` in the CLI envelope.
        let err_body = serde_json::json!({
            "kind": "unauthorized",
            "policy": "rbac-v1",
            "reason": "insufficient permissions"
        });
        let (_mock, store) = happy_store(403, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Unauthorized { policy, reason }) => {
                assert_eq!(policy, "rbac-v1");
                assert_eq!(reason, "insufficient permissions");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn error_403_without_a8_body_maps_to_unauthorized() {
        // A denial from a proxy/LB in front of the store (non-A8 body) is
        // still a denial — the fallback status mapping keeps the noun.
        let (_mock, store) = happy_store(403, "access denied by gateway");
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::Unauthorized { policy, reason }) => {
                assert_eq!(policy, "remote");
                assert_eq!(reason, "access denied by gateway");
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn error_501_maps_to_not_yet_implemented() {
        let err_body = serde_json::json!({
            "kind": "not-yet-implemented",
            "detail": "backup/restore lands in PR-4"
        });
        let (_mock, store) = happy_store(501, &err_body.to_string());
        let result = store.update_environment(&env_id(), UpdateEnvironmentPayload::default());
        match result {
            Err(StoreError::NotYetImplemented(detail)) => {
                assert_eq!(detail, "backup/restore lands in PR-4");
            }
            other => panic!("expected NotYetImplemented, got {other:?}"),
        }
    }

    #[test]
    fn transport_error_maps_to_conflict() {
        // Connect to a port that is definitely not listening.
        let store =
            HttpEnvironmentStore::new(Url::parse("http://127.0.0.1:1").unwrap(), AuthMethod::None)
                .unwrap();
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
    // Fix 1: percent-encoding of dynamic path segments
    // -----------------------------------------------------------------------

    #[test]
    fn encode_segment_passes_through_alphanumeric() {
        assert_eq!(encode_segment("local"), "local");
        assert_eq!(
            encode_segment("01JTKW5B4W4Q5Y1CQW93F7S5VH"),
            "01JTKW5B4W4Q5Y1CQW93F7S5VH"
        );
    }

    #[test]
    fn encode_segment_escapes_slash() {
        let encoded = encode_segment("foo/bar");
        assert!(
            !encoded.contains('/'),
            "slash must be escaped, got: {encoded}"
        );
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn encode_segment_escapes_dot_dot() {
        let encoded = encode_segment("..");
        assert!(
            !encoded.contains(".."),
            "dots must be escaped, got: {encoded}"
        );
        assert!(encoded.contains("%2E"));
    }

    #[test]
    fn encode_segment_escapes_query() {
        let encoded = encode_segment("id?foo=bar");
        assert!(
            !encoded.contains('?'),
            "query marker must be escaped, got: {encoded}"
        );
    }

    #[test]
    fn encode_segment_escapes_fragment() {
        let encoded = encode_segment("id#frag");
        assert!(
            !encoded.contains('#'),
            "fragment marker must be escaped, got: {encoded}"
        );
    }

    #[test]
    fn key_id_with_slash_reaches_escaped_path() {
        let body = wrap_mutation(serde_json::json!({
            "removed_key_id": "a/b",
            "removed_public_key_pem": "PEM",
            "trusted_key_count": 0
        }));
        let check = Arc::new(|req_line: &str, _headers: &str, _body: &[u8]| {
            assert!(
                req_line.contains("a%2Fb"),
                "expected escaped slash in path, got: {req_line}"
            );
        });
        let mock = start_mock(vec![(200, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::None);
        let _ = store.remove_trusted_key(&env_id(), "a/b".to_string(), idem());
    }

    // -----------------------------------------------------------------------
    // Fix 2: MutationEnvelope parsing
    // -----------------------------------------------------------------------

    #[test]
    fn mutation_envelope_with_extra_metadata_is_accepted() {
        // The envelope carries etag/generation/audit alongside the result.
        // Verify that the client parses the envelope correctly.
        let domain = serde_json::json!({
            "schema": "greentic.environment.v1",
            "environment_id": "local",
            "name": "test-envelope",
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
        let body = wrap_mutation(domain);
        let (_mock, store) = happy_store(201, &body);
        let result = store.create_environment(
            &env_id(),
            "test-envelope".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().name, "test-envelope");
    }

    // -----------------------------------------------------------------------
    // Fix 4: idempotency-key minting for methods without payload key
    // -----------------------------------------------------------------------

    #[test]
    fn bootstrap_trust_root_sends_idempotency_key() {
        let body = sample_trust_root_seed();
        let check = Arc::new(|_req_line: &str, headers: &str, _body: &[u8]| {
            assert!(
                headers.contains("Idempotency-Key:"),
                "expected Idempotency-Key header in: {headers}"
            );
            // Extract the key value and verify it's non-empty.
            let key = headers
                .lines()
                .find(|l| l.starts_with("Idempotency-Key:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim())
                .unwrap_or("");
            assert!(!key.is_empty(), "Idempotency-Key must be non-empty");
        });
        let mock = start_mock(vec![(201, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::None);
        let _ = store.bootstrap_trust_root(&env_id());
    }

    #[test]
    fn create_environment_sends_idempotency_key() {
        let domain = serde_json::json!({
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
        let body = wrap_mutation(domain);
        let check = Arc::new(|_req_line: &str, headers: &str, _body: &[u8]| {
            assert!(
                headers.contains("Idempotency-Key:"),
                "expected Idempotency-Key header for create_environment: {headers}"
            );
        });
        let mock = start_mock(vec![(201, &body)], Some(check));
        let store = mock_store(mock.addr, AuthMethod::None);
        let _ = store.create_environment(
            &env_id(),
            "test".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
        );
    }

    #[test]
    fn minted_keys_are_unique_per_call() {
        let key1 = mint_idempotency_key();
        let key2 = mint_idempotency_key();
        assert_ne!(key1, key2, "minted keys must differ per call");
    }

    // -----------------------------------------------------------------------
    // Fix 5: insecure-transport guard
    // -----------------------------------------------------------------------

    #[test]
    fn bearer_over_http_non_loopback_is_rejected() {
        let result = HttpEnvironmentStore::new(
            Url::parse("http://192.0.2.1:8080").unwrap(),
            AuthMethod::Bearer("token".to_string()),
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ConstructionError::InsecureTransport(_)),
            "expected InsecureTransport, got: {err:?}"
        );
    }

    #[test]
    fn bearer_over_http_loopback_is_allowed() {
        let result = HttpEnvironmentStore::new(
            Url::parse("http://127.0.0.1:8080").unwrap(),
            AuthMethod::Bearer("token".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn bearer_over_https_is_allowed() {
        let result = HttpEnvironmentStore::new(
            Url::parse("https://example.com").unwrap(),
            AuthMethod::Bearer("token".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn no_auth_over_http_is_allowed() {
        let result = HttpEnvironmentStore::new(
            Url::parse("http://192.0.2.1:8080").unwrap(),
            AuthMethod::None,
        );
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Object-safety compile guard (same as mutations.rs)
    // -----------------------------------------------------------------------

    #[allow(dead_code)]
    fn _http_store_is_trait_object(store: &HttpEnvironmentStore) {
        let _dyn: &dyn EnvironmentMutations = store;
    }
}
