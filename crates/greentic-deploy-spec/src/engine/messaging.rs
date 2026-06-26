//! Pure messaging-endpoint verb semantics (Phase D PR-4.2h).
//!
//! The messaging verb group (`op messaging endpoint add | link-bundle |
//! unlink-bundle | set-welcome-flow | remove | rotate-webhook-secret`)
//! follows the PR-4.2a engine contract: pure `&mut Environment` transforms
//! with no I/O and no clock. Both `LocalFsStore` (greentic-deployer, behind
//! a flock) and the operator-store-server (behind SQLite CAS) drive the
//! SAME functions, so replay detection, duplicate rules, and welcome-flow
//! validation cannot drift between local and remote.
//!
//! # The webhook-secret seam
//!
//! Telegram-class endpoints need a per-endpoint webhook secret. Generating
//! the VALUE and deciding where it lives are backend concerns, so `add` and
//! `rotate-webhook-secret` take a `provision` closure: it receives the
//! endpoint's existing ref (`Some` when rotating an endpoint that already
//! carries one, `None` otherwise) and returns the [`SecretRef`] to stamp on
//! `MessagingEndpoint.webhook_secret_ref`. `LocalFsStore` mints the value
//! and persists it into the env-pack dev-store
//! (`cli::messaging::provision_webhook_secret`).
//!
//! Callers may instead SUPPLY the ref directly on `add` via
//! [`AddMessagingEndpointPayload::webhook_secret_ref`]: when present for a
//! telegram-class endpoint the transform validates and stamps it WITHOUT
//! calling `provision`. Remote operator stores use this — the operator owns
//! value provisioning in its own secrets plane and ships only the ref, so
//! the control-plane store never custodies secret material. Its `provision`
//! closure always refuses ([`MessagingError::SecretProvision`], mapped to
//! 501): the server neither mints nor rotates secrets, so a telegram-class
//! `add` over a remote store must supply the ref and `rotate-webhook-secret`
//! is unsupported there (the server cannot prove a value rotated). The
//! closure / supplied-ref step runs AFTER replay/duplicate/ref validation,
//! so it never fires on a replay and never leaves a half-validated
//! mutation.
//!
//! # Idempotency key is domain state here
//!
//! Unlike the bindings/bundles groups (key = transport metadata), this
//! group embeds the key in `MessagingEndpoint.updated_by`
//! (`"<by>#idem=<op>:<key>"`) and uses it for **operation-scoped**
//! same-key replay detection on `add` and `rotate-webhook-secret` — so
//! the transforms take the
//! [`IdempotencyKey`](crate::IdempotencyKey) (the traffic-group
//! precedent). The server hands the A8 `Idempotency-Key` header to the
//! engine; the durable replay ledger remains PR-4.3.
//!
//! The operation name (`add`, `link-bundle`, `unlink-bundle`,
//! `set-welcome-flow`, `rotate-webhook-secret`) is part of the stamp so
//! a key used by one verb cannot satisfy a replay check for a different
//! verb. Without the op in the stamp a `rotate-webhook-secret` replaying
//! a key that was originally stamped by `add` would report success
//! without actually rotating — a false SUCCESS that never provisions
//! anything. Endpoints stamped under the old format (`"<by>#idem=<key>"`,
//! without `<op>:`) simply never match the new replay checks; a
//! cross-version retry re-executes instead of replaying, which is
//! acceptable — crash-retry replay is best-effort until the PR-4.3
//! request-fingerprint replay ledger.
//!
//! # Persist rule (read before calling)
//!
//! - `Ok(applied)` with `applied.mutated == true` — the env was mutated;
//!   the backend persists.
//! - `Ok(applied)` with `applied.mutated == false` — idempotent replay or
//!   no-op; the env is UNTOUCHED, do not persist (the server echoes the
//!   loaded CAS coordinates). `LocalFsStore` still refreshes its derived
//!   `<env_dir>/messaging/` projection on this path — that repair step is
//!   LocalFS-only, like the runtime-config projection.
//! - `Err(_)` — the env was not mutated; nothing to persist.
//!
//! # Wire shapes
//!
//! [`AddMessagingEndpointPayload`] / [`MessagingBundleLinkPayload`] /
//! [`SetMessagingWelcomeFlowPayload`] / [`RotateWebhookSecretPayload`]
//! double as the A8 request bodies on the `/environments/{env}/messaging`
//! routes the PR-3b client pinned. The wire-format tests at the bottom pin
//! the encoding.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::environment::Environment;
use crate::ids::{BundleId, MessagingEndpointId, PackId};
use crate::messaging_endpoint::{MessagingEndpoint, WelcomeFlowRef};
use crate::refs::SecretRef;
use crate::remote::IdempotencyKey;
use crate::version::SchemaVersion;
use greentic_types::EnvId;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a messaging verb refused to mutate the environment. Display strings
/// are verbatim what `LocalFsStore` raised before the move (PR-4.2h), so
/// operator-facing CLI errors are unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MessagingError {
    /// Same-key replay whose payload identity does NOT match the endpoint
    /// the key originally stamped — a key-reuse protocol violation.
    #[error(
        "idempotency key `{key}` already used to add `{provider_type}`/`{provider_id}` \
         in env `{env_id}`; pass a fresh key"
    )]
    IdempotencyKeyReuse {
        key: String,
        provider_type: String,
        provider_id: String,
        env_id: EnvId,
    },
    /// `(provider_type, provider_id)` is unique per environment.
    #[error(
        "messaging endpoint with provider_type=`{provider_type}` provider_id=`{provider_id}` \
         already exists in env `{env_id}`"
    )]
    EndpointAlreadyExists {
        provider_type: String,
        provider_id: String,
        env_id: EnvId,
    },
    #[error("messaging endpoint `{endpoint_id}` not found in env `{env_id}`")]
    EndpointNotFound {
        endpoint_id: MessagingEndpointId,
        env_id: EnvId,
    },
    #[error("bundle `{bundle_id}` is not deployed in env `{env_id}`")]
    BundleNotDeployed { bundle_id: BundleId, env_id: EnvId },
    #[error(
        "cannot unlink bundle `{bundle_id}` from endpoint `{endpoint_id}` while it owns the \
         welcome_flow; clear the welcome_flow first via `set-welcome-flow` to a different \
         linked bundle, or `remove` the endpoint"
    )]
    WelcomeFlowOwned {
        bundle_id: BundleId,
        endpoint_id: MessagingEndpointId,
    },
    #[error(
        "welcome_flow bundle `{bundle_id}` is not linked to endpoint `{endpoint_id}`; \
         link it first via `link-bundle`"
    )]
    BundleNotLinked {
        bundle_id: BundleId,
        endpoint_id: MessagingEndpointId,
    },
    #[error(
        "welcome_flow.pack_id `{pack_id}` does not appear in any current revision of \
         bundle `{bundle_id}` (known: [{}])", known.join(", ")
    )]
    WelcomePackUnknown {
        pack_id: String,
        bundle_id: BundleId,
        known: Vec<String>,
    },
    #[error("secret_ref `{raw}`: {message}")]
    InvalidSecretRef { raw: String, message: String },
    /// The backend's webhook-secret `provision` closure failed (or, on the
    /// operator-store-server, refused — no secrets sink yet). The message
    /// is the backend's verbatim detail; each backend owns its mapping
    /// (LocalFS → `Conflict`, server → 501 `not-yet-implemented`).
    #[error("{0}")]
    SecretProvision(String),
}

// ---------------------------------------------------------------------------
// Wire payloads / outcomes
// ---------------------------------------------------------------------------

/// Inputs to `EnvironmentMutations::add_messaging_endpoint`, and the A8
/// `POST /environments/{env}/messaging` request body.
///
/// No `endpoint_id` — the storage-owning side mints it (the bundles-group
/// `DeploymentId` precedent). No `idempotency_key` — the key rides the
/// trait method and the A8 `Idempotency-Key` header; the engine receives
/// it as a transform parameter because this group uses it for replay
/// detection (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddMessagingEndpointPayload {
    pub provider_id: String,
    pub provider_type: String,
    pub display_name: String,
    /// Raw `secret://` URIs — validated into [`SecretRef`]s by the
    /// transform so local and remote reject malformed refs identically.
    #[serde(default)]
    pub secret_refs: Vec<String>,
    /// Optional caller-supplied per-endpoint webhook secret ref (raw
    /// `secret://` URI). When present for a telegram-class endpoint the
    /// transform validates and stamps it WITHOUT calling `provision` — the
    /// caller owns value provisioning (remote operator stores use this so
    /// the control-plane store never mints or custodies secret material).
    /// `None` keeps the backend-provision path (LocalFS auto-mints). Supplying
    /// it for a non-telegram-class endpoint is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret_ref: Option<String>,
    pub updated_by: String,
}

/// The A8 request body shared by the `link-bundle` and `unlink-bundle`
/// verbs (`POST /environments/{env}/messaging/{eid}/link` / `/unlink` —
/// the two routes diverge by URL suffix only, as the PR-3b client pinned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessagingBundleLinkPayload {
    pub bundle_id: BundleId,
    pub updated_by: String,
}

/// Inputs to `EnvironmentMutations::set_messaging_welcome_flow`, and the
/// A8 `POST /environments/{env}/messaging/{eid}/welcome-flow` request body
/// (`endpoint_id` rides in the body too — the server cross-checks it
/// against the URL segment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetMessagingWelcomeFlowPayload {
    pub endpoint_id: MessagingEndpointId,
    pub bundle_id: BundleId,
    pub pack_id: PackId,
    pub flow_id: String,
    pub updated_by: String,
}

/// The A8 `POST /environments/{env}/messaging/{eid}/rotate-secret` request
/// body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateWebhookSecretPayload {
    pub updated_by: String,
}

/// What a messaging transform did, by index into
/// `Environment.messaging_endpoints`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagingApplied {
    /// Index of the affected endpoint in `Environment.messaging_endpoints`.
    pub index: usize,
    /// `false` = idempotent replay / no-op: the env is untouched, do not
    /// persist (see the module-doc persist rule).
    pub mutated: bool,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Canonical operation names for the idem stamp. Each matches the audit-verb
/// vocabulary (`body["audit"]["verb"]` in the operator-store-server).
const OP_ADD: &str = "add";
const OP_LINK_BUNDLE: &str = "link-bundle";
const OP_UNLINK_BUNDLE: &str = "unlink-bundle";
const OP_SET_WELCOME_FLOW: &str = "set-welcome-flow";
const OP_ROTATE_WEBHOOK_SECRET: &str = "rotate-webhook-secret";

/// Telegram-class providers need a per-endpoint webhook secret generated at
/// creation time. Covers `"telegram"`, `"telegram.<x>"`,
/// `"messaging.telegram"`, and `"messaging.telegram.<x>"` — strict on the
/// dot so `"telegrambot"` and `"messaging.telegrambot"` do NOT match.
///
/// Public so the remote dispatch layer can reuse the canonical matcher to
/// pre-validate that a telegram-class endpoint carries a caller-supplied
/// `webhook_secret_ref` before a remote round-trip (rather than duplicating
/// the rule and risking drift).
pub fn is_telegram_class(provider_type: &str) -> bool {
    let rest = provider_type
        .strip_prefix("messaging.")
        .unwrap_or(provider_type);
    rest == "telegram" || rest.starts_with("telegram.")
}

/// Embed the idempotency key AND operation name in `updated_by` so a
/// same-key retry surfaces as the original mutation only when the
/// operation matches. `MessagingEndpoint` has no separate
/// `idempotency_key` field; the encoding keeps the replay contract without
/// bloating the spec type.
fn format_idem_writer(updated_by: &str, op: &str, idempotency_key: &str) -> String {
    format!("{updated_by}#idem={op}:{idempotency_key}")
}

/// Build the `#idem=<op>:<key>` suffix once so a linear scan over
/// `messaging_endpoints` does not allocate a fresh `String` per element.
///
/// The `#idem=` anchor combined with full-suffix `ends_with` matching
/// means a crafted key containing `:` cannot cross-match operations —
/// the op portion is fixed between `#idem=` and the first `:`, and the
/// key portion is everything after that first `:`.
fn idem_suffix(op: &str, idempotency_key: &str) -> String {
    format!("#idem={op}:{idempotency_key}")
}

fn carries_idem_key(endpoint: &MessagingEndpoint, idem_suffix: &str) -> bool {
    endpoint.updated_by.ends_with(idem_suffix)
}

/// Bump generation and re-stamp the mutation metadata on an endpoint.
fn stamp_mutation(
    endpoint: &mut MessagingEndpoint,
    updated_by: &str,
    op: &str,
    idempotency_key: &str,
    now: DateTime<Utc>,
) {
    endpoint.generation = endpoint.generation.saturating_add(1);
    endpoint.updated_at = now;
    endpoint.updated_by = format_idem_writer(updated_by, op, idempotency_key);
}

/// Locate a messaging endpoint by id, returning
/// [`MessagingError::EndpointNotFound`] when absent.
fn find_endpoint_idx(
    env: &Environment,
    endpoint_id: MessagingEndpointId,
) -> Result<usize, MessagingError> {
    env.messaging_endpoints
        .iter()
        .position(|e| e.endpoint_id == endpoint_id)
        .ok_or_else(|| MessagingError::EndpointNotFound {
            endpoint_id,
            env_id: env.environment_id.clone(),
        })
}

/// Welcome-flow `pack_id` validation: the pack must appear in some current
/// revision's pack_list of the bundle — unless the bundle has no
/// deployments or no revision lists any pack yet (pre-staging authoring is
/// allowed; the runner re-validates at dispatch).
fn validate_welcome_pack_id(
    env: &Environment,
    bundle_id: &BundleId,
    pack_id: &str,
) -> Result<(), MessagingError> {
    let bundles: Vec<_> = env
        .bundles
        .iter()
        .filter(|b| b.bundle_id == *bundle_id)
        .collect();
    if bundles.is_empty() {
        return Ok(());
    }
    let mut saw_any_pack = false;
    let mut known_packs: Vec<String> = Vec::new();
    for bundle in bundles {
        for rev_id in &bundle.current_revisions {
            let Some(rev) = env.revisions.iter().find(|r| r.revision_id == *rev_id) else {
                continue;
            };
            for entry in &rev.pack_list {
                saw_any_pack = true;
                if entry.pack_id.as_str() == pack_id {
                    return Ok(());
                }
                known_packs.push(entry.pack_id.as_str().to_string());
            }
        }
    }
    if !saw_any_pack {
        return Ok(());
    }
    known_packs.sort();
    known_packs.dedup();
    Err(MessagingError::WelcomePackUnknown {
        pack_id: pack_id.to_string(),
        bundle_id: bundle_id.clone(),
        known: known_packs,
    })
}

// ---------------------------------------------------------------------------
// Transforms
// ---------------------------------------------------------------------------

/// Add a messaging endpoint. Rejects with
/// [`MessagingError::EndpointAlreadyExists`] when the
/// `(provider_type, provider_id)` pair is already present, and with
/// [`MessagingError::IdempotencyKeyReuse`] when the key was already used
/// for a different endpoint identity. Idempotent on same-key
/// same-identity replay (`mutated == false`).
///
/// Validation order is pinned (and tested): replay check → duplicate check
/// → `secret_refs` parse → `provision` (telegram-class only) → push. A
/// malformed ref therefore never leaves an orphan secret in the backend's
/// sink, and a replay never re-provisions.
pub fn add_messaging_endpoint(
    env: &mut Environment,
    payload: AddMessagingEndpointPayload,
    endpoint_id: MessagingEndpointId,
    idempotency_key: &IdempotencyKey,
    now: DateTime<Utc>,
    provision: impl FnOnce(Option<&SecretRef>) -> Result<SecretRef, MessagingError>,
) -> Result<MessagingApplied, MessagingError> {
    let suffix = idem_suffix(OP_ADD, idempotency_key.as_str());
    // Idempotent replay: re-running with the same key AND same op
    // returns the previously-created endpoint iff the payload's instance
    // identity matches what was stored. A key stamped by a different op
    // (link-bundle, rotate, etc.) does NOT satisfy this check — the add
    // proceeds as a fresh mutation and the duplicate-identity check
    // below still guards collisions.
    if let Some(idx) = env
        .messaging_endpoints
        .iter()
        .position(|e| carries_idem_key(e, &suffix))
    {
        let prev = &env.messaging_endpoints[idx];
        if prev.provider_type == payload.provider_type && prev.provider_id == payload.provider_id {
            return Ok(MessagingApplied {
                index: idx,
                mutated: false,
            });
        }
        return Err(MessagingError::IdempotencyKeyReuse {
            key: idempotency_key.as_str().to_string(),
            provider_type: prev.provider_type.clone(),
            provider_id: prev.provider_id.clone(),
            env_id: env.environment_id.clone(),
        });
    }
    if env
        .messaging_endpoints
        .iter()
        .any(|e| e.provider_type == payload.provider_type && e.provider_id == payload.provider_id)
    {
        return Err(MessagingError::EndpointAlreadyExists {
            provider_type: payload.provider_type,
            provider_id: payload.provider_id,
            env_id: env.environment_id.clone(),
        });
    }
    // Validate secret_refs BEFORE provisioning the webhook secret so a
    // malformed ref does not leave an orphan secret in the backend's sink.
    let secret_refs: Vec<SecretRef> = payload
        .secret_refs
        .iter()
        .map(|r| {
            SecretRef::try_new(r).map_err(|e| MessagingError::InvalidSecretRef {
                raw: r.clone(),
                message: e.to_string(),
            })
        })
        .collect::<Result<_, _>>()?;
    let webhook_secret_ref = match (
        is_telegram_class(&payload.provider_type),
        payload.webhook_secret_ref.as_deref(),
    ) {
        // Telegram-class with a caller-supplied ref: validate and stamp it,
        // never calling the backend sink. The caller owns value provisioning
        // (remote operator stores ship the ref so the control-plane store
        // never mints or custodies secret material).
        (true, Some(raw)) => {
            Some(
                SecretRef::try_new(raw).map_err(|e| MessagingError::InvalidSecretRef {
                    raw: raw.to_string(),
                    message: e.to_string(),
                })?,
            )
        }
        // Telegram-class with no supplied ref: the backend provisions
        // (LocalFS auto-mints + stores; a control-plane store refuses).
        (true, None) => Some(provision(None)?),
        // A webhook secret ref is meaningless for a non-telegram-class
        // endpoint; supplying one is a caller error.
        (false, Some(raw)) => {
            return Err(MessagingError::InvalidSecretRef {
                raw: raw.to_string(),
                message: "webhook_secret_ref is only valid for telegram-class providers"
                    .to_string(),
            });
        }
        (false, None) => None,
    };
    env.messaging_endpoints.push(MessagingEndpoint {
        schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
        env_id: env.environment_id.clone(),
        endpoint_id,
        provider_id: payload.provider_id,
        provider_type: payload.provider_type,
        display_name: payload.display_name,
        secret_refs,
        webhook_secret_ref,
        linked_bundles: Vec::new(),
        welcome_flow: None,
        generation: 0,
        created_at: now,
        updated_at: now,
        updated_by: format_idem_writer(&payload.updated_by, OP_ADD, idempotency_key.as_str()),
    });
    Ok(MessagingApplied {
        index: env.messaging_endpoints.len() - 1,
        mutated: true,
    })
}

/// Link a bundle to an existing messaging endpoint. Idempotent when the
/// bundle is already linked (`mutated == false`). Rejects when the
/// endpoint or bundle is missing.
pub fn link_messaging_bundle(
    env: &mut Environment,
    endpoint_id: MessagingEndpointId,
    bundle_id: BundleId,
    updated_by: &str,
    idempotency_key: &IdempotencyKey,
    now: DateTime<Utc>,
) -> Result<MessagingApplied, MessagingError> {
    let idx = find_endpoint_idx(env, endpoint_id)?;
    if !env.bundles.iter().any(|b| b.bundle_id == bundle_id) {
        return Err(MessagingError::BundleNotDeployed {
            bundle_id,
            env_id: env.environment_id.clone(),
        });
    }
    if env.messaging_endpoints[idx]
        .linked_bundles
        .contains(&bundle_id)
    {
        return Ok(MessagingApplied {
            index: idx,
            mutated: false,
        });
    }
    env.messaging_endpoints[idx].linked_bundles.push(bundle_id);
    stamp_mutation(
        &mut env.messaging_endpoints[idx],
        updated_by,
        OP_LINK_BUNDLE,
        idempotency_key.as_str(),
        now,
    );
    Ok(MessagingApplied {
        index: idx,
        mutated: true,
    })
}

/// Unlink a bundle from an existing messaging endpoint. Idempotent when
/// the bundle is not linked (`mutated == false`). Rejects with
/// [`MessagingError::WelcomeFlowOwned`] if the bundle owns the endpoint's
/// `welcome_flow`.
pub fn unlink_messaging_bundle(
    env: &mut Environment,
    endpoint_id: MessagingEndpointId,
    bundle_id: BundleId,
    updated_by: &str,
    idempotency_key: &IdempotencyKey,
    now: DateTime<Utc>,
) -> Result<MessagingApplied, MessagingError> {
    let idx = find_endpoint_idx(env, endpoint_id)?;
    let Some(bidx) = env.messaging_endpoints[idx]
        .linked_bundles
        .iter()
        .position(|b| b == &bundle_id)
    else {
        // Idempotent: unlinking a bundle that isn't linked is a no-op.
        return Ok(MessagingApplied {
            index: idx,
            mutated: false,
        });
    };
    if let Some(welcome) = &env.messaging_endpoints[idx].welcome_flow
        && welcome.bundle_id == bundle_id
    {
        return Err(MessagingError::WelcomeFlowOwned {
            bundle_id,
            endpoint_id,
        });
    }
    env.messaging_endpoints[idx].linked_bundles.remove(bidx);
    stamp_mutation(
        &mut env.messaging_endpoints[idx],
        updated_by,
        OP_UNLINK_BUNDLE,
        idempotency_key.as_str(),
        now,
    );
    Ok(MessagingApplied {
        index: idx,
        mutated: true,
    })
}

/// Set the welcome flow on a messaging endpoint. Rejects with
/// [`MessagingError::BundleNotLinked`] when the bundle is not linked, and
/// [`MessagingError::WelcomePackUnknown`] when `pack_id` does not appear
/// in any current revision's pack_list. Idempotent when the same welcome
/// flow ref is already set (`mutated == false`).
pub fn set_messaging_welcome_flow(
    env: &mut Environment,
    payload: SetMessagingWelcomeFlowPayload,
    idempotency_key: &IdempotencyKey,
    now: DateTime<Utc>,
) -> Result<MessagingApplied, MessagingError> {
    let idx = find_endpoint_idx(env, payload.endpoint_id)?;
    if !env.messaging_endpoints[idx]
        .linked_bundles
        .contains(&payload.bundle_id)
    {
        return Err(MessagingError::BundleNotLinked {
            bundle_id: payload.bundle_id,
            endpoint_id: payload.endpoint_id,
        });
    }
    validate_welcome_pack_id(env, &payload.bundle_id, payload.pack_id.as_str())?;
    let new_welcome = WelcomeFlowRef {
        bundle_id: payload.bundle_id,
        pack_id: payload.pack_id,
        flow_id: payload.flow_id,
    };
    if env.messaging_endpoints[idx].welcome_flow.as_ref() == Some(&new_welcome) {
        return Ok(MessagingApplied {
            index: idx,
            mutated: false,
        });
    }
    env.messaging_endpoints[idx].welcome_flow = Some(new_welcome);
    stamp_mutation(
        &mut env.messaging_endpoints[idx],
        &payload.updated_by,
        OP_SET_WELCOME_FLOW,
        idempotency_key.as_str(),
        now,
    );
    Ok(MessagingApplied {
        index: idx,
        mutated: true,
    })
}

/// Remove a messaging endpoint by id. Idempotent when the endpoint is
/// already absent — returns whether the env was actually mutated (the
/// only verb in this group that cannot fail).
pub fn remove_messaging_endpoint(env: &mut Environment, endpoint_id: MessagingEndpointId) -> bool {
    match env
        .messaging_endpoints
        .iter()
        .position(|e| e.endpoint_id == endpoint_id)
    {
        Some(idx) => {
            env.messaging_endpoints.remove(idx);
            true
        }
        None => false,
    }
}

/// Rotate the webhook secret for a messaging endpoint: `provision` mints a
/// new secret value (receiving the existing ref so an already-decoupled
/// endpoint keeps its URI) and the returned ref is stamped. Idempotent on
/// same-key replay (`mutated == false`, `provision` not called — a replay
/// must never overwrite the live secret with a fresh value).
pub fn rotate_messaging_webhook_secret(
    env: &mut Environment,
    endpoint_id: MessagingEndpointId,
    updated_by: &str,
    idempotency_key: &IdempotencyKey,
    now: DateTime<Utc>,
    provision: impl FnOnce(Option<&SecretRef>) -> Result<SecretRef, MessagingError>,
) -> Result<MessagingApplied, MessagingError> {
    let idx = find_endpoint_idx(env, endpoint_id)?;
    let suffix = idem_suffix(OP_ROTATE_WEBHOOK_SECRET, idempotency_key.as_str());
    if carries_idem_key(&env.messaging_endpoints[idx], &suffix) {
        return Ok(MessagingApplied {
            index: idx,
            mutated: false,
        });
    }
    let secret_ref = provision(env.messaging_endpoints[idx].webhook_secret_ref.as_ref())?;
    env.messaging_endpoints[idx].webhook_secret_ref = Some(secret_ref);
    stamp_mutation(
        &mut env.messaging_endpoints[idx],
        updated_by,
        OP_ROTATE_WEBHOOK_SECRET,
        idempotency_key.as_str(),
        now,
    );
    Ok(MessagingApplied {
        index: idx,
        mutated: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle_deployment::{
        BundleDeployment, BundleDeploymentStatus, RouteBinding, TenantSelector,
    };
    use crate::engine::fresh_environment;
    use crate::environment::EnvironmentHostConfig;
    use crate::ids::{CustomerId, RevisionId};
    use crate::retention::{HealthStatus, RetentionPolicy, RevocationConfig};
    use crate::revision::{PackListEntry, Revision, RevisionLifecycle};
    use std::path::PathBuf;

    fn env_id() -> EnvId {
        EnvId::try_from("local").unwrap()
    }

    fn minimal_env() -> Environment {
        fresh_environment(
            &env_id(),
            "Local".to_string(),
            EnvironmentHostConfig {
                env_id: env_id(),
                region: None,
                tenant_org_id: None,
                listen_addr: None,
                public_base_url: None,
                gui_enabled: None,
            },
            RevocationConfig::default(),
            RetentionPolicy::default(),
            HealthStatus::default(),
        )
    }

    fn fixed_now() -> DateTime<Utc> {
        "2026-06-12T00:00:00Z".parse().unwrap()
    }

    fn key(raw: &str) -> IdempotencyKey {
        IdempotencyKey::new(raw).unwrap()
    }

    fn add_payload(provider_type: &str, provider_id: &str) -> AddMessagingEndpointPayload {
        AddMessagingEndpointPayload {
            provider_id: provider_id.to_string(),
            provider_type: provider_type.to_string(),
            display_name: format!("{provider_type} {provider_id}"),
            secret_refs: Vec::new(),
            webhook_secret_ref: None,
            updated_by: "tester".to_string(),
        }
    }

    fn add_payload_with_webhook_ref(
        provider_type: &str,
        provider_id: &str,
        webhook_secret_ref: &str,
    ) -> AddMessagingEndpointPayload {
        AddMessagingEndpointPayload {
            webhook_secret_ref: Some(webhook_secret_ref.to_string()),
            ..add_payload(provider_type, provider_id)
        }
    }

    /// A provision closure that must never run.
    fn no_provision(_: Option<&SecretRef>) -> Result<SecretRef, MessagingError> {
        panic!("provision must not be called on this path");
    }

    fn fixed_ref() -> SecretRef {
        SecretRef::try_new("secret://local/default/_/messaging-x/webhook_secret").unwrap()
    }

    fn deployed_bundle(env: &mut Environment, bundle: &str) -> BundleId {
        let bundle_id = BundleId::new(bundle);
        env.bundles.push(BundleDeployment {
            schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
            deployment_id: crate::ids::DeploymentId::new(),
            env_id: env_id(),
            bundle_id: bundle_id.clone(),
            customer_id: CustomerId::new("cust"),
            status: BundleDeploymentStatus::Active,
            current_revisions: Vec::new(),
            route_binding: RouteBinding {
                hosts: Vec::new(),
                path_prefixes: Vec::new(),
                tenant_selector: TenantSelector {
                    tenant: "default".to_string(),
                    team: "default".to_string(),
                },
            },
            revenue_share: Vec::new(),
            revenue_policy_ref: PathBuf::new(),
            usage: None,
            created_at: fixed_now(),
            authorization_ref: PathBuf::from("auth.json"),
            config_overrides: Default::default(),
        });
        bundle_id
    }

    fn added(env: &mut Environment, provider_type: &str, provider_id: &str, k: &str) -> usize {
        add_messaging_endpoint(
            env,
            add_payload(provider_type, provider_id),
            MessagingEndpointId::new(),
            &key(k),
            fixed_now(),
            no_provision,
        )
        .expect("add")
        .index
    }

    // --- add -----------------------------------------------------------------

    #[test]
    fn add_non_telegram_skips_provision_and_pushes() {
        let mut env = minimal_env();
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("teams", "legal"),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            no_provision,
        )
        .unwrap();
        assert!(applied.mutated);
        let ep = &env.messaging_endpoints[applied.index];
        assert_eq!(ep.provider_type, "teams");
        assert_eq!(ep.updated_by, "tester#idem=add:k1");
        assert_eq!(ep.generation, 0);
        assert!(ep.webhook_secret_ref.is_none());
    }

    #[test]
    fn add_telegram_class_provisions_with_no_existing_ref() {
        let mut env = minimal_env();
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("telegram", "bot-a"),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            |existing| {
                assert!(existing.is_none(), "fresh endpoint has no existing ref");
                Ok(fixed_ref())
            },
        )
        .unwrap();
        assert_eq!(
            env.messaging_endpoints[applied.index].webhook_secret_ref,
            Some(fixed_ref())
        );
    }

    #[test]
    fn add_telegram_class_with_supplied_ref_uses_it_without_provision() {
        let mut env = minimal_env();
        let supplied = "secret://local/default/_/messaging-byo/webhook_secret";
        // `no_provision` panics if called — proves the supplied ref bypasses
        // the backend sink entirely (the remote operator-store path).
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload_with_webhook_ref("telegram", "bot-a", supplied),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            no_provision,
        )
        .unwrap();
        assert!(applied.mutated);
        assert_eq!(
            env.messaging_endpoints[applied.index]
                .webhook_secret_ref
                .as_ref()
                .map(|r| r.as_str()),
            Some(supplied)
        );
    }

    #[test]
    fn add_telegram_class_with_malformed_supplied_ref_is_rejected() {
        let mut env = minimal_env();
        let err = add_messaging_endpoint(
            &mut env,
            add_payload_with_webhook_ref("telegram", "bot-a", "not-a-secret-uri"),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            no_provision,
        )
        .unwrap_err();
        assert!(matches!(err, MessagingError::InvalidSecretRef { .. }));
        assert!(
            env.messaging_endpoints.is_empty(),
            "a rejected add must not push"
        );
    }

    #[test]
    fn add_non_telegram_with_supplied_ref_is_rejected() {
        let mut env = minimal_env();
        let err = add_messaging_endpoint(
            &mut env,
            add_payload_with_webhook_ref(
                "teams",
                "legal",
                "secret://local/default/_/messaging-x/webhook_secret",
            ),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            no_provision,
        )
        .unwrap_err();
        match err {
            MessagingError::InvalidSecretRef { ref message, .. } => {
                assert!(
                    message.contains("only valid for telegram-class"),
                    "got {err:?}"
                );
            }
            other => panic!("expected InvalidSecretRef, got {other:?}"),
        }
        assert!(env.messaging_endpoints.is_empty());
    }

    #[test]
    fn add_same_key_same_identity_replays_without_mutation() {
        let mut env = minimal_env();
        let idx = added(&mut env, "teams", "legal", "k-replay");
        let before = env.clone();
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("teams", "legal"),
            MessagingEndpointId::new(),
            &key("k-replay"),
            fixed_now(),
            no_provision,
        )
        .unwrap();
        assert_eq!(applied.index, idx);
        assert!(!applied.mutated);
        assert_eq!(env, before, "replay must leave the env untouched");
    }

    #[test]
    fn add_same_key_different_identity_is_key_reuse() {
        let mut env = minimal_env();
        added(&mut env, "teams", "legal", "k-shared");
        let err = add_messaging_endpoint(
            &mut env,
            add_payload("slack", "ops"),
            MessagingEndpointId::new(),
            &key("k-shared"),
            fixed_now(),
            no_provision,
        )
        .unwrap_err();
        assert!(matches!(err, MessagingError::IdempotencyKeyReuse { .. }));
        assert_eq!(
            err.to_string(),
            "idempotency key `k-shared` already used to add `teams`/`legal` in env `local`; \
             pass a fresh key"
        );
    }

    #[test]
    fn add_duplicate_identity_rejected() {
        let mut env = minimal_env();
        added(&mut env, "teams", "legal", "k1");
        let err = add_messaging_endpoint(
            &mut env,
            add_payload("teams", "legal"),
            MessagingEndpointId::new(),
            &key("k2"),
            fixed_now(),
            no_provision,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "messaging endpoint with provider_type=`teams` provider_id=`legal` already \
             exists in env `local`"
        );
    }

    #[test]
    fn add_invalid_secret_ref_rejected_before_provision() {
        let mut env = minimal_env();
        let mut payload = add_payload("telegram", "bot-a");
        payload.secret_refs = vec!["not-a-ref".to_string()];
        // `no_provision` panics if called — passing it pins the ordering.
        let err = add_messaging_endpoint(
            &mut env,
            payload,
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            no_provision,
        )
        .unwrap_err();
        assert!(matches!(err, MessagingError::InvalidSecretRef { .. }));
        assert!(env.messaging_endpoints.is_empty());
    }

    #[test]
    fn add_provision_failure_leaves_env_untouched() {
        let mut env = minimal_env();
        let err = add_messaging_endpoint(
            &mut env,
            add_payload("telegram", "bot-a"),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            |_| Err(MessagingError::SecretProvision("sink down".to_string())),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "sink down");
        assert!(env.messaging_endpoints.is_empty());
    }

    // --- link / unlink ---------------------------------------------------------

    #[test]
    fn link_appends_and_stamps() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        let applied = link_messaging_bundle(
            &mut env,
            eid,
            bundle_id.clone(),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap();
        assert!(applied.mutated);
        let ep = &env.messaging_endpoints[applied.index];
        assert_eq!(ep.linked_bundles, vec![bundle_id]);
        assert_eq!(ep.generation, 1);
        assert_eq!(ep.updated_by, "op#idem=link-bundle:k2");
    }

    #[test]
    fn link_unknown_endpoint_not_found() {
        let mut env = minimal_env();
        deployed_bundle(&mut env, "legal-pack");
        let ghost = MessagingEndpointId::new();
        let err = link_messaging_bundle(
            &mut env,
            ghost,
            BundleId::new("legal-pack"),
            "op",
            &key("k1"),
            fixed_now(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("messaging endpoint `{ghost}` not found in env `local`")
        );
    }

    #[test]
    fn link_undeployed_bundle_rejected() {
        let mut env = minimal_env();
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        let err = link_messaging_bundle(
            &mut env,
            eid,
            BundleId::new("ghost-pack"),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "bundle `ghost-pack` is not deployed in env `local`"
        );
    }

    #[test]
    fn link_already_linked_is_noop() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        link_messaging_bundle(
            &mut env,
            eid,
            bundle_id.clone(),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap();
        let before = env.clone();
        let applied =
            link_messaging_bundle(&mut env, eid, bundle_id, "op", &key("k3"), fixed_now()).unwrap();
        assert!(!applied.mutated);
        assert_eq!(env, before);
    }

    #[test]
    fn unlink_welcome_owner_rejected() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        link_messaging_bundle(
            &mut env,
            eid,
            bundle_id.clone(),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap();
        set_messaging_welcome_flow(
            &mut env,
            SetMessagingWelcomeFlowPayload {
                endpoint_id: eid,
                bundle_id: bundle_id.clone(),
                pack_id: PackId::new("welcome-pack"),
                flow_id: "hello".to_string(),
                updated_by: "op".to_string(),
            },
            &key("k3"),
            fixed_now(),
        )
        .unwrap();
        let err = unlink_messaging_bundle(&mut env, eid, bundle_id, "op", &key("k4"), fixed_now())
            .unwrap_err();
        assert!(matches!(err, MessagingError::WelcomeFlowOwned { .. }));
    }

    #[test]
    fn unlink_not_linked_is_noop() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        let before = env.clone();
        let applied =
            unlink_messaging_bundle(&mut env, eid, bundle_id, "op", &key("k2"), fixed_now())
                .unwrap();
        assert!(!applied.mutated);
        assert_eq!(env, before);
    }

    #[test]
    fn unlink_removes_and_stamps() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        link_messaging_bundle(
            &mut env,
            eid,
            bundle_id.clone(),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap();
        let applied =
            unlink_messaging_bundle(&mut env, eid, bundle_id, "op", &key("k3"), fixed_now())
                .unwrap();
        assert!(applied.mutated);
        let ep = &env.messaging_endpoints[applied.index];
        assert!(ep.linked_bundles.is_empty());
        assert_eq!(ep.generation, 2);
    }

    // --- set-welcome-flow ------------------------------------------------------

    #[test]
    fn welcome_flow_requires_linked_bundle() {
        let mut env = minimal_env();
        deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        let err = set_messaging_welcome_flow(
            &mut env,
            SetMessagingWelcomeFlowPayload {
                endpoint_id: eid,
                bundle_id: BundleId::new("legal-pack"),
                pack_id: PackId::new("welcome-pack"),
                flow_id: "hello".to_string(),
                updated_by: "op".to_string(),
            },
            &key("k2"),
            fixed_now(),
        )
        .unwrap_err();
        assert!(matches!(err, MessagingError::BundleNotLinked { .. }));
    }

    #[test]
    fn welcome_flow_unknown_pack_rejected_with_known_list() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        // Give the deployment a current revision listing a different pack.
        let rev_id = RevisionId::new();
        env.bundles[0].current_revisions.push(rev_id);
        env.revisions.push(Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: rev_id,
            env_id: env_id(),
            bundle_id: bundle_id.clone(),
            deployment_id: env.bundles[0].deployment_id,
            sequence: 1,
            created_at: fixed_now(),
            bundle_digest: "sha256:deadbeef".to_string(),
            bundle_source_uri: None,
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("known-pack"),
                version: "1.0.0".parse().unwrap(),
                digest: "sha256:cafe".to_string(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            pack_config_refs: Vec::new(),
            config_digest: "sha256:cafe".to_string(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle: RevisionLifecycle::Ready,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 0,
            abort_metrics: Vec::new(),
        });
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        link_messaging_bundle(
            &mut env,
            eid,
            bundle_id.clone(),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap();
        let err = set_messaging_welcome_flow(
            &mut env,
            SetMessagingWelcomeFlowPayload {
                endpoint_id: eid,
                bundle_id,
                pack_id: PackId::new("ghost-pack"),
                flow_id: "hello".to_string(),
                updated_by: "op".to_string(),
            },
            &key("k3"),
            fixed_now(),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "welcome_flow.pack_id `ghost-pack` does not appear in any current revision of \
             bundle `legal-pack` (known: [known-pack])"
        );
    }

    #[test]
    fn welcome_flow_same_ref_is_noop() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        link_messaging_bundle(
            &mut env,
            eid,
            bundle_id.clone(),
            "op",
            &key("k2"),
            fixed_now(),
        )
        .unwrap();
        let payload = SetMessagingWelcomeFlowPayload {
            endpoint_id: eid,
            bundle_id,
            pack_id: PackId::new("welcome-pack"),
            flow_id: "hello".to_string(),
            updated_by: "op".to_string(),
        };
        let first =
            set_messaging_welcome_flow(&mut env, payload.clone(), &key("k3"), fixed_now()).unwrap();
        assert!(first.mutated);
        let before = env.clone();
        let second =
            set_messaging_welcome_flow(&mut env, payload, &key("k4"), fixed_now()).unwrap();
        assert!(!second.mutated);
        assert_eq!(env, before);
    }

    // --- remove ------------------------------------------------------------------

    #[test]
    fn remove_present_then_absent() {
        let mut env = minimal_env();
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        assert!(remove_messaging_endpoint(&mut env, eid));
        assert!(env.messaging_endpoints.is_empty());
        assert!(!remove_messaging_endpoint(&mut env, eid));
    }

    // --- rotate ------------------------------------------------------------------

    #[test]
    fn rotate_passes_existing_ref_and_stamps() {
        let mut env = minimal_env();
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("telegram", "bot-a"),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            |_| Ok(fixed_ref()),
        )
        .unwrap();
        let eid = env.messaging_endpoints[applied.index].endpoint_id;
        let rotated = rotate_messaging_webhook_secret(
            &mut env,
            eid,
            "op",
            &key("k2"),
            fixed_now(),
            |existing| {
                assert_eq!(existing, Some(&fixed_ref()), "existing ref must be reused");
                Ok(fixed_ref())
            },
        )
        .unwrap();
        assert!(rotated.mutated);
        assert_eq!(env.messaging_endpoints[rotated.index].generation, 1);
    }

    #[test]
    fn rotate_same_key_replay_skips_provision() {
        let mut env = minimal_env();
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("telegram", "bot-a"),
            MessagingEndpointId::new(),
            &key("k1"),
            fixed_now(),
            |_| Ok(fixed_ref()),
        )
        .unwrap();
        let eid = env.messaging_endpoints[applied.index].endpoint_id;
        // First rotate with key "k-rotate" — must provision.
        rotate_messaging_webhook_secret(
            &mut env,
            eid,
            "op",
            &key("k-rotate"),
            fixed_now(),
            |existing| {
                assert_eq!(existing, Some(&fixed_ref()));
                Ok(fixed_ref())
            },
        )
        .unwrap();
        // Same-op same-key replay — provision must NOT run.
        let before = env.clone();
        let rotated = rotate_messaging_webhook_secret(
            &mut env,
            eid,
            "op",
            &key("k-rotate"),
            fixed_now(),
            no_provision,
        )
        .unwrap();
        assert!(!rotated.mutated);
        assert_eq!(env, before);
    }

    #[test]
    fn rotate_unknown_endpoint_not_found() {
        let mut env = minimal_env();
        let ghost = MessagingEndpointId::new();
        let err = rotate_messaging_webhook_secret(
            &mut env,
            ghost,
            "op",
            &key("k1"),
            fixed_now(),
            no_provision,
        )
        .unwrap_err();
        assert!(matches!(err, MessagingError::EndpointNotFound { .. }));
    }

    // --- cross-op idem-key isolation (regression for the operation-scope fix) -----

    /// Regression: add-with-K then rotate-with-K must NOT take the replay
    /// path — the rotate must invoke provision and report `mutated == true`.
    #[test]
    fn rotate_with_add_key_does_not_replay() {
        let mut env = minimal_env();
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("telegram", "bot-a"),
            MessagingEndpointId::new(),
            &key("k-shared"),
            fixed_now(),
            |_| Ok(fixed_ref()),
        )
        .unwrap();
        assert!(applied.mutated);
        let eid = env.messaging_endpoints[applied.index].endpoint_id;
        // Rotate reusing the add's key — provision MUST run.
        let mut provision_called = false;
        let rotated = rotate_messaging_webhook_secret(
            &mut env,
            eid,
            "op",
            &key("k-shared"),
            fixed_now(),
            |existing| {
                provision_called = true;
                assert_eq!(existing, Some(&fixed_ref()));
                Ok(fixed_ref())
            },
        )
        .unwrap();
        assert!(
            provision_called,
            "provision must be called for a cross-op key"
        );
        assert!(rotated.mutated);
        assert_eq!(env.messaging_endpoints[rotated.index].generation, 1);
    }

    /// Regression: link-bundle stamps key K on an endpoint; a subsequent
    /// `add_messaging_endpoint` with the SAME key K and a DIFFERENT identity
    /// must NOT raise `IdempotencyKeyReuse` — it must create the new
    /// endpoint (fresh mutation, guarded by the duplicate-identity check).
    #[test]
    fn add_with_link_stamped_key_proceeds_as_fresh_mutation() {
        let mut env = minimal_env();
        let bundle_id = deployed_bundle(&mut env, "legal-pack");
        let idx = added(&mut env, "teams", "legal", "k1");
        let eid = env.messaging_endpoints[idx].endpoint_id;
        // Link stamps key "k-shared" onto the existing endpoint.
        link_messaging_bundle(
            &mut env,
            eid,
            bundle_id,
            "op",
            &key("k-shared"),
            fixed_now(),
        )
        .unwrap();
        // Now add a NEW endpoint with the SAME key but different identity.
        let applied = add_messaging_endpoint(
            &mut env,
            add_payload("slack", "ops"),
            MessagingEndpointId::new(),
            &key("k-shared"),
            fixed_now(),
            no_provision,
        )
        .unwrap();
        assert!(applied.mutated);
        assert_eq!(
            env.messaging_endpoints[applied.index].provider_type,
            "slack"
        );
    }

    // --- telegram classifier -------------------------------------------------------

    #[test]
    fn telegram_class_is_strict_on_the_dot() {
        assert!(is_telegram_class("telegram"));
        assert!(is_telegram_class("telegram.bot"));
        assert!(is_telegram_class("messaging.telegram"));
        assert!(is_telegram_class("messaging.telegram.bot"));
        assert!(!is_telegram_class("telegrambot"));
        assert!(!is_telegram_class("messaging.telegrambot"));
        assert!(!is_telegram_class("teams"));
    }

    // --- wire-format pins ------------------------------------------------------------
    //
    // These pin the JSON encoding the PR-3b `HttpEnvironmentStore` client
    // established with its private DTOs. Changing them breaks the deployed
    // client/server pairing.

    #[test]
    fn add_payload_wire_encoding() {
        let payload = AddMessagingEndpointPayload {
            provider_id: "legal-bot".to_string(),
            provider_type: "teams".to_string(),
            display_name: "Legal".to_string(),
            secret_refs: vec!["secret://local/default/_/p/token".to_string()],
            webhook_secret_ref: None,
            updated_by: "op".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        // `webhook_secret_ref: None` is omitted (skip_serializing_if), so the
        // wire shape stays byte-compatible with pre-BYO-ref clients/servers.
        assert_eq!(
            json,
            serde_json::json!({
                "provider_id": "legal-bot",
                "provider_type": "teams",
                "display_name": "Legal",
                "secret_refs": ["secret://local/default/_/p/token"],
                "updated_by": "op",
            })
        );
        let back: AddMessagingEndpointPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn add_payload_wire_encoding_with_webhook_ref() {
        let payload = AddMessagingEndpointPayload {
            provider_id: "tg-bot".to_string(),
            provider_type: "telegram".to_string(),
            display_name: "Bot".to_string(),
            secret_refs: Vec::new(),
            webhook_secret_ref: Some(
                "secret://local/default/_/messaging-byo/webhook_secret".to_string(),
            ),
            updated_by: "op".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            json["webhook_secret_ref"],
            "secret://local/default/_/messaging-byo/webhook_secret"
        );
        let back: AddMessagingEndpointPayload = serde_json::from_value(json).unwrap();
        assert_eq!(back, payload);
    }

    #[test]
    fn link_payload_wire_encoding() {
        let payload = MessagingBundleLinkPayload {
            bundle_id: BundleId::new("legal-pack"),
            updated_by: "op".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            serde_json::json!({"bundle_id": "legal-pack", "updated_by": "op"})
        );
    }

    #[test]
    fn welcome_flow_payload_wire_encoding() {
        let eid = MessagingEndpointId::new();
        let payload = SetMessagingWelcomeFlowPayload {
            endpoint_id: eid,
            bundle_id: BundleId::new("legal-pack"),
            pack_id: PackId::new("welcome-pack"),
            flow_id: "hello".to_string(),
            updated_by: "op".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            serde_json::json!({
                "endpoint_id": eid.to_string(),
                "bundle_id": "legal-pack",
                "pack_id": "welcome-pack",
                "flow_id": "hello",
                "updated_by": "op",
            })
        );
    }

    #[test]
    fn rotate_payload_wire_encoding() {
        let payload = RotateWebhookSecretPayload {
            updated_by: "op".to_string(),
        };
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            serde_json::json!({"updated_by": "op"})
        );
    }
}
