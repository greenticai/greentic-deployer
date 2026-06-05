//! `gtc op messaging endpoint {add,list,show,link-bundle,unlink-bundle,set-welcome-flow,remove}`
//! (`Phase M1.2`).
//!
//! Manages `Environment.messaging_endpoints: Vec<MessagingEndpoint>` plus the
//! derived `<env_dir>/messaging/` projection. Each mutation:
//!
//! 1. transacts under the env flock,
//! 2. validates the resulting `Environment`,
//! 3. saves `environment.json`,
//! 4. re-materializes the per-endpoint files and `index.json`,
//! 5. records the operation in the local-only audit log.
//!
//! Endpoint ids are ULID-shaped — minted on `add`, accepted as positionals on
//! every other verb. `provider_id` is the INSTANCE identity (`teams-legal-bot`)
//! distinct from `provider_type` (`teams`); the two together are unique per
//! environment.

use chrono::Utc;
use greentic_deploy_spec::{
    BundleId, EnvId, MessagingEndpoint, MessagingEndpointId, PackId, SchemaVersion, SecretRef,
    WelcomeFlowRef,
};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str::FromStr;

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

const NOUN: &str = "messaging.endpoint";

// --- payloads ----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointAddPayload {
    pub environment_id: String,
    pub provider_id: String,
    pub provider_type: String,
    pub display_name: String,
    #[serde(default)]
    pub secret_refs: Vec<String>,
    pub idempotency_key: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointLinkBundlePayload {
    pub environment_id: String,
    pub endpoint_id: String,
    pub bundle_id: String,
    pub idempotency_key: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSetWelcomeFlowPayload {
    pub environment_id: String,
    pub endpoint_id: String,
    pub bundle_id: String,
    pub pack_id: String,
    pub flow_id: String,
    pub idempotency_key: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRotateWebhookSecretPayload {
    pub environment_id: String,
    pub endpoint_id: String,
    pub idempotency_key: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRemovePayload {
    pub environment_id: String,
    pub endpoint_id: String,
    pub idempotency_key: String,
    pub updated_by: String,
}

// --- summary -----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub environment_id: String,
    pub endpoint_id: String,
    pub provider_type: String,
    pub provider_id: String,
    pub display_name: String,
    pub linked_bundles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_flow: Option<WelcomeFlowSummary>,
    pub secret_refs: Vec<String>,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeFlowSummary {
    pub bundle_id: String,
    pub pack_id: String,
    pub flow_id: String,
}

impl EndpointSummary {
    fn from(env_id: &EnvId, ep: &MessagingEndpoint) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            endpoint_id: ep.endpoint_id.to_string(),
            provider_type: ep.provider_type.clone(),
            provider_id: ep.provider_id.clone(),
            display_name: ep.display_name.clone(),
            linked_bundles: ep
                .linked_bundles
                .iter()
                .map(|b| b.as_str().to_string())
                .collect(),
            welcome_flow: ep.welcome_flow.as_ref().map(|w| WelcomeFlowSummary {
                bundle_id: w.bundle_id.as_str().to_string(),
                pack_id: w.pack_id.as_str().to_string(),
                flow_id: w.flow_id.clone(),
            }),
            secret_refs: ep
                .secret_refs
                .iter()
                .map(|r| r.as_str().to_string())
                .collect(),
            generation: ep.generation,
        }
    }
}

// --- verbs -------------------------------------------------------------------

pub fn add(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EndpointAddPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "add", add_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let provider_id = require_nonempty("provider_id", &payload.provider_id)?;
    let provider_type = require_nonempty("provider_type", &payload.provider_type)?;
    let display_name = require_nonempty("display_name", &payload.display_name)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let secret_refs = parse_secret_refs(&payload.secret_refs)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({
            "provider_id": provider_id,
            "provider_type": provider_type,
        }),
        idempotency_key: Some(idempotency_key.clone()),
    };
    let idem_suffix = idem_suffix(&idempotency_key);
    audit_and_record(store, ctx, |committed| {
        let summary = store.transact(&env_id, |locked| -> Result<EndpointSummary, OpError> {
            let mut env = locked.load()?;
            // Idempotent replay: re-running `add` with the same key returns
            // the previously-created endpoint iff the payload's instance
            // identity matches what was stored; otherwise the key has been
            // reused for a different request and we refuse (traffic.rs
            // precedent). Drives off the key alone — `updated_by` is a
            // free-form actor label that retries may carry differently.
            if let Some(prev) = env
                .messaging_endpoints
                .iter()
                .find(|e| carries_idem_key(e, &idem_suffix))
            {
                if prev.provider_type == provider_type && prev.provider_id == provider_id {
                    // No env mutation needed, but a prior call may have
                    // failed AFTER saving env.json and BEFORE the projection
                    // refresh succeeded — re-run the refresh so retry
                    // repairs any stale on-disk projection.
                    let summary = EndpointSummary::from(&env_id, prev);
                    locked.refresh_messaging_projection(&env)?;
                    return Ok(summary);
                }
                return Err(OpError::Conflict(format!(
                    "idempotency key `{idempotency_key}` already used to add `{}`/`{}` in env `{env_id}`; pass a fresh key",
                    prev.provider_type, prev.provider_id
                )));
            }
            // `(provider_type, provider_id)` must be unique per env (M1
            // hard-cutover) — caught later by validate(), but surface a
            // precise error here so callers see the right message.
            if env
                .messaging_endpoints
                .iter()
                .any(|e| e.provider_type == provider_type && e.provider_id == provider_id)
            {
                return Err(OpError::Conflict(format!(
                    "messaging endpoint with provider_type=`{provider_type}` provider_id=`{provider_id}` already exists in env `{env_id}`"
                )));
            }
            let now = Utc::now();
            let webhook_secret = if is_telegram_class(&provider_type) {
                Some(generate_webhook_secret()?)
            } else {
                None
            };
            let endpoint = MessagingEndpoint {
                schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
                env_id: env_id.clone(),
                endpoint_id: MessagingEndpointId::new(),
                provider_id: provider_id.clone(),
                provider_type: provider_type.clone(),
                display_name: display_name.clone(),
                secret_refs: secret_refs.clone(),
                webhook_secret,
                linked_bundles: Vec::new(),
                welcome_flow: None,
                generation: 0,
                created_at: now,
                updated_at: now,
                updated_by: format_idem_writer(&updated_by, &idempotency_key),
            };
            env.messaging_endpoints.push(endpoint);
            locked.save(&env)?;
            // env.json is durable from this point — signal so an audit-append
            // failure on the projection-refresh path goes fail-closed instead
            // of being demoted to a warning.
            committed.mark_committed();
            locked.refresh_messaging_projection(&env)?;
            Ok(EndpointSummary::from(
                &env_id,
                env.messaging_endpoints
                    .last()
                    .expect("just pushed endpoint"),
            ))
        })?;
        Ok((
            OpOutcome::new(
                NOUN,
                "add",
                serde_json::to_value(summary).expect("EndpointSummary is json-safe"),
            ),
            super::AuditGens::NONE,
        ))
    })
}

pub fn list(store: &LocalFsStore, flags: &OpFlags, env_id: &str) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({"input_schema": "env_id positional"}),
        ));
    }
    let env_id = parse_env_id(env_id)?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let endpoints: Vec<EndpointSummary> = env
        .messaging_endpoints
        .iter()
        .map(|e| EndpointSummary::from(&env_id, e))
        .collect();
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({"environment_id": env_id.as_str(), "endpoints": endpoints}),
    ))
}

pub fn show(
    store: &LocalFsStore,
    flags: &OpFlags,
    env_id: &str,
    endpoint_id: &str,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "show",
            json!({"input_schema": "env_id + endpoint_id positionals"}),
        ));
    }
    let env_id = parse_env_id(env_id)?;
    let endpoint_id = parse_endpoint_id(endpoint_id)?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    let endpoint = env
        .messaging_endpoints
        .iter()
        .find(|e| e.endpoint_id == endpoint_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "messaging endpoint `{endpoint_id}` not found in env `{env_id}`"
            ))
        })?;
    Ok(OpOutcome::new(
        NOUN,
        "show",
        serde_json::to_value(EndpointSummary::from(&env_id, endpoint))
            .expect("EndpointSummary is json-safe"),
    ))
}

pub fn link_bundle(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EndpointLinkBundlePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "link-bundle", link_bundle_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let bundle_id = parse_bundle_id(&payload.bundle_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "link-bundle",
        target: json!({
            "endpoint_id": endpoint_id.to_string(),
            "bundle_id": bundle_id.as_str(),
        }),
        idempotency_key: Some(idempotency_key.clone()),
    };
    audit_and_record(store, ctx, |committed| {
        let summary = store.transact(&env_id, |locked| -> Result<EndpointSummary, OpError> {
            let mut env = locked.load()?;
            let idx = find_endpoint_idx(&env, endpoint_id, &env_id)?;
            // Idempotent replay on the (endpoint, bundle, key) triple is a
            // no-op success. Validate() rejects unknown bundle ids; we surface
            // a precise error first.
            if !env.bundles.iter().any(|b| b.bundle_id == bundle_id) {
                return Err(OpError::NotFound(format!(
                    "bundle `{bundle_id}` is not deployed in env `{env_id}`"
                )));
            }
            if env.messaging_endpoints[idx]
                .linked_bundles
                .contains(&bundle_id)
            {
                let summary = EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]);
                // Repair any stale projection from a prior failed call.
                locked.refresh_messaging_projection(&env)?;
                return Ok(summary);
            }
            env.messaging_endpoints[idx].linked_bundles.push(bundle_id);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &updated_by,
                &idempotency_key,
            );
            locked.save(&env)?;
            committed.mark_committed();
            locked.refresh_messaging_projection(&env)?;
            Ok(EndpointSummary::from(
                &env_id,
                &env.messaging_endpoints[idx],
            ))
        })?;
        Ok((
            OpOutcome::new(
                NOUN,
                "link-bundle",
                serde_json::to_value(summary).expect("EndpointSummary is json-safe"),
            ),
            super::AuditGens::NONE,
        ))
    })
}

pub fn unlink_bundle(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EndpointLinkBundlePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "unlink-bundle", link_bundle_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let bundle_id = parse_bundle_id(&payload.bundle_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "unlink-bundle",
        target: json!({
            "endpoint_id": endpoint_id.to_string(),
            "bundle_id": bundle_id.as_str(),
        }),
        idempotency_key: Some(idempotency_key.clone()),
    };
    audit_and_record(store, ctx, |committed| {
        let summary = store.transact(&env_id, |locked| -> Result<EndpointSummary, OpError> {
            let mut env = locked.load()?;
            let idx = find_endpoint_idx(&env, endpoint_id, &env_id)?;
            let bundle_idx = env.messaging_endpoints[idx]
                .linked_bundles
                .iter()
                .position(|b| b == &bundle_id);
            let Some(bidx) = bundle_idx else {
                // Idempotent: unlinking a bundle that isn't linked is a no-op.
                let summary = EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]);
                // Repair any stale projection from a prior failed call.
                locked.refresh_messaging_projection(&env)?;
                return Ok(summary);
            };
            // Removing a bundle that the welcome_flow points at would leave
            // the endpoint in a state validate() rejects; require the user
            // to clear the welcome flow first rather than silently dropping it.
            if let Some(welcome) = &env.messaging_endpoints[idx].welcome_flow
                && welcome.bundle_id == bundle_id
            {
                return Err(OpError::Conflict(format!(
                    "cannot unlink bundle `{bundle_id}` from endpoint `{endpoint_id}` while it owns the welcome_flow; clear the welcome_flow first via `set-welcome-flow` to a different linked bundle, or `remove` the endpoint"
                )));
            }
            env.messaging_endpoints[idx].linked_bundles.remove(bidx);
            stamp_mutation(&mut env.messaging_endpoints[idx], &updated_by, &idempotency_key);
            locked.save(&env)?;
            committed.mark_committed();
            locked.refresh_messaging_projection(&env)?;
            Ok(EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]))
        })?;
        Ok((
            OpOutcome::new(
                NOUN,
                "unlink-bundle",
                serde_json::to_value(summary).expect("EndpointSummary is json-safe"),
            ),
            super::AuditGens::NONE,
        ))
    })
}

pub fn set_welcome_flow(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EndpointSetWelcomeFlowPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "set-welcome-flow",
            set_welcome_flow_schema(),
        ));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let bundle_id = parse_bundle_id(&payload.bundle_id)?;
    let pack_id = require_nonempty("pack_id", &payload.pack_id)?;
    let flow_id = require_nonempty("flow_id", &payload.flow_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "set-welcome-flow",
        target: json!({
            "endpoint_id": endpoint_id.to_string(),
            "bundle_id": bundle_id.as_str(),
            "pack_id": pack_id,
            "flow_id": flow_id,
        }),
        idempotency_key: Some(idempotency_key.clone()),
    };
    audit_and_record(store, ctx, |committed| {
        let summary = store.transact(&env_id, |locked| -> Result<EndpointSummary, OpError> {
            let mut env = locked.load()?;
            let idx = find_endpoint_idx(&env, endpoint_id, &env_id)?;
            if !env.messaging_endpoints[idx]
                .linked_bundles
                .contains(&bundle_id)
            {
                return Err(OpError::InvalidArgument(format!(
                    "welcome_flow bundle `{bundle_id}` is not linked to endpoint `{endpoint_id}`; link it first via `link-bundle`"
                )));
            }
            // Cheap typo guard: when the linked bundle has at least one
            // current revision, require `pack_id` to appear in some
            // revision's `pack_list`. If `current_revisions` is empty the
            // bundle has not been staged yet, so accept and defer pack/flow
            // validation to runtime dispatch (M1.5). `flow_id` lives in
            // pack-manifest metadata that deploy-spec does not see, so
            // it stays caller-asserted and validated at first contact.
            validate_welcome_pack_id(&env, &bundle_id, &pack_id)?;
            let new_welcome = WelcomeFlowRef {
                bundle_id: bundle_id.clone(),
                pack_id: PackId::new(pack_id.clone()),
                flow_id: flow_id.clone(),
            };
            if env.messaging_endpoints[idx].welcome_flow.as_ref() == Some(&new_welcome) {
                // Idempotent replay — repair any stale projection from a
                // prior failed call before returning.
                let summary = EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]);
                locked.refresh_messaging_projection(&env)?;
                return Ok(summary);
            }
            env.messaging_endpoints[idx].welcome_flow = Some(new_welcome);
            stamp_mutation(&mut env.messaging_endpoints[idx], &updated_by, &idempotency_key);
            locked.save(&env)?;
            committed.mark_committed();
            locked.refresh_messaging_projection(&env)?;
            Ok(EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]))
        })?;
        Ok((
            OpOutcome::new(
                NOUN,
                "set-welcome-flow",
                serde_json::to_value(summary).expect("EndpointSummary is json-safe"),
            ),
            super::AuditGens::NONE,
        ))
    })
}

pub fn remove(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EndpointRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "remove", remove_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    // Validate inputs are non-empty for the audit envelope's sake; the values
    // themselves are not consumed by the remove path (no endpoint left to
    // stamp), so the audit ctx below references payload.idempotency_key
    // directly without binding here.
    require_nonempty("updated_by", &payload.updated_by)?;
    require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"endpoint_id": endpoint_id.to_string()}),
        idempotency_key: Some(payload.idempotency_key.clone()),
    };
    audit_and_record(store, ctx, |committed| {
        let removed_id =
            store.transact(&env_id, |locked| -> Result<MessagingEndpointId, OpError> {
                let mut env = locked.load()?;
                let idx = env
                    .messaging_endpoints
                    .iter()
                    .position(|e| e.endpoint_id == endpoint_id);
                let Some(idx) = idx else {
                    // Idempotent: removing an absent endpoint succeeds. Repair
                    // any stale projection from a prior failed call so a
                    // retry actually cleans up.
                    locked.refresh_messaging_projection(&env)?;
                    return Ok(endpoint_id);
                };
                env.messaging_endpoints.remove(idx);
                locked.save(&env)?;
                committed.mark_committed();
                locked.refresh_messaging_projection(&env)?;
                Ok(endpoint_id)
            })?;
        Ok((
            OpOutcome::new(
                NOUN,
                "remove",
                json!({"environment_id": env_id.as_str(), "endpoint_id": removed_id.to_string()}),
            ),
            super::AuditGens::NONE,
        ))
    })
}

pub fn rotate_webhook_secret(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<EndpointRotateWebhookSecretPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "rotate-webhook-secret",
            rotate_webhook_secret_schema(),
        ));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rotate-webhook-secret",
        target: json!({"endpoint_id": endpoint_id.to_string()}),
        idempotency_key: Some(idempotency_key.clone()),
    };
    let idem_suffix = idem_suffix(&idempotency_key);
    audit_and_record(store, ctx, |committed| {
        let summary = store.transact(&env_id, |locked| -> Result<EndpointSummary, OpError> {
            let mut env = locked.load()?;
            let idx = find_endpoint_idx(&env, endpoint_id, &env_id)?;
            // Idempotent replay: if the endpoint already carries this idem key,
            // the rotation already landed — return the existing endpoint.
            if carries_idem_key(&env.messaging_endpoints[idx], &idem_suffix) {
                let summary = EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]);
                locked.refresh_messaging_projection(&env)?;
                return Ok(summary);
            }
            let new_secret = generate_webhook_secret()?;
            env.messaging_endpoints[idx].webhook_secret = Some(new_secret);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &updated_by,
                &idempotency_key,
            );
            locked.save(&env)?;
            committed.mark_committed();
            locked.refresh_messaging_projection(&env)?;
            Ok(EndpointSummary::from(
                &env_id,
                &env.messaging_endpoints[idx],
            ))
        })?;
        Ok((
            OpOutcome::new(
                NOUN,
                "rotate-webhook-secret",
                serde_json::to_value(summary).expect("EndpointSummary is json-safe"),
            ),
            super::AuditGens::NONE,
        ))
    })
}

// --- internals ---------------------------------------------------------------

fn resolve_payload<T: serde::de::DeserializeOwned>(
    flags: &OpFlags,
    payload: Option<T>,
) -> Result<T, OpError> {
    if let Some(p) = payload {
        return Ok(p);
    }
    if let Some(path) = &flags.answers {
        return super::load_answers::<T>(path);
    }
    Err(OpError::InvalidArgument(
        "no payload provided: pass --answers <path> or supply positional args".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

fn parse_endpoint_id(raw: &str) -> Result<MessagingEndpointId, OpError> {
    ulid::Ulid::from_str(raw)
        .map(MessagingEndpointId)
        .map_err(|e| OpError::InvalidArgument(format!("endpoint_id: {e}")))
}

fn parse_bundle_id(raw: &str) -> Result<BundleId, OpError> {
    if raw.trim().is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }
    Ok(BundleId::new(raw))
}

fn parse_secret_refs(raws: &[String]) -> Result<Vec<SecretRef>, OpError> {
    raws.iter()
        .map(|r| {
            SecretRef::try_new(r)
                .map_err(|e| OpError::InvalidArgument(format!("secret_ref `{r}`: {e}")))
        })
        .collect()
}

fn require_nonempty(field: &str, value: &str) -> Result<String, OpError> {
    if value.trim().is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "{field} must not be empty"
        )));
    }
    Ok(value.to_string())
}

fn find_endpoint_idx(
    env: &greentic_deploy_spec::Environment,
    endpoint_id: MessagingEndpointId,
    env_id: &EnvId,
) -> Result<usize, OpError> {
    env.messaging_endpoints
        .iter()
        .position(|e| e.endpoint_id == endpoint_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "messaging endpoint `{endpoint_id}` not found in env `{env_id}`"
            ))
        })
}

/// Embed the idempotency key in `updated_by` so a same-key retry surfaces as
/// the original mutation. `MessagingEndpoint` has no separate
/// `idempotency_key` field today; the encoding here keeps the contract
/// without bloating the spec type for one CLI-side concern.
fn format_idem_writer(updated_by: &str, idempotency_key: &str) -> String {
    format!("{updated_by}#idem={idempotency_key}")
}

/// Build the `#idem=<key>` suffix once at the call site so a linear scan
/// over `messaging_endpoints` does not allocate a fresh `String` per element.
fn idem_suffix(idempotency_key: &str) -> String {
    format!("#idem={idempotency_key}")
}

fn carries_idem_key(endpoint: &MessagingEndpoint, idem_suffix: &str) -> bool {
    endpoint.updated_by.ends_with(idem_suffix)
}

/// Telegram-class providers need a per-endpoint webhook secret generated at
/// creation time. The prefix check covers `"telegram"`, `"messaging.telegram"`,
/// and `"messaging.telegram.bot"` — all plausible aliases in current configs.
fn is_telegram_class(provider_type: &str) -> bool {
    provider_type == "telegram"
        || provider_type.starts_with("telegram.")
        || provider_type == "messaging.telegram"
        || provider_type.starts_with("messaging.telegram.")
}

/// Generate a 32-char CSPRNG secret from `[A-Za-z0-9]` (≈190 bits entropy).
/// Passes the deploy-spec's `MIN_WEBHOOK_SECRET_LEN` validation.
fn generate_webhook_secret() -> Result<String, OpError> {
    const LEN: usize = 32;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; LEN];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| OpError::InvalidArgument(format!("CSPRNG entropy failure: {e}")))?;
    let secret: String = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    Ok(secret)
}

fn stamp_mutation(endpoint: &mut MessagingEndpoint, updated_by: &str, idempotency_key: &str) {
    endpoint.generation = endpoint.generation.saturating_add(1);
    endpoint.updated_at = Utc::now();
    endpoint.updated_by = format_idem_writer(updated_by, idempotency_key);
}

/// Catch obvious typos when setting a welcome flow's `pack_id`: when the
/// linked bundle has at least one `current_revision` whose pinned `pack_list`
/// is non-empty, the supplied `pack_id` must match one of those pack ids.
///
/// When `current_revisions` is empty (a freshly-deployed bundle that has not
/// been staged yet), the validator accepts and defers pack/flow resolution
/// to runtime dispatch (M1.5). Same for the inverse case where every
/// referenced revision's `pack_list` is empty — there is nothing to compare
/// against. `flow_id` is never validated here; it lives in pack-manifest
/// metadata that deploy-spec does not see, so it stays caller-asserted.
fn validate_welcome_pack_id(
    env: &greentic_deploy_spec::Environment,
    bundle_id: &BundleId,
    pack_id: &str,
) -> Result<(), OpError> {
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
    Err(OpError::InvalidArgument(format!(
        "welcome_flow.pack_id `{pack_id}` does not appear in any current revision of bundle `{bundle_id}` (known: [{}])",
        known_packs.join(", ")
    )))
}

// --- schema stubs ------------------------------------------------------------
//
// JSON Schema generation for the payload types is left out of M1.2 — the
// schemars wiring in `crates/greentic-deploy-spec/src/json_schema.rs` is a
// reserved stub for the whole crate, and adding hand-written schemas here
// would drift from the rest of the cli/ modules. Stubs return a hint string
// today; the wiring lands when the workspace schemars pass does.

fn verb_schema(verb: &str, fields: &[&str]) -> Value {
    json!({ "noun": NOUN, "verb": verb, "fields": fields })
}

fn add_schema() -> Value {
    verb_schema(
        "add",
        &[
            "environment_id",
            "provider_id",
            "provider_type",
            "display_name",
            "secret_refs (array of secret:// URIs)",
            "idempotency_key",
            "updated_by",
        ],
    )
}

fn link_bundle_schema() -> Value {
    verb_schema(
        "link-bundle / unlink-bundle",
        &[
            "environment_id",
            "endpoint_id",
            "bundle_id",
            "idempotency_key",
            "updated_by",
        ],
    )
}

fn set_welcome_flow_schema() -> Value {
    verb_schema(
        "set-welcome-flow",
        &[
            "environment_id",
            "endpoint_id",
            "bundle_id",
            "pack_id",
            "flow_id",
            "idempotency_key",
            "updated_by",
        ],
    )
}

fn remove_schema() -> Value {
    verb_schema(
        "remove",
        &[
            "environment_id",
            "endpoint_id",
            "idempotency_key",
            "updated_by",
        ],
    )
}

fn rotate_webhook_secret_schema() -> Value {
    verb_schema(
        "rotate-webhook-secret",
        &[
            "environment_id",
            "endpoint_id",
            "idempotency_key",
            "updated_by",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::{make_bundle_deployment, make_env};
    use crate::environment::messaging::MessagingEndpointIndexEntry;
    use tempfile::tempdir;

    fn seeded_store_with_bundles(
        bundle_ids: &[&str],
    ) -> (tempfile::TempDir, LocalFsStore, Vec<BundleId>) {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let mut ids = Vec::new();
        for id in bundle_ids {
            let b = make_bundle_deployment("local", id);
            ids.push(b.bundle_id.clone());
            env.bundles.push(b);
        }
        store.save(&env).unwrap();
        (dir, store, ids)
    }

    fn add_payload(provider_type: &str, provider_id: &str, key: &str) -> EndpointAddPayload {
        EndpointAddPayload {
            environment_id: "local".to_string(),
            provider_id: provider_id.to_string(),
            provider_type: provider_type.to_string(),
            display_name: format!("{provider_type} {provider_id}"),
            secret_refs: vec![],
            idempotency_key: key.to_string(),
            updated_by: "tester".to_string(),
        }
    }

    fn endpoint_id_from(outcome: &OpOutcome) -> MessagingEndpointId {
        let raw = outcome.result["endpoint_id"].as_str().expect("endpoint_id");
        parse_endpoint_id(raw).expect("endpoint_id parses")
    }

    #[test]
    fn add_then_show_returns_endpoint() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let shown = show(&store, &OpFlags::default(), "local", &id.to_string()).unwrap();
        assert_eq!(shown.result["provider_type"], "teams");
        assert_eq!(shown.result["provider_id"], "legal-bot");
    }

    #[test]
    fn list_enumerates_all_endpoints() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "accounting", "k2")),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let endpoints = listed.result["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn duplicate_provider_instance_rejected_at_verb_layer() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let err = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k2")),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)));
    }

    #[test]
    fn idempotent_add_returns_same_endpoint() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let first = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k-replay")),
        )
        .unwrap();
        let second = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k-replay")),
        )
        .unwrap();
        assert_eq!(
            endpoint_id_from(&first),
            endpoint_id_from(&second),
            "idempotent replay must return the original endpoint"
        );
    }

    #[test]
    fn same_key_with_different_payload_is_conflict() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k-shared")),
        )
        .unwrap();
        let err = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("slack", "ops", "k-shared")),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)));
    }

    #[test]
    fn link_then_unlink_bundle_updates_endpoint() {
        let (_dir, store, bundle_ids) = seeded_store_with_bundles(&["legal-pack"]);
        let bundle = &bundle_ids[0];
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let linked = link_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        let linked_bundles = linked.result["linked_bundles"].as_array().unwrap();
        assert_eq!(linked_bundles.len(), 1);
        let unlinked = unlink_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k3".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        assert!(
            unlinked.result["linked_bundles"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn link_unknown_bundle_is_not_found() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let err = link_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: "ghost-bundle".to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)));
    }

    #[test]
    fn set_welcome_flow_requires_linked_bundle() {
        let (_dir, store, bundle_ids) = seeded_store_with_bundles(&["legal-pack"]);
        let bundle = &bundle_ids[0];
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        // No link yet ⇒ set-welcome-flow rejects with InvalidArgument.
        let err = set_welcome_flow(
            &store,
            &OpFlags::default(),
            Some(EndpointSetWelcomeFlowPayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                pack_id: "legal".to_string(),
                flow_id: "main".to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
        // Link, then succeed.
        link_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k3".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        let set = set_welcome_flow(
            &store,
            &OpFlags::default(),
            Some(EndpointSetWelcomeFlowPayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                pack_id: "legal".to_string(),
                flow_id: "main".to_string(),
                idempotency_key: "k4".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(set.result["welcome_flow"]["flow_id"], "main");
    }

    #[test]
    fn unlink_welcome_flow_bundle_is_rejected() {
        let (_dir, store, bundle_ids) = seeded_store_with_bundles(&["legal-pack"]);
        let bundle = &bundle_ids[0];
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        link_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        set_welcome_flow(
            &store,
            &OpFlags::default(),
            Some(EndpointSetWelcomeFlowPayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                pack_id: "legal".to_string(),
                flow_id: "main".to_string(),
                idempotency_key: "k3".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        let err = unlink_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k4".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)));
    }

    #[test]
    fn remove_then_show_returns_not_found() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        remove(
            &store,
            &OpFlags::default(),
            Some(EndpointRemovePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        let err = show(&store, &OpFlags::default(), "local", &id.to_string()).unwrap_err();
        assert!(matches!(err, OpError::NotFound(_)));
    }

    #[test]
    fn idempotent_remove_succeeds_when_absent() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let outcome = remove(
            &store,
            &OpFlags::default(),
            Some(EndpointRemovePayload {
                environment_id: "local".to_string(),
                endpoint_id: MessagingEndpointId::new().to_string(),
                idempotency_key: "k1".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.op, "remove");
    }

    #[test]
    fn add_materializes_index_and_per_endpoint_file() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let endpoint_path = env_dir.join("messaging").join(format!("{id}.json"));
        let index_path = env_dir.join("messaging").join("index.json");
        assert!(
            endpoint_path.exists(),
            "per-endpoint file must be materialized"
        );
        assert!(index_path.exists(), "index.json must be materialized");
        let index: Vec<MessagingEndpointIndexEntry> =
            serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].endpoint_id, id);
    }

    #[test]
    fn remove_prunes_per_endpoint_file_and_deletes_empty_index() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let endpoint_path = env_dir.join("messaging").join(format!("{id}.json"));
        let index_path = env_dir.join("messaging").join("index.json");
        assert!(endpoint_path.exists());
        remove(
            &store,
            &OpFlags::default(),
            Some(EndpointRemovePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        assert!(
            !endpoint_path.exists(),
            "per-endpoint file must be pruned on remove"
        );
        assert!(
            !index_path.exists(),
            "index.json must be deleted when env has no endpoints"
        );
    }

    #[test]
    fn idempotent_replay_repairs_stale_projection() {
        // Regression for Codex Finding #2: a prior failed call may have
        // saved env.json but left the projection stale; the idempotent
        // retry must re-materialize the projection rather than early-return
        // without touching disk.
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let endpoint_path = env_dir.join("messaging").join(format!("{id}.json"));
        let index_path = env_dir.join("messaging").join("index.json");
        // Simulate a prior failed projection refresh by clobbering the
        // per-endpoint file out from under the store.
        std::fs::remove_file(&endpoint_path).unwrap();
        std::fs::remove_file(&index_path).unwrap();
        // Replay add with the same key — should re-publish the projection
        // even though env.json is already correct.
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        assert!(
            endpoint_path.exists(),
            "idempotent add replay must republish the per-endpoint projection"
        );
        assert!(
            index_path.exists(),
            "idempotent add replay must republish the index"
        );
    }

    #[test]
    fn idempotent_remove_replay_repairs_stale_projection() {
        // Companion to the add case: remove that succeeded against env.json
        // but failed to prune the projection must be repaired on retry,
        // which hits the absent-endpoint idempotent path.
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        let endpoint_path = env_dir.join("messaging").join(format!("{id}.json"));
        // Manually mutate env.json out from under the store to drop the
        // endpoint, leaving the projection in the "previous-call-saved-but-
        // pruning-failed" shape.
        let env_path = env_dir.join("environment.json");
        let mut env: greentic_deploy_spec::Environment =
            serde_json::from_slice(&std::fs::read(&env_path).unwrap()).unwrap();
        env.messaging_endpoints.clear();
        std::fs::write(&env_path, serde_json::to_vec_pretty(&env).unwrap()).unwrap();
        assert!(
            endpoint_path.exists(),
            "fixture: per-endpoint file must still be present pre-replay"
        );
        // Replay remove — endpoint is absent from env.json, hits the
        // idempotent path, must still prune the stale per-endpoint file.
        remove(
            &store,
            &OpFlags::default(),
            Some(EndpointRemovePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        assert!(
            !endpoint_path.exists(),
            "idempotent remove replay must prune the stale per-endpoint file"
        );
    }

    #[test]
    fn set_welcome_flow_rejects_unknown_pack_id_when_revisions_exist() {
        // Regression for Codex Finding #3: when the linked bundle has at
        // least one current revision with a non-empty pack_list, a typo'd
        // pack_id is rejected at write time rather than persisted as a
        // ticking time-bomb for first-contact dispatch (M1.5).
        use greentic_deploy_spec::RevisionLifecycle;
        let (_dir, store, bundle_ids) = seeded_store_with_bundles(&["legal-pack"]);
        let bundle = &bundle_ids[0];
        // Seed a revision with a known pack id so the validator has
        // something to compare against.
        let env_id_typed = EnvId::try_from("local").unwrap();
        let mut env = store.load(&env_id_typed).unwrap();
        let deployment_id = env.bundles[0].deployment_id;
        let rev = crate::cli::tests_common::make_revision(
            "local",
            bundle.as_str(),
            &deployment_id,
            1,
            RevisionLifecycle::Ready,
        );
        env.bundles[0].current_revisions.push(rev.revision_id);
        env.revisions.push(rev);
        store.save(&env).unwrap();
        // Wire endpoint + link.
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        link_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        // Typo'd pack id — must reject.
        let err = set_welcome_flow(
            &store,
            &OpFlags::default(),
            Some(EndpointSetWelcomeFlowPayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                pack_id: "typo-pack".to_string(),
                flow_id: "main".to_string(),
                idempotency_key: "k3".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(_)),
            "typo'd pack_id must be rejected when bundle has current revisions to compare against, got: {err:?}"
        );
        // Real pack id (from make_revision's pack_list[0]) — must succeed.
        let ok = set_welcome_flow(
            &store,
            &OpFlags::default(),
            Some(EndpointSetWelcomeFlowPayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                pack_id: "greentic.test.pack".to_string(),
                flow_id: "main".to_string(),
                idempotency_key: "k4".to_string(),
                updated_by: "tester".to_string(),
            }),
        );
        assert!(
            ok.is_ok(),
            "pack_id matching the bundle's pack_list must be accepted"
        );
    }

    #[test]
    fn set_welcome_flow_accepts_any_pack_id_when_bundle_has_no_revisions_yet() {
        // Companion to the above: bundles deployed but not yet staged carry
        // an empty `current_revisions`; the validator must skip the typo
        // guard rather than blocking the onboarding flow where set-welcome-
        // flow is wired before stage.
        let (_dir, store, bundle_ids) = seeded_store_with_bundles(&["legal-pack"]);
        let bundle = &bundle_ids[0];
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("teams", "legal", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        link_bundle(
            &store,
            &OpFlags::default(),
            Some(EndpointLinkBundlePayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                idempotency_key: "k2".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        let outcome = set_welcome_flow(
            &store,
            &OpFlags::default(),
            Some(EndpointSetWelcomeFlowPayload {
                environment_id: "local".to_string(),
                endpoint_id: id.to_string(),
                bundle_id: bundle.as_str().to_string(),
                pack_id: "future-pack".to_string(),
                flow_id: "main".to_string(),
                idempotency_key: "k3".to_string(),
                updated_by: "tester".to_string(),
            }),
        )
        .unwrap();
        assert_eq!(outcome.result["welcome_flow"]["pack_id"], "future-pack");
    }

    #[test]
    fn add_with_missing_required_field_is_invalid_argument() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let bad = EndpointAddPayload {
            environment_id: "local".to_string(),
            provider_id: "".to_string(),
            provider_type: "teams".to_string(),
            display_name: "x".to_string(),
            secret_refs: vec![],
            idempotency_key: "k1".to_string(),
            updated_by: "tester".to_string(),
        };
        let err = add(&store, &OpFlags::default(), Some(bad)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    // --- webhook_secret auto-gen + rotate tests --------------------------------

    /// Load the raw `MessagingEndpoint` from the store for a given endpoint id.
    fn load_raw_endpoint(
        store: &LocalFsStore,
        endpoint_id: &MessagingEndpointId,
    ) -> MessagingEndpoint {
        let env_id = EnvId::try_from("local").unwrap();
        let env = store.load(&env_id).unwrap();
        env.messaging_endpoints
            .into_iter()
            .find(|e| e.endpoint_id == *endpoint_id)
            .expect("endpoint must exist")
    }

    #[test]
    fn add_telegram_generates_webhook_secret() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&outcome);
        let ep = load_raw_endpoint(&store, &id);
        let secret = ep
            .webhook_secret
            .expect("telegram must have webhook_secret");
        assert!(
            secret.len() >= 32,
            "secret must be ≥32 chars, got {}",
            secret.len()
        );
    }

    #[test]
    fn add_telegram_dotted_generates_webhook_secret() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("messaging.telegram.bot", "tg-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&outcome);
        let ep = load_raw_endpoint(&store, &id);
        assert!(
            ep.webhook_secret.is_some(),
            "messaging.telegram.bot must auto-gen webhook_secret"
        );
    }

    #[test]
    fn add_non_telegram_has_no_webhook_secret() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("slack", "ops", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&outcome);
        let ep = load_raw_endpoint(&store, &id);
        assert!(
            ep.webhook_secret.is_none(),
            "non-telegram provider must not auto-gen webhook_secret"
        );
    }

    #[test]
    fn idempotent_add_preserves_original_webhook_secret() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let first = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k-replay")),
        )
        .unwrap();
        let id = endpoint_id_from(&first);
        let secret_1 = load_raw_endpoint(&store, &id)
            .webhook_secret
            .expect("first call must generate a secret");
        // Replay with same idem key.
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k-replay")),
        )
        .unwrap();
        let secret_2 = load_raw_endpoint(&store, &id)
            .webhook_secret
            .expect("replay must preserve the secret");
        assert_eq!(
            secret_1, secret_2,
            "idempotent replay must return the SAME secret, not regenerate"
        );
    }

    #[test]
    fn generated_secret_passes_deploy_spec_validate() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&outcome);
        let ep = load_raw_endpoint(&store, &id);
        ep.validate()
            .expect("endpoint with auto-gen secret must pass deploy-spec validate");
    }

    fn rotate_payload(endpoint_id: &str, key: &str) -> EndpointRotateWebhookSecretPayload {
        EndpointRotateWebhookSecretPayload {
            environment_id: "local".to_string(),
            endpoint_id: endpoint_id.to_string(),
            idempotency_key: key.to_string(),
            updated_by: "tester".to_string(),
        }
    }

    #[test]
    fn rotate_webhook_secret_changes_secret_and_bumps_generation() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let before = load_raw_endpoint(&store, &id);
        let before_secret = before.webhook_secret.clone().expect("has secret");
        let before_gen = before.generation;
        rotate_webhook_secret(
            &store,
            &OpFlags::default(),
            Some(rotate_payload(&id.to_string(), "k-rotate")),
        )
        .unwrap();
        let after = load_raw_endpoint(&store, &id);
        let after_secret = after.webhook_secret.expect("rotated secret must be Some");
        assert_ne!(
            before_secret, after_secret,
            "rotate must produce a different secret"
        );
        assert!(after_secret.len() >= 32, "rotated secret must be ≥32 chars");
        assert_eq!(
            after.generation,
            before_gen + 1,
            "rotate must bump generation"
        );
    }

    #[test]
    fn idempotent_rotate_returns_same_secret() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        rotate_webhook_secret(
            &store,
            &OpFlags::default(),
            Some(rotate_payload(&id.to_string(), "k-rotate")),
        )
        .unwrap();
        let secret_1 = load_raw_endpoint(&store, &id)
            .webhook_secret
            .expect("has secret");
        let gen_1 = load_raw_endpoint(&store, &id).generation;
        // Replay with same idem key.
        rotate_webhook_secret(
            &store,
            &OpFlags::default(),
            Some(rotate_payload(&id.to_string(), "k-rotate")),
        )
        .unwrap();
        let secret_2 = load_raw_endpoint(&store, &id)
            .webhook_secret
            .expect("has secret");
        let gen_2 = load_raw_endpoint(&store, &id).generation;
        assert_eq!(
            secret_1, secret_2,
            "idempotent rotate replay must preserve the secret"
        );
        assert_eq!(gen_1, gen_2, "idempotent replay must not bump generation");
    }
}
