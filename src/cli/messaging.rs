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

use greentic_deploy_spec::{
    BundleId, EnvId, MessagingEndpoint, MessagingEndpointId, PackId, SecretRef,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str::FromStr;

use crate::environment::{
    AddMessagingEndpointPayload, EnvironmentReads, LocalFsStore, SetMessagingWelcomeFlowPayload,
};

use super::dispatch::{
    MessagingEndpointAddArgs, MessagingEndpointLinkBundleArgs, MessagingEndpointRemoveArgs,
    MessagingEndpointSetWelcomeFlowArgs,
};
use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
    resolve_idempotency_key,
};
use std::path::PathBuf;

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
    /// Optional caller-supplied per-endpoint webhook secret ref. Only valid
    /// for telegram-class providers. Required when adding such an endpoint
    /// against a remote `--store-url` store (which never mints secrets); on
    /// the local store it is optional (absent → the dev-store sink auto-mints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret_ref: Option<String>,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointLinkBundlePayload {
    pub environment_id: String,
    pub endpoint_id: String,
    pub bundle_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSetWelcomeFlowPayload {
    pub environment_id: String,
    pub endpoint_id: String,
    pub bundle_id: String,
    pub pack_id: String,
    pub flow_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRotateWebhookSecretPayload {
    pub environment_id: String,
    pub endpoint_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub updated_by: String,
    /// Optional NEW webhook secret ref (raw `secret://` URI) for the
    /// new-ref rotation variant on a remote `--store-url` store: the operator
    /// provisions the value in its own secrets plane and passes its ref here,
    /// so the control-plane store records it without ever minting or custodying
    /// secret material. Supplied via `--answers` only (the inline-flag form
    /// carries no ref). Honored ONLY by the remote dispatch — the local store
    /// mints its own value and REJECTS a supplied ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRemovePayload {
    pub environment_id: String,
    pub endpoint_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, the verb mints one per invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub updated_by: String,
}

// --- inline-flag → payload conversions ---------------------------------------
//
// Each verb's args struct yields:
//   `Ok(None)`                — no inline flag was supplied → defer to `--answers`
//   `Ok(Some(payload))`       — every required field present → use inline payload
//   `Err(InvalidArgument(…))` — SOME flags supplied but required ones missing,
//                                OR inline flags were combined with `--answers`,
//                                which is always misuse
//
// This prevents a destructive-misdirection footgun where partial inline flags
// silently fall through to `--answers`, loading a stale JSON that targets a
// different resource.
//
// The mutual-exclusion check lives inside each converter (not at dispatch) so
// every call-site gets it automatically — adding a new verb cannot forget the
// guard.

/// Reject `--answers` when any inline flag is set. Combining them is always a
/// misuse: inline-only is fine, `--answers` only is fine; the mixed form would
/// silently honor one and drop the other.
fn reject_inline_plus_answers(
    has_inline: bool,
    flags: &OpFlags,
    verb: &'static str,
) -> Result<(), OpError> {
    if has_inline && flags.answers.is_some() {
        return Err(OpError::InvalidArgument(format!(
            "messaging.endpoint {verb}: inline flags and --answers are mutually exclusive; use one or the other"
        )));
    }
    Ok(())
}

/// Format a partial-flags rejection: which verb, the full required-flag list,
/// and the subset that was actually missing.
fn partial_inline_error(verb: &'static str, required: &str, missing: &[&str]) -> OpError {
    OpError::InvalidArgument(format!(
        "messaging.endpoint {verb}: inline-flag form requires {required}; missing: {}",
        missing.join(", ")
    ))
}

impl MessagingEndpointAddArgs {
    /// Returns `true` when the caller supplied at least one inline flag.
    fn has_inline_input(&self) -> bool {
        self.env.is_some()
            || self.provider_type.is_some()
            || self.provider_id.is_some()
            || self.display_name.is_some()
            || !self.secret_ref.is_empty()
            || self.webhook_secret_ref.is_some()
            || self.idempotency_key.is_some()
            || self.updated_by.is_some()
    }

    pub fn into_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EndpointAddPayload>, OpError> {
        let has_inline = self.has_inline_input();
        reject_inline_plus_answers(has_inline, flags, verb)?;
        if !has_inline {
            return Ok(None);
        }
        let mut missing = Vec::new();
        if self.env.is_none() {
            missing.push("--env");
        }
        if self.provider_type.is_none() {
            missing.push("--provider-type");
        }
        if self.provider_id.is_none() {
            missing.push("--provider-id");
        }
        if self.display_name.is_none() {
            missing.push("--display-name");
        }
        if self.idempotency_key.is_none() {
            missing.push("--idempotency-key");
        }
        if self.updated_by.is_none() {
            missing.push("--updated-by");
        }
        if !missing.is_empty() {
            return Err(partial_inline_error(
                verb,
                "--env, --provider-type, --provider-id, --display-name, --idempotency-key, --updated-by",
                &missing,
            ));
        }
        Ok(Some(EndpointAddPayload {
            environment_id: self.env.unwrap(),
            provider_id: self.provider_id.unwrap(),
            provider_type: self.provider_type.unwrap(),
            display_name: self.display_name.unwrap(),
            secret_refs: self.secret_ref,
            webhook_secret_ref: self.webhook_secret_ref,
            idempotency_key: self.idempotency_key,
            updated_by: self.updated_by.unwrap(),
        }))
    }
}

impl MessagingEndpointLinkBundleArgs {
    /// Returns `true` when the caller supplied at least one inline flag.
    fn has_inline_input(&self) -> bool {
        self.env.is_some()
            || self.endpoint_id.is_some()
            || self.bundle_id.is_some()
            || self.idempotency_key.is_some()
            || self.updated_by.is_some()
    }

    pub fn into_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EndpointLinkBundlePayload>, OpError> {
        let has_inline = self.has_inline_input();
        reject_inline_plus_answers(has_inline, flags, verb)?;
        if !has_inline {
            return Ok(None);
        }
        let mut missing = Vec::new();
        if self.env.is_none() {
            missing.push("--env");
        }
        if self.endpoint_id.is_none() {
            missing.push("--endpoint-id");
        }
        if self.bundle_id.is_none() {
            missing.push("--bundle-id");
        }
        if self.idempotency_key.is_none() {
            missing.push("--idempotency-key");
        }
        if self.updated_by.is_none() {
            missing.push("--updated-by");
        }
        if !missing.is_empty() {
            return Err(partial_inline_error(
                verb,
                "--env, --endpoint-id, --bundle-id, --idempotency-key, --updated-by",
                &missing,
            ));
        }
        Ok(Some(EndpointLinkBundlePayload {
            environment_id: self.env.unwrap(),
            endpoint_id: self.endpoint_id.unwrap(),
            bundle_id: self.bundle_id.unwrap(),
            idempotency_key: self.idempotency_key,
            updated_by: self.updated_by.unwrap(),
        }))
    }
}

impl MessagingEndpointSetWelcomeFlowArgs {
    /// Returns `true` when the caller supplied at least one inline flag.
    fn has_inline_input(&self) -> bool {
        self.env.is_some()
            || self.endpoint_id.is_some()
            || self.bundle_id.is_some()
            || self.pack_id.is_some()
            || self.flow_id.is_some()
            || self.idempotency_key.is_some()
            || self.updated_by.is_some()
    }

    pub fn into_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EndpointSetWelcomeFlowPayload>, OpError> {
        let has_inline = self.has_inline_input();
        reject_inline_plus_answers(has_inline, flags, verb)?;
        if !has_inline {
            return Ok(None);
        }
        let mut missing = Vec::new();
        if self.env.is_none() {
            missing.push("--env");
        }
        if self.endpoint_id.is_none() {
            missing.push("--endpoint-id");
        }
        if self.bundle_id.is_none() {
            missing.push("--bundle-id");
        }
        if self.pack_id.is_none() {
            missing.push("--pack-id");
        }
        if self.flow_id.is_none() {
            missing.push("--flow-id");
        }
        if self.idempotency_key.is_none() {
            missing.push("--idempotency-key");
        }
        if self.updated_by.is_none() {
            missing.push("--updated-by");
        }
        if !missing.is_empty() {
            return Err(partial_inline_error(
                verb,
                "--env, --endpoint-id, --bundle-id, --pack-id, --flow-id, --idempotency-key, --updated-by",
                &missing,
            ));
        }
        Ok(Some(EndpointSetWelcomeFlowPayload {
            environment_id: self.env.unwrap(),
            endpoint_id: self.endpoint_id.unwrap(),
            bundle_id: self.bundle_id.unwrap(),
            pack_id: self.pack_id.unwrap(),
            flow_id: self.flow_id.unwrap(),
            idempotency_key: self.idempotency_key,
            updated_by: self.updated_by.unwrap(),
        }))
    }
}

/// Validated 4-tuple shared by `remove` and `rotate-webhook-secret`: both verbs
/// take the same args struct and consume the same field set.
/// The third element is an optional idempotency key (minted by the CLI verb
/// when absent).
type ValidatedRemoveFields = (String, String, Option<String>, String);

impl MessagingEndpointRemoveArgs {
    /// Returns `true` when the caller supplied at least one inline flag.
    fn has_inline_input(&self) -> bool {
        self.env.is_some()
            || self.endpoint_id.is_some()
            || self.idempotency_key.is_some()
            || self.updated_by.is_some()
    }

    /// Single validation pass shared by `remove` and `rotate-webhook-secret`.
    /// Returns the four fields in canonical order; both verbs then assemble
    /// their own payload type from this tuple.
    fn validated_fields(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<ValidatedRemoveFields>, OpError> {
        let has_inline = self.has_inline_input();
        reject_inline_plus_answers(has_inline, flags, verb)?;
        if !has_inline {
            return Ok(None);
        }
        let mut missing = Vec::new();
        if self.env.is_none() {
            missing.push("--env");
        }
        if self.endpoint_id.is_none() {
            missing.push("--endpoint-id");
        }
        if self.idempotency_key.is_none() {
            missing.push("--idempotency-key");
        }
        if self.updated_by.is_none() {
            missing.push("--updated-by");
        }
        if !missing.is_empty() {
            return Err(partial_inline_error(
                verb,
                "--env, --endpoint-id, --idempotency-key, --updated-by",
                &missing,
            ));
        }
        Ok(Some((
            self.env.unwrap(),
            self.endpoint_id.unwrap(),
            self.idempotency_key,
            self.updated_by.unwrap(),
        )))
    }

    pub fn into_remove_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EndpointRemovePayload>, OpError> {
        Ok(self
            .validated_fields(verb, flags)?
            .map(|(env, eid, ikey, by)| EndpointRemovePayload {
                environment_id: env,
                endpoint_id: eid,
                idempotency_key: ikey,
                updated_by: by,
            }))
    }

    pub fn into_rotate_payload(
        self,
        verb: &'static str,
        flags: &OpFlags,
    ) -> Result<Option<EndpointRotateWebhookSecretPayload>, OpError> {
        Ok(self
            .validated_fields(verb, flags)?
            .map(|(env, eid, ikey, by)| EndpointRotateWebhookSecretPayload {
                environment_id: env,
                endpoint_id: eid,
                idempotency_key: ikey,
                updated_by: by,
                // The inline-flag form carries no new ref; the new-ref variant
                // is supplied via `--answers` (a remote-only enhancement).
                webhook_secret_ref: None,
            }))
    }
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
    pub(crate) fn from(env_id: &EnvId, ep: &MessagingEndpoint) -> Self {
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
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({
            "provider_id": provider_id,
            "provider_type": provider_type,
        }),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let ep = store
            .add_messaging_endpoint(
                &env_id,
                AddMessagingEndpointPayload {
                    provider_id,
                    provider_type,
                    display_name,
                    secret_refs: payload.secret_refs,
                    webhook_secret_ref: payload.webhook_secret_ref,
                    updated_by,
                },
                idempotency_key,
            )
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        committed.mark_committed();
        let summary = EndpointSummary::from(&env_id, &ep);
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

pub fn list(
    store: &dyn EnvironmentReads,
    flags: &OpFlags,
    env_id: &str,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "list",
            json!({"input_schema": "env_id positional"}),
        ));
    }
    let env_id = parse_env_id(env_id)?;
    if !store.env_exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load_env(&env_id)?;
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
    store: &dyn EnvironmentReads,
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
    if !store.env_exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load_env(&env_id)?;
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
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "link-bundle",
        target: json!({
            "endpoint_id": endpoint_id.to_string(),
            "bundle_id": bundle_id.as_str(),
        }),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let ep = store
            .link_messaging_bundle(&env_id, endpoint_id, bundle_id, updated_by, idempotency_key)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        committed.mark_committed();
        let summary = EndpointSummary::from(&env_id, &ep);
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
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "unlink-bundle",
        target: json!({
            "endpoint_id": endpoint_id.to_string(),
            "bundle_id": bundle_id.as_str(),
        }),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let ep = store
            .unlink_messaging_bundle(&env_id, endpoint_id, bundle_id, updated_by, idempotency_key)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        committed.mark_committed();
        let summary = EndpointSummary::from(&env_id, &ep);
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
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
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
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let ep = store
            .set_messaging_welcome_flow(
                &env_id,
                SetMessagingWelcomeFlowPayload {
                    endpoint_id,
                    bundle_id,
                    pack_id: PackId::new(pack_id),
                    flow_id,
                    updated_by,
                },
                idempotency_key,
            )
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        committed.mark_committed();
        let summary = EndpointSummary::from(&env_id, &ep);
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
    require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"endpoint_id": endpoint_id.to_string()}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let removed_id = store
            .remove_messaging_endpoint(&env_id, endpoint_id)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        committed.mark_committed();
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
    // The new-ref variant is a remote-store-only enhancement: the local store
    // custodies the value and mints its own ref, so a caller-supplied ref has
    // no honest meaning here. Reject it rather than silently ignore it.
    if payload.webhook_secret_ref.is_some() {
        return Err(OpError::InvalidArgument(
            "webhook_secret_ref is only honored by a remote `--store-url` store; the local \
             store mints its own webhook secret value and ref"
                .to_string(),
        ));
    }
    let env_id = parse_env_id(&payload.environment_id)?;
    let endpoint_id = parse_endpoint_id(&payload.endpoint_id)?;
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "rotate-webhook-secret",
        target: json!({"endpoint_id": endpoint_id.to_string()}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |committed| {
        let ep = store
            .rotate_messaging_webhook_secret(&env_id, endpoint_id, updated_by, idempotency_key)
            .inspect_err(|err| {
                if err.is_committed_after_save() {
                    committed.mark_committed();
                }
            })
            .map_err(map_store_err_preserving_noun)?;
        committed.mark_committed();
        let summary = EndpointSummary::from(&env_id, &ep);
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

fn require_nonempty(field: &str, value: &str) -> Result<String, OpError> {
    if value.trim().is_empty() {
        return Err(OpError::InvalidArgument(format!(
            "{field} must not be empty"
        )));
    }
    Ok(value.to_string())
}

// The idem-writer stamp helpers (`format_idem_writer`, `idem_suffix`,
// `carries_idem_key`, `stamp_mutation`) and the telegram-class classifier
// moved to `greentic_deploy_spec::engine::messaging` (PR-4.2h) so the
// operator-store-server applies identical replay/stamping semantics. What
// stays here is the LocalFS webhook-secret SINK: CSPRNG value generation +
// the dev-store write below.

/// The generation policy for a per-endpoint webhook secret: 32 `raw_text`
/// characters. Routed through the shared `greentic-secrets` generator so the
/// deployer mints webhook material the same way every other consumer mints a
/// pack-declared generated secret (instead of a local ad-hoc CSPRNG).
fn webhook_secret_policy() -> greentic_secrets_lib::GeneratedSecretRequirement {
    greentic_secrets_lib::GeneratedSecretRequirement {
        policy: "random".to_string(),
        length: 32,
        encoding: "raw_text".to_string(),
        scope: greentic_secrets_lib::GeneratedSecretScope {
            level: "tenant".to_string(),
            team: Some("_".to_string()),
        },
        regenerate_if_present: false,
    }
}

/// Mint a fresh per-endpoint webhook secret via the shared generator.
fn generate_webhook_secret() -> Result<String, OpError> {
    let (bytes, _) = greentic_secrets_lib::generate_secret_value(&webhook_secret_policy())
        .map_err(|e| OpError::InvalidArgument(format!("webhook secret generation: {e}")))?;
    String::from_utf8(bytes)
        .map_err(|e| OpError::InvalidArgument(format!("webhook secret encoding: {e}")))
}

/// Construct the deterministic `SecretRef` URI for an endpoint's webhook
/// secret. The dev-store backend requires the 5-segment shape
/// `secrets://<env>/<tenant>/<team>/<pack>/<name>`, so the SecretRef mirrors
/// that: `secret://<env>/<tenant>/_/messaging-<eid>/webhook_secret`.
///
/// `tenant` is the env's owning tenant (`tenant_org_id`), or `default` for an
/// ownerless local env. It MUST match the tenant the runtime secrets backend
/// is scoped to: a Vault-backed worker pod scopes its `SecretsCore` to the env
/// owner, so a hardcoded `default` segment on an owned env would be refused
/// in-process and the webhook would never resolve. `_` is the tenant-level
/// team placeholder (the runtime's `canonical_team` maps `default` → `_`). The
/// endpoint id is folded to lowercase in the pack segment because
/// `MessagingEndpointId` is a ULID (uppercase) and the runtime canonicalizes
/// pack segments.
fn build_webhook_secret_ref(
    env_id: &EnvId,
    endpoint_id: &MessagingEndpointId,
    tenant: &str,
) -> Result<SecretRef, OpError> {
    let eid_lower = endpoint_id.to_string().to_lowercase();
    let uri = format!(
        "secret://{}/{}/_/messaging-{}/webhook_secret",
        env_id.as_str(),
        tenant,
        eid_lower
    );
    SecretRef::try_new(uri)
        .map_err(|e| OpError::InvalidArgument(format!("webhook secret ref: {e}")))
}

/// Provision a webhook secret for an endpoint: choose the ref URI (existing if
/// rotating an endpoint that already has one; freshly built under the resolved
/// tenant otherwise) and, when the env's secrets backend custodies values in the
/// local dev-store (`custodial`), mint a fresh value and write it there. For a
/// non-custodial backend (e.g. Vault) the value is seeded out-of-band by the
/// operator — the control plane only stamps the ref and never writes a value the
/// runtime would not read. Returns the ref the caller stamps onto
/// `MessagingEndpoint.webhook_secret_ref`.
///
/// `owner` is the env's owning tenant. The dev-store is not tenant-scoped, so a
/// custodial env with no owner keeps the conventional `default` segment. A
/// non-custodial backend scopes reads to the env owner, so a `default`/blank
/// segment would be unresolvable at runtime — require a real owner and fail
/// closed rather than stamp a dead ref.
///
/// Shared by `add` (always `existing_ref = None` — fresh endpoint) and
/// `rotate_webhook_secret` (`existing_ref = Some(_)` for endpoints that
/// already carry a ref, `None` for first-time setting on a pre-decoupling
/// endpoint). Keeps the entropy source, URI shape, and write target in one
/// place so the two verbs cannot drift.
pub(crate) fn provision_webhook_secret(
    store: &LocalFsStore,
    env_id: &EnvId,
    endpoint_id: &MessagingEndpointId,
    owner: Option<&str>,
    custodial: bool,
    existing_ref: Option<&SecretRef>,
) -> Result<SecretRef, OpError> {
    // The tenant segment is the env owner when present. When it is absent, the
    // dev-store (not tenant-scoped) falls back to the conventional `default`,
    // while a non-custodial backend (tenant-scoped) fails closed rather than
    // stamp an unresolvable ref.
    let tenant = match owner {
        Some(owner) => owner,
        None if custodial => "default",
        None => {
            return Err(OpError::Conflict(format!(
                "a webhook secret on a non-dev-store secrets backend requires the environment to \
                 declare an owning tenant (`tenant_org_id`); env `{}` has none",
                env_id.as_str()
            )));
        }
    };
    let secret_ref = match existing_ref {
        Some(r) => r.clone(),
        None => build_webhook_secret_ref(env_id, endpoint_id, tenant)?,
    };
    if custodial {
        let value = generate_webhook_secret()?;
        write_webhook_secret_to_devstore(store, env_id, &secret_ref, &value)?;
    }
    Ok(secret_ref)
}

/// Write the webhook secret VALUE into the env-pack dev-store. Mirrors the
/// `cli/secrets.rs put` idiom: same `dev_store_put` + `resolve_dev_store_path`
/// pattern (sidecar flock, dedicated OS thread, own current-thread runtime).
///
/// `secret_ref` can be caller-supplied (an endpoint may carry its own webhook
/// ref, reused verbatim across rotations), so the reserved control-plane
/// namespace is enforced here: without it, an endpoint added with a ref pointing
/// at the deployer's own credential path would, on rotation, overwrite the env's
/// bound deployer credential with a webhook secret.
fn write_webhook_secret_to_devstore(
    store: &LocalFsStore,
    env_id: &EnvId,
    secret_ref: &SecretRef,
    value: &str,
) -> Result<(), OpError> {
    let env_dir = store.env_dir(env_id)?;
    let dev_path = super::secrets::resolve_dev_store_path(
        &env_dir,
        std::env::var_os(super::secrets::DEV_SECRETS_PATH_ENV).map(PathBuf::from),
    );
    let store_uri = super::secrets::secret_ref_to_store_uri(secret_ref)?;
    if let Some(rel) = super::secrets::store_uri_rel_path(&store_uri) {
        super::secrets::reject_reserved_credential_rel_path(rel)?;
    }
    super::secrets::dev_store_put(&dev_path, &store_uri, value)
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
            "webhook_secret_ref (optional; telegram-class only; required on a remote --store-url store)",
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
    use crate::environment::EnvironmentStore;
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
            webhook_secret_ref: None,
            idempotency_key: Some(key.to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k3".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k3".to_string()),
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
                idempotency_key: Some("k4".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k3".to_string()),
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
                idempotency_key: Some("k4".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k1".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k3".to_string()),
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
                idempotency_key: Some("k4".to_string()),
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
                idempotency_key: Some("k2".to_string()),
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
                idempotency_key: Some("k3".to_string()),
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
            webhook_secret_ref: None,
            idempotency_key: Some("k1".to_string()),
            updated_by: "tester".to_string(),
        };
        let err = add(&store, &OpFlags::default(), Some(bad)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    // --- webhook_secret_ref auto-gen + rotate tests -----------------------------

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

    /// Read back a secret value from the env's dev-store. Mirrors
    /// `cli/secrets.rs::read_back` — sync tests build a fresh
    /// current-thread runtime, no `std::thread::scope` needed (there is no
    /// outer runtime to nest under).
    fn read_devstore_value(store: &LocalFsStore, secret_ref: &SecretRef) -> String {
        use greentic_secrets_lib::{DevStore, SecretsStore};
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        let dev_path = crate::cli::secrets::resolve_dev_store_path(
            &env_dir,
            std::env::var_os(crate::cli::secrets::DEV_SECRETS_PATH_ENV).map(PathBuf::from),
        );
        let store_uri =
            crate::cli::secrets::secret_ref_to_store_uri(secret_ref).expect("store-aligned ref");
        let dev = DevStore::with_path(dev_path).expect("open dev store");
        let bytes = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { dev.get(&store_uri).await.unwrap() });
        bytes.into_iter().map(|b| b as char).collect()
    }

    #[test]
    fn add_telegram_generates_webhook_secret_ref() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&outcome);
        let ep = load_raw_endpoint(&store, &id);
        let secret_ref = ep
            .webhook_secret_ref
            .as_ref()
            .expect("telegram must have webhook_secret_ref");
        let eid_lower = id.to_string().to_lowercase();
        let expected_uri = format!("secret://local/default/_/messaging-{eid_lower}/webhook_secret");
        assert_eq!(secret_ref.as_str(), expected_uri);
        // Verify the actual value was written to the dev-store.
        let value = read_devstore_value(&store, secret_ref);
        assert!(
            value.len() >= 32,
            "dev-store secret must be ≥32 chars, got {}",
            value.len()
        );
    }

    #[test]
    fn add_telegram_with_supplied_ref_stamps_it_and_skips_auto_mint() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let supplied = "secret://local/default/_/messaging-byo/webhook_secret";
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(EndpointAddPayload {
                webhook_secret_ref: Some(supplied.to_string()),
                ..add_payload("telegram", "legal-bot", "k1")
            }),
        )
        .unwrap();
        let id = endpoint_id_from(&outcome);
        let ep = load_raw_endpoint(&store, &id);
        // The supplied ref is stamped verbatim — NOT the eid-derived URI the
        // auto-mint path would build.
        assert_eq!(
            ep.webhook_secret_ref.as_ref().map(|r| r.as_str()),
            Some(supplied)
        );
    }

    #[test]
    fn add_telegram_dotted_generates_webhook_secret_ref() {
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
            ep.webhook_secret_ref.is_some(),
            "messaging.telegram.bot must auto-gen webhook_secret_ref"
        );
    }

    #[test]
    fn add_non_telegram_has_no_webhook_secret_ref() {
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
            ep.webhook_secret_ref.is_none(),
            "non-telegram provider must not auto-gen webhook_secret_ref"
        );
    }

    #[test]
    fn idempotent_add_preserves_original_webhook_secret_ref() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let first = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k-replay")),
        )
        .unwrap();
        let id = endpoint_id_from(&first);
        let ref_1 = load_raw_endpoint(&store, &id)
            .webhook_secret_ref
            .expect("first call must generate a ref");
        let value_1 = read_devstore_value(&store, &ref_1);
        // Replay with same idem key — the idempotent path returns BEFORE
        // any DevStore write, so the URI and the stored value are unchanged.
        add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k-replay")),
        )
        .unwrap();
        let ref_2 = load_raw_endpoint(&store, &id)
            .webhook_secret_ref
            .expect("replay must preserve the ref");
        let value_2 = read_devstore_value(&store, &ref_2);
        assert_eq!(
            ref_1, ref_2,
            "idempotent replay must return the SAME SecretRef"
        );
        assert_eq!(
            value_1, value_2,
            "idempotent replay must not overwrite the dev-store value"
        );
    }

    #[test]
    fn webhook_secret_ref_passes_deploy_spec_validate() {
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
            .expect("endpoint with webhook_secret_ref must pass deploy-spec validate");
    }

    /// Like [`read_devstore_value`] but does not panic when the key is absent —
    /// used to assert that non-custodial provisioning writes NOTHING.
    fn devstore_has_value(store: &LocalFsStore, secret_ref: &SecretRef) -> bool {
        use greentic_secrets_lib::{DevStore, SecretsStore};
        let env_id = EnvId::try_from("local").unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        let dev_path = crate::cli::secrets::resolve_dev_store_path(
            &env_dir,
            std::env::var_os(crate::cli::secrets::DEV_SECRETS_PATH_ENV).map(PathBuf::from),
        );
        let store_uri =
            crate::cli::secrets::secret_ref_to_store_uri(secret_ref).expect("store-aligned ref");
        // The dev-store file only exists once something has written to it; a
        // non-custodial provision writes nothing, so an absent store == no value.
        let Ok(dev) = DevStore::with_path(dev_path) else {
            return false;
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async { dev.get(&store_uri).await.is_ok() })
    }

    #[test]
    fn build_webhook_secret_ref_uses_provided_tenant() {
        // The tenant segment is the env owner, not a hardcoded `default`, so the
        // ref resolves under a Vault-backed worker's tenant-scoped SecretsCore.
        let env_id = EnvId::try_from("vault-demo").unwrap();
        let eid = MessagingEndpointId::new();
        let eid_lower = eid.to_string().to_lowercase();
        let r = build_webhook_secret_ref(&env_id, &eid, "tenant-default").unwrap();
        assert_eq!(
            r.as_str(),
            format!("secret://vault-demo/tenant-default/_/messaging-{eid_lower}/webhook_secret")
        );
    }

    /// An endpoint carries its own webhook ref, reused verbatim on rotation. A
    /// ref aimed at the deployer's reserved credential path would therefore let
    /// a rotation overwrite the env's live bound deployer credential with a
    /// webhook secret — breaking every later deployer verb, and writing material
    /// that staging strips anyway. The write must fail closed, and must leave the
    /// existing credential byte-for-byte intact.
    #[test]
    fn provision_webhook_secret_refuses_to_clobber_a_reserved_credential_path() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let env_id = EnvId::try_from("local").unwrap();
        let eid = MessagingEndpointId::new();

        for path in crate::credentials::store_paths::BOUND_CREDENTIAL_STORE_PATHS {
            let reserved = SecretRef::try_new(format!("secret://local/{path}")).unwrap();

            // The env's real bound deployer credential lives here.
            let env_dir = store.env_dir(&env_id).unwrap();
            crate::cli::secrets::put_credential_material(&env_dir, &reserved, "REAL-DEPLOYER-CRED")
                .unwrap();

            let err = provision_webhook_secret(
                &store,
                &env_id,
                &eid,
                Some("default"),
                true,
                Some(&reserved),
            )
            .unwrap_err();
            assert!(
                matches!(&err, OpError::InvalidArgument(msg) if msg.contains("reserved")),
                "a webhook secret must not be writable at the reserved deployer \
                 credential path `{path}`; got {err:?}"
            );
            assert_eq!(
                read_devstore_value(&store, &reserved),
                "REAL-DEPLOYER-CRED",
                "the bound deployer credential at `{path}` must be untouched"
            );
        }
    }

    #[test]
    fn provision_webhook_secret_honors_tenant_and_custodial_gate() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let env_id = EnvId::try_from("local").unwrap();
        let eid = MessagingEndpointId::new();
        let eid_lower = eid.to_string().to_lowercase();

        // Non-custodial (e.g. Vault): builds the tenant-scoped ref but writes
        // NOTHING to the dev-store — the operator seeds the value out-of-band.
        let ref_vault =
            provision_webhook_secret(&store, &env_id, &eid, Some("tenant-default"), false, None)
                .unwrap();
        assert_eq!(
            ref_vault.as_str(),
            format!("secret://local/tenant-default/_/messaging-{eid_lower}/webhook_secret")
        );
        assert!(
            !devstore_has_value(&store, &ref_vault),
            "non-custodial provisioning must not write a dev-store value"
        );

        // Custodial (dev-store): the value is minted and written at the ref.
        // No owner → the conventional `default` tenant segment.
        let ref_dev = provision_webhook_secret(&store, &env_id, &eid, None, true, None).unwrap();
        assert_eq!(
            ref_dev.as_str(),
            format!("secret://local/default/_/messaging-{eid_lower}/webhook_secret")
        );
        assert!(
            devstore_has_value(&store, &ref_dev),
            "custodial provisioning must write the dev-store value"
        );
        assert!(
            read_devstore_value(&store, &ref_dev).len() >= 32,
            "custodial webhook secret must be ≥32 chars"
        );
    }

    #[test]
    fn provision_webhook_secret_fails_closed_on_non_custodial_without_owner() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let env_id = EnvId::try_from("local").unwrap();
        let eid = MessagingEndpointId::new();
        // A non-custodial backend (e.g. Vault) scopes reads to the env owner, so a
        // missing owner would mint an unresolvable `default` ref — fail closed.
        let err = provision_webhook_secret(&store, &env_id, &eid, None, false, None).unwrap_err();
        let OpError::Conflict(msg) = err else {
            panic!("expected OpError::Conflict");
        };
        assert!(msg.contains("owning tenant"), "got: {msg}");
    }

    fn rotate_payload(endpoint_id: &str, key: &str) -> EndpointRotateWebhookSecretPayload {
        EndpointRotateWebhookSecretPayload {
            environment_id: "local".to_string(),
            endpoint_id: endpoint_id.to_string(),
            idempotency_key: Some(key.to_string()),
            updated_by: "tester".to_string(),
            webhook_secret_ref: None,
        }
    }

    #[test]
    fn rotate_webhook_secret_changes_devstore_value_and_bumps_generation() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        let before = load_raw_endpoint(&store, &id);
        let before_ref = before.webhook_secret_ref.clone().expect("has ref");
        let before_value = read_devstore_value(&store, &before_ref);
        let before_gen = before.generation;
        rotate_webhook_secret(
            &store,
            &OpFlags::default(),
            Some(rotate_payload(&id.to_string(), "k-rotate")),
        )
        .unwrap();
        let after = load_raw_endpoint(&store, &id);
        let after_ref = after
            .webhook_secret_ref
            .as_ref()
            .expect("rotated endpoint must have ref");
        let after_value = read_devstore_value(&store, after_ref);
        assert_eq!(
            before_ref, *after_ref,
            "rotate must preserve the same URI ref"
        );
        assert_ne!(
            before_value, after_value,
            "rotate must produce a different dev-store value"
        );
        assert!(after_value.len() >= 32, "rotated secret must be ≥32 chars");
        assert_eq!(
            after.generation,
            before_gen + 1,
            "rotate must bump generation"
        );
    }

    #[test]
    fn local_rotate_rejects_supplied_webhook_ref() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let added = add(
            &store,
            &OpFlags::default(),
            Some(add_payload("telegram", "legal-bot", "k1")),
        )
        .unwrap();
        let id = endpoint_id_from(&added);
        // The new-ref variant is remote-store-only: the local store mints its
        // own value+ref, so a caller-supplied ref fails closed rather than
        // being silently ignored.
        let mut payload = rotate_payload(&id.to_string(), "k-rotate");
        payload.webhook_secret_ref =
            Some("secret://local/default/_/messaging-x/webhook_secret".to_string());
        let err = rotate_webhook_secret(&store, &OpFlags::default(), Some(payload)).unwrap_err();
        assert!(
            matches!(err, OpError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );
    }

    #[test]
    fn idempotent_rotate_preserves_devstore_value() {
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
        // One load per snapshot — `ref_N` and `gen_N` come from the SAME
        // snapshot so they can't theoretically diverge under concurrent writers.
        let snapshot_1 = load_raw_endpoint(&store, &id);
        let ref_1 = snapshot_1.webhook_secret_ref.clone().expect("has ref");
        let gen_1 = snapshot_1.generation;
        let value_1 = read_devstore_value(&store, &ref_1);
        // Replay with same idem key.
        rotate_webhook_secret(
            &store,
            &OpFlags::default(),
            Some(rotate_payload(&id.to_string(), "k-rotate")),
        )
        .unwrap();
        let snapshot_2 = load_raw_endpoint(&store, &id);
        let ref_2 = snapshot_2.webhook_secret_ref.clone().expect("has ref");
        let gen_2 = snapshot_2.generation;
        let value_2 = read_devstore_value(&store, &ref_2);
        assert_eq!(ref_1, ref_2, "idempotent replay must preserve the URI ref");
        assert_eq!(
            value_1, value_2,
            "idempotent rotate replay must preserve the dev-store value"
        );
        assert_eq!(gen_1, gen_2, "idempotent replay must not bump generation");
    }

    // ---- inline-flag → payload conversion ---------------------------------

    fn add_args_full() -> MessagingEndpointAddArgs {
        MessagingEndpointAddArgs {
            env: Some("local".into()),
            provider_type: Some("telegram".into()),
            provider_id: Some("legal-bot".into()),
            display_name: Some("Legal Bot".into()),
            secret_ref: vec![],
            webhook_secret_ref: None,
            idempotency_key: Some("k1".into()),
            updated_by: Some("alice".into()),
        }
    }

    #[test]
    fn add_args_with_all_flags_yields_payload() {
        let payload = add_args_full()
            .into_payload("add", &OpFlags::default())
            .expect("ok")
            .expect("some");
        assert_eq!(payload.environment_id, "local");
        assert_eq!(payload.provider_type, "telegram");
        assert_eq!(payload.provider_id, "legal-bot");
        assert_eq!(payload.display_name, "Legal Bot");
        assert_eq!(payload.idempotency_key, Some("k1".to_string()));
        assert_eq!(payload.updated_by, "alice");
        assert!(payload.secret_refs.is_empty());
    }

    #[test]
    fn add_args_propagates_secret_refs() {
        let mut args = add_args_full();
        args.secret_ref = vec![
            "secret://local/global/telegram/bot_token".into(),
            "secret://local/global/telegram/api_key".into(),
        ];
        let payload = args
            .into_payload("add", &OpFlags::default())
            .expect("ok")
            .expect("some");
        assert_eq!(payload.secret_refs.len(), 2);
        assert_eq!(
            payload.secret_refs[0],
            "secret://local/global/telegram/bot_token"
        );
    }

    #[test]
    fn add_args_missing_required_field_is_rejected() {
        let mut args = add_args_full();
        args.display_name = None;
        let err = args.into_payload("add", &OpFlags::default()).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--display-name"),
            "error must name the missing flag: {msg}"
        );
    }

    #[test]
    fn add_args_missing_idem_key_is_rejected() {
        let mut args = add_args_full();
        args.idempotency_key = None;
        let err = args.into_payload("add", &OpFlags::default()).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--idempotency-key"),
            "error must name the missing flag: {msg}"
        );
    }

    #[test]
    fn add_args_no_flags_returns_none() {
        let args = MessagingEndpointAddArgs {
            env: None,
            provider_type: None,
            provider_id: None,
            display_name: None,
            secret_ref: vec![],
            webhook_secret_ref: None,
            idempotency_key: None,
            updated_by: None,
        };
        assert!(
            args.into_payload("add", &OpFlags::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn link_bundle_args_with_all_flags_yields_payload() {
        let args = MessagingEndpointLinkBundleArgs {
            env: Some("local".into()),
            endpoint_id: Some("01HXYZ...".into()),
            bundle_id: Some("legal".into()),
            idempotency_key: Some("k-link".into()),
            updated_by: Some("alice".into()),
        };
        let payload = args
            .into_payload("link-bundle", &OpFlags::default())
            .expect("ok")
            .expect("some");
        assert_eq!(payload.environment_id, "local");
        assert_eq!(payload.endpoint_id, "01HXYZ...");
        assert_eq!(payload.bundle_id, "legal");
    }

    #[test]
    fn link_bundle_args_missing_bundle_is_rejected() {
        let args = MessagingEndpointLinkBundleArgs {
            env: Some("local".into()),
            endpoint_id: Some("01HXYZ".into()),
            bundle_id: None,
            idempotency_key: Some("k".into()),
            updated_by: Some("alice".into()),
        };
        let err = args
            .into_payload("link-bundle", &OpFlags::default())
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--bundle-id"),
            "error must name the missing flag: {msg}"
        );
    }

    #[test]
    fn link_bundle_args_no_flags_returns_none() {
        let args = MessagingEndpointLinkBundleArgs {
            env: None,
            endpoint_id: None,
            bundle_id: None,
            idempotency_key: None,
            updated_by: None,
        };
        assert!(
            args.into_payload("link-bundle", &OpFlags::default())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn set_welcome_flow_args_with_all_flags_yields_payload() {
        let args = MessagingEndpointSetWelcomeFlowArgs {
            env: Some("local".into()),
            endpoint_id: Some("01HXYZ".into()),
            bundle_id: Some("legal".into()),
            pack_id: Some("welcome".into()),
            flow_id: Some("hello".into()),
            idempotency_key: Some("k-set".into()),
            updated_by: Some("alice".into()),
        };
        let payload = args
            .into_payload("set-welcome-flow", &OpFlags::default())
            .expect("ok")
            .expect("some");
        assert_eq!(payload.pack_id, "welcome");
        assert_eq!(payload.flow_id, "hello");
    }

    #[test]
    fn set_welcome_flow_args_missing_flow_id_is_rejected() {
        let args = MessagingEndpointSetWelcomeFlowArgs {
            env: Some("local".into()),
            endpoint_id: Some("01HXYZ".into()),
            bundle_id: Some("legal".into()),
            pack_id: Some("welcome".into()),
            flow_id: None,
            idempotency_key: Some("k".into()),
            updated_by: Some("alice".into()),
        };
        let err = args
            .into_payload("set-welcome-flow", &OpFlags::default())
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--flow-id"),
            "error must name the missing flag: {msg}"
        );
    }

    #[test]
    fn set_welcome_flow_args_no_flags_returns_none() {
        let args = MessagingEndpointSetWelcomeFlowArgs {
            env: None,
            endpoint_id: None,
            bundle_id: None,
            pack_id: None,
            flow_id: None,
            idempotency_key: None,
            updated_by: None,
        };
        assert!(
            args.into_payload("set-welcome-flow", &OpFlags::default())
                .unwrap()
                .is_none()
        );
    }

    fn remove_args_full() -> MessagingEndpointRemoveArgs {
        MessagingEndpointRemoveArgs {
            env: Some("local".into()),
            endpoint_id: Some("01HXYZ".into()),
            idempotency_key: Some("k-rm".into()),
            updated_by: Some("alice".into()),
        }
    }

    #[test]
    fn remove_args_with_all_flags_yields_remove_payload() {
        let payload = remove_args_full()
            .into_remove_payload("remove", &OpFlags::default())
            .expect("ok")
            .expect("some");
        assert_eq!(payload.environment_id, "local");
        assert_eq!(payload.endpoint_id, "01HXYZ");
        assert_eq!(payload.idempotency_key, Some("k-rm".to_string()));
    }

    #[test]
    fn remove_args_with_all_flags_yields_rotate_payload() {
        let payload = remove_args_full()
            .into_rotate_payload("rotate-webhook-secret", &OpFlags::default())
            .expect("ok")
            .expect("some");
        assert_eq!(payload.environment_id, "local");
        assert_eq!(payload.endpoint_id, "01HXYZ");
    }

    #[test]
    fn remove_args_missing_endpoint_id_is_rejected() {
        let mut args = remove_args_full();
        args.endpoint_id = None;
        let err = args
            .into_remove_payload("remove", &OpFlags::default())
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--endpoint-id"),
            "error must name the missing flag: {msg}"
        );
        // The rotate path takes the same args struct — same rejection
        // semantics on the same field set.
        let mut args = remove_args_full();
        args.endpoint_id = None;
        let err = args
            .into_rotate_payload("rotate-webhook-secret", &OpFlags::default())
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn remove_args_no_flags_returns_none() {
        let args = MessagingEndpointRemoveArgs {
            env: None,
            endpoint_id: None,
            idempotency_key: None,
            updated_by: None,
        };
        assert!(
            args.into_remove_payload("remove", &OpFlags::default())
                .unwrap()
                .is_none()
        );
        let args = MessagingEndpointRemoveArgs {
            env: None,
            endpoint_id: None,
            idempotency_key: None,
            updated_by: None,
        };
        assert!(
            args.into_rotate_payload("rotate-webhook-secret", &OpFlags::default())
                .unwrap()
                .is_none()
        );
    }

    // --- partial inline flags: the destructive-misdirection footgun -----------
    //
    // Each verb must reject partial inline flags with a precise error listing
    // what's missing, rather than silently falling through to --answers.

    #[test]
    fn add_partial_flags_rejected_with_missing_list() {
        // Supply env + provider-type, omit the rest.
        let args = MessagingEndpointAddArgs {
            env: Some("prod".into()),
            provider_type: Some("telegram".into()),
            provider_id: None,
            display_name: None,
            secret_ref: vec![],
            webhook_secret_ref: None,
            idempotency_key: None,
            updated_by: None,
        };
        let err = args.into_payload("add", &OpFlags::default()).unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--provider-id"),
            "must list --provider-id: {msg}"
        );
        assert!(
            msg.contains("--display-name"),
            "must list --display-name: {msg}"
        );
        assert!(
            msg.contains("--idempotency-key"),
            "must list --idempotency-key: {msg}"
        );
        assert!(
            msg.contains("--updated-by"),
            "must list --updated-by: {msg}"
        );
    }

    #[test]
    fn link_bundle_partial_flags_rejected() {
        let args = MessagingEndpointLinkBundleArgs {
            env: Some("prod".into()),
            endpoint_id: Some("01HXYZ".into()),
            bundle_id: None,
            idempotency_key: None,
            updated_by: Some("alice".into()),
        };
        let err = args
            .into_payload("link-bundle", &OpFlags::default())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("--bundle-id"), "must list --bundle-id: {msg}");
        assert!(
            msg.contains("--idempotency-key"),
            "must list --idempotency-key: {msg}"
        );
    }

    #[test]
    fn unlink_bundle_partial_flags_rejected() {
        let args = MessagingEndpointLinkBundleArgs {
            env: Some("prod".into()),
            endpoint_id: None,
            bundle_id: Some("legal".into()),
            idempotency_key: Some("k".into()),
            updated_by: None,
        };
        let err = args
            .into_payload("unlink-bundle", &OpFlags::default())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--endpoint-id"),
            "must list --endpoint-id: {msg}"
        );
        assert!(
            msg.contains("--updated-by"),
            "must list --updated-by: {msg}"
        );
    }

    #[test]
    fn set_welcome_flow_partial_flags_rejected() {
        let args = MessagingEndpointSetWelcomeFlowArgs {
            env: Some("prod".into()),
            endpoint_id: Some("01HXYZ".into()),
            bundle_id: Some("legal".into()),
            pack_id: None,
            flow_id: None,
            idempotency_key: Some("k".into()),
            updated_by: Some("alice".into()),
        };
        let err = args
            .into_payload("set-welcome-flow", &OpFlags::default())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(msg.contains("--pack-id"), "must list --pack-id: {msg}");
        assert!(msg.contains("--flow-id"), "must list --flow-id: {msg}");
    }

    #[test]
    fn remove_partial_flags_rejected() {
        let args = MessagingEndpointRemoveArgs {
            env: Some("prod".into()),
            endpoint_id: Some("01HXYZ".into()),
            idempotency_key: None,
            updated_by: None,
        };
        let err = args
            .into_remove_payload("remove", &OpFlags::default())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--idempotency-key"),
            "must list --idempotency-key: {msg}"
        );
        assert!(
            msg.contains("--updated-by"),
            "must list --updated-by: {msg}"
        );
    }

    #[test]
    fn rotate_webhook_secret_partial_flags_rejected() {
        let args = MessagingEndpointRemoveArgs {
            env: Some("prod".into()),
            endpoint_id: None,
            idempotency_key: Some("k".into()),
            updated_by: Some("alice".into()),
        };
        let err = args
            .into_rotate_payload("rotate-webhook-secret", &OpFlags::default())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--endpoint-id"),
            "must list --endpoint-id: {msg}"
        );
    }

    // --- inline flags + --answers mutual exclusion ----------------------------

    fn flags_with_answers() -> OpFlags {
        OpFlags {
            schema_only: false,
            answers: Some(std::path::PathBuf::from("stale.json")),
        }
    }

    #[test]
    fn add_inline_plus_answers_is_rejected() {
        // Inline flags + --answers is always misuse: the converter rejects
        // before any payload work, so a destructive `remove` with both forms
        // can never proceed against a stale answers file.
        let err = remove_args_full()
            .into_remove_payload("remove", &flags_with_answers())
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("mutually exclusive"),
            "must mention mutual exclusion: {msg}"
        );
    }

    #[test]
    fn rotate_inline_plus_answers_is_rejected() {
        let err = remove_args_full()
            .into_rotate_payload("rotate-webhook-secret", &flags_with_answers())
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn add_args_inline_plus_answers_is_rejected() {
        let err = add_args_full()
            .into_payload("add", &flags_with_answers())
            .unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)));
    }

    #[test]
    fn no_inline_flags_plus_answers_is_ok() {
        // Pure --answers path (no inline flags) must NOT be rejected.
        let args = MessagingEndpointRemoveArgs {
            env: None,
            endpoint_id: None,
            idempotency_key: None,
            updated_by: None,
        };
        assert!(
            args.into_remove_payload("remove", &flags_with_answers())
                .unwrap()
                .is_none()
        );
    }

    // End-to-end: CLI-derived payload feeds the verb the same way `--answers`
    // does, and the resulting endpoint is materialized correctly.
    #[test]
    fn cli_derived_add_payload_drives_verb_e2e() {
        let (_dir, store, _) = seeded_store_with_bundles(&[]);
        let payload = MessagingEndpointAddArgs {
            env: Some("local".into()),
            provider_type: Some("teams".into()),
            provider_id: Some("cli-bot".into()),
            display_name: Some("CLI Bot".into()),
            secret_ref: vec![],
            webhook_secret_ref: None,
            idempotency_key: Some("cli-add-1".into()),
            updated_by: Some("cli".into()),
        }
        .into_payload("add", &OpFlags::default())
        .expect("ok")
        .expect("some");
        let outcome = add(&store, &OpFlags::default(), Some(payload)).unwrap();
        assert_eq!(outcome.result["provider_type"], "teams");
        assert_eq!(outcome.result["provider_id"], "cli-bot");
        assert_eq!(outcome.result["display_name"], "CLI Bot");
    }
}
