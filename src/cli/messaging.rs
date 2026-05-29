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
    audit_and_record(store, ctx, |_committed| {
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
                .find(|e| carries_idem_key(e, &idempotency_key))
            {
                if prev.provider_type == provider_type && prev.provider_id == provider_id {
                    return Ok(EndpointSummary::from(&env_id, prev));
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
            let endpoint = MessagingEndpoint {
                schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
                env_id: env_id.clone(),
                endpoint_id: MessagingEndpointId::new(),
                provider_id: provider_id.clone(),
                provider_type: provider_type.clone(),
                display_name: display_name.clone(),
                secret_refs: secret_refs.clone(),
                linked_bundles: Vec::new(),
                welcome_flow: None,
                generation: 0,
                created_at: now,
                updated_at: now,
                updated_by: format_idem_writer(&updated_by, &idempotency_key),
            };
            env.messaging_endpoints.push(endpoint);
            locked.save(&env)?;
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
    audit_and_record(store, ctx, |_committed| {
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
                return Ok(EndpointSummary::from(
                    &env_id,
                    &env.messaging_endpoints[idx],
                ));
            }
            env.messaging_endpoints[idx].linked_bundles.push(bundle_id);
            stamp_mutation(
                &mut env.messaging_endpoints[idx],
                &updated_by,
                &idempotency_key,
            );
            locked.save(&env)?;
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
    audit_and_record(store, ctx, |_committed| {
        let summary = store.transact(&env_id, |locked| -> Result<EndpointSummary, OpError> {
            let mut env = locked.load()?;
            let idx = find_endpoint_idx(&env, endpoint_id, &env_id)?;
            let bundle_idx = env.messaging_endpoints[idx]
                .linked_bundles
                .iter()
                .position(|b| b == &bundle_id);
            let Some(bidx) = bundle_idx else {
                // Idempotent: unlinking a bundle that isn't linked is a no-op.
                return Ok(EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]));
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
    audit_and_record(store, ctx, |_committed| {
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
            let new_welcome = WelcomeFlowRef {
                bundle_id: bundle_id.clone(),
                pack_id: PackId::new(pack_id.clone()),
                flow_id: flow_id.clone(),
            };
            if env.messaging_endpoints[idx].welcome_flow.as_ref() == Some(&new_welcome) {
                // Idempotent replay.
                return Ok(EndpointSummary::from(&env_id, &env.messaging_endpoints[idx]));
            }
            env.messaging_endpoints[idx].welcome_flow = Some(new_welcome);
            stamp_mutation(&mut env.messaging_endpoints[idx], &updated_by, &idempotency_key);
            locked.save(&env)?;
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
    let updated_by = require_nonempty("updated_by", &payload.updated_by)?;
    let idempotency_key = require_nonempty("idempotency_key", &payload.idempotency_key)?;
    let _ = (updated_by, idempotency_key);
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"endpoint_id": endpoint_id.to_string()}),
        idempotency_key: Some(payload.idempotency_key.clone()),
    };
    audit_and_record(store, ctx, |_committed| {
        let removed_id =
            store.transact(&env_id, |locked| -> Result<MessagingEndpointId, OpError> {
                let mut env = locked.load()?;
                let idx = env
                    .messaging_endpoints
                    .iter()
                    .position(|e| e.endpoint_id == endpoint_id);
                let Some(idx) = idx else {
                    // Idempotent: removing an absent endpoint succeeds.
                    return Ok(endpoint_id);
                };
                env.messaging_endpoints.remove(idx);
                locked.save(&env)?;
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

fn carries_idem_key(endpoint: &MessagingEndpoint, idempotency_key: &str) -> bool {
    endpoint
        .updated_by
        .ends_with(&format!("#idem={idempotency_key}"))
}

fn stamp_mutation(endpoint: &mut MessagingEndpoint, updated_by: &str, idempotency_key: &str) {
    endpoint.generation = endpoint.generation.saturating_add(1);
    endpoint.updated_at = Utc::now();
    endpoint.updated_by = format_idem_writer(updated_by, idempotency_key);
}

// --- schema stubs ------------------------------------------------------------
//
// JSON Schema generation for the payload types is left out of M1.2 — the
// schemars wiring in `crates/greentic-deploy-spec/src/json_schema.rs` is a
// reserved stub for the whole crate, and adding hand-written schemas here
// would drift from the rest of the cli/ modules. Stubs return a hint string
// today; the wiring lands when the workspace schemars pass does.

fn add_schema() -> Value {
    json!({
        "noun": NOUN,
        "verb": "add",
        "fields": [
            "environment_id", "provider_id", "provider_type", "display_name",
            "secret_refs (array of secret:// URIs)", "idempotency_key", "updated_by"
        ]
    })
}

fn link_bundle_schema() -> Value {
    json!({
        "noun": NOUN,
        "verb": "link-bundle / unlink-bundle",
        "fields": ["environment_id", "endpoint_id", "bundle_id", "idempotency_key", "updated_by"]
    })
}

fn set_welcome_flow_schema() -> Value {
    json!({
        "noun": NOUN,
        "verb": "set-welcome-flow",
        "fields": [
            "environment_id", "endpoint_id", "bundle_id", "pack_id", "flow_id",
            "idempotency_key", "updated_by"
        ]
    })
}

fn remove_schema() -> Value {
    json!({
        "noun": NOUN,
        "verb": "remove",
        "fields": ["environment_id", "endpoint_id", "idempotency_key", "updated_by"]
    })
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
}
