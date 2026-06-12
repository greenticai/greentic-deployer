//! `gtc op bundles {add,update,remove,list}` (`A3`).
//!
//! Manages `Environment.bundles: Vec<BundleDeployment>`. Each call records
//! the bundle deployment metadata only — actual staging of a `.gtbundle`
//! into a `Revision` happens via `op revisions stage`. The intentional
//! split: `bundles` owns rollout-unit metadata (`route_binding`,
//! `revenue_share`, `customer_id`); `revisions` owns the per-version
//! artifact pointers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
    RevenueShareEntry, RouteBinding, TenantSelector,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::mutations::UpdateBundlePayload as StoreUpdateBundlePayload;
use crate::environment::{
    AddBundlePayload as StoreAddBundlePayload, EnvironmentStore, LocalFsStore, RemoveBundleOutcome,
};

use super::{
    AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record, map_store_err_preserving_noun,
    resolve_idempotency_key,
};

const NOUN: &str = "bundles";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleAddPayload {
    pub environment_id: String,
    pub bundle_id: String,
    /// Billing principal (P6). Required for non-`local` envs; defaults to
    /// [`LOCAL_DEV_CUSTOMER_ID`] when omitted on the `local` env.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
    pub route_binding: RouteBindingPayload,
    #[serde(default = "default_revenue_share")]
    pub revenue_share: Vec<RevenueShareEntryPayload>,
    #[serde(default = "default_authorization_ref")]
    pub authorization_ref: PathBuf,
    /// D.4: per-pack provider config overrides applied at egress time.
    /// Outer key = `pack_id`, inner key = config key, value = JSON value.
    /// Structurally validated by `BundleDeployment::validate`; pack ids are
    /// cross-referenced against the deployment's revisions in
    /// `Environment::validate`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config_overrides: BTreeMap<String, BTreeMap<String, Value>>,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, `add` mints one per invocation. Operators
    /// wanting safe lost-response retries (HTTP backend, PR-3b) supply a
    /// stable key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// Default `customer_id` for the `local` env when none is supplied. Non-local
/// envs must pass one explicitly (B10).
const LOCAL_DEV_CUSTOMER_ID: &str = "local-dev";

pub(crate) fn default_revenue_share() -> Vec<RevenueShareEntryPayload> {
    vec![RevenueShareEntryPayload {
        party_id: "greentic".to_string(),
        basis_points: 10_000,
    }]
}
pub(crate) fn default_authorization_ref() -> PathBuf {
    PathBuf::from("auth.json")
}

/// Convert the CLI `RevenueShareEntryPayload` list into the spec
/// [`RevenueShareEntry`] list. Shared by the remote dispatch's `bundles
/// add`/`update` so the two HTTP call sites don't re-roll the mapping.
pub(crate) fn convert_revenue_share(
    entries: &[RevenueShareEntryPayload],
) -> Vec<RevenueShareEntry> {
    entries
        .iter()
        .cloned()
        .map(|e| RevenueShareEntry {
            party_id: greentic_deploy_spec::PartyId::new(e.party_id),
            basis_points: e.basis_points,
        })
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteBindingPayload {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub tenant_selector: Option<TenantSelectorPayload>,
}

impl RouteBindingPayload {
    /// A binding with `tenant_selector` set but no host/path matcher is
    /// structurally unreachable (no inbound request can match it). Reject at
    /// payload-construction time so the CLI flag path and the `--answers`
    /// JSON path share the same validation.
    pub fn validate(&self) -> Result<(), OpError> {
        if self.tenant_selector.is_some() && self.hosts.is_empty() && self.path_prefixes.is_empty()
        {
            return Err(OpError::InvalidArgument(
                "route_binding: tenant_selector requires at least one host or path_prefix \
                 (a binding with no matchers would be unreachable)"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSelectorPayload {
    pub tenant: String,
    pub team: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevenueShareEntryPayload {
    pub party_id: String,
    pub basis_points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSummary {
    pub environment_id: String,
    pub bundle_id: String,
    pub deployment_id: String,
    pub customer_id: String,
    pub status: BundleDeploymentStatus,
    pub current_revision_count: usize,
    pub hosts: Vec<String>,
}

impl BundleSummary {
    pub(crate) fn from(env_id: &EnvId, b: &BundleDeployment) -> Self {
        Self {
            environment_id: env_id.as_str().to_string(),
            bundle_id: b.bundle_id.as_str().to_string(),
            deployment_id: b.deployment_id.to_string(),
            customer_id: b.customer_id.as_str().to_string(),
            status: b.status,
            current_revision_count: b.current_revisions.len(),
            hosts: b.route_binding.hosts.clone(),
        }
    }
}

pub fn add(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<BundleAddPayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "add", add_schema()));
    }
    let payload = resolve_payload(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    if payload.bundle_id.trim().is_empty() {
        return Err(OpError::InvalidArgument(
            "bundle_id must not be empty".to_string(),
        ));
    }
    let bundle_id = BundleId::new(payload.bundle_id);
    // P6 (B10): customer_id is the billing principal. Required for non-local
    // envs; defaults to `local-dev` on `local`. Validated before authz so a
    // missing principal surfaces as a precise argument error.
    let customer_id = resolve_customer_id(&env_id, payload.customer_id.clone())?;
    let revenue_share: Vec<RevenueShareEntry> = payload
        .revenue_share
        .iter()
        .cloned()
        .map(|e| RevenueShareEntry {
            party_id: greentic_deploy_spec::PartyId::new(e.party_id),
            basis_points: e.basis_points,
        })
        .collect();
    let config_overrides = payload.config_overrides.clone();
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let route_binding_payload = payload.route_binding.clone();
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({
            "bundle_id": bundle_id.as_str(),
            "customer_id": customer_id.as_str(),
            "revenue_share": revenue_share_json(&revenue_share),
            "config_overrides": config_overrides_audit_shape(&config_overrides),
        }),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let deployment = store
            .add_bundle(
                &env_id,
                StoreAddBundlePayload {
                    bundle_id,
                    customer_id,
                    revenue_share,
                    route_binding: Some(into_route_binding(route_binding_payload)),
                    authorization_ref: Some(
                        payload.authorization_ref.to_string_lossy().into_owned(),
                    ),
                    config_overrides,
                },
                idempotency_key,
            )
            .map_err(map_store_err_preserving_noun)?;
        let summary = BundleSummary::from(&env_id, &deployment);
        let outcome = OpOutcome::new(
            NOUN,
            "add",
            serde_json::to_value(summary).expect("BundleSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleUpdatePayload {
    pub environment_id: String,
    pub deployment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<BundleDeploymentStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_binding: Option<RouteBindingPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revenue_share: Option<Vec<RevenueShareEntryPayload>>,
    /// D.4: replace the deployment's config_overrides map.
    ///
    /// `None` (the default) leaves the existing overrides untouched.
    /// `Some(map)` replaces them wholesale — pass `Some(empty)` to clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_overrides: Option<BTreeMap<String, BTreeMap<String, Value>>>,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, `update` mints one per invocation. Operators
    /// wanting safe lost-response retries (HTTP backend, PR-3b) supply a
    /// stable key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

pub fn update(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<BundleUpdatePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "update", update_schema()));
    }
    let payload = resolve_payload::<BundleUpdatePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    // Parse the revenue-share change up front so the audit event records it
    // (the plan requires `bundle update` audit to carry revenue_share changes).
    let new_revenue_share: Option<Vec<RevenueShareEntry>> =
        payload.revenue_share.as_ref().map(|s| {
            s.iter()
                .cloned()
                .map(|e| RevenueShareEntry {
                    party_id: greentic_deploy_spec::PartyId::new(e.party_id),
                    basis_points: e.basis_points,
                })
                .collect()
        });
    let new_route_binding = payload.route_binding.clone().map(into_route_binding);
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let mut target = json!({"deployment_id": deployment_id.to_string()});
    if let Some(shares) = &new_revenue_share {
        target["revenue_share"] = revenue_share_json(shares);
    }
    if let Some(overrides) = &payload.config_overrides {
        target["config_overrides"] = config_overrides_audit_shape(overrides);
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target,
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let deployment = store
            .update_bundle(
                &env_id,
                StoreUpdateBundlePayload {
                    deployment_id,
                    status: payload.status,
                    route_binding: new_route_binding,
                    revenue_share: new_revenue_share,
                    config_overrides: payload.config_overrides,
                },
                idempotency_key,
            )
            .map_err(map_store_err_preserving_noun)?;
        let summary = BundleSummary::from(&env_id, &deployment);
        let outcome = OpOutcome::new(
            NOUN,
            "update",
            serde_json::to_value(summary).expect("BundleSummary is json-safe"),
        );
        Ok((outcome, super::AuditGens::NONE))
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRemovePayload {
    pub environment_id: String,
    pub deployment_id: String,
    /// Caller-supplied A8 §2 idempotency key. Optional on the CLI
    /// surface; when absent, `remove` mints one per invocation. Operators
    /// wanting safe lost-response retries (HTTP backend, PR-3b) supply a
    /// stable key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

pub fn remove(
    store: &LocalFsStore,
    flags: &OpFlags,
    payload: Option<BundleRemovePayload>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(NOUN, "remove", remove_schema()));
    }
    let payload = resolve_payload::<BundleRemovePayload>(flags, payload)?;
    let env_id = parse_env_id(&payload.environment_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idempotency_key = resolve_idempotency_key(payload.idempotency_key)?;
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        // `pruned_revision_ids` is added inside the closure once the typed
        // verb returns the prune set — the destructive side effect is
        // explicit in the audit event.
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: Some(idempotency_key.as_str().to_string()),
    };
    audit_and_record(store, ctx, |_committed| {
        let RemoveBundleOutcome {
            deployment,
            pruned_revision_ids,
        } = store
            .remove_bundle(&env_id, deployment_id, idempotency_key)
            .map_err(map_store_err_preserving_noun)?;
        let summary = BundleSummary::from(&env_id, &deployment);
        let mut result = serde_json::to_value(summary).expect("BundleSummary is json-safe");
        // Surface pruned IDs on the wire response so HTTP callers see
        // exactly what was destroyed (matches what the audit event now
        // captures via the explicit-side-effect contract).
        result["pruned_revision_ids"] = json!(
            pruned_revision_ids
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
        );
        let outcome = OpOutcome::new(NOUN, "remove", result);
        Ok((outcome, super::AuditGens::NONE))
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
    let deployments: Vec<BundleSummary> = env
        .bundles
        .iter()
        .map(|b| BundleSummary::from(&env_id, b))
        .collect();
    Ok(OpOutcome::new(
        NOUN,
        "list",
        json!({"environment_id": env_id.as_str(), "deployments": deployments}),
    ))
}

// --- internals -----------------------------------------------------------

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
        "no payload provided: pass --answers <path> or supply the payload directly".to_string(),
    ))
}

fn parse_env_id(raw: &str) -> Result<EnvId, OpError> {
    EnvId::try_from(raw).map_err(|e| OpError::InvalidArgument(format!("environment_id: {e}")))
}

/// P6 (B10): resolve the billing principal. `local` defaults to `local-dev`
/// when none is supplied; every other env must pass one explicitly.
pub(crate) fn resolve_customer_id(
    env_id: &EnvId,
    supplied: Option<String>,
) -> Result<CustomerId, OpError> {
    match supplied {
        Some(c) if c.trim().is_empty() => Err(OpError::InvalidArgument(
            "customer_id must not be empty".to_string(),
        )),
        Some(c) => Ok(CustomerId::new(c)),
        None if env_id.as_str() == crate::defaults::LOCAL_ENV_ID => {
            Ok(CustomerId::new(LOCAL_DEV_CUSTOMER_ID))
        }
        None => Err(OpError::InvalidArgument(format!(
            "customer_id is required for non-local env `{env_id}` (the billing principal; P6)"
        ))),
    }
}

/// Render `config_overrides` as a key-shape only payload for audit logs:
/// `{"<pack_id>": ["<key>", ...], ...}`. Values are NEVER logged — they
/// may carry secrets-adjacent material (e.g. an API base URL with a
/// query-string token), and the audit trail must not be a leak channel.
///
/// TODO(d4-followup): config-key schema linter — see Codex review thread on
/// PR #243. Override key NAMES are user-controlled; a future PR should
/// validate against a known-safe set OR log counts/hashes by default so a
/// token/URI accidentally placed in a key name cannot leak through audit.
pub(super) fn config_overrides_audit_shape(
    overrides: &BTreeMap<String, BTreeMap<String, Value>>,
) -> Value {
    let mut shape = serde_json::Map::with_capacity(overrides.len());
    for (pack_id, keys) in overrides {
        let keys: Vec<Value> = keys.keys().map(|k| Value::String(k.clone())).collect();
        shape.insert(pack_id.clone(), Value::Array(keys));
    }
    Value::Object(shape)
}

/// Render revenue-share entries for the audit `target` payload.
fn revenue_share_json(shares: &[RevenueShareEntry]) -> Value {
    Value::Array(
        shares
            .iter()
            .map(|e| json!({"party_id": e.party_id.as_str(), "basis_points": e.basis_points}))
            .collect(),
    )
}

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
    Ok(DeploymentId(ulid))
}

pub(crate) fn into_route_binding(payload: RouteBindingPayload) -> RouteBinding {
    let tenant_selector = payload
        .tenant_selector
        .map(|t| TenantSelector {
            tenant: t.tenant,
            team: t.team,
        })
        .unwrap_or_else(|| TenantSelector {
            tenant: "default".to_string(),
            team: "default".to_string(),
        });
    RouteBinding {
        hosts: payload.hosts,
        path_prefixes: payload.path_prefixes,
        tenant_selector,
    }
}

fn add_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "BundleAddPayload",
        "type": "object",
        "required": ["environment_id", "bundle_id", "route_binding"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "bundle_id": {"type": "string"},
            "customer_id": {"type": "string", "description": "billing principal; required for non-local envs, defaults to `local-dev` on `local`"},
            "route_binding": {"type": "object"},
            "revenue_share": {"type": "array"},
            "authorization_ref": {"type": "string"},
            "config_overrides": {
                "type": "object",
                "description": "D.4: per-pack provider config overrides — object keyed by pack_id, values are objects of {key: json-value}",
                "additionalProperties": {"type": "object"}
            },
            "idempotency_key": {
                "type": "string",
                "description": "Optional A8 §2 caller-supplied key for safe retry replay; minted per-invocation when omitted."
            }
        }
    })
}

fn update_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "BundleUpdatePayload",
        "type": "object",
        "required": ["environment_id", "deployment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "ULID"},
            "status": {"type": "string", "enum": ["active", "paused", "archived"]},
            "route_binding": {"type": "object"},
            "revenue_share": {"type": "array"},
            "config_overrides": {
                "type": "object",
                "description": "D.4: replace the deployment's config_overrides map wholesale (omit to leave untouched; pass `{}` to clear)",
                "additionalProperties": {"type": "object"}
            },
            "idempotency_key": {
                "type": "string",
                "description": "Optional A8 §2 caller-supplied key for safe retry replay; minted per-invocation when omitted."
            }
        }
    })
}

fn remove_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "BundleRemovePayload",
        "type": "object",
        "required": ["environment_id", "deployment_id"],
        "additionalProperties": false,
        "properties": {
            "environment_id": {"type": "string"},
            "deployment_id": {"type": "string", "description": "ULID"},
            "idempotency_key": {
                "type": "string",
                "description": "Optional A8 §2 caller-supplied key for safe retry replay; minted per-invocation when omitted."
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use tempfile::tempdir;

    /// PR-3a.7 Codex regression: `BundleRemovePayload` accepts an
    /// `idempotency_key` field; the schema published via `--schema` MUST
    /// list it under `properties`, otherwise schema-driven callers
    /// (`gtc op bundles remove --schema | jsonschema-validator …`)
    /// reject the exact field needed for stable A8 §2 retry keys.
    #[test]
    fn remove_schema_lists_idempotency_key() {
        let schema = remove_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "remove_schema must list `idempotency_key` so --schema-driven \
             callers can supply the A8 retry key (schema: {schema:#})"
        );
    }

    /// PR-3a.7b: `BundleAddPayload` accepts an `idempotency_key` field;
    /// the schema published via `--schema` MUST list it under `properties`,
    /// otherwise schema-driven callers reject the field.
    #[test]
    fn add_schema_lists_idempotency_key() {
        let schema = add_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "add_schema must list `idempotency_key` so --schema-driven \
             callers can supply the A8 retry key (schema: {schema:#})"
        );
    }

    /// PR-3a.7b: `BundleUpdatePayload` accepts an `idempotency_key` field;
    /// the schema published via `--schema` MUST list it under `properties`,
    /// otherwise schema-driven callers reject the field.
    #[test]
    fn update_schema_lists_idempotency_key() {
        let schema = update_schema();
        assert!(
            schema.pointer("/properties/idempotency_key").is_some(),
            "update_schema must list `idempotency_key` so --schema-driven \
             callers can supply the A8 retry key (schema: {schema:#})"
        );
    }

    /// PR-3a.7 Codex regression: removing a bundle prunes its archived
    /// revisions, but the destructive side effect must be explicit on the
    /// wire response (and the audit event) — HTTP backends will apply a
    /// separate authz check against the prune set.
    #[test]
    fn remove_response_surfaces_pruned_revision_ids() {
        use greentic_deploy_spec::RevisionLifecycle;
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let env_id = EnvId::try_from("local").unwrap();
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&env_id).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);

        let added = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let did_str = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let deployment_id = parse_deployment_id(&did_str).unwrap();

        // Seed two archived revisions under that deployment (the live-
        // state guard demands archived; otherwise remove refuses).
        let mut env = store.load(&env_id).unwrap();
        for _ in 0..2 {
            env.revisions.push(crate::cli::tests_common::make_revision(
                "local",
                "fast2flow",
                &deployment_id,
                1,
                RevisionLifecycle::Archived,
            ));
        }
        store.save(&env).unwrap();

        let removed = remove(
            &store,
            &OpFlags::default(),
            Some(BundleRemovePayload {
                environment_id: "local".to_string(),
                deployment_id: did_str,
                idempotency_key: None,
            }),
        )
        .unwrap();

        let pruned = removed
            .result
            .get("pruned_revision_ids")
            .and_then(|v| v.as_array())
            .expect("pruned_revision_ids on response");
        assert_eq!(
            pruned.len(),
            2,
            "both archived revisions surface in the response: {removed:#?}"
        );
    }

    fn payload(bundle_id: &str) -> BundleAddPayload {
        BundleAddPayload {
            environment_id: "local".to_string(),
            bundle_id: bundle_id.to_string(),
            customer_id: Some("local-dev".to_string()),
            route_binding: RouteBindingPayload {
                hosts: vec![format!("{bundle_id}.local")],
                path_prefixes: Vec::new(),
                tenant_selector: None,
            },
            revenue_share: default_revenue_share(),
            authorization_ref: default_authorization_ref(),
            config_overrides: BTreeMap::new(),
            idempotency_key: None,
        }
    }

    #[test]
    fn add_then_list_returns_deployment() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let outcome = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let did = outcome
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(!did.is_empty());
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let deployments = listed
            .result
            .get("deployments")
            .and_then(|v| v.as_array())
            .expect("deployments array");
        assert_eq!(deployments.len(), 1);
    }

    #[test]
    fn add_without_bootstrap_surfaces_operator_key_not_trusted() {
        // xhigh #10: `bundles add` must NOT auto-generate `~/.greentic/operator/key.pem`
        // as a side effect of a command that then fails the trust-root
        // precondition. With `load_existing_only`, an unbootstrapped env
        // surfaces a clean OperatorKeyNotTrusted (or NotFound when the
        // operator key itself doesn't exist yet).
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        // NOTE: NO bootstrap_env_trust_root call here. The fixture would
        // have side-effected `~/.greentic/operator/key.pem` and added it
        // to the env trust root; this test asserts that absent both, the
        // CLI refuses without auto-creating either.
        let err = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap_err();
        // Either OperatorKey (key doesn't exist) or RevenuePolicy
        // (key exists from a prior run but isn't in this env's trust root)
        // is acceptable — both signal "operator must bootstrap first".
        assert!(
            matches!(
                err,
                OpError::OperatorKey(_)
                    | OpError::RevenuePolicy(
                        crate::environment::BundleDeploymentError::OperatorKeyNotTrusted { .. }
                    )
            ),
            "expected OperatorKey or OperatorKeyNotTrusted, got {err:?}"
        );
    }

    #[test]
    fn add_rejects_duplicate_bundle_customer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let err = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn add_allows_same_bundle_for_different_customer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let mut p2 = payload("fast2flow");
        p2.customer_id = Some("other".to_string());
        let outcome = add(&store, &OpFlags::default(), Some(p2)).unwrap();
        assert_eq!(outcome.op, "add");
    }

    #[test]
    fn update_changes_status_and_route_binding() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let added = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let did = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let outcome = update(
            &store,
            &OpFlags::default(),
            Some(BundleUpdatePayload {
                environment_id: "local".to_string(),
                deployment_id: did.clone(),
                status: Some(BundleDeploymentStatus::Paused),
                route_binding: Some(RouteBindingPayload {
                    hosts: vec!["new.example.com".to_string()],
                    path_prefixes: vec!["/v1".to_string()],
                    tenant_selector: None,
                }),
                revenue_share: None,
                config_overrides: None,
                idempotency_key: None,
            }),
        )
        .unwrap();
        assert_eq!(
            outcome.result.get("status").and_then(|v| v.as_str()),
            Some("paused")
        );
        let hosts = outcome
            .result
            .get("hosts")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].as_str(), Some("new.example.com"));
    }

    #[test]
    fn remove_rejects_deployment_with_revisions() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let mut bundle = crate::cli::tests_common::make_bundle_deployment("local", "fast2flow");
        let did = bundle.deployment_id;
        // `Environment::validate` requires every `current_revisions` id to
        // resolve to a real Revision in the env, so push a matching one.
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            greentic_deploy_spec::RevisionLifecycle::Ready,
        );
        bundle.current_revisions.push(revision.revision_id);
        env.bundles.push(bundle);
        env.revisions.push(revision);
        store.save(&env).unwrap();
        let err = remove(
            &store,
            &OpFlags::default(),
            Some(BundleRemovePayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn remove_with_no_revisions_succeeds() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let added = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let did = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        remove(
            &store,
            &OpFlags::default(),
            Some(BundleRemovePayload {
                environment_id: "local".to_string(),
                deployment_id: did,
                idempotency_key: None,
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let deployments = listed.result.get("deployments").and_then(|v| v.as_array());
        assert!(deployments.map(|v| v.is_empty()).unwrap_or(false));
    }

    #[test]
    fn remove_rejects_when_traffic_split_references_deployment() {
        // Codex regression: the prior guard checked `current_revisions`,
        // which the CLI stage/warm/traffic path never populates. Verify
        // that a live traffic split blocks removal even when
        // current_revisions is empty.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let bundle = crate::cli::tests_common::make_bundle_deployment("local", "fast2flow");
        let did = bundle.deployment_id;
        // Note: current_revisions intentionally left empty — matches the
        // CLI path's state.
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            greentic_deploy_spec::RevisionLifecycle::Ready,
        );
        let split = crate::cli::tests_common::make_traffic_split(
            "local",
            "fast2flow",
            &did,
            &revision.revision_id,
            "k1",
        );
        env.bundles.push(bundle);
        env.revisions.push(revision);
        env.traffic_splits.push(split);
        store.save(&env).unwrap();
        let err = remove(
            &store,
            &OpFlags::default(),
            Some(BundleRemovePayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn remove_rejects_when_non_archived_revision_exists() {
        // Same C4 finding, the other live-state signal: a non-archived
        // revision (even one that's not yet referenced by a traffic split)
        // must block removal.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        let mut env = make_env("local");
        let bundle = crate::cli::tests_common::make_bundle_deployment("local", "fast2flow");
        let did = bundle.deployment_id;
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            greentic_deploy_spec::RevisionLifecycle::Staged,
        );
        env.bundles.push(bundle);
        env.revisions.push(revision);
        store.save(&env).unwrap();
        let err = remove(
            &store,
            &OpFlags::default(),
            Some(BundleRemovePayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
                idempotency_key: None,
            }),
        )
        .unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    // --- B10: customer_id requirement + signed/versioned revenue policy ----

    #[test]
    fn add_writes_v1_revenue_policy_and_pins_ref() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();

        let env = store.load(&parse_env_id("local").unwrap()).unwrap();
        let dep = &env.bundles[0];
        assert_eq!(
            dep.revenue_policy_ref,
            PathBuf::from("billing-policies/fast2flow/local-dev/v1.json.sig")
        );
        let env_dir = dir.path().join("local");
        assert!(env_dir.join(&dep.revenue_policy_ref).is_file());
        assert!(
            env_dir
                .join("billing-policies/fast2flow/local-dev/v1.json")
                .is_file()
        );
    }

    #[test]
    fn add_overwrites_orphan_v1_from_failed_prior_attempt() {
        // Codex regression: a prior `add` that wrote v1.json but failed before
        // committing env.json must NOT cause the retry to advance to v2 and
        // chain through a never-committed/dangling v1. Since the deployment
        // isn't committed, the retry stays at v1 and overwrites the orphan.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        // Simulate the orphan document left by a failed attempt.
        let orphan_dir = dir
            .path()
            .join("local/billing-policies/fast2flow/local-dev");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("v1.json"), b"{\"stale\":true}").unwrap();

        add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();

        let env = store.load(&parse_env_id("local").unwrap()).unwrap();
        assert_eq!(
            env.bundles[0].revenue_policy_ref,
            PathBuf::from("billing-policies/fast2flow/local-dev/v1.json.sig"),
            "retry must reuse v1, not advance past the orphan"
        );
        assert!(!orphan_dir.join("v2.json").exists());
        // The orphan was overwritten with a valid versioned document.
        let doc: greentic_deploy_spec::RevenuePolicyDocument =
            serde_json::from_slice(&std::fs::read(orphan_dir.join("v1.json")).unwrap()).unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.validate().is_ok());
    }

    #[test]
    fn add_rejects_empty_bundle_id_early() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let mut p = payload("fast2flow");
        p.bundle_id = "".to_string();
        let err = add(&store, &OpFlags::default(), Some(p)).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("bundle_id")),
            "got {err:?}"
        );
        // No partial billing-policy artifacts left behind.
        assert!(!dir.path().join("local/billing-policies").exists());
    }

    #[test]
    fn add_rejects_empty_customer_id_early() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let mut p = payload("fast2flow");
        p.customer_id = Some("".to_string());
        let err = add(&store, &OpFlags::default(), Some(p)).unwrap_err();
        assert!(
            matches!(&err, OpError::InvalidArgument(m) if m.contains("customer_id")),
            "got {err:?}"
        );
        assert!(!dir.path().join("local/billing-policies").exists());
    }

    #[test]
    fn add_local_defaults_customer_id_when_omitted() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let mut p = payload("fast2flow");
        p.customer_id = None;
        let outcome = add(&store, &OpFlags::default(), Some(p)).unwrap();
        assert_eq!(
            outcome.result.get("customer_id").and_then(|v| v.as_str()),
            Some("local-dev")
        );
    }

    #[test]
    fn add_non_local_without_customer_id_is_invalid_argument() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("prod-eu")).unwrap();
        let mut p = payload("fast2flow");
        p.environment_id = "prod-eu".to_string();
        p.customer_id = None;
        // The argument contract is checked before authorization, so a missing
        // billing principal surfaces precisely (not as a generic authz deny).
        let err = add(&store, &OpFlags::default(), Some(p)).unwrap_err();
        assert!(matches!(err, OpError::InvalidArgument(_)), "got {err:?}");
    }

    #[test]
    fn add_non_local_with_customer_id_is_authz_denied() {
        // With a billing principal supplied, the arg gate passes and the
        // non-local env is rejected by the local-only authz policy (A8 ships
        // real RBAC). Confirms the customer_id gate doesn't let non-local through.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("prod-eu")).unwrap();
        let mut p = payload("fast2flow");
        p.environment_id = "prod-eu".to_string();
        p.customer_id = Some("cust-acme".to_string());
        let err = add(&store, &OpFlags::default(), Some(p)).unwrap_err();
        assert!(matches!(err, OpError::Unauthorized { .. }), "got {err:?}");
    }

    #[test]
    fn update_revenue_share_writes_new_version_and_chains() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let added = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let did = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        update(
            &store,
            &OpFlags::default(),
            Some(BundleUpdatePayload {
                environment_id: "local".to_string(),
                deployment_id: did,
                status: None,
                route_binding: None,
                revenue_share: Some(vec![
                    RevenueShareEntryPayload {
                        party_id: "agency-a".to_string(),
                        basis_points: 3_000,
                    },
                    RevenueShareEntryPayload {
                        party_id: "greentic".to_string(),
                        basis_points: 7_000,
                    },
                ]),
                config_overrides: None,
                idempotency_key: None,
            }),
        )
        .unwrap();

        let env = store.load(&parse_env_id("local").unwrap()).unwrap();
        let dep = &env.bundles[0];
        assert_eq!(
            dep.revenue_policy_ref,
            PathBuf::from("billing-policies/fast2flow/local-dev/v2.json.sig")
        );
        let env_dir = dir.path().join("local");
        assert!(
            env_dir
                .join("billing-policies/fast2flow/local-dev/v2.json")
                .is_file()
        );
        // Audit recorded the revenue-share change.
        let audit = std::fs::read_to_string(env_dir.join("audit/events.jsonl")).unwrap();
        assert!(
            audit.contains("agency-a") && audit.contains("3000"),
            "update audit event must carry the revenue_share change: {audit}"
        );
    }

    #[test]
    fn update_without_revenue_share_keeps_policy_ref() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let added = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let did = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        update(
            &store,
            &OpFlags::default(),
            Some(BundleUpdatePayload {
                environment_id: "local".to_string(),
                deployment_id: did,
                status: Some(BundleDeploymentStatus::Paused),
                route_binding: None,
                revenue_share: None,
                config_overrides: None,
                idempotency_key: None,
            }),
        )
        .unwrap();
        let env = store.load(&parse_env_id("local").unwrap()).unwrap();
        assert_eq!(
            env.bundles[0].revenue_policy_ref,
            PathBuf::from("billing-policies/fast2flow/local-dev/v1.json.sig")
        );
    }

    // ---- D.4 train-2 ----------------------------------------------------

    fn payload_with_overrides(
        bundle_id: &str,
        overrides: BTreeMap<String, BTreeMap<String, Value>>,
    ) -> BundleAddPayload {
        BundleAddPayload {
            config_overrides: overrides,
            ..payload(bundle_id)
        }
    }

    fn single_override(
        pack_id: &str,
        key: &str,
        value: Value,
    ) -> BTreeMap<String, BTreeMap<String, Value>> {
        BTreeMap::from([(
            pack_id.to_string(),
            BTreeMap::from([(key.to_string(), value)]),
        )])
    }

    #[test]
    fn add_persists_config_overrides_on_bundle_deployment() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let overrides = single_override(
            "messaging-telegram",
            "api_base_url",
            Value::String("https://staging.example.com".to_string()),
        );
        let outcome = add(
            &store,
            &OpFlags::default(),
            Some(payload_with_overrides("fast2flow", overrides.clone())),
        )
        .unwrap();
        assert_eq!(outcome.op, "add");
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles[0].config_overrides, overrides);
    }

    #[test]
    fn add_rejects_structurally_invalid_config_overrides() {
        // Spec-level validation (`BundleDeployment::validate`) catches empty
        // pack_id / key / size violations and propagates as `OpError::Spec`.
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let overrides = BTreeMap::from([(
            String::new(), // empty pack_id → rejected by structural validation
            BTreeMap::from([("k".to_string(), Value::String("v".to_string()))]),
        )]);
        let err = add(
            &store,
            &OpFlags::default(),
            Some(payload_with_overrides("fast2flow", overrides)),
        )
        .unwrap_err();
        // Validation fires inside `store.save(&env)`, so the SpecError lands
        // wrapped in `OpError::Store(StoreError::Spec(_))`.
        let msg = format!("{err:?}");
        assert!(
            msg.contains("ConfigOverrideEmptyPackId"),
            "expected ConfigOverrideEmptyPackId, got {err:?}"
        );
    }

    #[test]
    fn update_replaces_config_overrides_when_some() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let initial = single_override(
            "messaging-telegram",
            "api_base_url",
            Value::String("https://v1.example.com".to_string()),
        );
        let added = add(
            &store,
            &OpFlags::default(),
            Some(payload_with_overrides("fast2flow", initial)),
        )
        .unwrap();
        let did = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let replaced = single_override(
            "messaging-telegram",
            "api_base_url",
            Value::String("https://v2.example.com".to_string()),
        );
        update(
            &store,
            &OpFlags::default(),
            Some(BundleUpdatePayload {
                environment_id: "local".to_string(),
                deployment_id: did,
                status: None,
                route_binding: None,
                revenue_share: None,
                config_overrides: Some(replaced.clone()),
                idempotency_key: None,
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles[0].config_overrides, replaced);
    }

    #[test]
    fn update_with_none_leaves_config_overrides_untouched() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        let env_dir = store.env_dir(&EnvId::try_from("local").unwrap()).unwrap();
        crate::cli::tests_common::bootstrap_env_trust_root(&env_dir);
        let initial = single_override(
            "messaging-slack",
            "webhook_url",
            Value::String("https://hooks.slack/v1".to_string()),
        );
        let added = add(
            &store,
            &OpFlags::default(),
            Some(payload_with_overrides("fast2flow", initial.clone())),
        )
        .unwrap();
        let did = added
            .result
            .get("deployment_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        // Update status only — `config_overrides: None` must leave them alone.
        update(
            &store,
            &OpFlags::default(),
            Some(BundleUpdatePayload {
                environment_id: "local".to_string(),
                deployment_id: did,
                status: Some(BundleDeploymentStatus::Paused),
                route_binding: None,
                revenue_share: None,
                config_overrides: None,
                idempotency_key: None,
            }),
        )
        .unwrap();
        let env = store.load(&EnvId::try_from("local").unwrap()).unwrap();
        assert_eq!(env.bundles[0].config_overrides, initial);
    }

    #[test]
    fn config_overrides_audit_shape_lists_keys_not_values() {
        // Values may carry secrets-adjacent material (URLs with tokens, etc.);
        // the audit shape must publish key NAMES only — never the values.
        let overrides = BTreeMap::from([
            (
                "messaging-telegram".to_string(),
                BTreeMap::from([
                    (
                        "api_base_url".to_string(),
                        Value::String("https://api.telegram.org/SECRET-TOKEN".to_string()),
                    ),
                    (
                        "retry_max".to_string(),
                        Value::Number(serde_json::Number::from(5)),
                    ),
                ]),
            ),
            (
                "messaging-slack".to_string(),
                BTreeMap::from([(
                    "webhook_url".to_string(),
                    Value::String("https://hooks.slack/T0123/B0456/SECRET-PATH".to_string()),
                )]),
            ),
        ]);
        let shape = config_overrides_audit_shape(&overrides);
        let serialized = serde_json::to_string(&shape).unwrap();
        assert!(
            !serialized.contains("SECRET"),
            "audit shape leaked a value: {serialized}"
        );
        assert!(
            serialized.contains("api_base_url") && serialized.contains("retry_max"),
            "audit shape missing key names: {serialized}"
        );
        // Keys are sorted (BTreeMap ordering), so the shape is deterministic.
        assert_eq!(
            serialized,
            r#"{"messaging-slack":["webhook_url"],"messaging-telegram":["api_base_url","retry_max"]}"#
        );
    }
}
