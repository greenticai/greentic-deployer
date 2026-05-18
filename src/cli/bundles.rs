//! `gtc op bundles {add,update,remove,list}` (`A3`).
//!
//! Manages `Environment.bundles: Vec<BundleDeployment>`. Each call records
//! the bundle deployment metadata only — actual staging of a `.gtbundle`
//! into a `Revision` happens via `op revisions stage`. The intentional
//! split: `bundles` owns rollout-unit metadata (`route_binding`,
//! `revenue_share`, `customer_id`); `revisions` owns the per-version
//! artifact pointers.

use std::path::PathBuf;

use chrono::Utc;
use greentic_deploy_spec::{
    BundleDeployment, BundleDeploymentStatus, BundleId, CustomerId, DeploymentId, EnvId,
    RevenueShareEntry, RouteBinding, SchemaVersion, TenantSelector,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::environment::{EnvironmentStore, LocalFsStore};

use super::{OpError, OpFlags, OpOutcome};

const NOUN: &str = "bundles";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleAddPayload {
    pub environment_id: String,
    pub bundle_id: String,
    #[serde(default = "default_customer_id")]
    pub customer_id: String,
    pub route_binding: RouteBindingPayload,
    #[serde(default = "default_revenue_share")]
    pub revenue_share: Vec<RevenueShareEntryPayload>,
    #[serde(default = "default_revenue_policy_ref")]
    pub revenue_policy_ref: PathBuf,
    #[serde(default = "default_authorization_ref")]
    pub authorization_ref: PathBuf,
}

fn default_customer_id() -> String {
    "local-dev".to_string()
}
fn default_revenue_share() -> Vec<RevenueShareEntryPayload> {
    vec![RevenueShareEntryPayload {
        party_id: "greentic".to_string(),
        basis_points: 10_000,
    }]
}
fn default_revenue_policy_ref() -> PathBuf {
    PathBuf::from("revenue.json")
}
fn default_authorization_ref() -> PathBuf {
    PathBuf::from("auth.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBindingPayload {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub tenant_selector: Option<TenantSelectorPayload>,
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
    fn from(env_id: &EnvId, b: &BundleDeployment) -> Self {
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
    let mut env = store.load(&env_id)?;
    let bundle_id = BundleId::new(payload.bundle_id);
    // Reject duplicate (bundle_id, customer_id) — that combination is the
    // P6 anchor (§5.4: one BundleDeployment per `(env_id, bundle_id,
    // customer_id)`).
    let customer_id = CustomerId::new(payload.customer_id);
    if env
        .bundles
        .iter()
        .any(|b| b.bundle_id == bundle_id && b.customer_id == customer_id)
    {
        return Err(OpError::Conflict(format!(
            "bundle `{}` for customer `{}` already deployed in env `{}`",
            bundle_id, customer_id, env_id
        )));
    }
    let deployment = BundleDeployment {
        schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
        deployment_id: crate::environment::mint_deployment_id(),
        env_id: env_id.clone(),
        bundle_id,
        customer_id,
        status: BundleDeploymentStatus::Active,
        current_revisions: Vec::new(),
        route_binding: into_route_binding(payload.route_binding),
        revenue_share: payload
            .revenue_share
            .into_iter()
            .map(|e| RevenueShareEntry {
                party_id: greentic_deploy_spec::PartyId::new(e.party_id),
                basis_points: e.basis_points,
            })
            .collect(),
        revenue_policy_ref: payload.revenue_policy_ref,
        usage: None,
        created_at: Utc::now(),
        authorization_ref: payload.authorization_ref,
    };
    env.bundles.push(deployment);
    store.save(&env)?;
    let summary = BundleSummary::from(&env_id, env.bundles.last().expect("just pushed"));
    Ok(OpOutcome::new(
        NOUN,
        "add",
        serde_json::to_value(summary).expect("BundleSummary is json-safe"),
    ))
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
    let mut env = store.load(&env_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idx = env
        .bundles
        .iter()
        .position(|b| b.deployment_id == deployment_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "deployment `{deployment_id}` not found in env `{env_id}`"
            ))
        })?;
    if let Some(status) = payload.status {
        env.bundles[idx].status = status;
    }
    if let Some(rb) = payload.route_binding {
        env.bundles[idx].route_binding = into_route_binding(rb);
    }
    if let Some(shares) = payload.revenue_share {
        env.bundles[idx].revenue_share = shares
            .into_iter()
            .map(|e| RevenueShareEntry {
                party_id: greentic_deploy_spec::PartyId::new(e.party_id),
                basis_points: e.basis_points,
            })
            .collect();
    }
    store.save(&env)?;
    let summary = BundleSummary::from(&env_id, &env.bundles[idx]);
    Ok(OpOutcome::new(
        NOUN,
        "update",
        serde_json::to_value(summary).expect("BundleSummary is json-safe"),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleRemovePayload {
    pub environment_id: String,
    pub deployment_id: String,
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
    let mut env = store.load(&env_id)?;
    let deployment_id = parse_deployment_id(&payload.deployment_id)?;
    let idx = env
        .bundles
        .iter()
        .position(|b| b.deployment_id == deployment_id)
        .ok_or_else(|| {
            OpError::NotFound(format!(
                "deployment `{deployment_id}` not found in env `{env_id}`"
            ))
        })?;
    // Refuse to remove a deployment whose revisions are still live. A5/A7
    // will gate this on the lifecycle audit log; for now we enforce the
    // simpler invariant: a deployment with current_revisions must be archived
    // first.
    if !env.bundles[idx].current_revisions.is_empty() {
        return Err(OpError::Conflict(format!(
            "deployment `{deployment_id}` has {} active revision(s); archive them first",
            env.bundles[idx].current_revisions.len()
        )));
    }
    let removed = env.bundles.remove(idx);
    // Also remove any TrafficSplit and orphan revisions for this deployment.
    env.traffic_splits
        .retain(|s| s.deployment_id != deployment_id);
    env.revisions.retain(|r| r.deployment_id != deployment_id);
    store.save(&env)?;
    let summary = BundleSummary::from(&env_id, &removed);
    Ok(OpOutcome::new(
        NOUN,
        "remove",
        serde_json::to_value(summary).expect("BundleSummary is json-safe"),
    ))
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

fn parse_deployment_id(raw: &str) -> Result<DeploymentId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("deployment_id: {e}")))?;
    Ok(DeploymentId(ulid))
}

fn into_route_binding(payload: RouteBindingPayload) -> RouteBinding {
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
            "customer_id": {"type": "string", "default": "local-dev"},
            "route_binding": {"type": "object"},
            "revenue_share": {"type": "array"},
            "revenue_policy_ref": {"type": "string"},
            "authorization_ref": {"type": "string"}
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
            "revenue_share": {"type": "array"}
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
            "deployment_id": {"type": "string", "description": "ULID"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests_common::make_env;
    use tempfile::tempdir;

    fn payload(bundle_id: &str) -> BundleAddPayload {
        BundleAddPayload {
            environment_id: "local".to_string(),
            bundle_id: bundle_id.to_string(),
            customer_id: "local-dev".to_string(),
            route_binding: RouteBindingPayload {
                hosts: vec![format!("{bundle_id}.local")],
                path_prefixes: Vec::new(),
                tenant_selector: None,
            },
            revenue_share: default_revenue_share(),
            revenue_policy_ref: default_revenue_policy_ref(),
            authorization_ref: default_authorization_ref(),
        }
    }

    #[test]
    fn add_then_list_returns_deployment() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
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
    fn add_rejects_duplicate_bundle_customer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let err = add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap_err();
        assert!(matches!(err, OpError::Conflict(_)), "got {err:?}");
    }

    #[test]
    fn add_allows_same_bundle_for_different_customer() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
        add(&store, &OpFlags::default(), Some(payload("fast2flow"))).unwrap();
        let mut p2 = payload("fast2flow");
        p2.customer_id = "other".to_string();
        let outcome = add(&store, &OpFlags::default(), Some(p2)).unwrap();
        assert_eq!(outcome.op, "add");
    }

    #[test]
    fn update_changes_status_and_route_binding() {
        let dir = tempdir().unwrap();
        let store = LocalFsStore::new(dir.path());
        store.save(&make_env("local")).unwrap();
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
        let did = bundle.deployment_id.clone();
        // `Environment::validate` requires every `current_revisions` id to
        // resolve to a real Revision in the env, so push a matching one.
        let revision = crate::cli::tests_common::make_revision(
            "local",
            "fast2flow",
            &did,
            1,
            greentic_deploy_spec::RevisionLifecycle::Ready,
        );
        bundle.current_revisions.push(revision.revision_id.clone());
        env.bundles.push(bundle);
        env.revisions.push(revision);
        store.save(&env).unwrap();
        let err = remove(
            &store,
            &OpFlags::default(),
            Some(BundleRemovePayload {
                environment_id: "local".to_string(),
                deployment_id: did.to_string(),
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
            }),
        )
        .unwrap();
        let listed = list(&store, &OpFlags::default(), "local").unwrap();
        let deployments = listed.result.get("deployments").and_then(|v| v.as_array());
        assert!(deployments.map(|v| v.is_empty()).unwrap_or(false));
    }
}
