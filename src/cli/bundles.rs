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

use super::{AuditCtx, OpError, OpFlags, OpOutcome, audit_and_record};

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
}

/// Default `customer_id` for the `local` env when none is supplied. Non-local
/// envs must pass one explicitly (B10).
const LOCAL_DEV_CUSTOMER_ID: &str = "local-dev";

fn default_revenue_share() -> Vec<RevenueShareEntryPayload> {
    vec![RevenueShareEntryPayload {
        party_id: "greentic".to_string(),
        basis_points: 10_000,
    }]
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "add",
        target: json!({
            "bundle_id": bundle_id.as_str(),
            "customer_id": customer_id.as_str(),
            "revenue_share": revenue_share_json(&revenue_share),
        }),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env_dir = store.env_dir(&env_id)?;
        let summary = store.transact(&env_id, |locked| -> Result<BundleSummary, OpError> {
            let mut env = locked.load()?;
            // P6 anchor (§5.4): one BundleDeployment per (env_id, bundle_id, customer_id).
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
            let created_at = Utc::now();
            let mut deployment = BundleDeployment {
                schema: SchemaVersion::new(SchemaVersion::BUNDLE_DEPLOYMENT_V1),
                deployment_id: crate::environment::mint_deployment_id(),
                env_id: env_id.clone(),
                bundle_id: bundle_id.clone(),
                customer_id: customer_id.clone(),
                status: BundleDeploymentStatus::Active,
                current_revisions: Vec::new(),
                route_binding: into_route_binding(payload.route_binding.clone()),
                revenue_share: revenue_share.clone(),
                // Replaced with the v1 policy sidecar path below.
                revenue_policy_ref: PathBuf::new(),
                usage: None,
                created_at,
                authorization_ref: payload.authorization_ref.clone(),
            };
            // Write the v1 signed/versioned revenue policy and pin the ref.
            let version = crate::environment::write_revenue_policy_version(
                &env_dir,
                &deployment,
                &deployment.revenue_share,
                created_at,
            )?;
            deployment.revenue_policy_ref = version.policy_ref;
            env.bundles.push(deployment);
            locked.save(&env)?;
            Ok(BundleSummary::from(
                &env_id,
                env.bundles.last().expect("just pushed"),
            ))
        })?;
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
    let mut target = json!({"deployment_id": deployment_id.to_string()});
    if let Some(shares) = &new_revenue_share {
        target["revenue_share"] = revenue_share_json(shares);
    }
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "update",
        target,
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let env_dir = store.env_dir(&env_id)?;
        let summary = store.transact(&env_id, |locked| -> Result<BundleSummary, OpError> {
            let mut env = locked.load()?;
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
            if let Some(rb) = payload.route_binding.clone() {
                env.bundles[idx].route_binding = into_route_binding(rb);
            }
            if let Some(shares) = new_revenue_share.clone() {
                // A revenue-share mutation creates a new signed/versioned policy
                // (B10): set the shares, write v{N+1}, and pin the new ref.
                env.bundles[idx].revenue_share = shares;
                let created_at = Utc::now();
                let version = crate::environment::write_revenue_policy_version(
                    &env_dir,
                    &env.bundles[idx],
                    &env.bundles[idx].revenue_share,
                    created_at,
                )?;
                env.bundles[idx].revenue_policy_ref = version.policy_ref;
            }
            locked.save(&env)?;
            Ok(BundleSummary::from(&env_id, &env.bundles[idx]))
        })?;
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
    let ctx = AuditCtx {
        env_id: env_id.clone(),
        noun: NOUN,
        verb: "remove",
        target: json!({"deployment_id": deployment_id.to_string()}),
        idempotency_key: None,
    };
    audit_and_record(store, ctx, |_committed| {
        let summary = store.transact(&env_id, |locked| -> Result<BundleSummary, OpError> {
            let mut env = locked.load()?;
            let idx = env
                .bundles
                .iter()
                .position(|b| b.deployment_id == deployment_id)
                .ok_or_else(|| {
                    OpError::NotFound(format!(
                        "deployment `{deployment_id}` not found in env `{env_id}`"
                    ))
                })?;
            // Live-state guard. `current_revisions` is plan-level future signal
            // that A3's stage/warm path does not yet maintain, so it can't be
            // the gate. The actual live-state proof is: any traffic split
            // pointing at this deployment, or any non-archived Revision for it.
            let active_splits = env
                .traffic_splits
                .iter()
                .filter(|s| s.deployment_id == deployment_id)
                .count();
            let active_revisions = env
                .revisions
                .iter()
                .filter(|r| {
                    r.deployment_id == deployment_id
                        && !matches!(
                            r.lifecycle,
                            greentic_deploy_spec::RevisionLifecycle::Archived
                        )
                })
                .count();
            if active_splits > 0 || active_revisions > 0 {
                return Err(OpError::Conflict(format!(
                    "deployment `{deployment_id}` is still live: {active_splits} traffic split(s), \
                     {active_revisions} non-archived revision(s). Archive revisions and clear the \
                     split first."
                )));
            }
            let removed = env.bundles.remove(idx);
            // No live state to nuke at this point; drop the archived revisions
            // for this deployment so the env stays compact.
            env.revisions.retain(|r| r.deployment_id != deployment_id);
            locked.save(&env)?;
            Ok(BundleSummary::from(&env_id, &removed))
        })?;
        let outcome = OpOutcome::new(
            NOUN,
            "remove",
            serde_json::to_value(summary).expect("BundleSummary is json-safe"),
        );
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
fn resolve_customer_id(env_id: &EnvId, supplied: Option<String>) -> Result<CustomerId, OpError> {
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
            "customer_id": {"type": "string", "description": "billing principal; required for non-local envs, defaults to `local-dev` on `local`"},
            "route_binding": {"type": "object"},
            "revenue_share": {"type": "array"},
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
            customer_id: Some("local-dev".to_string()),
            route_binding: RouteBindingPayload {
                hosts: vec![format!("{bundle_id}.local")],
                path_prefixes: Vec::new(),
                tenant_selector: None,
            },
            revenue_share: default_revenue_share(),
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
        p2.customer_id = Some("other".to_string());
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
            }),
        )
        .unwrap();
        let env = store.load(&parse_env_id("local").unwrap()).unwrap();
        assert_eq!(
            env.bundles[0].revenue_policy_ref,
            PathBuf::from("billing-policies/fast2flow/local-dev/v1.json.sig")
        );
    }
}
