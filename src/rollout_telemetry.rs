//! C5.3 rollout-event emission helpers for greentic-deployer.
//!
//! Wraps [`greentic_telemetry::emit_rollout_event`] with the deployer's
//! lifecycle attribution sources so every live CLI verb that mutates revision
//! state (`warm`, `drain`, `archive`, traffic `set`) emits the corresponding
//! [`RolloutEvent`] without each call site repeating the
//! [`TelemetryCtx`](greentic_telemetry::TelemetryCtx) construction.
//!
//! ## Tenant attribution
//!
//! Lifecycle events ride on [`Environment.host_config.tenant_org_id`]
//! (the env owner). Envs without an owner — single-process `local` dev —
//! fall back to [`LOCAL_TENANT_FALLBACK`] so the emitted `gt.tenant`
//! attribute is never empty.
//!
//! ## Live vs deferred
//!
//! The CLI verbs in [`crate::cli::revisions`] and [`crate::cli::traffic`]
//! are reached by the operator HTTP routes (`POST /deployments/{warm,
//! drain, activate, ...}`), so emissions from these helpers are observable
//! end-to-end today. Phase-D scaffolds that haven't been wired through the
//! live producer (greentic-start's `RevisionDrainCoordinator` /
//! `StartRevisionHealthGate`) keep their own forward-compat emit wiring
//! and will fire when their consumers are wired.

use greentic_deploy_spec::{BundleId, DeploymentId, Environment, Revision};
use greentic_telemetry::{RolloutEvent, TelemetryCtx, emit_rollout_event};

/// Fallback tenant for envs without an owner — matches the operator's
/// single-process `local` convention.
const LOCAL_TENANT_FALLBACK: &str = "local";

/// Build the [`TelemetryCtx`] for a per-revision lifecycle event
/// (`HealthGatePassed`/`HealthGateFailed`/`RevisionWarmed`/`RevisionDraining`/
/// `RevisionEvicted`). Pure, no I/O, unit-testable via
/// [`TelemetryCtx::kv`].
pub(crate) fn build_lifecycle_ctx(env: &Environment, revision: &Revision) -> TelemetryCtx {
    let tenant = env
        .host_config
        .tenant_org_id
        .as_deref()
        .unwrap_or(LOCAL_TENANT_FALLBACK);
    TelemetryCtx::new(tenant)
        .with_env(env.environment_id.as_str())
        .with_deployment_id(revision.deployment_id.to_string())
        .with_bundle_id(revision.bundle_id.to_string())
        .with_revision_id(revision.revision_id.to_string())
}

/// Build the [`TelemetryCtx`] for a `TrafficSplitApplied` event — the
/// deployment-level transition has no single revision, so the attribution
/// is at the env + deployment + bundle + new-generation granularity.
pub(crate) fn build_traffic_split_ctx(
    env: &Environment,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    new_generation: u64,
) -> TelemetryCtx {
    let tenant = env
        .host_config
        .tenant_org_id
        .as_deref()
        .unwrap_or(LOCAL_TENANT_FALLBACK);
    TelemetryCtx::new(tenant)
        .with_env(env.environment_id.as_str())
        .with_deployment_id(deployment_id.to_string())
        .with_bundle_id(bundle_id.to_string())
        .with_generation(new_generation)
}

/// Emit a per-revision lifecycle event with the standard attribution.
pub(crate) fn emit_lifecycle_event(event: RolloutEvent, env: &Environment, revision: &Revision) {
    let ctx = build_lifecycle_ctx(env, revision);
    emit_rollout_event(event, &ctx);
}

/// Emit `TrafficSplitApplied` for a deployment-level split rotation.
pub(crate) fn emit_traffic_split_applied(
    env: &Environment,
    deployment_id: DeploymentId,
    bundle_id: &BundleId,
    new_generation: u64,
) {
    let ctx = build_traffic_split_ctx(env, deployment_id, bundle_id, new_generation);
    emit_rollout_event(RolloutEvent::TrafficSplitApplied, &ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use greentic_deploy_spec::{
        BundleId, DeploymentId, EnvId, Environment, EnvironmentHostConfig, PackId, PackListEntry,
        Revision, RevisionId, RevisionLifecycle, SchemaVersion, SemVer,
    };
    use std::path::PathBuf;

    fn env_with_owner(owner: Option<&str>) -> Environment {
        Environment {
            schema: SchemaVersion::new(SchemaVersion::ENVIRONMENT_V1),
            environment_id: EnvId::try_from("prod-eu").unwrap(),
            name: "prod-eu".into(),
            host_config: EnvironmentHostConfig {
                env_id: EnvId::try_from("prod-eu").unwrap(),
                region: None,
                tenant_org_id: owner.map(str::to_string),
            },
            packs: Vec::new(),
            credentials_ref: None,
            bundles: Vec::new(),
            revisions: Vec::new(),
            traffic_splits: Vec::new(),
            revocation: Default::default(),
            retention: Default::default(),
            health: Default::default(),
        }
    }

    fn sample_revision() -> Revision {
        Revision {
            schema: SchemaVersion::new(SchemaVersion::REVISION_V1),
            revision_id: RevisionId::new(),
            env_id: EnvId::try_from("prod-eu").unwrap(),
            bundle_id: BundleId::new("customer.support"),
            deployment_id: DeploymentId::new(),
            sequence: 1,
            created_at: Utc.timestamp_opt(0, 0).unwrap(),
            bundle_digest: "sha256:00".into(),
            pack_list: vec![PackListEntry {
                pack_id: PackId::new("greentic.support.pack"),
                version: SemVer::new(1, 0, 0),
                digest: "sha256:00".into(),
                source_uri: None,
            }],
            pack_list_lock_ref: PathBuf::from("pack-list.lock"),
            config_digest: "sha256:00".into(),
            signature_sidecar_ref: PathBuf::from("rev.sig"),
            lifecycle: RevisionLifecycle::Ready,
            staged_at: None,
            warmed_at: None,
            drain_seconds: 30,
            abort_metrics: Vec::new(),
        }
    }

    fn get<'a>(kv: &'a [(&'static str, Option<&str>)], key: &str) -> Option<&'a str> {
        kv.iter().find(|(k, _)| *k == key).and_then(|(_, v)| *v)
    }

    #[test]
    fn lifecycle_ctx_uses_env_tenant_org_id_when_set() {
        let env = env_with_owner(Some("acme"));
        let rev = sample_revision();
        let ctx = build_lifecycle_ctx(&env, &rev);
        let kv = ctx.kv();
        assert_eq!(get(&kv, "gt.tenant"), Some("acme"));
        assert_eq!(get(&kv, "gt.env"), Some("prod-eu"));
        assert_eq!(get(&kv, "gt.bundle_id"), Some("customer.support"));
        assert_eq!(
            get(&kv, "gt.deployment_id"),
            Some(rev.deployment_id.to_string().as_str())
        );
        assert_eq!(
            get(&kv, "gt.revision_id"),
            Some(rev.revision_id.to_string().as_str())
        );
    }

    /// `local` envs have `host_config.tenant_org_id == None`; the helper
    /// falls back to [`LOCAL_TENANT_FALLBACK`] so the emitted
    /// `gt.tenant` attribute is never empty.
    #[test]
    fn lifecycle_ctx_falls_back_to_local_tenant_when_unowned() {
        let env = env_with_owner(None);
        let rev = sample_revision();
        let ctx = build_lifecycle_ctx(&env, &rev);
        assert_eq!(get(&ctx.kv(), "gt.tenant"), Some(LOCAL_TENANT_FALLBACK));
    }

    #[test]
    fn traffic_split_ctx_stamps_deployment_bundle_and_generation() {
        let env = env_with_owner(Some("acme"));
        let deployment_id = DeploymentId::new();
        let bundle_id = BundleId::new("customer.support");
        let ctx = build_traffic_split_ctx(&env, deployment_id, &bundle_id, 7);
        let kv = ctx.kv();
        assert_eq!(get(&kv, "gt.tenant"), Some("acme"));
        assert_eq!(get(&kv, "gt.env"), Some("prod-eu"));
        assert_eq!(
            get(&kv, "gt.deployment_id"),
            Some(deployment_id.to_string().as_str())
        );
        assert_eq!(get(&kv, "gt.bundle_id"), Some("customer.support"));
        assert_eq!(get(&kv, "gt.generation"), Some("7"));
        // Traffic-split events have no single revision — `gt.revision_id`
        // stays unset (matches the C5.1 cardinality contract for split-
        // level events).
        assert!(get(&kv, "gt.revision_id").is_none());
    }

    /// The `emit_*` wrappers don't panic when no subscriber is installed —
    /// matches the contract `emit_rollout_event` itself guarantees.
    #[test]
    fn emit_helpers_do_not_panic_without_subscriber() {
        let env = env_with_owner(Some("acme"));
        let rev = sample_revision();
        emit_lifecycle_event(RolloutEvent::HealthGatePassed, &env, &rev);
        emit_lifecycle_event(RolloutEvent::HealthGateFailed, &env, &rev);
        emit_lifecycle_event(RolloutEvent::RevisionWarmed, &env, &rev);
        emit_lifecycle_event(RolloutEvent::RevisionDraining, &env, &rev);
        emit_lifecycle_event(RolloutEvent::RevisionEvicted, &env, &rev);
        emit_traffic_split_applied(&env, rev.deployment_id, &rev.bundle_id, 3);
    }
}
