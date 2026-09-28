//! `op env drain-revision`, `op env sweep`, `op env capabilities`, and the
//! archive-time drain gate `op env apply-revision` runs (P5-R2 / P5-R3).
//!
//! - **drain-revision** runs the bound deployer's enforced drain against the
//!   live provider: wait the revision's `drain_seconds` (capped by
//!   `GREENTIC_DEPLOYER_DRAIN_MAX_SECONDS`), then confirm it serves nothing.
//! - **apply-revision** on an absent revision (the archive branch) first asks
//!   the deployer to confirm the revision is drained RIGHT NOW, and refuses
//!   with [`OpError::NotDrained`] naming the revision unless `--force-drain`.
//! - **sweep** (K8s) removes worker objects the deployer labeled whose
//!   revision is absent from the store. Dry-run unless `--apply`.
//! - **capabilities** reports the bound adapter's capability flags. A verb
//!   needing a capability the adapter lacks is refused with the name.

use greentic_deploy_spec::{CapabilitySlot, EnvId, Environment, PackDescriptor, RevisionId};
use serde_json::{Value, json};

use super::dispatch::{EnvDrainRevisionArgs, EnvSweepArgs};
use super::env::{load_render_answers, resolve_live_deployer_kind};
use super::{OpError, OpFlags, OpOutcome};
use crate::env_packs::deployer::{
    Capability, CapabilityReport, Deployer, DeployerError, DrainEvidence,
};
use crate::env_packs::{EnvPackHandler, EnvPackRegistry};
use crate::environment::{EnvironmentStore, LocalFsStore};

const NOUN: &str = "env";

/// Map a deployer failure onto the CLI error, keeping `NotDrained` typed.
pub(crate) fn drain_error(err: DeployerError) -> OpError {
    match err {
        DeployerError::NotDrained {
            revision_id,
            reason,
        } => OpError::NotDrained {
            revision_id: revision_id.to_string(),
            reason,
        },
        other => OpError::Conflict(other.to_string()),
    }
}

/// Map a sweep preflight refusal onto the CLI error; a missing permission
/// stays typed (`permission-missing`) and names the re-bootstrap.
pub(crate) fn preflight_error(err: crate::env_packs::k8s::sweep::SweepPreflightError) -> OpError {
    use crate::env_packs::k8s::sweep::SweepPreflightError;
    match err {
        e @ SweepPreflightError::MissingPermission { .. } => {
            OpError::PermissionMissing(e.to_string())
        }
        e @ SweepPreflightError::ReviewFailed(_) => OpError::Conflict(e.to_string()),
    }
}

/// The archive-time drain gate. `force` skips the check (loudly).
pub(crate) async fn archive_drain_gate<D: Deployer + ?Sized>(
    deployer: &D,
    env: &Environment,
    revision_id: RevisionId,
    answers: Option<&Value>,
    force: bool,
) -> Result<DrainEvidence, OpError> {
    if force {
        tracing::warn!(
            revision_id = %revision_id,
            "--force-drain: archiving without confirming the revision is drained"
        );
        return Ok(DrainEvidence::Unsupported);
    }
    deployer
        .confirm_drained(env, revision_id, answers)
        .await
        .map_err(drain_error)
}

fn load_env(store: &LocalFsStore, env_id: &str) -> Result<(EnvId, Environment), OpError> {
    let env_id =
        EnvId::try_from(env_id).map_err(|e| OpError::InvalidArgument(format!("env_id: {e}")))?;
    if !store.exists(&env_id)? {
        return Err(OpError::NotFound(format!("environment `{env_id}`")));
    }
    let env = store.load(&env_id)?;
    Ok((env_id, env))
}

fn deployer_of<'r>(
    registry: &'r EnvPackRegistry,
    descriptor: &PackDescriptor,
) -> Result<&'r dyn Deployer, OpError> {
    let handler: &dyn EnvPackHandler = registry
        .resolve_for_slot(CapabilitySlot::Deployer, descriptor)
        .map_err(|e| OpError::Conflict(e.to_string()))?;
    handler.as_deployer().ok_or_else(|| {
        OpError::Conflict(format!(
            "env-pack `{}` does not implement the Deployer contract",
            descriptor.path()
        ))
    })
}

fn is_k8s(descriptor: &PackDescriptor) -> bool {
    descriptor.path() == crate::env_packs::k8s::K8sDeployerHandler::DESCRIPTOR_PATH
}

fn parse_revision(env: &Environment, raw: &str) -> Result<RevisionId, OpError> {
    use std::str::FromStr;
    let ulid = ulid::Ulid::from_str(raw)
        .map_err(|e| OpError::InvalidArgument(format!("revision_id: {e}")))?;
    let revision_id = RevisionId(ulid);
    if env.revisions.iter().any(|r| r.revision_id == revision_id) {
        Ok(revision_id)
    } else {
        Err(OpError::NotFound(format!(
            "revision `{revision_id}` not found in env `{}`",
            env.environment_id
        )))
    }
}

/// `op env capabilities <env_id> [--kind]`.
pub fn capabilities(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    env_id: &str,
    kind: Option<&str>,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "capabilities",
            json!({"input_schema": "env_id positional; --kind optional"}),
        ));
    }
    let (_, env) = load_env(store, env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, kind)?;
    let deployer = deployer_of(registry, &descriptor)?;
    let report = CapabilityReport::new(
        descriptor.path(),
        deployer.capabilities(),
        deployer.capability_notes(),
    );
    let mut result = serde_json::to_value(report)
        .map_err(|e| OpError::Conflict(format!("capability report: {e}")))?;
    result["environment_id"] = json!(env.environment_id.as_str());
    Ok(OpOutcome::new(NOUN, "capabilities", result))
}

/// Capability report for the env's resolvable deployer binding, for
/// `op env doctor`. `None` when nothing resolves (doctor reports that).
pub(crate) fn doctor_capabilities(registry: &EnvPackRegistry, env: &Environment) -> Value {
    let Some(binding) = env.pack_for_slot(CapabilitySlot::Deployer) else {
        return Value::Null;
    };
    match deployer_of(registry, &binding.kind) {
        Ok(d) => serde_json::to_value(CapabilityReport::new(
            binding.kind.path(),
            d.capabilities(),
            d.capability_notes(),
        ))
        .unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

/// `op env drain-revision <env_id> <revision_id> [--kind]`.
pub fn drain_revision(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    args: EnvDrainRevisionArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "drain-revision",
            json!({"input_schema": "env_id + revision_id positional; --kind optional"}),
        ));
    }
    let (env_id, env) = load_env(store, &args.env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, args.kind.as_deref())?;
    deployer_of(registry, &descriptor)?
        .capabilities()
        .require(descriptor.path(), Capability::Drain)?;
    let revision_id = parse_revision(&env, &args.revision_id)?;
    let (answers, _) = load_render_answers(store, &env, &descriptor)?;
    let outcome = live::drain(store, &env, &env_id, &descriptor, revision_id, answers)?;
    Ok(OpOutcome::new(
        NOUN,
        "drain-revision",
        json!({
            "environment_id": env.environment_id.as_str(),
            "kind": descriptor.as_str(),
            "revision_id": revision_id.to_string(),
            "waited_seconds": outcome.waited_seconds,
            "evidence": outcome.evidence,
        }),
    ))
}

/// `op env sweep <env_id> [--apply] [--kind]`.
pub fn sweep(
    store: &LocalFsStore,
    registry: &EnvPackRegistry,
    flags: &OpFlags,
    args: EnvSweepArgs,
) -> Result<OpOutcome, OpError> {
    if flags.schema_only {
        return Ok(OpOutcome::new(
            NOUN,
            "sweep",
            json!({"input_schema": "env_id positional; --apply to delete (dry-run by default)"}),
        ));
    }
    let (env_id, env) = load_env(store, &args.env_id)?;
    let descriptor = resolve_live_deployer_kind(&env, args.kind.as_deref())?;
    deployer_of(registry, &descriptor)?
        .capabilities()
        .require(descriptor.path(), Capability::Remove)?;
    if !is_k8s(&descriptor) {
        return Err(OpError::Conflict(format!(
            "`op env sweep` reclaims label-owned K8s workers; deployer `{}` has no \
             label-scoped listing",
            descriptor.path()
        )));
    }
    let (answers, _) = load_render_answers(store, &env, &descriptor)?;
    let report = live::sweep_k8s(store, &env, &env_id, answers, args.apply)?;
    let mut result = serde_json::to_value(report)
        .map_err(|e| OpError::Conflict(format!("sweep report: {e}")))?;
    result["environment_id"] = json!(env.environment_id.as_str());
    Ok(OpOutcome::new(NOUN, "sweep", result))
}

/// Live-provider dispatch. Each backend connects exactly as `apply-revision`
/// does (bound identity when one is bound, ambient otherwise).
mod live {
    use super::*;
    use crate::env_packs::deployer::DrainOutcome;
    use crate::env_packs::k8s::sweep::SweepReport;

    pub(super) fn drain(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        descriptor: &PackDescriptor,
        revision_id: RevisionId,
        answers: Option<Value>,
    ) -> Result<DrainOutcome, OpError> {
        if is_k8s(descriptor) {
            return drain_k8s(store, env, env_id, revision_id, answers);
        }
        #[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
        if super::super::env::is_cloudrun_kind(descriptor) {
            return drain_cloudrun(store, env, env_id, revision_id, answers);
        }
        Err(OpError::Conflict(format!(
            "this build cannot drain deployer `{}` live",
            descriptor.path()
        )))
    }

    /// Connect a K8s handler for `env` (bound token when bound).
    #[cfg(feature = "k8s-client")]
    async fn k8s_handler(
        kubeconfig_context: Option<String>,
        bound_token: Option<String>,
    ) -> Result<(crate::env_packs::k8s::K8sDeployerHandler, kube::Client), OpError> {
        use crate::env_packs::k8s::kube_client::connect;
        use crate::env_packs::k8s::{K8sDeployerHandler, KubeCluster};
        let client = connect(kubeconfig_context.as_deref(), bound_token.as_deref())
            .await
            .map_err(|e| OpError::Conflict(format!("cannot reach the cluster: {e}")))?;
        let handler =
            K8sDeployerHandler::with_cluster(std::sync::Arc::new(KubeCluster::new(client.clone())));
        Ok((handler, client))
    }

    #[cfg(feature = "k8s-client")]
    fn k8s_inputs(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        answers: Option<&Value>,
    ) -> Result<(Option<String>, Option<String>), OpError> {
        use crate::env_packs::k8s::manifests::kubeconfig_context_from_answers;
        let token = crate::env_packs::k8s::resolve_bound_identity(store, env, env_id, answers)?;
        Ok((kubeconfig_context_from_answers(answers), token))
    }

    #[cfg(feature = "k8s-client")]
    fn drain_k8s(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        revision_id: RevisionId,
        answers: Option<Value>,
    ) -> Result<DrainOutcome, OpError> {
        use crate::env_packs::k8s::async_bridge::run_k8s_async;
        let (context, token) = k8s_inputs(store, env, env_id, answers.as_ref())?;
        run_k8s_async(async move {
            let (handler, _) = k8s_handler(context, token).await?;
            handler
                .drain_revision(env, revision_id, answers.as_ref())
                .await
                .map_err(drain_error)
        })
    }

    #[cfg(not(feature = "k8s-client"))]
    fn drain_k8s(
        _store: &LocalFsStore,
        _env: &Environment,
        _env_id: &EnvId,
        _revision_id: RevisionId,
        _answers: Option<Value>,
    ) -> Result<DrainOutcome, OpError> {
        Err(no_k8s_client())
    }

    #[cfg(not(feature = "k8s-client"))]
    fn no_k8s_client() -> OpError {
        OpError::Conflict(
            "this build was compiled without the `k8s-client` feature; it cannot reach a cluster"
                .to_string(),
        )
    }

    #[cfg(feature = "k8s-client")]
    pub(super) fn sweep_k8s(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        answers: Option<Value>,
        apply: bool,
    ) -> Result<SweepReport, OpError> {
        use crate::env_packs::k8s::async_bridge::run_k8s_async;
        use crate::env_packs::k8s::kube_client::KubeValidatorClient;
        use crate::env_packs::k8s::manifests::K8sParams;
        use crate::env_packs::k8s::sweep::require_sweep_access;
        let (context, token) = k8s_inputs(store, env, env_id, answers.as_ref())?;
        let namespace = K8sParams::from_answers(env, answers.as_ref())
            .map_err(|e| OpError::InvalidArgument(format!("invalid answers: {e}")))?
            .namespace;
        run_k8s_async(async move {
            let (handler, client) = k8s_handler(context, token).await?;
            // Check `list` BEFORE listing: a Role bootstrapped before the sweep
            // existed lacks it, and `credentials requirements` does not probe it.
            require_sweep_access(
                &KubeValidatorClient::new(client),
                env.environment_id.as_str(),
                &namespace,
            )
            .await
            .map_err(preflight_error)?;
            handler
                .sweep(env, answers.as_ref(), apply)
                .await
                .map_err(|e| OpError::Conflict(e.to_string()))
        })
    }

    #[cfg(not(feature = "k8s-client"))]
    pub(super) fn sweep_k8s(
        _store: &LocalFsStore,
        _env: &Environment,
        _env_id: &EnvId,
        _answers: Option<Value>,
        _apply: bool,
    ) -> Result<SweepReport, OpError> {
        Err(no_k8s_client())
    }

    #[cfg(all(feature = "creds-gcp", feature = "deploy-gcp-cloudrun"))]
    fn drain_cloudrun(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        revision_id: RevisionId,
        answers: Option<Value>,
    ) -> Result<DrainOutcome, OpError> {
        use crate::env_packs::gcp_cloudrun::credentials::run_gcp_async;
        let (_identity, params, credentials) =
            super::super::env::cloudrun_target_inputs(store, env, env_id, answers.as_ref())?;
        run_gcp_async(async move {
            let handler = super::super::env::resolve_cloudrun_handler(
                &params.project,
                &params.region,
                credentials,
                None,
            )
            .await?;
            handler
                .drain_revision(env, revision_id, answers.as_ref())
                .await
                .map_err(drain_error)
        })
    }
}

#[cfg(test)]
#[path = "env_drain_tests.rs"]
mod tests;
