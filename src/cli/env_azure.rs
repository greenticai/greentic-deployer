//! CLI glue for the Azure Container Apps env-pack: resolve the service principal
//! and params, build the live target, drive the verbs. Only the live path needs
//! `deploy-azure-aca`; a build without it refuses by name.

use greentic_deploy_spec::{EnvId, Environment, RevisionId};
use serde_json::Value;

use super::OpError;
use super::env::RevisionVerb;
use crate::environment::LocalFsStore;

/// Descriptor path, known in every build.
pub(crate) const AZURE_ACA_DEPLOYER_PATH: &str = "greentic.deployer.azure-aca";

pub(crate) const NO_DEPLOY_FEATURE: &str = "this build was compiled without the \
     `deploy-azure-aca` feature; it cannot deploy an Azure Container Apps environment";

#[cfg(all(feature = "creds-azure", feature = "deploy-azure-aca"))]
pub(super) use live::{AcaProviderTeardown, apply_revision_azure, apply_traffic_azure};

#[cfg(not(all(feature = "creds-azure", feature = "deploy-azure-aca")))]
pub(super) fn apply_revision_azure(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _revision_id: RevisionId,
    _verb: RevisionVerb,
    _answers: Option<&Value>,
) -> Result<(&'static str, String, Option<String>), OpError> {
    Err(OpError::Conflict(NO_DEPLOY_FEATURE.to_string()))
}

#[cfg(not(all(feature = "creds-azure", feature = "deploy-azure-aca")))]
pub(super) fn apply_traffic_azure(
    _store: &LocalFsStore,
    _env: &Environment,
    _env_id: &EnvId,
    _deployment_id: greentic_deploy_spec::DeploymentId,
    _answers: Option<&Value>,
) -> Result<
    (
        &'static str,
        crate::env_packs::deployer::TrafficSplitOutcome,
    ),
    OpError,
> {
    Err(OpError::Conflict(NO_DEPLOY_FEATURE.to_string()))
}

#[cfg(all(feature = "creds-azure", feature = "deploy-azure-aca"))]
mod live {
    use std::sync::Arc;

    use serde_json::Value;

    use super::*;
    use crate::env_packs::azure_aca::arm_paths::AzureScope;
    use crate::env_packs::azure_aca::credentials::run_async;
    use crate::env_packs::azure_aca::real_target::RealAcaTarget;
    use crate::env_packs::azure_aca::reqwest_http::ReqwestHttp;
    use crate::env_packs::azure_aca::teardown::teardown_environment;
    use crate::env_packs::azure_aca::token::ClientCredentials;
    use crate::env_packs::azure_aca::{AcaParams, AzureAcaDeployerHandler, bound_session, naming};
    use crate::env_packs::deployer::Deployer;
    use crate::environment::{ProviderTeardown, ProviderTeardownCtx, StoreError};

    #[cfg(test)]
    pub(crate) mod aca_target_seam {
        //! Test-only replacement of the live target, keyed by subscription id.
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};

        use crate::env_packs::azure_aca::deploy_target::AcaDeployTarget;

        static TARGETS: Mutex<BTreeMap<String, Arc<dyn AcaDeployTarget>>> =
            Mutex::new(BTreeMap::new());

        pub(crate) struct Installed(String);

        impl Drop for Installed {
            fn drop(&mut self) {
                if let Ok(mut m) = TARGETS.lock() {
                    m.remove(&self.0);
                }
            }
        }

        pub(crate) fn install(subscription: &str, t: Arc<dyn AcaDeployTarget>) -> Installed {
            if let Ok(mut m) = TARGETS.lock() {
                m.insert(subscription.to_string(), t);
            }
            Installed(subscription.to_string())
        }

        pub(super) fn lookup(subscription: &str) -> Option<Arc<dyn AcaDeployTarget>> {
            TARGETS.lock().ok()?.get(subscription).cloned()
        }
    }

    pub(in crate::cli) struct AzureTargetInputs {
        pub identity: &'static str,
        pub params: AcaParams,
        pub creds: ClientCredentials,
    }

    /// Parse the binding answers and resolve the principal (bound, else ambient).
    /// Fails closed before any Azure call.
    pub(in crate::cli) fn azure_target_inputs(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        answers: Option<&Value>,
    ) -> Result<AzureTargetInputs, OpError> {
        let params = AcaParams::from_answers(answers)
            .map_err(|e| OpError::Conflict(format!("invalid azure-aca binding answers: {e}")))?;
        #[cfg(test)]
        if aca_target_seam::lookup(&params.subscription_id).is_some() {
            let creds = ClientCredentials::new("t", "c", "test-secret", None);
            return Ok(AzureTargetInputs {
                identity: "bound",
                params,
                creds,
            });
        }
        let (identity, creds) = bound_session::resolve(store, env, env_id)?;
        Ok(AzureTargetInputs {
            identity,
            params,
            creds,
        })
    }

    pub(in crate::cli) fn build_target(
        inputs: &AzureTargetInputs,
    ) -> Result<Arc<dyn crate::env_packs::azure_aca::deploy_target::AcaDeployTarget>, OpError> {
        #[cfg(test)]
        if let Some(fake) = aca_target_seam::lookup(&inputs.params.subscription_id) {
            return Ok(fake);
        }
        let scope = AzureScope {
            subscription: inputs.params.subscription_id.clone(),
            resource_group: inputs.params.resource_group.clone(),
            environment: inputs.params.environment_name.clone(),
        };
        let http = ReqwestHttp::new(inputs.creds.clone())
            .map_err(|e| OpError::Conflict(format!("cannot initialize the Azure client: {e}")))?;
        Ok(Arc::new(RealAcaTarget::new(Arc::new(http), scope)))
    }

    fn bridge<T: Send>(
        fut: impl std::future::Future<Output = Result<T, OpError>> + Send,
    ) -> Result<T, OpError> {
        run_async(fut).map_err(OpError::Conflict)?
    }

    pub(in crate::cli) fn apply_revision_azure(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        revision_id: RevisionId,
        verb: RevisionVerb,
        answers: Option<&Value>,
    ) -> Result<(&'static str, String, Option<String>), OpError> {
        let revision = env
            .revisions
            .iter()
            .find(|r| r.revision_id == revision_id)
            .ok_or_else(|| {
                OpError::NotFound(format!(
                    "revision `{revision_id}` is not part of environment `{env_id}`"
                ))
            })?;
        let worker_name = naming::app_name(&revision.deployment_id)
            .as_str()
            .to_string();
        let inputs = azure_target_inputs(store, env, env_id, answers)?;
        let identity = inputs.identity;
        // Dev store as seed material only on a warm, and only when the env
        // resolves `secret://` against the dev store (same guard as Cloud Run).
        let dev_secrets =
            if verb == RevisionVerb::Warm && super::super::env::env_stages_dev_secrets(env) {
                super::super::env::read_dev_secrets_bytes(store, env_id)?
            } else {
                None
            };
        let target = build_target(&inputs)?;
        let endpoint = bridge(async move {
            let handler = AzureAcaDeployerHandler::with_target_and_dev_secrets(target, dev_secrets);
            match verb {
                RevisionVerb::Warm => handler
                    .warm_revision(env, revision_id, answers)
                    .await
                    .map(|o| o.endpoint_url),
                RevisionVerb::Drain => handler
                    .drain_revision(env, revision_id, answers)
                    .await
                    .map(|_| None),
                RevisionVerb::Archive => handler
                    .archive_revision(env, revision_id, answers)
                    .await
                    .map(|_| None),
            }
            .map_err(|e| OpError::Conflict(e.to_string()))
        })?;
        Ok((identity, worker_name, endpoint))
    }

    pub(in crate::cli) fn apply_traffic_azure(
        store: &LocalFsStore,
        env: &Environment,
        env_id: &EnvId,
        deployment_id: greentic_deploy_spec::DeploymentId,
        answers: Option<&Value>,
    ) -> Result<
        (
            &'static str,
            crate::env_packs::deployer::TrafficSplitOutcome,
        ),
        OpError,
    > {
        crate::cli::env::preflight_split_granularity(
            env,
            crate::env_packs::azure_aca::deployer::WEIGHT_GRANULARITY_BPS,
            "Container Apps",
            "1%",
            Some(deployment_id),
        )?;
        let inputs = azure_target_inputs(store, env, env_id, answers)?;
        let identity = inputs.identity;
        let target = build_target(&inputs)?;
        let outcome = bridge(async move {
            let handler = AzureAcaDeployerHandler::with_target_and_dev_secrets(target, None);
            handler
                .apply_traffic_split(env, deployment_id, answers)
                .await
                .map_err(|e| OpError::Conflict(e.to_string()))
        })?;
        Ok((identity, outcome))
    }

    /// Store-injected teardown, run under the destroy flock.
    pub(crate) struct AcaProviderTeardown;

    impl ProviderTeardown for AcaProviderTeardown {
        fn teardown(&self, ctx: ProviderTeardownCtx<'_>) -> Result<Value, StoreError> {
            let fail = |what: &str, e: &dyn std::fmt::Display| {
                StoreError::ProviderTeardown(format!("{what}: {e}"))
            };
            let inputs = azure_target_inputs(ctx.store, ctx.env, ctx.env_id, ctx.answers)
                .map_err(|e| fail("resolving the azure-aca binding", &e))?;
            let target = build_target(&inputs)
                .map_err(|e| fail("cannot initialize the Azure client", &e))?;
            let ids = ctx.deployment_ids.to_vec();
            let env_id = ctx.env_id.as_str().to_string();
            let (sub, rg) = (
                inputs.params.subscription_id.clone(),
                inputs.params.resource_group.clone(),
            );
            let mut report =
                run_async(
                    async move { teardown_environment(target.as_ref(), &env_id, &ids).await },
                )
                .map_err(|e| fail("running the teardown", &e))?
                .map_err(|e| fail("tearing down the azure-aca environment", &e))?;
            report["subscription"] = Value::String(sub);
            report["resource_group"] = Value::String(rg);
            Ok(report)
        }
    }

    #[cfg(test)]
    pub(crate) use aca_target_seam::install as install_target;
}

#[cfg(all(test, feature = "creds-azure", feature = "deploy-azure-aca"))]
pub(crate) use live::install_target;
