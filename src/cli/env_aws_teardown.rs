//! `op env destroy` for an AWS-ECS environment: resolve the real ECS target
//! from the binding and hand it to the target-generic
//! [`teardown_environment`](crate::env_packs::aws::teardown::teardown_environment).
//! Only compiled with the live AWS client; a build without it refuses the
//! destroy through the store (`ProviderTeardownUnavailable`).

use serde_json::Value;

use crate::env_packs::aws::credentials::run_aws_async;
use crate::env_packs::aws::real_target::RealEcsTarget;
use crate::env_packs::aws::teardown::teardown_environment;
use crate::environment::{ProviderTeardown, ProviderTeardownCtx, StoreError};

/// Store-injected teardown of an ECS env, run under the destroy flock before the
/// local state is purged. Idempotent, so a destroy retried after a partial
/// failure converges.
pub(super) struct EcsProviderTeardown;

impl ProviderTeardown for EcsProviderTeardown {
    fn teardown(&self, ctx: ProviderTeardownCtx<'_>) -> Result<Value, StoreError> {
        let fail = |what: &str, e: &dyn std::fmt::Display| {
            StoreError::ProviderTeardown(format!("{what}: {e}"))
        };
        // Same inputs the deploy path uses; fails closed on an unreadable bound
        // session or a binding with no launch config.
        let inputs = super::env::aws_ecs_target_inputs(ctx.store, ctx.env, ctx.env_id, ctx.answers)
            .map_err(|e| fail("resolving the aws-ecs binding", &e))?;
        let params = inputs.params;
        let deployment_ids = ctx.deployment_ids.to_vec();
        let env_id = ctx.env_id.as_str().to_string();
        run_aws_async(async move {
            let target = RealEcsTarget::resolve(
                &params.region,
                inputs.launch,
                params.target_group_pool.clone(),
                inputs.session,
            )
            .await
            .map_err(|e| fail("cannot initialize the AWS ECS deployer client", &e))?;
            teardown_environment(&target, &params, &env_id, &deployment_ids)
                .await
                .map_err(|e| fail("tearing down the aws-ecs environment", &e))
        })
    }
}
