# Greentic Deployer

`greentic-deployer` is a library that builds provider-agnostic deployment plans for Greentic application packs, resolves deployment-pack targets, and persists the runtime metadata an operator or control plane needs to execute those deployment packs.

## Concepts

- **Application packs** (`kind: application` or `mixed`) describe flows, components, tools, secrets, tenant bindings, and deployment hints.
- **Deployment plans** (`greentic-types::DeploymentPlan`) are the normalized output of pack introspection.
- **Deployment packs** (`kind: deployment`) consume the deployment plan through `greentic:deploy-plan@1.0.0`.
- **Providers / strategies** map `(provider, strategy)` to `(deployment_pack_id, flow_id)`.
- **Executors** are registered by the host, operator, or control plane and are responsible for invoking the deployment pack.

## Building

```bash
cargo build -p greentic-deployer
```

## Runtime behavior

- The runtime is capability-first: deployment packs can declare `generate`, `plan`, `apply`, `destroy`, `status`, and `rollback`.
- `plan` builds the deployment plan, resolves the deployment pack, writes runtime metadata, and returns a typed plan payload.
- `generate`, `status`, and `rollback` return typed contract-backed payloads even without an executor.
- `apply` and `destroy` return typed handoff payloads in preview mode and use the registered executor when execution is enabled.
- Executed operations keep the same typed payloads and also include an execution report with executor outcomes when available.

Runtime artifacts are written to:

- `deploy/<provider>/<tenant>/<environment>/._deployer_invocation.json`
- `deploy/<provider>/<tenant>/<environment>/._runner_cmd.txt`
- `.greentic/state/runtime/<tenant>/<environment>/plan.json`
- `.greentic/state/runtime/<tenant>/<environment>/invoke.json`

## Configuration

- Configuration is resolved via `greentic-config` with precedence `request > env > project (.greentic/config.toml) > user (~/.config/greentic/config.toml) > defaults`.
- `DeployerRequest.config_path` replaces project discovery with an explicit config file.
- `DeployerRequest.allow_remote_in_offline` overrides the offline guard for distributor-backed pack resolution.
- `deployer.base_domain` controls the domain used for OAuth redirect URLs and ingress hints.

## Deployment packs

Deployment packs own:

- operation schemas
- execution-result schemas
- planner inputs and outputs
- dispatch metadata
- provider-specific validation
- examples, fixtures, and wizard questions

The deployer library does not own target-specific prompts or provider execution logic.

See [docs/deployment-packs.md](/projects/ai/greentic-ng/greentic-deployer/docs/deployment-packs.md) for the runtime contract and authoring model.

## Embedding

```rust
use std::path::PathBuf;
use std::sync::Arc;

use greentic_deployer::config::{DeployerConfig, DeployerRequest, Provider};
use greentic_deployer::contract::DeployerCapability;
use greentic_deployer::deployment::{
    self, DeploymentDispatch, DeploymentExecutor, ExecutionOutcome,
};

struct RunnerExecutor;

#[async_trait::async_trait]
impl DeploymentExecutor for RunnerExecutor {
    async fn execute(
        &self,
        config: &greentic_deployer::DeployerConfig,
        plan: &greentic_deployer::plan::PlanContext,
        dispatch: &DeploymentDispatch,
    ) -> greentic_deployer::Result<ExecutionOutcome> {
        let _ = (config, plan, dispatch);
        Ok(ExecutionOutcome::default())
    }
}

let request = DeployerRequest::new(
    DeployerCapability::Plan,
    Provider::Aws,
    "acme",
    PathBuf::from("examples/acme-pack"),
);
let config = DeployerConfig::resolve(request)?;
deployment::set_deployment_executor(Arc::new(RunnerExecutor));
let result = greentic_deployer::apply::run(config).await?;
let _ = result.execution;
```
