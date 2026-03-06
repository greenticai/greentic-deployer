# Deployment Packs

Deployment packs extend `greentic-deployer` without changing the deployer itself. They are normal Greentic packs with:

- `kind: "deployment"`
- one or more `type: events` deployment flows
- components that support `greentic:deploy-plan@1.0.0`
- host permissions for the assets they need to emit

## Runtime contract

`greentic-deployer` does four things:

1. loads the application pack
2. builds a provider-agnostic `DeploymentPlan`
3. resolves `(provider, strategy)` to `(deployment_pack_id, flow_id)`
4. persists runtime metadata and hands execution to a registered deployment executor

The deployer itself no longer contains provider-specific execution backends. Actual deployment execution belongs to the registered executor, which will typically invoke `greentic-runner`.
The deployment pack owns planner inputs, planner behavior, and the dispatch metadata the operator uses to invoke each supported capability.

`greentic.deployer.v1` currently supports:

- planner input/output schemas
- per-capability input/output schemas
- per-capability execution-result schemas
- QA spec refs
- example asset refs
- per-capability flow dispatch

## Provider and strategy mapping

Targets are keyed by:

- `provider`
- `strategy`

That pair resolves to:

- `pack_id`
- `flow_id`

You can override mappings with environment variables:

- `DEPLOY_TARGET_<PROVIDER>_<STRATEGY>_PACK_ID`
- `DEPLOY_TARGET_<PROVIDER>_<STRATEGY>_FLOW_ID`
- `DEPLOY_TARGET_<PROVIDER>_PACK_ID`
- `DEPLOY_TARGET_<PROVIDER>_FLOW_ID`

## Executor handoff

When the deployer resolves a deployment pack it writes:

- `deploy/<provider>/<tenant>/<environment>/._deployer_invocation.json`
- `deploy/<provider>/<tenant>/<environment>/._runner_cmd.txt`
- `.greentic/state/runtime/<tenant>/<environment>/plan.json`
- `.greentic/state/runtime/<tenant>/<environment>/invoke.json`

These files are the stable handoff point for external runners and control planes.

At runtime the library returns:

- typed operator payloads for `generate`, `plan`, `apply`, `destroy`, `status`, and `rollback`
- `output_validation` for pre-execution payloads validated against pack-owned output schemas
- `execution` reports for executed operations
- `outcome_validation` for executor-returned payloads validated against pack-owned execution schemas

## Authoring notes

- keep deployment logic inside the deployment pack, not in the deployer binary
- keep planner and dispatch ownership inside the deployment pack, not in the deployer binary
- keep execution result schemas inside the deployment pack, not in the deployer binary
- consume the normalized deployment plan rather than application-pack internals directly
- emit provider-specific assets through host capabilities exposed by the executor environment
- treat the deployer as the planner and dispatcher, not the infrastructure engine
