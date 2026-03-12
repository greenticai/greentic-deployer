# Greentic Deployer

`greentic-deployer` is a unified deployer surface over isolated adapter families. Today it contains a stable OSS `single-vm` path and a separate provider-oriented `multi-target` path used for non-single-vm deployment-pack execution.

## Product Scope Note

The current open-source product direction is single-VM deployment only. Broader deployment targets should be treated as commercial/private scope. See [docs/single-vm-v1.md](docs/single-vm-v1.md).

## Concepts

- **Application packs** (`kind: application` or `mixed`) describe flows, components, tools, secrets, tenant bindings, and deployment hints.
- **Deployment plans** (`greentic-types::DeploymentPlan`) are the normalized output of pack introspection.
- **Deployment packs** (`kind: deployment`) consume the deployment plan through `greentic:deploy-plan@1.0.0`.
- **Providers / strategies** map `(provider, strategy)` to `(deployment_pack_id, flow_id)`.
- **Executors** are registered by the host, operator, or control plane and are responsible for invoking the deployment pack.

Adapter families:

- `single-vm`: dedicated OSS adapter for one Linux VM running one active bundle
- `multi-target`: provider-oriented path for cloud/k8s/generic deployment-pack flows
- `aws`: explicit AWS adapter currently using the terraform-backed `iac-only` baseline
- `azure`: explicit Azure adapter currently using the terraform-backed `iac-only` baseline
- `gcp`: explicit GCP adapter currently using the terraform-backed `iac-only` baseline
- `helm`: explicit Helm adapter layered over `multi-target`
- `juju-k8s`: explicit Juju k8s adapter layered over `multi-target`
- `juju-machine`: explicit Juju machine adapter layered over `multi-target`
- `k8s-raw`: explicit raw-manifests k8s adapter layered over `multi-target`
- `operator`: explicit k8s operator adapter layered over `multi-target`
- `serverless`: explicit serverless adapter layered over `multi-target`
- `snap`: explicit Snap adapter layered over `multi-target`
- `terraform`: first explicit adapter layered over `multi-target` with `provider=generic` and `strategy=terraform`

## Building

```bash
cargo build -p greentic-deployer
```

## Nightly

Nightly verification scaffolding now lives in-repo:

- [ci/nightly_matrix.json](ci/nightly_matrix.json)
- [docs/nightly_e2e.md](docs/nightly_e2e.md)
- [scripts/nightly_e2e_stub.sh](scripts/nightly_e2e_stub.sh)

The matrix is the source of truth for target tiers, expected nightly mode
(`execute` vs `handoff`), and the minimum lifecycle steps that should be run
for each adapter.

## Single VM CLI

The current OSS deployment path is single-VM only.

Example spec:

- [examples/single-vm.deployment.yaml](examples/single-vm.deployment.yaml)

Plan:

```bash
cargo run --bin greentic-deployer -- \
  single-vm plan \
  --spec examples/single-vm.deployment.yaml \
  --output yaml
```

Status:

```bash
cargo run --bin greentic-deployer -- \
  single-vm status \
  --spec examples/single-vm.deployment.yaml \
  --output json
```

Apply without live runtime operations:

```bash
cargo run --bin greentic-deployer -- \
  single-vm apply \
  --spec examples/single-vm.deployment.yaml \
  --output json
```

Without `--execute`, `apply` returns a preview/handoff report and does not mutate the host.

Apply and execute runtime operations:

```bash
cargo run --bin greentic-deployer -- \
  single-vm apply \
  --spec examples/single-vm.deployment.yaml \
  --execute \
  --output json
```

Without `--execute`, `destroy` returns a preview/handoff report and does not mutate the host.

With `--execute`, the current implementation will also run:

- `docker pull`
- `systemctl daemon-reload`
- `systemctl enable`
- `systemctl restart`

Destroy without live runtime operations:

```bash
cargo run --bin greentic-deployer -- \
  single-vm destroy \
  --spec examples/single-vm.deployment.yaml \
  --output json
```

Destroy and execute runtime operations:

```bash
cargo run --bin greentic-deployer -- \
  single-vm destroy \
  --spec examples/single-vm.deployment.yaml \
  --execute \
  --output json
```

With `--execute`, the current implementation will also run:

- `systemctl stop`
- `systemctl disable`

Current single-VM execution model:

- Linux `x86_64`
- container-first runtime
- `systemd + docker`
- localhost-only admin HTTPS with mTLS
- readonly bundle mount
- separate writable state/cache/log/temp directories

Persisted single-VM state is written to:

- `<stateDir>/single-vm-state.json`

## Multi-Target CLI

The provider-oriented `multi-target` path is now exposed explicitly as a separate
CLI surface for non-single-vm deployment-pack flows.

Example plan:

```bash
cargo run --bin greentic-deployer -- \
  multi-target plan \
  --provider generic \
  --strategy terraform \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --output json
```

Example preview apply:

```bash
cargo run --bin greentic-deployer -- \
  multi-target apply \
  --provider generic \
  --strategy terraform \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --preview \
  --output json
```

Example local apply execution:

```bash
cargo run --bin greentic-deployer -- \
  terraform apply \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --execute \
  --output json
```

Example preview rollback:

```bash
cargo run --bin greentic-deployer -- \
  multi-target rollback \
  --provider generic \
  --strategy terraform \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --preview \
  --output json
```

## Terraform CLI

`terraform` is the first explicit `multi-target` adapter surface. It keeps the same
underlying deployment-pack flow, but fixes `provider=generic` and
`strategy=terraform` for a simpler operator-facing CLI.

Example plan:

```bash
cargo run --bin greentic-deployer -- \
  terraform plan \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --output json
```

Example preview apply:

```bash
cargo run --bin greentic-deployer -- \
  terraform apply \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --preview \
  --output json
```

Example status:

```bash
cargo run --bin greentic-deployer -- \
  terraform status \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --output json
```

Example preview destroy:

```bash
cargo run --bin greentic-deployer -- \
  terraform destroy \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --preview \
  --output json
```

Example preview rollback:

```bash
cargo run --bin greentic-deployer -- \
  terraform rollback \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.terraform.gtpack \
  --preview \
  --output json
```

`terraform` also accepts optional `--deploy-pack-id` and `--deploy-flow-id` overrides
for local adapter development, matching the lower-level `multi-target` surface.

`terraform apply` and `terraform destroy` remain preview-first by default. The
new `--execute` flag enables a local execution scaffold that runs the
materialized helper scripts from `output_dir`.

When the terraform adapter resolves a provider pack that contains a `terraform/`
subtree, the deployer now materializes that tree into the runtime `output_dir`
and writes helper handoff scripts such as `terraform-init.sh`,
`terraform-plan.sh`, `terraform-apply.sh`, `terraform-destroy.sh`, and
`terraform-status.sh`. It also persists `terraform-runtime.json`, which is used
by text rendering to show a terraform-specific handoff/status summary.

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

For the provider-oriented path, prefer the explicit `multi_target` surface:

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
let result = greentic_deployer::multi_target::run(config).await?;
let _ = result.execution;
```

The stable OSS single-VM path is exposed separately via `greentic_deployer::single_vm`
and `greentic_deployer::surface::single_vm`.

The first explicit multi-target adapter is also exposed as
`greentic_deployer::terraform` and `greentic_deployer::surface::terraform`.

## K8s Raw CLI

`k8s-raw` is the second explicit `multi-target` adapter surface. It fixes
`provider=k8s` and `strategy=raw-manifests`.

Example generate:

```bash
cargo run --bin greentic-deployer -- \
  k8s-raw generate \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.k8s.gtpack \
  --output json
```

Example status:

```bash
cargo run --bin greentic-deployer -- \
  k8s-raw status \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.k8s.gtpack \
  --output json
```

When the provider pack exposes `assets/examples/rendered-manifests.yaml`, the
deployer materializes it into `output_dir/k8s/rendered-manifests.yaml` and also
writes helper handoff scripts such as `kubectl-apply.sh`, `kubectl-delete.sh`,
and `kubectl-status.sh`.

## Helm CLI

`helm` is another explicit `multi-target` adapter surface. It fixes
`provider=k8s` and `strategy=helm`.

Example generate:

```bash
cargo run --bin greentic-deployer -- \
  helm generate \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.helm.gtpack \
  --output json
```

Example status:

```bash
cargo run --bin greentic-deployer -- \
  helm status \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.helm.gtpack \
  --output json
```

When the provider pack contains a Helm chart subtree, the deployer materializes
it into `output_dir/helm-chart` and writes helper handoff scripts such as
`helm-upgrade.sh`, `helm-rollback.sh`, and `helm-status.sh`.

## AWS CLI

`aws` is the first cloud-specific adapter baseline. Today it uses the
terraform-backed `iac-only` path, so it benefits from the same materialized
terraform handoff and local status/apply scaffolding when the provider pack
contains a `terraform/` subtree.

Example generate:

```bash
cargo run --bin greentic-deployer -- \
  aws generate \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.aws.gtpack \
  --output json
```

Example status:

```bash
cargo run --bin greentic-deployer -- \
  aws status \
  --tenant acme \
  --pack examples/acme-pack \
  --provider-pack path/to/greentic.deploy.aws.gtpack \
  --output json
```

The same terraform-backed cloud baseline is also exposed as `gcp` and `azure`.

## Snap CLI

`snap` is an explicit local packaging/deployment adapter surface. It currently
materializes the provider-pack `snap/` subtree into `output_dir/snap` and
writes helper scripts such as `snap-install.sh`, `snap-remove.sh`, and
`snap-status.sh`.

## Juju Machine CLI

`juju-machine` is an explicit Juju machine adapter surface. It currently
materializes the provider-pack `charm/` subtree into `output_dir/juju-machine-charm`
and writes helper scripts such as `juju-machine-deploy.sh`,
`juju-machine-remove.sh`, and `juju-machine-status.sh`.

## Juju K8s CLI

`juju-k8s` is an explicit Juju k8s adapter surface. It currently materializes
the provider-pack `charm/` subtree into `output_dir/juju-k8s-charm` and writes
helper scripts such as `juju-k8s-deploy.sh`, `juju-k8s-remove.sh`, and
`juju-k8s-status.sh`.

## Operator CLI

`operator` is an explicit k8s adapter surface for operator-style deployments.
Today it uses a manifest handoff baseline and materializes
`output_dir/operator/rendered-manifests.yaml` plus helper scripts such as
`operator-apply.sh`, `operator-delete.sh`, and `operator-status.sh`.

## Serverless CLI

`serverless` is an explicit serverless adapter surface. Today it materializes
`output_dir/serverless/deployment-descriptor.json` and helper scripts such as
`serverless-deploy.sh` and `serverless-status.sh` when the provider pack
includes the serverless fixture descriptor.
