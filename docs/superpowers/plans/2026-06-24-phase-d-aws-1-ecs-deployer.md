# Phase D — D-AWS-1: AWS-ECS env-pack `Deployer` (new model)

**Repo:** `greentic-deployer` (single repo)
**Base branch:** `develop`
**Verification:** mock SDK clients in CI; live-account E2E is a single gated PR.

## Goal

Bring the **new-model** AWS-ECS env-pack to K8s parity by implementing the
`Deployer` trait (`src/env_packs/deployer/trait_def.rs`) for
`AwsEcsDeployerHandler`, so `gtc op env apply-revision` / `op deploy` drive real
AWS Fargate infrastructure via the **ECS task-set (EXTERNAL deployment) /
blue-green** model — the AWS-native analogue of the K8s env-pack.

### Context: legacy vs new model

- `2026-04-19-phase-b-4b-4c-aws-ecs-fargate.md` is the **legacy ext/clap path**
  (`src/aws.rs` + `backend_adapter.rs`, Terraform-driven). Shipped. Not this.
- On the **new env-pack model**, AWS was a **C3 stub**: `DeployerCredentials`
  (STS + IAM validate) + IAM-rules `bootstrap`, but `as_deployer()` returned
  `None` ⇒ AWS could not deploy. Closing that gap is D-AWS-1.

## Decisions (locked)

1. **Typed AWS SDK, not runtime Terraform** (bootstrap renders HCL for the
   admin; Greentic never runs `terraform`).
2. **Imperative, not declarative** — AWS implements no `as_manifest_renderer`;
   there is **no `op env render` / `op env reconcile`** for AWS. The deploy path
   is the per-revision verbs + `apply_traffic_split`.
3. **ECS task-set / EXTERNAL deployment model** — one service per
   `deployment_id`, one task set per revision; traffic shifts via weighted ALB
   forward rules across the task-set target groups (`ecs:CreateTaskSet` is in
   the validated IAM verb list).
4. **Seam + in-memory fake** mirroring `K8sCluster` / `InMemoryCluster`. The new
   `EcsDeployTarget` async-trait is the unit-test + conformance seam; the real
   aws-sdk impl is one implementation of it.
5. **Mock SDK clients in CI; real-account E2E is the final gated PR.**
6. **STS AssumeRole session minter lands mid-train (PR-3), with a consumer** —
   the real `EcsDeployTarget` assumes the bound deployer role for a scoped
   session, so it is no longer the consumer-less work flagged at #366.
7. **Feature gating** — seam + fake + verbs are SDK-free (gated `creds-aws`);
   the real `aws-sdk-ecs` / `aws-sdk-elasticloadbalancingv2` client goes behind a
   new default-on `deploy-aws-ecs` feature.

## Architecture

```
AwsEcsDeployerHandler {
    creds:  AwsDeployerCredentials,                  // C3
    target: Arc<dyn EcsDeployTarget>,                // default = UnconfiguredEcsTarget
}
    └─ impl Deployer  (aws/deployer.rs) ─ verbs call the seam
    └─ EnvPackHandler::as_deployer() -> Some(self)   // flipped in PR-1
```

### `EcsDeployTarget` seam (`aws/deploy_target.rs`) — 5 methods

| Method | Used by |
|---|---|
| `ensure_service(ServiceSpec)` (idempotent) | warm |
| `create_task_set(TaskSetSpec) -> TaskSetHandle` (idempotent; registers task-def + creates set) | warm |
| `task_set_stability(TaskSetRef) -> TaskSetStability` | warm wait |
| `delete_task_set(TaskSetRef)` (idempotent; deletes set + deregisters task-def) | archive |
| `apply_listener_weights(ListenerRef, &[TargetGroupWeight])` | apply_traffic_split |

Implementations: `InMemoryEcs` (unit tests + conformance), `UnconfiguredEcsTarget`
(default; fails honestly), `RealEcsTarget` (aws-sdk; PR-2).

### `AwsEcsParams::from_answers(env, answers)`

Reads `region` / `ecs_cluster_name` / `alb_listener_arn` / `ecr_repository_prefix`
/ `container_image_tag_prefix` from the binding's wizard answers (`None` →
sandbox defaults). Unknown keys are rejected (deny-by-default); credential-
scoping knobs (`aws_profile`, `assume_role_arn`) are accepted-and-ignored
(consumed by the client builder in PR-2/PR-3). A malformed blob fails **before
any AWS call**.

### Verb → side-effect

| Verb | AWS side-effect |
|---|---|
| `stage_revision` | no-op (image/bundle delivery is a separate cross-provider slice). |
| `warm_revision` | `ensure_service` + `create_task_set`; wait until the task set stabilizes (steady state + healthy targets), bounded by `GREENTIC_AWS_ECS_WARM_READY_TIMEOUT_SECS`. |
| `drain_revision` | no-op (routing-side; weight shift is `apply_traffic_split`). |
| `archive_revision` | `delete_task_set` (idempotent against absent). |
| `apply_traffic_split` | `enforce_split_invariants` first → when an `alb_listener_arn` is bound, `apply_listener_weights` across the deployment's task-set target groups; with no listener bound the ALB is skipped (dispatcher authoritative). Sibling-deployment independence. |
| `report_runtime_config` | default `materialize_runtime_config`. |

## PR train

### PR-1 — Deployer logic (DONE in this branch)
Seam + `InMemoryEcs` + `UnconfiguredEcsTarget` + `AwsEcsParams` + the full
`Deployer` impl (all verbs, task-set model) + the warm-stability wait + flip
`as_deployer()` → `Some(self)` + the `run_conformance` gate. All against the
in-memory fake — **zero new crate deps**, default `UnconfiguredEcsTarget` keeps
`op deploy` honest until a real target lands. ~3 files, conformance-green.

### PR-2 — `RealEcsTarget` (aws-sdk-backed) — DONE in this branch
New default-on `deploy-aws-ecs` feature + `aws-sdk-ecs` /
`aws-sdk-elasticloadbalancingv2` (region-pinned clients via
`aws_config::defaults(..).region(..)`, mirroring `RealAwsClient::resolve`).
`RealEcsTarget` (in `aws/real_target.rs`, `#[cfg(feature = "deploy-aws-ecs")]`)
implements all five `EcsDeployTarget` methods over the SDK: service
describe/create (EXTERNAL controller), `RegisterTaskDefinition` +
`CreateTaskSet`, `DescribeTaskSets` stability, `DeleteTaskSet` +
`DeregisterTaskDefinition`, and ELBv2 `ModifyListener` weighted forward actions.

**Design — launch config lives on the target, not the seam.** A real
`RegisterTaskDefinition` needs the Fargate launch config (execution/task role
ARNs, subnets, security groups, CPU/memory, container port). That config is
**stable per binding**, not per revision, so it sits on `FargateLaunchConfig`
held by the target — the per-revision seam specs + the `InMemoryEcs` fake stay
untouched. The seam's `(deployment, revision)` identity bridges to ECS's opaque
task-set id via a deterministic `externalId` (set at create, matched on
describe/delete). Target groups route by **name** through the seam; the target
resolves names→ARNs (`DescribeTargetGroups`). `TrafficSplit` basis points
(0–10000) scale to the ELBv2 forward-weight range (0–999), ratio-preserving.

Every request-build + response-parse step is a **pure free function**,
unit-tested with SDK types built via their own builders — **no real AWS in CI**
and **no SDK-HTTP mock dependency** (13 tests). `--no-default-features` +
`creds-aws`-only and the zero-feature baseline stay green (the module is
feature-gated out). `RealEcsTarget::resolve` / `FargateLaunchConfig` are public
API; the default handler target stays `UnconfiguredEcsTarget`.

### PR-3 — STS AssumeRole session minter + construction wiring (deferred half-b)
`bootstrap` assumes the bound deployer role → returns `Some(bound_*)`; override
`rotate_at` to decode the STS session expiry via #366's `rotate_at_from_window`.
**Consumer:** the construction path builds `RealEcsTarget` from the binding —
`FargateLaunchConfig` sourced from new wizard answers (subnets / security groups
/ exec+task role ARNs / cpu / memory / container port, extending
`wizard.qaspec.yaml` + `AwsEcsParams::from_answers`) and the client from the
bound STS session — then injects it via `AwsEcsDeployerHandler::with_target`.

### PR-4 — Live-account proving ground (gated/manual E2E)
Analogue of #364: bootstrap → warm on Fargate → traffic split → archive against a
real account, behind an explicit env gate. Not in the default CI matrix.

## Conformance gate (every PR)

`run_conformance(&handler)` asserts (against the in-memory fake): happy-path +
idempotency on every verb; unknown-revision → `RevisionNotFound`; invalid split
→ `InvalidSplit`; missing split → `SplitNotFound`; cross-deployment independence;
runtime-config projection == `materialize_runtime_config`. PR-1 wires it; every
later PR keeps it green.

## Non-goals

- Bundle/image delivery to the Fargate task (separate cross-provider slice;
  `stage_revision` is a no-op).
- `op env render` / `op env reconcile` for AWS (imperative; no manifest renderer).
- GCP / Azure deployers (separate trains).
- Real AWS in default CI (gated/manual only, PR-4).

## Open question (for PR-3)

Should `RealEcsTarget` default to AssumeRole-the-bound-role, or keep the ambient
chain as a dev fallback? Recommend: bound role when `credentials_ref` resolves,
ambient fallback otherwise (mirrors K8s bound-vs-admin).
