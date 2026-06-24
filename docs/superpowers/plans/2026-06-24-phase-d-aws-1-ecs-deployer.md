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

**Sliced (2026-06-24):** the two codex findings with no wizard/bootstrap
dependency front-load as **PR-3a** (IAM verb parity + concurrent-deploy
idempotency — items 1 & 4 below, SHIPPED); the STS credentials half is
**PR-3b (SHIPPED, #370)**; construction wiring + the remaining ALB findings
(items 2 & 3) is PR-3c.

**PR-3b (✅ SHIPPED, #370):** `bootstrap` now assumes the bound deployer role
(the binding answers' `assume_role_arn`) → returns `Some(bound_*)` as a
serialized `AssumedSession` blob; `rotate_at` decodes the `issued_at`/expiration
window via #366's `rotate_at_from_window` and re-mints at 80%. `--bind` is
dispatched by deployer kind (K8s → AWS → reject) and requires `assume_role_arn`
(unlike K8s, nothing is applied live — the role must pre-exist). The
`AssumedSession` JSON is the forward contract PR-3c's runtime client parses.

**PR-3c sliced again (2026-06-24, 3 sub-PRs; user decisions: F2 = stateless
target-group pool, F1 = per-deployment `ModifyRule`):**

- **PR-3c-1 (✅ SHIPPED, #371):** wizard + params plumbing, no live behavior
  change. `wizard.qaspec.yaml` gains the Fargate launch config + the
  `target_group_arns` pool (comma-separated string answers, matching the
  all-string binding-wizard surface). `FargateLaunchConfig` moves out of the
  feature-gated `real_target` into the always-compiled `deployer` module (pure
  data; `pub use`-re-exported to keep its path) and `AwsEcsParams::from_answers`
  becomes the single parsed home: `launch: Option<FargateLaunchConfig>`
  (all-or-nothing: `execution_role_arn` + `subnets` + `security_groups`) +
  `target_group_pool: Vec<String>` (ARN-or-≤32-char-name validated). Verbs
  ignore both; the generated `target_group` name is untouched (replaced in
  3c-2). Default target stays `UnconfiguredEcsTarget`.
- **PR-3c-2 (NEXT):** construction wiring + the **F2 mechanism**. Build the
  bound-session SDK client (read the `AssumedSession` PR-3b persisted at
  `secret://<env>/…/deployer_session`, static-credentials provider, ambient
  fallback when unbound — the AWS analogue of K8s `resolve_bound_identity`);
  add the AWS branch to the CLI deploy path (`apply-revision` + traffic-split,
  NOT reconcile — AWS is imperative) that builds `RealEcsTarget` from
  `params.launch` + `params.target_group_pool` and injects it via
  `with_target`. F2 mechanism: move the pool onto `RealEcsTarget` (next to
  `FargateLaunchConfig`), drop the deployer-computed `target_group` from the
  seam, and assign each revision a free pool member **statelessly** (read the
  task sets' load-balancer bindings — like the `externalId` rediscovery), so
  blue/green shifts across separate per-revision TGs.
- **PR-3c-3:** the **F1 fix** — per-deployment ALB `ModifyRule` (host/path
  condition from a new wizard routing answer), preserving the default action +
  sibling rules so multiple deployments coexist behind one listener.

**Must also fix (PR-2 codex adversarial review, all valid — deferred here
because the real fixes need PR-3's wizard/bootstrap data, not surface patches):**

1. **IAM preflight ↔ real-target verb parity (F3) — ✅ SHIPPED in PR-3a.**
   `VALIDATED_IAM_VERBS` (`credentials.rs`) gained the 6 missing verbs
   (`ecs:DescribeServices`, `ecs:RegisterTaskDefinition`, `ecs:DescribeTaskSets`,
   `ecs:DeleteTaskSet`, `ecs:DeregisterTaskDefinition`,
   `elasticloadbalancing:DescribeTargetGroups`); the bootstrap rules-pack renders
   from the same list, so it is covered too. `real_target::REAL_ECS_TARGET_IAM_ACTIONS`
   is now the authoritative runtime surface, with a test pinning it ⊆
   `VALIDATED_IAM_VERBS` so a new SDK call without a matching verb fails CI.
2. **Target-group identity, not a 60-char generated name (F2). Contract in
   PR-3c-1; mechanism in PR-3c-2.** `target_group` (`deployer.rs`) renders
   `gtc-tg-<dep_ulid>-<rev_ulid>` = 60 chars, over ELBv2's 32-char limit, AND
   nothing provisions a target group under a deployer-generated name. Decision:
   **operator-provided stateless pool** — the wizard collects
   `target_group_arns` (ARNs or ≤32-char names; PR-3c-1), and `RealEcsTarget`
   assigns each revision a free pool member, read back from the task sets'
   load-balancer bindings (PR-3c-2). Not a shortened generated name.
3. **Per-deployment ALB scoping (F1) → PR-3c-3.** `apply_listener_weights`
   replaces the listener's *default* action (whole-listener ownership), so
   multiple deployments behind one `alb_listener_arn` clobber each other and any
   sibling/auth/redirect action is discarded. Decision: scope the write to a
   per-deployment `ModifyRule` (host/path condition from a new wizard routing
   answer), preserving the default action + sibling rules so deployments coexist
   behind one listener. (PR-2 documents the current ownership constraint on the
   method.)
4. **Idempotency under concurrent deploy — ✅ SHIPPED in PR-3a.**
   `ensure_service` now passes a deterministic `clientToken` (UUID-form, derived
   from the deployment ULID) on `CreateService`, so two `warm_revision` callers
   for the same deployment dedupe instead of one failing — ECS `CreateService`
   has no dedicated already-exists error (a duplicate surfaces as
   `InvalidParameterException`). The describe-then-create stays as a fast path.
   Cross-deploy aliasing within the ECS idempotency window is a PR-4 live-verify
   note.

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

## Open question (for PR-3) — RESOLVED

Should `RealEcsTarget` default to AssumeRole-the-bound-role, or keep the ambient
chain as a dev fallback? **Resolved (PR-3c-2 design):** bound session when the
env's `deployer_session` ref resolves (build the SDK client from the
`AssumedSession` PR-3b minted), ambient chain otherwise — the AWS analogue of
K8s `resolve_bound_identity` (bound bearer vs. ambient kubeconfig).
