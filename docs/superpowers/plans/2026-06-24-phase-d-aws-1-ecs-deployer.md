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
- **PR-3c-2 (NEXT — sub-sliced into 3c-2a then 3c-2b, 2026-06-24, user
  decision):** construction wiring + the **F2 mechanism**, split into the
  pure seam/provider half and the live-wiring half.
  - **PR-3c-2a (the F2 seam + mechanism, no creds, no CLI, no live path):**
    drop the deployer-computed `target_group` from the `EcsDeployTarget` seam
    (`TaskSetSpec` + `TargetGroupWeight` lose the field; `AwsEcsParams::target_group`
    is removed); the handler stops computing per-revision TG names. Move the
    pool onto `RealEcsTarget` (next to `FargateLaunchConfig`; `resolve` gains a
    `target_group_pool` arg). Assign each revision a free pool member
    **statelessly** in `create_task_set` (read the live task sets'
    load-balancer bindings via the `describe_task_sets` it already calls →
    which pool ARNs are taken → pick a free one), and in `apply_listener_weights`
    map each weighted revision → its task set's bound TG ARN (no name lookup —
    the binding carries the ARN). The mechanism lives in pure free helpers
    (`assigned_pool_members` / `bound_target_group` / `pick_free_pool_member` /
    `split_pool_identities`) unit-tested against constructed `DescribeTaskSets`
    outputs, same pattern as the existing `*_from` parsers. The `InMemoryEcs`
    fake needs **no** LB-binding model — the seam no longer carries
    `target_group` through the handler, so its `weights_for` round-trip is
    unchanged (the binding-readback is RealEcsTarget-internal). Pool name→ARN
    normalization (`resolve_pool_arns`, mixed names+ARNs) is thin async glue,
    PR-4-verified like the rest of the `.send()` surface. Default target stays
    `UnconfiguredEcsTarget`; nothing constructs `RealEcsTarget` with a real pool
    yet (that is 3c-2b).
  - **PR-3c-2b (bound-session client + the AWS CLI branch) — ✅ SHIPPED
    (core live-wiring; cross-deployment exclusivity deferred to PR-3c-2c per
    user decision, 2026-06-24).** Built the bound-session SDK client: the new
    `aws::bound_session::resolve_bound_session` reads the `AssumedSession` PR-3b
    persisted at `secret://<env>/…/deployer_session` via
    `resolve_credentials_token`, fail-closed parse, ambient fallback when
    unbound (the AWS analogue of K8s `resolve_bound_identity`);
    `RealEcsTarget::resolve` gained a `session` arg that injects it as a static
    credentials provider (`session_credentials`, expiry passed through). Added
    the AWS branch to the CLI deploy path: `apply_revision` (env.rs) no longer
    hard-rejects the AWS-ECS descriptor — an applicability gate (before the
    per-revision lookup, preserving the old "reject regardless of revision"
    property) admits K8s + AWS-ECS; the AWS arm builds
    `RealEcsTarget::resolve(region, launch, pool, session)` from
    `aws_ecs_launch_params` (requires a Fargate launch config — rejected before
    any AWS call), injects via `with_target`, and dispatches warm/archive
    (mirrors `apply_revision_k8s_cluster`). Live traffic-shift shipped as the
    **new `op env apply-traffic <env> <dep>` verb** — a surgical live verb
    mirroring `apply-revision` that reads the recorded split and pushes ALB
    listener weights via `apply_traffic_split`; AWS-ECS only (K8s serves splits
    from its in-process runtime router); `op traffic set` stays spec-only. AWS
    is imperative — NOT reconcile. All AWS construction is behind
    `all(creds-aws, deploy-aws-ecs)` with honest stubs on the off combos.
  - **PR-3c-2c (cross-deployment pool exclusivity, PR-3c-2a codex finding,
    high) — ✅ SHIPPED as a fail-closed single-owner guard.** The stateless
    allocator reads `describe_task_sets` per ECS service, so it is exclusive
    *within* a deployment but blind across deployments sharing one binding pool —
    two deployments could be handed the same target group. PR-3c-2a already
    rejects a *duplicate* TG within one pool (`pool_arns_from`). **Design
    decision (industry-standard alignment, 2026-06-24):** ECS blue/green target
    groups are per-service resources (CodeDeploy uses a dedicated TG pair per
    service; CDK/Terraform provision per-service TGs) — a *shared fungible pool*
    (env-wide free-list or hash partition) is an AWS anti-pattern, and true
    per-deployment pools are the standard end-state but the env model has no
    authoring-time deployment name to key one on (deployments are runtime ULIDs;
    the pool is one per-binding answer). So PR-3c-2c does NOT introduce sharing or
    speculative named deployments. Instead it makes the single per-binding pool
    **explicitly single-owner**: `create_task_set` calls `sibling_pool_bindings`
    (paginated `ListServices` on the env cluster → per `gtc-svc-*` service
    `DescribeTaskSets`, skipping `me` and non-greentic services), and the pure
    `conflicting_pool_owner` fails the warm closed with an actionable `Conflict`
    if any sibling already holds a pool member (naming the owning service + TG).
    Within-deployment blue/green is untouched (the two revisions share one
    service, never counted as a sibling). Stateless — re-derived from live
    services each call (no CAS/lease; consistent with the F2 choice). Added IAM
    verb `ecs:ListServices` to `VALIDATED_IAM_VERBS` +
    `REAL_ECS_TARGET_IAM_ACTIONS` (subset test holds; bootstrap rules-pack covers
    it). When multi-deployment-per-env becomes real, the clean follow-up is true
    per-deployment pools (+ named deployments) and this guard is what relaxes.
    **Scope (codex PR-3c-2c review, high — accepted as a documented residual, not
    fixed):** the guard is a read-then-create check, so it closes the
    *steady-state* collision (a sibling deployment already established in the
    pool) but is not atomic — two deployments' *first* warms interleaving inside
    the read→create window could both pick a free member. That cross-deployment
    race, like the same-service concurrent-warm race, stays a PR-4 live-verify
    note (the deploy path warms sequentially; closing it durably needs the
    CAS/lease the stateless F2 choice rules out). The docs/comment now scope the
    guard to "steady-state" rather than claiming total closure.
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
