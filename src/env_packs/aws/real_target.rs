//! [`RealEcsTarget`]: the aws-sdk-backed [`EcsDeployTarget`] implementation.
//!
//! PR-1 shipped the [`EcsDeployTarget`] seam + the [`InMemoryEcs`] fake + the
//! [`UnconfiguredEcsTarget`] default; the [`Deployer`] verbs drive that seam.
//! This module supplies the production implementation: the same five methods,
//! backed by `aws-sdk-ecs` (task sets) and `aws-sdk-elasticloadbalancingv2`
//! (weighted forward actions). Behind the default-on `deploy-aws-ecs` feature.
//!
//! ## What the seam carries vs. what Fargate needs
//!
//! The per-revision seam specs ([`TaskSetSpec`] etc.) carry only the identity +
//! image — the things that vary per revision. A real Fargate
//! `RegisterTaskDefinition` / `CreateTaskSet` also needs the launch-time
//! compute + network config (execution role, subnets, security groups, CPU /
//! memory, container port) **and** an ALB target group to register into. Both
//! are **stable per binding** (one VPC / role set / target-group pool per
//! env-pack binding), not per revision, so they live on the target —
//! [`FargateLaunchConfig`] and the `target_group_pool` — not on the seam specs.
//! This keeps the seam (and the [`InMemoryEcs`] fake) minimal while letting the
//! real target stand up a complete task definition.
//!
//! ## Target-group assignment (stateless pool)
//!
//! The deployer never computes a per-revision target-group name. The operator
//! supplies a **pool** of ≥2 ALB target groups (blue/green needs each live
//! revision in its own TG); the target assigns each revision a free pool member
//! at `create_task_set` by reading which pool members are already bound to live
//! task sets (`assigned_pool_members`) and picking a free one
//! (`pick_free_pool_member`). The assignment is **not persisted** — it is
//! re-derived from the live task sets' load-balancer bindings on every call, so
//! a fresh process recovers the same mapping. `apply_listener_weights` reads the
//! same bindings (`bound_target_group`) to route each weighted revision to its
//! TG, so the binding on the task set is the single source of truth.
//!
//! **Exclusivity boundary.** `assigned_pool_members` reads `describe_task_sets`,
//! which is scoped to one deployment's service, so the free-member *assignment*
//! is exclusive only *within a deployment* — each revision sees its siblings'
//! bindings and skips them. It does NOT span deployments: two deployments
//! drawing from the same pool through different ECS services cannot see each
//! other's assignments, so a shared pool could otherwise hand both the same
//! target group. Because the env binding declares ONE pool, a pool serves a
//! single deployment's blue/green pair; the **single-owner guard** enforces
//! that. Before assigning, `create_task_set` calls `sibling_pool_bindings` —
//! the cluster's other `gtc-svc-*` services and their bound pool members — and
//! `conflicting_pool_owner` fails the warm closed if any sibling already holds a
//! pool member, naming the owner. This is a **read-then-create** check, so it
//! closes the **steady-state** collision — a sibling deployment already
//! established in the pool, the realistic case since the deploy path warms
//! sequentially. It is deliberately NOT atomic: two deployments' *first* warms
//! interleaving inside the read→create window could both still pick a free
//! member (the cross-deployment form of the same-service concurrent-warm race
//! below). Closing that durably would need the CAS/lease the stateless design
//! rules out, so it stays a PR-4 live-verify note, not a guarantee this guard
//! makes. Stateless like the assignment itself (re-derived from live services
//! each call). Per-deployment pools (a distinct pool per deployment, lifting the
//! one-deployment limit) are a tracked follow-up. A *duplicate* target group
//! within one pool is a separate config error that guarantees a self-collision
//! and is rejected at resolve time (`pool_arns_from`). The same-service
//! concurrent-warm race (two distinct revisions both seeing a TG free) is
//! inherent to the stateless model — the deploy path warms a deployment's
//! revisions sequentially; closing it durably would require a claim/lease that
//! contradicts the stateless design (a PR-4 live-verify note).
//!
//! ## Listener routing (default action vs per-deployment rule)
//!
//! `apply_listener_weights` mirrors the `TrafficSplit` onto the listener in one
//! of two shapes, chosen by the binding's routing answers:
//!
//! - **No routing condition** (`alb_routing_host` / `alb_routing_path` both
//!   blank): the listener's **default action** is written, so the listener
//!   serves exactly this deployment. This is the original behaviour, kept for
//!   single-deployment listeners; a second deployment behind the same listener
//!   would clobber it.
//! - **A routing condition is set**: a per-deployment listener **rule** keyed by
//!   the host/path condition is written, leaving the default action and sibling
//!   rules intact, so deployments coexist behind one listener. The rule is
//!   found-or-created idempotently — the routing condition is the rule's natural
//!   key (`match_rule`), so re-applying updates the rule rather than stacking
//!   duplicates. **Ownership is proven before mutation:** a condition match alone
//!   does not authorize a write — a sibling deployment or an operator may hold a
//!   rule with the same host/path (carrying auth/redirect actions). Each created
//!   rule is stamped with an owner tag (`RULE_OWNER_TAG_KEY` → the deployment
//!   ULID); before `ModifyRule` the rule's tags are read (`DescribeTags`) and a
//!   non-owned match is refused (`ListenerRuleConflict`) rather than hijacked.
//!   Like the pool assignment this is a read-then-write against live AWS state
//!   (no persisted rule map); concurrent first-applies of two distinct
//!   deployments are a PR-4 live-verify note, not a guarantee here.
//!
//! ## Identity bridge
//!
//! The seam addresses task sets by `(deployment_id, revision_id)`; ECS assigns
//! its own opaque task-set id. The target bridges the two with a deterministic
//! **`externalId`** (`task_set_external_id`) set at `create_task_set` and
//! looked up on every `describe` / `delete`, so a fresh process can re-find a
//! revision's task set without persisting the ECS id.
//!
//! ## Testing
//!
//! No real AWS in CI. Every request-build and response-parse step is a pure
//! free function (`*_from` parsers, `container_def` / `network_config` /
//! `forward_action` builders) unit-tested with SDK types constructed via their
//! builders. The thin async glue that calls `.send()` is exercised only by the
//! gated live E2E (PR-4).
//!
//! [`EcsDeployTarget`]: super::deploy_target::EcsDeployTarget
//! [`InMemoryEcs`]: super::deploy_target::InMemoryEcs
//! [`UnconfiguredEcsTarget`]: super::deploy_target::UnconfiguredEcsTarget
//! [`Deployer`]: crate::env_packs::deployer::Deployer

use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_ecs::operation::create_task_set::CreateTaskSetOutput;
use aws_sdk_ecs::operation::describe_services::DescribeServicesOutput;
use aws_sdk_ecs::operation::describe_task_sets::DescribeTaskSetsOutput;
use aws_sdk_ecs::operation::register_task_definition::RegisterTaskDefinitionOutput;
use aws_sdk_ecs::types::{
    AssignPublicIp, AwsVpcConfiguration, Compatibility, ContainerDefinition, DeploymentController,
    DeploymentControllerType, LoadBalancer, NetworkConfiguration, NetworkMode, PortMapping, Scale,
    ScaleUnit, StabilityStatus, TaskSet,
};
use aws_sdk_elasticloadbalancingv2::operation::describe_target_groups::DescribeTargetGroupsOutput;
use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, ForwardActionConfig, HostHeaderConditionConfig,
    PathPatternConditionConfig, Rule, RuleCondition, Tag, TagDescription, TargetGroupTuple,
};
use greentic_deploy_spec::{DeploymentId, RevisionId};

use super::deploy_target::{
    EcsDeployTarget, EcsTargetError, ListenerRef, ListenerRouting, ServiceSpec, TargetGroupWeight,
    TaskSetHandle, TaskSetRef, TaskSetSpec, TaskSetStability,
};
// The launch config is pure data parsed by `AwsEcsParams::from_answers`, so it
// lives in the always-compiled deployer module; re-exported here to keep the
// `real_target::FargateLaunchConfig` public path stable.
use super::credentials::AssumedSession;
pub use super::deployer::FargateLaunchConfig;

/// Production [`EcsDeployTarget`]: ECS task sets + ELBv2 weighted forward
/// actions, region-pinned at construction.
#[derive(Debug, Clone)]
pub struct RealEcsTarget {
    ecs: aws_sdk_ecs::Client,
    elb: aws_sdk_elasticloadbalancingv2::Client,
    launch: FargateLaunchConfig,
    /// Operator-supplied ALB target groups (ARNs or names) the target assigns
    /// revisions to, one per live revision. Blue/green needs ≥2; assignment is
    /// stateless (see the module-level "Target-group assignment" note).
    target_group_pool: Vec<String>,
}

/// The IAM actions [`RealEcsTarget`]'s five methods call at deploy time — the
/// authoritative ECS / ELBv2 runtime surface. A test pins this ⊆
/// [`VALIDATED_IAM_VERBS`](super::credentials::VALIDATED_IAM_VERBS) so the
/// credentials preflight can never under-declare what a live deploy needs:
/// adding an SDK call here without the matching validated verb fails CI rather
/// than the customer's first warm / traffic-shift / archive.
pub const REAL_ECS_TARGET_IAM_ACTIONS: &[&str] = &[
    "ecs:DescribeServices",       // ensure_service
    "ecs:ListServices",           // create_task_set (single-owner pool guard)
    "ecs:CreateService",          // ensure_service
    "ecs:RegisterTaskDefinition", // create_task_set
    "ecs:CreateTaskSet",          // create_task_set
    // create_task_set / task_set_stability / delete_task_set / apply_listener_weights
    // (apply_listener_weights reads each revision's target-group binding here)
    "ecs:DescribeTaskSets",
    "ecs:DeleteTaskSet",                         // delete_task_set
    "ecs:DeregisterTaskDefinition",              // delete_task_set
    "elasticloadbalancing:DescribeTargetGroups", // create_task_set (resolve_pool_arns, name→ARN)
    "elasticloadbalancing:ModifyListener", // apply_listener_weights (default-action, no routing)
    "elasticloadbalancing:DescribeRules",  // apply_listener_weights (find this deployment's rule)
    "elasticloadbalancing:CreateRule",     // apply_listener_weights (first per-deployment rule)
    "elasticloadbalancing:ModifyRule",     // apply_listener_weights (update per-deployment rule)
    "elasticloadbalancing:AddTags", // apply_listener_weights (stamp rule owner tag on create)
    "elasticloadbalancing:DescribeTags", // apply_listener_weights (prove rule ownership before modify)
];

impl RealEcsTarget {
    /// Resolve the AWS credential chain (region-pinned) and build the ECS +
    /// ELBv2 clients. Mirrors `RealAwsClient::resolve` in `credentials.rs`: the
    /// region comes from the binding (the env-pack binding is single-region, so
    /// the per-spec `region` always equals this).
    ///
    /// `session` is the env's bound deployer identity (the [`AssumedSession`]
    /// the `--bind` STS minter persisted): `Some` injects it as a static
    /// credentials provider so every ECS/ELBv2 call runs as the scoped deployer
    /// role; `None` falls back to the ambient chain (`AWS_PROFILE` / env keys /
    /// instance role) the rest of the AWS code walks. The AWS analogue of the
    /// K8s bound-ServiceAccount bearer — fail-closed resolution happens upstream
    /// (`resolve_bound_session`), so by here `None` genuinely means "no ref
    /// bound", not "ref bound but unreadable".
    pub async fn resolve(
        region: &str,
        launch: FargateLaunchConfig,
        target_group_pool: Vec<String>,
        session: Option<AssumedSession>,
    ) -> Result<Self, EcsTargetError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(session) = session.as_ref() {
            loader = loader.credentials_provider(session_credentials(session));
        }
        let config = loader.load().await;
        if config.credentials_provider().is_none() {
            return Err(EcsTargetError::Api(
                "no AWS credentials provider in the resolved SDK config — bind the deployer \
                 identity (`op env bootstrap --bind` / `op credentials rotate`) or set AWS_PROFILE \
                 / AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY"
                    .to_string(),
            ));
        }
        Ok(Self {
            ecs: aws_sdk_ecs::Client::new(&config),
            elb: aws_sdk_elasticloadbalancingv2::Client::new(&config),
            launch,
            target_group_pool,
        })
    }

    /// Normalize the configured pool to ARNs. Pool entries are ARNs or names
    /// (the wizard accepts both); task-set load-balancer bindings are always
    /// ARNs, so assignment compares in ARN space. ARN-form entries pass
    /// through; name-form entries are resolved via DescribeTargetGroups. Order
    /// is preserved so assignment is deterministic. A name that resolves to no
    /// target group is an error (a typo'd pool member must not silently shrink
    /// the pool).
    async fn resolve_pool_arns(&self) -> Result<Vec<String>, EcsTargetError> {
        // Only name-form entries need a DescribeTargetGroups lookup; ARN-form
        // entries pass through. Resolve the names, then map the whole pool to
        // ARNs in order (`pool_arns_from`).
        let names: Vec<String> = self
            .target_group_pool
            .iter()
            .filter(|e| !e.starts_with("arn:"))
            .cloned()
            .collect();
        let resolved = if names.is_empty() {
            HashMap::new()
        } else {
            let out = self
                .elb
                .describe_target_groups()
                .set_names(Some(names))
                .send()
                .await
                .map_err(|e| api("describe_target_groups", e))?;
            target_group_arns_from(&out)
        };
        pool_arns_from(&self.target_group_pool, &resolved)
    }

    /// Enumerate this cluster's other deployment services (`gtc-svc-*` other than
    /// `me`) and read each one's bound pool target groups. Feeds the single-owner
    /// pool guard in [`create_task_set`](EcsDeployTarget::create_task_set). Thin
    /// async glue — paginated `ListServices` plus a `DescribeTaskSets` per
    /// greentic service — so it is PR-4 live-verified like the rest of the
    /// `.send()` surface; the fail-closed decision is the pure
    /// [`conflicting_pool_owner`]. Services with no pool binding are skipped, and
    /// non-greentic services in the cluster (no `gtc-svc-` prefix) are ignored.
    async fn sibling_pool_bindings(
        &self,
        cluster: &str,
        me: &str,
    ) -> Result<Vec<(String, Vec<String>)>, EcsTargetError> {
        let mut bindings = Vec::new();
        let mut next_token = None;
        loop {
            let page = self
                .ecs
                .list_services()
                .cluster(cluster)
                .set_next_token(next_token)
                .send()
                .await
                .map_err(|e| api("list_services", e))?;
            for arn in page.service_arns() {
                let name = service_name_from_arn(arn);
                if name == me || !name.starts_with(SERVICE_NAME_PREFIX) {
                    continue;
                }
                let task_sets = self
                    .ecs
                    .describe_task_sets()
                    .cluster(cluster)
                    .service(name)
                    .send()
                    .await
                    .map_err(|e| api("describe_task_sets", e))?;
                let bound: Vec<String> = assigned_pool_members(&task_sets).into_iter().collect();
                if !bound.is_empty() {
                    bindings.push((name.to_string(), bound));
                }
            }
            match page.next_token() {
                Some(token) => next_token = Some(token.to_string()),
                None => break,
            }
        }
        Ok(bindings)
    }
}

/// Build a static credentials provider from the bound [`AssumedSession`].
///
/// All three STS session parts (access key, secret key, session token) are
/// required to sign requests; the session `expiration` is passed through so the
/// SDK treats the credentials as expiring (a deploy that outlives the session
/// surfaces an auth error rather than silently signing with stale creds — the
/// rotation engine re-mints at 80% of the window before that). Pure (no
/// network), so it is unit-tested directly.
fn session_credentials(session: &AssumedSession) -> aws_sdk_ecs::config::Credentials {
    aws_sdk_ecs::config::Credentials::new(
        session.access_key_id.clone(),
        session.secret_access_key.clone(),
        Some(session.session_token.clone()),
        Some(std::time::SystemTime::from(session.expiration)),
        "greentic-bound-deployer-session",
    )
}

#[async_trait]
impl EcsDeployTarget for RealEcsTarget {
    async fn ensure_service(&self, spec: &ServiceSpec) -> Result<(), EcsTargetError> {
        let service = service_name(&spec.deployment_id);
        let described = self
            .ecs
            .describe_services()
            .cluster(&spec.cluster)
            .services(&service)
            .send()
            .await
            .map_err(|e| api("describe_services", e))?;
        if active_service_exists(&described, &service) {
            return Ok(());
        }
        // The describe-then-create above is a TOCTOU window: two concurrent
        // `warm_revision` callers for the same deployment can both observe an
        // absent service and both reach this create. A deterministic
        // `clientToken` keyed on the deployment closes it — ECS dedupes
        // same-token creates within its idempotency window, so the loser of the
        // race gets the original service back instead of an error (CreateService
        // has no dedicated already-exists error; a naked duplicate surfaces as
        // `InvalidParameterException`). The describe stays as a fast path that
        // skips the create entirely once the service is ACTIVE.
        self.ecs
            .create_service()
            .cluster(&spec.cluster)
            .service_name(&service)
            .client_token(service_client_token(&spec.deployment_id))
            .deployment_controller(
                DeploymentController::builder()
                    .r#type(DeploymentControllerType::External)
                    .build()
                    .expect("deployment controller type is set"),
            )
            .send()
            .await
            .map_err(|e| api("create_service", e))?;
        Ok(())
    }

    async fn create_task_set(&self, spec: &TaskSetSpec) -> Result<TaskSetHandle, EcsTargetError> {
        let service = service_name(&spec.deployment_id);
        let external_id = task_set_external_id(&spec.revision_id);

        // Fast path: if a task set already tagged with our externalId exists,
        // return its handle without registering another task definition. The
        // `clientToken` on CreateTaskSet (below) is what actually closes the
        // describe-then-(register+create) race — concurrent same-revision
        // callers dedupe to one task set rather than creating duplicates. The
        // loser's just-registered task definition is a minor orphan (an extra
        // ACTIVE task-def revision); reclaiming it requires comparing the
        // deduped response's task-def to the registered one and deregistering
        // the loser's, which is a PR-4 live-verification item.
        let existing = self
            .ecs
            .describe_task_sets()
            .cluster(&spec.cluster)
            .service(&service)
            .send()
            .await
            .map_err(|e| api("describe_task_sets", e))?;
        if let Some(handle) = existing_task_set_handle(&existing, &external_id) {
            return Ok(handle);
        }

        // Assign this revision a free target group from the pool. The members
        // already bound to live task sets (read from the same describe above)
        // are taken; pick the first free one. Stateless — re-derived from the
        // live task sets every call, so a fresh process recovers the mapping.
        let pool = self.resolve_pool_arns().await?;

        // Single-owner pool guard. This env binding declares ONE target-group
        // pool, so it may serve exactly one deployment's blue/green pair. The
        // within-service `taken` set below is blind to sibling deployments (each
        // deployment is its own ECS service), so before assigning we check
        // whether another `gtc-svc-*` service in this cluster already holds a
        // pool member. If so, refuse rather than silently double-bind the same
        // target group across deployments. This is a read-then-create check: it
        // closes the steady-state case (a sibling already established) — the
        // realistic one, since the deploy path warms sequentially. Two
        // deployments' first warms racing inside this read→create window are the
        // cross-deployment form of the same-service warm race (a PR-4 live-verify
        // note), deliberately not closed with a CAS/lease. Stateless —
        // re-derived from the live services each call, consistent with the rest
        // of the assignment model. Per-deployment pools are a tracked follow-up;
        // until then one binding = one deployment.
        let siblings = self.sibling_pool_bindings(&spec.cluster, &service).await?;
        if let Some((owner, shared_tg)) = conflicting_pool_owner(&siblings, &pool) {
            return Err(EcsTargetError::PoolConflict { owner, shared_tg });
        }

        let taken = assigned_pool_members(&existing);
        let target_group_arn = pick_free_pool_member(&pool, &taken).ok_or_else(|| {
            EcsTargetError::Api(if pool.is_empty() {
                "the AWS-ECS binding configures no ALB target groups — set \
                 `target_group_arns` (≥2 for blue/green) so warm can place the revision"
                    .to_string()
            } else {
                format!(
                    "target-group pool exhausted: all {} configured target group(s) are bound \
                     to live task sets; add more to `target_group_arns` to warm another revision",
                    pool.len()
                )
            })
        })?;

        let registered = self
            .ecs
            .register_task_definition()
            .family(task_def_family(&spec.deployment_id, &spec.revision_id))
            .requires_compatibilities(Compatibility::Fargate)
            .network_mode(NetworkMode::Awsvpc)
            .cpu(&self.launch.cpu)
            .memory(&self.launch.memory)
            .execution_role_arn(&self.launch.execution_role_arn)
            .set_task_role_arn(self.launch.task_role_arn.clone())
            .container_definitions(container_def(&self.launch, &spec.image))
            .send()
            .await
            .map_err(|e| api("register_task_definition", e))?;
        let task_def_arn = task_def_arn_from(&registered)?;

        let created = self
            .ecs
            .create_task_set()
            .cluster(&spec.cluster)
            .service(&service)
            .task_definition(&task_def_arn)
            .external_id(&external_id)
            .client_token(task_set_client_token(&spec.revision_id))
            .network_configuration(network_config(&self.launch))
            .load_balancers(load_balancer(&self.launch, &target_group_arn))
            .scale(
                Scale::builder()
                    .value(100.0)
                    .unit(ScaleUnit::Percent)
                    .build(),
            )
            .send()
            .await
            .map_err(|e| api("create_task_set", e))?;

        task_set_handle_from(&created, task_def_arn)
    }

    async fn task_set_stability(
        &self,
        task_set: &TaskSetRef,
    ) -> Result<TaskSetStability, EcsTargetError> {
        let service = service_name(&task_set.deployment_id);
        let external_id = task_set_external_id(&task_set.revision_id);
        let out = self
            .ecs
            .describe_task_sets()
            .cluster(&task_set.cluster)
            .service(&service)
            .send()
            .await
            .map_err(|e| api("describe_task_sets", e))?;
        stability_from(&out, &external_id)
    }

    async fn delete_task_set(&self, task_set: &TaskSetRef) -> Result<(), EcsTargetError> {
        let service = service_name(&task_set.deployment_id);
        let external_id = task_set_external_id(&task_set.revision_id);
        let out = self
            .ecs
            .describe_task_sets()
            .cluster(&task_set.cluster)
            .service(&service)
            .send()
            .await
            .map_err(|e| api("describe_task_sets", e))?;
        // Idempotent: an absent task set is a no-op success.
        let Some(found) = task_set_for_delete(&out, &external_id) else {
            return Ok(());
        };
        self.ecs
            .delete_task_set()
            .cluster(&task_set.cluster)
            .service(&service)
            .task_set(&found.id)
            .force(true)
            .send()
            .await
            .map_err(|e| api("delete_task_set", e))?;
        // Deregister the revision's task definition so archived revisions don't
        // accumulate ACTIVE task-def revisions. A deregister failure is
        // surfaced; the delete above already landed, so a retry finds no task
        // set (idempotent Ok) and skips straight past this.
        if let Some(arn) = found.task_definition {
            self.ecs
                .deregister_task_definition()
                .task_definition(&arn)
                .send()
                .await
                .map_err(|e| api("deregister_task_definition", e))?;
        }
        Ok(())
    }

    /// Mirror the deployment's `TrafficSplit` onto the ALB as a weighted forward
    /// across the revisions' target groups.
    ///
    /// **Two routing models, chosen by [`ListenerRef::routing`]:**
    ///
    /// - `None` (legacy, one deployment per listener): writes the listener's
    ///   *default* action, so binding an `alb_listener_arn` hands that listener's
    ///   routing to the deployer — any pre-existing default / auth / redirect
    ///   action is replaced, and a second deployment behind the same listener
    ///   would clobber the first. This is the original behaviour, kept for
    ///   bindings that record no routing answers.
    /// - `Some(routing)` (per-deployment): writes a listener **rule** keyed by
    ///   this deployment's host/path condition, leaving the default action and
    ///   every sibling rule untouched, so multiple deployments coexist behind
    ///   one listener. The rule is found-or-created idempotently: the deployment
    ///   is identified on the listener by its routing condition (the same
    ///   condition is the rule's natural key), so re-applying a split updates
    ///   the existing rule rather than stacking duplicates.
    ///
    /// [`ListenerRef::routing`]: super::deploy_target::ListenerRef::routing
    async fn apply_listener_weights(
        &self,
        listener: &ListenerRef,
        weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError> {
        // Each weighted revision routes to the target group its task set is
        // bound to. That binding (recorded by the pool assignment at warm time)
        // is the single source of truth, so the weights carry only the routing
        // weight and the ARN is read back from the live task sets here — no
        // name lookup, and no deployer-computed target-group name.
        let service = service_name(&listener.deployment_id);
        let out = self
            .ecs
            .describe_task_sets()
            .cluster(&listener.cluster)
            .service(&service)
            .send()
            .await
            .map_err(|e| api("describe_task_sets", e))?;
        let tuples = weighted_target_groups(weights, &out)?;
        let action = forward_action(&tuples)?;
        match &listener.routing {
            None => self.write_listener_default(listener, action).await,
            Some(routing) => self.write_listener_rule(listener, routing, action).await,
        }
    }
}

#[cfg(feature = "deploy-aws-ecs")]
impl RealEcsTarget {
    /// Legacy default-action write (no routing condition): the listener serves
    /// exactly this deployment. See [`apply_listener_weights`] for the ownership
    /// caveat.
    ///
    /// [`apply_listener_weights`]: RealEcsTarget::apply_listener_weights
    async fn write_listener_default(
        &self,
        listener: &ListenerRef,
        action: Action,
    ) -> Result<(), EcsTargetError> {
        self.elb
            .modify_listener()
            .listener_arn(&listener.listener_arn)
            .default_actions(action)
            .send()
            .await
            .map_err(|e| api("modify_listener", e))?;
        Ok(())
    }

    /// Per-deployment rule write: find this deployment's rule on the listener by
    /// its routing condition and update its action, or create the rule (stamped
    /// with this deployment's owner tag) when it is absent. The default action
    /// and every sibling/operator rule are left untouched.
    ///
    /// **Ownership is proven, not assumed.** A condition match alone is not
    /// enough to mutate a rule — a sibling deployment or an operator may have a
    /// rule with the same host/path (carrying auth/redirect actions). Before
    /// `ModifyRule` the rule's tags are read (`DescribeTags`) and the write is
    /// refused ([`EcsTargetError::ListenerRuleConflict`]) unless the rule carries
    /// THIS deployment's owner tag — so the deployer only ever rewrites a rule it
    /// created. Re-applying a split (the rule already tagged ours) updates it
    /// idempotently.
    async fn write_listener_rule(
        &self,
        listener: &ListenerRef,
        routing: &ListenerRouting,
        action: Action,
    ) -> Result<(), EcsTargetError> {
        let existing = self
            .elb
            .describe_rules()
            .listener_arn(&listener.listener_arn)
            .send()
            .await
            .map_err(|e| api("describe_rules", e))?;
        let rules = existing.rules();
        match match_rule(rules, routing) {
            Some(rule_arn) => {
                if !self
                    .rule_owned_by_deployment(&rule_arn, &listener.deployment_id)
                    .await?
                {
                    return Err(EcsTargetError::ListenerRuleConflict {
                        rule_arn,
                        condition: routing_summary(routing),
                    });
                }
                self.elb
                    .modify_rule()
                    .rule_arn(&rule_arn)
                    .actions(action)
                    .send()
                    .await
                    .map_err(|e| api("modify_rule", e))?;
            }
            None => {
                self.elb
                    .create_rule()
                    .listener_arn(&listener.listener_arn)
                    .priority(next_rule_priority(rules))
                    .set_conditions(Some(routing_conditions(routing)))
                    .actions(action)
                    .tags(owner_tag(&listener.deployment_id))
                    .send()
                    .await
                    .map_err(|e| api("create_rule", e))?;
            }
        }
        Ok(())
    }

    /// Read a rule's tags and decide whether THIS deployment created it (carries
    /// the [`RULE_OWNER_TAG_KEY`] tag with this deployment's ULID). `DescribeRules`
    /// does not return tags, so ownership needs this extra read.
    async fn rule_owned_by_deployment(
        &self,
        rule_arn: &str,
        deployment_id: &DeploymentId,
    ) -> Result<bool, EcsTargetError> {
        let out = self
            .elb
            .describe_tags()
            .resource_arns(rule_arn)
            .send()
            .await
            .map_err(|e| api("describe_tags", e))?;
        Ok(tag_descriptions_owned_by(
            out.tag_descriptions(),
            deployment_id,
        ))
    }
}

// ── Pure helpers (the unit-tested core) ──────────────────────────────────────

/// Map any SDK error to a [`EcsTargetError::Api`] carrying the operation name +
/// the response detail, so operators get an actionable message.
fn api<E: std::fmt::Display>(op: &str, err: E) -> EcsTargetError {
    EcsTargetError::Api(format!("ecs {op}: {err}"))
}

/// Prefix shared by every deployment's ECS service name. Filters `ListServices`
/// output to greentic-managed deployment services in the single-owner pool
/// guard (`sibling_pool_bindings`), so unrelated services in the cluster are
/// ignored.
const SERVICE_NAME_PREFIX: &str = "gtc-svc-";

/// Deterministic ECS service name for a deployment (one EXTERNAL-controller
/// service per `deployment_id`). `pub(crate)` so the CLI deploy path can report
/// the live service name in the `op env apply-revision` outcome without
/// re-deriving the format.
pub(crate) fn service_name(deployment_id: &DeploymentId) -> String {
    format!("{SERVICE_NAME_PREFIX}{}", deployment_id.0)
}

/// Render a 128-bit id as a UUID-form (36-char) string for use as an ECS
/// idempotency `clientToken` (the field accepts "up to 36 ASCII characters in
/// the form of a UUID"). Deterministic, so concurrent same-identity creates
/// present the same token and ECS dedupes the race.
fn uuid_form(bits: u128) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (bits >> 96) as u32,
        (bits >> 80) as u16,
        (bits >> 64) as u16,
        (bits >> 48) as u16,
        (bits & 0xffff_ffff_ffff) as u64,
    )
}

/// Deterministic `CreateService` idempotency token for a deployment (one
/// EXTERNAL-controller service per deployment, keyed on the deployment ULID).
fn service_client_token(deployment_id: &DeploymentId) -> String {
    uuid_form(deployment_id.0.into())
}

/// Deterministic `CreateTaskSet` idempotency token for a revision. One task
/// set per revision, keyed on the revision ULID (globally unique, matching the
/// `externalId` scheme), so two concurrent `create_task_set` calls for the same
/// revision present the same token and ECS dedupes the duplicate create.
fn task_set_client_token(revision_id: &RevisionId) -> String {
    uuid_form(revision_id.0.into())
}

/// Deterministic task-definition family for a revision.
fn task_def_family(deployment_id: &DeploymentId, revision_id: &RevisionId) -> String {
    format!("gtc-td-{}-{}", deployment_id.0, revision_id.0)
}

/// Deterministic `externalId` bridging the seam's `(deployment, revision)`
/// identity to ECS's opaque task-set id. Set at create, matched on
/// describe / delete.
fn task_set_external_id(revision_id: &RevisionId) -> String {
    format!("gtc-rev-{}", revision_id.0)
}

/// True when DescribeServices returned an ACTIVE service of the given name.
/// ECS also returns recently-deleted services as INACTIVE; those are treated as
/// absent so the service is recreated.
fn active_service_exists(out: &DescribeServicesOutput, name: &str) -> bool {
    out.services().iter().any(|s| {
        s.service_name() == Some(name)
            && s.status()
                .is_some_and(|st| st.eq_ignore_ascii_case("ACTIVE"))
    })
}

/// The container definition for a revision: the single essential container
/// running the revision's image, exposing the launch config's container port.
fn container_def(launch: &FargateLaunchConfig, image: &str) -> ContainerDefinition {
    ContainerDefinition::builder()
        .name(&launch.container_name)
        .image(image)
        .essential(true)
        .port_mappings(
            PortMapping::builder()
                .container_port(launch.container_port)
                .build(),
        )
        .build()
}

/// The awsvpc network configuration for the task set's Fargate ENIs.
fn network_config(launch: &FargateLaunchConfig) -> NetworkConfiguration {
    let assign = if launch.assign_public_ip {
        AssignPublicIp::Enabled
    } else {
        AssignPublicIp::Disabled
    };
    NetworkConfiguration::builder()
        .awsvpc_configuration(
            AwsVpcConfiguration::builder()
                .set_subnets(Some(launch.subnets.clone()))
                .set_security_groups(Some(launch.security_groups.clone()))
                .assign_public_ip(assign)
                .build()
                .expect("awsvpc subnets are set"),
        )
        .build()
}

/// The load-balancer binding for the task set: register the launch config's
/// container port against the revision's target group.
fn load_balancer(launch: &FargateLaunchConfig, target_group_arn: &str) -> LoadBalancer {
    LoadBalancer::builder()
        .target_group_arn(target_group_arn)
        .container_name(&launch.container_name)
        .container_port(launch.container_port)
        .build()
}

/// Read the registered task-definition ARN out of RegisterTaskDefinition.
fn task_def_arn_from(out: &RegisterTaskDefinitionOutput) -> Result<String, EcsTargetError> {
    out.task_definition()
        .and_then(|td| td.task_definition_arn())
        .map(str::to_string)
        .ok_or_else(|| {
            EcsTargetError::Api(
                "RegisterTaskDefinition returned no task-definition ARN".to_string(),
            )
        })
}

/// Build the [`TaskSetHandle`] from CreateTaskSet (id + the task-def ARN we
/// registered, so delete can deregister it).
fn task_set_handle_from(
    out: &CreateTaskSetOutput,
    task_def_arn: String,
) -> Result<TaskSetHandle, EcsTargetError> {
    let id = out
        .task_set()
        .and_then(|ts| ts.id())
        .map(str::to_string)
        .ok_or_else(|| EcsTargetError::Api("CreateTaskSet returned no task-set id".to_string()))?;
    Ok(TaskSetHandle {
        task_set_id: id,
        task_def_arn,
    })
}

/// Find an existing task set by `externalId` and project it to a handle (for
/// idempotent re-create).
fn existing_task_set_handle(
    out: &DescribeTaskSetsOutput,
    external_id: &str,
) -> Option<TaskSetHandle> {
    find_task_set(out, external_id).and_then(|ts| {
        let id = ts.id()?.to_string();
        let task_def_arn = ts.task_definition()?.to_string();
        Some(TaskSetHandle {
            task_set_id: id,
            task_def_arn,
        })
    })
}

/// Read the rollout status of the task set tagged with `external_id`. A task set
/// that has not appeared yet is an honest error (warm just created it).
fn stability_from(
    out: &DescribeTaskSetsOutput,
    external_id: &str,
) -> Result<TaskSetStability, EcsTargetError> {
    let ts = find_task_set(out, external_id).ok_or_else(|| {
        EcsTargetError::Api(format!(
            "DescribeTaskSets returned no task set for externalId `{external_id}`"
        ))
    })?;
    let stabilized = ts.stability_status() == Some(&StabilityStatus::SteadyState);
    Ok(TaskSetStability {
        stabilized,
        running: ts.running_count().max(0) as u32,
        desired: ts.computed_desired_count().max(0) as u32,
    })
}

/// The id + task-definition ARN of the task set to delete, or `None` when
/// absent (idempotent delete).
struct TaskSetToDelete {
    id: String,
    task_definition: Option<String>,
}

fn task_set_for_delete(out: &DescribeTaskSetsOutput, external_id: &str) -> Option<TaskSetToDelete> {
    let ts = find_task_set(out, external_id)?;
    Some(TaskSetToDelete {
        id: ts.id()?.to_string(),
        task_definition: ts.task_definition().map(str::to_string),
    })
}

/// Find the task set carrying our `externalId` in a DescribeTaskSets response.
fn find_task_set<'a>(out: &'a DescribeTaskSetsOutput, external_id: &str) -> Option<&'a TaskSet> {
    out.task_sets()
        .iter()
        .find(|ts| ts.external_id() == Some(external_id))
}

/// The target-group ARN the task set tagged with `external_id` is bound to (its
/// first load-balancer binding). `None` when the task set is absent or carries
/// no load-balancer binding. This binding — written at `create_task_set` — is
/// the source of truth for both pool assignment and traffic routing, so the
/// deployer never needs to recompute or persist a per-revision target group.
fn bound_target_group(out: &DescribeTaskSetsOutput, external_id: &str) -> Option<String> {
    find_task_set(out, external_id)?
        .load_balancers()
        .iter()
        .find_map(|lb| lb.target_group_arn().map(str::to_string))
}

/// Every target-group ARN currently bound to a live task set — the "taken"
/// members of the pool. Pool assignment subtracts this set from the configured
/// pool to find a free target group. Stateless: derived from the live task sets
/// each call, never persisted.
fn assigned_pool_members(out: &DescribeTaskSetsOutput) -> std::collections::HashSet<String> {
    out.task_sets()
        .iter()
        .flat_map(|ts| ts.load_balancers())
        .filter_map(|lb| lb.target_group_arn().map(str::to_string))
        .collect()
}

/// The first pool member (in configured order, so assignment is deterministic)
/// not already bound to a live task set. `None` when the pool is empty or every
/// member is taken — the caller turns that into an actionable error.
fn pick_free_pool_member(
    pool_arns: &[String],
    taken: &std::collections::HashSet<String>,
) -> Option<String> {
    pool_arns.iter().find(|arn| !taken.contains(*arn)).cloned()
}

/// Extract the service name from an ECS service ARN — the segment after the
/// final `/` (`arn:aws:ecs:<region>:<acct>:service/<cluster>/<name>`). A value
/// with no `/` (already a bare name) is returned unchanged.
fn service_name_from_arn(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

/// Whether a sibling deployment already owns this binding's single target-group
/// pool. Returns the first `(service_name, target_group)` where a sibling's
/// bound target group is also a configured pool member — proof another
/// deployment holds the shared pool, so assignment must fail closed. `None`
/// means no sibling contends and the current deployment may claim the pool. Pure
/// (the live read is [`RealEcsTarget::sibling_pool_bindings`]), so the
/// fail-closed decision is unit-tested directly.
fn conflicting_pool_owner(
    siblings: &[(String, Vec<String>)],
    pool: &[String],
) -> Option<(String, String)> {
    let pool_set: std::collections::HashSet<&str> = pool.iter().map(String::as_str).collect();
    siblings.iter().find_map(|(service, bound)| {
        bound
            .iter()
            .find(|tg| pool_set.contains(tg.as_str()))
            .map(|tg| (service.clone(), tg.clone()))
    })
}

/// Map a configured pool to ARNs in order: ARN-form entries (prefix `arn:`)
/// pass through; name-form entries are looked up in `resolved` (a `name → ARN`
/// map from DescribeTargetGroups). A name absent from `resolved` is an error —
/// a typo'd pool member must not silently shrink the pool. Pure so the mapping
/// is unit-tested; the async glue that builds `resolved` is
/// [`RealEcsTarget::resolve_pool_arns`].
fn pool_arns_from(
    pool: &[String],
    resolved: &HashMap<String, String>,
) -> Result<Vec<String>, EcsTargetError> {
    let arns: Vec<String> = pool
        .iter()
        .map(|entry| {
            if entry.starts_with("arn:") {
                Ok(entry.clone())
            } else {
                resolved.get(entry).cloned().ok_or_else(|| {
                    EcsTargetError::Api(format!(
                        "target group pool member `{entry}` not found in this account/region"
                    ))
                })
            }
        })
        .collect::<Result<_, _>>()?;
    // A target group repeated in the pool (the same ARN twice, or a name that
    // resolves to an already-listed ARN) guarantees two revisions get assigned
    // the same TG — defeating the blue/green isolation the split relies on.
    // Reject it as a config error rather than silently halving the usable pool.
    if let Some(dup) = first_duplicate(&arns) {
        return Err(EcsTargetError::Api(format!(
            "target group `{dup}` appears more than once in the pool; each pool member \
             must be a distinct target group"
        )));
    }
    Ok(arns)
}

/// The first value that repeats in `arns` (in order), or `None` when every
/// entry is distinct.
fn first_duplicate(arns: &[String]) -> Option<&str> {
    let mut seen = std::collections::HashSet::new();
    arns.iter()
        .find(|a| !seen.insert(a.as_str()))
        .map(String::as_str)
}

/// Map DescribeTargetGroups → `name → ARN`. Skips entries missing either field.
fn target_group_arns_from(out: &DescribeTargetGroupsOutput) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for tg in out.target_groups() {
        if let (Some(name), Some(arn)) = (tg.target_group_name(), tg.target_group_arn()) {
            map.insert(name.to_string(), arn.to_string());
        }
    }
    map
}

/// Resolve each weighted revision to the target-group ARN its task set is bound
/// to (`bound_target_group`), yielding `(weight_bps, arn)` pairs for the forward
/// action. A weighted revision with no live task set / load-balancer binding is
/// an error: a split can only route to revisions that have been warmed (the
/// caller's `enforce_split_invariants` guarantees the revisions exist, but warm
/// is a separate step).
fn weighted_target_groups(
    weights: &[TargetGroupWeight],
    task_sets: &DescribeTaskSetsOutput,
) -> Result<Vec<(u32, String)>, EcsTargetError> {
    weights
        .iter()
        .map(|w| {
            let external_id = task_set_external_id(&w.revision_id);
            let arn = bound_target_group(task_sets, &external_id).ok_or_else(|| {
                EcsTargetError::Api(format!(
                    "revision `{}` has no live task set with a target-group binding to route \
                     traffic to — warm it before shifting traffic",
                    w.revision_id.0
                ))
            })?;
            Ok((w.weight_bps, arn))
        })
        .collect()
}

/// Build the weighted forward [`Action`] mirroring the `TrafficSplit`: one
/// target-group tuple per `(weight_bps, arn)` pair.
fn forward_action(tuples: &[(u32, String)]) -> Result<Action, EcsTargetError> {
    let mut forward = ForwardActionConfig::builder();
    for (weight_bps, arn) in tuples {
        forward = forward.target_groups(
            TargetGroupTuple::builder()
                .target_group_arn(arn)
                .weight(elb_weight(*weight_bps))
                .build(),
        );
    }
    Ok(Action::builder()
        .r#type(ActionTypeEnum::Forward)
        .forward_config(forward.build())
        .build())
}

/// Convert a basis-point weight (0–10000, the `TrafficSplit` unit) to an ELBv2
/// forward weight (0–999). ELBv2 normalizes by the sum of weights, so dividing
/// every weight by the same factor preserves the ratio; the result is clamped
/// to the API's 999 ceiling (only a lone 100% revision hits it, and a single
/// non-zero tuple takes all traffic regardless).
fn elb_weight(weight_bps: u32) -> i32 {
    (weight_bps / 10).min(999) as i32
}

/// Build the ELBv2 rule conditions for a deployment's routing: a host-header
/// condition and/or a path-pattern condition (ELBv2 AND-combines them when both
/// are present). The parser guarantees a `Some` routing has a host or a path,
/// so the returned vec is never empty.
fn routing_conditions(routing: &ListenerRouting) -> Vec<RuleCondition> {
    let mut conditions = Vec::with_capacity(2);
    if let Some(host) = &routing.host {
        conditions.push(
            RuleCondition::builder()
                .field("host-header")
                .host_header_config(HostHeaderConditionConfig::builder().values(host).build())
                .build(),
        );
    }
    if let Some(path) = &routing.path {
        conditions.push(
            RuleCondition::builder()
                .field("path-pattern")
                .path_pattern_config(PathPatternConditionConfig::builder().values(path).build())
                .build(),
        );
    }
    conditions
}

/// The (host-header values, path-pattern values) a rule's conditions match on,
/// as sorted sets — a deployment's identity on the listener. Reads the typed
/// config ELBv2 returns for rules created through this API. A default rule (no
/// conditions) yields two empty sets.
fn rule_routing_key(
    conditions: &[RuleCondition],
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let mut hosts = std::collections::BTreeSet::new();
    let mut paths = std::collections::BTreeSet::new();
    for c in conditions {
        if let Some(cfg) = c.host_header_config() {
            hosts.extend(cfg.values().iter().cloned());
        }
        if let Some(cfg) = c.path_pattern_config() {
            paths.extend(cfg.values().iter().cloned());
        }
    }
    (hosts, paths)
}

/// The routing key for a [`ListenerRouting`], comparable to [`rule_routing_key`]
/// — the same (host set, path set) shape so a deployment's desired routing and
/// a live rule's conditions compare directly.
fn routing_key(
    routing: &ListenerRouting,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    (
        routing.host.iter().cloned().collect(),
        routing.path.iter().cloned().collect(),
    )
}

/// Find the listener rule whose host/path condition matches this deployment's
/// routing — the deployment's natural key on the listener, which makes the
/// rule write idempotent. Skips the default rule (it carries no conditions).
fn match_rule(rules: &[Rule], routing: &ListenerRouting) -> Option<String> {
    let want = routing_key(routing);
    rules
        .iter()
        .filter(|r| r.is_default() != Some(true))
        .find(|r| rule_routing_key(r.conditions()) == want)
        .and_then(|r| r.rule_arn().map(str::to_string))
}

/// The priority to assign a newly-created rule: one above the highest numeric
/// priority already on the listener (`1` when none). ELBv2 rule priorities are
/// unique `1..=50000` integers; the default rule's priority is the non-numeric
/// `"default"` and is skipped.
fn next_rule_priority(rules: &[Rule]) -> i32 {
    rules
        .iter()
        .filter_map(|r| r.priority().and_then(|p| p.parse::<i32>().ok()))
        .max()
        .map_or(1, |m| m + 1)
}

/// Tag key stamped on every listener rule this deployer creates, carrying the
/// owning deployment's ULID. Read back (`DescribeTags`) before `ModifyRule` so
/// the deployer only rewrites a rule it created — never a sibling deployment's
/// or an operator-managed rule that happens to share the host/path condition.
const RULE_OWNER_TAG_KEY: &str = "greentic:deployment-id";

/// The owner tag a rule this deployment creates carries (`RULE_OWNER_TAG_KEY` →
/// the deployment ULID).
fn owner_tag(deployment_id: &DeploymentId) -> Tag {
    Tag::builder()
        .key(RULE_OWNER_TAG_KEY)
        .value(deployment_id.0.to_string())
        .build()
}

/// True iff some tag description carries this deployment's owner tag — i.e. the
/// rule was created by this deployment and may be rewritten.
fn tag_descriptions_owned_by(
    descriptions: &[TagDescription],
    deployment_id: &DeploymentId,
) -> bool {
    let want = deployment_id.0.to_string();
    descriptions.iter().any(|d| {
        d.tags()
            .iter()
            .any(|t| t.key() == Some(RULE_OWNER_TAG_KEY) && t.value() == Some(want.as_str()))
    })
}

/// Human-readable summary of a routing condition for the conflict error message.
fn routing_summary(routing: &ListenerRouting) -> String {
    match (&routing.host, &routing.path) {
        (Some(h), Some(p)) => format!("host `{h}` + path `{p}`"),
        (Some(h), None) => format!("host `{h}`"),
        (None, Some(p)) => format!("path `{p}`"),
        (None, None) => "<no condition>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ecs::types::{Service, TaskDefinition};
    use aws_sdk_elasticloadbalancingv2::types::TargetGroup;
    use ulid::Ulid;

    fn launch() -> FargateLaunchConfig {
        FargateLaunchConfig {
            execution_role_arn: "arn:aws:iam::111122223333:role/exec".to_string(),
            task_role_arn: Some("arn:aws:iam::111122223333:role/task".to_string()),
            subnets: vec!["subnet-a".to_string(), "subnet-b".to_string()],
            security_groups: vec!["sg-1".to_string()],
            assign_public_ip: false,
            cpu: "256".to_string(),
            memory: "512".to_string(),
            container_name: "worker".to_string(),
            container_port: 8080,
        }
    }

    fn dep() -> DeploymentId {
        DeploymentId(Ulid::from(0x0d_u128))
    }
    fn rev() -> RevisionId {
        RevisionId(Ulid::from(0x1e_u128))
    }

    #[test]
    fn names_are_deterministic_and_revision_id_bridges_identity() {
        // IDs are opaque ULIDs; pin the literal prefixes + structure, not the
        // ULID value (so the helper format is the thing under test).
        let (d, r) = (dep(), rev());
        assert_eq!(service_name(&d), format!("gtc-svc-{}", d.0));
        assert_eq!(task_def_family(&d, &r), format!("gtc-td-{}-{}", d.0, r.0));
        assert_eq!(task_set_external_id(&r), format!("gtc-rev-{}", r.0));
    }

    #[test]
    fn active_service_exists_ignores_inactive_and_other_names() {
        let out = DescribeServicesOutput::builder()
            .services(
                Service::builder()
                    .service_name("gtc-svc-dep1")
                    .status("ACTIVE")
                    .build(),
            )
            .build();
        assert!(active_service_exists(&out, "gtc-svc-dep1"));
        assert!(!active_service_exists(&out, "gtc-svc-other"));

        let inactive = DescribeServicesOutput::builder()
            .services(
                Service::builder()
                    .service_name("gtc-svc-dep1")
                    .status("INACTIVE")
                    .build(),
            )
            .build();
        assert!(
            !active_service_exists(&inactive, "gtc-svc-dep1"),
            "an INACTIVE (recently deleted) service must be treated as absent"
        );

        let empty = DescribeServicesOutput::builder().build();
        assert!(!active_service_exists(&empty, "gtc-svc-dep1"));
    }

    #[test]
    fn container_def_carries_image_name_and_port() {
        let cd = container_def(&launch(), "registry/img:rev-rev1");
        assert_eq!(cd.name(), Some("worker"));
        assert_eq!(cd.image(), Some("registry/img:rev-rev1"));
        assert_eq!(cd.essential(), Some(true));
        assert_eq!(cd.port_mappings().len(), 1);
        assert_eq!(cd.port_mappings()[0].container_port(), Some(8080));
    }

    #[test]
    fn network_config_maps_subnets_security_groups_and_public_ip() {
        let nc = network_config(&launch());
        let vpc = nc.awsvpc_configuration().expect("awsvpc config present");
        assert_eq!(vpc.subnets(), ["subnet-a", "subnet-b"]);
        assert_eq!(vpc.security_groups(), ["sg-1"]);
        assert_eq!(vpc.assign_public_ip(), Some(&AssignPublicIp::Disabled));

        let mut public = launch();
        public.assign_public_ip = true;
        let nc = network_config(&public);
        assert_eq!(
            nc.awsvpc_configuration().unwrap().assign_public_ip(),
            Some(&AssignPublicIp::Enabled)
        );
    }

    #[test]
    fn load_balancer_binds_container_to_target_group() {
        let lb = load_balancer(&launch(), "arn:aws:elasticloadbalancing:::targetgroup/tg/1");
        assert_eq!(
            lb.target_group_arn(),
            Some("arn:aws:elasticloadbalancing:::targetgroup/tg/1")
        );
        assert_eq!(lb.container_name(), Some("worker"));
        assert_eq!(lb.container_port(), Some(8080));
    }

    #[test]
    fn task_def_arn_from_reads_arn_or_errors() {
        let out = RegisterTaskDefinitionOutput::builder()
            .task_definition(
                TaskDefinition::builder()
                    .task_definition_arn("arn:aws:ecs:us-east-1:111122223333:task-definition/x:1")
                    .build(),
            )
            .build();
        assert_eq!(
            task_def_arn_from(&out).unwrap(),
            "arn:aws:ecs:us-east-1:111122223333:task-definition/x:1"
        );

        let empty = RegisterTaskDefinitionOutput::builder().build();
        assert!(task_def_arn_from(&empty).is_err());
    }

    #[test]
    fn task_set_handle_from_reads_id_with_the_registered_arn() {
        let out = CreateTaskSetOutput::builder()
            .task_set(TaskSet::builder().id("ecs-ts-abc").build())
            .build();
        let handle = task_set_handle_from(&out, "td-arn".to_string()).unwrap();
        assert_eq!(handle.task_set_id, "ecs-ts-abc");
        assert_eq!(handle.task_def_arn, "td-arn");

        let empty = CreateTaskSetOutput::builder().build();
        assert!(task_set_handle_from(&empty, "td-arn".to_string()).is_err());
    }

    fn task_set_with(
        external_id: &str,
        status: StabilityStatus,
        running: i32,
        desired: i32,
    ) -> TaskSet {
        TaskSet::builder()
            .id(format!("ecs-{external_id}"))
            .external_id(external_id)
            .task_definition(format!("td-{external_id}"))
            .stability_status(status)
            .running_count(running)
            .computed_desired_count(desired)
            .build()
    }

    #[test]
    fn find_and_stability_match_by_external_id() {
        let out = DescribeTaskSetsOutput::builder()
            .task_sets(task_set_with(
                "gtc-rev-other",
                StabilityStatus::Stabilizing,
                0,
                1,
            ))
            .task_sets(task_set_with(
                "gtc-rev-rev1",
                StabilityStatus::SteadyState,
                2,
                2,
            ))
            .build();

        let stab = stability_from(&out, "gtc-rev-rev1").unwrap();
        assert!(stab.stabilized);
        assert_eq!(stab.running, 2);
        assert_eq!(stab.desired, 2);

        let other = stability_from(&out, "gtc-rev-other").unwrap();
        assert!(!other.stabilized, "Stabilizing status is not steady state");

        assert!(
            stability_from(&out, "gtc-rev-missing").is_err(),
            "a task set that has not appeared is an honest error"
        );
    }

    #[test]
    fn existing_handle_and_delete_lookup_project_the_matched_task_set() {
        let out = DescribeTaskSetsOutput::builder()
            .task_sets(task_set_with(
                "gtc-rev-rev1",
                StabilityStatus::SteadyState,
                1,
                1,
            ))
            .build();

        let handle = existing_task_set_handle(&out, "gtc-rev-rev1").unwrap();
        assert_eq!(handle.task_set_id, "ecs-gtc-rev-rev1");
        assert_eq!(handle.task_def_arn, "td-gtc-rev-rev1");
        assert!(existing_task_set_handle(&out, "gtc-rev-absent").is_none());

        let del = task_set_for_delete(&out, "gtc-rev-rev1").expect("present");
        assert_eq!(del.id, "ecs-gtc-rev-rev1");
        assert_eq!(del.task_definition.as_deref(), Some("td-gtc-rev-rev1"));
        assert!(
            task_set_for_delete(&out, "gtc-rev-absent").is_none(),
            "absent task set yields None so delete is an idempotent no-op"
        );
    }

    #[test]
    fn target_group_arns_from_skips_partial_entries() {
        let out = DescribeTargetGroupsOutput::builder()
            .target_groups(
                TargetGroup::builder()
                    .target_group_name("tg-a")
                    .target_group_arn("arn-a")
                    .build(),
            )
            .target_groups(
                TargetGroup::builder()
                    .target_group_name("tg-no-arn")
                    .build(),
            )
            .build();
        let map = target_group_arns_from(&out);
        assert_eq!(map.get("tg-a").map(String::as_str), Some("arn-a"));
        assert!(!map.contains_key("tg-no-arn"));
    }

    #[test]
    fn forward_action_mirrors_weight_arn_tuples() {
        let tuples = vec![
            (7000u32, "arn-a".to_string()),
            (3000u32, "arn-b".to_string()),
        ];
        let action = forward_action(&tuples).unwrap();
        assert_eq!(action.r#type(), Some(&ActionTypeEnum::Forward));
        let tgs = action.forward_config().unwrap().target_groups();
        assert_eq!(tgs.len(), 2);
        assert_eq!(tgs[0].target_group_arn(), Some("arn-a"));
        assert_eq!(tgs[0].weight(), Some(700));
        assert_eq!(tgs[1].target_group_arn(), Some("arn-b"));
        assert_eq!(tgs[1].weight(), Some(300));
    }

    /// `bound_target_group` reads the TG ARN bound to a task set; assignment +
    /// routing both rely on it being the source of truth.
    #[test]
    fn bound_target_group_reads_the_load_balancer_binding() {
        let out = DescribeTaskSetsOutput::builder()
            .task_sets(
                TaskSet::builder()
                    .external_id("gtc-rev-blue")
                    .load_balancers(LoadBalancer::builder().target_group_arn("arn-blue").build())
                    .build(),
            )
            .task_sets(
                // A task set with no LB binding yields None (not yet routable).
                TaskSet::builder().external_id("gtc-rev-bare").build(),
            )
            .build();
        assert_eq!(
            bound_target_group(&out, "gtc-rev-blue").as_deref(),
            Some("arn-blue")
        );
        assert_eq!(bound_target_group(&out, "gtc-rev-bare"), None);
        assert_eq!(bound_target_group(&out, "gtc-rev-absent"), None);
    }

    /// `assigned_pool_members` collects every TG ARN bound to a live task set —
    /// the "taken" set pool assignment subtracts from the pool.
    #[test]
    fn assigned_pool_members_collects_every_bound_target_group() {
        let out = DescribeTaskSetsOutput::builder()
            .task_sets(
                TaskSet::builder()
                    .external_id("gtc-rev-blue")
                    .load_balancers(LoadBalancer::builder().target_group_arn("arn-blue").build())
                    .build(),
            )
            .task_sets(
                TaskSet::builder()
                    .external_id("gtc-rev-green")
                    .load_balancers(
                        LoadBalancer::builder()
                            .target_group_arn("arn-green")
                            .build(),
                    )
                    .build(),
            )
            .build();
        let taken = assigned_pool_members(&out);
        assert!(taken.contains("arn-blue") && taken.contains("arn-green"));
        assert_eq!(taken.len(), 2);
        assert!(assigned_pool_members(&DescribeTaskSetsOutput::builder().build()).is_empty());
    }

    /// `pick_free_pool_member` returns the first pool member (in order) not
    /// already bound, so blue/green lands a fresh revision in a free TG; `None`
    /// when the pool is exhausted or empty.
    #[test]
    fn pick_free_pool_member_picks_the_first_free_in_order() {
        let pool = vec![
            "arn-blue".to_string(),
            "arn-green".to_string(),
            "arn-amber".to_string(),
        ];
        let taken = std::collections::HashSet::from(["arn-blue".to_string()]);
        assert_eq!(
            pick_free_pool_member(&pool, &taken).as_deref(),
            Some("arn-green"),
            "skips the bound member, picks the next in configured order"
        );

        let all_taken = pool.iter().cloned().collect();
        assert_eq!(
            pick_free_pool_member(&pool, &all_taken),
            None,
            "pool exhausted → None (caller errors)"
        );
        assert_eq!(
            pick_free_pool_member(&[], &std::collections::HashSet::new()),
            None,
            "empty pool → None"
        );
    }

    /// `service_name_from_arn` takes the segment after the final `/`, and passes
    /// a bare name (no `/`) through unchanged — so the single-owner guard can
    /// prefix-filter `ListServices` ARNs against [`SERVICE_NAME_PREFIX`].
    #[test]
    fn service_name_from_arn_takes_the_segment_after_the_final_slash() {
        assert_eq!(
            service_name_from_arn(
                "arn:aws:ecs:eu-west-1:123456789012:service/greentic-prod/gtc-svc-01ABC"
            ),
            "gtc-svc-01ABC"
        );
        assert_eq!(service_name_from_arn("gtc-svc-01ABC"), "gtc-svc-01ABC");
    }

    /// `conflicting_pool_owner` fails closed when a sibling deployment already
    /// holds a pool member, names that owner + the shared TG, and stays silent
    /// when no sibling contends or a sibling holds an out-of-pool TG (a different
    /// binding's pool).
    #[test]
    fn conflicting_pool_owner_flags_only_a_sibling_holding_a_pool_member() {
        let pool = vec!["tg-blue".to_string(), "tg-green".to_string()];

        // A sibling deployment already bound `tg-blue` from the shared pool.
        let owner = vec![("gtc-svc-other".to_string(), vec!["tg-blue".to_string()])];
        assert_eq!(
            conflicting_pool_owner(&owner, &pool),
            Some(("gtc-svc-other".to_string(), "tg-blue".to_string())),
            "a sibling holding a pool member fails closed and names the owner",
        );

        // Sibling holds a TG outside this env's pool (a different binding) — not
        // a conflict.
        let unrelated = vec![(
            "gtc-svc-other".to_string(),
            vec!["tg-unrelated".to_string()],
        )];
        assert_eq!(
            conflicting_pool_owner(&unrelated, &pool),
            None,
            "an out-of-pool sibling binding does not contend",
        );

        // No siblings → free to claim.
        assert_eq!(conflicting_pool_owner(&[], &pool), None);
    }

    /// `pool_arns_from` passes ARN-form entries through, resolves name-form ones
    /// against the lookup map (preserving order), and errors on an unknown name.
    #[test]
    fn pool_arns_from_resolves_names_passes_arns_and_errors_on_unknown() {
        const BLUE: &str = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/blue/1";
        const GREEN: &str =
            "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/green/2";
        let resolved = HashMap::from([("green-tg".to_string(), GREEN.to_string())]);

        // ARN passes through; name resolves; order preserved.
        assert_eq!(
            pool_arns_from(&[BLUE.to_string(), "green-tg".to_string()], &resolved).unwrap(),
            vec![BLUE.to_string(), GREEN.to_string()],
        );

        let missing = vec!["typo-tg".to_string()];
        assert!(
            pool_arns_from(&missing, &resolved).is_err(),
            "an unresolved name must error, not silently shrink the pool"
        );

        // A duplicate target group (here a name resolving to an already-listed
        // ARN) is a config error — it would assign two revisions the same TG.
        let dup = vec![GREEN.to_string(), "green-tg".to_string()];
        assert!(
            pool_arns_from(&dup, &resolved).is_err(),
            "a target group repeated in the pool must be rejected"
        );
        assert!(
            pool_arns_from(&[BLUE.to_string(), GREEN.to_string()], &resolved).is_ok(),
            "a pool of distinct ARNs is accepted"
        );
    }

    #[test]
    fn first_duplicate_finds_the_first_repeat_in_order() {
        assert_eq!(
            first_duplicate(&["a".to_string(), "b".to_string(), "a".to_string()]),
            Some("a")
        );
        assert_eq!(
            first_duplicate(&["a".to_string(), "b".to_string(), "c".to_string()]),
            None
        );
        assert_eq!(first_duplicate(&[]), None);
    }

    /// `weighted_target_groups` maps each weighted revision to its task set's
    /// bound TG ARN; a revision with no live task set is an error.
    #[test]
    fn weighted_target_groups_maps_revisions_to_bound_arns() {
        let blue = RevisionId(Ulid::from(0xb1u128));
        let out = DescribeTaskSetsOutput::builder()
            .task_sets(
                TaskSet::builder()
                    .external_id(task_set_external_id(&blue))
                    .load_balancers(LoadBalancer::builder().target_group_arn("arn-blue").build())
                    .build(),
            )
            .build();

        let tuples = weighted_target_groups(
            &[TargetGroupWeight {
                revision_id: blue,
                weight_bps: 10000,
            }],
            &out,
        )
        .unwrap();
        assert_eq!(tuples, vec![(10000u32, "arn-blue".to_string())]);

        // A weighted revision with no warmed task set is an error.
        let unwarmed = RevisionId(Ulid::from(0xddu128));
        assert!(
            weighted_target_groups(
                &[TargetGroupWeight {
                    revision_id: unwarmed,
                    weight_bps: 10000,
                }],
                &out,
            )
            .is_err()
        );
    }

    #[test]
    fn elb_weight_scales_bps_and_clamps_to_the_api_ceiling() {
        assert_eq!(elb_weight(0), 0);
        assert_eq!(elb_weight(2500), 250);
        assert_eq!(elb_weight(5000), 500);
        // A lone 100% revision (10000bps) clamps to the ELBv2 999 ceiling.
        assert_eq!(elb_weight(10000), 999);
    }

    /// Shared shape check for the UUID-form idempotency tokens: 36 chars, dashes
    /// at 8/13/18/23, lowercase-hex elsewhere.
    fn assert_uuid_form_shape(token: &str) {
        assert_eq!(
            token.len(),
            36,
            "ECS clientToken is a 36-char UUID-form string"
        );
        let dashes: Vec<usize> = token.match_indices('-').map(|(i, _)| i).collect();
        assert_eq!(dashes, vec![8, 13, 18, 23], "dash positions: {token}");
        assert!(
            token.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
            "token is lowercase-hex + dashes only; got {token}"
        );
    }

    #[test]
    fn service_client_token_is_deterministic_uuid_shaped_and_per_deployment() {
        let d = dep();
        let token = service_client_token(&d);
        assert_eq!(
            token,
            service_client_token(&d),
            "same deployment must yield the same idempotency token so concurrent \
             ensure_service calls dedupe"
        );
        assert_uuid_form_shape(&token);
        // Distinct deployments get distinct tokens — no cross-deployment dedupe.
        assert_ne!(
            service_client_token(&DeploymentId(Ulid::from(0xbeef_u128))),
            token
        );
    }

    #[test]
    fn task_set_client_token_is_deterministic_uuid_shaped_and_per_revision() {
        let r = rev();
        let token = task_set_client_token(&r);
        assert_eq!(
            token,
            task_set_client_token(&r),
            "same revision must yield the same idempotency token so concurrent \
             create_task_set calls dedupe"
        );
        assert_uuid_form_shape(&token);
        // Distinct revisions get distinct tokens — no cross-revision dedupe.
        assert_ne!(
            task_set_client_token(&RevisionId(Ulid::from(0xbeef_u128))),
            token
        );
    }

    /// Parity guard: every IAM action the real target calls must be in the
    /// credentials preflight's validated verb list, so a role that passes
    /// `gtc op credentials requirements` can actually warm / shift / archive.
    #[test]
    fn real_target_iam_actions_are_a_subset_of_validated_verbs() {
        use crate::env_packs::aws::credentials::VALIDATED_IAM_VERBS;
        for action in REAL_ECS_TARGET_IAM_ACTIONS {
            assert!(
                VALIDATED_IAM_VERBS.contains(action),
                "RealEcsTarget calls `{action}` but the credentials preflight does \
                 not validate it — add it to VALIDATED_IAM_VERBS so a validated \
                 role does not fail on the first live deploy"
            );
        }
    }

    /// The bound-session injection maps all three STS parts onto the static
    /// provider and passes the session expiry through (so the SDK treats the
    /// credentials as expiring rather than permanent).
    #[test]
    fn session_credentials_carry_all_three_parts_and_the_expiry() {
        let expiration = chrono::DateTime::from_timestamp(1_900_000_000, 0).unwrap();
        let session = AssumedSession {
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: "shh-the-key".to_string(),
            session_token: "the-session-blob".to_string(),
            expiration,
            issued_at: chrono::DateTime::from_timestamp(1_899_000_000, 0).unwrap(),
        };
        let creds = session_credentials(&session);
        assert_eq!(creds.access_key_id(), "AKIAEXAMPLE");
        assert_eq!(creds.secret_access_key(), "shh-the-key");
        assert_eq!(creds.session_token(), Some("the-session-blob"));
        assert_eq!(
            creds.expiry(),
            Some(std::time::SystemTime::from(expiration))
        );
    }

    /// Build a non-default listener rule with the given host/path condition
    /// values — the shape `describe_rules` returns for a per-deployment rule.
    fn rule_with(rule_arn: &str, priority: &str, host: Option<&str>, path: Option<&str>) -> Rule {
        let mut conditions = Vec::new();
        if let Some(h) = host {
            conditions.push(
                RuleCondition::builder()
                    .field("host-header")
                    .host_header_config(HostHeaderConditionConfig::builder().values(h).build())
                    .build(),
            );
        }
        if let Some(p) = path {
            conditions.push(
                RuleCondition::builder()
                    .field("path-pattern")
                    .path_pattern_config(PathPatternConditionConfig::builder().values(p).build())
                    .build(),
            );
        }
        Rule::builder()
            .rule_arn(rule_arn)
            .priority(priority)
            .is_default(false)
            .set_conditions(Some(conditions))
            .build()
    }

    /// `routing_conditions` emits one host-header and/or one path-pattern
    /// condition, carrying the operator's values, and never an empty vec.
    #[test]
    fn routing_conditions_emits_host_and_path_conditions() {
        let both = routing_conditions(&ListenerRouting {
            host: Some("app.example.com".into()),
            path: Some("/app/*".into()),
        });
        assert_eq!(both.len(), 2);
        assert_eq!(
            both[0].host_header_config().unwrap().values()[0],
            "app.example.com"
        );
        assert_eq!(both[1].path_pattern_config().unwrap().values()[0], "/app/*");

        let host_only = routing_conditions(&ListenerRouting {
            host: Some("h".into()),
            path: None,
        });
        assert_eq!(host_only.len(), 1);
        assert!(host_only[0].host_header_config().is_some());

        let path_only = routing_conditions(&ListenerRouting {
            host: None,
            path: Some("/p".into()),
        });
        assert_eq!(path_only.len(), 1);
        assert!(path_only[0].path_pattern_config().is_some());
    }

    /// `match_rule` returns the rule whose host/path condition equals the
    /// deployment's routing, skips the default rule and out-of-scope siblings,
    /// and returns `None` when nothing matches (so the caller creates one).
    #[test]
    fn match_rule_finds_the_rule_with_matching_conditions() {
        let want = ListenerRouting {
            host: Some("app.example.com".into()),
            path: Some("/app/*".into()),
        };
        let rules = vec![
            // Default rule (no conditions) — never matched.
            Rule::builder()
                .rule_arn("arn:rule/default")
                .priority("default")
                .is_default(true)
                .build(),
            // A sibling deployment's rule — different host.
            rule_with(
                "arn:rule/sibling",
                "10",
                Some("other.example.com"),
                Some("/app/*"),
            ),
            // Ours.
            rule_with(
                "arn:rule/ours",
                "20",
                Some("app.example.com"),
                Some("/app/*"),
            ),
        ];
        assert_eq!(match_rule(&rules, &want).as_deref(), Some("arn:rule/ours"));

        // A routing with no live rule → create path.
        let absent = ListenerRouting {
            host: Some("nope.example.com".into()),
            path: None,
        };
        assert_eq!(match_rule(&rules, &absent), None);
    }

    /// `next_rule_priority` is one above the highest numeric priority, ignores
    /// the non-numeric `"default"`, and starts at 1 on an empty listener.
    #[test]
    fn next_rule_priority_is_one_above_the_max_numeric() {
        let rules = vec![
            Rule::builder()
                .rule_arn("arn:rule/default")
                .priority("default")
                .is_default(true)
                .build(),
            rule_with("arn:rule/a", "5", Some("a"), None),
            rule_with("arn:rule/b", "12", Some("b"), None),
        ];
        assert_eq!(next_rule_priority(&rules), 13);
        assert_eq!(next_rule_priority(&[]), 1);
    }

    /// `tag_descriptions_owned_by` recognizes only a rule carrying THIS
    /// deployment's owner tag — a sibling's tag, a foreign key, or no tags at
    /// all (an operator-managed rule) all read as not-owned, so the caller fails
    /// closed instead of hijacking the rule.
    #[test]
    fn tag_descriptions_owned_by_matches_only_this_deployments_owner_tag() {
        let dep = DeploymentId(Ulid::from(0x01_u128));
        let owner_value = dep.0.to_string();

        let descriptions_with = |tags: Vec<Tag>| {
            vec![
                TagDescription::builder()
                    .resource_arn("arn:rule/x")
                    .set_tags(Some(tags))
                    .build(),
            ]
        };

        // Our owner tag → owned.
        let ours = descriptions_with(vec![owner_tag(&dep)]);
        assert!(tag_descriptions_owned_by(&ours, &dep));

        // A sibling deployment's owner tag → not ours.
        let sibling = descriptions_with(vec![
            Tag::builder()
                .key(RULE_OWNER_TAG_KEY)
                .value(DeploymentId(Ulid::from(0x02_u128)).0.to_string())
                .build(),
        ]);
        assert!(!tag_descriptions_owned_by(&sibling, &dep));

        // Right value but a different key → not ours.
        let wrong_key = descriptions_with(vec![
            Tag::builder().key("other").value(&owner_value).build(),
        ]);
        assert!(!tag_descriptions_owned_by(&wrong_key, &dep));

        // No tags (operator-managed rule) → not ours.
        assert!(!tag_descriptions_owned_by(&descriptions_with(vec![]), &dep));
        assert!(!tag_descriptions_owned_by(&[], &dep));
    }

    /// `routing_summary` renders host, path, or both for the conflict message.
    #[test]
    fn routing_summary_renders_host_path_or_both() {
        assert_eq!(
            routing_summary(&ListenerRouting {
                host: Some("h".into()),
                path: Some("/p".into()),
            }),
            "host `h` + path `/p`"
        );
        assert_eq!(
            routing_summary(&ListenerRouting {
                host: Some("h".into()),
                path: None,
            }),
            "host `h`"
        );
        assert_eq!(
            routing_summary(&ListenerRouting {
                host: None,
                path: Some("/p".into()),
            }),
            "path `/p`"
        );
    }
}
