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
//! image + target-group **name** — the things that vary per revision. A real
//! Fargate `RegisterTaskDefinition` / `CreateTaskSet` also needs the
//! launch-time compute + network config (execution role, subnets, security
//! groups, CPU / memory, container port). That config is **stable per binding**
//! (one VPC / role set per env-pack binding), not per revision, so it lives on
//! [`FargateLaunchConfig`] held by the target — not on the seam specs. This
//! keeps the seam (and the [`InMemoryEcs`] fake) minimal while letting the real
//! target stand up a complete task definition.
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
    Action, ActionTypeEnum, ForwardActionConfig, TargetGroupTuple,
};
use greentic_deploy_spec::{DeploymentId, RevisionId};

use super::deploy_target::{
    EcsDeployTarget, EcsTargetError, ListenerRef, ServiceSpec, TargetGroupWeight, TaskSetHandle,
    TaskSetRef, TaskSetSpec, TaskSetStability,
};

/// Per-binding Fargate launch config the real target needs to stand up a task
/// definition + task set, but which the per-revision seam specs deliberately do
/// not carry (it is stable across a binding's revisions). Sourced from the
/// binding's wizard answers by the construction path that wires this target
/// (PR-3); the seam / fake stay unaware of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FargateLaunchConfig {
    /// IAM role the ECS agent assumes to pull the image + write logs.
    pub execution_role_arn: String,
    /// Optional IAM role the task's containers assume (app-level AWS access).
    pub task_role_arn: Option<String>,
    /// awsvpc subnets the Fargate ENIs attach to (at least one).
    pub subnets: Vec<String>,
    /// Security groups applied to the task ENIs.
    pub security_groups: Vec<String>,
    /// Whether tasks get a public IP (public subnets without a NAT need this to
    /// reach ECR / the image registry).
    pub assign_public_ip: bool,
    /// Task-level CPU units (Fargate requires it at the task level), e.g. `256`.
    pub cpu: String,
    /// Task-level memory (MiB) as a string, e.g. `512`.
    pub memory: String,
    /// Logical container name in the task definition; also the `containerName`
    /// the load balancer routes to.
    pub container_name: String,
    /// Port the container listens on / the target group forwards to.
    pub container_port: i32,
}

/// Production [`EcsDeployTarget`]: ECS task sets + ELBv2 weighted forward
/// actions, region-pinned at construction.
#[derive(Debug, Clone)]
pub struct RealEcsTarget {
    ecs: aws_sdk_ecs::Client,
    elb: aws_sdk_elasticloadbalancingv2::Client,
    launch: FargateLaunchConfig,
}

/// The IAM actions [`RealEcsTarget`]'s five methods call at deploy time — the
/// authoritative ECS / ELBv2 runtime surface. A test pins this ⊆
/// [`VALIDATED_IAM_VERBS`](super::credentials::VALIDATED_IAM_VERBS) so the
/// credentials preflight can never under-declare what a live deploy needs:
/// adding an SDK call here without the matching validated verb fails CI rather
/// than the customer's first warm / traffic-shift / archive.
pub const REAL_ECS_TARGET_IAM_ACTIONS: &[&str] = &[
    "ecs:DescribeServices",                      // ensure_service
    "ecs:CreateService",                         // ensure_service
    "ecs:RegisterTaskDefinition",                // create_task_set
    "ecs:CreateTaskSet",                         // create_task_set
    "ecs:DescribeTaskSets", // create_task_set / task_set_stability / delete_task_set
    "ecs:DeleteTaskSet",    // delete_task_set
    "ecs:DeregisterTaskDefinition", // delete_task_set
    "elasticloadbalancing:DescribeTargetGroups", // create_task_set / apply_listener_weights
    "elasticloadbalancing:ModifyListener", // apply_listener_weights
];

impl RealEcsTarget {
    /// Resolve the AWS credential chain (region-pinned) and build the ECS +
    /// ELBv2 clients. Mirrors `RealAwsClient::resolve` in `credentials.rs`: the
    /// region comes from the binding (the env-pack binding is single-region, so
    /// the per-spec `region` always equals this), and the credential chain is
    /// the same one the rest of the AWS code walks.
    pub async fn resolve(
        region: &str,
        launch: FargateLaunchConfig,
    ) -> Result<Self, EcsTargetError> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        if config.credentials_provider().is_none() {
            return Err(EcsTargetError::Api(
                "no AWS credentials provider in the resolved SDK config — set AWS_PROFILE or \
                 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"
                    .to_string(),
            ));
        }
        Ok(Self {
            ecs: aws_sdk_ecs::Client::new(&config),
            elb: aws_sdk_elasticloadbalancingv2::Client::new(&config),
            launch,
        })
    }

    /// DescribeTargetGroups by name → ARN. The seam routes by target-group
    /// **name**; ECS task-set load balancers and ELBv2 forward actions need the
    /// **ARN**, so the real target resolves it.
    async fn target_group_arns(
        &self,
        names: &[String],
    ) -> Result<HashMap<String, String>, EcsTargetError> {
        if names.is_empty() {
            return Ok(HashMap::new());
        }
        let out = self
            .elb
            .describe_target_groups()
            .set_names(Some(names.to_vec()))
            .send()
            .await
            .map_err(|e| api("describe_target_groups", e))?;
        Ok(target_group_arns_from(&out))
    }
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

        let target_group_arn = self
            .target_group_arns(std::slice::from_ref(&spec.target_group))
            .await?
            .remove(&spec.target_group)
            .ok_or_else(|| {
                EcsTargetError::Api(format!(
                    "target group `{}` not found in this account/region",
                    spec.target_group
                ))
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

    /// Mirror the deployment's `TrafficSplit` onto the ALB by **replacing the
    /// listener's default action** with a weighted forward across the
    /// revisions' target groups.
    ///
    /// **Ownership model — one deployment per listener.** This writes the
    /// listener's *default* action, so binding an `alb_listener_arn` hands that
    /// listener's routing to the deployer: any pre-existing default / auth /
    /// redirect action is replaced. `deployment_id` is carried on
    /// [`ListenerRef`] but not yet used to scope the write, so serving multiple
    /// deployments behind one listener would clobber siblings. Per-deployment
    /// scoping (a `ModifyRule` rule keyed by a host/path condition, preserving
    /// unrelated listener actions) needs the operator's routing topology and
    /// lands with the construction wiring in the next slice (PR-3).
    ///
    /// [`ListenerRef`]: super::deploy_target::ListenerRef
    async fn apply_listener_weights(
        &self,
        listener: &ListenerRef,
        weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError> {
        let names: Vec<String> = weights.iter().map(|w| w.target_group.clone()).collect();
        let arns = self.target_group_arns(&names).await?;
        let action = forward_action(weights, &arns)?;
        self.elb
            .modify_listener()
            .listener_arn(&listener.listener_arn)
            .default_actions(action)
            .send()
            .await
            .map_err(|e| api("modify_listener", e))?;
        Ok(())
    }
}

// ── Pure helpers (the unit-tested core) ──────────────────────────────────────

/// Map any SDK error to a [`EcsTargetError::Api`] carrying the operation name +
/// the response detail, so operators get an actionable message.
fn api<E: std::fmt::Display>(op: &str, err: E) -> EcsTargetError {
    EcsTargetError::Api(format!("ecs {op}: {err}"))
}

/// Deterministic ECS service name for a deployment (one EXTERNAL-controller
/// service per `deployment_id`).
fn service_name(deployment_id: &DeploymentId) -> String {
    format!("gtc-svc-{}", deployment_id.0)
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

/// Build the weighted forward [`Action`] mirroring the `TrafficSplit`: one
/// target-group tuple per weight, ARN resolved from `arns`.
fn forward_action(
    weights: &[TargetGroupWeight],
    arns: &HashMap<String, String>,
) -> Result<Action, EcsTargetError> {
    let mut forward = ForwardActionConfig::builder();
    for w in weights {
        let arn = arns.get(&w.target_group).ok_or_else(|| {
            EcsTargetError::Api(format!(
                "target group `{}` not found in this account/region",
                w.target_group
            ))
        })?;
        forward = forward.target_groups(
            TargetGroupTuple::builder()
                .target_group_arn(arn)
                .weight(elb_weight(w.weight_bps))
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
    fn forward_action_mirrors_weights_and_resolves_arns() {
        let arns = HashMap::from([
            ("tg-a".to_string(), "arn-a".to_string()),
            ("tg-b".to_string(), "arn-b".to_string()),
        ]);
        let weights = vec![
            TargetGroupWeight {
                revision_id: RevisionId(Ulid::from(0xa_u128)),
                weight_bps: 7000,
                target_group: "tg-a".to_string(),
            },
            TargetGroupWeight {
                revision_id: RevisionId(Ulid::from(0xb_u128)),
                weight_bps: 3000,
                target_group: "tg-b".to_string(),
            },
        ];
        let action = forward_action(&weights, &arns).unwrap();
        assert_eq!(action.r#type(), Some(&ActionTypeEnum::Forward));
        let tgs = action.forward_config().unwrap().target_groups();
        assert_eq!(tgs.len(), 2);
        assert_eq!(tgs[0].target_group_arn(), Some("arn-a"));
        assert_eq!(tgs[0].weight(), Some(700));
        assert_eq!(tgs[1].target_group_arn(), Some("arn-b"));
        assert_eq!(tgs[1].weight(), Some(300));
    }

    #[test]
    fn forward_action_errors_on_unresolved_target_group() {
        let weights = vec![TargetGroupWeight {
            revision_id: RevisionId(Ulid::from(0xa_u128)),
            weight_bps: 10000,
            target_group: "tg-missing".to_string(),
        }];
        assert!(forward_action(&weights, &HashMap::new()).is_err());
    }

    #[test]
    fn elb_weight_scales_bps_and_clamps_to_the_api_ceiling() {
        assert_eq!(elb_weight(0), 0);
        assert_eq!(elb_weight(2500), 250);
        assert_eq!(elb_weight(5000), 500);
        // A lone 100% revision (10000bps) clamps to the ELBv2 999 ceiling.
        assert_eq!(elb_weight(10000), 999);
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
        // UUID shape: 36 chars with dashes at 8/13/18/23, hex elsewhere.
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
        // Distinct deployments get distinct tokens — no cross-deployment dedupe.
        let other = DeploymentId(Ulid::from(0xbeef_u128));
        assert_ne!(service_client_token(&other), token);
    }

    #[test]
    fn task_set_client_token_is_deterministic_uuid_shaped_and_per_revision() {
        let r = rev();
        let tok = task_set_client_token(&r);
        assert_eq!(
            tok,
            task_set_client_token(&r),
            "same revision must yield the same idempotency token so concurrent \
             create_task_set calls dedupe"
        );
        // UUID shape: 36 chars with dashes at 8/13/18/23, hex elsewhere.
        assert_eq!(
            tok.len(),
            36,
            "ECS clientToken is a 36-char UUID-form string"
        );
        let dashes: Vec<usize> = tok.match_indices('-').map(|(i, _)| i).collect();
        assert_eq!(dashes, vec![8, 13, 18, 23], "dash positions: {tok}");
        assert!(
            tok.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
            "token is lowercase-hex + dashes only; got {tok}"
        );
        // Distinct revisions get distinct tokens — no cross-revision dedupe.
        let other = RevisionId(Ulid::from(0xbeef_u128));
        assert_ne!(task_set_client_token(&other), tok);
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
}
