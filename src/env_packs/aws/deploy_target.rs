//! The [`EcsDeployTarget`] seam: the side-effect surface the AWS-ECS
//! [`Deployer`](crate::env_packs::deployer::Deployer) verbs mutate through.
//!
//! This is the AWS twin of [`K8sCluster`](crate::env_packs::k8s::cluster::K8sCluster):
//! an object-safe async trait the verbs call, with three implementations —
//!
//! - [`InMemoryEcs`] — the unit-test + conformance fake. Records services,
//!   task sets, and listener weights in maps so per-verb tests can assert what
//!   landed. `task_set_stability` reports stable immediately so the warm wait
//!   resolves on the first poll.
//! - [`UnconfiguredEcsTarget`] — the [`AwsEcsDeployerHandler`](super::AwsEcsDeployerHandler)
//!   default. Every method fails with [`EcsTargetError::Unconfigured`] so a
//!   handler built without a real client fails verbs **honestly** rather than
//!   pretending the AWS calls happened (mirrors `UnconfiguredCluster`).
//! - `RealEcsTarget` (the aws-sdk-backed impl) lands in a follow-up PR behind
//!   the `deploy-aws-ecs` feature; it implements this same trait unchanged.
//!
//! ## Why task sets (ECS EXTERNAL deployment)
//!
//! The deployer drives ECS services configured with the `EXTERNAL` deployment
//! controller: one service per `deployment_id`, one **task set** per revision.
//! `warm` registers a task set; `apply_traffic_split` writes weighted forward
//! rules across the revisions' target groups; `archive` deletes the task set.
//! This is the AWS-native blue/green shape (`ecs:CreateTaskSet` is already in
//! the validated IAM verb list) and keeps each revision independently
//! addressable on the ALB.

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, RevisionId};

/// Opaque ECS identifiers. Strings on the wire; newtyped only where the
/// domain benefits — these two are pass-through handles the real SDK fills.
pub type TaskDefArn = String;
pub type TaskSetId = String;

/// Failures the seam surfaces to the verbs. The verb layer maps every variant
/// into [`DeployerError::Provider`](crate::env_packs::deployer::DeployerError::Provider)
/// — preconditions have already passed by the time the seam is touched, so any
/// seam failure is provider-side.
#[derive(Debug, thiserror::Error)]
pub enum EcsTargetError {
    /// An AWS API call failed. Carries an actionable message (the operation +
    /// the response detail) so operators can act.
    #[error("ECS API error: {0}")]
    Api(String),
    /// The handler has no real ECS client wired (the default
    /// [`UnconfiguredEcsTarget`]). The operator must bind AWS credentials and
    /// rebuild the handler with a connected client.
    #[error("no ECS API client configured for this handler")]
    Unconfigured,
}

/// Desired state of the per-deployment ECS service (one per `deployment_id`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub deployment_id: DeploymentId,
    pub cluster: String,
    pub region: String,
}

/// Desired state of one revision's task set.
///
/// The ALB target group this revision binds to is **not** on the spec: the
/// real target assigns it statelessly from its operator-supplied pool (reading
/// which pool members are already bound to live task sets), so the deployer
/// never computes or carries a target-group name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSetSpec {
    pub deployment_id: DeploymentId,
    pub revision_id: RevisionId,
    pub cluster: String,
    pub region: String,
    /// Container image the Fargate task runs.
    pub image: String,
}

/// Identity of a task set for describe / delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSetRef {
    pub deployment_id: DeploymentId,
    pub revision_id: RevisionId,
    pub cluster: String,
    /// AWS region the task set lives in. ECS is regional, so describe /
    /// delete must carry it — a fresh process cannot reconstruct the region
    /// from the other identifiers. Populated from `AwsEcsParams::region`.
    pub region: String,
}

/// What [`EcsDeployTarget::create_task_set`] returns: the created (or existing,
/// on an idempotent re-create) task set plus its task-definition ARN, so
/// [`EcsDeployTarget::delete_task_set`] can deregister the definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSetHandle {
    pub task_set_id: TaskSetId,
    pub task_def_arn: TaskDefArn,
}

/// Rollout status of a task set, polled by the warm readiness wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskSetStability {
    /// True once the task set has reached steady state (running == desired AND
    /// its target group is healthy).
    pub stabilized: bool,
    pub running: u32,
    pub desired: u32,
}

/// Identity of the ALB listener whose weighted forward action mirrors a
/// deployment's `TrafficSplit`. Carries the operator-supplied listener ARN
/// (the wizard's `alb_listener_arn`); the verbs build this only when an ALB
/// mirror is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerRef {
    pub deployment_id: DeploymentId,
    pub listener_arn: String,
    /// ECS cluster the deployment's task sets live in — the target reads their
    /// load-balancer bindings to map each weighted revision to its target
    /// group, and `describe_task_sets` is cluster-scoped.
    pub cluster: String,
}

/// One weighted revision in a listener rule's forward action. The revision's
/// target group is **not** carried here: the real target maps each revision to
/// the TG its task set is bound to (read from the live task sets), so the
/// deployer passes only the routing weight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetGroupWeight {
    pub revision_id: RevisionId,
    pub weight_bps: u32,
}

/// The side-effect seam the AWS-ECS deployer verbs drive.
///
/// Object-safe (`async_trait`) so the handler holds `Arc<dyn EcsDeployTarget>`
/// and the real aws-sdk client is one implementation among the fakes. Every
/// method MUST be idempotent: `ensure_service` / `create_task_set` upsert,
/// `delete_task_set` of an absent set is `Ok`. The conformance bench leans on
/// this.
#[async_trait]
pub trait EcsDeployTarget: std::fmt::Debug + Send + Sync {
    /// Create the per-deployment `EXTERNAL`-controller service if absent.
    /// Idempotent: a second call against an existing service is `Ok`.
    async fn ensure_service(&self, spec: &ServiceSpec) -> Result<(), EcsTargetError>;

    /// Register the revision's task definition + create its task set.
    /// Idempotent: re-creating a task set for an existing `(deployment,
    /// revision)` returns the existing [`TaskSetHandle`] without registering a
    /// second definition.
    async fn create_task_set(&self, spec: &TaskSetSpec) -> Result<TaskSetHandle, EcsTargetError>;

    /// Poll a task set's rollout status (steady state + target-group health).
    async fn task_set_stability(
        &self,
        task_set: &TaskSetRef,
    ) -> Result<TaskSetStability, EcsTargetError>;

    /// Delete a task set and deregister its task definition. Idempotent
    /// against an already-absent set.
    async fn delete_task_set(&self, task_set: &TaskSetRef) -> Result<(), EcsTargetError>;

    /// Set the listener's weighted forward action across the deployment's
    /// task-set target groups (the ALB mirror of the env's `TrafficSplit`).
    async fn apply_listener_weights(
        &self,
        listener: &ListenerRef,
        weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError>;
}

/// The default target for a handler with no real client wired. Every provider
/// method fails honestly so an unconfigured deployer cannot silently "succeed".
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfiguredEcsTarget;

#[async_trait]
impl EcsDeployTarget for UnconfiguredEcsTarget {
    async fn ensure_service(&self, _spec: &ServiceSpec) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn create_task_set(&self, _spec: &TaskSetSpec) -> Result<TaskSetHandle, EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn task_set_stability(
        &self,
        _task_set: &TaskSetRef,
    ) -> Result<TaskSetStability, EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn delete_task_set(&self, _task_set: &TaskSetRef) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn apply_listener_weights(
        &self,
        _listener: &ListenerRef,
        _weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
}

/// In-memory fake target for unit tests + the conformance bench.
///
/// Records the side effects so tests can assert what landed. `task_set_stability`
/// reports stable immediately, so the warm readiness wait resolves on the first
/// poll (the timeout path is exercised by a scripted fake in `deployer.rs`).
#[derive(Debug, Default)]
pub struct InMemoryEcs {
    /// Deployments whose service has been ensured.
    services: std::sync::Mutex<std::collections::BTreeSet<DeploymentId>>,
    /// Task sets keyed by `(deployment, revision)`.
    task_sets:
        std::sync::Mutex<std::collections::BTreeMap<(DeploymentId, RevisionId), TaskSetHandle>>,
    /// Last-applied listener weights per deployment.
    weights: std::sync::Mutex<std::collections::BTreeMap<DeploymentId, Vec<TargetGroupWeight>>>,
}

impl InMemoryEcs {
    /// Snapshot of the ensured services.
    pub fn services(&self) -> std::collections::BTreeSet<DeploymentId> {
        self.services.lock().expect("mutex not poisoned").clone()
    }

    /// Snapshot of the live task sets.
    pub fn task_sets(
        &self,
    ) -> std::collections::BTreeMap<(DeploymentId, RevisionId), TaskSetHandle> {
        self.task_sets.lock().expect("mutex not poisoned").clone()
    }

    /// Snapshot of the last-applied weights for a deployment.
    pub fn weights_for(&self, deployment_id: DeploymentId) -> Option<Vec<TargetGroupWeight>> {
        self.weights
            .lock()
            .expect("mutex not poisoned")
            .get(&deployment_id)
            .cloned()
    }
}

#[async_trait]
impl EcsDeployTarget for InMemoryEcs {
    async fn ensure_service(&self, spec: &ServiceSpec) -> Result<(), EcsTargetError> {
        self.services
            .lock()
            .expect("mutex not poisoned")
            .insert(spec.deployment_id);
        Ok(())
    }

    async fn create_task_set(&self, spec: &TaskSetSpec) -> Result<TaskSetHandle, EcsTargetError> {
        let key = (spec.deployment_id, spec.revision_id);
        let mut sets = self.task_sets.lock().expect("mutex not poisoned");
        // Idempotent: re-creating an existing task set returns the existing
        // handle without minting a new id.
        if let Some(existing) = sets.get(&key) {
            return Ok(existing.clone());
        }
        let handle = TaskSetHandle {
            task_set_id: format!("ts-{}-{}", spec.deployment_id.0, spec.revision_id.0),
            task_def_arn: format!("td-{}-{}", spec.deployment_id.0, spec.revision_id.0),
        };
        sets.insert(key, handle.clone());
        Ok(handle)
    }

    async fn task_set_stability(
        &self,
        _task_set: &TaskSetRef,
    ) -> Result<TaskSetStability, EcsTargetError> {
        // In-memory tasks are instantly stable.
        Ok(TaskSetStability {
            stabilized: true,
            running: 1,
            desired: 1,
        })
    }

    async fn delete_task_set(&self, task_set: &TaskSetRef) -> Result<(), EcsTargetError> {
        // Idempotent: removing an absent set is Ok.
        self.task_sets
            .lock()
            .expect("mutex not poisoned")
            .remove(&(task_set.deployment_id, task_set.revision_id));
        Ok(())
    }

    async fn apply_listener_weights(
        &self,
        listener: &ListenerRef,
        weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError> {
        self.weights
            .lock()
            .expect("mutex not poisoned")
            .insert(listener.deployment_id, weights.to_vec());
        Ok(())
    }
}
