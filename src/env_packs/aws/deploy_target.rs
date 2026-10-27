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
    /// A deployer *policy* refusal from the single-owner pool guard: the env's
    /// one target-group pool is already owned by another deployment. Distinct
    /// from [`Api`](Self::Api) so the operator message isn't mislabeled as an AWS
    /// API failure — this is a configuration boundary, not a broken call.
    #[error(
        "target-group pool already owned by deployment service `{owner}` (bound to `{shared_tg}`); \
         one pool serves a single deployment's blue/green pair. Per-deployment pools are not \
         supported yet — roll this revision out under the existing deployment, or give this \
         deployment its own environment binding with a distinct `target_group_arns` pool"
    )]
    PoolConflict { owner: String, shared_tg: String },
    /// A deployer *policy* refusal from the per-deployment listener-rule write:
    /// a non-default rule already carries this deployment's routing condition but
    /// is NOT owned by this deployment (no matching owner tag) — a sibling
    /// deployment's rule or an operator-managed auth/redirect rule sharing the
    /// host/path. The deployer refuses to rewrite a rule it did not create rather
    /// than silently strip its actions. Distinct from [`Api`](Self::Api): a
    /// configuration boundary, not a broken call.
    #[error(
        "listener rule `{rule_arn}` already serves {condition} but is owned by another deployment \
         or is operator-managed; refusing to rewrite a rule this deployment did not create. Give \
         this deployment a distinct `alb_routing_host` / `alb_routing_path`, or remove the \
         conflicting rule"
    )]
    ListenerRuleConflict { rule_arn: String, condition: String },
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
    /// Tasks the service keeps running (the wizard's `min_instances`, never
    /// 0). Task sets scale to 100% of this count.
    pub desired_count: u32,
}

/// Prefix shared by every deployment's ECS service name. Filters `ListServices`
/// output to greentic-managed deployment services in the single-owner pool
/// guard (`sibling_pool_bindings`), so unrelated services in the cluster are
/// ignored.
#[cfg(feature = "deploy-aws-ecs")]
pub(crate) const SERVICE_NAME_PREFIX: &str = "gtc-svc-";

/// Deterministic ECS service name for a deployment (one EXTERNAL-controller
/// service per `deployment_id`). `pub(crate)` so the CLI deploy path can report
/// the live service name in the `op env apply-revision` outcome without
/// re-deriving the format.
#[cfg(feature = "deploy-aws-ecs")]
pub(crate) fn service_name(deployment_id: &DeploymentId) -> String {
    format!("{SERVICE_NAME_PREFIX}{}", deployment_id.0)
}

/// CloudWatch log group the deployment's containers write to:
/// `/greentic/<secret_prefix>/<deployment_id>`.
pub fn log_group_name(secret_prefix: &str, deployment_id: &DeploymentId) -> String {
    format!("/greentic/{secret_prefix}/{}", deployment_id.0)
}

/// Retention values CloudWatch Logs accepts for `PutRetentionPolicy`
/// (`retentionInDays`); anything else is an `InvalidParameterException`.
pub const LOG_RETENTION_DAYS: &[i32] = &[
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922,
    3288, 3653,
];

/// True when `days` is a retention CloudWatch Logs accepts.
pub fn valid_log_retention_days(days: i32) -> bool {
    LOG_RETENTION_DAYS.contains(&days)
}

/// Refusal for a retention CloudWatch Logs would reject.
pub(crate) fn invalid_retention(days: i32) -> EcsTargetError {
    EcsTargetError::Api(format!(
        "log retention of {days} day(s) is not one CloudWatch Logs accepts \
         (allowed: {LOG_RETENTION_DAYS:?})"
    ))
}

/// Tag key stamped on a revision's task definition carrying its revision
/// intent (see `revision_intent`). Read back on a re-warm to tell a retry of
/// the same warm from a changed configuration under an immutable revision.
pub const REVISION_INTENT_TAG_KEY: &str = "greentic:revision-intent";

/// What the provider holds for a revision's task set.
///
/// Three states, not `Option<String>`: a task set with no intent stamp is not
/// the same fact as no task set, and folding it into either would make an
/// unverifiable task set read as "create it" or as "converged".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveTaskSet {
    /// No task set for this revision.
    Absent,
    /// A task set exists; `intent` is its task definition's stamp (`None` when
    /// unstamped).
    Present { intent: Option<String> },
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
    /// Plain environment of the worker container (see `boot_env`).
    pub env: Vec<(String, String)>,
    /// Secrets Manager values injected into the worker as env vars.
    pub secret_env: Vec<SecretEnvRef>,
    /// Seed delivered by the `seed-init` container; `None` ships no seed.
    pub seed: Option<SeedInit>,
    /// CloudWatch log group for the awslogs driver; `None` configures no logs.
    pub log_group: Option<String>,
    /// Fingerprint of everything that defines the revision's configuration.
    pub revision_intent: String,
}

/// A task-definition `secrets` entry: env var `name` resolved at task start
/// from a Secrets Manager reference (ECS `valueFrom` form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEnvRef {
    pub name: String,
    pub value_from_arn: String,
}

/// The seed delivery plan (see `docs/aws-ecs-seed-and-bundle-delivery.md`):
/// a non-essential init container writes each file onto a shared bind-mount
/// volume before the worker starts. Secret values never appear in the task
/// definition, only version-pinned ARNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedInit {
    /// Digest-pinned init image (busybox).
    pub image: String,
    pub files: Vec<SeedFile>,
}

/// One file the init container writes under `/seed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedFile {
    /// Path relative to `/seed`, e.g. `environment.json`.
    pub name: String,
    /// Secrets Manager reference including the version pin
    /// (`<arn>:::<version-id>`).
    pub secret_value_from: String,
    /// Expected SHA-256 of the file content, lowercase hex.
    pub sha256_hex: String,
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

/// Identity of a deployment's ECS service for deletion. ECS is regional and
/// cluster-scoped, so both travel with the ref (a fresh process cannot
/// reconstruct them from the deployment id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRef {
    pub deployment_id: DeploymentId,
    pub cluster: String,
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

/// Per-deployment ALB routing condition: the host-header and/or path-pattern
/// that scopes this deployment's weighted forward to its *own* listener rule,
/// so several deployments coexist behind one `alb_listener_arn` instead of
/// fighting over the listener's default action. At least one of `host` / `path`
/// is set — an all-blank wizard answer parses to `None` routing, which keeps
/// the legacy default-action write (one deployment per listener). Built from
/// the wizard's `alb_routing_host` / `alb_routing_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerRouting {
    pub host: Option<String>,
    pub path: Option<String>,
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
    /// Per-deployment routing condition. `Some` scopes the weighted forward to
    /// this deployment's own listener rule (host/path), preserving the default
    /// action + sibling rules; `None` writes the listener's default action
    /// (legacy single-deployment-per-listener behaviour).
    pub routing: Option<ListenerRouting>,
}

/// Compose a public endpoint URL from the listener's protocol, the host to
/// reach it on (the routing host or the load balancer DNS name) and an
/// optional path. The path is joined with exactly one `/`; an empty or `/`
/// path adds nothing.
pub fn compose_endpoint(protocol_is_https: bool, dns_or_host: &str, path: Option<&str>) -> String {
    let scheme = if protocol_is_https { "https" } else { "http" };
    let host = dns_or_host.trim().trim_end_matches('/');
    let path = path.map(|p| p.trim().trim_matches('/')).unwrap_or("");
    if path.is_empty() {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}/{path}")
    }
}

/// Reduce an operator-supplied `alb_routing_host` to something safe to put in
/// a URL authority: `host` or `host:port`. Strips a leading `http(s)://`, cuts
/// at the first `/`, `?` or `#`, keeps a `:port` only when it is 1..=65535.
/// `None` for an empty host, a wildcard (`*.example.com` is a valid ALB rule
/// value but not an address) or any character outside `[A-Za-z0-9.-]`; the
/// caller then falls back to the load balancer's DNS name.
pub fn endpoint_host(raw: &str) -> Option<String> {
    let mut rest = raw.trim();
    for scheme in ["https://", "http://"] {
        if rest
            .get(..scheme.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
        {
            rest = rest.get(scheme.len()..).unwrap_or("");
            break;
        }
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end).unwrap_or("").trim();
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    let port = port
        .and_then(|p| p.parse::<u16>().ok().filter(|n| *n != 0))
        .filter(|_| port.is_some_and(|p| p.chars().all(|c| c.is_ascii_digit())));
    Some(match port {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
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

/// Tag key carrying the owning environment's stamp on a Secrets Manager secret
/// (the AWS twin of the GCP `greentic-owner` label).
pub const SECRET_OWNER_TAG_KEY: &str = "greentic:owner";

/// Outcome of [`EcsDeployTarget::ensure_secret`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsuredSecret {
    /// This call created the secret, stamped with the caller's owner.
    Created,
    /// The secret already existed, stamped by `owner` (empty = no stamp). The
    /// caller decides whether that owner is itself or a conflict.
    Existed { owner: String },
}

/// One stored secret version: the secret ARN plus the version id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVersionRef {
    pub arn: String,
    pub version_id: String,
}

impl SecretVersionRef {
    /// The ECS task-definition `valueFrom` string pinning this exact version.
    ///
    /// ECS `valueFrom` is `<secret-arn>:<json-key>:<version-stage>:<version-id>`;
    /// leaving the json-key and version-stage empty and giving the version id is
    /// `<arn>:::<version-id>` (see `docs/aws-ecs-seed-and-bundle-delivery.md`,
    /// "Pin a secret version"). Needs Fargate platform 1.4.0+.
    pub fn value_from(&self) -> String {
        format!("{}:::{}", self.arn, self.version_id)
    }
}

/// Content-derived `ClientRequestToken` / version id for a secret value:
/// lowercase hex SHA-256 (64 chars, inside Secrets Manager's 32-64 limit).
/// Identical bytes therefore map to the same version, which keeps a re-staged
/// unchanged seed from minting a new version (unlabeled versions beyond 100 are
/// garbage-collected after 24h, which would orphan version-pinned task defs).
pub fn secret_version_token(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
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

    /// Read whether the revision's task set exists and, if so, the revision
    /// intent stamped on its task definition ([`REVISION_INTENT_TAG_KEY`]).
    async fn live_revision_intent(
        &self,
        task_set: &TaskSetRef,
    ) -> Result<LiveTaskSet, EcsTargetError>;

    /// Poll a task set's rollout status (steady state + target-group health).
    async fn task_set_stability(
        &self,
        task_set: &TaskSetRef,
    ) -> Result<TaskSetStability, EcsTargetError>;

    /// Delete a task set and deregister its task definition. Idempotent
    /// against an already-absent set.
    async fn delete_task_set(&self, task_set: &TaskSetRef) -> Result<(), EcsTargetError>;

    /// Delete the deployment's whole service: every remaining task set first
    /// (an `EXTERNAL`-controller service cannot be deleted while it has any),
    /// then the service itself. Idempotent: an absent (or already `INACTIVE`)
    /// service is `Ok`. Leaves the cluster and the operator's target groups
    /// alone.
    async fn delete_service(&self, service: &ServiceRef) -> Result<(), EcsTargetError>;

    /// Remove the deployment's own host/path listener rule, if this deployment
    /// created one. Idempotent: an absent rule is `Ok`. Never touches the
    /// listener itself (its default action included), another deployment's rule,
    /// an operator-managed rule that merely shares the condition, or the load
    /// balancer and target groups. A listener without per-deployment routing
    /// owns no rule, so the call is a no-op.
    async fn delete_listener_rule(&self, listener: &ListenerRef) -> Result<(), EcsTargetError>;

    /// Set the listener's weighted forward action across the deployment's
    /// task-set target groups (the ALB mirror of the env's `TrafficSplit`).
    async fn apply_listener_weights(
        &self,
        listener: &ListenerRef,
        weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError>;

    /// Discover the public endpoint the listener serves: `https://<host>` for an
    /// HTTPS listener, `http://<host>` otherwise, where `<host>` is the
    /// listener's `routing.host` when set, else the load balancer's DNS name.
    /// `Ok(None)` means the listener names no load balancer that has a DNS
    /// name; a failed lookup is an error, never a silent `None`.
    async fn discover_endpoint(
        &self,
        listener: &ListenerRef,
    ) -> Result<Option<String>, EcsTargetError>;

    /// Create the secret `name` tagged `greentic:owner=<owner>` if absent. A
    /// create race or an existing secret surfaces as
    /// [`EnsuredSecret::Existed`] carrying the live owner stamp, never as a
    /// silent adoption.
    async fn ensure_secret(&self, name: &str, owner: &str)
    -> Result<EnsuredSecret, EcsTargetError>;

    /// Read the owner stamp of the secret `name` WITHOUT creating it. `None` =
    /// no such secret; `Some("")` = it exists with no owner tag (a foreign
    /// secret on this lane, see [`secret_owner_conflict`](super::seed_stage)).
    /// The teardown's probe; the warm path uses [`Self::ensure_secret`].
    async fn get_secret_owner(&self, name: &str) -> Result<Option<String>, EcsTargetError>;

    /// Store `bytes` as a value of the existing secret `name`. Content
    /// idempotent: identical bytes yield the same version (the request token is
    /// [`secret_version_token`]), different bytes a new one.
    async fn put_secret_value(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<SecretVersionRef, EcsTargetError>;

    /// Delete the secret immediately, without a recovery window. Idempotent
    /// against an absent secret.
    async fn delete_secret(&self, name: &str) -> Result<(), EcsTargetError>;

    /// Create the CloudWatch log group `name` if absent and set its retention
    /// to `retention_days`. Idempotent. A retention outside
    /// [`LOG_RETENTION_DAYS`] is refused before any call.
    async fn ensure_log_group(&self, name: &str, retention_days: i32)
    -> Result<(), EcsTargetError>;

    /// Delete the log group. Idempotent against an absent group.
    async fn delete_log_group(&self, name: &str) -> Result<(), EcsTargetError>;
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
    async fn live_revision_intent(
        &self,
        _task_set: &TaskSetRef,
    ) -> Result<LiveTaskSet, EcsTargetError> {
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
    async fn delete_service(&self, _service: &ServiceRef) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn delete_listener_rule(&self, _listener: &ListenerRef) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn apply_listener_weights(
        &self,
        _listener: &ListenerRef,
        _weights: &[TargetGroupWeight],
    ) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn discover_endpoint(
        &self,
        _listener: &ListenerRef,
    ) -> Result<Option<String>, EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn ensure_secret(
        &self,
        _name: &str,
        _owner: &str,
    ) -> Result<EnsuredSecret, EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn get_secret_owner(&self, _name: &str) -> Result<Option<String>, EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn put_secret_value(
        &self,
        _name: &str,
        _bytes: &[u8],
    ) -> Result<SecretVersionRef, EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn delete_secret(&self, _name: &str) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn ensure_log_group(
        &self,
        _name: &str,
        _retention_days: i32,
    ) -> Result<(), EcsTargetError> {
        Err(EcsTargetError::Unconfigured)
    }
    async fn delete_log_group(&self, _name: &str) -> Result<(), EcsTargetError> {
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
    services: std::sync::Mutex<std::collections::BTreeMap<DeploymentId, u32>>,
    /// Log groups by name -> retention days.
    log_groups: std::sync::Mutex<std::collections::BTreeMap<String, i32>>,
    /// Task sets keyed by `(deployment, revision)`.
    task_sets:
        std::sync::Mutex<std::collections::BTreeMap<(DeploymentId, RevisionId), TaskSetHandle>>,
    /// Last-applied listener weights per deployment.
    weights: std::sync::Mutex<std::collections::BTreeMap<DeploymentId, Vec<TargetGroupWeight>>>,
    /// Last-applied listener routing per deployment — the `ListenerRef::routing`
    /// the verb carried (`None` inner = a default-action write, `Some` = a
    /// per-deployment rule). Records the deployer's contract decision, which the
    /// real target turns into a `ModifyListener` vs `CreateRule`/`ModifyRule`.
    routing: std::sync::Mutex<std::collections::BTreeMap<DeploymentId, Option<ListenerRouting>>>,
    /// Secrets by name -> owner stamp.
    secrets: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
    /// Version ids per secret, in creation order.
    secret_versions: std::sync::Mutex<std::collections::BTreeMap<String, Vec<String>>>,
    /// The spec each live task set was created from (its intent included).
    task_set_specs:
        std::sync::Mutex<std::collections::BTreeMap<(DeploymentId, RevisionId), TaskSetSpec>>,
    /// `create_task_set` calls received, including idempotent re-creates.
    create_task_set_calls: std::sync::atomic::AtomicUsize,
    /// Every listener `discover_endpoint` was asked about, in call order.
    endpoint_queries: std::sync::Mutex<Vec<ListenerRef>>,
    /// When set, `discover_endpoint` fails with this message.
    endpoint_failure: std::sync::Mutex<Option<String>>,
    /// Deployments whose per-deployment listener rule `delete_listener_rule`
    /// removed, in call order (only calls that carried routing are recorded).
    rule_deletions: std::sync::Mutex<Vec<DeploymentId>>,
    /// Set when the fake listener is plain HTTP (default: HTTPS).
    listener_is_http: std::sync::atomic::AtomicBool,
}

impl InMemoryEcs {
    /// Seed a secret with an arbitrary owner stamp (`""` = unstamped), as if
    /// another environment or an operator had created it.
    pub fn seed_secret(&self, name: &str, owner: &str) {
        self.secrets
            .lock()
            .expect("mutex not poisoned")
            .insert(name.to_string(), owner.to_string());
    }

    /// Seed a service as if it had been ensured earlier.
    pub fn seed_service(&self, deployment_id: DeploymentId, desired_count: u32) {
        self.services
            .lock()
            .expect("mutex not poisoned")
            .insert(deployment_id, desired_count);
    }

    /// Deployments whose listener rule was deleted, in call order.
    pub fn rule_deletions(&self) -> Vec<DeploymentId> {
        self.rule_deletions
            .lock()
            .expect("mutex not poisoned")
            .clone()
    }

    /// Snapshot of the ensured secrets (name -> owner stamp).
    pub fn secrets(&self) -> std::collections::BTreeMap<String, String> {
        self.secrets.lock().expect("mutex not poisoned").clone()
    }

    /// Version ids stored for a secret, in creation order.
    pub fn secret_versions_of(&self, name: &str) -> Vec<String> {
        self.secret_versions
            .lock()
            .expect("mutex not poisoned")
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    /// Snapshot of the ensured services.
    pub fn services(&self) -> std::collections::BTreeSet<DeploymentId> {
        self.services
            .lock()
            .expect("mutex not poisoned")
            .keys()
            .copied()
            .collect()
    }

    /// Desired count the deployment's service was first ensured with.
    pub fn desired_count_of(&self, deployment_id: DeploymentId) -> Option<u32> {
        self.services
            .lock()
            .expect("mutex not poisoned")
            .get(&deployment_id)
            .copied()
    }

    /// Snapshot of the ensured log groups (name -> retention days).
    pub fn log_groups(&self) -> std::collections::BTreeMap<String, i32> {
        self.log_groups.lock().expect("mutex not poisoned").clone()
    }

    /// The spec the revision's live task set was created from.
    pub fn task_set_spec_of(
        &self,
        deployment_id: DeploymentId,
        revision_id: RevisionId,
    ) -> Option<TaskSetSpec> {
        self.task_set_specs
            .lock()
            .expect("mutex not poisoned")
            .get(&(deployment_id, revision_id))
            .cloned()
    }

    /// How many times `create_task_set` was called.
    pub fn create_task_set_calls(&self) -> usize {
        self.create_task_set_calls
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Snapshot of the live task sets.
    pub fn task_sets(
        &self,
    ) -> std::collections::BTreeMap<(DeploymentId, RevisionId), TaskSetHandle> {
        self.task_sets.lock().expect("mutex not poisoned").clone()
    }

    /// Make every later `discover_endpoint` fail with `message`.
    pub fn fail_endpoint_discovery(&self, message: &str) {
        *self.endpoint_failure.lock().expect("mutex not poisoned") = Some(message.to_string());
    }

    /// Choose the fake listener's protocol (default HTTPS).
    pub fn set_listener_https(&self, https: bool) {
        self.listener_is_http
            .store(!https, std::sync::atomic::Ordering::SeqCst);
    }

    /// Listeners `discover_endpoint` was asked about, in call order.
    pub fn endpoint_queries(&self) -> Vec<ListenerRef> {
        self.endpoint_queries
            .lock()
            .expect("mutex not poisoned")
            .clone()
    }

    /// Snapshot of the last-applied weights for a deployment.
    pub fn weights_for(&self, deployment_id: DeploymentId) -> Option<Vec<TargetGroupWeight>> {
        self.weights
            .lock()
            .expect("mutex not poisoned")
            .get(&deployment_id)
            .cloned()
    }

    /// Snapshot of the routing the last `apply_listener_weights` carried for a
    /// deployment. Outer `None` = no listener write recorded; inner `None` = a
    /// default-action write; inner `Some` = a per-deployment rule.
    pub fn routing_for(&self, deployment_id: DeploymentId) -> Option<Option<ListenerRouting>> {
        self.routing
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
            .entry(spec.deployment_id)
            .or_insert(spec.desired_count);
        Ok(())
    }

    async fn create_task_set(&self, spec: &TaskSetSpec) -> Result<TaskSetHandle, EcsTargetError> {
        self.create_task_set_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
        self.task_set_specs
            .lock()
            .expect("mutex not poisoned")
            .insert(key, spec.clone());
        Ok(handle)
    }

    async fn live_revision_intent(
        &self,
        task_set: &TaskSetRef,
    ) -> Result<LiveTaskSet, EcsTargetError> {
        let key = (task_set.deployment_id, task_set.revision_id);
        if !self
            .task_sets
            .lock()
            .expect("mutex not poisoned")
            .contains_key(&key)
        {
            return Ok(LiveTaskSet::Absent);
        }
        let intent = self
            .task_set_specs
            .lock()
            .expect("mutex not poisoned")
            .get(&key)
            .map(|spec| spec.revision_intent.clone())
            .filter(|intent| !intent.is_empty());
        Ok(LiveTaskSet::Present { intent })
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
        let key = (task_set.deployment_id, task_set.revision_id);
        self.task_sets
            .lock()
            .expect("mutex not poisoned")
            .remove(&key);
        self.task_set_specs
            .lock()
            .expect("mutex not poisoned")
            .remove(&key);
        Ok(())
    }

    async fn delete_service(&self, service: &ServiceRef) -> Result<(), EcsTargetError> {
        // Idempotent: like the real target, every task set goes first, then the
        // service; absent is Ok.
        let dep = service.deployment_id;
        {
            let mut sets = self.task_sets.lock().expect("mutex not poisoned");
            sets.retain(|(d, _), _| *d != dep);
        }
        self.task_set_specs
            .lock()
            .expect("mutex not poisoned")
            .retain(|(d, _), _| *d != dep);
        self.services
            .lock()
            .expect("mutex not poisoned")
            .remove(&dep);
        Ok(())
    }

    async fn delete_listener_rule(&self, listener: &ListenerRef) -> Result<(), EcsTargetError> {
        // Without routing the deployment owns no rule (it wrote the listener's
        // default action, which is not ours to remove).
        if listener.routing.is_none() {
            return Ok(());
        }
        let dep = listener.deployment_id;
        let had_rule = self
            .routing
            .lock()
            .expect("mutex not poisoned")
            .remove(&dep)
            .is_some();
        self.weights
            .lock()
            .expect("mutex not poisoned")
            .remove(&dep);
        if had_rule {
            self.rule_deletions
                .lock()
                .expect("mutex not poisoned")
                .push(dep);
        }
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
        self.routing
            .lock()
            .expect("mutex not poisoned")
            .insert(listener.deployment_id, listener.routing.clone());
        Ok(())
    }

    async fn discover_endpoint(
        &self,
        listener: &ListenerRef,
    ) -> Result<Option<String>, EcsTargetError> {
        self.endpoint_queries
            .lock()
            .expect("mutex not poisoned")
            .push(listener.clone());
        if let Some(message) = self
            .endpoint_failure
            .lock()
            .expect("mutex not poisoned")
            .clone()
        {
            return Err(EcsTargetError::Api(message));
        }
        let https = !self
            .listener_is_http
            .load(std::sync::atomic::Ordering::SeqCst);
        let host = listener
            .routing
            .as_ref()
            .and_then(|r| r.host.as_deref())
            .and_then(endpoint_host)
            .unwrap_or_else(|| format!("{}.alb.invalid", listener.deployment_id.0));
        Ok(Some(compose_endpoint(https, &host, None)))
    }

    async fn ensure_secret(
        &self,
        name: &str,
        owner: &str,
    ) -> Result<EnsuredSecret, EcsTargetError> {
        let mut secrets = self.secrets.lock().expect("mutex not poisoned");
        if let Some(live) = secrets.get(name) {
            return Ok(EnsuredSecret::Existed {
                owner: live.clone(),
            });
        }
        secrets.insert(name.to_string(), owner.to_string());
        Ok(EnsuredSecret::Created)
    }

    async fn get_secret_owner(&self, name: &str) -> Result<Option<String>, EcsTargetError> {
        Ok(self
            .secrets
            .lock()
            .expect("mutex not poisoned")
            .get(name)
            .cloned())
    }

    async fn put_secret_value(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<SecretVersionRef, EcsTargetError> {
        if !self
            .secrets
            .lock()
            .expect("mutex not poisoned")
            .contains_key(name)
        {
            return Err(EcsTargetError::Api(format!(
                "secretsmanager PutSecretValue: secret `{name}` not found"
            )));
        }
        // Mimic the real target: the version id is the content token, so
        // identical bytes are one version.
        let version_id = secret_version_token(bytes);
        let mut versions = self.secret_versions.lock().expect("mutex not poisoned");
        let list = versions.entry(name.to_string()).or_default();
        if !list.contains(&version_id) {
            list.push(version_id.clone());
        }
        Ok(SecretVersionRef {
            arn: format!("arn:aws:secretsmanager:in-memory:000000000000:secret:{name}-AAAAAA"),
            version_id,
        })
    }

    async fn delete_secret(&self, name: &str) -> Result<(), EcsTargetError> {
        self.secrets
            .lock()
            .expect("mutex not poisoned")
            .remove(name);
        self.secret_versions
            .lock()
            .expect("mutex not poisoned")
            .remove(name);
        Ok(())
    }

    async fn ensure_log_group(
        &self,
        name: &str,
        retention_days: i32,
    ) -> Result<(), EcsTargetError> {
        if !valid_log_retention_days(retention_days) {
            return Err(invalid_retention(retention_days));
        }
        self.log_groups
            .lock()
            .expect("mutex not poisoned")
            .insert(name.to_string(), retention_days);
        Ok(())
    }

    async fn delete_log_group(&self, name: &str) -> Result<(), EcsTargetError> {
        self.log_groups
            .lock()
            .expect("mutex not poisoned")
            .remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod log_tests {
    use super::*;
    use ulid::Ulid;

    #[tokio::test]
    async fn ensure_log_group_is_idempotent() {
        let ecs = InMemoryEcs::default();
        ecs.ensure_log_group("/g/a", 14).await.unwrap();
        ecs.ensure_log_group("/g/a", 30).await.unwrap();
        let groups = ecs.log_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups.get("/g/a"), Some(&30));
    }

    #[tokio::test]
    async fn ensure_log_group_refuses_a_retention_aws_does_not_accept() {
        let ecs = InMemoryEcs::default();
        let err = ecs.ensure_log_group("/g/a", 2).await.unwrap_err();
        assert!(err.to_string().contains("2 day(s)"), "{err}");
        assert!(ecs.log_groups().is_empty());
        assert!(valid_log_retention_days(3653) && !valid_log_retention_days(0));
    }

    #[tokio::test]
    async fn live_revision_intent_reads_absent_then_the_stamp() {
        let ecs = InMemoryEcs::default();
        let d = DeploymentId(Ulid::from(0x01_u128));
        let r = RevisionId(Ulid::from(0x02_u128));
        let at = TaskSetRef {
            deployment_id: d,
            revision_id: r,
            cluster: "c".into(),
            region: "us-east-1".into(),
        };
        assert_eq!(
            ecs.live_revision_intent(&at).await.unwrap(),
            LiveTaskSet::Absent
        );
        let spec = |intent: &str| TaskSetSpec {
            deployment_id: d,
            revision_id: r,
            cluster: "c".into(),
            region: "us-east-1".into(),
            image: "img".into(),
            env: Vec::new(),
            secret_env: Vec::new(),
            seed: None,
            log_group: None,
            revision_intent: intent.into(),
        };
        ecs.create_task_set(&spec("abc")).await.unwrap();
        assert_eq!(
            ecs.live_revision_intent(&at).await.unwrap(),
            LiveTaskSet::Present {
                intent: Some("abc".into())
            }
        );
        ecs.delete_task_set(&at).await.unwrap();
        ecs.create_task_set(&spec("")).await.unwrap();
        assert_eq!(
            ecs.live_revision_intent(&at).await.unwrap(),
            LiveTaskSet::Present { intent: None }
        );
    }

    #[tokio::test]
    async fn delete_log_group_is_idempotent() {
        let ecs = InMemoryEcs::default();
        ecs.ensure_log_group("/g/a", 14).await.unwrap();
        ecs.delete_log_group("/g/a").await.unwrap();
        ecs.delete_log_group("/g/a").await.unwrap();
        assert!(ecs.log_groups().is_empty());
    }

    #[tokio::test]
    async fn unconfigured_target_refuses_log_calls() {
        let t = UnconfiguredEcsTarget;
        assert!(matches!(
            t.ensure_log_group("g", 7).await,
            Err(EcsTargetError::Unconfigured)
        ));
        assert!(matches!(
            t.delete_log_group("g").await,
            Err(EcsTargetError::Unconfigured)
        ));
    }

    #[test]
    fn log_group_name_is_prefix_and_deployment() {
        let d = DeploymentId(Ulid::from(0x01_u128));
        assert_eq!(
            log_group_name("gtc-dev", &d),
            format!("/greentic/gtc-dev/{}", d.0)
        );
    }
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[tokio::test]
    async fn ensure_secret_reports_existing_owner() {
        let ecs = InMemoryEcs::default();
        assert_eq!(
            ecs.ensure_secret("s1", "owner-a").await.unwrap(),
            EnsuredSecret::Created
        );
        assert_eq!(
            ecs.ensure_secret("s1", "owner-b").await.unwrap(),
            EnsuredSecret::Existed {
                owner: "owner-a".to_string()
            }
        );
        assert_eq!(ecs.secrets().get("s1").map(String::as_str), Some("owner-a"));
    }

    #[tokio::test]
    async fn delete_secret_is_idempotent() {
        let ecs = InMemoryEcs::default();
        ecs.ensure_secret("s1", "o").await.unwrap();
        ecs.put_secret_value("s1", b"x").await.unwrap();
        ecs.delete_secret("s1").await.unwrap();
        ecs.delete_secret("s1").await.unwrap();
        assert!(ecs.secrets().is_empty());
        assert!(ecs.secret_versions_of("s1").is_empty());
    }

    #[tokio::test]
    async fn put_secret_value_returns_a_new_version_each_time_for_different_bytes() {
        let ecs = InMemoryEcs::default();
        ecs.ensure_secret("s1", "o").await.unwrap();
        let a = ecs.put_secret_value("s1", b"one").await.unwrap();
        let b = ecs.put_secret_value("s1", b"two").await.unwrap();
        assert_ne!(a.version_id, b.version_id);
        assert_eq!(a.arn, b.arn);
        assert_eq!(ecs.secret_versions_of("s1").len(), 2);
    }

    #[tokio::test]
    async fn put_secret_value_is_idempotent_for_identical_bytes() {
        let ecs = InMemoryEcs::default();
        ecs.ensure_secret("s1", "o").await.unwrap();
        let a = ecs.put_secret_value("s1", b"same").await.unwrap();
        let b = ecs.put_secret_value("s1", b"same").await.unwrap();
        assert_eq!(a, b);
        assert_eq!(ecs.secret_versions_of("s1").len(), 1);
    }

    #[tokio::test]
    async fn put_secret_value_on_a_missing_secret_fails() {
        let ecs = InMemoryEcs::default();
        assert!(ecs.put_secret_value("nope", b"x").await.is_err());
    }

    #[tokio::test]
    async fn unconfigured_target_refuses_secret_calls() {
        let t = UnconfiguredEcsTarget;
        assert!(matches!(
            t.ensure_secret("s", "o").await,
            Err(EcsTargetError::Unconfigured)
        ));
        assert!(matches!(
            t.put_secret_value("s", b"x").await,
            Err(EcsTargetError::Unconfigured)
        ));
        assert!(matches!(
            t.delete_secret("s").await,
            Err(EcsTargetError::Unconfigured)
        ));
    }

    #[test]
    fn value_from_pins_the_version_with_three_colons() {
        let r = SecretVersionRef {
            arn: "arn:aws:secretsmanager:eu-west-1:1:secret:n-AbCdEf".to_string(),
            version_id: "abc".to_string(),
        };
        assert_eq!(
            r.value_from(),
            "arn:aws:secretsmanager:eu-west-1:1:secret:n-AbCdEf:::abc"
        );
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use ulid::Ulid;

    fn listener(routing: Option<ListenerRouting>) -> ListenerRef {
        ListenerRef {
            deployment_id: DeploymentId(Ulid::from(0x07_u128)),
            listener_arn: "arn:aws:elasticloadbalancing:us-east-1:1:listener/app/x/y/z".into(),
            cluster: "c".into(),
            routing,
        }
    }

    #[test]
    fn compose_endpoint_picks_the_scheme_from_the_protocol() {
        assert_eq!(
            compose_endpoint(true, "a.example", None),
            "https://a.example"
        );
        assert_eq!(
            compose_endpoint(false, "a.example", None),
            "http://a.example"
        );
    }

    #[test]
    fn compose_endpoint_trims_stray_slashes_and_whitespace() {
        assert_eq!(
            compose_endpoint(true, " a.example/ ", None),
            "https://a.example"
        );
    }

    #[test]
    fn compose_endpoint_joins_a_path_with_one_slash() {
        assert_eq!(
            compose_endpoint(true, "a.example", Some("/app/")),
            "https://a.example/app"
        );
        assert_eq!(
            compose_endpoint(true, "a.example", Some("app")),
            "https://a.example/app"
        );
    }

    #[test]
    fn compose_endpoint_ignores_an_empty_or_root_path() {
        assert_eq!(
            compose_endpoint(true, "a.example", Some("")),
            "https://a.example"
        );
        assert_eq!(
            compose_endpoint(true, "a.example", Some("/")),
            "https://a.example"
        );
    }

    #[test]
    fn endpoint_host_keeps_a_plain_host() {
        assert_eq!(
            endpoint_host("app.example.com"),
            Some("app.example.com".into())
        );
    }

    #[test]
    fn endpoint_host_keeps_a_valid_port() {
        assert_eq!(
            endpoint_host("app.example.com:8443"),
            Some("app.example.com:8443".into())
        );
    }

    #[test]
    fn endpoint_host_strips_a_scheme_in_any_case() {
        assert_eq!(
            endpoint_host("https://app.example.com"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("HTTP://app.example.com"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("HtTpS://app.example.com"),
            Some("app.example.com".into())
        );
    }

    #[test]
    fn endpoint_host_cuts_a_path_query_or_fragment() {
        assert_eq!(
            endpoint_host("app.example.com/x"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("app.example.com?q=1"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("app.example.com#f"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("https://app.example.com:8443/x"),
            Some("app.example.com:8443".into())
        );
    }

    #[test]
    fn endpoint_host_rejects_a_wildcard() {
        assert_eq!(endpoint_host("*.example.com"), None);
    }

    #[test]
    fn endpoint_host_rejects_empty_and_whitespace() {
        assert_eq!(endpoint_host(""), None);
        assert_eq!(endpoint_host("   "), None);
        assert_eq!(endpoint_host("https://"), None);
    }

    #[test]
    fn endpoint_host_drops_an_invalid_port() {
        assert_eq!(
            endpoint_host("app.example.com:0"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("app.example.com:99999"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("app.example.com:abc"),
            Some("app.example.com".into())
        );
        assert_eq!(
            endpoint_host("app.example.com:"),
            Some("app.example.com".into())
        );
    }

    #[test]
    fn endpoint_host_does_not_panic_on_multibyte_boundary() {
        for raw in [
            "a\u{e9}\u{e9}\u{e9}\u{e9}",
            "b\u{fc}cher-shop.de",
            "abcdefg\u{20ac}",
            "abcdef\u{1f600}",
            "\u{1f600}\u{1f600}\u{1f600}",
            "https://b\u{fc}cher.de",
        ] {
            assert_eq!(endpoint_host(raw), None, "{raw}");
        }
    }

    #[test]
    fn endpoint_host_rejects_illegal_characters() {
        assert_eq!(endpoint_host("app_example.com"), None);
        assert_eq!(endpoint_host("user@app.example.com"), None);
    }

    #[tokio::test]
    async fn in_memory_target_can_fail_discovery_on_demand() {
        let ecs = InMemoryEcs::default();
        ecs.fail_endpoint_discovery("boom");
        let err = ecs.discover_endpoint(&listener(None)).await.unwrap_err();
        assert!(matches!(err, EcsTargetError::Api(m) if m.contains("boom")));
    }

    #[tokio::test]
    async fn in_memory_target_sanitizes_the_routing_host_and_falls_back() {
        let ecs = InMemoryEcs::default();
        let routed = |h: &str| {
            listener(Some(ListenerRouting {
                host: Some(h.into()),
                path: None,
            }))
        };
        assert_eq!(
            ecs.discover_endpoint(&routed("https://app.example.com/x"))
                .await
                .unwrap(),
            Some("https://app.example.com".into())
        );
        let l = routed("*.example.com");
        assert_eq!(
            ecs.discover_endpoint(&l).await.unwrap(),
            Some(format!("https://{}.alb.invalid", l.deployment_id.0))
        );
    }

    #[tokio::test]
    async fn in_memory_target_uses_http_for_an_http_listener() {
        let ecs = InMemoryEcs::default();
        ecs.set_listener_https(false);
        let l = listener(None);
        assert_eq!(
            ecs.discover_endpoint(&l).await.unwrap(),
            Some(format!("http://{}.alb.invalid", l.deployment_id.0))
        );
    }

    #[tokio::test]
    async fn in_memory_target_returns_a_deterministic_url_and_records_the_listener() {
        let ecs = InMemoryEcs::default();
        let l = listener(None);
        let first = ecs.discover_endpoint(&l).await.unwrap();
        let second = ecs.discover_endpoint(&l).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first,
            Some(format!("https://{}.alb.invalid", l.deployment_id.0))
        );
        assert_eq!(ecs.endpoint_queries(), vec![l.clone(), l]);
    }

    #[tokio::test]
    async fn unconfigured_target_refuses_endpoint_discovery() {
        let t = UnconfiguredEcsTarget;
        assert!(matches!(
            t.discover_endpoint(&listener(None)).await,
            Err(EcsTargetError::Unconfigured)
        ));
    }
}
