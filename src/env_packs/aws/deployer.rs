//! [`Deployer`] impl for the AWS-ECS env-pack.
//!
//! Verbs follow the contract's order: pure-spec preconditions first (shared
//! helpers — `require_revision`, `enforce_split_invariants`), provider work
//! second. The provider work drives the [`EcsDeployTarget`] seam (the AWS twin
//! of `K8sCluster`).
//!
//! **Answers:** `warm_revision` / `archive_revision` / `apply_traffic_split`
//! take the binding's wizard answers and render through
//! [`AwsEcsParams::from_answers`] (`None` → [`AwsEcsParams::for_env`] sandbox
//! defaults), so a verb scopes to the same region / cluster / listener the
//! operator bound. A malformed answers blob fails BEFORE any AWS call.
//!
//! | Verb | Provider side-effect |
//! |---|---|
//! | `stage_revision` | None. Image/bundle delivery is a separate cross-provider slice (K8s defers it too). |
//! | `warm_revision` | Ensure the deployment's `EXTERNAL`-controller service + create the revision's task set; wait until it stabilizes. |
//! | `drain_revision` | None — routing-side. Traffic shifts via `apply_traffic_split`; target-group deregistration-delay drains in-flight. |
//! | `archive_revision` | Delete the revision's task set + deregister its task definition (idempotent against absent). |
//! | `apply_traffic_split` | Write the listener rule's weighted forward action across the deployment's task-set target groups. Never re-creates task sets. |
//!
//! Idempotency falls out of the seam's contract: `ensure_service` /
//! `create_task_set` upsert, `delete_task_set` of an absent set is `Ok`. The
//! conformance bench runs against [`InMemoryEcs`](super::deploy_target::InMemoryEcs);
//! the real aws-sdk-backed target inherits these verbs unchanged once it lands.

use std::time::Duration;

use async_trait::async_trait;
use greentic_deploy_spec::{DeploymentId, Environment, Revision, RevisionId};
use serde_json::Value;
use tokio::time::{Instant, sleep};

use super::AwsEcsDeployerHandler;
use super::deploy_target::{
    EcsDeployTarget, EcsTargetError, ListenerRuleRef, ServiceSpec, TargetGroupWeight, TaskSetRef,
    TaskSetSpec,
};
use crate::env_packs::deployer::{
    ArchiveOutcome, Deployer, DeployerError, DrainOutcome, StageOutcome, TrafficSplitOutcome,
    WarmOutcome, enforce_split_invariants, require_revision,
};

/// Default container image base when the binding supplies no
/// `ecr_repository_prefix`. The in-memory path never pulls it; the real target
/// requires the operator to scope `ecr_repository_prefix` to their account.
const DEFAULT_IMAGE_BASE: &str = "greentic/operator";

/// Seam failures surface as provider failures — the verb's preconditions have
/// already passed by the time the target is touched.
fn provider(err: EcsTargetError) -> DeployerError {
    DeployerError::Provider(err.to_string())
}

/// Resolved scope for the AWS-ECS verbs, built from the binding's wizard
/// answers (`None` → sandbox defaults). Holds the non-secret identifiers the
/// verbs need; credential MATERIAL is never here (it rides the AWS chain in the
/// real target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEcsParams {
    /// AWS region the cluster lives in.
    pub region: String,
    /// ECS cluster name the deployer manages services in.
    pub cluster: String,
    /// Container image base every revision's image is built from.
    pub image_base: String,
    /// ALB listener ARN the weighted forward rules are written to. `None`
    /// derives a deterministic per-deployment placeholder (the runtime
    /// dispatcher stays authoritative when no ALB mirror is configured).
    pub listener_arn: Option<String>,
}

/// Why a wizard answers blob could not be read into [`AwsEcsParams`].
#[derive(Debug, thiserror::Error)]
pub enum AwsEcsParamsError {
    #[error("answers must be a JSON object")]
    NotAnObject,
    #[error("answer `{0}` must be a string")]
    NotAString(String),
    #[error("unknown answer key `{0}`")]
    UnknownKey(String),
}

fn answer_string(key: &str, value: &Value) -> Result<String, AwsEcsParamsError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| AwsEcsParamsError::NotAString(key.to_string()))
}

impl AwsEcsParams {
    /// Sandbox defaults derived from the env (no binding answers).
    pub fn for_env(env: &Environment) -> Self {
        Self {
            region: env
                .host_config
                .region
                .clone()
                .unwrap_or_else(|| "us-east-1".to_string()),
            cluster: format!("greentic-{}", env.environment_id.as_str()),
            image_base: DEFAULT_IMAGE_BASE.to_string(),
            listener_arn: None,
        }
    }

    /// Overlay the binding's recorded wizard answers onto [`Self::for_env`].
    ///
    /// Keys mirror `wizard.qaspec.yaml`. Unknown keys are rejected (deny-by-
    /// default, so an operator typo fails loudly rather than being silently
    /// dropped). Credential-scoping knobs (`aws_profile`, `assume_role_arn`)
    /// and image-tag knobs are validated as strings and accepted so a full
    /// binding's answers deserialize; they are consumed by the SDK client
    /// builder / image tagging in later slices, not by these verbs.
    pub fn from_answers(
        env: &Environment,
        answers: Option<&Value>,
    ) -> Result<Self, AwsEcsParamsError> {
        let mut params = Self::for_env(env);
        let Some(answers) = answers else {
            return Ok(params);
        };
        let obj = answers.as_object().ok_or(AwsEcsParamsError::NotAnObject)?;
        for (key, value) in obj {
            match key.as_str() {
                "region" => params.region = answer_string(key, value)?,
                "ecs_cluster_name" => params.cluster = answer_string(key, value)?,
                "ecr_repository_prefix" => params.image_base = answer_string(key, value)?,
                "alb_listener_arn" => params.listener_arn = Some(answer_string(key, value)?),
                "container_image_tag_prefix" | "aws_profile" | "assume_role_arn" => {
                    answer_string(key, value)?;
                }
                other => return Err(AwsEcsParamsError::UnknownKey(other.to_string())),
            }
        }
        Ok(params)
    }

    /// Image the revision's Fargate task runs.
    fn image_for(&self, revision_id: RevisionId) -> String {
        format!("{}:rev-{}", self.image_base, revision_id.0)
    }

    /// Deterministic target-group name for a revision's task set.
    fn target_group(&self, deployment_id: DeploymentId, revision_id: RevisionId) -> String {
        format!("gtc-tg-{}-{}", deployment_id.0, revision_id.0)
    }

    /// Listener rule the deployment's weighted forward action is written to —
    /// the operator-supplied ARN, or a deterministic per-deployment placeholder.
    fn listener_rule_arn(&self, deployment_id: DeploymentId) -> String {
        self.listener_arn
            .clone()
            .unwrap_or_else(|| format!("gtc-rule-{}", deployment_id.0))
    }
}

/// Build params from the binding's answers, mapping a malformed blob to a
/// provider error BEFORE any AWS call (no typed answers-rejection variant;
/// mirrors the K8s deployer).
fn params_from_answers(
    env: &Environment,
    answers: Option<&Value>,
) -> Result<AwsEcsParams, DeployerError> {
    AwsEcsParams::from_answers(env, answers)
        .map_err(|e| DeployerError::Provider(format!("invalid answers: {e}")))
}

/// Default upper bound on the warm stabilization wait. A task set that has not
/// reached steady state within this window fails the warm rather than letting a
/// revision promote `Warming → Ready` over tasks that never became healthy.
const WARM_STABILIZE_TIMEOUT: Duration = Duration::from_secs(300);

/// Env override for [`WARM_STABILIZE_TIMEOUT`] (whole seconds). The live E2E
/// sets a short value so the gate's failure path is observable without a
/// multi-minute hang. An unset / unparseable value falls back to the default.
const WARM_STABILIZE_TIMEOUT_ENV: &str = "GREENTIC_AWS_ECS_WARM_READY_TIMEOUT_SECS";

/// Poll cadence while waiting for the task set to stabilize.
const WARM_STABILIZE_POLL_INTERVAL: Duration = Duration::from_secs(5);

fn warm_stabilize_timeout() -> Duration {
    std::env::var(WARM_STABILIZE_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(WARM_STABILIZE_TIMEOUT)
}

/// Block until the task set reaches steady state, or fail on timeout.
///
/// `timeout` / `poll_interval` are parameters (not the module consts) so the
/// unit tests drive the loop deterministically under a paused clock.
async fn wait_for_task_set_stability(
    target: &dyn EcsDeployTarget,
    task_set: &TaskSetRef,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<(), DeployerError> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = target
            .task_set_stability(task_set)
            .await
            .map_err(provider)?;
        if status.stabilized {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(DeployerError::Provider(format!(
                "task set for revision `{}` (deployment `{}`) did not stabilize within {}s \
                 (running {}/{})",
                task_set.revision_id.0,
                task_set.deployment_id.0,
                timeout.as_secs(),
                status.running,
                status.desired,
            )));
        }
        sleep(poll_interval).await;
    }
}

impl AwsEcsDeployerHandler {
    /// Locate the revision (the caller already passed `require_revision`, so
    /// the lookup is infallible by construction — keep it total anyway).
    fn revision(env: &Environment, revision_id: RevisionId) -> Option<&Revision> {
        env.revisions.iter().find(|r| r.revision_id == revision_id)
    }
}

#[async_trait]
impl Deployer for AwsEcsDeployerHandler {
    async fn stage_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<StageOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // No AWS work at stage time — see the module table.
        Ok(StageOutcome::default())
    }

    async fn warm_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<WarmOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = Self::revision(env, revision_id).expect("require_revision passed");
        let params = params_from_answers(env, answers)?;
        let deployment_id = revision.deployment_id;

        self.target
            .ensure_service(&ServiceSpec {
                deployment_id,
                cluster: params.cluster.clone(),
                region: params.region.clone(),
            })
            .await
            .map_err(provider)?;
        self.target
            .create_task_set(&TaskSetSpec {
                deployment_id,
                revision_id,
                cluster: params.cluster.clone(),
                region: params.region.clone(),
                image: params.image_for(revision_id),
                target_group: params.target_group(deployment_id, revision_id),
            })
            .await
            .map_err(provider)?;

        // The task set is created; the revision is only Ready once it reaches
        // steady state (running == desired AND its target group is healthy). A
        // task set that never stabilizes fails the warm, so the operator sees
        // the stall instead of a revision silently promoted over non-serving
        // tasks.
        wait_for_task_set_stability(
            self.target.as_ref(),
            &TaskSetRef {
                deployment_id,
                revision_id,
                cluster: params.cluster.clone(),
            },
            warm_stabilize_timeout(),
            WARM_STABILIZE_POLL_INTERVAL,
        )
        .await?;

        Ok(WarmOutcome::default())
    }

    async fn drain_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
    ) -> Result<DrainOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        // Routing-side only — see the module table. Task sets stay up so
        // in-flight sessions complete; archive tears them down.
        Ok(DrainOutcome::default())
    }

    async fn archive_revision(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ArchiveOutcome, DeployerError> {
        require_revision(env, revision_id)?;
        let revision = Self::revision(env, revision_id).expect("require_revision passed");
        let params = params_from_answers(env, answers)?;
        self.target
            .delete_task_set(&TaskSetRef {
                deployment_id: revision.deployment_id,
                revision_id,
                cluster: params.cluster,
            })
            .await
            .map_err(provider)?;
        Ok(ArchiveOutcome::default())
    }

    async fn apply_traffic_split(
        &self,
        env: &Environment,
        deployment_id: DeploymentId,
        answers: Option<&Value>,
    ) -> Result<TrafficSplitOutcome, DeployerError> {
        // Preconditions + outcome construction BEFORE any AWS call.
        let outcome = enforce_split_invariants(env, deployment_id)?;
        let params = params_from_answers(env, answers)?;
        let weights: Vec<TargetGroupWeight> = outcome
            .applied_entries
            .iter()
            .map(|entry| TargetGroupWeight {
                revision_id: entry.revision_id,
                weight_bps: entry.weight_bps,
                target_group: params.target_group(deployment_id, entry.revision_id),
            })
            .collect();
        self.target
            .apply_listener_weights(
                &ListenerRuleRef {
                    deployment_id,
                    rule_arn: params.listener_rule_arn(deployment_id),
                },
                &weights,
            )
            .await
            .map_err(provider)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::env_packs::aws::deploy_target::{InMemoryEcs, TaskSetHandle, TaskSetStability};
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::deployer::run_conformance;
    use ulid::Ulid;

    fn handler_with_fake() -> (AwsEcsDeployerHandler, Arc<InMemoryEcs>) {
        let target = Arc::new(InMemoryEcs::default());
        (AwsEcsDeployerHandler::with_target(target.clone()), target)
    }

    // ---- conformance: the Phase D entry gate ----------------------------

    #[tokio::test]
    async fn aws_ecs_deployer_passes_conformance() {
        let (handler, _target) = handler_with_fake();
        run_conformance(&handler)
            .await
            .expect("AWS-ECS deployer satisfies the Phase D conformance contract");
    }

    // ---- verb behavior against the in-memory fake -----------------------

    #[tokio::test]
    async fn warm_ensures_service_and_creates_the_task_set() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();

        assert!(
            target.services().contains(&rev.deployment_id),
            "warm ensures the deployment's service"
        );
        let sets = target.task_sets();
        assert_eq!(sets.len(), 1, "exactly one task set");
        assert!(
            sets.contains_key(&(rev.deployment_id, rev.revision_id)),
            "task set keyed by (deployment, revision)"
        );
    }

    #[tokio::test]
    async fn warm_is_idempotent() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        let first = target.task_sets();
        // Warm again: upsert, still exactly one task set with the same handle.
        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert_eq!(target.task_sets(), first, "warm is idempotent");
    }

    #[tokio::test]
    async fn warm_honors_a_cluster_answer() {
        let (handler, _target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        // A custom cluster answer scopes the verb; the fake records identity
        // not cluster, so assert via the params path that the answer parses
        // and the verb still lands a task set (the real target threads the
        // cluster into the SDK call).
        let answers = serde_json::json!({ "ecs_cluster_name": "custom-cluster" });
        handler
            .warm_revision(&env, rev.revision_id, Some(&answers))
            .await
            .unwrap();
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.cluster, "custom-cluster");
    }

    #[tokio::test]
    async fn warm_rejects_invalid_answers_before_touching_the_target() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];
        let answers = serde_json::json!({ "unknown_key": "x" });

        let err = handler
            .warm_revision(&env, rev.revision_id, Some(&answers))
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => assert!(msg.contains("invalid answers"), "msg: {msg}"),
            other => panic!("expected Provider, got {other:?}"),
        }
        assert!(
            target.task_sets().is_empty() && target.services().is_empty(),
            "invalid answers must not touch the target"
        );
    }

    #[tokio::test]
    async fn archive_deletes_the_task_set_and_tolerates_absence() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let rev = &env.revisions[0];

        handler
            .warm_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert_eq!(target.task_sets().len(), 1);

        handler
            .archive_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
        assert!(target.task_sets().is_empty());

        // Retried archive against an already-deleted set is Ok.
        handler
            .archive_revision(&env, rev.revision_id, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn traffic_split_applies_weights_mirroring_the_split() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep = env.bundles[0].deployment_id;

        let outcome = handler.apply_traffic_split(&env, dep, None).await.unwrap();
        assert_eq!(outcome.applied_deployment_id, dep);

        let weights = target.weights_for(dep).expect("weights applied");
        let split = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == dep)
            .unwrap();
        assert_eq!(weights.len(), split.entries.len());
        for entry in &split.entries {
            assert!(
                weights
                    .iter()
                    .any(|w| w.revision_id == entry.revision_id && w.weight_bps == entry.weight_bps),
                "weight for revision {} must mirror the split entry",
                entry.revision_id.0
            );
        }
    }

    /// A split for deployment A must not perturb deployment B's recorded
    /// weights (cross-deployment independence at the seam level).
    #[tokio::test]
    async fn traffic_split_is_independent_across_deployments() {
        let (handler, target) = handler_with_fake();
        let env = build_fixture_env();
        let dep_a = env.bundles[0].deployment_id;
        let dep_b = env.bundles[1].deployment_id;

        handler
            .apply_traffic_split(&env, dep_a, None)
            .await
            .unwrap();
        assert!(
            target.weights_for(dep_b).is_none(),
            "applying A's split must not write B's weights"
        );
        handler
            .apply_traffic_split(&env, dep_b, None)
            .await
            .unwrap();
        // A's weights are still its own.
        let split_a = env
            .traffic_splits
            .iter()
            .find(|s| s.deployment_id == dep_a)
            .unwrap();
        assert_eq!(
            target.weights_for(dep_a).unwrap().len(),
            split_a.entries.len()
        );
    }

    /// Preconditions run BEFORE any target call: unknown revision / invalid
    /// split must leave the target untouched.
    #[tokio::test]
    async fn preconditions_reject_before_any_target_call() {
        let (handler, target) = handler_with_fake();
        let mut env = build_fixture_env();
        let unknown = RevisionId(Ulid::from(0xFFFF_u128));

        let err = handler
            .warm_revision(&env, unknown, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::RevisionNotFound { .. }));

        // Invalid split (sum != 10000) on deployment A.
        env.traffic_splits[0].entries[0].weight_bps = 1;
        let dep = env.bundles[0].deployment_id;
        let err = handler
            .apply_traffic_split(&env, dep, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DeployerError::InvalidSplit { .. }));

        assert!(
            target.task_sets().is_empty()
                && target.services().is_empty()
                && target.weights_for(dep).is_none(),
            "rejected preconditions must not touch the target"
        );
    }

    /// The default handler (no real ECS client) fails provider verbs honestly
    /// instead of pretending the work happened.
    #[tokio::test]
    async fn unconfigured_target_surfaces_a_provider_error() {
        let handler = AwsEcsDeployerHandler::default();
        let env = build_fixture_env();
        let err = handler
            .warm_revision(&env, env.revisions[0].revision_id, None)
            .await
            .unwrap_err();
        match err {
            DeployerError::Provider(msg) => {
                assert!(msg.contains("no ECS API client"), "msg: {msg}");
            }
            other => panic!("expected Provider, got {other:?}"),
        }
        // Pure preconditions still come first even unconfigured.
        let unknown = RevisionId(Ulid::from(0xFFFF_u128));
        assert!(matches!(
            handler
                .warm_revision(&env, unknown, None)
                .await
                .unwrap_err(),
            DeployerError::RevisionNotFound { .. }
        ));
    }

    // ---- warm stabilization wait ----------------------------------------

    /// A target whose task set reports "not stable" for the first
    /// `stable_after` polls, then stable. Other methods are no-ops.
    #[derive(Debug)]
    struct ScriptedStabilityTarget {
        stable_after: usize,
        polls: AtomicUsize,
    }

    #[async_trait]
    impl EcsDeployTarget for ScriptedStabilityTarget {
        async fn ensure_service(&self, _spec: &ServiceSpec) -> Result<(), EcsTargetError> {
            Ok(())
        }
        async fn create_task_set(
            &self,
            _spec: &TaskSetSpec,
        ) -> Result<TaskSetHandle, EcsTargetError> {
            Ok(TaskSetHandle {
                task_set_id: "ts".into(),
                task_def_arn: "td".into(),
            })
        }
        async fn task_set_stability(
            &self,
            _task_set: &TaskSetRef,
        ) -> Result<TaskSetStability, EcsTargetError> {
            let n = self.polls.fetch_add(1, Ordering::SeqCst);
            Ok(TaskSetStability {
                stabilized: n >= self.stable_after,
                running: if n >= self.stable_after { 1 } else { 0 },
                desired: 1,
            })
        }
        async fn delete_task_set(&self, _task_set: &TaskSetRef) -> Result<(), EcsTargetError> {
            Ok(())
        }
        async fn apply_listener_weights(
            &self,
            _rule: &ListenerRuleRef,
            _weights: &[TargetGroupWeight],
        ) -> Result<(), EcsTargetError> {
            Ok(())
        }
    }

    fn task_set_ref() -> TaskSetRef {
        TaskSetRef {
            deployment_id: DeploymentId(Ulid::from(0x01_u128)),
            revision_id: RevisionId(Ulid::from(0x10_u128)),
            cluster: "greentic-test".into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn warm_stabilize_wait_resolves_once_the_task_set_is_stable() {
        let target = ScriptedStabilityTarget {
            stable_after: 3,
            polls: AtomicUsize::new(0),
        };
        wait_for_task_set_stability(
            &target,
            &task_set_ref(),
            Duration::from_secs(60),
            Duration::from_secs(2),
        )
        .await
        .expect("stabilizes once the task set reports steady state");
        assert!(
            target.polls.load(Ordering::SeqCst) >= 4,
            "must keep polling until stable"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn warm_stabilize_wait_times_out_when_never_stable() {
        let target = ScriptedStabilityTarget {
            stable_after: usize::MAX,
            polls: AtomicUsize::new(0),
        };
        let err = wait_for_task_set_stability(
            &target,
            &task_set_ref(),
            Duration::from_secs(10),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        match err {
            DeployerError::Provider(msg) => {
                assert!(msg.contains("did not stabilize"), "msg: {msg}");
                assert!(msg.contains("running 0/1"), "msg: {msg}");
            }
            other => panic!("expected a Provider timeout error, got {other:?}"),
        }
    }

    // ---- AwsEcsParams ---------------------------------------------------

    #[test]
    fn from_answers_none_equals_for_env() {
        let env = build_fixture_env();
        assert_eq!(
            AwsEcsParams::from_answers(&env, None).unwrap(),
            AwsEcsParams::for_env(&env)
        );
    }

    #[test]
    fn from_answers_overlays_known_keys() {
        let env = build_fixture_env();
        let answers = serde_json::json!({
            "region": "eu-west-1",
            "ecs_cluster_name": "prod",
            "ecr_repository_prefix": "123.dkr.ecr/greentic/",
            "alb_listener_arn": "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener/app/x/y/z",
            "aws_profile": "prod-admin",
        });
        let params = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap();
        assert_eq!(params.region, "eu-west-1");
        assert_eq!(params.cluster, "prod");
        assert_eq!(params.image_base, "123.dkr.ecr/greentic/");
        assert!(params.listener_arn.is_some());
    }

    #[test]
    fn from_answers_rejects_unknown_key() {
        let env = build_fixture_env();
        let answers = serde_json::json!({ "bogus": "x" });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::UnknownKey(k) if k == "bogus"));
    }

    #[test]
    fn from_answers_rejects_non_string_value() {
        let env = build_fixture_env();
        let answers = serde_json::json!({ "region": 123 });
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::NotAString(k) if k == "region"));
    }

    #[test]
    fn from_answers_rejects_non_object() {
        let env = build_fixture_env();
        let answers = serde_json::json!("not an object");
        let err = AwsEcsParams::from_answers(&env, Some(&answers)).unwrap_err();
        assert!(matches!(err, AwsEcsParamsError::NotAnObject));
    }
}
