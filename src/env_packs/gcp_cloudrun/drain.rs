//! Enforced drain for the Cloud Run env-pack (P5-R2).
//!
//! Cloud Run owns the request path, so the drain confirms on the one signal it
//! exposes: the Service's live `traffic[]` gives the revision **0 %**. The
//! sequence is: wait the drain window (`drain_seconds`, capped by the policy)
//! so requests already routed finish, then read the live Service until the
//! revision's percent is 0 (or the confirm timeout names it `NotDrained`).
//! Cloud Run then scales the revision to zero instances on its own.
//!
//! The live traffic, not the recorded split, is the truth here: a split
//! recorded with `op traffic set` but never pushed (`op env apply-traffic`)
//! still routes live requests, and the drain must not claim otherwise.

use tokio::time::sleep;

use greentic_deploy_spec::{Environment, RevisionId};
use serde_json::Value;

use super::GcpCloudRunDeployerHandler;
use super::deploy_target::ServiceRef;
use super::deployer::{find_revision, params_from_answers, provider, service_name};
use crate::env_packs::deployer::drain::confirm_within;
use crate::env_packs::deployer::{
    DeployerError, DrainEvidence, DrainOutcome, DrainPolicy, DrainProbe, require_revision,
};

impl GcpCloudRunDeployerHandler {
    fn drain_service_ref(
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<ServiceRef, DeployerError> {
        require_revision(env, revision_id)?;
        let revision =
            find_revision(env, revision_id).ok_or_else(|| DeployerError::RevisionNotFound {
                env_id: env.environment_id.clone(),
                revision_id,
            })?;
        let params = params_from_answers(env, answers)?;
        Ok(ServiceRef {
            deployment_id: revision.deployment_id,
            project: params.project,
            region: params.region,
        })
    }

    async fn probe_traffic(
        &self,
        service: &ServiceRef,
        revision_id: RevisionId,
    ) -> Result<DrainProbe, DeployerError> {
        let name = service_name(service.deployment_id);
        let live = self.target.get_service(service).await.map_err(provider)?;
        Ok(match live {
            None => DrainProbe::Drained(DrainEvidence::ZeroTrafficPercent {
                service: name,
                service_absent: true,
            }),
            Some(status) => {
                let percent: u32 = status
                    .traffic
                    .iter()
                    .filter(|t| t.revision_id == revision_id)
                    .map(|t| t.percent)
                    .sum();
                if percent == 0 {
                    DrainProbe::Drained(DrainEvidence::ZeroTrafficPercent {
                        service: name,
                        service_absent: false,
                    })
                } else {
                    DrainProbe::Pending(format!(
                        "Cloud Run service `{name}` still routes {percent}% of live traffic to it; \
                         push the moved split first (`op env apply-traffic`)"
                    ))
                }
            }
        })
    }

    pub(super) async fn drain_enforced(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainOutcome, DeployerError> {
        let service = Self::drain_service_ref(env, revision_id, answers)?;
        let window = find_revision(env, revision_id)
            .map(|r| self.drain_policy.window(r))
            .unwrap_or_default();
        sleep(window).await;
        let evidence = confirm_within(revision_id, &self.drain_policy, || {
            self.probe_traffic(&service, revision_id)
        })
        .await?;
        Ok(DrainOutcome {
            waited_seconds: window.as_secs(),
            evidence,
        })
    }

    pub(super) async fn confirm_drained_now(
        &self,
        env: &Environment,
        revision_id: RevisionId,
        answers: Option<&Value>,
    ) -> Result<DrainEvidence, DeployerError> {
        let service = Self::drain_service_ref(env, revision_id, answers)?;
        confirm_within(revision_id, &DrainPolicy::immediate(), || {
            self.probe_traffic(&service, revision_id)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::env_packs::deployer::Deployer;
    use crate::env_packs::deployer::conformance::build_fixture_env;
    use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;

    fn handler(policy: DrainPolicy) -> (GcpCloudRunDeployerHandler, Arc<InMemoryCloudRun>) {
        let target = Arc::new(InMemoryCloudRun::default());
        (
            GcpCloudRunDeployerHandler::with_target(target.clone()).with_drain_policy(policy),
            target,
        )
    }

    #[tokio::test]
    async fn a_revision_serving_live_traffic_is_not_drained() {
        let (h, _) = handler(DrainPolicy::immediate());
        let env = build_fixture_env();
        let r = env.revisions[0].revision_id;
        // First warm pins 100 % to this revision.
        h.warm_revision(&env, r, None).await.unwrap();
        let err = h.drain_revision(&env, r, None).await.unwrap_err();
        assert!(
            matches!(err, DeployerError::NotDrained { revision_id, ref reason }
                if revision_id == r && reason.contains("100%")),
            "{err:?}"
        );
        assert!(matches!(
            h.confirm_drained(&env, r, None).await.unwrap_err(),
            DeployerError::NotDrained { .. }
        ));
    }

    #[tokio::test]
    async fn a_zero_percent_revision_drains_with_evidence() {
        let (h, _) = handler(DrainPolicy::immediate());
        let env = build_fixture_env();
        let (r0, r1) = (env.revisions[0].revision_id, env.revisions[1].revision_id);
        h.warm_revision(&env, r0, None).await.unwrap();
        h.warm_revision(&env, r1, None).await.unwrap(); // added at 0 %
        let out = h.drain_revision(&env, r1, None).await.unwrap();
        assert!(matches!(
            out.evidence,
            DrainEvidence::ZeroTrafficPercent {
                service_absent: false,
                ..
            }
        ));
        h.confirm_drained(&env, r1, None).await.unwrap();
    }

    #[tokio::test]
    async fn an_absent_service_is_drained() {
        let (h, _) = handler(DrainPolicy::immediate());
        let env = build_fixture_env();
        let out = h
            .drain_revision(&env, env.revisions[1].revision_id, None)
            .await
            .unwrap();
        assert!(matches!(
            out.evidence,
            DrainEvidence::ZeroTrafficPercent {
                service_absent: true,
                ..
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_waits_the_capped_window_before_confirming() {
        let (h, _) = handler(DrainPolicy {
            max_wait: Duration::from_secs(12),
            ..DrainPolicy::immediate()
        });
        let env = build_fixture_env(); // drain_seconds = 30 → capped to 12
        let started = tokio::time::Instant::now();
        let out = h
            .drain_revision(&env, env.revisions[1].revision_id, None)
            .await
            .unwrap();
        assert_eq!(out.waited_seconds, 12);
        assert!(started.elapsed() >= Duration::from_secs(12));
    }
}
