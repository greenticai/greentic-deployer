//! Enforced drain for the Cloud Run env-pack (P5-R2).
//!
//! Cloud Run owns the request path, so the drain confirms on the one signal it
//! exposes: the Service's live `traffic[]` gives the revision **0 %**. Cloud
//! Run then scales the revision to zero instances on its own.
//!
//! Order: probe first (fail fast when the revision is still routed), then the
//! window as grace for requests in flight at the moment of the cut, then a
//! final confirmation.
//!
//! **Whole-bundle retire** is different: one Service per deployment, and its
//! `traffic[]` always sums to 100 %, so the Service's last revision can never
//! reach 0 %. When the deployment is retiring, confirmation is "no messaging
//! endpoint routes to the bundle any more" plus the window, and
//! `archive_revision` deletes the whole Service.
//!
//! The live traffic, not the recorded split, is the truth here: a split
//! recorded with `op traffic set` but never pushed (`op env apply-traffic`)
//! still routes live requests, and the drain must not claim otherwise.

use tokio::time::sleep;

use greentic_deploy_spec::{BundleDeploymentStatus, Environment, RevisionId, RevisionLifecycle};
use serde_json::Value;

use super::GcpCloudRunDeployerHandler;
use super::deploy_target::ServiceRef;
use super::deployer::{find_revision, params_from_answers, provider, service_name};
use crate::env_packs::deployer::drain::confirm_within;
use crate::env_packs::deployer::{
    DeployerError, DrainEvidence, DrainOutcome, DrainPolicy, DrainProbe, require_revision,
};

/// True when the revision's whole deployment is retiring (`op bundles retire`
/// marked it `archived`). Cloud Run has one Service per deployment and its
/// live `traffic[]` always sums to 100 %, so the Service's last revision can
/// never reach 0 %: the unit being drained is the Service itself.
pub(super) fn whole_bundle_retiring(env: &Environment, revision_id: RevisionId) -> bool {
    let Some(revision) = find_revision(env, revision_id) else {
        return false;
    };
    env.bundles.iter().any(|b| {
        b.deployment_id == revision.deployment_id && b.status == BundleDeploymentStatus::Archived
    })
}

/// Whole-bundle drain precondition: no messaging endpoint still routes to the
/// bundle (retire's own preflight enforces this; checked again because the
/// store can move between the two).
fn require_no_endpoint_route(
    env: &Environment,
    revision_id: RevisionId,
) -> Result<(), DeployerError> {
    let Some(revision) = find_revision(env, revision_id) else {
        return Ok(());
    };
    let bundle = &revision.bundle_id;
    let still: Vec<&str> = env
        .messaging_endpoints
        .iter()
        .filter(|ep| {
            ep.linked_bundles.contains(bundle)
                || ep
                    .welcome_flow
                    .as_ref()
                    .is_some_and(|wf| &wf.bundle_id == bundle)
        })
        .map(|ep| ep.display_name.as_str())
        .collect();
    if still.is_empty() {
        Ok(())
    } else {
        Err(DeployerError::NotDrained {
            revision_id,
            reason: format!(
                "messaging endpoint(s) {} still route to bundle `{bundle}`; unlink them first",
                still.join(", ")
            ),
        })
    }
}

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
        env: &Environment,
        service: &ServiceRef,
        revision_id: RevisionId,
    ) -> Result<DrainProbe, DeployerError> {
        let name = service_name(service.deployment_id);
        let live = self.target.get_service(service).await.map_err(provider)?;
        let Some(status) = live else {
            return Ok(DrainProbe::Drained(DrainEvidence::ZeroTrafficPercent {
                service: name,
                service_absent: true,
            }));
        };
        let percent: u32 = status
            .traffic
            .iter()
            .filter(|t| t.revision_id == revision_id)
            .map(|t| t.percent)
            .sum();
        // Entries we cannot attribute to a named revision (`LATEST`, or a
        // revision name this deployer did not mint) are dropped from
        // `traffic[]`; whatever they carry could be this revision.
        let attributed: u32 = status.traffic.iter().map(|t| t.percent).sum();
        let unattributed = 100u32.saturating_sub(attributed);
        if percent == 0 && unattributed == 0 {
            return Ok(DrainProbe::Drained(DrainEvidence::ZeroTrafficPercent {
                service: name,
                service_absent: false,
            }));
        }
        if percent == 0 {
            return Ok(DrainProbe::Pending(format!(
                "Cloud Run service `{name}` routes {unattributed}% of live traffic to `LATEST` \
                 or an unrecognised target, which may be this revision; pin traffic to named \
                 revisions first (`op env apply-traffic`)"
            )));
        }
        let survivor = find_revision(env, revision_id).is_some_and(|rev| {
            env.revisions.iter().any(|r| {
                r.deployment_id == rev.deployment_id
                    && r.revision_id != revision_id
                    && r.lifecycle != RevisionLifecycle::Archived
            })
        });
        let advice = if survivor {
            "move its weight to a surviving revision and push the split (`op traffic set`, then \
             `op env apply-traffic`)"
        } else {
            "it is the Service's only revision, so no split can move its traffic; retire the \
             whole bundle (`op bundles retire`), which deletes the Service"
        };
        Ok(DrainProbe::Pending(format!(
            "Cloud Run service `{name}` still routes {percent}% of live traffic to it; {advice}"
        )))
    }

    /// Enforced drain: confirm routing is already 0 % (fail fast), THEN wait
    /// the window as grace for requests in flight at the cut, then confirm
    /// again. A whole-bundle retire drains the Service instead.
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
        if whole_bundle_retiring(env, revision_id) {
            require_no_endpoint_route(env, revision_id)?;
            sleep(window).await;
            return Ok(DrainOutcome {
                waited_seconds: window.as_secs(),
                evidence: DrainEvidence::ServiceRetiring {
                    service: service_name(service.deployment_id),
                },
            });
        }
        if let DrainProbe::Pending(reason) = self.probe_traffic(env, &service, revision_id).await? {
            return Err(DeployerError::NotDrained {
                revision_id,
                reason,
            });
        }
        sleep(window).await;
        let evidence = confirm_within(revision_id, &self.drain_policy, || {
            self.probe_traffic(env, &service, revision_id)
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
        if whole_bundle_retiring(env, revision_id) {
            require_no_endpoint_route(env, revision_id)?;
            return Ok(DrainEvidence::ServiceRetiring {
                service: service_name(service.deployment_id),
            });
        }
        confirm_within(revision_id, &DrainPolicy::immediate(), || {
            self.probe_traffic(env, &service, revision_id)
        })
        .await
    }
}

#[cfg(test)]
#[path = "drain_tests.rs"]
mod tests;
