//! A warm must retain traffic the seam cannot represent. Pin LATEST to the
//! currently ready revision before changing the template, so warming does not
//! promote the candidate. Never repair a missing allocation by promoting it.

use google_cloud_run_v2::model as run;
use greentic_deploy_spec::{DeploymentId, RevisionId};

use super::{CloudRunTargetError, revision_name};

pub(super) fn preserve(
    current: &run::Service,
    deployment: DeploymentId,
    candidate: RevisionId,
) -> Result<Vec<run::TrafficTarget>, CloudRunTargetError> {
    let pin_latest = || {
        current.latest_ready_revision.rsplit('/').next()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| CloudRunTargetError::Api(
                "cannot preserve LATEST traffic while warming: the service has no latest ready revision; no update was sent".into()
            ))
    };
    let mut traffic = current.traffic.clone();
    if traffic.is_empty() {
        traffic.push(
            run::TrafficTarget::new()
                .set_type(run::TrafficTargetAllocationType::Revision)
                .set_revision(pin_latest()?)
                .set_percent(100),
        );
    }
    for target in &mut traffic {
        if target.r#type == run::TrafficTargetAllocationType::Latest {
            target.revision = pin_latest()?.to_string();
            target.r#type = run::TrafficTargetAllocationType::Revision;
        }
    }
    let total: i64 = traffic.iter().map(|t| i64::from(t.percent)).sum();
    if total != 100
        || traffic
            .iter()
            .any(|t| !(0..=100).contains(&t.percent) || t.revision.is_empty())
    {
        return Err(CloudRunTargetError::Api(
            "cannot preserve live traffic while warming: expected named targets totalling 100%; no update was sent".into()
        ));
    }
    let candidate = revision_name(deployment, candidate);
    if !traffic.iter().any(|t| t.revision == candidate) {
        traffic.push(
            run::TrafficTarget::new()
                .set_type(run::TrafficTargetAllocationType::Revision)
                .set_revision(candidate)
                .set_percent(0),
        );
    }
    Ok(traffic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ulid::Ulid;

    fn ids() -> (DeploymentId, RevisionId) {
        (
            DeploymentId(Ulid::from(1_u128)),
            RevisionId(Ulid::from(2_u128)),
        )
    }

    fn latest(percent: i32) -> run::TrafficTarget {
        run::TrafficTarget::new()
            .set_type(run::TrafficTargetAllocationType::Latest)
            .set_percent(percent)
    }

    #[test]
    fn latest_only_is_pinned_to_old_ready_revision_and_candidate_stays_zero() {
        let svc = run::Service::new()
            .set_latest_ready_revision("projects/p/locations/r/services/s/revisions/old-ready")
            .set_traffic([latest(100).set_tag("production")]);
        let (d, r) = ids();
        let out = preserve(&svc, d, r).unwrap();
        assert_eq!(out[0].revision, "old-ready");
        assert_eq!(out[0].percent, 100);
        assert_eq!(out[0].tag, "production");
        assert_eq!(out[0].r#type, run::TrafficTargetAllocationType::Revision);
        assert_eq!(out[1].revision, revision_name(d, r));
        assert_eq!(out[1].percent, 0);
    }

    #[test]
    fn cloud_run_generated_revision_keeps_its_entire_allocation_during_warm() {
        // The healthy revision created by the credential repair is not a ULID
        // revision, so the seam's traffic projection drops it completely.
        let (d, r) = ids();
        let repaired = format!("{}-00006-b6w", super::super::service_name(d));
        let svc = run::Service::new().set_traffic([run::TrafficTarget::new()
            .set_type(run::TrafficTargetAllocationType::Revision)
            .set_revision(repaired.clone())
            .set_percent(100)]);
        assert!(super::super::traffic_targets_from(&svc.traffic).is_empty());
        let out = preserve(&svc, d, r).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].revision, repaired);
        assert_eq!(out[0].percent, 100);
        assert_eq!(out[1].percent, 0);
        assert_eq!(out.iter().map(|t| t.percent).sum::<i32>(), 100);
    }

    #[test]
    fn mixed_foreign_and_latest_allocations_and_tags_survive() {
        let svc = run::Service::new()
            .set_latest_ready_revision("old-ready")
            .set_traffic([
                run::TrafficTarget::new()
                    .set_type(run::TrafficTargetAllocationType::Revision)
                    .set_revision("foreign-revision")
                    .set_percent(60),
                latest(40),
            ]);
        let (d, r) = ids();
        let out = preserve(&svc, d, r).unwrap();
        assert_eq!(
            out.iter().map(|t| t.percent).collect::<Vec<_>>(),
            [60, 40, 0]
        );
        assert_eq!(out[0].revision, "foreign-revision");
        assert_eq!(out[1].revision, "old-ready");
    }

    #[test]
    fn implicit_latest_is_pinned_and_rewarming_does_not_duplicate_candidate() {
        let (d, r) = ids();
        let svc = run::Service::new().set_latest_ready_revision(revision_name(d, r));
        let out = preserve(&svc, d, r).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].percent, 100);
    }

    #[test]
    fn unresolved_latest_and_invalid_totals_refuse_without_promoting_candidate() {
        let (d, r) = ids();
        for svc in [
            run::Service::new(),
            run::Service::new().set_traffic([latest(100)]),
            run::Service::new()
                .set_latest_ready_revision("old")
                .set_traffic([latest(0)]),
            run::Service::new()
                .set_latest_ready_revision("old")
                .set_traffic([latest(120)]),
        ] {
            assert!(preserve(&svc, d, r).is_err());
        }
    }
}
