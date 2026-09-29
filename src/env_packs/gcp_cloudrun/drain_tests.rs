//! Tests for [`super`] (Cloud Run enforced drain).
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

/// `op bundles retire --drain-seconds`: the override replaces the revision's
/// own 30 s (and is not capped by `max_wait`), on both the per-revision and
/// the whole-bundle drain paths.
#[tokio::test(start_paused = true)]
async fn drain_waits_the_override_window_instead_of_the_recorded_one() {
    let policy = DrainPolicy {
        max_wait: Duration::from_secs(12),
        ..DrainPolicy::immediate()
    };
    for (override_secs, expected) in [(Some(40), 40), (Some(1), 1), (None, 12)] {
        let (h, _) = handler(policy.with_window_override(override_secs.map(Duration::from_secs)));
        let env = build_fixture_env(); // drain_seconds = 30
        let started = tokio::time::Instant::now();
        let out = h
            .drain_revision(&env, env.revisions[1].revision_id, None)
            .await
            .unwrap();
        assert_eq!(out.waited_seconds, expected, "{override_secs:?}");
        assert!(started.elapsed() >= Duration::from_secs(expected));

        let (env, r) = retiring_single_revision_env();
        let out = h.drain_revision(&env, r, None).await.unwrap();
        assert_eq!(
            out.waited_seconds, expected,
            "whole bundle {override_secs:?}"
        );
    }
}

/// The fixture's single-revision deployment (`dep_b`, revision 2), marked
/// retiring as `op bundles retire` leaves it.
fn retiring_single_revision_env() -> (Environment, RevisionId) {
    let mut env = build_fixture_env();
    env.bundles[1].status = greentic_deploy_spec::BundleDeploymentStatus::Archived;
    env.traffic_splits
        .retain(|s| s.deployment_id != env.bundles[1].deployment_id);
    let r = env.revisions[2].revision_id;
    (env, r)
}

#[tokio::test]
async fn a_whole_bundle_retire_drains_the_service_and_archive_deletes_it() {
    let (h, target) = handler(DrainPolicy::immediate());
    let (env, r) = retiring_single_revision_env();
    let dep = env.bundles[1].deployment_id;
    h.warm_revision(&env, r, None).await.unwrap();
    // Its only revision carries 100 % — a per-revision 0 % check could never pass.
    assert_eq!(target.traffic_for(dep).unwrap()[0].percent, 100);
    let out = h.drain_revision(&env, r, None).await.unwrap();
    assert!(
        matches!(out.evidence, DrainEvidence::ServiceRetiring { .. }),
        "{out:?}"
    );
    h.confirm_drained(&env, r, None).await.unwrap();
    h.archive_revision(&env, r, None).await.unwrap();
    assert!(
        target.traffic_for(dep).is_none(),
        "the whole Service is deleted"
    );
    // Idempotent against the now-absent Service.
    h.archive_revision(&env, r, None).await.unwrap();
}

#[tokio::test]
async fn a_whole_bundle_retire_refuses_while_an_endpoint_still_routes_to_it() {
    use greentic_deploy_spec::{MessagingEndpoint, MessagingEndpointId, SchemaVersion};
    let (h, _) = handler(DrainPolicy::immediate());
    let (mut env, r) = retiring_single_revision_env();
    let bundle = env.revisions[2].bundle_id.clone();
    env.messaging_endpoints.push(MessagingEndpoint {
        schema: SchemaVersion::new(SchemaVersion::MESSAGING_ENDPOINT_V1),
        env_id: env.environment_id.clone(),
        endpoint_id: MessagingEndpointId::new(),
        provider_id: "tg".into(),
        provider_type: "messaging.telegram.bot".into(),
        display_name: "support-bot".into(),
        secret_refs: Vec::new(),
        webhook_secret_ref: None,
        linked_bundles: vec![bundle],
        welcome_flow: None,
        generation: 0,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        updated_by: "test".into(),
    });
    let err = h.drain_revision(&env, r, None).await.unwrap_err();
    assert!(
        matches!(err, DeployerError::NotDrained { ref reason, .. } if reason.contains("support-bot")),
        "{err:?}"
    );
}

#[tokio::test]
async fn the_only_routed_revision_is_told_to_retire_the_bundle_not_apply_traffic() {
    let (h, _) = handler(DrainPolicy::immediate());
    let env = build_fixture_env();
    let r = env.revisions[2].revision_id; // dep_b's only revision, deployment still active
    h.warm_revision(&env, r, None).await.unwrap();
    let err = h.drain_revision(&env, r, None).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("op bundles retire") && !msg.contains("apply-traffic"),
        "{msg}"
    );
}

#[tokio::test]
async fn traffic_pinned_to_latest_is_never_read_as_drained() {
    use crate::env_packs::gcp_cloudrun::deploy_target::{
        CloudRunTarget, ServiceRef, TrafficTarget,
    };
    let (h, target) = handler(DrainPolicy::immediate());
    let env = build_fixture_env();
    let (r0, r1) = (env.revisions[0].revision_id, env.revisions[1].revision_id);
    h.warm_revision(&env, r0, None).await.unwrap();
    h.warm_revision(&env, r1, None).await.unwrap();
    // Console edit: 60 % named r0, the rest on LATEST (dropped from traffic[]).
    let service = ServiceRef {
        deployment_id: env.bundles[0].deployment_id,
        project: "p".into(),
        region: "r".into(),
    };
    let etag = target.get_service(&service).await.unwrap().unwrap().etag;
    target
        .set_traffic(
            &service,
            &[TrafficTarget {
                revision_id: r0,
                percent: 60,
            }],
            &etag,
        )
        .await
        .unwrap();
    let err = h.drain_revision(&env, r1, None).await.unwrap_err();
    assert!(
        matches!(err, DeployerError::NotDrained { ref reason, .. } if reason.contains("LATEST")),
        "{err:?}"
    );
}
