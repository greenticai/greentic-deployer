use ulid::Ulid;

use super::*;
use crate::env_packs::azure_aca::arm_types::*;
use crate::env_packs::azure_aca::naming::{app_name, revision_suffix};
use greentic_deploy_spec::{DeploymentId, RevisionId};

fn spec(n: u128, intent: &str, secrets: Vec<AppSecret>, traffic: &[(u128, u32)]) -> AppSpec {
    let name = app_name(&DeploymentId(Ulid::from(1_u128)));
    let t = traffic
        .iter()
        .map(|(r, w)| TrafficEntry {
            revision_name: revision_name(&name, &revision_suffix(&RevisionId(Ulid::from(*r)))),
            weight: *w,
        })
        .collect();
    AppSpec {
        name,
        location: "l".into(),
        environment_id: "e".into(),
        tags: vec![(OWNER_TAG.into(), "me".into())],
        target_port: 8080,
        secrets,
        traffic: t,
        revision: RevisionSpec {
            suffix: revision_suffix(&RevisionId(Ulid::from(n))),
            image: "i".into(),
            cpu: 0.5,
            memory: "1Gi".into(),
            env: vec![
                EnvEntry::plain(INTENT_ENV, intent),
                EnvEntry::secret_ref("S", "seed-a"),
            ],
            init: None,
            min_replicas: 0,
            max_replicas: 1,
        },
    }
}

fn seeds() -> Vec<AppSecret> {
    vec![AppSecret::new("seed-a", "v")]
}

#[tokio::test]
async fn put_revision_is_idempotent_for_the_same_intent_and_conflicts_otherwise() {
    let t = InMemoryAca::new();
    let a = t
        .put_revision(&spec(0x10, "i1", seeds(), &[(0x10, 100)]))
        .await
        .unwrap();
    let b = t
        .put_revision(&spec(0x10, "i1", seeds(), &[(0x10, 100)]))
        .await
        .unwrap();
    assert_eq!(a, b);
    let e = t
        .put_revision(&spec(0x10, "i2", seeds(), &[(0x10, 100)]))
        .await
        .unwrap_err();
    assert!(matches!(e, AcaTargetError::Conflict(_)));
    assert_eq!(t.revisions_of(&a.app.name).len(), 1);
}

#[tokio::test]
async fn traffic_must_sum_to_100_and_name_known_revisions() {
    let t = InMemoryAca::new();
    let r = t
        .put_revision(&spec(0x10, "i", seeds(), &[(0x10, 100)]))
        .await
        .unwrap();
    let w = |n: &str, w| TrafficEntry {
        revision_name: n.into(),
        weight: w,
    };
    assert!(t.set_traffic(&r.app, &[w(&r.name, 60)]).await.is_err());
    assert!(t.set_traffic(&r.app, &[w("nope", 100)]).await.is_err());
    t.set_traffic(&r.app, &[w(&r.name, 100)]).await.unwrap();
}

#[tokio::test]
async fn a_referenced_secret_cannot_be_dropped() {
    let t = InMemoryAca::new();
    t.put_revision(&spec(0x10, "i", seeds(), &[(0x10, 100)]))
        .await
        .unwrap();
    let e = t
        .put_revision(&spec(
            0x20,
            "j",
            vec![AppSecret::new("other", "x")],
            &[(0x10, 100), (0x20, 0)],
        ))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("still referenced"), "{e}");
}

#[tokio::test]
async fn delete_is_idempotent_and_deactivate_tolerates_absence() {
    let t = InMemoryAca::new();
    let r = t
        .put_revision(&spec(0x10, "i", seeds(), &[(0x10, 100)]))
        .await
        .unwrap();
    t.deactivate_revision(&r).await.unwrap();
    assert_eq!(
        t.revision_status(&r).await.unwrap(),
        RevisionStatus::Inactive
    );
    assert!(t.delete_app(&r.app).await.unwrap());
    assert!(!t.delete_app(&r.app).await.unwrap());
    t.deactivate_revision(&r).await.unwrap();
}

#[tokio::test]
async fn a_foreign_owner_is_reported_and_refused() {
    let t = InMemoryAca::new();
    let name = app_name(&DeploymentId(Ulid::from(1_u128)));
    t.seed_app(name.as_str(), Some("someone-else"));
    let app = AppRef {
        name: name.as_str().into(),
    };
    assert!(matches!(
        t.inspect_app(&app).await.unwrap(),
        AppState::Present { owner: Some(o), .. } if o == "someone-else"
    ));
    assert!(
        t.put_revision(&spec(0x10, "i", seeds(), &[(0x10, 100)]))
            .await
            .is_err()
    );
}
