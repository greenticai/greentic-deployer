use super::*;
use crate::env_packs::gcp_cloudrun::credentials::VALIDATED_GCP_PERMISSIONS;
use crate::env_packs::gcp_cloudrun::real_target::REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS;
use crate::env_packs::gcp_cloudrun::sor::spec::{
    SorServiceInputs, StagedVersions, sor_service_spec,
};
use crate::env_packs::k8s::manifests::sor::tests::unit;
use crate::environment::sor_units::CloudRunSorPlacement;

fn spec(with_ca: bool) -> SorServiceSpec {
    let (u, p) = (
        unit(),
        CloudRunSorPlacement::for_unit("proj", "europe-west1", "gtc-local", "landlord"),
    );
    let staged = StagedVersions {
        answers: "1".into(),
        postgres_url: "2".into(),
        shared_secret: "3".into(),
        postgres_ca: with_ca.then(|| "4".to_string()),
    };
    sor_service_spec(&SorServiceInputs {
        unit: &u,
        placement: &p,
        runtime_service_account: "sa@proj.iam.gserviceaccount.com",
        owner: "local-stamp",
        intent: "0123456789abcdef0123456789abcdef",
        staged: &staged,
    })
}

fn ready_condition() -> run::Condition {
    run::Condition::new()
        .set_type("Ready")
        .set_state(run::condition::State::ConditionSucceeded)
}

/// A service Cloud Run has finished rolling out: the latest created revision
/// is the latest ready one and the observed generation caught up.
fn settled_service(generation: i64, observed: i64, latest_ready: &str) -> run::Service {
    let mut svc = run::Service::new()
        .set_uri("https://gtc-sor-landlord-x.a.run.app")
        .set_terminal_condition(ready_condition());
    svc.generation = generation;
    svc.observed_generation = observed;
    svc.latest_created_revision = "gtc-sor-landlord-00002".to_string();
    svc.latest_ready_revision = latest_ready.to_string();
    svc
}

#[test]
fn a_create_carries_no_name_and_an_update_carries_the_name_and_etag() {
    let created = build_sor_service_message(&spec(false), None);
    assert!(created.name.is_empty() && created.etag.is_empty());
    let updated = build_sor_service_message(&spec(false), Some("e1"));
    assert_eq!(
        updated.name,
        "projects/proj/locations/europe-west1/services/gtc-sor-landlord"
    );
    assert_eq!(updated.etag, "e1");
}

#[test]
fn the_service_is_public_latest_traffic_scale_to_zero_and_labelled() {
    let svc = build_sor_service_message(&spec(false), None);
    assert_eq!(svc.ingress, run::IngressTraffic::All);
    assert_eq!(svc.traffic.len(), 1);
    assert_eq!(
        svc.traffic[0].r#type,
        run::TrafficTargetAllocationType::Latest
    );
    assert_eq!(svc.traffic[0].percent, 100);
    assert_eq!(
        svc.labels.get("greentic-managed").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        svc.labels.get("greentic-env").map(String::as_str),
        Some("local-stamp")
    );
    assert_eq!(
        svc.labels.get("greentic-sor-unit").map(String::as_str),
        Some("landlord")
    );
    assert_eq!(
        svc.labels.get("greentic-sor-intent").map(String::as_str),
        Some("0123456789abcdef0123456789abcdef")
    );
    let template = svc.template.as_ref().expect("template");
    assert_eq!(template.service_account, "sa@proj.iam.gserviceaccount.com");
    let scaling = template.scaling.as_ref().expect("scaling");
    assert_eq!(
        (scaling.min_instance_count, scaling.max_instance_count),
        (0, 1)
    );
}

#[test]
fn the_container_runs_sorx_on_8787_probed_at_healthz_with_version_pinned_inputs() {
    let svc = build_sor_service_message(&spec(true), None);
    let template = svc.template.as_ref().expect("template");
    let c = &template.containers[0];
    assert_eq!(c.args[0], "start");
    assert_eq!(
        c.args[2..],
        ["--answers", "env:SORX_ANSWERS", "--non-interactive"]
    );
    assert_eq!(c.ports[0].container_port, 8787);
    let probe = c.startup_probe.as_ref().expect("startup probe");
    let get = probe.http_get().expect("http probe");
    assert_eq!((get.path.as_str(), get.port), ("/healthz", 8787));
    let refs: Vec<(String, String)> = c
        .env
        .iter()
        .filter_map(|e| {
            e.value_source()
                .and_then(|s| s.secret_key_ref.as_ref())
                .map(|k| (e.name.clone(), k.version.clone()))
        })
        .collect();
    assert_eq!(
        refs,
        vec![
            ("SORX_ANSWERS".to_string(), "1".to_string()),
            ("SORX_POSTGRES_URL".to_string(), "2".to_string()),
            ("SORX_SHARED_SECRET".to_string(), "3".to_string()),
        ]
    );
    let volume = template.volumes[0].secret().expect("CA volume");
    assert_eq!(volume.secret, "gtc-local-sor-landlord");
    assert_eq!(
        (
            volume.items[0].version.as_str(),
            volume.items[0].path.as_str()
        ),
        ("4", "ca.pem")
    );
    assert_eq!(c.volume_mounts[0].mount_path, "/etc/sorx/postgres-ca");
}

#[test]
fn status_reads_owner_and_intent_labels_and_a_reconciling_service_is_not_ready() {
    let mut svc = settled_service(2, 2, "gtc-sor-landlord-00002").set_labels([
        ("greentic-env".to_string(), "local-stamp".to_string()),
        ("greentic-sor-intent".to_string(), "abc".to_string()),
    ]);
    let status = sor_status_from(&svc);
    assert_eq!(status.owner.as_deref(), Some("local-stamp"));
    assert_eq!(status.intent.as_deref(), Some("abc"));
    assert_eq!(
        status.url.as_deref(),
        Some("https://gtc-sor-landlord-x.a.run.app")
    );
    assert!(status.ready);
    svc.reconciling = true;
    let rolling = sor_status_from(&svc);
    assert!(!rolling.ready && rolling.reconciling && !rolling.failed());
}

/// Right after an upsert Cloud Run can still report Ready for the PREVIOUS
/// revision while the new generation has not been observed. Reading that as
/// ready would publish a route document (with a rotated token) the running
/// sorx rejects.
#[test]
fn a_lagging_observed_generation_is_reconciling_not_ready() {
    let svc = settled_service(2, 1, "gtc-sor-landlord-00002");
    let status = sor_status_from(&svc);
    assert!(!status.ready, "Ready=True alone must not mean ready");
    assert!(status.reconciling, "a lagging generation is a rollout");
    assert!(!status.failed());
}

#[test]
fn a_caught_up_service_whose_latest_created_revision_is_ready_is_ready() {
    let status = sor_status_from(&settled_service(2, 2, "gtc-sor-landlord-00002"));
    assert!(status.ready && !status.reconciling && !status.failed());
}

/// Settled, but the newest revision never became ready (the old one still
/// serves): failed, so the next run redeploys instead of reading it converged.
#[test]
fn a_settled_service_whose_latest_created_revision_is_not_ready_has_failed() {
    let status = sor_status_from(&settled_service(2, 2, "gtc-sor-landlord-00001"));
    assert!(!status.ready && !status.reconciling && status.failed());
    let mut empty = settled_service(2, 2, "");
    empty.latest_created_revision = String::new();
    assert!(
        !sor_status_from(&empty).ready,
        "no revision at all is not ready"
    );
}

#[test]
fn the_reader_binding_is_added_once_and_leaves_conditional_bindings_alone() {
    let member = "serviceAccount:sa@proj.iam.gserviceaccount.com";
    let conditional = serde_json::json!({
        "role": "roles/artifactregistry.reader",
        "members": ["user:x@example.com"],
        "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"},
    });
    let policy = serde_json::json!({"bindings": [conditional.clone()], "etag": "AbC="});
    let written = apply_ar_reader_binding(policy, member).expect("changed");
    assert_eq!(written["etag"], "AbC=", "the etag rides back");
    assert_eq!(written["bindings"][0], conditional, "untouched");
    assert_eq!(
        written["bindings"][1],
        serde_json::json!({"role": "roles/artifactregistry.reader", "members": [member]})
    );
    assert!(
        apply_ar_reader_binding(written, member).is_none(),
        "already granted"
    );
    assert!(apply_ar_reader_binding(serde_json::json!({}), member).is_some());
}

/// The SoR path needs no permission a validated deployer does not already
/// hold; the best-effort grant's permissions stay OUT of the preflight so
/// a deployer without them is not refused.
#[test]
fn the_sor_permission_contract_holds() {
    for p in SOR_REQUIRED_IAM_PERMISSIONS {
        assert!(
            REAL_CLOUDRUN_TARGET_IAM_PERMISSIONS.contains(p),
            "{p} not in REAL"
        );
    }
    for p in SOR_BEST_EFFORT_IAM_PERMISSIONS {
        assert!(
            !VALIDATED_GCP_PERMISSIONS.contains(p),
            "{p} must stay best effort"
        );
    }
}
