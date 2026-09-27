use std::time::Duration;

use super::*;
use crate::env_packs::gcp_cloudrun::deploy_target::InMemoryCloudRun;
use crate::env_packs::gcp_cloudrun::deployer::env_owner_stamp;
use crate::env_packs::gcp_cloudrun::sor::fake::InMemorySorServices;
use crate::env_packs::gcp_cloudrun::sor::retire::{SorRetireOutcome, retire};
use crate::env_packs::k8s::manifests::sor::tests::{inputs, unit};
use crate::runtime_secrets::SecretValue;

const SA: &str = "gtc-local-runtime@proj.iam.gserviceaccount.com";
const SERVICE: &str = "gtc-sor-landlord";
const SECRET: &str = "gtc-local-sor-landlord";

fn placement() -> CloudRunSorPlacement {
    CloudRunSorPlacement::for_unit("proj", "europe-west1", "gtc-local", "landlord")
}

fn render(with_ca: bool) -> SorUnitRender {
    SorUnitRender {
        unit: unit(),
        inputs: inputs(with_ca),
    }
}

fn ctx() -> SorUpContext<'static> {
    SorUpContext {
        env_id: "local",
        runtime_service_account: SA,
        timing: SorReadyTiming {
            timeout: Duration::from_millis(40),
            poll: Duration::from_millis(5),
        },
    }
}

async fn run(
    secrets: &InMemoryCloudRun,
    services: &InMemorySorServices,
    render: &SorUnitRender,
) -> Result<SorUpOutcome, DeployerError> {
    let p = placement();
    bring_up(
        secrets,
        services,
        &ctx(),
        &[PlacedSorUnit {
            render,
            placement: &p,
        }],
    )
    .await
}

fn fakes() -> (InMemoryCloudRun, InMemorySorServices) {
    (InMemoryCloudRun::default(), InMemorySorServices::default())
}

#[tokio::test]
async fn a_first_run_stages_each_input_grants_the_runtime_account_and_publishes_the_url() {
    let (secrets, services) = fakes();
    let out = run(&secrets, &services, &render(false)).await.expect("up");

    assert_eq!(secrets.secrets()[SECRET].versions, 3);
    assert_eq!(
        secrets.secret_accessors_for(SECRET),
        Some(vec![SA.to_string()])
    );
    let spec = services.spec(SERVICE).expect("deployed");
    let pinned: Vec<(&str, &str)> = spec
        .secret_env
        .iter()
        .map(|e| (e.name.as_str(), e.version.as_str()))
        .collect();
    assert_eq!(
        pinned,
        vec![
            ("SORX_ANSWERS", "1"),
            ("SORX_POSTGRES_URL", "2"),
            ("SORX_SHARED_SECRET", "3"),
        ]
    );
    assert!(services.is_public(SERVICE), "allUsers invoker (E5)");

    let url = InMemorySorServices::url_for(SERVICE);
    assert_eq!(
        out.statuses,
        vec![SorUnitStatus {
            unit_id: "landlord".into(),
            sor: "landlord-tenant-sor".into(),
            service: SERVICE.into(),
            url: url.clone(),
            ready: true,
        }]
    );
    assert_eq!(out.routes[0].sor, "landlord-tenant-sor");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(out.routes[0].value.expose()).unwrap(),
        serde_json::json!({"url": url, "token": "shared-SECRET-token", "tenant": "acme"})
    );
    assert!(out.notes.is_empty(), "no AR host, nothing to grant");
}

#[tokio::test]
async fn a_rerun_with_unchanged_inputs_stages_nothing_and_does_not_redeploy() {
    let (secrets, services) = fakes();
    run(&secrets, &services, &render(false)).await.unwrap();
    let again = run(&secrets, &services, &render(false)).await.unwrap();
    assert_eq!(secrets.secrets()[SECRET].versions, 3, "no new version");
    assert_eq!(services.upserts(), 1, "no new revision");
    assert_eq!(
        again.routes.len(),
        1,
        "the route document is still produced"
    );
}

#[tokio::test]
async fn a_changed_input_restages_and_redeploys() {
    let (secrets, services) = fakes();
    run(&secrets, &services, &render(false)).await.unwrap();
    let mut rotated = render(false);
    rotated.inputs.shared_secret = SecretValue::from("rotated-SECRET".to_string());
    run(&secrets, &services, &rotated).await.unwrap();
    assert_eq!(secrets.secrets()[SECRET].versions, 6);
    assert_eq!(services.upserts(), 2);
}

#[tokio::test]
async fn a_service_another_environment_owns_is_refused_before_anything_is_staged() {
    let (secrets, services) = fakes();
    services.seed_service(SERVICE, Some("someone-else"));
    let msg = run(&secrets, &services, &render(false))
        .await
        .expect_err("refused")
        .to_string();
    assert!(
        msg.contains("belongs to environment `someone-else`"),
        "{msg}"
    );
    assert!(secrets.secrets().is_empty(), "nothing staged");
    assert_eq!(services.upserts(), 0);
}

#[tokio::test]
async fn a_secret_another_environment_owns_is_refused() {
    let (secrets, services) = fakes();
    secrets.seed_secret(SECRET, Some("someone-else"));
    let msg = run(&secrets, &services, &render(false))
        .await
        .expect_err("refused")
        .to_string();
    assert!(msg.contains(SECRET), "{msg}");
    assert!(services.spec(SERVICE).is_none(), "no service deployed");
}

#[tokio::test]
async fn a_service_that_fails_to_boot_fails_the_run_with_cloud_runs_reason() {
    let (secrets, services) = fakes();
    services.fail_boot(SERVICE, "Image pull failed: 403 Forbidden");
    let msg = run(&secrets, &services, &render(false))
        .await
        .expect_err("failed")
        .to_string();
    assert!(msg.contains("Image pull failed: 403 Forbidden"), "{msg}");
    assert!(msg.contains("No worker was deployed"), "{msg}");
    assert!(msg.contains("roles/artifactregistry.reader"), "{msg}");
    assert!(!msg.contains("SECRET"), "no input value: {msg}");
    assert!(
        !services.is_public(SERVICE),
        "a failed SoR is not opened up"
    );
}

#[tokio::test]
async fn a_failed_service_is_redeployed_on_the_next_run() {
    let (secrets, services) = fakes();
    services.fail_boot(SERVICE, "Postgres unreachable");
    assert!(run(&secrets, &services, &render(false)).await.is_err());
    services.heal(SERVICE);
    run(&secrets, &services, &render(false))
        .await
        .expect("recovered");
    assert_eq!(services.upserts(), 2, "the failed revision was replaced");
    assert!(services.service(SERVICE).is_some_and(|s| s.ready));
}

#[tokio::test]
async fn a_service_that_never_settles_times_out_naming_the_budget() {
    let (secrets, services) = fakes();
    services.stall_boot(SERVICE);
    let msg = run(&secrets, &services, &render(false))
        .await
        .expect_err("timed out")
        .to_string();
    assert!(msg.contains("did not become ready within"), "{msg}");
}

#[tokio::test]
async fn the_ca_is_staged_as_a_fourth_version_and_mounted() {
    let (secrets, services) = fakes();
    run(&secrets, &services, &render(true)).await.unwrap();
    assert_eq!(secrets.secrets()[SECRET].versions, 4);
    let spec = services.spec(SERVICE).unwrap();
    assert_eq!(spec.secret_mounts[0].items[0].version, "4");
}

fn ar_render() -> SorUnitRender {
    let mut r = render(false);
    r.unit.pack_ref = format!(
        "oci://europe-west1-docker.pkg.dev/proj/greentic/sorla/landlord:t1@sha256:{}",
        "d".repeat(64)
    );
    r
}

#[tokio::test]
async fn an_artifact_registry_pack_is_granted_to_the_runtime_account() {
    let (secrets, services) = fakes();
    run(&secrets, &services, &ar_render()).await.unwrap();
    assert_eq!(
        services.ar_grants(),
        vec![(
            "projects/proj/locations/europe-west1/repositories/greentic".to_string(),
            SA.to_string()
        )]
    );
}

#[tokio::test]
async fn a_refused_grant_is_a_note_with_the_gcloud_command_not_a_failure() {
    let (secrets, services) = fakes();
    services.refuse_ar_grants("HTTP 403");
    let out = run(&secrets, &services, &ar_render())
        .await
        .expect("still deploys");
    assert_eq!(out.notes.len(), 1);
    assert!(out.notes[0].contains("gcloud artifacts repositories add-iam-policy-binding greentic"));
    assert!(out.notes[0].contains(SA));
    assert!(!out.notes[0].contains("SECRET"));
}

#[tokio::test]
async fn retire_deletes_this_environments_service_and_secret() {
    let (secrets, services) = fakes();
    run(&secrets, &services, &render(false)).await.unwrap();
    let out = retire(&secrets, &services, "local", &[placement()], &[])
        .await
        .unwrap();
    assert_eq!(out.deleted_services, vec![SERVICE.to_string()]);
    assert_eq!(out.deleted_secrets, vec![SECRET.to_string()]);
    assert!(services.service(SERVICE).is_none());
    assert!(!secrets.secrets().contains_key(SECRET));
}

#[tokio::test]
async fn retire_leaves_foreign_or_unstamped_resources_in_place_with_a_note() {
    let (secrets, services) = fakes();
    services.seed_service(SERVICE, Some("someone-else"));
    secrets.seed_secret(SECRET, None);
    let out = retire(&secrets, &services, "local", &[placement()], &[])
        .await
        .unwrap();
    assert!(out.deleted_services.is_empty() && out.deleted_secrets.is_empty());
    assert_eq!(out.notes.len(), 2, "{:?}", out.notes);
    assert!(services.service(SERVICE).is_some());
    assert!(secrets.secrets().contains_key(SECRET));
}

#[tokio::test]
async fn retire_of_an_absent_unit_is_a_no_op() {
    let (secrets, services) = fakes();
    let out = retire(&secrets, &services, "local", &[placement()], &[])
        .await
        .unwrap();
    assert_eq!(out, SorRetireOutcome::default());
}

#[tokio::test]
async fn retire_never_deletes_a_service_or_secret_a_declared_unit_still_uses() {
    let (secrets, services) = fakes();
    run(&secrets, &services, &render(false)).await.unwrap();
    let old = CloudRunSorPlacement {
        secret: "old-sor-landlord".into(),
        ..placement()
    };
    secrets.seed_secret("old-sor-landlord", Some(&env_owner_stamp("local")));
    let out = retire(&secrets, &services, "local", &[old], &[placement()])
        .await
        .unwrap();
    assert!(out.deleted_services.is_empty(), "the live service stays");
    assert_eq!(out.deleted_secrets, vec!["old-sor-landlord".to_string()]);
    assert!(services.service(SERVICE).is_some());
    assert!(secrets.secrets().contains_key(SECRET));

    // A region move: the old entry's same-named service in the OLD region is
    // retired, while the project-scoped secret the declared unit still uses
    // and the service in the new region both survive.
    services.seed_service_at(
        "proj",
        "us-central1",
        SERVICE,
        Some(&env_owner_stamp("local")),
    );
    let moved = CloudRunSorPlacement {
        region: "us-central1".into(),
        ..placement()
    };
    let out = retire(&secrets, &services, "local", &[moved], &[placement()])
        .await
        .unwrap();
    assert_eq!(out.deleted_services, vec![SERVICE.to_string()]);
    assert!(
        services
            .service_at("proj", "us-central1", SERVICE)
            .is_none()
    );
    assert!(
        services.service(SERVICE).is_some(),
        "the new region's service stays"
    );
    assert!(out.deleted_secrets.is_empty(), "{:?}", out.deleted_secrets);
    assert!(
        secrets.secrets().contains_key(SECRET),
        "the live secret stays"
    );
}
