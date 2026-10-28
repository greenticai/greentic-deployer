use ulid::Ulid;

use super::*;
use crate::env_packs::azure_aca::arm_types::*;
use crate::env_packs::azure_aca::naming::{app_name, revision_name, revision_suffix};
use greentic_deploy_spec::{DeploymentId, RevisionId};

fn suffix(n: u128) -> crate::env_packs::azure_aca::naming::RevisionSuffix {
    revision_suffix(&RevisionId(Ulid::from(n)))
}

fn spec(traffic: Vec<TrafficEntry>, n: u128) -> AppSpec {
    AppSpec {
        name: app_name(&DeploymentId(Ulid::from(1_u128))),
        location: "southeastasia".into(),
        environment_id:
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/e"
                .into(),
        tags: vec![(OWNER_TAG.into(), "owner-1".into())],
        target_port: 8080,
        secrets: vec![
            AppSecret::new("seed-env-aaaaaaaaaaaa", "SEEDCONTENT"),
            AppSecret::new("oci-pw", "hunter2"),
        ],
        traffic,
        revision: RevisionSpec {
            suffix: suffix(n),
            image: "ghcr.io/x/runtime:develop".into(),
            cpu: 0.5,
            memory: "1Gi".into(),
            env: vec![
                EnvEntry::plain("GREENTIC_ENV", "e"),
                EnvEntry::secret_ref("OCI_PASSWORD", "oci-pw"),
            ],
            init: Some(InitSpec {
                image: "busybox".into(),
                script: "set -eu\n".into(),
                env: vec![EnvEntry::secret_ref(
                    "GREENTIC_SEED_ENVIRONMENT_JSON",
                    "seed-env-aaaaaaaaaaaa",
                )],
            }),
            min_replicas: 0,
            max_replicas: 1,
        },
    }
}

fn rev(n: u128) -> String {
    revision_name(&app_name(&DeploymentId(Ulid::from(1_u128))), &suffix(n))
}

#[test]
fn first_revision_body_routes_100_to_itself_and_matches_the_golden() {
    let body = container_app_body(&spec(
        vec![TrafficEntry {
            revision_name: rev(0x10),
            weight: 100,
        }],
        0x10,
    ));
    let golden: Value = serde_json::from_str(include_str!("golden/first_revision.json")).unwrap();
    assert_eq!(
        body,
        golden,
        "{}",
        serde_json::to_string_pretty(&body).unwrap()
    );
}

#[test]
fn second_revision_routes_0_to_new_and_keeps_old_weights() {
    let traffic = vec![
        TrafficEntry {
            revision_name: rev(0x10),
            weight: 100,
        },
        TrafficEntry {
            revision_name: rev(0x20),
            weight: 0,
        },
    ];
    let body = container_app_body(&spec(traffic, 0x20));
    let t = body["properties"]["configuration"]["ingress"]["traffic"]
        .as_array()
        .unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!(
        (t[0]["weight"].as_u64(), t[1]["weight"].as_u64()),
        (Some(100), Some(0))
    );
    assert!(t.iter().all(|e| e["latestRevision"] == false));
}

#[test]
fn mode_is_multiple_ingress_is_external_https_only() {
    let body = container_app_body(&spec(vec![], 0x10));
    let c = &body["properties"]["configuration"];
    assert_eq!(c["activeRevisionsMode"], "Multiple");
    assert_eq!(c["ingress"]["external"], true);
    assert_eq!(c["ingress"]["allowInsecure"], false);
    assert_eq!(
        body["properties"]["template"]["volumes"][0]["storageType"],
        "EmptyDir"
    );
}

#[test]
fn seed_and_credentials_only_appear_as_secret_refs() {
    let body = container_app_body(&spec(vec![], 0x10));
    let tpl = &body["properties"]["template"];
    let plain: Vec<&Value> = tpl["containers"][0]["env"]
        .as_array()
        .unwrap()
        .iter()
        .chain(tpl["initContainers"][0]["env"].as_array().unwrap())
        .filter(|e| e.get("value").is_some())
        .collect();
    let text = serde_json::to_string(&plain).unwrap();
    assert!(
        !text.contains("SEEDCONTENT") && !text.contains("hunter2"),
        "{text}"
    );
    assert_eq!(tpl["containers"][0]["env"][1]["secretRef"], "oci-pw");
}

#[test]
fn traffic_patch_touches_only_ingress_traffic() {
    let b = traffic_patch_body(&[TrafficEntry {
        revision_name: rev(0x10),
        weight: 100,
    }]);
    assert_eq!(b["properties"].as_object().unwrap().len(), 1);
    assert_eq!(
        b["properties"]["configuration"].as_object().unwrap().len(),
        1
    );
    assert_eq!(
        b["properties"]["configuration"]["ingress"]["traffic"][0]["weight"],
        100
    );
}

#[test]
fn secrets_are_resent_in_full_and_never_altered() {
    let existing = vec![AppSecret::new("a", "1"), AppSecret::new("b", "2")];
    let merged = secrets_with_values(
        &existing,
        &[AppSecret::new("c", "3"), AppSecret::new("a", "1")],
    )
    .unwrap();
    let names: Vec<&str> = merged.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["a", "b", "c"]);
    assert_eq!(
        secrets_with_values(&existing, &[AppSecret::new("a", "other")]),
        Err(SecretConflict("a".into()))
    );
}

#[test]
fn debug_of_the_spec_never_prints_secret_values() {
    let shown = format!("{:?}", spec(vec![], 0x10));
    assert!(
        !shown.contains("SEEDCONTENT") && !shown.contains("hunter2"),
        "{shown}"
    );
}
